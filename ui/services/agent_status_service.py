"""Per-agent liveness probe powering the Agent Health card on Agent Insights.

Each registered agent (``agents`` table) is reported with a ``live``/``down``
state:

* Agents with no endpoint or no usable API key are ``down`` immediately
  (no network call, message states why).
* Otherwise the agent's Foundry project is probed with a minimal, cached
  request (1 output token) so we never hammer the endpoint. Results are cached
  ``STATUS_TTL`` seconds because the Insights page polls on an interval.

The probe mirrors ``gateway.foundry_client`` key resolution so it honours
per-agent ``FOUNDRY_API_KEY_<AGENT_ID>`` environment variables exactly like
real chat traffic does. No API key is ever returned by this service.

Probe state is shared across users (the agent estate is platform-wide), but
the ``last_active``/``conversations`` activity shown on the health card is
scoped to the signed-in user so each user only sees their own usage.
"""

import concurrent.futures
import threading
import time

import requests

from database.db import get_session
from database.repositories import InsightsRepository
from gateway import foundry_client

STATUS_TTL = 120
PROBE_TIMEOUT = 8
PROBE_WORKERS = 8

_lock = threading.Lock()
_cache = {"ts": 0.0, "agents": []}
_refreshing = False
_refresh_done = threading.Event()
_refresh_done.set()


def _last_activity_by_agent(user_id=None):
    """Per-agent last telemetry timestamp + conversation count.

    Activity is scoped to the requesting ``user_id`` so the Agent Health
    card never reveals another user's conversation volume or recency.
    """
    by_name = {}
    session = get_session()
    try:
        rows = InsightsRepository(session).list_conversations(user_id=user_id)
        for row in rows:
            data = row.data or {}
            name = row.agent_name or row.agent_id or ""
            if not name:
                continue
            record = by_name.setdefault(
                name,
                {"last_active": 0.0, "conversations": 0},
            )
            record["last_active"] = max(
                record["last_active"], float(data.get("updated") or 0)
            )
            record["conversations"] += 1
    except Exception:
        pass
    finally:
        session.close()
    return by_name


def _post_probe(url, api_key, payload):
    started = time.monotonic()
    try:
        response = requests.post(
            url,
            headers={
                "api-key": api_key,
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=PROBE_TIMEOUT,
        )
        latency_ms = int((time.monotonic() - started) * 1000)
        if response.status_code == 200:
            return {"live": True, "detail": "Reachable (HTTP 200)", "latency_ms": latency_ms}
        return {"live": False, "detail": "HTTP {0}".format(response.status_code), "latency_ms": latency_ms}
    except Exception as exc:
        latency_ms = int((time.monotonic() - started) * 1000)
        return {"live": False, "detail": str(exc)[:100] or "Unreachable", "latency_ms": latency_ms}


def _probe_agent(agent):
    """Return ``{"live": bool, "detail": str, "latency_ms": int|None}``.

    Mirrors ``gateway.foundry_client.chat`` routing exactly: the agent is live
    when its Foundry prompt-agent route answers, otherwise (route missing) when
    the ephemeral model+platform-tools call that chat would use answers HTTP 200.
    A minimal ``{"input": ...}`` ping is sent so the probe never runs tool side
    effects - function calls are returned to us but never executed.
    """
    endpoint = (agent.get("agent_endpoint") or "").rstrip("/")
    api_key = foundry_client._resolve_api_key(agent)

    if not endpoint:
        return {"live": False, "detail": "No endpoint configured", "latency_ms": None}
    if not api_key:
        return {"live": False, "detail": "No API key configured", "latency_ms": None}

    agent_name = (agent.get("agent_id") or agent.get("name") or "").strip()
    # "ping" is deliberately benign: prompts like "status" can make some
    # Foundry prompt agents invoke their slow server-side tool, which would
    # time the probe out even though the agent is healthy.
    conversation = [{"role": "user", "content": "ping"}]

    if agent_name:
        # Primary path (as in foundry_client.chat): the Foundry prompt agent.
        url = foundry_client._foundry_agent_responses_url(endpoint, agent_name)
        result = _post_probe(url, api_key, {"input": conversation})
        if result["live"]:
            return result
        # Route missing (mirrors chat's 404/403 -> ephemeral fallback).
        if result["detail"] not in ("HTTP 404", "HTTP 403"):
            return result

    # Fallback path (as in foundry_client.chat): ephemeral model + tool schemas.
    url = foundry_client._responses_url(endpoint)
    payload = {
        "model": agent.get("model", "gpt-5.1"),
        "input": conversation,
    }
    if foundry_client.is_firewall_audit_agent(agent):
        payload["tools"] = foundry_client.TOOL_SCHEMAS
    sys_prompt = foundry_client._system_prompt(agent)
    if sys_prompt:
        payload["instructions"] = sys_prompt
    return _post_probe(url, api_key, payload)


def _probe_all(registered):
    """Probe every agent concurrently so total latency is the slowest probe."""
    if not registered:
        return []
    now = time.time()
    workers = max(1, min(PROBE_WORKERS, len(registered)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        probes = list(pool.map(_probe_agent, registered))
    rows = []
    for agent, probe in zip(registered, probes):
        rows.append(
            {
                "id": agent.get("id"),
                "name": agent.get("name") or agent.get("id") or "Unknown",
                "type": agent.get("type") or "Agent",
                "model": agent.get("model") or "-",
                "connected": bool(agent.get("connected")),
                "status": "live" if probe["live"] else "down",
                "detail": probe["detail"],
                "latency_ms": probe["latency_ms"],
                "checked_at": now,
            }
        )
    return rows


def _refresh_cache():
    """Probe the agent estate and replace the shared cache."""
    from services import agents_service

    # include_key=True so the probe resolves the real secret (env override or
    # stored value); the key is never placed on the returned dicts.
    registered = agents_service.list_agents(include_key=True)
    base = _probe_all(registered)
    with _lock:
        _cache["agents"] = base
        _cache["ts"] = time.time()
    return base


def _claim_refresh():
    """Become the single in-flight refresher. Other callers wait on the event."""
    global _refreshing
    with _lock:
        if _refreshing:
            return False
        _refreshing = True
        _refresh_done.clear()
        return True


def _finish_refresh():
    global _refreshing
    with _lock:
        _refreshing = False
        _refresh_done.set()


def _background_refresh():
    try:
        _refresh_cache()
    except Exception:
        pass
    finally:
        _finish_refresh()


def _decorate(base, user_id):
    """Merge per-user activity onto the shared probe rows."""
    activity = _last_activity_by_agent(user_id=user_id)
    result = []
    for entry in base:
        row = dict(entry)
        record = activity.get(entry["name"]) or {}
        row["last_active"] = record.get("last_active") or 0
        row["conversations"] = record.get("conversations") or 0
        result.append(row)
    return result


def get_agent_statuses(force=False, user_id=None):
    """Return the live/down status of every registered agent.

    Probes run concurrently and are cached ``STATUS_TTL`` seconds (they reflect
    the shared agent estate). A stale cache is served immediately while one
    background refresh runs, so page loads never wait on the full probe sweep.
    Only a cold cache blocks, and only for a single caller (single-flight).
    The per-agent ``last_active``/``conversations`` activity is merged per
    request and scoped to ``user_id``. Never includes API keys.
    """
    now = time.time()
    with _lock:
        cached = list(_cache["agents"])
        fresh = bool(cached) and (now - _cache["ts"] < STATUS_TTL)
        in_flight = _refreshing

    if fresh and not force:
        return _decorate(cached, user_id)

    if force:
        if _claim_refresh():
            try:
                _refresh_cache()
            finally:
                _finish_refresh()
        else:
            _refresh_done.wait(timeout=PROBE_TIMEOUT * 2 + 2)
        with _lock:
            cached = list(_cache["agents"])
        return _decorate(cached, user_id)

    if cached:
        # Stale-while-revalidate: answer now, refresh in the background.
        if not in_flight and _claim_refresh():
            threading.Thread(target=_background_refresh, daemon=True).start()
        return _decorate(cached, user_id)

    # Cold cache: one caller probes, concurrent callers wait for that probe.
    for _ in range(2):
        if _claim_refresh():
            try:
                _refresh_cache()
            finally:
                _finish_refresh()
            break
        _refresh_done.wait(timeout=PROBE_TIMEOUT * 2 + 2)
    with _lock:
        cached = list(_cache["agents"])
    return _decorate(cached, user_id)
