"""Component health for the FEAT (Firewall Execution Agent).

The Agents page shows FEAT's A2A route, Function App / OpenAPI bridge,
PAN-OS connectivity and job-worker health separately. Every value here comes
from a real backend probe or the shared agent-status cache; nothing is
synthesised. Components the backend cannot observe are reported as
``unknown`` with the reason instead of a guessed state.
"""

import threading
import time

from services import agent_status_service
from services import netsec_service

CACHE_TTL = 20
PROBE_TIMEOUT = 6

FEAT_AGENT_ID = "netsec-execution-agent"

_lock = threading.Lock()
_cache = {"ts": 0.0, "data": None}


def _component(component_id, label, status, detail, latency_ms=None):
    return {
        "id": component_id,
        "label": label,
        "status": status,
        "detail": detail or "",
        "latency_ms": latency_ms,
    }


def _a2a_component():
    try:
        rows = agent_status_service.get_agent_statuses(force=False)
    except Exception as exc:
        return _component(
            "a2a", "A2A endpoint", "unknown", "Status probe failed: {0}".format(str(exc)[:120])
        )
    row = None
    for entry in rows:
        if str(entry.get("id") or "") == FEAT_AGENT_ID:
            row = entry
            break
    if row is None:
        return _component(
            "a2a", "A2A endpoint", "unknown", "FEAT is not registered in the agent registry."
        )
    status = "live" if row.get("status") == "live" else "down"
    return _component(
        "a2a",
        "A2A endpoint",
        status,
        row.get("detail") or ("Reachable" if status == "live" else "Unreachable"),
        row.get("latency_ms"),
    )


def _function_app_component(client, via):
    if not client.configured:
        missing = ", ".join(client.missing_config()) or "configuration"
        return _component(
            "function_app",
            "Function App / OpenAPI",
            "down",
            "Missing configuration: {0}".format(missing),
        )
    if via != "function_app":
        return _component(
            "function_app",
            "Function App / OpenAPI",
            "unknown",
            "FEAT is configured for direct PAN-OS access; the Function App bridge is not in the request path.",
        )
    started = time.monotonic()
    try:
        client._get("panos/info", timeout=PROBE_TIMEOUT)
    except Exception as exc:
        return _component(
            "function_app",
            "Function App / OpenAPI",
            "down",
            str(exc)[:160] or "Function App unreachable",
            int((time.monotonic() - started) * 1000),
        )
    return _component(
        "function_app",
        "Function App / OpenAPI",
        "live",
        "Function App responded to /panos/info",
        int((time.monotonic() - started) * 1000),
    )


def _pan_os_component(client, via):
    if not client.configured:
        missing = ", ".join(client.missing_config()) or "configuration"
        return _component(
            "pan_os",
            "PAN-OS connectivity",
            "down",
            "Missing configuration: {0}".format(missing),
        )
    started = time.monotonic()
    try:
        if via == "function_app":
            client._get("panos/test_connection", timeout=PROBE_TIMEOUT + 2)
        else:
            client.get("/config/devices/entry")
    except Exception as exc:
        return _component(
            "pan_os",
            "PAN-OS connectivity",
            "down",
            str(exc)[:160] or "PAN-OS unreachable",
            int((time.monotonic() - started) * 1000),
        )
    return _component(
        "pan_os",
        "PAN-OS connectivity",
        "live",
        "PAN-OS API responded to test_connection",
        int((time.monotonic() - started) * 1000),
    )


def _collect():
    try:
        client = netsec_service._client()
    except Exception as exc:
        error = "FEAT client unavailable: {0}".format(str(exc)[:140])
        return {
            "components": [
                _a2a_component(),
                _component("function_app", "Function App / OpenAPI", "unknown", error),
                _component("pan_os", "PAN-OS connectivity", "unknown", error),
                _component("job_worker", "Job worker", "unknown", error),
            ],
            "checked_at": time.time(),
        }

    via = (
        "function_app"
        if client.__class__.__name__ == "FunctionAppPanosClient"
        else "panos"
    )
    components = [
        _a2a_component(),
        _function_app_component(client, via),
        _pan_os_component(client, via),
        _component(
            "job_worker",
            "Job worker",
            "unknown",
            "No job-worker health endpoint is exposed by the backend.",
        ),
    ]
    return {"components": components, "checked_at": time.time()}


def get_feat_health(force=False):
    now = time.time()
    with _lock:
        if (
            not force
            and _cache["data"] is not None
            and now - _cache["ts"] < CACHE_TTL
        ):
            return _cache["data"]
    data = _collect()
    with _lock:
        _cache["data"] = data
        _cache["ts"] = time.time()
    return data
