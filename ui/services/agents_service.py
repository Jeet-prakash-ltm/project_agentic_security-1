"""Agent registry backed by the ``agents`` table (formerly ``agents.json``).

Only the repository layer touches PostgreSQL; this service provides the same
API the routes/UI expect (list/add/update/remove agents, connected agent).
"""

import json
import os
import re

from database.db import get_session
from database.repositories import AgentsRepository

_CATALOG_CACHE = None

RETIRED_AGENT_IDS = frozenset((
    "zero-trust-assessment-agent",
))


def _as_dict(agent):
    if agent is None:
        return None
    return {
        "id": agent.id,
        "name": agent.name,
        "type": agent.type,
        "model": agent.model,
        "agent_endpoint": agent.agent_endpoint,
        "api_key": agent.api_key or "",
        "connected": bool(agent.connected),
        "created_at": agent.created_at,
        "agent_id": agent.agent_id,
    }


def _repo():
    return AgentsRepository(get_session())


def _catalog_agents():
    global _CATALOG_CACHE
    if _CATALOG_CACHE is not None:
        return _CATALOG_CACHE
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "config",
        "agents.json",
    )
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception:
        _CATALOG_CACHE = []
        return _CATALOG_CACHE
    _CATALOG_CACHE = list(payload.get("agents") or [])
    return _CATALOG_CACHE


def _catalog_by_id():
    by_id = {}
    for entry in _catalog_agents():
        agent_id = (entry.get("id") or "").strip()
        if agent_id:
            by_id[agent_id] = entry
    return by_id


def _apply_catalog_route(item, catalog):
    if not item:
        return item
    entry = catalog.get(item.get("id") or "")
    if not entry:
        return item
    wanted_agent_id = (entry.get("agent_id") or "").strip()
    if wanted_agent_id:
        item["agent_id"] = wanted_agent_id
    wanted_endpoint = (entry.get("agent_endpoint") or "").strip()
    if wanted_endpoint:
        item["agent_endpoint"] = wanted_endpoint
    return item


def _catalog_public(entry, include_key=False):
    item = {
        "id": entry.get("id") or "",
        "name": entry.get("name") or "",
        "type": entry.get("type") or "",
        "model": entry.get("model") or "gpt-5.1",
        "agent_endpoint": entry.get("agent_endpoint") or "",
        "api_key": entry.get("api_key") or "",
        "connected": bool(entry.get("connected", False)),
        "created_at": entry.get("created_at") or "",
        "agent_id": entry.get("agent_id") or entry.get("name") or "",
    }
    if not include_key:
        item["api_key"] = mask_key(item["api_key"])
    return item


def list_agents(include_key=False):
    result = []
    seen = set()
    catalog = _catalog_by_id()
    for agent in _repo().list_agents():
        item = _as_dict(agent)
        agent_id = item.get("id") or ""
        if agent_id in RETIRED_AGENT_IDS:
            continue
        if not include_key:
            item["api_key"] = mask_key(agent.api_key or "")
        result.append(_apply_catalog_route(item, catalog))
        if agent_id:
            seen.add(agent_id)
    for entry in _catalog_agents():
        agent_id = (entry.get("id") or "").strip()
        if not agent_id or agent_id in seen or agent_id in RETIRED_AGENT_IDS:
            continue
        result.append(_catalog_public(entry, include_key=include_key))
        seen.add(agent_id)
    return result


def get_agent(agent_id):
    catalog = _catalog_by_id()
    found = _as_dict(_repo().get(agent_id))
    if found:
        return _apply_catalog_route(found, catalog)
    for entry in _catalog_agents():
        if (entry.get("id") or "").strip() == agent_id:
            return _catalog_public(entry, include_key=True)
    return None


def get_connected_agent():
    return _as_dict(_repo().get_connected())


def mask_key(key):
    if not key:
        return ""
    if len(key) <= 8:
        return "*" * len(key)
    return "••••••••" + key[-4:]


ALLOWED_AGENT_TYPES = (
    "Network Security Agent",
    "Cloud Security Agent",
    "Master Orchestrator",
)

DISPLAY_AGENT_TYPES = (
    "Network Security Agent",
    "Cloud Security Agent",
)


def slugify(name):
    slug = re.sub(r"[^a-z0-9]+", "-", name.strip().lower())
    return slug.strip("-") or "agent"


def add_agent(name, type_name, endpoint, api_key, model="gpt-5.1", connected=True):
    type_name = (type_name or "").strip()
    if type_name not in ALLOWED_AGENT_TYPES:
        raise ValueError(
            "Type must be Network Security Agent or Cloud Security Agent."
        )
    repo = _repo()
    agent_id = slugify(name)
    existing = repo.get(agent_id)

    if existing is not None:
        repo.update(
            agent_id,
            name=name,
            type=type_name,
            model=model,
            agent_endpoint=endpoint,
            api_key=api_key,
        )
        if connected:
            repo.set_connected(agent_id, True)
        return _as_dict(repo.get(agent_id))

    if connected:
        repo.set_connected(None, False)

    repo.create(
        {
            "id": agent_id,
            "name": name,
            "type": type_name,
            "model": model,
            "agent_endpoint": endpoint,
            "api_key": api_key,
            "connected": connected,
            "created_at": _now(),
            "agent_id": name,
        }
    )
    return _as_dict(repo.get(agent_id))


def set_connected(agent_id, connected=True):
    _repo().set_connected(agent_id, connected)
    return get_agent(agent_id)


def remove_agent(agent_id):
    repo = _repo()
    agent = repo.get(agent_id)
    if agent is None:
        return False
    repo.delete(agent)
    return True


def _now():
    from services import timeutil

    return timeutil.ist_now().isoformat()
