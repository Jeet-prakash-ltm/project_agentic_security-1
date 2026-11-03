"""Agent registry backed by the ``agents`` table (formerly ``agents.json``).

Only the repository layer touches PostgreSQL; this service provides the same
API the routes/UI expect (list/add/update/remove agents, connected agent).
"""

import re

from database.db import get_session
from database.repositories import AgentsRepository


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


def list_agents(include_key=False):
    result = []
    for agent in _repo().list_agents():
        item = _as_dict(agent)
        if not include_key:
            item["api_key"] = mask_key(agent.api_key or "")
        result.append(item)
    return result


def get_agent(agent_id):
    return _as_dict(_repo().get(agent_id))


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
