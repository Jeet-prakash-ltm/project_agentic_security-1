"""One-time bootstrap for the multi-tenant user model.

Runs after schema reconciliation at startup and is idempotent:

* Seeds the primary administrator (``Jeet Prakash``) when it does not exist.
* Reclaims data created before multi-tenancy (conversations, insights and
  reports without an owner or owned by the legacy ``anonymous``/``demo``
  placeholders) and binds it to the seeded administrator so historical work
  stays visible without ever being visible to newly registered accounts.
"""

import logging
import time

from werkzeug.security import generate_password_hash

from database.db import get_session
from database.repositories import (
    ConversationsRepository,
    InsightsRepository,
    ReportsRepository,
    UsersRepository,
)

log = logging.getLogger("bootstrap")

ADMIN_USER_ID = "usr-admin"
ADMIN_NAME = "Jeet Prakash"
ADMIN_EMAIL = "jeet.prakashparida@ltm.com"
ADMIN_PASSWORD = "Jeet@12345"
ADMIN_ROLE = "Admin"

# Legacy owner markers used before real user accounts existed.
LEGACY_OWNERS = ("anonymous", "demo")

# Legacy agent display names mapped to their current registry name. Historical
# rows keep the name recorded at the time they were written; this mapping lets
# startup normalise them so every surface shows the current agent name.
AGENT_NAME_ALIASES = {
    "Firewall-Audit-Agent": "Firewall Audit Agent",
    "Firewall Auditor": "Firewall Audit Agent",
}


def ensure_admin_user():
    """Create the seeded administrator account (idempotent)."""
    from services import users_service

    existing = users_service.find_by_email(ADMIN_EMAIL)
    if existing is not None:
        changed = False
        if (existing.role or "") not in users_service.ADMIN_ROLES:
            users_service.set_role(existing.id, ADMIN_ROLE)
            changed = True
        if (existing.status or "approved") != "approved":
            users_service.set_status(existing.id, "approved")
            changed = True
        return existing.id if not changed else existing.id

    repo = UsersRepository(get_session())
    user = repo.create(
        {
            "id": ADMIN_USER_ID,
            "name": ADMIN_NAME,
            "email": ADMIN_EMAIL,
            "password_hash": generate_password_hash(ADMIN_PASSWORD),
            "role": ADMIN_ROLE,
            "status": "approved",
            "created": time.time(),
        }
    )
    log.info("Seeded administrator account %s (%s).", user.id, user.email)
    return user.id


def reclaim_legacy_data(user_id):
    """Reassign pre-multi-tenancy data to the given user.

    Returns a dict of how many rows were reclaimed per table.
    """
    if not user_id:
        return {}
    counts = {}
    try:
        counts["conversations"] = ConversationsRepository(
            get_session()
        ).claim_anonymous(user_id, legacy=LEGACY_OWNERS)
    except Exception as exc:
        log.warning("Conversation legacy reclaim failed: %s", exc)
    try:
        counts["insights"] = InsightsRepository(get_session()).claim_legacy(
            user_id, legacy=LEGACY_OWNERS
        )
    except Exception as exc:
        log.warning("Insights legacy reclaim failed: %s", exc)
    try:
        counts["reports"] = ReportsRepository(get_session()).claim_legacy(
            user_id, legacy=LEGACY_OWNERS
        )
    except Exception as exc:
        log.warning("Reports legacy reclaim failed: %s", exc)
    return counts


def seed_agents_from_config():
    """Seed/refresh the agent registry from ``config/agents.json``.

    Idempotent reconciliation: missing agents are created and field drift on
    existing agents (name/type/model/endpoint) is corrected. A stored API key
    is never overwritten by a placeholder from the config file, and the
    ``connected`` flag of existing rows is left untouched so deploy-time
    decisions survive restarts.
    """
    import json
    import os

    from database.repositories import AgentsRepository

    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "config",
        "agents.json",
    )
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception as exc:
        log.warning("Agent registry seed skipped (agents.json unreadable): %s", exc)
        return 0

    repo = AgentsRepository(get_session())
    seeded = 0
    for entry in payload.get("agents") or []:
        agent_id = (entry.get("id") or "").strip()
        if not agent_id:
            continue
        endpoint = entry.get("agent_endpoint") or ""
        api_key = entry.get("api_key") or ""
        if not endpoint:
            continue

        existing = repo.get(agent_id)
        if existing is None:
            repo.create(
                {
                    "id": agent_id,
                    "name": entry.get("name") or agent_id,
                    "type": entry.get("type") or "Custom Agent",
                    "model": entry.get("model") or "gpt-5.1",
                    "agent_endpoint": endpoint,
                    "api_key": api_key,
                    "connected": bool(entry.get("connected", False)),
                    "created_at": entry.get("created_at") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "agent_id": entry.get("agent_id") or entry.get("name") or agent_id,
                }
            )
            seeded += 1
            log.info("Seeded agent %s from config.", agent_id)
            continue

        updates = {}
        if (existing.name or "") != (entry.get("name") or agent_id):
            updates["name"] = entry.get("name") or agent_id
        if (existing.type or "") != (entry.get("type") or "Custom Agent"):
            updates["type"] = entry.get("type") or "Custom Agent"
        if (existing.model or "") != (entry.get("model") or "gpt-5.1"):
            updates["model"] = entry.get("model") or "gpt-5.1"
        if (existing.agent_endpoint or "") != endpoint:
            updates["agent_endpoint"] = endpoint
        wanted_agent_id = entry.get("agent_id") or existing.agent_id or entry.get("name") or agent_id
        if (existing.agent_id or "") != wanted_agent_id:
            updates["agent_id"] = wanted_agent_id
        current_key = existing.api_key or ""
        if not current_key or current_key.startswith("PLACEHOLDER"):
            if api_key and (existing.api_key or "") != api_key:
                updates["api_key"] = api_key
        if updates:
            repo.update(agent_id, **updates)
            seeded += 1
    return seeded


def reconcile_agent_names():
    """Rewrite legacy agent display names in historical rows (idempotent).

    ``seed_agents_from_config`` refreshes the ``agents`` registry, but snapshot
    copies written earlier (insights, telemetry history, generated reports and
    stored chat messages) keep the old label. This normalises those rows so the
    rename shows up in every database-backed surface, not just the registry.
    """
    from sqlalchemy import text

    from database.db import get_session, remove_session

    renames = {
        "agents": ["name"],
        "insights": ["agent_name", "agent_type"],
        "telemetry_history": ["agent_name"],
        "reports_history": ["generated_by"],
    }

    session = get_session()
    changed = 0
    try:
        for old, new in AGENT_NAME_ALIASES.items():
            params = {"old": old, "new": new}
            for table, columns in renames.items():
                for column in columns:
                    result = session.execute(
                        text(
                            "UPDATE {0} SET {1} = :new WHERE {1} = :old".format(
                                table, column
                            )
                        ),
                        params,
                    )
                    changed += result.rowcount or 0

            # Stored chat messages carry the attribution inside the ``meta``
            # JSON payload rather than a dedicated column.
            result = session.execute(
                text(
                    "UPDATE messages SET meta = "
                    "jsonb_set(meta::jsonb, '{agentName}', to_jsonb(:new))::json "
                    "WHERE meta->>'agentName' = :old"
                ),
                params,
            )
            changed += result.rowcount or 0

            # Telemetry map snapshots embed the agent label inside each node.
            result = session.execute(
                text(
                    "UPDATE telemetry_history AS th SET nodes = sub.nodes::json "
                    "FROM ("
                    "  SELECT id, jsonb_agg("
                    "    CASE WHEN elem->>'label' = :old "
                    "      THEN jsonb_set(elem, '{label}', to_jsonb(:new)) "
                    "      ELSE elem END"
                    "  ) AS nodes "
                    "  FROM telemetry_history, jsonb_array_elements(nodes::jsonb) AS elem "
                    "  GROUP BY id "
                    "  HAVING bool_or(elem->>'label' = :old)"
                    ") AS sub "
                    "WHERE th.id = sub.id"
                ),
                params,
            )
            changed += result.rowcount or 0
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        remove_session()
    return changed


def run_bootstrap():
    """Seed the administrator, agent registry and reclaim legacy rows."""
    try:
        admin_id = ensure_admin_user()
    except Exception as exc:
        log.warning("Admin seed failed: %s", exc)
        return

    try:
        seed_agents_from_config()
    except Exception as exc:
        log.warning("Agent registry seed failed: %s", exc)

    try:
        renamed = reconcile_agent_names()
        if renamed:
            log.info("Normalised %s legacy agent name row(s).", renamed)
    except Exception as exc:
        log.warning("Agent name reconciliation failed: %s", exc)

    try:
        from services import managed_firewalls_service

        managed_firewalls_service.ensure_defaults()
    except Exception as exc:
        log.warning("Firewall inventory seed failed: %s", exc)

    try:
        counts = reclaim_legacy_data(admin_id)
    except Exception as exc:
        log.warning("Legacy data reclaim failed: %s", exc)
        return

    if any(counts.values()):
        log.info("Legacy data reclaimed to %s: %s", admin_id, counts)
