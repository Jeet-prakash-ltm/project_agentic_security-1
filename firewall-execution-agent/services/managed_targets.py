"""Validate write targets against ``managed_firewalls``.

Every Function App write (create, update, delete, single, bulk) must resolve
to one unique managed firewall. Host IP is not unique for clones. The default
``NETSEC_FW_HOST`` is never used as a write target.
"""

import logging

from services.job_planner import JobValidationError
from services.job_store import database_url, is_configured

logger = logging.getLogger("firewall.jobs.targets")

MISSING_FIREWALL = "MISSING_FIREWALL"
INVALID_FIREWALL = "INVALID_FIREWALL"
AMBIGUOUS_FIREWALL = "AMBIGUOUS_FIREWALL"

MISSING_FIREWALL_MESSAGE = (
    "Select a firewall by firewall_id or firewall_name before this write."
)
INVALID_FIREWALL_MESSAGE = (
    "Selected firewall is not in inventory. "
    "Choose one from the list by firewall_id/target_asset_id or firewall_name."
)
AMBIGUOUS_FIREWALL_MESSAGE = (
    "Multiple firewalls match that selection. "
    "Choose one by firewall_id or firewall_name."
)


class MissingFirewallError(JobValidationError):
    def __init__(self, message=MISSING_FIREWALL_MESSAGE, firewalls=None, pending_write=None):
        super().__init__(message)
        self.code = MISSING_FIREWALL
        self.firewalls = firewalls or []
        self.pending_write = pending_write


class InvalidFirewallError(JobValidationError):
    def __init__(
        self,
        message=INVALID_FIREWALL_MESSAGE,
        firewalls=None,
        pending_write=None,
        code=INVALID_FIREWALL,
    ):
        super().__init__(message)
        self.code = code
        self.firewalls = firewalls or []
        self.pending_write = pending_write


def _clean(value, limit=255):
    return str(value or "").strip()[:limit]


def _public(row):
    host_ip = _clean(row.get("host_ip"), 64)
    host_name = _clean(row.get("host_name"), 255)
    device_name = _clean(row.get("device_name"), 64)
    raw_status = _clean(row.get("status"), 16).lower()
    if raw_status in ("live", "up", "online", "active", "reachable"):
        status = "live"
    else:
        status = "down"
    firewall_id = str(row.get("id") or "").strip()
    display = device_name or host_name or host_ip
    return {
        "firewall_id": firewall_id,
        "id": firewall_id,
        "target_asset_id": firewall_id,
        "firewall_name": device_name,
        "device_name": device_name,
        "name": display,
        "host_name": host_name,
        "hostname": host_name or device_name or host_ip,
        "host_ip": host_ip,
        "ip": host_ip or host_name,
        "management_ip": host_ip or host_name,
        "firewall_host": host_ip or host_name,
        "status": status,
        "vendor": _clean(row.get("vendor"), 128) or "Palo Alto",
        "port": row.get("port"),
        "device_type": _clean(row.get("device_type"), 64) or "Firewall",
        "clone_of": _clean(row.get("clone_of"), 64) or None,
        "source": "managed_firewalls",
        "label": "{0} ({1})".format(display, host_ip) if host_ip and display != host_ip else display,
    }


def list_managed_firewalls():
    """Return managed firewall rows for agent selection."""
    if not is_configured():
        raise JobValidationError(
            "DATABASE_URL is not configured; managed_firewalls cannot be listed."
        )
    import psycopg2
    import psycopg2.extras

    conn = psycopg2.connect(
        database_url(),
        cursor_factory=psycopg2.extras.RealDictCursor,
        connect_timeout=10,
    )
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, device_name, host_name, host_ip, status, vendor,
                       port, username, device_type, clone_of
                FROM managed_firewalls
                ORDER BY device_name
                """
            )
            rows = cur.fetchall() or []
    finally:
        conn.close()
    out = []
    for row in rows:
        entry = _public(row)
        if entry.get("firewall_name") or entry.get("firewall_id"):
            out.append(entry)
    return out


def _looks_like_ip(value):
    parts = str(value or "").split(".")
    return len(parts) == 4 and all(part.isdigit() for part in parts)


def _matches_id(entry, wanted):
    if not wanted:
        return False
    wanted = str(wanted).strip()
    for key in ("firewall_id", "id", "target_asset_id"):
        value = entry.get(key)
        if value is not None and str(value).strip() == wanted:
            return True
    return False


def _matches_name(entry, wanted):
    if not wanted or _looks_like_ip(wanted):
        return False
    needle = wanted.lower()
    for key in ("firewall_name", "device_name", "name"):
        value = (entry.get(key) or "").strip()
        if value and value.lower() == needle:
            return True
    host_name = (entry.get("host_name") or "").strip()
    if host_name and not _looks_like_ip(host_name) and host_name.lower() == needle:
        return True
    return False


def _matches_host(entry, wanted):
    if not wanted:
        return False
    return wanted in (
        entry.get("firewall_host"),
        entry.get("host_ip"),
        entry.get("host_name"),
        entry.get("firewall_name"),
    )


def _unique(matches, wanted, pending_write=None, firewalls=None):
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise InvalidFirewallError(
            AMBIGUOUS_FIREWALL_MESSAGE,
            firewalls=firewalls,
            pending_write=pending_write,
            code=AMBIGUOUS_FIREWALL,
        )
    raise InvalidFirewallError(
        "{0} ({1}).".format(INVALID_FIREWALL_MESSAGE.rstrip("."), wanted),
        firewalls=firewalls,
        pending_write=pending_write,
    )


def extract_target_fields(payload):
    payload = payload or {}
    requested = payload.get("requested_payload")
    requested = requested if isinstance(requested, dict) else {}
    firewall_id = (
        _clean(payload.get("firewall_id") or payload.get("target_asset_id"), 64)
        or _clean(requested.get("firewall_id") or requested.get("target_asset_id"), 64)
    )
    firewall_name = (
        _clean(payload.get("firewall_name") or payload.get("device_name"), 64)
        or _clean(requested.get("firewall_name") or requested.get("device_name"), 64)
    )
    firewall_host = (
        _clean(payload.get("firewall_host"), 255)
        or _clean(requested.get("firewall_host"), 255)
    )
    if not firewall_id and not firewall_name and firewall_host:
        if firewall_host.isdigit():
            firewall_id = firewall_host
        elif not _looks_like_ip(firewall_host):
            firewall_name = firewall_host
    return {
        "firewall_id": firewall_id,
        "firewall_name": firewall_name,
        "firewall_host": firewall_host,
    }


def pending_write_from_payload(payload):
    payload = payload or {}
    changes = payload.get("changes") if isinstance(payload.get("changes"), list) else []
    requested = payload.get("requested_payload")
    requested = requested if isinstance(requested, dict) else {}
    first = changes[0] if changes else requested
    if not isinstance(first, dict):
        first = {}
    fields = first.get("fields") if isinstance(first.get("fields"), dict) else {}
    operation = _clean(payload.get("operation"), 64).lower()
    bulk = operation == "apply_bulk" or bool(
        payload.get("workbook_base64") or payload.get("source_file_id")
    )
    return {
        "category": first.get("category") or requested.get("category"),
        "action": first.get("action") or requested.get("action"),
        "name": first.get("name") or first.get("object_name") or requested.get("name"),
        "fields": fields,
        "operation": operation or ("apply_bulk" if bulk else "apply_change"),
        "source_type": payload.get("source_type"),
        "source_name": payload.get("source_name"),
        "conversation_id": payload.get("conversation_id"),
        "bulk": bulk,
    }


def resolve_write_target(payload):
    """Resolve one managed firewall. Host IP alone is never enough."""
    fields = extract_target_fields(payload)
    pending = pending_write_from_payload(payload)
    wanted_id = fields["firewall_id"]
    wanted_name = fields["firewall_name"]
    wanted_host = fields["firewall_host"]
    firewalls = list_managed_firewalls()
    if not wanted_id and not wanted_name:
        raise MissingFirewallError(
            MISSING_FIREWALL_MESSAGE,
            firewalls=firewalls,
            pending_write=pending,
        )
    if wanted_id:
        matches = [entry for entry in firewalls if _matches_id(entry, wanted_id)]
        if not matches:
            matches = [entry for entry in firewalls if _matches_name(entry, wanted_id)]
        if matches:
            return _unique(matches, wanted_id, pending_write=pending, firewalls=firewalls)
    if wanted_name:
        matches = [entry for entry in firewalls if _matches_name(entry, wanted_name)]
        if not matches:
            matches = [entry for entry in firewalls if _matches_id(entry, wanted_name)]
        if matches:
            return _unique(matches, wanted_name, pending_write=pending, firewalls=firewalls)
    if wanted_host:
        matches = [entry for entry in firewalls if _matches_host(entry, wanted_host)]
        if matches:
            return _unique(matches, wanted_host, pending_write=pending, firewalls=firewalls)
    raise InvalidFirewallError(
        INVALID_FIREWALL_MESSAGE,
        firewalls=firewalls,
        pending_write=pending,
    )


def job_identity(target):
    if not target:
        raise MissingFirewallError(MISSING_FIREWALL_MESSAGE)
    firewall_id = _clean(target.get("firewall_id") or target.get("target_asset_id"), 64)
    firewall_name = _clean(target.get("firewall_name") or target.get("device_name"), 64)
    host = _clean(target.get("firewall_host") or target.get("host_ip"), 255)
    if not firewall_id and not firewall_name:
        raise MissingFirewallError(MISSING_FIREWALL_MESSAGE)
    if not host:
        raise InvalidFirewallError(
            "Managed firewall {0} has no host IP.".format(firewall_name or firewall_id)
        )
    return {
        "firewall_id": firewall_id,
        "target_asset_id": firewall_id or None,
        "firewall_name": firewall_name,
        "device_name": firewall_name,
        "firewall_host": host,
    }
