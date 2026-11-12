"""Workspace / Automation Hub bridge onto PrepareFirewallJob.

Manual rows and uploaded Excel workbooks are queued as canonical
``security_jobs``. Hub Execute is the approval; Jobs is status only.
"""

import io
import logging
import os
import re

from netsec_execution.connector.function_app import make_client
from netsec_execution.services import catalog
from netsec_execution.services import common
from netsec_execution.services import workbook
from services import firewall_jobs_service
from services import managed_firewalls_service

logger = logging.getLogger("netsec.service")

UPLOAD_DIR = os.environ.get("NETSEC_WORKBOOK_DIR", "/tmp/netsec_uploads")
MAX_ROWS = int(os.environ.get("NETSEC_MAX_ROWS", "500") or "500")

PLAYBOOK_CATEGORIES = {
    "objects-addresses": "address",
    "objects-address-groups": "address_group",
    "objects-services": "service",
    "objects-service-groups": "service_group",
    "network-zones": "zone",
    "network-virtual-routers": "virtual_router",
    "network-static-routes": "static_route",
    "network-interfaces": "interface",
    "network-interface-mgmt": "interface_mgmt_profile",
    "policies-security-rules": "security_rule",
    "policies-nat-rules": "nat_rule",
}


def _workbook_path(user_id):
    safe_id = re.sub(r"[^A-Za-z0-9._-]+", "-", str(user_id or "anon"))
    return os.path.join(UPLOAD_DIR, "{0}.xlsx".format(safe_id))


def _ensure_dir():
    try:
        os.makedirs(UPLOAD_DIR, exist_ok=True)
    except OSError as exc:
        logger.warning("NetSec upload dir unavailable: %s", exc)


def _client():
    return make_client()


def _sheet_key(name):
    return re.sub(r"\s+", "", str(name or "").lower())


def _playbook_for_sheet(title):
    key = _sheet_key(title)
    for playbook in catalog.PLAYBOOKS:
        if _sheet_key(playbook.get("sheet")) == key:
            return playbook
        if _sheet_key(playbook.get("id")) == key:
            return playbook
    return None


def _row_fields(row):
    fields = {}
    for header, value in (row or {}).items():
        if header == "Action":
            continue
        if isinstance(value, list):
            value = ", ".join(str(item) for item in value)
        text = str(value).strip() if value is not None else ""
        if text:
            fields[header] = text
    return fields


def _norm_cell(value):
    if isinstance(value, list):
        value = ", ".join(str(item) for item in value)
    return str(value or "").strip().lower()


def _is_example_row(playbook, row):
    examples = (playbook or {}).get("examples") or []
    if not examples or not isinstance(row, dict):
        return False
    columns = list((playbook or {}).get("columns") or []) or list(row.keys())
    for example in examples:
        if not isinstance(example, dict):
            continue
        if all(_norm_cell(row.get(col)) == _norm_cell(example.get(col)) for col in columns):
            return True
    return False


def workbook_changes(path, row_limit=None):
    """Parse an uploaded workbook into preview ``changes[]`` (no PAN-OS writes)."""
    limit = MAX_ROWS if row_limit is None else int(row_limit)
    sheets = workbook.read_workbook(path)
    changes = []
    errors = []
    sequence = 0
    for title, data in sheets.items():
        playbook = _playbook_for_sheet(title)
        category = PLAYBOOK_CATEGORIES.get((playbook or {}).get("id") or "")
        for index, row in enumerate(data.get("rows") or [], start=2):
            if sequence >= limit:
                break
            if playbook and _is_example_row(playbook, row):
                continue
            fields = _row_fields(row)
            if not fields and not str((row or {}).get("Action") or "").strip():
                continue
            sequence += 1
            try:
                action = common.normalize_action((row or {}).get("Action"), default="create")
            except ValueError as exc:
                errors.append(
                    {"row": index, "sheet": title, "error": str(exc)}
                )
                continue
            if not playbook or not category:
                errors.append(
                    {
                        "row": index,
                        "sheet": title,
                        "error": "Sheet does not match a playbook in the catalogue.",
                    }
                )
                continue
            name = fields.get("Name") or fields.get("Interface") or ""
            changes.append(
                {
                    "sequence": sequence,
                    "source_sheet": title,
                    "source_row": index,
                    "category": category,
                    "action": action,
                    "name": name,
                    "fields": fields,
                    "playbook_id": playbook.get("id") or "",
                    "playbook_title": playbook.get("title") or title,
                }
            )
    summary = workbook.summarize(path)
    summary["changes"] = changes
    summary["errors"] = errors
    summary["change_count"] = len(changes)
    return summary


def _public_firewall(entry):
    if not entry:
        return None
    host = (entry.get("host_ip") or entry.get("host_name") or "").strip()
    return {
        "id": entry.get("id"),
        "device_name": entry.get("device_name") or "",
        "host_name": entry.get("host_name") or "",
        "host_ip": entry.get("host_ip") or "",
        "host": host,
        "status": entry.get("status") or "down",
        "label": managed_firewalls_service.display_label(
            entry.get("device_name") or host
        )
        or host,
    }


def list_target_firewalls():
    try:
        entries = managed_firewalls_service.list_firewalls() or []
    except Exception as exc:
        logger.warning("Managed firewall inventory unavailable: %s", exc)
        return []
    return [_public_firewall(entry) for entry in entries if _public_firewall(entry)]


def resolve_target(firewall_id=None, firewall_host=None):
    """Resolve a managed firewall for Hub bulk jobs."""
    wanted_id = str(firewall_id or "").strip()
    wanted_host = str(firewall_host or "").strip()
    entries = list_target_firewalls()
    for entry in entries:
        if wanted_id and str(entry.get("id") or "") == wanted_id:
            return entry
        if wanted_id and (entry.get("device_name") or "") == wanted_id:
            return entry
        if wanted_host and wanted_host in (
            entry.get("host"),
            entry.get("host_ip"),
            entry.get("host_name"),
            entry.get("device_name"),
        ):
            return entry
    if wanted_host:
        return {
            "id": None,
            "device_name": wanted_host,
            "host_name": wanted_host,
            "host_ip": wanted_host,
            "host": wanted_host,
            "status": "unknown",
            "label": wanted_host,
        }
    live = [entry for entry in entries if (entry.get("status") or "").lower() == "live"]
    chosen = (live[0] if live else None) or (entries[0] if entries else None)
    if chosen and chosen.get("host"):
        return chosen
    fallback = (_client().host or "").strip()
    if fallback:
        return {
            "id": None,
            "device_name": fallback,
            "host_name": fallback,
            "host_ip": fallback,
            "host": fallback,
            "status": "unknown",
            "label": fallback,
        }
    raise ValueError("Select a managed firewall before preparing the job.")


def info():
    client = _client()
    firewalls = list_target_firewalls()
    if not firewalls and client.host:
        firewalls = [
            {
                "id": None,
                "device_name": client.host,
                "host_name": client.host,
                "host_ip": client.host,
                "host": client.host,
                "status": "unknown",
                "label": client.host,
            }
        ]
    return {
        "configured": bool(client.configured),
        "missing": client.missing_config(),
        "host": client.host or "",
        "dry_run": bool(client.dry_run),
        "max_rows": MAX_ROWS,
        "playbooks": catalog.list_playbooks(),
        "firewalls": firewalls,
        "via": "function_app" if client.__class__.__name__ == "FunctionAppPanosClient" else "panos",
    }


def save_workbook(user_id, file_storage):
    _ensure_dir()
    path = _workbook_path(user_id)
    file_storage.save(path)
    summary = workbook_changes(path)
    logger.info("Workbook saved for user %s: %s", user_id, summary)
    return summary


def workbook_summary(user_id):
    path = _workbook_path(user_id)
    if not os.path.exists(path):
        return None
    return workbook_changes(path)


def build_template_bytes():
    buffer = io.BytesIO()
    workbook.build_template(buffer, catalog.PLAYBOOKS)
    buffer.seek(0)
    return buffer


def _job_preview(job):
    job = job or {}
    job_id = job.get("job_id") or job.get("task_id") or ""
    operations = job.get("operations") or []
    counts = {"created": 0, "updated": 0, "deleted": 0, "errors": 0}
    rows = []
    for item in operations:
        action = (item.get("action") or "create").strip().lower()
        if action in counts:
            counts[action] += 1
        rows.append(
            {
                "row": item.get("source_row") or item.get("sequence"),
                "op": action,
                "kind": item.get("category") or "",
                "name": item.get("object_name") or "",
                "detail": "queued for approval",
            }
        )
    preview_changes = []
    for item in operations:
        preview_changes.append(
            {
                "sequence": item.get("sequence"),
                "source_sheet": item.get("source_sheet") or "",
                "source_row": item.get("source_row"),
                "category": item.get("category") or "",
                "action": (item.get("action") or "create").strip().lower(),
                "name": item.get("object_name") or "",
                "fields": item.get("normalized_fields") or item.get("requested_fields") or {},
            }
        )
    if not preview_changes:
        for item in (job.get("normalized_payload") or {}).get("changes") or []:
            preview_changes.append(
                {
                    "sequence": item.get("sequence"),
                    "source_sheet": item.get("source_sheet") or "",
                    "source_row": item.get("source_row"),
                    "category": item.get("category") or "",
                    "action": (item.get("action") or "create").strip().lower(),
                    "name": item.get("object_name") or item.get("name") or "",
                    "fields": item.get("fields") or {},
                }
            )
    return {
        "job": job,
        "job_id": job_id,
        "job_number": "JOB-{0}".format(str(job_id)[:8].upper()) if job_id else "",
        "status": job.get("status") or "queued",
        "approval_status": job.get("approval_status") or "approved",
        "playbook_id": job.get("operation") or "",
        "playbook_title": job.get("source_name") or "Firewall change",
        "host": job.get("firewall_host") or "",
        "firewall_host": job.get("firewall_host") or "",
        "operation": job.get("operation") or "apply_bulk",
        "source_type": job.get("source_type") or "automation_hub",
        "counts": counts,
        "committed": False,
        "commit_error": "",
        "summary": (
            "Queued {0} operation(s). Watch status on the Jobs page."
        ).format(len(operations) or len(preview_changes)),
        "rows": rows,
        "changes": preview_changes,
        "awaiting_approval": False,
    }


def _require_live(user_id, firewall_host=None):
    preflight = firewall_jobs_service.preflight(user_id, firewall_host=firewall_host)
    if not preflight.get("live"):
        raise firewall_jobs_service.FirewallJobsError(
            preflight.get("message") or "cannot proceed firewall is down",
            409,
        )
    return preflight


def prepare_workbook_job(
    user_id,
    source_type="automation_hub",
    source_name="",
    firewall_id=None,
    firewall_host=None,
):
    """Prepare one bulk job from the user's stored workbook."""
    client = _client()
    if not client.configured:
        raise ValueError(
            "The Firewall Execution Agent is not connected to a firewall. "
            "Missing environment configuration: {0}.".format(
                ", ".join(client.missing_config())
            )
        )
    path = _workbook_path(user_id)
    if not os.path.exists(path):
        raise ValueError(
            "No playbook workbook uploaded yet. Download the template, fill "
            "it in, then upload it in the panel before running a playbook."
        )
    preview = workbook_changes(path)
    if preview.get("errors"):
        first = preview["errors"][0]
        raise ValueError(
            "{0} row {1}: {2}".format(
                first.get("sheet") or "Workbook",
                first.get("row") or "?",
                first.get("error") or "Invalid workbook row.",
            )
        )
    if not preview.get("changes"):
        raise ValueError("The uploaded workbook has no executable change rows.")
    target = resolve_target(firewall_id=firewall_id, firewall_host=firewall_host)
    host = target.get("host") or client.host or ""
    preflight = _require_live(user_id, firewall_host=host)
    body = {
        "operation": "apply_bulk",
        "source_type": source_type,
        "source_name": source_name or (
            "Automation Hub" if source_type == "automation_hub" else "AI Workspace"
        ),
        "device_group": "vsys1",
        "firewall_host": host or preflight.get("host") or "",
        "target_asset_id": str(target.get("id") or "") or None,
        "row_limit": MAX_ROWS,
        "changes": [
            {
                "category": item.get("category"),
                "action": item.get("action"),
                "name": item.get("name"),
                "fields": item.get("fields") or {},
                "source_sheet": item.get("source_sheet"),
                "source_row": item.get("source_row"),
            }
            for item in preview.get("changes") or []
        ],
    }
    job = firewall_jobs_service.create_job(user_id, body)
    if not job:
        raise firewall_jobs_service.FirewallJobsError(
            "Firewall Execution Agent did not return a job.",
            502,
        )
    result = _job_preview(job)
    result["target"] = target
    if not result.get("changes"):
        result["changes"] = preview.get("changes") or []
    return result


def run_playbook(
    user_id,
    playbook_id,
    commit=None,
    source_type="automation_hub",
    source_name="",
    firewall_id=None,
    firewall_host=None,
):
    """Prepare a bulk job. ``playbook_id`` is accepted for Hub compatibility."""
    playbook = catalog.find_playbook(playbook_id) if playbook_id else None
    label = source_name or ((playbook.get("title") if playbook else "") or playbook_id)
    return prepare_workbook_job(
        user_id,
        source_type=source_type,
        source_name=label or "Automation Hub",
        firewall_id=firewall_id,
        firewall_host=firewall_host,
    )


def run_row(user_id, playbook_id, row, commit=None):
    """Prepare a single manual change as an AI Workspace job."""
    playbook = catalog.find_playbook(playbook_id)
    if playbook is None:
        raise ValueError("Unknown object type: {0}.".format(playbook_id or "none"))
    if not isinstance(row, dict) or not row:
        raise ValueError("A row with the object fields is required.")
    action = (row.get("Action") or "").strip().lower()
    if action not in ("create", "update", "delete"):
        raise ValueError(
            "Pick an Action of create, update or delete for the operation."
        )
    client = _client()
    if not client.configured:
        raise ValueError(
            "The Firewall Execution Agent is not connected to a firewall. "
            "Missing environment configuration: {0}.".format(
                ", ".join(client.missing_config())
            )
        )
    preflight = _require_live(user_id)
    category = PLAYBOOK_CATEGORIES.get(playbook_id)
    if not category:
        raise ValueError("Unsupported object type: {0}.".format(playbook_id))
    fields = {}
    for header in list(playbook.get("columns") or []):
        if header == "Action":
            continue
        value = row.get(header)
        if isinstance(value, list):
            value = ", ".join(str(item) for item in value)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            fields[header] = text
    name = fields.get("Name") or fields.get("Interface") or ""
    body = {
        "operation": "apply_change",
        "source_type": "ai_workspace",
        "source_name": "AI Workspace",
        "device_group": "vsys1",
        "firewall_host": preflight.get("host") or client.host or "",
        "changes": [
            {
                "category": category,
                "action": action,
                "name": name,
                "fields": fields,
            }
        ],
    }
    job = firewall_jobs_service.create_job(user_id, body)
    if not job:
        raise firewall_jobs_service.FirewallJobsError(
            "Firewall Execution Agent did not return a job.",
            502,
        )
    preview = _job_preview(job)
    preview["playbook_id"] = playbook_id
    preview["playbook_title"] = playbook.get("title") or playbook_id
    preview["sheet"] = playbook.get("sheet") or ""
    return preview
