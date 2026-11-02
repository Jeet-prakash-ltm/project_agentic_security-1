"""Workspace / Automation Hub bridge onto PrepareFirewallJob.

Manual rows and uploaded Excel workbooks are prepared as canonical
``security_jobs``. Nothing is written to PAN-OS until a Jobs-page approve.
"""

import base64
import io
import logging
import os
import re

from netsec_execution.connector.function_app import make_client
from netsec_execution.services import catalog
from netsec_execution.services import workbook
from services import firewall_jobs_service

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


def info():
    client = _client()
    return {
        "configured": bool(client.configured),
        "missing": client.missing_config(),
        "host": client.host or "",
        "dry_run": bool(client.dry_run),
        "max_rows": MAX_ROWS,
        "playbooks": catalog.list_playbooks(),
        "via": "function_app" if client.__class__.__name__ == "FunctionAppPanosClient" else "panos",
    }


def save_workbook(user_id, file_storage):
    _ensure_dir()
    path = _workbook_path(user_id)
    file_storage.save(path)
    summary = workbook.summarize(path)
    logger.info("Workbook saved for user %s: %s", user_id, summary)
    return summary


def workbook_summary(user_id):
    path = _workbook_path(user_id)
    if not os.path.exists(path):
        return None
    return workbook.summarize(path)


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
    return {
        "job": job,
        "job_id": job_id,
        "job_number": "JOB-{0}".format(str(job_id)[:8].upper()) if job_id else "",
        "status": job.get("status") or "awaiting_approval",
        "approval_status": job.get("approval_status") or "pending",
        "playbook_id": job.get("operation") or "",
        "playbook_title": job.get("source_name") or "Firewall change",
        "host": job.get("firewall_host") or "",
        "counts": counts,
        "committed": False,
        "commit_error": "",
        "summary": (
            "Prepared {0} operation(s). Approve the job on the Jobs page "
            "to apply it on the firewall."
        ).format(len(operations)),
        "rows": rows,
        "awaiting_approval": True,
    }


def _require_live(user_id):
    preflight = firewall_jobs_service.preflight(user_id)
    if not preflight.get("live"):
        raise firewall_jobs_service.FirewallJobsError(
            preflight.get("message") or "cannot proceed firewall is down",
            409,
        )
    return preflight


def prepare_workbook_job(user_id, source_type="automation_hub", source_name=""):
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
    preflight = _require_live(user_id)
    with open(path, "rb") as handle:
        payload = handle.read()
    body = {
        "operation": "apply_bulk",
        "source_type": source_type,
        "source_name": source_name or (
            "Automation Hub" if source_type == "automation_hub" else "AI Workspace"
        ),
        "device_group": "vsys1",
        "firewall_host": preflight.get("host") or client.host or "",
        "workbook_base64": base64.b64encode(payload).decode("ascii"),
        "row_limit": MAX_ROWS,
    }
    job = firewall_jobs_service.create_job(user_id, body)
    if not job:
        raise firewall_jobs_service.FirewallJobsError(
            "Firewall Execution Agent did not return a job.",
            502,
        )
    return _job_preview(job)


def run_playbook(user_id, playbook_id, commit=None, source_type="automation_hub", source_name=""):
    """Prepare a bulk job. ``playbook_id`` is accepted for Hub compatibility."""
    playbook = catalog.find_playbook(playbook_id) if playbook_id else None
    label = source_name or ((playbook.get("title") if playbook else "") or playbook_id)
    return prepare_workbook_job(
        user_id,
        source_type=source_type,
        source_name=label or "Automation Hub",
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
