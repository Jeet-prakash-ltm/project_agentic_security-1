"""Jobs page reads canonical ``security_jobs`` / ``security_job_operations``.

Firewall writes are prepared by the Function App. This module only projects
those rows into the Jobs UI shape. New firewall executions are not written
to ``automation_jobs`` or ``firewall_jobs``.
"""

from database.db import get_session
from database.repositories.security_jobs_repository import SecurityJobsRepository
from services import managed_firewalls_service
from services import timeutil
from services import users_service


JOBS_SEE_ALL_ROLES = ("Admin", "Security Analyst")

_CATEGORY_TITLES = {
    "address": "Address Objects",
    "address_group": "Address Groups",
    "service": "Service Objects",
    "service_group": "Service Groups",
    "zone": "Zones",
    "virtual_router": "Virtual Routers",
    "static_route": "Static Routes",
    "interface": "Interfaces",
    "interface_mgmt_profile": "Interface Management Profiles",
    "security_rule": "Security Rules",
    "nat_rule": "NAT Rules",
}

_STATUS_TO_UI = {
    "awaiting_approval": "queued",
    "pending_approval": "queued",
    "pending": "queued",
    "queued": "queued",
    "approved": "queued",
    "running": "running",
    "committing": "running",
    "starting": "running",
    "applying_config": "running",
    "post_validation": "running",
    "completed": "successful",
    "succeeded": "successful",
    "success": "successful",
    "failed": "failed",
    "timeout": "failed",
    "cancelled": "cancelled",
    "canceled": "cancelled",
    "rejected": "cancelled",
}

_OP_STATUS_TO_UI = {
    "pending": "pending",
    "running": "running",
    "success": "successful",
    "succeeded": "successful",
    "completed": "successful",
    "failed": "failed",
    "skipped": "cancelled",
    "rejected": "cancelled",
}


def _repo():
    return SecurityJobsRepository(get_session())


def can_view_all_jobs(user_id=None):
    if not user_id:
        return False
    user = users_service.get_user(user_id)
    role = ""
    if user is not None:
        role = getattr(user, "role", None) or ""
    return (role or "").strip() in JOBS_SEE_ALL_ROLES


def _user_names():
    names = {"anonymous": "Anonymous", "smoke-test": "Smoke Test"}
    for member in users_service.list_members():
        uid = str(member.get("id") or "").strip()
        if uid:
            names[uid] = (member.get("name") or "").strip() or uid
    return names


def _user_display(user_id, names=None):
    uid = str(user_id or "").strip() or "anonymous"
    table = names if names is not None else _user_names()
    return table.get(uid) or uid


def _visible_user_ids(user_id):
    if can_view_all_jobs(user_id):
        return None
    ids = []
    if user_id:
        ids.append(user_id)
    if "anonymous" not in ids:
        ids.append("anonymous")
    return ids


def _unique(values):
    seen = []
    for value in values or []:
        text = str(value or "").strip()
        if text and text not in seen:
            seen.append(text)
    return seen


def category_title(category):
    key = str(category or "").strip().lower()
    if key in _CATEGORY_TITLES:
        return _CATEGORY_TITLES[key]
    text = key.replace("_", " ").strip()
    if not text:
        return "Firewall Change"
    return text.title() + ("s" if not text.endswith("s") else "")


def feat_ui_status(status):
    key = str(status or "").strip().lower()
    return _STATUS_TO_UI.get(key, "queued")


def _op_ui_status(status):
    key = str(status or "").strip().lower()
    return _OP_STATUS_TO_UI.get(key, feat_ui_status(status))


def _security_domain(value):
    text = str(value or "").strip().lower()
    if "cloud" in text:
        return "Cloud security"
    return "Network security"


def _created_ts(value):
    if value is None:
        return 0
    if hasattr(value, "timestamp"):
        try:
            return value.timestamp()
        except Exception:
            return 0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0


def _count_key(action):
    text = str(action or "").strip().lower()
    if text in ("delete", "remove"):
        return "deleted"
    if text in ("update", "edit", "modify"):
        return "updated"
    if text in ("create", "add", "set"):
        return "created"
    return ""


def _op_counts(op, ui_status):
    counts = {"created": 0, "updated": 0, "deleted": 0, "errors": 0}
    if ui_status in ("failed", "cancelled"):
        counts["errors"] = 1
        return counts
    if ui_status == "successful":
        key = _count_key(op.action)
        if key:
            counts[key] = 1
    return counts


def _source_name(job):
    name = (job.source_name or "").strip()
    if name:
        return name
    source = (job.source_type or "").strip().lower()
    if source == "automation_hub":
        return "Automation Hub"
    if source in ("ai_workspace", "conversation", "maestro"):
        return "AI Workspace"
    return "Firewall Change"


def _as_dict(job, names=None):
    if job is None:
        return None
    job_id = str(job.job_id or job.id or "")
    ops = list(job.operations or [])
    operations = []
    actions = []
    playbooks = []
    sheets = []
    for op in ops:
        ui_status = _op_ui_status(op.status)
        title = category_title(op.category)
        action = (op.action or "").strip().lower() or "create"
        error = op.error_message or ""
        operations.append(
            {
                "id": str(op.id or ""),
                "sequence": op.sequence,
                "playbook_id": op.category or "",
                "playbook_title": title,
                "sheet": op.source_sheet or title,
                "source_row": op.source_row,
                "object_name": op.object_name or "",
                "actions": [action] if action else [],
                "counts": _op_counts(op, ui_status),
                "committed": ui_status == "successful",
                "task_id": job_id,
                "status": ui_status,
                "summary": "{0} {1}".format(action, op.object_name or title).strip(),
                "error_reason": error,
                "commit_error": error,
                "error_code": op.error_code or "",
                "executed_at": timeutil.format_ist(
                    _created_ts(op.completed_at or op.started_at),
                    "%Y-%m-%d %H:%M:%S",
                )
                if (op.completed_at or op.started_at)
                else "",
            }
        )
        if action:
            actions.append(action)
        playbooks.append(title)
        if op.source_sheet:
            sheets.append(op.source_sheet)
        else:
            sheets.append(title)
    user_id = job.user_id or "anonymous"
    created = _created_ts(job.created_at)
    approval = (job.approval_status or "").strip().lower()
    return {
        "id": job_id,
        "job_id": job_id,
        "task_id": job_id,
        "job_number": "JOB-{0}".format(job_id[:8].upper()),
        "user_id": user_id,
        "user_name": _user_display(user_id, names),
        "firewall_name": managed_firewalls_service.display_label(job.firewall_host),
        "firewall_host": job.firewall_host or "",
        "device_group": job.device_group or "",
        "security_domain": _security_domain(job.security_domain),
        "workbook_name": _source_name(job),
        "source_type": job.source_type or "",
        "source_name": _source_name(job),
        "operation": job.operation or "",
        "actions": _unique(actions),
        "playbooks": _unique(playbooks),
        "sheets": _unique(sheets),
        "status": feat_ui_status(job.status),
        "approval_status": approval,
        "error_message": job.error_message or "",
        "created": created,
        "created_display": timeutil.format_ist(created, "%Y-%m-%d %H:%M:%S")
        if created
        else "",
        "operations": operations,
        "can_approve": False,
    }


def list_jobs(user_id=None, limit=200):
    names = _user_names()
    rows = _repo().list_jobs(
        user_ids=_visible_user_ids(user_id), limit=limit
    )
    jobs = [_as_dict(job, names) for job in rows]
    return [job for job in jobs if job]


def get_job(user_id, job_id):
    job = _repo().get_job(job_id)
    if job is None:
        return None
    if not can_view_all_jobs(user_id):
        if user_id and job.user_id not in (user_id, "anonymous"):
            return None
    return _as_dict(job)


def create_job(user_id, payload):
    raise ValueError(
        "Firewall jobs are prepared by POST /api/firewall/jobs. "
        "The Jobs page no longer stores independent automation_jobs rows."
    )
