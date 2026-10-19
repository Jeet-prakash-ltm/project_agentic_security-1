"""Persist Firewall Execution bulk commits as Automation jobs."""

import time

from database.db import get_session
from database.repositories.automation_jobs_repository import AutomationJobsRepository
from database.repositories.firewall_jobs_repository import FirewallJobsRepository
from services import managed_firewalls_service
from services import timeutil


def _repo():
    return AutomationJobsRepository(get_session())


def _feat_repo():
    return FirewallJobsRepository(get_session())


def _visible_user_ids(user_id):
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


def _security_domain(value):
    text = str(value or "").strip().lower()
    if "cloud" in text:
        return "Cloud security"
    return "Network security"


def _as_dict(job):
    if not job:
        return None
    operations = list(job.operations or [])
    return {
        "id": job.id,
        "job_number": "JOB-{0:04d}".format(job.id),
        "user_id": job.user_id,
        "firewall_name": managed_firewalls_service.display_label(job.firewall_name),
        "security_domain": getattr(job, "security_domain", None) or "Network security",
        "workbook_name": job.workbook_name or "",
        "actions": list(job.actions or []),
        "playbooks": list(job.playbooks or []),
        "sheets": list(job.sheets or []),
        "status": job.status or "failed",
        "created": job.created,
        "created_display": timeutil.format_ist(job.created, "%Y-%m-%d %H:%M:%S"),
        "operations": operations,
    }


def create_job(user_id, payload):
    operations = list(payload.get("operations") or [])
    actions = _unique(payload.get("actions") or [])
    playbooks = _unique(payload.get("playbooks") or [])
    sheets = _unique(payload.get("sheets") or [])
    if not actions:
        for op in operations:
            actions.extend(_unique(op.get("actions") or [op.get("action")]))
        actions = _unique(actions)
    if not playbooks:
        playbooks = _unique(
            [op.get("playbook_title") or op.get("playbook_id") for op in operations]
        )
    if not sheets:
        sheets = _unique([op.get("sheet") for op in operations])
    status = (payload.get("status") or "").strip().lower()
    allowed_status = (
        "successful", "failed", "queued", "running", "pending", "cancelled",
    )
    if status not in allowed_status:
        failed = any(
            (op.get("status") or "").lower() == "failed"
            or op.get("commit_error")
            or ((op.get("counts") or {}).get("errors") or 0)
            for op in operations
        )
        status = "failed" if failed else "successful"
    job = _repo().create(
        {
            "user_id": user_id or "anonymous",
            "firewall_name": managed_firewalls_service.display_label(
                payload.get("firewall_name")
            ),
            "security_domain": _security_domain(payload.get("security_domain")),
            "workbook_name": (payload.get("workbook_name") or "").strip(),
            "actions": actions,
            "playbooks": playbooks,
            "sheets": sheets,
            "status": status,
            "created": payload.get("created") or time.time(),
            "operations": operations,
        }
    )
    return _as_dict(job)


_FEAT_TO_UI = {
    "PENDING_APPROVAL": "pending",
    "APPROVED": "queued",
    "QUEUED": "queued",
    "STARTING": "running",
    "APPLYING_CONFIG": "running",
    "COMMITTING": "running",
    "RUNNING": "running",
    "POST_VALIDATION": "running",
    "SUCCEEDED": "successful",
    "FAILED": "failed",
    "TIMEOUT": "failed",
    "CANCELLED": "cancelled",
}


def feat_ui_status(status):
    return _FEAT_TO_UI.get((status or "").upper(), "queued")


def _created_ts(value):
    if value is None:
        return time.time()
    if hasattr(value, "timestamp"):
        try:
            return value.timestamp()
        except Exception:
            return time.time()
    try:
        return float(value)
    except (TypeError, ValueError):
        return time.time()


def _feat_as_dict(row):
    if not row:
        return None
    payload = row.requested_payload or {}
    if not isinstance(payload, dict):
        payload = {}
    return {
        "task_id": str(row.task_id or ""),
        "user_id": row.user_id or "anonymous",
        "firewall_host": row.firewall_host or "",
        "operation": row.operation or "",
        "status": (row.status or "").upper(),
        "requested_payload": payload,
        "error_message": row.error_message or "",
        "panos_job_id": row.panos_job_id or "",
        "created": _created_ts(row.created_at),
    }


def _list_feat_jobs(user_id, limit=200):
    try:
        rows = _feat_repo().list_jobs(
            user_ids=_visible_user_ids(user_id), limit=limit
        )
    except Exception:
        return []
    return [_feat_as_dict(row) for row in rows if row]


def _feat_summary(feat):
    payload = feat.get("requested_payload") or {}
    summary = str(payload.get("summary") or "").strip()
    if summary:
        return summary
    action = (
        payload.get("row_action")
        or payload.get("action")
        or feat.get("operation")
        or "change"
    )
    name = payload.get("name") or (payload.get("fields") or {}).get("Name") or ""
    category = str(payload.get("category") or "firewall").replace("_", " ")
    return "{0} {1} {2}".format(action, category, name).strip()


def _feat_to_automation_payload(feat):
    payload = feat.get("requested_payload") or {}
    action = payload.get("row_action") or payload.get("action") or "apply"
    category = payload.get("category") or feat.get("operation") or "firewall"
    summary = _feat_summary(feat)
    ui_status = _FEAT_TO_UI.get((feat.get("status") or "").upper(), "queued")
    error = feat.get("error_message") or ""
    return {
        "firewall_name": feat.get("firewall_host") or "",
        "security_domain": "Network security",
        "workbook_name": "Maestro AI",
        "actions": [action],
        "playbooks": [summary],
        "sheets": [category],
        "status": ui_status,
        "created": feat.get("created") or time.time(),
        "operations": [
            {
                "playbook_id": category,
                "playbook_title": summary,
                "sheet": category,
                "actions": [action],
                "counts": {},
                "committed": ui_status == "successful",
                "task_id": feat.get("task_id") or "",
                "status": ui_status,
                "summary": summary,
                "error_reason": error,
                "commit_error": error,
                "panos_job_id": feat.get("panos_job_id") or "",
            }
        ],
    }


def _known_task_ids(jobs):
    known = set()
    for job in jobs:
        for op in job.get("operations") or []:
            task_id = str(op.get("task_id") or "").strip()
            if task_id:
                known.add(task_id)
    return known


def _rollup_status(ops):
    statuses = [(op.get("status") or "").lower() for op in ops]
    if any(item == "failed" for item in statuses):
        return "failed"
    if any(item == "running" for item in statuses):
        return "running"
    if any(item == "queued" for item in statuses):
        return "queued"
    if any(item == "pending" for item in statuses):
        return "pending"
    if any(item == "cancelled" for item in statuses):
        return "cancelled"
    if statuses and all(item == "successful" for item in statuses):
        return "successful"
    return None


def _overlay_feat_status(jobs, feat_jobs):
    by_id = {
        str(item.get("task_id") or ""): item for item in (feat_jobs or [])
    }
    if not by_id:
        return jobs
    repo = None
    for job in jobs:
        ops = list(job.get("operations") or [])
        changed = False
        for op in ops:
            feat = by_id.get(str(op.get("task_id") or ""))
            if not feat:
                continue
            ui_status = _FEAT_TO_UI.get((feat.get("status") or "").upper())
            if not ui_status:
                continue
            op["status"] = ui_status
            if feat.get("panos_job_id"):
                op["panos_job_id"] = feat.get("panos_job_id")
            if feat.get("error_message"):
                op["error_reason"] = feat.get("error_message")
                op["commit_error"] = feat.get("error_message")
            changed = True
        if not changed:
            continue
        job["operations"] = ops
        rolled = _rollup_status(ops)
        if rolled:
            job["status"] = rolled
        if job["status"] in ("successful", "failed", "cancelled"):
            if repo is None:
                repo = _repo()
            row = repo.get_job(job["id"])
            if row and (row.status or "").lower() not in (
                "successful", "failed", "cancelled",
            ):
                repo.update(
                    row, status=job["status"], operations=job["operations"]
                )
    return jobs


def _backfill_feat_jobs(jobs, feat_jobs, user_id):
    known = _known_task_ids(jobs)
    added = []
    for feat in feat_jobs or []:
        task_id = str(feat.get("task_id") or "").strip()
        if not task_id or task_id in known:
            continue
        owner = feat.get("user_id") or user_id or "anonymous"
        try:
            created = create_job(owner, _feat_to_automation_payload(feat))
        except Exception:
            continue
        if created:
            added.append(created)
            known.add(task_id)
    if not added:
        return jobs
    combined = list(added) + list(jobs or [])
    combined.sort(key=lambda item: item.get("created") or 0, reverse=True)
    return combined


def list_jobs(user_id=None, limit=200):
    jobs = [
        _as_dict(job)
        for job in _repo().list_jobs(
            user_ids=_visible_user_ids(user_id), limit=limit
        )
    ]
    feat_jobs = _list_feat_jobs(user_id, limit=limit)
    jobs = _overlay_feat_status(jobs, feat_jobs)
    jobs = _backfill_feat_jobs(jobs, feat_jobs, user_id)
    return jobs[:limit]


def get_job(user_id, job_id):
    job = _repo().get_job(job_id)
    if job is None:
        return None
    if user_id and job.user_id not in (user_id, "anonymous"):
        return None
    return _as_dict(job)
