"""Persist Firewall Execution bulk commits as Automation jobs."""

import time

from database.db import get_session
from database.repositories.automation_jobs_repository import AutomationJobsRepository
from services import managed_firewalls_service
from services import timeutil


def _repo():
    return AutomationJobsRepository(get_session())


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


def _overlay_feat_status(jobs, user_id):
    task_ids = set()
    for job in jobs:
        for op in job.get("operations") or []:
            task_id = str(op.get("task_id") or "").strip()
            if task_id:
                task_ids.add(task_id)
    if not task_ids:
        return jobs
    try:
        from services import firewall_jobs_service

        feat_jobs = firewall_jobs_service.list_jobs(user_id, limit=200)
    except Exception:
        return jobs
    by_id = {
        str(item.get("task_id") or ""): item for item in (feat_jobs or [])
    }
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
        statuses = [(op.get("status") or "").lower() for op in ops]
        if any(item == "failed" for item in statuses):
            job["status"] = "failed"
        elif any(item == "running" for item in statuses):
            job["status"] = "running"
        elif any(item == "queued" for item in statuses):
            job["status"] = "queued"
        elif any(item == "pending" for item in statuses):
            job["status"] = "pending"
        elif any(item == "cancelled" for item in statuses):
            job["status"] = "cancelled"
        elif statuses and all(item == "successful" for item in statuses):
            job["status"] = "successful"
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


def list_jobs(user_id=None, limit=200):
    jobs = [_as_dict(job) for job in _repo().list_jobs(user_id=user_id, limit=limit)]
    return _overlay_feat_status(jobs, user_id)


def get_job(user_id, job_id):
    job = _repo().get_job(job_id)
    if job is None:
        return None
    if user_id and job.user_id not in (user_id, "anonymous"):
        return None
    return _as_dict(job)
