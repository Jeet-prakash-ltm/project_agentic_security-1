"""Persist Firewall Execution bulk commits as Automation jobs."""

import time

from database.db import get_session
from database.repositories.automation_jobs_repository import AutomationJobsRepository
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


def _as_dict(job):
    if not job:
        return None
    operations = list(job.operations or [])
    return {
        "id": job.id,
        "job_number": "JOB-{0:04d}".format(job.id),
        "user_id": job.user_id,
        "firewall_name": job.firewall_name or "",
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
    if status not in ("successful", "failed"):
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
            "firewall_name": (payload.get("firewall_name") or "").strip(),
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


def list_jobs(user_id=None, limit=200):
    return [_as_dict(job) for job in _repo().list_jobs(user_id=user_id, limit=limit)]
