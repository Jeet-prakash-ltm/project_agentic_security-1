"""Persist Firewall Execution bulk commits as Automation jobs."""

import time

from database.db import get_session
from database.repositories.automation_jobs_repository import AutomationJobsRepository
from database.repositories.firewall_jobs_repository import FirewallJobsRepository
from services import managed_firewalls_service
from services import timeutil
from services import users_service


JOBS_SEE_ALL_ROLES = ("Admin", "Security Analyst")


def _repo():
    return AutomationJobsRepository(get_session())


def _feat_repo():
    return FirewallJobsRepository(get_session())


def can_view_all_jobs(user_id=None):
    if not user_id:
        return False
    user = users_service.get_user(user_id)
    role = ""
    if user is not None:
        role = getattr(user, "role", None) or ""
    return (role or "").strip() in JOBS_SEE_ALL_ROLES


def _user_names():
    names = {"anonymous": "Anonymous"}
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


def _security_domain(value):
    text = str(value or "").strip().lower()
    if "cloud" in text:
        return "Cloud security"
    return "Network security"


def _as_dict(job, names=None):
    if not job:
        return None
    operations = list(job.operations or [])
    user_id = job.user_id or "anonymous"
    return {
        "id": job.id,
        "job_number": "JOB-{0:04d}".format(job.id),
        "user_id": user_id,
        "user_name": _user_display(user_id, names),
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


_EMPTY_COUNTS = {
    "created": 0,
    "updated": 0,
    "deleted": 0,
    "errors": 0,
}

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


def category_title(category):
    key = str(category or "").strip().lower()
    if key in _CATEGORY_TITLES:
        return _CATEGORY_TITLES[key]
    text = key.replace("_", " ").strip()
    if not text:
        return "Firewall Change"
    return text.title() + ("s" if not text.endswith("s") else "")


def _count_key(action, summary=""):
    blob = " ".join(
        [str(action or "").strip().lower(), str(summary or "").strip().lower()]
    )
    if any(word in blob for word in ("delete", "remove")):
        return "deleted"
    if any(word in blob for word in ("update", "edit", "modify")):
        return "updated"
    if any(word in blob for word in ("create", "add", "set")):
        return "created"
    return ""


def _as_counts(value):
    counts = dict(_EMPTY_COUNTS)
    if not isinstance(value, dict):
        return counts
    for key in _EMPTY_COUNTS:
        try:
            counts[key] = int(value.get(key) or 0)
        except (TypeError, ValueError):
            counts[key] = 0
    return counts


def change_counts(action, status, error=None, existing=None, summary=""):
    counts = _as_counts(existing)
    ui = str(status or "").strip().lower()
    feat = str(status or "").strip().upper()
    err = str(error or "").strip()
    failed = ui in ("failed", "cancelled") or feat in (
        "FAILED", "TIMEOUT", "CANCELLED",
    )
    successful = ui == "successful" or feat == "SUCCEEDED"
    if failed or err:
        counts["created"] = 0
        counts["updated"] = 0
        counts["deleted"] = 0
        counts["errors"] = max(counts["errors"], 1)
        return counts
    if successful:
        key = _count_key(action, summary)
        if key and counts[key] == 0 and counts["errors"] == 0:
            counts[key] = 1
    return counts


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


def _feat_action(feat, op=None):
    payload = (feat or {}).get("requested_payload") or {}
    candidates = [
        payload.get("row_action"),
        (op or {}).get("action"),
    ]
    actions = list((op or {}).get("actions") or [])
    if actions:
        candidates.append(actions[0])
    candidates.append(payload.get("action"))
    for value in candidates:
        text = str(value or "").strip().lower()
        if text in ("create", "add", "update", "edit", "modify", "delete", "remove"):
            return "delete" if text in ("delete", "remove") else (
                "update" if text in ("update", "edit", "modify") else "create"
            )
        if text == "set":
            return "create"
    return "create"


def _op_category(op, feat=None):
    payload = (feat or {}).get("requested_payload") or {}
    for candidate in (
        payload.get("category"),
        (op or {}).get("playbook_id"),
        (op or {}).get("sheet"),
    ):
        key = str(candidate or "").strip().lower()
        if key in _CATEGORY_TITLES:
            return key
    text = " ".join(
        [
            str((op or {}).get("playbook_title") or ""),
            str((op or {}).get("summary") or ""),
            str(payload.get("summary") or ""),
        ]
    ).lower()
    for key, title in _CATEGORY_TITLES.items():
        needle = title.lower().rstrip("s")
        if key.replace("_", " ") in text or needle in text:
            return key
    return "address"


def _feat_to_automation_payload(feat):
    payload = feat.get("requested_payload") or {}
    action = _feat_action(feat)
    category = _op_category({}, feat)
    title = category_title(category)
    summary = _feat_summary(feat)
    ui_status = _FEAT_TO_UI.get((feat.get("status") or "").upper(), "queued")
    error = feat.get("error_message") or ""
    return {
        "firewall_name": feat.get("firewall_host") or "",
        "security_domain": "Network security",
        "workbook_name": "Maestro AI",
        "actions": [action],
        "playbooks": [title],
        "sheets": [title],
        "status": ui_status,
        "created": feat.get("created") or time.time(),
        "operations": [
            {
                "playbook_id": category,
                "playbook_title": title,
                "sheet": title,
                "actions": [action],
                "counts": change_counts(
                    action, ui_status, error, summary=summary
                ),
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


def _is_maestro_job(job):
    workbook = str((job or {}).get("workbook_name") or "").strip().lower()
    if workbook == "maestro ai":
        return True
    ops = (job or {}).get("operations") or []
    return any(str(op.get("task_id") or "").strip() for op in ops)


def _overlay_feat_status(jobs, feat_jobs):
    by_id = {
        str(item.get("task_id") or ""): item for item in (feat_jobs or [])
    }
    repo = None
    for job in jobs:
        if not _is_maestro_job(job):
            continue
        ops = list(job.get("operations") or [])
        changed = False
        for op in ops:
            feat = by_id.get(str(op.get("task_id") or ""))
            if feat:
                ui_status = _FEAT_TO_UI.get((feat.get("status") or "").upper())
                if ui_status and op.get("status") != ui_status:
                    op["status"] = ui_status
                    changed = True
                if feat.get("panos_job_id") and op.get("panos_job_id") != feat.get("panos_job_id"):
                    op["panos_job_id"] = feat.get("panos_job_id")
                    changed = True
                if feat.get("error_message"):
                    if op.get("error_reason") != feat.get("error_message"):
                        op["error_reason"] = feat.get("error_message")
                        op["commit_error"] = feat.get("error_message")
                        changed = True
                payload = feat.get("requested_payload") or {}
                category = _op_category(op, feat)
                title = category_title(category)
                if category and op.get("playbook_id") != category:
                    op["playbook_id"] = category
                    changed = True
                if title and op.get("playbook_title") != title:
                    op["playbook_title"] = title
                    op["sheet"] = title
                    changed = True
                action = _feat_action(feat, op)
            else:
                ui_status = op.get("status")
                action = _feat_action({}, op)
                category = _op_category(op)
                title = category_title(category)
                if title and op.get("playbook_title") != title:
                    op["playbook_title"] = title
                    op["sheet"] = title
                    changed = True
            if action and (op.get("actions") or [None])[0] != action:
                op["actions"] = [action]
                changed = True
            next_counts = change_counts(
                action,
                ui_status or op.get("status"),
                op.get("commit_error") or op.get("error_reason"),
                op.get("counts"),
                op.get("summary") or op.get("playbook_title"),
            )
            if next_counts != _as_counts(op.get("counts")):
                op["counts"] = next_counts
                changed = True
        if not changed:
            continue
        job["operations"] = ops
        rolled = _rollup_status(ops)
        if rolled:
            job["status"] = rolled
        if repo is None:
            repo = _repo()
        row = repo.get_job(job["id"])
        if row:
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
    names = _user_names()
    jobs = [
        _as_dict(job, names)
        for job in _repo().list_jobs(
            user_ids=_visible_user_ids(user_id), limit=limit
        )
    ]
    feat_jobs = _list_feat_jobs(user_id, limit=limit)
    jobs = _overlay_feat_status(jobs, feat_jobs)
    jobs = _backfill_feat_jobs(jobs, feat_jobs, user_id)
    for job in jobs:
        if job and not job.get("user_name"):
            job["user_name"] = _user_display(job.get("user_id"), names)
    return jobs[:limit]


def get_job(user_id, job_id):
    job = _repo().get_job(job_id)
    if job is None:
        return None
    if not can_view_all_jobs(user_id):
        if user_id and job.user_id not in (user_id, "anonymous"):
            return None
    return _as_dict(job)
