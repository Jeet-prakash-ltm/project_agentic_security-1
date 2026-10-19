"""Firewall jobs repository (table ``firewall_jobs``)."""

import uuid

from database.firewall_job_lifecycle import (
    PENDING,
    PENDING_APPROVAL,
)
from database.models import FirewallJob
from database.repositories.base import BaseRepository


def _task_id(value):
    try:
        return str(uuid.UUID(str(value)))
    except (TypeError, ValueError):
        return None


class FirewallJobsRepository(BaseRepository):
    model = FirewallJob

    def create(self, data):
        task_id = data.get("task_id") or str(uuid.uuid4())
        job = FirewallJob(
            task_id=task_id,
            user_id=(data.get("user_id") or "anonymous"),
            session_id=(data.get("session_id") or ""),
            firewall_host=(data.get("firewall_host") or ""),
            device_group=(data.get("device_group") or ""),
            operation=(data.get("operation") or ""),
            panos_job_id=data.get("panos_job_id"),
            status=(data.get("status") or PENDING_APPROVAL),
            requested_payload=data.get("requested_payload") or {},
            result=data.get("result"),
            error_message=data.get("error_message"),
            approval_status=(data.get("approval_status") or PENDING),
        )
        self.session.add(job)
        self.session.commit()
        return job

    def get_job(self, task_id):
        normalized = _task_id(task_id)
        if normalized is None:
            return None
        return self.session.get(FirewallJob, normalized)

    def list_jobs(self, user_id=None, user_ids=None, status=None, limit=200):
        query = self.session.query(FirewallJob)
        if user_ids:
            query = query.filter(FirewallJob.user_id.in_(list(user_ids)))
        elif user_id:
            query = query.filter(FirewallJob.user_id == user_id)
        if status:
            query = query.filter(FirewallJob.status == status)
        return (
            query.order_by(FirewallJob.created_at.desc())
            .limit(limit)
            .all()
        )

    def update(self, job, **fields):
        for key, value in fields.items():
            if hasattr(job, key):
                setattr(job, key, value)
        self.session.add(job)
        self.session.commit()
        return job
