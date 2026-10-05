"""Automation jobs repository (table ``automation_jobs``)."""

from database.models import AutomationJob
from database.repositories.base import BaseRepository


class AutomationJobsRepository(BaseRepository):
    model = AutomationJob

    def create(self, data):
        job = AutomationJob(
            user_id=(data.get("user_id") or "anonymous"),
            firewall_name=(data.get("firewall_name") or ""),
            security_domain=(data.get("security_domain") or "Network security"),
            workbook_name=(data.get("workbook_name") or ""),
            actions=data.get("actions") or [],
            playbooks=data.get("playbooks") or [],
            sheets=data.get("sheets") or [],
            status=(data.get("status") or "failed"),
            created=data.get("created"),
            operations=data.get("operations") or [],
        )
        self.session.add(job)
        self.session.commit()
        return job

    def list_jobs(self, user_id=None, limit=200):
        query = self.session.query(AutomationJob)
        if user_id:
            query = query.filter(AutomationJob.user_id == user_id)
        return (
            query.order_by(AutomationJob.id.desc())
            .limit(limit)
            .all()
        )

    def get_job(self, job_id):
        return self.session.get(AutomationJob, job_id)
