"""Read canonical ``security_jobs`` / ``security_job_operations``."""

from sqlalchemy.orm import subqueryload

from database.models import SecurityJob, SecurityJobOperation
from database.repositories.base import BaseRepository


class SecurityJobsRepository(BaseRepository):
    model = SecurityJob

    def list_jobs(self, user_id=None, user_ids=None, status=None, limit=200):
        query = self.session.query(SecurityJob).options(
            subqueryload(SecurityJob.operations)
        )
        if user_ids:
            query = query.filter(SecurityJob.user_id.in_(list(user_ids)))
        elif user_id:
            query = query.filter(SecurityJob.user_id == user_id)
        if status:
            query = query.filter(SecurityJob.status == status)
        return (
            query.order_by(SecurityJob.created_at.desc())
            .limit(limit)
            .all()
        )

    def get_job(self, job_id):
        if not job_id:
            return None
        return (
            self.session.query(SecurityJob)
            .options(subqueryload(SecurityJob.operations))
            .filter(SecurityJob.job_id == str(job_id))
            .first()
        )

    def list_operations(self, job_id):
        return (
            self.session.query(SecurityJobOperation)
            .filter(SecurityJobOperation.job_id == str(job_id))
            .order_by(SecurityJobOperation.sequence.asc())
            .all()
        )
