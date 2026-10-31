"""Reports history repository (table ``reports_history``).

Newest report first, mirroring the previous ``reports_history.json`` array.
"""

from database.models import ReportHistory
from database.repositories.base import BaseRepository


class ReportsRepository(BaseRepository):
    model = ReportHistory

    def list_reports(self, user_id=None, limit=100):
        query = self.session.query(ReportHistory)
        if user_id:
            query = query.filter(ReportHistory.user_id == user_id)
        return (
            query.order_by(ReportHistory.ts.desc())
            .limit(limit)
            .all()
        )

    def get_report(self, report_id, user_id=None):
        query = self.session.query(ReportHistory).filter(
            ReportHistory.id == report_id
        )
        if user_id:
            query = query.filter(ReportHistory.user_id == user_id)
        return query.first()

    def recent(self, limit=100):
        return (
            self.session.query(ReportHistory)
            .order_by(ReportHistory.ts.desc())
            .limit(limit)
            .all()
        )

    def append_report(self, data, user_id=None):
        report = ReportHistory(
            user_id=(user_id or "anonymous"),
            name=data.get("name"),
            type=data.get("type"),
            generated_by=data.get("generated_by"),
            firewall=data.get("firewall"),
            ts=data.get("ts"),
            status=data.get("status") or "Completed",
            size=data.get("size"),
            download_url=data.get("download_url"),
            assessment_id=data.get("assessment_id"),
            job_id=data.get("job_id"),
            security_domain=data.get("security_domain") or "network_security",
            storage_reference=data.get("storage_reference"),
        )
        self.session.add(report)
        self.session.commit()
        return report

    def count(self):
        return self.session.query(ReportHistory).count()

    def claim_legacy(self, user_id, legacy=("anonymous", "demo")):
        """Reassign unowned reports to the given user (bootstrap)."""
        from sqlalchemy import or_

        result = (
            self.session.query(ReportHistory)
            .filter(
                or_(
                    ReportHistory.user_id.is_(None),
                    ReportHistory.user_id.in_(list(legacy)),
                )
            )
            .update({ReportHistory.user_id: user_id}, synchronize_session=False)
        )
        self.session.commit()
        return int(result or 0)
