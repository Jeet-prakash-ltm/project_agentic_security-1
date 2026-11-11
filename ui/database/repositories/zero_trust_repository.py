"""Zero Trust assessment repository (table ``zero_trust_assessments``).

Historical table. The live Function App writes canonical ``assessments`` /
``assessment_findings`` / ``assessment_evidence``. Dashboard reads never use
this repository. Keep it for one-shot ``zero_trust_store.sync_legacy``
migration of remaining historical rows.
"""

from sqlalchemy import func

from database.models import ZeroTrustAssessment
from database.repositories.base import BaseRepository


class ZeroTrustRepository(BaseRepository):
    model = ZeroTrustAssessment

    def get_assessment(self, assessment_id):
        if not assessment_id:
            return None
        return (
            self.session.query(ZeroTrustAssessment)
            .filter(ZeroTrustAssessment.assessment_id == assessment_id)
            .first()
        )

    def latest_assessment(self, completed_only=True):
        query = self.session.query(ZeroTrustAssessment)
        if completed_only:
            query = query.filter(ZeroTrustAssessment.status == "completed")
        return (
            query.order_by(
                func.coalesce(
                    ZeroTrustAssessment.started_at, ZeroTrustAssessment.updated_at
                ).desc(),
                ZeroTrustAssessment.assessment_id.desc(),
            )
            .first()
        )

    def list_assessments(self, limit=50):
        return (
            self.session.query(ZeroTrustAssessment)
            .order_by(
                func.coalesce(
                    ZeroTrustAssessment.started_at, ZeroTrustAssessment.updated_at
                ).desc(),
                ZeroTrustAssessment.assessment_id.desc(),
            )
            .limit(limit)
            .all()
        )

    def count(self):
        return self.session.query(ZeroTrustAssessment).count()

    def latest_completed_at(self):
        row = (
            self.session.query(ZeroTrustAssessment.completed_at)
            .filter(ZeroTrustAssessment.status == "completed")
            .filter(ZeroTrustAssessment.completed_at.isnot(None))
            .order_by(ZeroTrustAssessment.completed_at.desc())
            .first()
        )
        return row[0] if row else None
