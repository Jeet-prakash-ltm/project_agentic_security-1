"""Zero Trust assessment repository (table ``zero_trust_assessments``).

Transitional table: the assessment Function App still writes here, and its
package is read-only so it cannot be changed from the UI. Every row is
mirrored into canonical storage (``assessments`` / ``assessment_findings`` /
``assessment_evidence``) by ``services.zero_trust_store``, which is the model
the Cloud Security page renders from. Keep this repository for the legacy
fallback and for reading runs the Function App has just created.
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
