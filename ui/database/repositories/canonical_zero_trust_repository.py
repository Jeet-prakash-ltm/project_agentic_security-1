"""Canonical Zero Trust storage: ``assessments`` + findings + evidence.

Zero Trust runs are canonical only when they live in the shared assessment
tables:

* ``assessments``           one row per run (``assessment_type='zero_trust'``,
                            ``security_domain='zero_trust'``) holding scores,
                            counts and the pillar summary
* ``assessment_findings``   one row per scored control
* ``assessment_evidence``   one row per collector payload

The legacy ``zero_trust_assessments`` table is transitional: rows written
there are mirrored into canonical storage (see ``save_run``) so both readers
and history converge on the shared model.

Reads return Function-App-shaped payloads so ``services.zero_trust_adapter``
can adapt them without knowing which table they came from. Writes are
idempotent per ``assessment_id``: a re-sync replaces findings and evidence but
never duplicates them.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import text

PILLAR_BY_COLLECTOR = {
    "tenant_profile": "Identity",
    "conditional_access": "Identity",
    "identity_security_defaults": "Identity",
    "privileged_roles": "Identity",
    "authentication_methods": "Identity",
    "risky_users": "Identity",
    "identity_risk_events": "Identity",
    "application_credentials": "Identity",
    "privileged_eligibility": "Identity",
    "auth_registration": "Identity",
    "sign_ins": "Identity",
    "access_reviews": "Identity",
    "directory_audits": "Identity",
    "device_compliance": "Devices",
    "managed_devices": "Devices",
    "device_enrollment": "Devices",
    "entra_devices": "Devices",
    "network_security": "Network",
    "sensitivity_labels": "Data",
    "dlp_policies": "Data",
    "sharepoint_settings": "Data",
    "retention_labels": "Data",
    "defender_secure_score": "Infrastructure",
    "defender_assessments": "Infrastructure",
    "infrastructure_security": "Infrastructure",
}

METADATA_COLLECTORS = ("tenant_id", "subscription_id")

RISK_SCORE_BY_SEVERITY = {
    "critical": 5,
    "high": 5,
    "medium": 3,
    "low": 1,
}

STATUS_MAP = {
    "pass": "passed",
    "passed": "passed",
    "fail": "failed",
    "failed": "failed",
    "investigate": "investigate",
    "planned": "planned",
    "skipped": "skipped",
    "not assessed": "not_assessed",
    "not_assessed": "not_assessed",
    "error": "error",
}

COLUMNS = """
    assessment_id, assessment_type, security_domain, tenant_id,
    subscription_id, status, overall_score, risk_level,
    total_checks, passed_checks, failed_checks, error_checks,
    critical_findings, high_findings, medium_findings, low_findings,
    total_findings, summary, started_at, completed_at, created_at, updated_at
"""


def _iso(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()
    return str(value)


def _json_dump(value):
    if value is None:
        return None
    return json.dumps(value, default=str)


def _json_load(value):
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return value


def _as_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _status_for(raw):
    token = str(raw or "").strip().lower()
    return STATUS_MAP.get(token, token or "unknown")


def _risk_level(score, critical, high):
    if critical > 0:
        return "critical"
    if high > 0:
        return "high"
    if score is None:
        return "medium"
    if score < 40:
        return "high"
    if score < 70:
        return "medium"
    return "low"


def _findings_from_report(report):
    findings = (report or {}).get("findings") or []
    return [item for item in findings if isinstance(item, dict)]


def _severity_counts(findings):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for item in findings:
        severity = str(item.get("severity") or "").strip().lower()
        if severity in counts:
            counts[severity] += 1
    return counts


def _summary_blob(payload, findings):
    summary = payload.get("summary") or {}
    counts = _severity_counts(findings)
    blob = {
        "source": "zero_trust_assessment",
        "scope": payload.get("scope") or "tenant",
        "checks": _as_int(summary.get("checks")),
        "passed": _as_int(summary.get("passed")),
        "failed": _as_int(summary.get("failed")),
        "errors": _as_int(summary.get("errors")),
        "progress": _as_int(payload.get("progress")),
        "message": payload.get("message"),
        "pillars": summary.get("pillars") or (payload.get("report") or {}).get("pillars"),
        "severity_counts": counts,
    }
    if payload.get("cached") is not None:
        blob["cached"] = bool(payload.get("cached"))
    return blob


class CanonicalZeroTrustRepository:
    """Reads and writes Zero Trust runs in the canonical assessment tables."""

    def __init__(self, session):
        self.session = session

    # -- reads ---------------------------------------------------------

    def latest_row(self, completed_only=True):
        sql = "SELECT " + COLUMNS + """
            FROM assessments
            WHERE security_domain = 'zero_trust'
        """
        if completed_only:
            sql += " AND lower(coalesce(status, '')) = 'completed'"
        sql += " ORDER BY completed_at DESC NULLS LAST, created_at DESC LIMIT 1"
        return self.session.execute(text(sql)).mappings().first()

    def get_row(self, assessment_id):
        if not assessment_id:
            return None
        return (
            self.session.execute(
                text(
                    "SELECT "
                    + COLUMNS
                    + """
                    FROM assessments
                    WHERE security_domain = 'zero_trust'
                      AND assessment_id = :assessment_id
                    LIMIT 1
                    """
                ),
                {"assessment_id": assessment_id},
            )
            .mappings()
            .first()
        )

    def count(self):
        row = self.session.execute(
            text(
                """
                SELECT count(*) AS n
                FROM assessments
                WHERE security_domain = 'zero_trust'
                """
            )
        ).mappings().first()
        return int(row["n"] or 0) if row else 0

    def latest_completed_at(self):
        row = self.latest_row(completed_only=True)
        return row["completed_at"] if row else None

    def load_run(self, assessment_id):
        """Rebuild the Function App report shape for one canonical run."""

        row = self.get_row(assessment_id)
        if row is None:
            return None
        return self._payload_from_row(row)

    def latest_run(self):
        row = self.latest_row(completed_only=True)
        if row is None:
            row = self.latest_row(completed_only=False)
        if row is None:
            return None
        return self._payload_from_row(row)

    def _findings(self, assessment_id):
        return list(
            self.session.execute(
                text(
                    """
                    SELECT pillar, category, control_id, control_name, status,
                           severity, risk_score, title, finding, detail,
                           observed_value, expected_value, remediation
                    FROM assessment_findings
                    WHERE assessment_id = :assessment_id
                    ORDER BY created_at, control_id
                    """
                ),
                {"assessment_id": assessment_id},
            ).mappings()
        )

    def _evidence(self, assessment_id):
        return list(
            self.session.execute(
                text(
                    """
                    SELECT pillar, collector, evidence_type, source, payload
                    FROM assessment_evidence
                    WHERE assessment_id = :assessment_id
                    ORDER BY collector
                    """
                ),
                {"assessment_id": assessment_id},
            ).mappings()
        )

    def _payload_from_row(self, row):
        assessment_id = row["assessment_id"]
        summary = _json_load(row["summary"]) or {}
        evidence = {}
        for item in self._evidence(assessment_id):
            collector = item["collector"] or item["pillar"]
            if collector:
                evidence[collector] = _json_load(item["payload"])

        findings = []
        for item in self._findings(assessment_id):
            findings.append(
                {
                    "id": item["control_id"],
                    "title": item["title"] or item["control_name"],
                    "detail": item["detail"] or item["finding"],
                    "pillar": item["pillar"],
                    "status": item["status"],
                    "severity": item["severity"],
                    "remediation": item["remediation"],
                    "assessmentLayer": _json_load(item["observed_value"]),
                }
            )

        completed = _iso(row["completed_at"] or row["started_at"] or row["created_at"])
        payload = {
            "assessment_id": assessment_id,
            "status": str(row["status"] or "").lower() or "queued",
            "scope": summary.get("scope") or "tenant",
            "progress": _as_int(summary.get("progress")) or 0,
            "message": summary.get("message"),
            "score": _as_int(row["overall_score"]),
            "tenant_id": row["tenant_id"] or evidence.get("tenant_id"),
            "subscription_id": row["subscription_id"] or evidence.get("subscription_id"),
            "started_at": _iso(row["started_at"]),
            "updated_at": _iso(row["updated_at"]),
            "completed_at": _iso(row["completed_at"]),
            "summary": summary,
            "findings": findings,
            "pillars": summary.get("pillars"),
            "evidence": evidence,
        }
        if summary.get("cached") is not None:
            payload["cached"] = bool(summary.get("cached"))
        payload["_source"] = "canonical"
        payload["_collected_at"] = completed
        return payload

    # -- writes --------------------------------------------------------

    def save_run(self, payload, user_id="anonymous"):
        """Upsert one run into canonical storage (idempotent)."""

        assessment_id = (payload or {}).get("assessment_id") or (payload or {}).get(
            "assessmentId"
        )
        if not assessment_id:
            raise ValueError("assessment_id is required to store a Zero Trust run")

        report = payload.get("report") or {}
        findings = _findings_from_report(report) or [
            item
            for item in (payload.get("findings") or [])
            if isinstance(item, dict)
        ]
        evidence = payload.get("evidence") or {}
        counts = _severity_counts(findings)
        summary = _summary_blob(payload, findings)
        score = _as_int(payload.get("score"))
        if score is None:
            score = _as_int(report.get("score"))

        passed = sum(1 for item in findings if _status_for(item.get("status")) == "passed")
        failed = sum(1 for item in findings if _status_for(item.get("status")) == "failed")

        values = {
            "id": str(uuid.uuid4()),
            "assessment_id": str(assessment_id),
            "tenant_id": payload.get("tenant_id") or evidence.get("tenant_id"),
            "subscription_id": payload.get("subscription_id")
            or evidence.get("subscription_id"),
            "user_id": user_id or "anonymous",
            "status": str(payload.get("status") or "completed").lower(),
            "overall_score": score,
            "risk_level": _risk_level(
                score, counts["critical"], counts["high"]
            ),
            "total_checks": len(findings),
            "passed_checks": passed,
            "failed_checks": failed,
            "error_checks": _as_int((payload.get("summary") or {}).get("errors")) or 0,
            "critical_findings": counts["critical"],
            "high_findings": counts["high"],
            "medium_findings": counts["medium"],
            "low_findings": counts["low"],
            "total_findings": len(findings),
            "summary": _json_dump(summary),
            "started_at": payload.get("started_at"),
            "completed_at": payload.get("completed_at"),
        }

        self.session.execute(
            text(
                """
                INSERT INTO assessments (
                    id, assessment_id, assessment_type, security_domain,
                    tenant_id, subscription_id, user_id, status,
                    overall_score, compliance_score, security_score, risk_level,
                    total_checks, passed_checks, failed_checks, error_checks,
                    critical_findings, high_findings, medium_findings,
                    low_findings, total_findings,
                    summary, started_at, completed_at, created_at, updated_at
                )
                VALUES (
                    :id, :assessment_id, 'zero_trust', 'zero_trust',
                    :tenant_id, :subscription_id, :user_id, :status,
                    :overall_score, :overall_score, :overall_score, :risk_level,
                    :total_checks, :passed_checks, :failed_checks, :error_checks,
                    :critical_findings, :high_findings, :medium_findings,
                    :low_findings, :total_findings,
                    CAST(:summary AS JSONB),
                    CAST(:started_at AS TIMESTAMPTZ),
                    CAST(:completed_at AS TIMESTAMPTZ),
                    coalesce(CAST(:started_at AS TIMESTAMPTZ), now()),
                    now()
                )
                ON CONFLICT (assessment_id) DO UPDATE SET
                    assessment_type = 'zero_trust',
                    security_domain = 'zero_trust',
                    tenant_id = EXCLUDED.tenant_id,
                    subscription_id = EXCLUDED.subscription_id,
                    status = EXCLUDED.status,
                    overall_score = EXCLUDED.overall_score,
                    compliance_score = EXCLUDED.compliance_score,
                    security_score = EXCLUDED.security_score,
                    risk_level = EXCLUDED.risk_level,
                    total_checks = EXCLUDED.total_checks,
                    passed_checks = EXCLUDED.passed_checks,
                    failed_checks = EXCLUDED.failed_checks,
                    error_checks = EXCLUDED.error_checks,
                    critical_findings = EXCLUDED.critical_findings,
                    high_findings = EXCLUDED.high_findings,
                    medium_findings = EXCLUDED.medium_findings,
                    low_findings = EXCLUDED.low_findings,
                    total_findings = EXCLUDED.total_findings,
                    summary = EXCLUDED.summary,
                    started_at = EXCLUDED.started_at,
                    completed_at = EXCLUDED.completed_at,
                    updated_at = now()
                """
            ),
            values,
        )

        self.session.execute(
            text("DELETE FROM assessment_findings WHERE assessment_id = :assessment_id"),
            {"assessment_id": values["assessment_id"]},
        )
        self.session.execute(
            text("DELETE FROM assessment_evidence WHERE assessment_id = :assessment_id"),
            {"assessment_id": values["assessment_id"]},
        )

        if findings:
            self.session.execute(
                text(
                    """
                    INSERT INTO assessment_findings (
                        id, assessment_id, pillar, category, control_id,
                        control_name, status, severity, risk_score, title,
                        finding, detail, observed_value, expected_value,
                        remediation, created_at
                    )
                    VALUES (
                        :id, :assessment_id, :pillar, :category, :control_id,
                        :control_name, :status, :severity, :risk_score, :title,
                        :finding, :detail, CAST(:observed_value AS JSONB),
                        CAST(:expected_value AS JSONB), :remediation,
                        coalesce(CAST(:completed_at AS TIMESTAMPTZ), now())
                    )
                    """
                ),
                [
                    {
                        "id": str(uuid.uuid4()),
                        "assessment_id": values["assessment_id"],
                        "pillar": item.get("pillar"),
                        "category": item.get("pillar"),
                        "control_id": item.get("id") or item.get("control_id"),
                        "control_name": item.get("title") or item.get("name"),
                        "status": _status_for(item.get("status")),
                        "severity": str(item.get("severity") or "").lower() or None,
                        "risk_score": RISK_SCORE_BY_SEVERITY.get(
                            str(item.get("severity") or "").strip().lower()
                        ),
                        "title": item.get("title") or item.get("name"),
                        "finding": item.get("detail"),
                        "detail": item.get("detail"),
                        "observed_value": _json_dump(item.get("assessmentLayer")),
                        "expected_value": None,
                        "remediation": item.get("remediation"),
                        "completed_at": values["completed_at"],
                    }
                    for item in findings
                ],
            )

        evidence_rows = []
        for collector, body in evidence.items():
            if collector in METADATA_COLLECTORS:
                continue
            evidence_rows.append(
                {
                    "id": str(uuid.uuid4()),
                    "assessment_id": values["assessment_id"],
                    "pillar": PILLAR_BY_COLLECTOR.get(collector),
                    "collector": collector,
                    "evidence_type": "collector",
                    "source": collector,
                    "payload": _json_dump(body),
                    "completed_at": values["completed_at"],
                }
            )
        if evidence_rows:
            self.session.execute(
                text(
                    """
                    INSERT INTO assessment_evidence (
                        id, assessment_id, pillar, collector, evidence_type,
                        source, payload, collected_at
                    )
                    VALUES (
                        :id, :assessment_id, :pillar, :collector, :evidence_type,
                        :source, CAST(:payload AS JSONB),
                        coalesce(CAST(:completed_at AS TIMESTAMPTZ), now())
                    )
                    """
                ),
                evidence_rows,
            )

        self.session.commit()
        return values["assessment_id"]
