"""Read canonical ``assessments`` / findings / evidence as the SSOT.

Does not create or alter tables. Failures return empty results so callers can
fall back to legacy history.
"""

from datetime import datetime, timezone

from sqlalchemy import text


STATUS_REVERSE = {
    "passed": "COMPLIANT",
    "failed": "NON_COMPLIANT",
    "not_assessed": "NOT_ASSESSED",
    "error": "NOT_ASSESSED",
    "compliant": "COMPLIANT",
    "non_compliant": "NON_COMPLIANT",
    "pass": "COMPLIANT",
    "fail": "NON_COMPLIANT",
}

EVIDENCE_COLLECTORS = (
    "inventory",
    "health_status",
    "ha_configuration",
    "policy_configuration",
    "security_services",
    "routing_configuration",
    "vpn_configuration",
    "logging_configuration",
    "administration_configuration",
    "zone_protection_configuration",
    "backup_configuration",
)

LATEST_COLUMNS = """
    assessment_id, firewall_id, status, overall_score, compliance_score,
    security_score, risk_level, total_checks, passed_checks, failed_checks,
    error_checks, critical_findings, high_findings, medium_findings,
    low_findings, total_findings, summary, completed_at, started_at, created_at
"""


def _ts(value):
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.timestamp()
    return None


def _iso(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()
    return str(value)


def _map_status(raw):
    text_value = (raw or "").strip()
    mapped = STATUS_REVERSE.get(text_value.lower())
    if mapped:
        return mapped
    upper = text_value.upper()
    if upper in ("COMPLIANT", "NON_COMPLIANT", "NOT_ASSESSED"):
        return upper
    return upper or "NOT_ASSESSED"


def _map_risk(raw):
    text_value = (raw or "").strip().upper()
    if text_value in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return text_value
    return text_value or "MEDIUM"


class CanonicalAssessmentsRepository:
    def __init__(self, session):
        self.session = session

    def latest_row(self, firewall_id=None):
        sql = (
            "SELECT "
            + LATEST_COLUMNS
            + """
            FROM assessments
            WHERE security_domain = 'network_security'
              AND lower(coalesce(status, '')) = 'completed'
            """
        )
        params = {}
        if firewall_id and firewall_id not in ("all", "estate"):
            sql += " AND firewall_id = :firewall_id"
            params["firewall_id"] = firewall_id
        sql += " ORDER BY completed_at DESC NULLS LAST, created_at DESC LIMIT 1"
        return self.session.execute(text(sql), params).mappings().first()

    def last_completed_ts(self, firewall_id=None):
        row = self.latest_row(firewall_id)
        if not row:
            return None
        return _ts(row["completed_at"] or row["started_at"] or row["created_at"])

    def list_completed(self, firewall_id=None, limit=200):
        sql = (
            "SELECT "
            + LATEST_COLUMNS
            + """
            FROM assessments
            WHERE security_domain = 'network_security'
              AND lower(coalesce(status, '')) = 'completed'
            """
        )
        params = {"limit": int(limit or 200)}
        if firewall_id and firewall_id not in ("all", "estate"):
            sql += " AND firewall_id = :firewall_id"
            params["firewall_id"] = firewall_id
        sql += " ORDER BY completed_at ASC NULLS LAST, created_at ASC LIMIT :limit"
        return list(self.session.execute(text(sql), params).mappings())

    def stats(self):
        row = self.session.execute(
            text(
                """
                SELECT count(*) AS n, max(completed_at) AS last_ts
                FROM assessments
                WHERE security_domain = 'network_security'
                  AND lower(coalesce(status, '')) = 'completed'
                """
            )
        ).mappings().first()
        if not row:
            return {"assessments_run": 0, "last_assessment_ts": None}
        return {
            "assessments_run": int(row["n"] or 0),
            "last_assessment_ts": _ts(row["last_ts"]),
        }

    def load_payload(self, firewall_id=None):
        row = self.latest_row(firewall_id)
        if not row:
            return None
        return self._payload_from_row(row)

    def _evidence(self, assessment_id):
        rows = self.session.execute(
            text(
                """
                SELECT pillar, collector, evidence_type, source, payload
                FROM assessment_evidence
                WHERE assessment_id = :assessment_id
                """
            ),
            {"assessment_id": assessment_id},
        ).mappings()
        return list(rows)

    def _findings(self, assessment_id):
        rows = self.session.execute(
            text(
                """
                SELECT pillar, category, control_id, control_name, status, severity,
                       risk_score, title, finding, detail, observed_value,
                       expected_value, remediation
                FROM assessment_findings
                WHERE assessment_id = :assessment_id
                ORDER BY created_at
                """
            ),
            {"assessment_id": assessment_id},
        ).mappings()
        return list(rows)

    def _payload_from_row(self, row):
        assessment_id = row["assessment_id"]
        firewall_id = row["firewall_id"] or "vmpafw01"
        summary_blob = row["summary"] if isinstance(row["summary"], dict) else {}
        evidence = self._evidence(assessment_id)
        finding_rows = self._findings(assessment_id)

        payload = {}
        assessment = []
        summary = {}
        for item in evidence:
            collector = item.get("collector") or item.get("pillar")
            kind = item.get("evidence_type")
            body = item.get("payload")
            if kind == "compliance_results" or collector == "assessment":
                if isinstance(body, list):
                    assessment = body
            elif kind == "assessment_summary" or collector == "summary":
                if isinstance(body, dict):
                    summary = dict(body)
            elif collector in EVIDENCE_COLLECTORS:
                payload[collector] = body

        if not summary:
            summary = {
                "total_controls": int(row["total_checks"] or 0),
                "compliant": int(row["passed_checks"] or 0),
                "non_compliant": int(row["failed_checks"] or 0),
                "not_assessed": int(row["error_checks"] or 0),
            }
        else:
            summary.setdefault("total_controls", int(row["total_checks"] or 0))
            summary.setdefault("compliant", int(row["passed_checks"] or 0))
            summary.setdefault("non_compliant", int(row["failed_checks"] or 0))
            summary.setdefault("not_assessed", int(row["error_checks"] or 0))

        if not payload.get("inventory"):
            inventory = summary_blob.get("inventory")
            if isinstance(inventory, dict):
                payload["inventory"] = inventory

        findings = []
        for item in finding_rows:
            findings.append(
                {
                    "control": item.get("control_id") or item.get("control_name"),
                    "status": _map_status(item.get("status")),
                    "risk": _map_risk(item.get("severity")),
                    "metric": item.get("category"),
                    "observed": item.get("observed_value"),
                    "expected": item.get("expected_value"),
                    "finding": item.get("finding") or item.get("detail"),
                    "remediation": item.get("remediation"),
                    "risk_score": item.get("risk_score"),
                }
            )

        if not assessment:
            assessment = [
                {
                    "control": item["control"],
                    "status": item["status"],
                    "risk": item["risk"],
                    "metric": item.get("metric"),
                    "observed": item.get("observed"),
                    "expected": item.get("expected"),
                    "operator": None,
                }
                for item in findings
            ]

        collected_at = _iso(row["completed_at"] or row["started_at"] or row["created_at"])
        payload.update(
            {
                "summary": summary,
                "findings": findings,
                "assessment": assessment,
                "assessment_id": assessment_id,
                "_run_id": assessment_id,
                "_firewall_id": firewall_id,
                "_source": "stored",
                "_collected_at": collected_at,
                "security_score": row["security_score"] or row["overall_score"],
            }
        )
        return payload

    def snapshot_from_row(self, row):
        completed = row["completed_at"] or row["started_at"] or row["created_at"]
        return {
            "run_id": row["assessment_id"],
            "ts": _ts(completed),
            "firewall_name": row["firewall_id"] or "vmpafw01",
            "compliance_pct": row["compliance_score"] or row["overall_score"],
            "security_score": row["security_score"] or row["overall_score"],
            "severity": {
                "critical": int(row["critical_findings"] or 0),
                "high": int(row["high_findings"] or 0),
                "medium": int(row["medium_findings"] or 0),
                "low": int(row["low_findings"] or 0),
            },
            "finding_count": int(row["total_findings"] or 0),
        }
