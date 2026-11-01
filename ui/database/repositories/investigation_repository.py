"""Read-only investigation queries over canonical assessment storage.

Every finding the Investigation Centre shows comes from the canonical tables
(``assessments`` + ``assessment_findings`` + ``assessment_evidence``). Nothing
here starts a run or touches a firewall: it only reads what has already been
persisted.

The default scope is the latest completed assessment per
``(security_domain, firewall_id)`` so the page never loads the full 12k-row
back catalogue. Passing ``assessment`` narrows to a single stored run.
"""

from __future__ import annotations

import json
from datetime import date, datetime, timezone

from sqlalchemy import text


NETWORK_STATUS_LABELS = {
    "compliant": "Compliant",
    "not_compliant": "Not Compliant",
    "not_assessed": "Not Assessed",
}

ZERO_TRUST_STATUS_LABELS = {
    "pass": "Pass",
    "fail": "Fail",
    "investigation": "Investigation",
}

STATUS_LABELS = {**NETWORK_STATUS_LABELS, **ZERO_TRUST_STATUS_LABELS}

STATUS_ALIASES = {
    "compliant": "compliant",
    "comply": "compliant",
    "passed": "compliant",
    "pass": "pass",
    "success": "compliant",
    "not_compliant": "not_compliant",
    "non_compliant": "not_compliant",
    "non-compliant": "not_compliant",
    "failed": "not_compliant",
    "fail": "fail",
    "failure": "fail",
    "not_assessed": "not_assessed",
    "not-assessed": "not_assessed",
    "notassessed": "not_assessed",
    "unknown": "not_assessed",
    "error": "investigation",
    "investigation": "investigation",
    "investigate": "investigation",
    "skipped": "not_assessed",
}

DOMAIN_LABELS = {
    "network_security": "Network Security",
    "zero_trust": "Zero Trust",
}

FINDING_COLUMNS = """
    f.id::text AS id,
    f.assessment_id,
    a.security_domain,
    a.assessment_type,
    a.firewall_id,
    a.completed_at,
    a.started_at,
    a.created_at,
    f.pillar,
    f.category,
    f.control_id,
    f.control_name,
    f.status,
    f.severity,
    {risk_score} AS risk_score,
    f.title,
    f.finding,
    f.detail,
    f.observed_value,
    f.expected_value,
    f.remediation
"""

SEVERITY_ORDER = """
    CASE lower(coalesce(f.severity, ''))
        WHEN 'critical' THEN 0
        WHEN 'high' THEN 1
        WHEN 'medium' THEN 2
        WHEN 'low' THEN 3
        WHEN 'info' THEN 4
        ELSE 5
    END
"""

# Stored scores are inconsistent: Zero Trust keeps a 1-5 rating while the
# firewall audit leaves it NULL. Normalise everything onto the 0-100 scale the
# UI and the risk-score filter use, falling back to the severity.
RISK_EXPR = """
    CASE
        WHEN f.risk_score IS NULL THEN
            CASE lower(coalesce(f.severity, ''))
                WHEN 'critical' THEN 95
                WHEN 'high' THEN 72
                WHEN 'medium' THEN 45
                WHEN 'low' THEN 20
                ELSE 10
            END
        WHEN f.risk_score <= 5 THEN
            CASE round(f.risk_score)
                WHEN 5 THEN 85
                WHEN 4 THEN 78
                WHEN 3 THEN 60
                WHEN 2 THEN 45
                ELSE 25
            END
        ELSE round(f.risk_score)
    END
"""


def normalize_status(raw, domain=None):
    """Collapse the storage vocabulary onto one domain-aware status token."""
    value = (raw or "").strip().lower().replace(" ", "_")
    token = STATUS_ALIASES.get(value)
    if token is None:
        token = "not_assessed"
    if domain == "zero_trust":
        if token == "compliant":
            return "pass"
        if token == "not_compliant":
            return "fail"
        if token == "not_assessed":
            return "investigation"
        return token
    if token == "pass":
        return "compliant"
    if token == "fail":
        return "not_compliant"
    if token == "investigation":
        return "not_assessed"
    return token


def status_label(token, domain=None):
    return STATUS_LABELS.get(token) or (token or "").replace("_", " ").title()


def domain_label(domain):
    return DOMAIN_LABELS.get(domain) or (domain or "").replace("_", " ").title()


def _iso(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, date):
        return value.isoformat()
    return str(value)


def _json(value):
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return value
    return value


def _as_text(value):
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        try:
            return json.dumps(value, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            return str(value)
    return str(value)


def _float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


class InvestigationRepository:
    def __init__(self, session):
        self.session = session

    # ------------------------------------------------------------
    # SCOPE
    # ------------------------------------------------------------

    def _latest_scope_sql(self, params):
        """Latest completed assessment per (security_domain, firewall_id)."""
        return """
            a.assessment_id IN (
                SELECT DISTINCT ON (
                    security_domain, coalesce(firewall_id, '')
                ) assessment_id
                FROM assessments
                WHERE lower(coalesce(status, '')) = 'completed'
                ORDER BY security_domain, coalesce(firewall_id, ''),
                         completed_at DESC NULLS LAST, created_at DESC
            )
        """

    def _build_where(self, filters):
        """Compose the WHERE clause shared by list + count queries."""
        clauses = []
        params = {}

        assessment = (filters.get("assessment") or "").strip()
        if assessment and assessment != "all":
            clauses.append("a.assessment_id = :assessment")
            params["assessment"] = assessment
        else:
            clauses.append(self._latest_scope_sql(params))

        domain = (filters.get("domain") or "").strip()
        if domain and domain != "all":
            clauses.append("a.security_domain = :domain")
            params["domain"] = domain

        firewall = (filters.get("firewall") or "").strip()
        if firewall and firewall != "all":
            clauses.append("a.firewall_id = :firewall")
            params["firewall"] = firewall

        pillar = (filters.get("pillar") or "").strip()
        if pillar and pillar != "all":
            clauses.append("coalesce(f.pillar, '') = :pillar")
            params["pillar"] = pillar

        category = (filters.get("category") or "").strip()
        if category and category != "all":
            clauses.append("coalesce(f.category, '') = :category")
            params["category"] = category

        status = (filters.get("status") or "").strip()
        if status and status != "all" and status.lower() == "open":
            # "Open" spans every non-passing status in both domains.
            clauses.append(
                "lower(replace(coalesce(f.status, ''), ' ', '_')) NOT IN "
                "('compliant', 'passed', 'pass', 'success')"
            )
        elif status and status != "all":
            tokens = self._status_candidates(status)
            placeholders = []
            for index, token in enumerate(tokens):
                key = "status{0}".format(index)
                placeholders.append(":" + key)
                params[key] = token
            clauses.append(
                "lower(replace(coalesce(f.status, ''), ' ', '_')) IN ("
                + ", ".join(placeholders)
                + ")"
            )

        severity = (filters.get("severity") or "").strip()
        if severity and severity != "all":
            clauses.append("lower(coalesce(f.severity, '')) = :severity")
            params["severity"] = severity.lower()

        risk = (filters.get("risk") or filters.get("risk_range") or "").strip()
        if risk and risk != "all":
            bucket = {
                "critical": (90, 101),
                "high": (70, 90),
                "medium": (40, 70),
                "low": (-1, 40),
            }.get(risk.lower())
            if bucket:
                clauses.append("({risk} ) >= :risk_min")
                clauses.append("({risk} ) < :risk_max")
                params["risk_min"] = bucket[0]
                params["risk_max"] = bucket[1]

        day = (filters.get("date") or "").strip()
        if day and day != "all":
            clauses.append("a.completed_at::date = :day")
            params["day"] = day

        search = (filters.get("search") or "").strip()
        if search:
            clauses.append(
                """(
                    coalesce(f.control_id, '') ILIKE :search
                    OR coalesce(f.control_name, '') ILIKE :search
                    OR coalesce(f.title, '') ILIKE :search
                    OR coalesce(f.finding, '') ILIKE :search
                    OR coalesce(f.detail, '') ILIKE :search
                    OR coalesce(f.category, '') ILIKE :search
                    OR coalesce(f.pillar, '') ILIKE :search
                    OR coalesce(f.remediation, '') ILIKE :search
                )"""
            )
            params["search"] = "%{0}%".format(search)

        where = " AND ".join(clauses) if clauses else "TRUE"
        return where.replace("{risk}", RISK_EXPR), params

    @staticmethod
    def _status_candidates(raw):
        """Map a UI status token onto the raw values stored for it.

        Zero Trust stores ``failed``/``error`` while the firewall audit stores
        ``failed``/``not_assessed``, so each token maps to exactly the storage
        values it means. A selected domain is applied separately in SQL.
        """
        token = str(raw or "").strip().lower().replace(" ", "_").replace("-", "_")
        groups = {
            "compliant": ("compliant", "passed", "pass", "success"),
            "pass": ("compliant", "passed", "pass", "success"),
            "not_compliant": ("not_compliant", "non_compliant", "failed", "fail"),
            "fail": ("failed", "fail", "failure"),
            "not_assessed": ("not_assessed", "unknown", "skipped"),
            "investigation": ("error", "investigate", "investigation"),
        }
        if token in groups:
            return groups[token]
        return (token,)

    def _order_sql(self, sort):
        return self._order_sql_raw(sort).replace("{risk}", RISK_EXPR)

    def _order_sql_raw(self, sort):
        sort = (sort or "").strip()
        if sort in ("risk", "riskDesc"):
            return "({risk})::int DESC NULLS LAST, " + SEVERITY_ORDER + ", f.control_id"
        if sort == "riskAsc":
            return "({risk})::int ASC NULLS LAST, " + SEVERITY_ORDER + ", f.control_id"
        if sort in ("recent", "assessed"):
            return "a.completed_at DESC NULLS LAST, " + SEVERITY_ORDER + ", f.control_id"
        if sort == "oldest":
            return "a.completed_at ASC NULLS LAST, " + SEVERITY_ORDER + ", f.control_id"
        if sort == "control":
            return "f.control_id ASC NULLS LAST"
        if sort in ("domain", "category"):
            return (
                "a.security_domain, coalesce(f.pillar, ''), "
                "coalesce(f.category, ''), " + SEVERITY_ORDER + ", f.control_id"
            )
        if sort == "firewall":
            return "a.firewall_id, " + SEVERITY_ORDER + ", f.control_id"
        return SEVERITY_ORDER + ", f.control_id"

    # ------------------------------------------------------------
    # READ
    # ------------------------------------------------------------

    def list_findings(self, filters=None, limit=2000, offset=0):
        filters = dict(filters or {})
        where, params = self._build_where(filters)
        params["limit"] = max(1, min(int(limit or 2000), 10000))
        params["offset"] = max(0, int(offset or 0))
        sql = (
            "SELECT "
            + FINDING_COLUMNS.format(risk_score=RISK_EXPR)
            + """
            FROM assessment_findings f
            JOIN assessments a ON a.assessment_id = f.assessment_id
            WHERE """
            + where
            + " ORDER BY "
            + self._order_sql(filters.get("sort"))
            + " LIMIT :limit OFFSET :offset"
        )
        rows = list(self.session.execute(text(sql), params).mappings())
        return [self._finding_row(row) for row in rows]

    def count_findings(self, filters=None):
        filters = dict(filters or {})
        where, params = self._build_where(filters)
        sql = (
            "SELECT count(*) AS n FROM assessment_findings f "
            "JOIN assessments a ON a.assessment_id = f.assessment_id "
            "WHERE " + where
        )
        row = self.session.execute(text(sql), params).mappings().first()
        return int((row or {}).get("n") or 0)

    def summary(self, filters=None):
        """Status / severity totals for the active scope (all filters but status)."""
        filters = dict(filters or {})
        filters["status"] = "all"
        where, params = self._build_where(filters)
        sql = """
            SELECT
                a.security_domain,
                lower(replace(coalesce(f.status, ''), ' ', '_')) AS status,
                lower(coalesce(f.severity, '')) AS severity,
                count(*) AS n,
                avg({risk}) AS avg_risk
            FROM assessment_findings f
            JOIN assessments a ON a.assessment_id = f.assessment_id
            WHERE {where}
            GROUP BY 1, 2, 3
        """.format(where=where, risk=RISK_EXPR)
        rows = list(self.session.execute(text(sql), params).mappings())

        by_status = {}
        by_severity = {}
        by_domain = {}
        risk_total = 0.0
        risk_count = 0
        for row in rows:
            domain = row["security_domain"]
            count = int(row["n"] or 0)
            token = normalize_status(row["status"], domain)
            by_status[token] = by_status.get(token, 0) + count
            severity = (row["severity"] or "unknown") or "unknown"
            by_severity[severity] = by_severity.get(severity, 0) + count
            by_domain[domain] = by_domain.get(domain, 0) + count
            avg = _float(row["avg_risk"])
            if avg is not None:
                risk_total += avg * count
                risk_count += count
        return {
            "total": sum(by_status.values()),
            "by_status": by_status,
            "by_severity": by_severity,
            "by_domain": by_domain,
            "avg_risk": round(risk_total / risk_count, 1) if risk_count else None,
        }

    def facets(self):
        """Distinct filter values for the default scope (latest per domain/device).

        Counts deliberately describe the same rows the page opens with, so a
        chip labelled "Zero Trust (54)" matches what the filter returns.
        """
        scope = """
            a.assessment_id IN (
                SELECT DISTINCT ON (security_domain, coalesce(firewall_id, ''))
                       assessment_id
                FROM assessments
                WHERE lower(coalesce(status, '')) = 'completed'
                ORDER BY security_domain, coalesce(firewall_id, ''),
                         completed_at DESC NULLS LAST, created_at DESC
            )
        """

        domains = [
            {
                "value": row["value"],
                "label": domain_label(row["value"]),
                "count": int(row["n"] or 0),
            }
            for row in self.session.execute(
                text(
                    """
                    SELECT a.security_domain AS value, count(*) AS n
                    FROM assessment_findings f
                    JOIN assessments a ON a.assessment_id = f.assessment_id
                    WHERE {scope}
                    GROUP BY 1 ORDER BY 1
                    """.format(scope=scope)
                )
            ).mappings()
        ]

        assessments = []
        for row in self.session.execute(
            text(
                """
                SELECT a.assessment_id, a.security_domain, a.firewall_id,
                       a.completed_at, a.total_findings, a.overall_score,
                       a.risk_level
                FROM assessments a
                WHERE lower(coalesce(a.status, '')) = 'completed'
                ORDER BY a.completed_at DESC NULLS LAST, a.created_at DESC
                LIMIT 100
                """
            )
        ).mappings():
            assessments.append(
                {
                    "assessment_id": row["assessment_id"],
                    "domain": row["security_domain"],
                    "domain_label": domain_label(row["security_domain"]),
                    "firewall_id": row["firewall_id"],
                    "completed_at": _iso(row["completed_at"]),
                    "total_findings": int(row["total_findings"] or 0),
                    "score": _float(row["overall_score"]),
                    "risk_level": row["risk_level"],
                }
            )

        def _group(sql):
            return [
                {"value": row["value"], "count": int(row["n"] or 0)}
                for row in self.session.execute(text(sql)).mappings()
                if row["value"]
            ]

        pillars = _group(
            """
            SELECT f.pillar AS value, count(*) AS n
            FROM assessment_findings f
            JOIN assessments a ON a.assessment_id = f.assessment_id
            WHERE {scope}
              AND a.security_domain = 'zero_trust'
              AND f.pillar IS NOT NULL AND f.pillar <> ''
            GROUP BY 1 ORDER BY 1
            """.format(scope=scope)
        )
        categories = _group(
            """
            SELECT f.category AS value, count(*) AS n
            FROM assessment_findings f
            JOIN assessments a ON a.assessment_id = f.assessment_id
            WHERE {scope}
              AND f.category IS NOT NULL AND f.category <> ''
            GROUP BY 1 ORDER BY 1
            """.format(scope=scope)
        )
        severities = _group(
            """
            SELECT lower(f.severity) AS value, count(*) AS n
            FROM assessment_findings f
            JOIN assessments a ON a.assessment_id = f.assessment_id
            WHERE {scope}
              AND f.severity IS NOT NULL AND f.severity <> ''
            GROUP BY 1 ORDER BY 1
            """.format(scope=scope)
        )
        dates = _group(
            """
            SELECT to_char(a.completed_at::date, 'YYYY-MM-DD') AS value,
                   count(DISTINCT a.assessment_id) AS n
            FROM assessments a
            WHERE a.completed_at IS NOT NULL
              AND lower(coalesce(a.status, '')) = 'completed'
            GROUP BY 1 ORDER BY 1 DESC LIMIT 60
            """
        )
        firewalls = _group(
            """
            SELECT a.firewall_id AS value, count(*) AS n
            FROM assessment_findings f
            JOIN assessments a ON a.assessment_id = f.assessment_id
            WHERE {scope}
              AND a.firewall_id IS NOT NULL AND a.firewall_id <> ''
            GROUP BY 1 ORDER BY 1
            """.format(scope=scope)
        )

        statuses = {}
        for row in self.session.execute(
            text(
                """
                SELECT a.security_domain,
                       lower(replace(coalesce(f.status, ''), ' ', '_')) AS status,
                       count(*) AS n
                FROM assessment_findings f
                JOIN assessments a ON a.assessment_id = f.assessment_id
                WHERE {scope}
                GROUP BY 1, 2
                """.format(scope=scope)
            )
        ).mappings():
            domain = row["security_domain"]
            token = normalize_status(row["status"], domain)
            entry = statuses.setdefault(
                token, {"value": token, "label": status_label(token, domain), "count": 0}
            )
            entry["count"] += int(row["n"] or 0)

        return {
            "domains": domains,
            "assessments": assessments,
            "pillars": pillars,
            "categories": categories,
            "severities": severities,
            "dates": dates,
            "firewalls": firewalls,
            "statuses": sorted(statuses.values(), key=lambda s: s["label"]),
        }

    # ------------------------------------------------------------
    # EVIDENCE
    # ------------------------------------------------------------

    def evidence_entries(self, assessment_id, pillar=None):
        """Collector metadata for an assessment (optionally one pillar)."""
        where = ["assessment_id = :assessment_id"]
        params = {"assessment_id": assessment_id}
        if pillar:
            where.append("coalesce(pillar, '') = :pillar")
            params["pillar"] = pillar
        rows = list(
            self.session.execute(
                text(
                    """
                    SELECT id::text AS id, pillar, collector, evidence_type,
                           source, collected_at, pg_column_size(payload) AS size
                    FROM assessment_evidence
                    WHERE {where}
                    ORDER BY pillar, collector
                    """.format(where=" AND ".join(where))
                ),
                params,
            ).mappings()
        )
        if not rows and pillar:
            return self.evidence_entries(assessment_id, None)
        return [
            {
                "id": row["id"],
                "pillar": row["pillar"],
                "collector": row["collector"],
                "evidence_type": row["evidence_type"],
                "source": row["source"],
                "collected_at": _iso(row["collected_at"]),
                "size": int(row["size"] or 0),
            }
            for row in rows
        ]

    def evidence_payload(self, assessment_id, evidence_id=None, collector=None, pillar=None):
        """Full payload for exactly one evidence row."""
        where = ["assessment_id = :assessment_id"]
        params = {"assessment_id": assessment_id}
        if evidence_id:
            where.append("id::text = :evidence_id")
            params["evidence_id"] = evidence_id
        if collector:
            where.append("collector = :collector")
            params["collector"] = collector
        if pillar:
            where.append("coalesce(pillar, '') = :pillar")
            params["pillar"] = pillar
        row = self.session.execute(
            text(
                """
                SELECT id::text AS id, pillar, collector, evidence_type, source,
                       collected_at, payload
                FROM assessment_evidence
                WHERE {where}
                ORDER BY collector
                LIMIT 1
                """.format(where=" AND ".join(where))
            ),
            params,
        ).mappings().first()
        if not row:
            return None
        return {
            "id": row["id"],
            "pillar": row["pillar"],
            "collector": row["collector"],
            "evidence_type": row["evidence_type"],
            "source": row["source"],
            "collected_at": _iso(row["collected_at"]),
            "payload": _json(row["payload"]),
        }

    # ------------------------------------------------------------
    # ROW MAPPING
    # ------------------------------------------------------------

    def _finding_row(self, row):
        domain = row["security_domain"]
        token = normalize_status(row["status"], domain)
        return {
            "id": row["id"],
            "assessment_id": row["assessment_id"],
            "domain": domain,
            "domain_label": domain_label(domain),
            "assessment_type": row["assessment_type"],
            "firewall_id": row["firewall_id"],
            "pillar": row["pillar"],
            "category": row["category"],
            "control_id": row["control_id"],
            "control_name": row["control_name"],
            "status": token,
            "status_label": status_label(token, domain),
            "severity": (row["severity"] or "").lower() or None,
            "risk_score": _float(row["risk_score"]),
            "title": row["title"],
            "finding": _as_text(row["finding"]),
            "detail": _as_text(row["detail"]),
            "observed": _as_text(row["observed_value"]),
            "expected": _as_text(row["expected_value"]),
            "remediation": _as_text(row["remediation"]),
            "completed_at": _iso(row["completed_at"] or row["created_at"]),
            "started_at": _iso(row["started_at"]),
        }
