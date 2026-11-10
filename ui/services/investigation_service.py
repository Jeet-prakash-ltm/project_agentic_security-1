"""Investigation Centre read model.

Everything here is a read over canonical storage. No assessment is started and
no firewall is contacted, so opening the page cannot enqueue a new run.
"""

from __future__ import annotations

import logging

from database.repositories.canonical_assessments_repository import (
    CanonicalAssessmentsRepository,
)
from database.repositories.investigation_repository import (
    DOMAIN_LABELS,
    InvestigationRepository,
    domain_label,
    normalize_status,
    status_label,
)
from database.db import get_session
from services.zero_trust_adapter import adapt_finding
from services.zero_trust_test_details import enrich_test

log = logging.getLogger(__name__)

DEFAULT_LIMIT = 2000
MAX_LIMIT = 10000

FINDINGS_VIEWS = ("firewall_audit", "zero_trust")
FINDINGS_VIEW_DOMAINS = {
    "firewall_audit": "network_security",
    "zero_trust": "zero_trust",
}


def resolve_findings_view(view=None, domain=None):
    """Map Investigation Centre tabs onto persisted assessment domains."""
    view = str(view or "").strip().lower().replace("-", "_")
    if view in FINDINGS_VIEWS:
        return view
    domain = str(domain or "").strip().lower().replace("-", "_")
    if domain == "zero_trust":
        return "zero_trust"
    return "firewall_audit"

STATUS_VOCABULARY = {
    "network_security": [
        {"value": "compliant", "label": "Compliant"},
        {"value": "not_compliant", "label": "Not Compliant"},
        {"value": "not_assessed", "label": "Not Assessed"},
    ],
    "zero_trust": [
        {"value": "pass", "label": "Pass"},
        {"value": "fail", "label": "Fail"},
        {"value": "investigation", "label": "Investigation"},
    ],
}

RISK_BUCKETS = [
    {"value": "critical", "label": "90-100 (Critical)", "min": 90, "max": 101},
    {"value": "high", "label": "70-89 (High)", "min": 70, "max": 90},
    {"value": "medium", "label": "40-69 (Medium)", "min": 40, "max": 70},
    {"value": "low", "label": "0-39 (Low)", "min": -1, "max": 40},
]

SORTS = [
    {"value": "severity", "label": "Severity"},
    {"value": "risk", "label": "Risk score (high to low)"},
    {"value": "riskAsc", "label": "Risk score (low to high)"},
    {"value": "recent", "label": "Most recent"},
    {"value": "oldest", "label": "Oldest"},
    {"value": "domain", "label": "Domain / pillar"},
    {"value": "firewall", "label": "Firewall"},
    {"value": "control", "label": "Control"},
]


def _repo(session=None):
    return InvestigationRepository(session or get_session())


def _canonical_repo(session=None):
    return CanonicalAssessmentsRepository(session or get_session())


def _clean_filters(args):
    """Normalise a request arg mapping into repository filters."""
    get = args.get if hasattr(args, "get") else lambda key, default=None: args.get(key, default)

    def pick(*names):
        for name in names:
            value = get(name)
            if value not in (None, ""):
                return str(value).strip()
        return ""

    filters = {
        "domain": pick("domain"),
        "assessment": pick("assessment", "assessment_id"),
        "firewall": pick("firewall", "device"),
        "pillar": pick("pillar"),
        "category": pick("category"),
        "status": pick("status"),
        "severity": pick("severity"),
        "risk": pick("risk", "risk_range", "riskRange"),
        "date": pick("date"),
        "sort": pick("sort") or "severity",
        "search": pick("search", "q"),
    }
    for key, value in list(filters.items()):
        if key == "sort" or key == "search":
            continue
        if value.lower() in ("", "all", "any"):
            filters[key] = "all"
    return filters


def attach_zero_trust_details(records, evidence_by_assessment=None):
    """Attach Cloud Security catalog, evidence tables, and links to Zero Trust rows."""
    evidence_by_assessment = evidence_by_assessment or {}
    for rec in records or []:
        if rec.get("domain") != "zero_trust":
            continue
        test = enrich_test(
            adapt_finding(
                {
                    "id": rec.get("control_id") or rec.get("control_name") or rec.get("id"),
                    "title": rec.get("title") or rec.get("control_name"),
                    "detail": rec.get("detail") or rec.get("finding"),
                    "pillar": rec.get("pillar"),
                    "category": rec.get("category"),
                    "status": rec.get("status"),
                    "severity": rec.get("severity"),
                    "remediation": rec.get("remediation"),
                },
                rec.get("completed_at"),
            ),
            evidence_by_assessment.get(rec.get("assessment_id")) or {},
        )
        rec["ms_details"] = {
            "id": test.get("id"),
            "name": test.get("name"),
            "risk": test.get("risk"),
            "status": test.get("status"),
            "userImpact": test.get("userImpact"),
            "implementationEffort": test.get("implementationEffort"),
            "license": test.get("license"),
            "whatWasChecked": test.get("whatWasChecked"),
            "howToCheck": test.get("howToCheck"),
            "controlSummary": test.get("controlSummary"),
            "whyItMatters": test.get("whyItMatters"),
            "baseline": test.get("baseline") or test.get("passRequirement"),
            "resultSummary": test.get("resultSummary"),
            "remediationActions": test.get("remediationActions") or [],
            "evidenceTables": test.get("evidenceTables") or [],
            "documentationUrl": test.get("documentationUrl"),
            "portalUrl": test.get("portalUrl"),
            "description": test.get("description"),
            "impact": test.get("impact"),
            "recommendation": test.get("recommendation"),
            "error": test.get("error"),
        }
    return records


def get_findings(args=None, session=None, limit=DEFAULT_LIMIT, offset=0):
    filters = _clean_filters(args or {})
    try:
        limit = int(limit or DEFAULT_LIMIT)
    except (TypeError, ValueError):
        limit = DEFAULT_LIMIT
    limit = max(1, min(limit, MAX_LIMIT))

    repo = _repo(session)
    records = repo.list_findings(filters, limit=limit, offset=offset)
    try:
        zt_ids = {
            rec.get("assessment_id")
            for rec in records
            if rec.get("domain") == "zero_trust" and rec.get("assessment_id")
        }
        evidence_by_assessment = {aid: repo.evidence_map(aid) for aid in zt_ids}
        attach_zero_trust_details(records, evidence_by_assessment)
    except Exception as exc:  # noqa: BLE001
        log.warning("Zero Trust finding details enrichment failed: %s", exc)
    summary = repo.summary(filters)
    facets = repo.facets()
    return {
        "records": records,
        "summary": summary,
        "facets": facets,
        "applied": filters,
        "status_vocabulary": STATUS_VOCABULARY,
        "risk_buckets": RISK_BUCKETS,
        "sorts": SORTS,
        "domains": [
            {"value": value, "label": label}
            for value, label in DOMAIN_LABELS.items()
        ],
    }


def get_options(session=None):
    repo = _repo(session)
    return {
        "facets": repo.facets(),
        "status_vocabulary": STATUS_VOCABULARY,
        "risk_buckets": RISK_BUCKETS,
        "sorts": SORTS,
        "domains": [
            {"value": value, "label": label}
            for value, label in DOMAIN_LABELS.items()
        ],
    }


def get_evidence(assessment_id, evidence_id=None, collector=None, pillar=None, session=None):
    """Evidence menu for a finding, plus one payload when a collector is given."""
    if not assessment_id:
        return {"error": "assessment_id is required."}, 400
    repo = _repo(session)
    entries = repo.evidence_entries(assessment_id, pillar=pillar)
    payload = None
    if evidence_id or collector:
        payload = repo.evidence_payload(
            assessment_id,
            evidence_id=evidence_id,
            collector=collector,
            pillar=pillar,
        )
    return {
        "assessment_id": assessment_id,
        "pillar": pillar,
        "entries": entries,
        "entry": payload,
        "available": bool(entries),
    }, 200


# ------------------------------------------------------------
# LEGACY SHAPE (AI Workspace firewall agent keeps working)
# ------------------------------------------------------------


def _stored_payload(firewall_id, session=None):
    """Stored canonical payload only - never triggers a collection."""
    try:
        return _canonical_repo(session).load_payload(firewall_id)
    except Exception as exc:  # noqa: BLE001 - degrade to empty
        log.warning("Canonical payload read failed: %s", exc)
        return None


def get_legacy_posture(firewall_id=None, session=None):
    """Return the historical ``/api/findings`` payload from stored data only."""
    firewall_id = (firewall_id or "vmpafw01").strip() or "vmpafw01"
    data = _stored_payload(firewall_id, session=session) or {}

    summary = dict(data.get("summary") or {})
    results = list(data.get("assessment") or [])
    findings = list(data.get("findings") or [])

    total = int(summary.get("total_controls") or len(results) or 0)
    compliant = int(summary.get("compliant") or 0)
    non_compliant = int(summary.get("non_compliant") or 0)
    not_assessed = int(summary.get("not_assessed") or 0)

    severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for item in findings:
        risk = (item.get("risk") or "").lower()
        if risk in severity:
            severity[risk] += 1

    inventory = dict(data.get("inventory") or {})
    collected_at = data.get("_collected_at")
    run_id = data.get("_run_id") or data.get("assessment_id")

    history = []
    try:
        repo = _canonical_repo(session)
        history = [
            repo.snapshot_from_row(row)
            for row in repo.list_completed(firewall_id, limit=200)
        ]
    except Exception as exc:  # noqa: BLE001
        log.warning("Canonical history read failed: %s", exc)

    posture = {
        "security_score": data.get("security_score"),
        "compliance_pct": round(compliant / total * 100, 1) if total else 0.0,
        "trend_pct": 0.0,
        "compliant": compliant,
        "non_compliant": non_compliant,
        "not_assessed": not_assessed,
        "total_controls": total,
        "severity": severity,
        "severity_change": {key: 0 for key in severity},
        "assessments_run": len(history),
        "run_id": run_id,
        "last_assessment_ts": data.get("_collected_at"),
        "collected_at": collected_at,
        "_source": data.get("_source", "stored"),
        "firewall_id": firewall_id,
    }

    firewall = {
        "hostname": inventory.get("hostname") or firewall_id,
        "model": inventory.get("model", ""),
        "version": inventory.get("version", ""),
        "serial": inventory.get("serial", ""),
    }

    return {
        "posture": posture,
        "firewall": firewall,
        "firewalls": [firewall],
        "findings": findings,
        "assessment": results,
        "history": history,
        "_source": data.get("_source", "stored"),
        "_collected_at": collected_at,
        "_firewall_id": firewall_id,
    }


__all__ = [
    "DEFAULT_LIMIT",
    "DOMAIN_LABELS",
    "MAX_LIMIT",
    "RISK_BUCKETS",
    "SORTS",
    "STATUS_VOCABULARY",
    "domain_label",
    "get_evidence",
    "get_findings",
    "get_legacy_posture",
    "get_options",
    "normalize_status",
    "status_label",
]
