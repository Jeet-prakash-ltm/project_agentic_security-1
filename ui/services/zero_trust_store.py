"""Zero Trust assessment reads served from PostgreSQL.

Canonical storage is ``assessments`` + ``assessment_findings`` +
``assessment_evidence`` (see ``CanonicalZeroTrustRepository``). The Function
App historically wrote only to ``zero_trust_assessments``, so this module also
reads that transitional table and mirrors any row it finds into canonical
storage on first access. That keeps history converging on the shared model
without a destructive migration.

The UI never depends on the Function App for rendering: every read below is a
database query. Writes originate from the assessment Function App.
"""

from __future__ import annotations

import logging

from database.db import get_session
from database.repositories import (
    CanonicalZeroTrustRepository,
    ZeroTrustRepository,
)
from services.zero_trust_adapter import adapt_assessment, sanitize_text

logger = logging.getLogger("zero_trust.store")


class ZeroTrustStoreError(RuntimeError):
    def __init__(self, message, status_code=404):
        super().__init__(message)
        self.status_code = status_code


def _canonical():
    return CanonicalZeroTrustRepository(get_session())


def _legacy():
    return ZeroTrustRepository(get_session())


def _iso(value):
    if value is None:
        return None
    try:
        return value.isoformat()
    except AttributeError:
        return str(value)


def _legacy_payload(row):
    """Rebuild the Function App report shape from a legacy row."""

    report = dict(row.report or {})
    summary = row.summary or {}
    evidence = row.evidence or {}

    findings = report.get("findings") or []
    pillars = report.get("pillars") or summary.get("pillars") or {}
    if pillars and "pillars" not in report:
        report["pillars"] = pillars

    for key in ("passed", "failed", "errors", "checks"):
        if key not in report and key in summary:
            report[key] = summary[key]

    if report.get("score") is None:
        report["score"] = row.score

    tenant_profile = evidence.get("tenant_profile") or {}
    return {
        "assessment_id": row.assessment_id,
        "status": row.status,
        "scope": row.scope,
        "progress": row.progress or 0,
        "message": row.message,
        "error": row.error,
        "score": row.score,
        "started_at": _iso(row.started_at),
        "updated_at": _iso(row.updated_at),
        "completed_at": _iso(row.completed_at),
        "tenant_id": row.tenant_id or evidence.get("tenant_id"),
        "subscription_id": row.subscription_id or evidence.get("subscription_id"),
        "tenant_name": tenant_profile.get("tenant_name"),
        "primary_domain": tenant_profile.get("primary_domain"),
        "users": tenant_profile.get("users"),
        "guests": tenant_profile.get("guests"),
        "groups": tenant_profile.get("groups"),
        "applications": tenant_profile.get("applications"),
        "summary": summary,
        "findings": findings,
        "pillars": pillars,
        "evidence": evidence,
        "report": report,
    }


def _summary_from_payload(payload):
    return {
        "assessmentId": payload.get("assessment_id") or payload.get("assessmentId"),
        "status": str(payload.get("status") or "queued").lower(),
        "progress": payload.get("progress") or 0,
        "message": sanitize_text(
            payload.get("message") or payload.get("error"), 240
        ),
        "score": payload.get("score"),
        "startedAt": payload.get("started_at"),
        "updatedAt": payload.get("updated_at"),
        "completedAt": payload.get("completed_at"),
        "error": sanitize_text(payload.get("error")),
    }


def sync_legacy(assessment_id):
    """Mirror one legacy ``zero_trust_assessments`` row into canonical tables.

    Returns the canonical payload, or ``None`` when the row does not exist.
    Safe to call repeatedly: canonical writes replace findings/evidence.
    """

    row = _legacy().get_assessment(assessment_id)
    if row is None:
        return None
    payload = _legacy_payload(row)
    try:
        _canonical().save_run(payload, user_id="zero-trust-function")
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Canonical mirror failed for %s: %s", assessment_id, exc)
        return None
    return _canonical().load_run(assessment_id)


def sync_missing(limit=200):
    """Mirror every legacy row that has no canonical counterpart."""

    mirrored = []
    for row in _legacy().list_assessments(limit=limit):
        if _canonical().get_row(row.assessment_id) is not None:
            continue
        if sync_legacy(row.assessment_id):
            mirrored.append(row.assessment_id)
    return mirrored


def _load(assessment_id):
    """Canonical payload first, legacy (mirrored) second."""

    payload = _canonical().load_run(assessment_id)
    if payload is not None:
        return payload
    return sync_legacy(assessment_id)


def _latest_legacy_row():
    rows = _legacy().list_assessments(limit=1)
    return rows[0] if rows else None


def _ts(value):
    if value is None:
        return None
    try:
        return value.timestamp()
    except AttributeError:
        return None


def latest_summary():
    """Summary of the most recent completed run, or ``None``.

    A run started from the UI lands in the transitional table first, so a
    newer legacy row is mirrored into canonical storage before reporting.
    """

    legacy_row = _latest_legacy_row()
    canonical_completed = _ts(_canonical().latest_completed_at())
    legacy_completed = _ts(legacy_row.completed_at) if legacy_row else None

    needs_mirror = legacy_row is not None and (
        canonical_completed is None
        or (legacy_completed is not None and legacy_completed > canonical_completed)
    )
    if needs_mirror:
        sync_legacy(legacy_row.assessment_id)

    payload = _canonical().latest_run()
    if payload is not None:
        return _summary_from_payload(payload)
    if legacy_row is None:
        return None
    mirrored = sync_legacy(legacy_row.assessment_id)
    return _summary_from_payload(mirrored or _legacy_payload(legacy_row))


def has_data():
    if _canonical().count():
        return True
    return _legacy().count() > 0


def latest_id():
    summary = latest_summary()
    return summary["assessmentId"] if summary else ""


def get_status(assessment_id, full=False):
    """Status for one assessment.

    The polled payload stays small: the full adapted assessment is only
    included when ``full`` is requested, which keeps status polling cheap.
    """

    payload = _load(assessment_id)
    if payload is None:
        raise ZeroTrustStoreError("Assessment was not found.", 404)
    result = _summary_from_payload(payload)
    if result["status"] == "completed" and full:
        result["assessment"] = adapt_assessment(payload)
    return result


def get_results(assessment_id):
    payload = _load(assessment_id)
    if payload is None:
        raise ZeroTrustStoreError("Assessment was not found.", 404)
    status = payload.get("status") or "queued"
    if status != "completed":
        return {
            "assessmentId": assessment_id,
            "status": status,
            "progress": payload.get("progress") or 0,
            "message": sanitize_text(
                payload.get("message") or "Report is not ready.", 240
            ),
            "error": sanitize_text(payload.get("error")),
            "assessment": None,
        }
    return {
        "assessmentId": assessment_id,
        "status": "completed",
        "progress": 100,
        "message": sanitize_text(
            payload.get("message") or "Assessment completed.", 240
        ),
        "assessment": adapt_assessment(payload),
    }


def latest_results():
    summary = latest_summary()
    if summary is None:
        return None
    return get_results(summary["assessmentId"])


def store_run(payload, user_id="zero-trust-function"):
    """Persist one Function App payload into canonical storage."""

    return _canonical().save_run(payload, user_id=user_id)


def available():
    try:
        return has_data()
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Zero Trust store unavailable: %s", exc)
        return False
