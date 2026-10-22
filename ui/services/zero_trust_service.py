"""Server-side proxy for the Zero Trust Assessment Function App.

The browser never receives the Function key. All start/status/report calls
go through authenticated Flask routes.
"""

from __future__ import annotations

import logging
import os

import requests

from config import settings
from services.zero_trust_adapter import adapt_assessment, sanitize_text

logger = logging.getLogger("zero_trust.service")

DEFAULT_FUNCTION_URL = "https://zero-trust-assessment.azurewebsites.net/api"
_KEY_NAMES = (
    "ZERO_TRUST_FUNCTION_KEY",
    "ZERO_TRUST_KEY",
    "ZT_FUNCTION_KEY",
    "ZERO_TRUST_ASSESSMENT_KEY",
    "ZERO_TRUST_HOST_KEY",
)
_URL_NAMES = (
    "ZERO_TRUST_FUNCTION_URL",
    "ZERO_TRUST_URL",
    "ZT_FUNCTION_URL",
    "ZERO_TRUST_ASSESSMENT_URL",
)


class ZeroTrustError(RuntimeError):
    def __init__(self, message, status_code=502, retry_after=None):
        super().__init__(message)
        self.status_code = status_code
        self.retry_after = retry_after


def _env_first(names, fallback=""):
    for name in names:
        value = (os.environ.get(name) or "").strip()
        if value:
            return value
    return (fallback or "").strip()


def _normalize_base_url(url):
    url = (url or "").strip().rstrip("/")
    if not url:
        return DEFAULT_FUNCTION_URL
    if url.endswith("/api"):
        return url
    return url + "/api"


def _base_url():
    fallback = getattr(settings, "ZERO_TRUST_FUNCTION_URL", "") or DEFAULT_FUNCTION_URL
    return _normalize_base_url(_env_first(_URL_NAMES, fallback))


def _function_key():
    fallback = getattr(settings, "ZERO_TRUST_FUNCTION_KEY", "")
    return _env_first(_KEY_NAMES, fallback)


def _key_usable(key):
    key = (key or "").strip()
    return bool(key) and not key.upper().startswith("PLACEHOLDER")


def configured():
    return bool(_base_url()) and _key_usable(_function_key())


def _timeout():
    raw = os.environ.get("ZERO_TRUST_FUNCTION_TIMEOUT")
    if raw is None or not str(raw).strip():
        raw = getattr(settings, "ZERO_TRUST_FUNCTION_TIMEOUT", 120)
    try:
        return max(5, int(raw))
    except (TypeError, ValueError):
        return 120


def _request(path, body=None):
    if not configured():
        raise ZeroTrustError(
            "The Zero Trust Assessment service is not configured "
            "(ZERO_TRUST_FUNCTION_URL / ZERO_TRUST_FUNCTION_KEY).",
            503,
        )
    headers = {
        "Content-Type": "application/json",
        "x-functions-key": _function_key(),
    }
    query = {"code": _function_key()}
    url = "{0}/{1}".format(_base_url(), path.lstrip("/"))
    try:
        response = requests.post(
            url,
            headers=headers,
            params=query,
            json=body or {},
            timeout=_timeout(),
        )
    except requests.RequestException as exc:
        raise ZeroTrustError(
            "Could not reach the Zero Trust Assessment service."
        ) from exc

    retry_after = response.headers.get("Retry-After")
    try:
        data = response.json()
    except ValueError:
        data = {}

    if response.status_code == 429:
        raise ZeroTrustError(
            "The Zero Trust Assessment service is throttled. Try again shortly.",
            429,
            retry_after=retry_after,
        )
    if response.status_code in (401, 403):
        raise ZeroTrustError(
            "The Zero Trust Assessment service rejected the request.",
            response.status_code,
        )
    if response.status_code == 404:
        raise ZeroTrustError(
            sanitize_text(data.get("message") or "Assessment was not found.")
            or "Assessment was not found.",
            404,
        )
    if response.status_code == 409:
        raise ZeroTrustError(
            sanitize_text(data.get("message") or "An assessment is already running.")
            or "An assessment is already running.",
            409,
        )
    if response.status_code >= 400:
        raise ZeroTrustError(
            sanitize_text(
                data.get("message")
                or data.get("error")
                or "Zero Trust Assessment request failed."
            )
            or "Zero Trust Assessment request failed.",
            response.status_code if response.status_code < 600 else 502,
        )
    if not isinstance(data, dict):
        raise ZeroTrustError("Unexpected response from the Zero Trust Assessment service.")
    return data, retry_after


def start_assessment(force=False, scope="tenant"):
    data, _retry = _request(
        "StartZeroTrustAssessment",
        {"scope": scope or "tenant", "force": bool(force)},
    )
    return {
        "assessmentId": data.get("assessment_id") or data.get("assessmentId"),
        "status": str(data.get("status") or "queued").lower(),
        "progress": data.get("progress") or 0,
        "message": sanitize_text(data.get("message"), 240),
        "cached": bool(data.get("cached")),
        "startedAt": data.get("started_at") or data.get("startedAt"),
        "completedAt": data.get("completed_at") or data.get("completedAt"),
        "score": data.get("score"),
    }


def get_status(assessment_id, full=False):
    if not assessment_id:
        raise ZeroTrustError("assessment_id is required.", 400)
    body = {"assessment_id": assessment_id}
    if full:
        body["full"] = True
    data, retry_after = _request("GetAssessmentStatus", body)
    status = str(data.get("status") or "").lower() or "queued"
    result = {
        "assessmentId": data.get("assessment_id") or assessment_id,
        "status": status,
        "progress": data.get("progress") or 0,
        "message": sanitize_text(data.get("message"), 240),
        "score": data.get("score"),
        "startedAt": data.get("started_at"),
        "completedAt": data.get("completed_at"),
        "error": sanitize_text(data.get("error")),
        "retryAfter": retry_after,
    }
    if status == "completed" and (full or data.get("findings")):
        result["assessment"] = adapt_assessment(data)
    return result


def get_results(assessment_id):
    if not assessment_id:
        raise ZeroTrustError("assessment_id is required.", 400)
    data, _retry = _request("GetAssessmentReport", {"assessment_id": assessment_id})
    status = str(data.get("status") or "").lower()
    if status != "completed":
        return {
            "assessmentId": assessment_id,
            "status": status or "running",
            "progress": data.get("progress") or 0,
            "message": sanitize_text(data.get("message") or "Report is not ready.", 240),
            "error": sanitize_text(data.get("error")),
            "assessment": None,
        }
    return {
        "assessmentId": assessment_id,
        "status": "completed",
        "progress": 100,
        "message": sanitize_text(data.get("message") or "Assessment completed.", 240),
        "assessment": adapt_assessment(data),
    }
