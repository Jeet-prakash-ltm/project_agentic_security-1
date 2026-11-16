"""Live firewall function client.

Calls the Azure Functions endpoints; when the live key is missing or the
endpoint rejects the call it falls back to the local assessment engines. Full
payloads returned by the live function are ingested into PostgreSQL
(``assessment_service.ingest_live_payload``) so runs are never lost.
"""

import time

import requests

from config import settings
from services import timeutil

TIMEOUT = 60


class LiveFunctionUnavailable(Exception):
    """Raised when the live firewall function cannot be called (missing key or 401/403)."""


def _key_usable(key):
    key = (key or "").strip()
    return bool(key) and not key.startswith("PLACEHOLDER")


def _get(endpoint, key=None, extra_params=None):
    key = key or settings.FUNCTION_KEY
    if not _key_usable(key):
        raise LiveFunctionUnavailable(
            "Live firewall function key is not configured."
        )

    params = {"code": key}
    if extra_params:
        for name, value in extra_params.items():
            if value is not None and value != "":
                params[name] = value

    response = requests.get(
        f"{settings.BASE_URL}/{endpoint}",
        params=params,
        timeout=TIMEOUT,
    )

    if response.status_code in (401, 403):
        raise LiveFunctionUnavailable(
            "Live firewall function rejected the access key (HTTP {0}).".format(
                response.status_code
            )
        )

    response.raise_for_status()
    return response.json()


def _refresh_cache(data):
    """Persist + cache the live assessment payload for the Security Ops pages."""
    import services.assessment_service as a

    data["_source"] = "live"
    data["_collected_at"] = timeutil.ist_now().isoformat()
    return a.ingest_live_payload(data)


def _local_assessment():
    import services.assessment_service as a
    return a.get_full_assessment(force=True)


def _local_executive_summary():
    import services.assessment_service as a
    return a.get_executive_summary(force=True)


def _local_excel_report():
    import services.assessment_service as a
    return a.get_excel_report(force=True)


def _firewall_params(kwargs):
    firewall = (
        kwargs.get("firewall")
        or kwargs.get("firewall_id")
        or kwargs.get("firewall_name")
        or kwargs.get("selected_firewall")
        or kwargs.get("hostname")
        or kwargs.get("scope")
    )
    if not firewall:
        return None
    return {"firewall": firewall}


def run_compliance_assessment(**kwargs):
    extra = _firewall_params(kwargs)
    try:
        data = _get("run_compliance_assessment", extra_params=extra)
    except LiveFunctionUnavailable:
        return _local_assessment()
    if isinstance(data, dict) and data.get("findings") and data.get("status") not in (
        "AWAITING_FIREWALL_SELECTION",
        "FIREWALL_DOWN",
    ):
        _refresh_cache(data)
    return data


def run_full_assessment(**kwargs):
    extra = _firewall_params(kwargs)
    try:
        data = _get(
            "run_full_assessment",
            key=settings.FULL_ASSESSMENT_KEY,
            extra_params=extra,
        )
    except LiveFunctionUnavailable:
        return _local_assessment()
    if isinstance(data, dict) and data.get("findings") and data.get("status") not in (
        "AWAITING_FIREWALL_SELECTION",
        "FIREWALL_DOWN",
    ):
        _refresh_cache(data)
    return data


def executive_summary(**kwargs):
    extra = _firewall_params(kwargs)
    try:
        return _get(
            "executive_summary",
            key=settings.EXECUTIVE_SUMMARY_KEY,
            extra_params=extra,
        )
    except LiveFunctionUnavailable:
        return _local_executive_summary()


def generate_excel_report(**kwargs):
    extra = _firewall_params(kwargs)
    try:
        return _get(
            "generate_excel_report",
            key=settings.EXCEL_KEY,
            extra_params=extra,
        )
    except LiveFunctionUnavailable:
        return _local_excel_report()
