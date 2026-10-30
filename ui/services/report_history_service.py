"""Report history service backed by ``reports_history`` (formerly reports_history.json).

Report rows are owned by a user (``user_id``) so history is never shared
between accounts. Legacy rows created before multi-tenancy are reclaimed to
the seeded administrator at startup.

Each row also records the ``firewall`` it was generated for so the Reports
page can filter history by estate device. Estate-wide rows use the sentinel
``"estate"``. Rows that predate the column are inferred from the stored
filename/download URL where possible.
"""

import os
import re

from database.db import get_session
from database.repositories import ReportsRepository

ESTATE_FIREWALL = "estate"

_NAME_SUMMARY_RE = re.compile(r"^Executive_Summary_([A-Za-z0-9_-]+?)_")
_URL_WORKBOOK_RE = re.compile(r"^([A-Za-z0-9_-]+?)_Assessment_Workbook\.xlsx$")


def _repo():
    return ReportsRepository(get_session())


def _infer_firewall(name, download_url):
    """Best-effort firewall for rows recorded before the column existed."""
    name = name or ""
    download_url = download_url or ""

    if "Full_Inventory" in download_url or "Full_Inventory" in name:
        return ESTATE_FIREWALL

    base = os.path.basename(download_url.split("?")[0])
    match = _URL_WORKBOOK_RE.search(base)
    if match:
        return match.group(1)

    match = _NAME_SUMMARY_RE.search(name)
    if match:
        return match.group(1)

    return None


def append_report(report, user_id=None):
    if not report.get("firewall"):
        report = dict(report)
        report["firewall"] = _infer_firewall(
            report.get("name"), report.get("download_url")
        )
    _repo().append_report(report, user_id=user_id)


def list_reports(user_id=None):
    reports = _repo().list_reports(user_id=user_id)
    return [
        {
            "id": report.id,
            "name": report.name,
            "type": report.type,
            "generated_by": report.generated_by,
            "firewall": report.firewall
            or _infer_firewall(report.name, report.download_url),
            "ts": report.ts,
            "status": report.status,
            "size": report.size,
            "download_url": report.download_url,
            "assessment_id": report.assessment_id,
            "security_domain": report.security_domain,
        }
        for report in reports
    ]
