"""Optional PostgreSQL persistence helpers for the netsec Function App."""

from dbwriter.persist import (
    load_latest_assessment,
    log_activity,
    persist_assessment,
    persist_report,
)

__all__ = [
    "load_latest_assessment",
    "log_activity",
    "persist_assessment",
    "persist_report",
]
