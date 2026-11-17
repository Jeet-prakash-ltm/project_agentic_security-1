"""Optional PostgreSQL persistence helpers for the netsec Function App."""

from dbwriter.persist import (
    get_firewall_by_selector,
    list_firewall_inventory,
    load_assessment_by_id,
    load_latest_assessment,
    log_activity,
    persist_assessment,
    persist_report,
    start_assessment,
)

__all__ = [
    "get_firewall_by_selector",
    "list_firewall_inventory",
    "load_assessment_by_id",
    "load_latest_assessment",
    "log_activity",
    "persist_assessment",
    "persist_report",
    "start_assessment",
]
