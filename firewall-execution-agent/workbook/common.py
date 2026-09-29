"""Shared helpers for the netsec execution services."""

import re

from workbook.xmlutil import entry_xml, member_list_xml, xml_escape

# Canonical action column used by every playbook sheet. Each row is executed
# as one of these operations against the firewall candidate configuration.
ACTIONS = ("create", "update", "delete")

_XPATH_BASE = (
    "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"
)
_NETWORK_XPATH = "/config/devices/entry[@name='localhost.localdomain']/network"


def vsys_base():
    return _XPATH_BASE


def network_base():
    return _NETWORK_XPATH


def to_text(value):
    """Normalise a spreadsheet cell to trimmed text."""
    if value is None:
        return ""
    text = str(value).strip()
    return text


def split_members(value):
    """Split a cell that may hold several members (newline/comma/semicolon)."""
    text = to_text(value)
    if not text:
        return []
    parts = re.split(r"[\n,;]+", text)
    members = []
    for part in parts:
        part = part.strip()
        if part and part not in members:
            members.append(part)
    return members


def normalize_action(value, default="create"):
    """Normalise a per-row action value to create/update/delete."""
    action = to_text(value).lower() or default
    if action in ("add", "new", "set"):
        return "create"
    if action in ("edit", "modify", "change"):
        return "update"
    if action in ("remove", "del"):
        return "delete"
    if action in ACTIONS:
        return action
    raise ValueError(
        "Unsupported action {0!r} (expected create, update or delete).".format(
            to_text(value)
        )
    )


def csv_list(value):
    """Normalise a cell holding a single value or a CSV list (not XML members)."""
    text = to_text(value)
    if not text:
        return ""
    return text


def ensure(required, row):
    """Raise a clear error when a required column value is missing."""
    missing = [key for key in required if not to_text(row.get(key))]
    if missing:
        raise ValueError(
            "Missing required column(s): {0}".format(", ".join(missing))
        )
