"""Parse firewall audit/compliance payloads for AI Workspace cards.

The Function App returns JSON with ``response_type``. Hosted Foundry agents
often echo that JSON (or a markdown summary) in the chat reply. This module
extracts a structured payload so the workspace can render cards before the
chat bubble.
"""

import json
import re

AUDIT_RESPONSE_TYPES = {
    "firewall_selection",
    "firewall_down",
    "firewall_assessment",
    "executive_summary",
}

_FENCE_RE = re.compile(
    r"```[ \t]*([A-Za-z0-9_\-]*)[ \t]*\r?\n(.*?)```",
    re.DOTALL,
)


def is_audit_payload(payload):
    if not isinstance(payload, dict):
        return False
    response_type = str(payload.get("response_type") or "").strip()
    if response_type in AUDIT_RESPONSE_TYPES:
        return True
    status = str(payload.get("status") or "").strip().upper()
    if status in ("AWAITING_FIREWALL_SELECTION", "FIREWALL_DOWN"):
        return True
    if payload.get("findings") and (
        payload.get("summary") or payload.get("inventory") or payload.get("assessment")
    ):
        return True
    if payload.get("top_findings") and payload.get("device"):
        return True
    if payload.get("firewalls") and payload.get("action_required"):
        return True
    return False


def normalize_audit_payload(payload):
    if not is_audit_payload(payload):
        return None
    data = dict(payload)
    status = str(data.get("status") or "").strip().upper()
    response_type = str(data.get("response_type") or "").strip()
    if not response_type:
        if status == "AWAITING_FIREWALL_SELECTION" or data.get("action_required") == "select_firewall":
            response_type = "firewall_selection"
        elif status == "FIREWALL_DOWN":
            response_type = "firewall_down"
        elif data.get("top_findings") is not None and data.get("device"):
            response_type = "executive_summary"
        else:
            response_type = "firewall_assessment"
        data["response_type"] = response_type
    return data


def _try_json(text):
    if not text or not isinstance(text, str):
        return None
    trimmed = text.strip()
    if not trimmed:
        return None
    try:
        parsed = json.loads(trimmed)
    except (TypeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _extract_json_objects(text):
    payloads = []
    if not text:
        return payloads
    for match in _FENCE_RE.finditer(text):
        parsed = _try_json(match.group(2) or "")
        if parsed:
            payloads.append(parsed)
    stripped = _FENCE_RE.sub("", text)
    start = stripped.find("{")
    while start != -1:
        depth = 0
        in_string = False
        escape = False
        end = None
        for index in range(start, len(stripped)):
            char = stripped[index]
            if in_string:
                if escape:
                    escape = False
                elif char == "\\":
                    escape = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
                continue
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    end = index + 1
                    break
        if end is None:
            break
        parsed = _try_json(stripped[start:end])
        if parsed:
            payloads.append(parsed)
        start = stripped.find("{", end)
    return payloads


def extract_audit_payload(text, tool_payload=None):
    if is_audit_payload(tool_payload):
        return normalize_audit_payload(tool_payload)
    for candidate in _extract_json_objects(text or ""):
        normalized = normalize_audit_payload(candidate)
        if normalized:
            return normalized
    return None
