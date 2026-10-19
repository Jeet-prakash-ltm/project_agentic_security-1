"""Route Maestro chat approvals onto the Firewall Execution Agent job pipeline.

Maestro collects and confirms the change in AI Workspace. After one Approve
the platform creates a ``firewall_jobs`` row, auto-approves it (the chat
confirm *is* the approval), and FEAT's Service Bus worker applies, commits
and polls PAN-OS. The Jobs page reads that ledger for live status.
"""

import logging
import re
import time

from gateway import interactive_blocks
from services import automation_jobs_service
from services import firewall_jobs_service

logger = logging.getLogger("maestro.firewall.jobs")

FIREWALL_DOWN_MESSAGE = "cannot proceed firewall is down"
JOBS_NOTICE = "Change is registered in Jobs section"

APPROVE_WORDS = frozenset(
    (
        "approve",
        "approved",
        "yes",
        "y",
        "ok",
        "okay",
        "confirm",
        "confirmed",
        "proceed",
        "go ahead",
        "do it",
        "apply",
        "create object",
        "apply change",
    )
)

REJECT_WORDS = frozenset(
    (
        "cancel",
        "cancelled",
        "canceled",
        "no",
        "n",
        "reject",
        "rejected",
        "deny",
        "stop",
        "don't",
        "do not",
    )
)

CATEGORY_LABELS = {
    "address": "Address Object",
    "address_group": "Address Group",
    "service": "Service Object",
    "service_group": "Service Group",
    "zone": "Zone",
    "virtual_router": "Virtual Router",
    "static_route": "Static Route",
    "interface": "Interface",
    "interface_mgmt_profile": "Interface Management Profile",
    "security_rule": "Security Rule",
    "nat_rule": "NAT Rule",
}

CATEGORY_KEYWORDS = (
    ("nat_rule", ("nat rule", "nat policy", "natrule", "nat ")),
    ("security_rule", (
        "security rule", "security policy", "firewall rule",
        "securityrule", "allow rule", "deny rule",
    )),
    ("static_route", ("static route", "staticroute")),
    ("interface_mgmt_profile", (
        "management profile", "mgmt profile", "interface management",
    )),
    ("address_group", ("address group", "addr group", "addressgroup")),
    ("service_group", ("service group", "svc group", "servicegroup")),
    ("virtual_router", ("virtual router", "virtualrouter")),
    ("service", ("service object", "tcp service", "udp service")),
    ("interface", ("interface ", "ethernet", "loopback", "tunnel")),
    ("zone", (" zone", "zone named", "create zone", "update zone", "delete zone")),
    ("address", (
        "address object", "host object", "address named", "create object",
        "create address", "update object", "delete object", "fqdn",
        "ip-netmask", "ip address",
    )),
)

FIELD_ALIASES = {
    "name": "Name",
    "objectname": "Name",
    "rulename": "Name",
    "addressname": "Name",
    "action": "Action",
    "addresstype": "Address Type",
    "type": "Address Type",
    "addressvalue": "Address Value",
    "ip": "Address Value",
    "ipaddress": "Address Value",
    "value": "Address Value",
    "fqdn": "Address Value",
    "host": "Address Value",
    "description": "Description",
    "desc": "Description",
    "comment": "Description",
    "tags": "Tags",
    "tag": "Tags",
    "members": "Members",
    "member": "Members",
    "grouptype": "Group Type",
    "protocol": "Protocol",
    "port": "Port",
    "destinationport": "Port",
    "sourceport": "Source Port",
    "from": "From",
    "fromzone": "From",
    "sourcezone": "From",
    "to": "To",
    "tozone": "To",
    "destinationzone": "To",
    "source": "Source",
    "destination": "Destination",
    "users": "Users",
    "applications": "Applications",
    "application": "Applications",
    "services": "Services",
    "service": "Service",
    "categories": "Categories",
    "ruleaction": "Rule Action",
    "permit": "Rule Action",
    "nattype": "NAT Type",
    "sourcetranslation": "Source Translation",
    "translatedinterface": "Translated Interface",
    "sourcetranslatedaddress": "Source Translated Address",
    "destinationtranslatedaddress": "Destination Translated Address",
    "destinationtranslatedport": "Destination Translated Port",
    "virtualrouter": "Virtual Router",
    "vr": "Virtual Router",
    "nexthop": "Next Hop",
    "nexthoptype": "Next Hop Type",
    "metric": "Metric",
    "interface": "Interface",
    "interfaces": "Interfaces",
    "ipaddresses": "IP Addresses",
    "managementprofile": "Management Profile",
    "mtu": "MTU",
    "zonetype": "Type",
    "disabled": "Disabled",
}

_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)"
    r"(?:/(?:3[0-2]|[12]?\d))?\b"
)
_IP_RANGE_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)"
    r"\s*-\s*"
    r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
)
_QUOTED_NAME_RE = re.compile(
    r"(?:object|named|called|name)\s+[\"'`]([^\"'`]{1,63})[\"'`]",
    re.IGNORECASE,
)
_OBJECT_NAME_RE = re.compile(
    r"(?:object|named|called)\s+([A-Za-z0-9][A-Za-z0-9 ._-]{0,62}?)"
    r"(?=\s+with\b|\s+ip\b|\s+address\b|\s+for\b|\s+from\b|\s+to\b|$)",
    re.IGNORECASE,
)
_CREATE_NAME_RE = re.compile(
    r"\b(?:create|add|update|delete|remove)\s+"
    r"(?:(?:an?|the|this|that)\s+)*"
    r"(?:address\s+object|host\s+object|object|rule|policy|zone|service)\s+"
    r"[\"'`]?([A-Za-z0-9][A-Za-z0-9._-]{0,62})[\"'`]?",
    re.IGNORECASE,
)
_OBJECT_TOKEN = r"(?:[A-Za-z][A-Za-z0-9]*[ ])?[A-Za-z][A-Za-z0-9]*[-_][A-Za-z0-9._-]{1,60}"
_DELETE_THIS_NAME_RE = re.compile(
    r"\b(?:delete|remove)\s+(?:(?:an?|the|this|that|object|address|host)\s+)*"
    r"[\"'` ]?(?P<name>" + _OBJECT_TOKEN + r")[\"'`]?",
    re.IGNORECASE,
)
_BARE_OBJECT_NAME_RE = re.compile(
    r"\b(" + _OBJECT_TOKEN + r")\b",
    re.IGNORECASE,
)
_INLINE_LABELS = (
    "Object name",
    "Address name",
    "Rule name",
    "IP address",
    "Address value",
    "Address type",
    "Description",
    "Source",
    "Destination",
    "Protocol",
    "Members",
    "Action",
    "Name",
    "From",
    "To",
    "Port",
    "Tags",
    "Tag",
)
_INLINE_LABEL_RE = re.compile(
    r"(?i)\b("
    + "|".join(re.escape(label) for label in sorted(_INLINE_LABELS, key=len, reverse=True))
    + r")\s*:\s*(.+?)(?=\s+(?:"
    + "|".join(re.escape(label) for label in sorted(_INLINE_LABELS, key=len, reverse=True))
    + r")\s*:|$)"
)
_NAME_STOPWORDS = frozenset(
    (
        "a", "an", "the", "this", "that", "it", "now", "please", "ok", "okay",
        "object", "address", "host", "rule", "policy", "zone", "service",
        "group", "named", "called", "name", "ip", "with", "from", "to",
    )
)
_SERVICE_NAME_RE = re.compile(
    r"\b(?:tcp|udp|sctp)?\s*service\s+[\"'`]?([A-Za-z0-9._-]{1,63})[\"'`]?",
    re.IGNORECASE,
)
_RULE_NAME_RE = re.compile(
    r"(?:rule|policy)\s+[\"'`]?([A-Za-z0-9._-]{1,63})[\"'`]?",
    re.IGNORECASE,
)
_ZONE_PAIR_RE = re.compile(
    r"\bfrom\s+([A-Za-z0-9._-]+)\s+to\s+([A-Za-z0-9._-]+)\b",
    re.IGNORECASE,
)
_SOURCE_RE = re.compile(
    r"\bsource\s+([A-Za-z0-9._/-]+)\b",
    re.IGNORECASE,
)
_DEST_RE = re.compile(
    r"\bdestination\s+([A-Za-z0-9._/-]+)\b",
    re.IGNORECASE,
)
_PROTO_RE = re.compile(r"\b(tcp|udp|sctp)\b", re.IGNORECASE)
_PORT_RE = re.compile(r"\bport\s+(\d{1,5}(?:-\d{1,5})?)\b", re.IGNORECASE)
_RULE_ACTION_RE = re.compile(
    r"\b(allow|deny|drop|reset-client|reset-server|reset-both)\b",
    re.IGNORECASE,
)


def _norm_key(value):
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def _clean(value, limit=255):
    return str(value or "").strip()[:limit]


def _normalize_name(value):
    text = _clean(value, 63)
    text = re.sub(r"[^A-Za-z0-9._-]+", "-", text)
    return text.strip("-")[:63]


def _is_maestro(agent):
    if not agent:
        return False
    text = " ".join(
        [
            str(agent.get("type") or ""),
            str(agent.get("name") or ""),
            str(agent.get("id") or ""),
            str(agent.get("agent_id") or ""),
        ]
    ).lower()
    return any(
        token in text
        for token in ("maestro", "orchestrat", "execution", "netsec")
    )


def _folded(text):
    return re.sub(r"\s+", " ", (text or "").strip().lower())


def is_approval(text):
    folded = _folded(text).rstrip(".!")
    if folded in APPROVE_WORDS:
        return True
    first = folded.split(" ", 1)[0]
    return first in ("approve", "approved", "confirm", "confirmed", "yes")


def is_rejection(text):
    return _folded(text).rstrip(".!") in REJECT_WORDS


def _detect_action(text):
    low = (text or "").lower()
    if re.search(r"\b(delete|remove|drop object)\b", low):
        return "delete"
    if re.search(r"\b(update|edit|modify|change)\b", low):
        return "update"
    return "create"


def _detect_category(text):
    low = " {0} ".format((text or "").lower())
    for category, keywords in CATEGORY_KEYWORDS:
        if any(keyword in low for keyword in keywords):
            return category
    if _IP_RE.search(text or "") or _IP_RANGE_RE.search(text or ""):
        return "address"
    if re.search(r"\b(create|add|update|delete|object|rule|policy)\b", low):
        return "address"
    return None


def _fields_from_labeled_lines(text):
    fields = {}
    blob = text or ""
    for match in _INLINE_LABEL_RE.finditer(blob):
        header = FIELD_ALIASES.get(_norm_key(match.group(1)))
        if not header:
            continue
        value = match.group(2).strip()
        if value:
            fields[header] = value[:255]
    return fields


def _usable_name(value):
    name = (value or "").strip().strip("\"'`")
    if not name:
        return ""
    if name.lower() in _NAME_STOPWORDS:
        return ""
    return name


def _extract_name(text, category):
    quoted = _QUOTED_NAME_RE.search(text or "")
    if quoted:
        name = _usable_name(quoted.group(1))
        if name:
            return name
    if category in ("security_rule", "nat_rule"):
        match = _RULE_NAME_RE.search(text or "")
        if match:
            name = _usable_name(match.group(1))
            if name:
                return name
    if category == "service":
        match = _SERVICE_NAME_RE.search(text or "")
        if match:
            name = _usable_name(match.group(1))
            if name:
                return name
    match = _OBJECT_NAME_RE.search(text or "")
    if match:
        name = _usable_name(match.group(1))
        if name:
            return name
    match = _DELETE_THIS_NAME_RE.search(text or "")
    if match:
        name = _usable_name(match.group(1))
        if name:
            return name
    match = _CREATE_NAME_RE.search(text or "")
    if match:
        name = _usable_name(match.group(1))
        if name:
            return name
    match = _BARE_OBJECT_NAME_RE.search(text or "")
    if match:
        name = _usable_name(match.group(1))
        if name:
            return name
    return ""


def _address_value(text):
    ranged = _IP_RANGE_RE.search(text or "")
    if ranged:
        return re.sub(r"\s+", "", ranged.group(0)), "ip-range"
    ip_match = _IP_RE.search(text or "")
    if ip_match:
        value = ip_match.group(0)
        if "/" not in value:
            value = "{0}/32".format(value)
        return value, "ip-netmask"
    fqdn = re.search(
        r"\b(?:fqdn|hostname)\s+([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b",
        text or "",
        re.IGNORECASE,
    )
    if fqdn:
        return fqdn.group(1), "fqdn"
    return "", ""


def parse_firewall_change(text):
    """Parse a chat utterance into a structured FEAT change, or None."""
    text = (text or "").strip()
    if not text or is_approval(text) or is_rejection(text):
        return None

    fields = _fields_from_labeled_lines(text)
    category = _detect_category(text)
    if not category and fields:
        if "Address Value" in fields or "Address Type" in fields:
            category = "address"
        elif "Rule Action" in fields or "From" in fields:
            category = "security_rule"
        elif "NAT Type" in fields:
            category = "nat_rule"
        elif "Protocol" in fields or "Port" in fields:
            category = "service"
        elif "Virtual Router" in fields:
            category = "static_route"
    if not category:
        return None

    action = _detect_action(text)
    name = fields.pop("Name", "") or _extract_name(text, category)
    if category == "interface" and not name:
        name = fields.get("Interface") or ""

    if category == "address":
        if "Address Value" not in fields:
            value, kind = _address_value(text)
            if value:
                fields["Address Value"] = value
                fields.setdefault("Address Type", kind)
        elif "Address Type" not in fields:
            value = fields.get("Address Value") or ""
            if _IP_RANGE_RE.search(value):
                fields["Address Type"] = "ip-range"
            elif _IP_RE.search(value):
                fields["Address Type"] = "ip-netmask"
                if "/" not in value:
                    fields["Address Value"] = "{0}/32".format(value)
            else:
                fields["Address Type"] = "fqdn"

    if category == "security_rule":
        zones = _ZONE_PAIR_RE.search(text)
        if zones:
            fields.setdefault("From", zones.group(1))
            fields.setdefault("To", zones.group(2))
        source = _SOURCE_RE.search(text)
        if source:
            fields.setdefault("Source", source.group(1))
        dest = _DEST_RE.search(text)
        if dest:
            fields.setdefault("Destination", dest.group(1))
        rule_action = _RULE_ACTION_RE.search(text)
        if rule_action:
            fields.setdefault("Rule Action", rule_action.group(1).lower())
        fields.setdefault("Rule Action", "allow")

    if category == "service":
        proto = _PROTO_RE.search(text)
        if proto:
            fields.setdefault("Protocol", proto.group(1).lower())
        port = _PORT_RE.search(text)
        if port:
            fields.setdefault("Port", port.group(1))

    if name:
        fields["Name"] = name
    if category == "interface" and name:
        fields.setdefault("Interface", name)

    required_ok = True
    if action != "delete" and not (name or fields.get("Interface")):
        required_ok = False
    if action != "delete":
        if category == "address" and not fields.get("Address Value"):
            required_ok = False
        elif category == "service" and not (
            fields.get("Protocol") and (fields.get("Port") or fields.get("Source Port"))
        ):
            required_ok = False
        elif category in ("address_group", "service_group") and not fields.get("Members"):
            required_ok = False

    if not required_ok:
        return None

    object_name = _normalize_name(name or fields.get("Interface") or "")
    if object_name:
        fields["Name"] = object_name
        if category == "interface":
            fields["Interface"] = object_name

    label = CATEGORY_LABELS.get(category, category.replace("_", " ").title())
    summary = "{0} {1} {2}".format(action.capitalize(), label.lower(), object_name).strip()
    return {
        "category": category,
        "action": action,
        "name": object_name,
        "fields": fields,
        "summary": summary,
        "label": label,
    }


class _CaptureClient(object):
    """Record the xpath/element a playbook handler would send to PAN-OS."""

    dry_run = True
    host = ""

    def __init__(self):
        self.action = None
        self.xpath = None
        self.element = None

    def set(self, xpath, element):
        self.action = "set"
        self.xpath = xpath
        self.element = element
        return {"dry_run": True, "op": "create", "xpath": xpath}

    def edit(self, xpath, element):
        self.action = "edit"
        self.xpath = xpath
        self.element = element
        return {"dry_run": True, "op": "update", "xpath": xpath}

    def delete(self, xpath):
        self.action = "delete"
        self.xpath = xpath
        self.element = None
        return {"dry_run": True, "op": "delete", "xpath": xpath}

    def commit(self, description=None):
        return {"dry_run": True, "action": "commit"}


_HANDLERS = None


def _handlers():
    global _HANDLERS
    if _HANDLERS is None:
        from netsec_execution.services.network import (
            apply_interface_management_profiles,
            apply_interfaces,
            apply_static_routes,
            apply_virtual_routers,
            apply_zones,
        )
        from netsec_execution.services.objects import (
            apply_address_groups,
            apply_addresses,
            apply_service_groups,
            apply_services,
        )
        from netsec_execution.services.policies import (
            apply_nat_rules,
            apply_security_rules,
        )

        _HANDLERS = {
            "address": apply_addresses,
            "address_group": apply_address_groups,
            "service": apply_services,
            "service_group": apply_service_groups,
            "zone": apply_zones,
            "virtual_router": apply_virtual_routers,
            "static_route": apply_static_routes,
            "interface": apply_interfaces,
            "interface_mgmt_profile": apply_interface_management_profiles,
            "security_rule": apply_security_rules,
            "nat_rule": apply_nat_rules,
        }
    return _HANDLERS


def build_requested_payload(change):
    """Build a FEAT apply_change payload (xpath + structured fields)."""
    handler = _handlers().get(change["category"])
    if handler is None:
        raise ValueError("Unsupported firewall change: {0}.".format(change["category"]))
    row = dict(change.get("fields") or {})
    row["Action"] = change["action"]
    if change.get("name"):
        row.setdefault("Name", change["name"])
        if change["category"] == "interface":
            row.setdefault("Interface", change["name"])
    client = _CaptureClient()
    handler(client, row)
    if not client.action or not client.xpath:
        raise ValueError("Could not build a firewall configuration change.")
    payload = {
        "action": client.action,
        "xpath": client.xpath,
        "category": change["category"],
        "name": change["name"],
        "row_action": change["action"],
        "fields": change.get("fields") or {},
        "summary": change.get("summary") or "",
    }
    if client.element:
        payload["element"] = client.element
    return payload


def _named_change_from_history(messages, skip_content=None):
    skip = _folded(skip_content or "")
    for item in reversed(messages or []):
        role = (item.get("role") or "").lower()
        content = (item.get("content") or "").strip()
        if role != "user" or not content:
            continue
        if is_approval(content) or is_rejection(content):
            continue
        if skip and _folded(content) == skip:
            continue
        parsed = parse_firewall_change(content)
        if parsed and parsed.get("name"):
            return parsed
    return None


def _with_history_name(change, messages, skip_content=None):
    if not change or change.get("name"):
        return change
    prior = _named_change_from_history(messages, skip_content=skip_content)
    name = (prior or {}).get("name") or ""
    if not name:
        return None
    fields = dict(change.get("fields") or {})
    fields["Name"] = name
    if change.get("category") == "interface":
        fields.setdefault("Interface", name)
    label = change.get("label") or CATEGORY_LABELS.get(
        change.get("category"), "object"
    )
    change = dict(change)
    change["name"] = name
    change["fields"] = fields
    change["summary"] = "{0} {1} {2}".format(
        (change.get("action") or "change").capitalize(),
        str(label).lower(),
        name,
    ).strip()
    return change


def pending_change_from_history(messages):
    user_texts = []
    for item in reversed(messages or []):
        role = (item.get("role") or "").lower()
        content = (item.get("content") or "").strip()
        if role != "user" or not content:
            continue
        if is_approval(content) or is_rejection(content):
            continue
        parsed = parse_firewall_change(content)
        if parsed:
            filled = _with_history_name(parsed, messages, skip_content=content)
            if filled:
                return filled
        user_texts.append(content)
        parsed = parse_firewall_change("\n".join(reversed(user_texts)))
        if parsed:
            filled = _with_history_name(parsed, messages)
            if filled:
                return filled
    return None


def _result(reply, blocks=None, started=None):
    return {
        "reply": reply,
        "blocks": blocks or [],
        "usage": {},
        "latency_ms": int((time.monotonic() - (started or time.monotonic())) * 1000),
        "model": "firewall-execution-agent",
        "routed_via": "feat_jobs",
    }


def _confirm_blocks(change):
    text = "{0}?".format(change["summary"])
    extra = []
    fields = change.get("fields") or {}
    if fields.get("Address Value"):
        extra.append("IP {0}".format(fields["Address Value"]))
    if fields.get("From") or fields.get("To"):
        extra.append("from {0} to {1}".format(
            fields.get("From") or "any", fields.get("To") or "any"
        ))
    if extra:
        text = "{0} ({1})?".format(change["summary"], ", ".join(extra))
    return [
        {
            "type": "confirm",
            "title": "Confirm firewall change",
            "text": text,
            "confirm_label": "Approve",
            "confirm_value": "Approve",
            "cancel_label": "Cancel",
            "cancel_value": "Cancel",
        }
    ]


def _register_automation_job(user_id, change, job):
    status = (job.get("status") or "QUEUED").upper()
    ui_status = automation_jobs_service.feat_ui_status(status)
    payload = {
        "firewall_name": job.get("firewall_host") or "",
        "security_domain": "Network security",
        "workbook_name": "Maestro AI",
        "actions": [change["action"]],
        "playbooks": [change["label"]],
        "sheets": [change["category"]],
        "status": ui_status,
        "operations": [
            {
                "playbook_id": change["category"],
                "playbook_title": change["summary"],
                "sheet": change["label"],
                "actions": [change["action"]],
                "counts": {},
                "committed": ui_status == "successful",
                "task_id": job.get("task_id") or "",
                "status": ui_status,
                "summary": change["summary"],
                "executed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
        ],
    }
    try:
        return automation_jobs_service.create_job(user_id, payload)
    except Exception:
        logger.exception("Failed to register Maestro job on the Jobs page")
        return None


def _submit_change(user_id, change):
    preflight = firewall_jobs_service.preflight(user_id)
    if not preflight.get("live"):
        raise firewall_jobs_service.FirewallJobsError(
            preflight.get("message") or FIREWALL_DOWN_MESSAGE,
            409,
        )
    body = {
        "operation": "apply_change",
        "device_group": "vsys1",
        "firewall_host": preflight.get("host") or "",
        "requested_payload": build_requested_payload(change),
    }
    job = firewall_jobs_service.create_job(user_id, body)
    if not job or not job.get("task_id"):
        raise firewall_jobs_service.FirewallJobsError(
            "Firewall Execution Agent did not return a job id.",
            502,
        )
    job = firewall_jobs_service.approve_job(user_id, job["task_id"], approve=True)
    return job


def try_handle(agent, user_id, message, messages=None):
    """Handle Maestro change/approval turns. Return a chat result or None."""
    if not _is_maestro(agent):
        return None
    text = (message or "").strip()
    if not text:
        return None

    started = time.monotonic()
    history = list(messages or [])

    if is_rejection(text):
        return _result(
            "Cancelled. No firewall change was sent to the Firewall Execution Agent.",
            started=started,
        )

    if is_approval(text):
        change = pending_change_from_history(history[:-1] if history else [])
        if change is None:
            return _result(
                "I could not find a firewall change to apply. "
                "Please describe the change again "
                "(for example: create object web-server-007 with ip 192.168.11.14).",
                started=started,
            )
        if not change.get("name"):
            return _result(
                "I need the object name to apply this change. "
                "For example: delete object web-server-013.",
                started=started,
            )
        try:
            job = _submit_change(user_id, change)
        except ValueError as exc:
            return _result(str(exc), [
                {"type": "callout", "tone": "danger", "text": str(exc)[:400]},
            ], started=started)
        except firewall_jobs_service.FirewallJobsError as exc:
            if exc.status_code == 409:
                return _result(FIREWALL_DOWN_MESSAGE, [
                    {"type": "callout", "tone": "danger", "text": FIREWALL_DOWN_MESSAGE},
                ], started=started)
            logger.warning("FEAT job dispatch failed: %s", exc)
            return _result(str(exc), [
                {"type": "callout", "tone": "danger", "text": str(exc)[:400]},
            ], started=started)

        auto_job = _register_automation_job(user_id, change, job)
        job_label = (auto_job or {}).get("job_number") or job.get("task_id")
        status = job.get("status") or "QUEUED"
        reply = (
            "{0}. Job {1} ({2}) is {3}. "
            "Track execution status on the Jobs page."
        ).format(JOBS_NOTICE, job_label, change["summary"], status.replace("_", " ").lower())
        blocks = [
            {
                "type": "card",
                "title": JOBS_NOTICE,
                "items": [
                    {"label": "Job", "value": str(job_label)},
                    {"label": "Change", "value": change["summary"]},
                    {"label": "Status", "value": str(status)},
                ],
            }
        ]
        return _result(reply, blocks, started=started)

    change = parse_firewall_change(text)
    if change is not None:
        filled = _with_history_name(change, history, skip_content=text)
        if filled is None and not change.get("name"):
            return _result(
                "I need the object name to delete. "
                "For example: delete object web-server-013.",
                started=started,
            )
        change = filled or change
    if change is None:
        return None

    try:
        preflight = firewall_jobs_service.preflight(user_id)
    except firewall_jobs_service.FirewallJobsError as exc:
        if exc.status_code == 409:
            return _result(FIREWALL_DOWN_MESSAGE, [
                {"type": "callout", "tone": "danger", "text": FIREWALL_DOWN_MESSAGE},
            ], started=started)
        logger.warning("Firewall preflight failed: %s", exc)
        return _result(str(exc), [
            {"type": "callout", "tone": "danger", "text": str(exc)[:400]},
        ], started=started)

    if not preflight.get("live"):
        return _result(FIREWALL_DOWN_MESSAGE, [
            {"type": "callout", "tone": "danger", "text": FIREWALL_DOWN_MESSAGE},
        ], started=started)

    lead = (
        "I can {0}. This change is sent to the Firewall Execution Agent "
        "only after you approve it."
    ).format(change["summary"].lower())
    return _result(lead, _confirm_blocks(change), started=started)


# Keep interactive_blocks imported so confirm cards stay on the allow-list.
assert "confirm" in interactive_blocks.BLOCK_TYPES
