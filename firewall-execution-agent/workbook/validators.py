"""Format/value validation for firewall configuration rows.

Nothing here talks to the firewall. These checks reject malformed or nonsensical
input (for example an address value of ``rte4536``, a service port of ``http`` or
a zone type of ``banana``) before any configuration is built or pushed. They are
run for both the single-change API and every workbook row, so random values can
never reach PAN-OS.

The validators are intentionally strict about the *shape* of a value and lenient
about semantics: an IP must parse as an IP, a port must be numeric and within
range, an enumerable field must be one of its allowed values.
"""

import ipaddress
import re

# PAN-OS object names: letters, digits, dot, underscore, hyphen. Spaces are
# tolerated because workbook cells often contain them, but leading/trailing
# spaces are trimmed upstream.
_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
# Interface identifiers include a slot/port separator, e.g. ethernet1/1.
_INTERFACE_NAME_RE = re.compile(r"^[A-Za-z0-9._/-]+$")
# A hostname/FQDN label sequence (RFC 1123 style), allowing a trailing dot.
_FQDN_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)
_PORT_RE = re.compile(r"^\d{1,5}$")
_PORT_SPEC_RE = re.compile(r"^\d{1,5}(-\d{1,5})?$")
_PROTOCOL_RE = re.compile(r"^[a-z0-9-]+$")


class ValidationFailure(ValueError):
    """Raised when a value fails format validation."""


def _fail(category, header, value, expected):
    raise ValidationFailure(
        "Invalid {0} for {1}: {2!r} ({3}).".format(header, category, value, expected)
    )


# --------------------------------------------------------------------------- #
# Primitive checks
# --------------------------------------------------------------------------- #
def is_ip(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def is_network(text):
    """True for a CIDR such as ``10.0.0.0/24`` (host bits allowed)."""
    if "/" not in text:
        return False
    try:
        ipaddress.ip_network(text, strict=False)
        return True
    except ValueError:
        return False


def is_ip_range(text):
    if "-" not in text:
        return False
    left, right = text.split("-", 1)
    left, right = left.strip(), right.strip()
    if not (is_ip(left) and is_ip(right)):
        return False
    return ipaddress.ip_address(left).version == ipaddress.ip_address(right).version


def is_fqdn(text):
    if not text or len(text) > 253:
        return False
    return bool(_FQDN_RE.match(text))


def is_address_literal(text):
    """True when a string is itself a valid address value (ip/net/range/fqdn)."""
    return is_ip(text) or is_network(text) or is_ip_range(text) or is_fqdn(text)


def is_port(text):
    return bool(_PORT_RE.match(text)) and 0 <= int(text) <= 65535


def is_port_spec(text):
    """A single port or range, e.g. ``80`` or ``80-443``."""
    if not _PORT_SPEC_RE.match(text):
        return False
    if "-" in text:
        low, high = (int(part) for part in text.split("-", 1))
        return low <= high and high <= 65535
    return 0 <= int(text) <= 65535


def is_port_list(text):
    """Comma separated ports/ranges, e.g. ``80,443,8080-8090``."""
    parts = [part.strip() for part in text.split(",") if part.strip()]
    return bool(parts) and all(is_port_spec(part) for part in parts)


def is_name(text):
    return bool(text) and len(text) <= 63 and bool(_NAME_RE.match(text))


def is_interface_name(text):
    return bool(text) and len(text) <= 63 and bool(_INTERFACE_NAME_RE.match(text))


def normalize_name(value):
    """Coerce an arbitrary name into a PAN-OS legal object name.

    Spaces and any other illegal run of characters become a single ``-``; the
    result is trimmed of leading/trailing dashes and capped at 63 characters.
    """
    text = str(value or "").strip()
    text = re.sub(r"[^A-Za-z0-9._-]+", "-", text)
    return text.strip("-")[:63]


def normalize_interface_name(value):
    """Like :func:`normalize_name` but keeps the interface slot separator ``/``."""
    text = str(value or "").strip()
    text = re.sub(r"[^A-Za-z0-9._/-]+", "-", text)
    return text.strip("-")[:63]


def normalize_identifiers(category, row):
    """Normalise the identifying column (Name / Interface) of ``row`` in place."""
    if not row:
        return row
    header = "Interface" if category == "interface" else "Name"
    if header in row:
        raw = row.get(header)
        if raw not in (None, ""):
            row[header] = (
                normalize_interface_name(raw) if header == "Interface"
                else normalize_name(raw)
            )
    return row


def as_bool(text):
    lowered = str(text).strip().lower()
    if lowered in ("", "yes", "no", "true", "false", "1", "0", "on", "off", "y", "n",
                   "enable", "disable", "enabled", "disabled"):
        return None if not lowered else lowered in (
            "yes", "true", "1", "on", "y", "enable", "enabled"
        )
    return "invalid"


# --------------------------------------------------------------------------- #
# Field validators
# --------------------------------------------------------------------------- #
ZONE_MODES = ("tap", "virtual-wire", "layer2", "layer3", "external")
RULE_ACTIONS = ("allow", "deny", "drop", "reset-client", "reset-server", "reset-both")
NAT_TYPES = ("source", "destination", "no", "none")
SOURCE_TRANSLATIONS = ("dynamic-ip-and-port", "dynamic-ip", "static-ip")
NEXT_HOP_TYPES = ("ip-address", "next-vr", "fqdn", "discard")
PROTOCOLS = ("tcp", "udp", "sctp")


def _validate_address_value(row, category):
    value = str(row.get("Address Value") or "").strip()
    if not value:
        _fail(category, "Address Value", value, "a non-empty value is required")
    declared = str(row.get("Address Type") or "").strip().lower()
    declared = {
        "ipnetmask": "ip-netmask", "netmask": "ip-netmask", "ip": "ip-netmask",
        "range": "ip-range", "dns": "fqdn", "hostname": "fqdn", "host": "fqdn",
    }.get(declared, declared)
    if declared == "ip-netmask":
        if not (is_ip(value) or is_network(value)):
            _fail(category, "Address Value", value, "an IP or IP/CIDR for ip-netmask")
    elif declared == "ip-range":
        if not is_ip_range(value):
            _fail(category, "Address Value", value, "two IPs separated by '-' for ip-range")
    elif declared == "fqdn":
        if not is_fqdn(value):
            _fail(category, "Address Value", value, "a valid hostname/FQDN")
    elif declared:
        _fail(category, "Address Type", declared,
              "one of ip-netmask, ip-range, fqdn")
    else:
        # No explicit type: the value itself must be recognisable.
        if not is_address_literal(value):
            _fail(category, "Address Value", value,
                  "an IP, IP/CIDR, IP range or FQDN")


def _validate_members_refs(category, row, header):
    value = str(row.get(header) or "").strip()
    if not value:
        _fail(category, header, value, "at least one member is required")


def _validate_name(category, row, header="Name", required=True):
    value = str(row.get(header) or "").strip()
    if not value:
        if required:
            _fail(category, header, value, "a name is required")
        return
    check = is_interface_name if header == "Interface" else is_name
    if not check(value):
        _fail(category, header, value,
              "letters, digits, dot, underscore or hyphen only (max 63 chars)")


def _validate_enum(category, row, header, allowed, required=False):
    raw = row.get(header)
    value = str(raw if raw is not None else "").strip().lower()
    if not value:
        if required:
            _fail(category, header, value, "required; one of {0}".format(", ".join(allowed)))
        return
    if value not in allowed:
        _fail(category, header, value, "one of {0}".format(", ".join(allowed)))


def _validate_port(category, row, header, required=False):
    raw = row.get(header)
    value = str(raw if raw is not None else "").strip()
    if not value:
        if required:
            _fail(category, header, value, "a port is required")
        return
    if not is_port_list(value):
        _fail(category, header, value, "a port, range or comma list (0-65535)")


def _validate_bool(category, row, header):
    raw = row.get(header)
    if raw is None or str(raw).strip() == "":
        return
    if as_bool(raw) == "invalid":
        _fail(category, header, raw, "yes/no or true/false")


def validate_row(category, row, action="create"):
    """Validate a normalised row for ``category``.

    Raises :class:`ValidationFailure` on the first problem found. Deletions only
    need the identifying name, so value checks are skipped for ``action=delete``.
    """
    row = row or {}

    # Every category is identified by a Name (interface by Interface).
    header = "Interface" if category == "interface" else "Name"
    _validate_name(category, row, header, required=True)

    if action == "delete":
        return

    if category == "address":
        _validate_address_value(row, category)
    elif category == "service":
        _validate_enum(category, row, "Protocol", PROTOCOLS, required=True)
        _validate_port(category, row, "Port", required=True)
        _validate_port(category, row, "Source Port")
    elif category in ("address_group", "service_group"):
        _validate_members_refs(category, row, "Members")
    elif category == "zone":
        _validate_enum(category, row, "Type", ZONE_MODES)
    elif category == "static_route":
        destination = str(row.get("Destination") or "").strip()
        if not destination:
            _fail(category, "Destination", destination, "a network/CIDR is required")
        if not is_network(destination):
            _fail(category, "Destination", destination, "an IP/CIDR such as 10.0.0.0/24")
        _validate_enum(category, row, "Next Hop Type", NEXT_HOP_TYPES)
        _validate_enum(category, row, "Version", ("ipv4", "ipv6"))
        _validate_port(category, row, "Metric")
        _validate_port(category, row, "Admin Distance")
        next_hop = str(row.get("Next Hop") or "").strip()
        hop_type = str(row.get("Next Hop Type") or "ip-address").strip().lower()
        if next_hop and hop_type == "ip-address" and not is_ip(next_hop):
            _fail(category, "Next Hop", next_hop, "an IP address")
        if next_hop and hop_type == "fqdn" and not is_fqdn(next_hop):
            _fail(category, "Next Hop", next_hop, "a hostname/FQDN")
    elif category == "interface":
        ip_raw = row.get("IP Addresses") or row.get("IP")
        value = str(ip_raw or "").strip()
        for member in [m.strip() for m in re.split(r"[\n,;]+", value) if m.strip()]:
            if not is_network(member):
                _fail(category, "IP Addresses", member, "IP/CIDR such as 10.0.0.1/24")
        mtu = row.get("MTU")
        if mtu is not None and str(mtu).strip():
            if not str(mtu).strip().isdigit():
                _fail(category, "MTU", mtu, "a number")
    elif category == "interface_mgmt_profile":
        for header in ("Ping", "Telnet", "Ssh", "Https", "Http", "Snmp", "Response Pages"):
            _validate_bool(category, row, header)
    elif category == "security_rule":
        _validate_enum(category, row, "Rule Action", RULE_ACTIONS)
    elif category == "nat_rule":
        _validate_enum(category, row, "NAT Type", NAT_TYPES)
        _validate_enum(category, row, "Source Translation", SOURCE_TRANSLATIONS)
        _validate_port(category, row, "Destination Translated Port")
        for header in ("Source Translated Address", "Destination Translated Address"):
            value = str(row.get(header) or "").strip()
            if value and not is_address_literal(value):
                _fail(category, header, value, "an IP, IP/CIDR, IP range or FQDN")
