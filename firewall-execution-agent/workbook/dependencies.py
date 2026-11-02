"""Referential integrity and dependency ordering for firewall changes.

A security rule (or NAT rule, or service group, ...) may only reference objects
that already exist on the firewall. This module:

* knows, per category, which fields reference other objects and of which kind;
* reads the firewall's current object inventory (read-only) and can confirm
  whether a referenced object exists;
* treats well-known builtins (``any``, ``application-default``, predefined
  applications) as always present;
* can *create* a missing dependency when the reference value is itself enough to
  define the object (an IP / CIDR / range / FQDN for an address, a ``proto/port``
  for a service) and rewrites the referring rule to point at the created object;
* reports anything that is referenced but missing and cannot be created, so the
  change is rejected instead of pushing a broken configuration.

Nothing here commits; callers apply the returned dependency rows (before the
dependent row) and commit once.
"""

import re
import xml.etree.ElementTree as ET

from workbook import common
from workbook import validators

# --------------------------------------------------------------------------- #
# Known builtins: names that always exist and never need a dependency.
# --------------------------------------------------------------------------- #
PREDEFINED_APPLICATIONS = {
    "any", "web-browsing", "ssl", "dns", "http", "https", "ssh", "telnet",
    "ftp", "tftp", "smtp", "pop3", "imap", "ping", "traceroute", "ntp", "ldap",
    "ldap-base", "kerberos", "smb", "ms-ds-smb", "ms-netlogon", "msrpc",
    "microsoft-ds", "snmp", "dhcp", "netbios-dg", "netbios-ns", "netbios-ss",
    "mysql", "mssql-db", "oracle", "ms-rdp", "rdp", "gre", "ipsec-esp",
    "ipsec-ah", "ike", "github", "google-base", "google-services",
    "google-analytics", "youtube-base", "youtube", "facebook-base",
    "twitter-base", "office365", "ms-office365", "sharepoint-online",
    "exchange-online", "win-update", "webdav", "quic-base", "rtmp",
    "skype-base", "teams", "zoom", "slack", "sip", "tcp", "udp", "icmp",
}

BUILTINS = {
    "address": {"any"},
    "service": {"any", "application-default"},
    "application": PREDEFINED_APPLICATIONS,
    "zone": {"any"},
    "user": {"any"},
    "category": {"any"},
    "virtual_router": {"default"},
    "interface_mgmt_profile": set(),
    "zone_protection_profile": {"none", "default"},
    "log_setting": set(),
    "address_group": set(),
    "service_group": set(),
}

# Categories whose referenced objects are leaf objects that can be auto-created
# when the reference is a literal.
CREATABLE_KINDS = {"address", "service"}

# Categories we cannot always enumerate; a miss is reported as a warning rather
# than a hard failure (PAN-OS ships thousands of predefined entries for these).
WARN_KINDS = {"application", "user", "category", "zone_protection_profile", "log_setting"}

# Config xpath used to read the current object names for a kind.
CONFIG_PATHS = {
    "address": common.vsys_base() + "/address",
    "address_group": common.vsys_base() + "/address-group",
    "service": common.vsys_base() + "/service",
    "service_group": common.vsys_base() + "/service-group",
    "zone": common.vsys_base() + "/zone",
    "application": common.vsys_base() + "/application",
    "tag": common.vsys_base() + "/tag",
    "virtual_router": common.network_base() + "/virtual-router",
    "interface": common.network_base() + "/interface/ethernet",
    "interface_mgmt_profile": (
        common.network_base() + "/profiles/interface-management-profile"
    ),
}

# Referenced fields, per category: (header, accepted kinds, multi-valued).
REFERENCE_FIELDS = {
    "security_rule": [
        ("From", ("zone",), True),
        ("To", ("zone",), True),
        ("Source", ("address", "address_group"), True),
        ("Destination", ("address", "address_group"), True),
        ("Applications", ("application",), True),
        ("Services", ("service", "service_group"), True),
        ("Users", ("user",), True),
        ("Categories", ("category",), True),
    ],
    "nat_rule": [
        ("From", ("zone",), True),
        ("To", ("zone",), True),
        ("Source", ("address", "address_group"), True),
        ("Destination", ("address", "address_group"), True),
        ("Service", ("service", "service_group"), False),
    ],
    "address_group": [("Members", ("address", "address_group"), True)],
    "service_group": [("Members", ("service", "service_group"), True)],
    "static_route": [
        ("Virtual Router", ("virtual_router",), False),
        ("Interface", ("interface",), False),
    ],
    "interface": [("Management Profile", ("interface_mgmt_profile",), False)],
    "zone": [
        ("Zone Protection Profile", ("zone_protection_profile",), False),
        ("Log Setting", ("log_setting",), False),
    ],
}

# Object category -> kind it defines (used to seed the inventory with objects
# that are created earlier in the same workbook run).
DEFINES_KIND = {
    "address": "address",
    "address_group": "address_group",
    "service": "service",
    "service_group": "service_group",
    "zone": "zone",
    "virtual_router": "virtual_router",
    "interface": "interface",
    "interface_mgmt_profile": "interface_mgmt_profile",
}

# Execution order so dependencies are created before the objects that use them.
CATEGORY_ORDER = (
    "address",
    "service",
    "address_group",
    "service_group",
    "interface_mgmt_profile",
    "interface",
    "zone",
    "virtual_router",
    "static_route",
    "nat_rule",
    "security_rule",
)


def category_rank(category):
    try:
        return CATEGORY_ORDER.index(category)
    except ValueError:
        return len(CATEGORY_ORDER)


def _object_name(value):
    """A valid object name derived from a literal address/service value."""
    return validators.normalize_name(value)


def _member_normalizer(kinds):
    return (
        validators.normalize_interface_name
        if "interface" in kinds
        else validators.normalize_name
    )


_SERVICE_LITERAL_RE = re.compile(r"^(tcp|udp|sctp)\s*/\s*(.+)$", re.IGNORECASE)


def creatable_literal(kind, value):
    """Return ``(category, row, name)`` if ``value`` fully defines an object."""
    value = str(value or "").strip()
    if not value:
        return None
    if kind == "address":
        if validators.is_ip(value) or validators.is_network(value):
            addr_type = "ip-netmask"
        elif validators.is_ip_range(value):
            addr_type = "ip-range"
        elif "." in value and validators.is_fqdn(value):
            addr_type = "fqdn"
        else:
            return None
        name = _object_name(value)
        return (
            "address",
            {
                "Name": name,
                "Action": "create",
                "Address Type": addr_type,
                "Address Value": value,
            },
            name,
        )
    if kind == "service":
        match = _SERVICE_LITERAL_RE.match(value)
        if not match:
            return None
        protocol = match.group(1).lower()
        port = match.group(2).strip()
        if not validators.is_port_list(port):
            return None
        name = _object_name("{0}/{1}".format(protocol, port))
        return (
            "service",
            {
                "Name": name,
                "Action": "create",
                "Protocol": protocol,
                "Port": port,
            },
            name,
        )
    return None


def _entry_names(xml_text):
    names = set()
    if not xml_text:
        return names
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return names
    for entry in root.iter("entry"):
        name = entry.attrib.get("name")
        if name:
            names.add(name)
    return names


class Inventory:
    """Read-only cache of object names currently configured on the firewall."""

    def __init__(self, client_factory=None, seed=None, prefetch=()):
        self._factory = client_factory
        self._names = {}
        self._attempted = set()
        self.available = None
        for kind, names in (seed or {}).items():
            self._names.setdefault(kind, set()).update(names)
        for kind in prefetch or ():
            self.names(kind)

    def names(self, kind):
        if kind in self._names:
            return set(self._names[kind])
        self._names[kind] = set()
        # The firewall was already found unreachable; do not pay the timeout again.
        if self.available is False:
            return set()
        path = CONFIG_PATHS.get(kind)
        if not self._factory or not path:
            if self.available is None:
                self.available = False
            return set()
        self._attempted.add(kind)
        try:
            xml = self._factory().get(path)
            self._names[kind] = _entry_names(xml)
            self.available = True
        except Exception:  # noqa: BLE001 - unreachable firewall -> no inventory
            self.available = False
        return set(self._names[kind])

    def has_any(self, kinds, name):
        for kind in kinds:
            if name in BUILTINS.get(kind, set()):
                return True
        for kind in kinds:
            if name in self.names(kind):
                return True
        return False

    def add(self, kind, name):
        self._names.setdefault(kind, set()).add(name)


def references(category, row):
    """Yield ``(header, accepted_kinds, member)`` for every reference in a row."""
    for header, kinds, multi in REFERENCE_FIELDS.get(category, ()):
        raw = row.get(header)
        if multi:
            members = common.split_members(raw)
        else:
            text = common.to_text(raw)
            members = [text] if text else []
        for member in members:
            yield header, kinds, member


def plan(category, row, inventory, auto_create=True, dry_run=False):
    """Resolve the references of one row.

    Returns ``(dependencies, errors, warnings, replacements)`` where
    ``dependencies`` is a list of ``{"category", "row", "kind", "name"}`` to be
    applied *before* the row, ``replacements`` is a list of
    ``(header, old_member, new_member)`` renames to apply to the row, and
    ``errors``/``warnings`` are human-readable messages.
    """
    dependencies = []
    errors = []
    warnings = []
    replacements = []

    for header, kinds, member in references(category, row):
        if member.lower() == "any":
            continue
        if inventory.has_any(kinds, member):
            continue
        normalized = _member_normalizer(kinds)(member)
        if normalized != member and inventory.has_any(kinds, normalized):
            replacements.append((header, member, normalized))
            continue
        created = None
        if auto_create:
            for kind in kinds:
                created = creatable_literal(kind, member)
                if created:
                    break
        if created:
            dep_category, dep_row, dep_name = created
            dependencies.append(
                {
                    "category": dep_category,
                    "row": dep_row,
                    "kind": kinds[0],
                    "name": dep_name,
                    "requested": member,
                    "header": header,
                }
            )
            inventory.add(kinds[0], dep_name)
            if dep_name != member:
                replacements.append((header, member, dep_name))
            continue

        display = normalized or member
        if all(kind in WARN_KINDS for kind in kinds):
            warnings.append(
                "{0} {1!r} could not be verified against the firewall".format(
                    _kind_label(kinds), display
                )
            )
        else:
            errors.append(
                "{0} {1!r} is not defined on the firewall; create it before this "
                "{2}".format(_kind_label(kinds), display, fields_kind(category))
            )

    if dry_run and not inventory.available and errors:
        # The firewall could not be read, so we cannot prove the reference is
        # missing. Do not block a dry run on an unverifiable reference.
        warnings.extend(
            "{0} (not verified: firewall inventory unavailable)".format(err)
            for err in errors
        )
        errors = []

    return dependencies, errors, warnings, replacements


def _kind_label(kinds):
    return "/".join(kinds)


def fields_kind(category):
    from workbook import fields

    return fields.kind_of(category)


def apply_replacements(row, replacements):
    """Return a copy of ``row`` with dependency renames applied."""
    if not replacements:
        return row
    updated = dict(row)
    for header, old, new in replacements:
        raw = common.to_text(updated.get(header))
        if not raw:
            continue
        parts = common.split_members(raw) if raw else []
        if parts:
            updated[header] = ", ".join(new if p == old else p for p in parts)
        elif raw == old:
            updated[header] = new
    return updated
