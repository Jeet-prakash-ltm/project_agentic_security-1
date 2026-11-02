"""Field normalisation and category detection.

The execution agent works without fixed playbook templates. Instead of requiring
a workbook whose sheet names and columns exactly match a pre-defined playbook,
this module:

* normalises arbitrary column/field names to the canonical PAN-OS headers the
  apply handlers expect (``Address Value``, ``Rule Action``, ...), and
* detects which configuration category a sheet/row belongs to, from its title or
  its column signatures.

Everything the rest of the app needs about a category (its human label, the
canonical headers, the synonyms accepted for each header, and the signature used
for detection) lives in :data:`SPEC`.
"""

import re

_SPLIT = re.compile(r"[^a-z0-9]+")


def norm(name):
    """Normalise a header/field name for comparison (case/punctuation agnostic)."""
    return _SPLIT.sub("", str(name or "").lower())


# Canonical headers per category, plus the synonyms accepted for each header.
# ``required`` must be present for a sheet to be classified as the category;
# ``signals`` are strong indicators used to score a match; ``min_signals`` is the
# minimum number of signals a sheet must expose.
SPEC = {
    "address": {
        "kind": "Address",
        "sheet_aliases": ["addresses", "address", "addressobjects", "addressobject"],
        "keywords": ["address object", "addresses", "address"],
        "required": ["Name", "Address Value"],
        "signals": ["Address Type", "Address Value"],
        "min_signals": 1,
        "fields": {
            "Name": [
                "name", "objectname", "addressname", "objname", "obj",
                "object", "addressobj",
            ],
            "Action": ["action", "operation", "op"],
            "Address Type": ["addresstype", "addrtype", "iptype", "type"],
            "Address Value": [
                "addressvalue", "value", "ip", "ipaddress", "ipvalue",
                "ipaddressvalue", "address", "addressval", "fqdn", "host",
                "subnet",
            ],
            "Tags": ["tags", "tag"],
            "Description": ["description", "desc", "comment"],
        },
    },
    "address_group": {
        "kind": "Address Group",
        "sheet_aliases": [
            "addressgroups", "addressgroup", "addrgroups", "addrgroup",
        ],
        "keywords": ["address group", "addr group", "addressgroups", "addrgroups"],
        "required": ["Name", "Members"],
        "signals": ["Members", "Group Type"],
        "min_signals": 1,
        "fields": {
            "Name": ["name", "groupname", "objectname"],
            "Action": ["action", "operation", "op"],
            "Members": ["members", "member", "addresses", "groupmembers"],
            "Group Type": ["grouptype", "type"],
            "Tags": ["tags", "tag"],
            "Description": ["description", "desc", "comment"],
        },
    },
    "service": {
        "kind": "Service",
        "sheet_aliases": ["services", "service", "serviceobjects", "serviceobject"],
        "keywords": ["service object", "services", "service"],
        "required": ["Name", "Protocol"],
        "signals": ["Protocol", "Port", "Source Port"],
        "min_signals": 1,
        "fields": {
            "Name": ["name", "servicename", "objectname", "svcname", "objname"],
            "Action": ["action", "operation", "op"],
            "Protocol": ["protocol", "proto"],
            "Port": ["port", "destinationport", "dstport", "destport"],
            "Source Port": ["sourceport", "srcport"],
            "Tags": ["tags", "tag"],
            "Description": ["description", "desc", "comment"],
        },
    },
    "service_group": {
        "kind": "Service Group",
        "sheet_aliases": [
            "servicegroups", "servicegroup", "svcgroups", "svcgroup",
        ],
        "keywords": ["service group", "svc group", "servicegroups", "svcgroups"],
        "required": ["Name", "Members"],
        "signals": ["Members"],
        "min_signals": 1,
        "fields": {
            "Name": ["name", "groupname", "objectname"],
            "Action": ["action", "operation", "op"],
            "Members": ["members", "member", "services", "groupmembers"],
            "Tags": ["tags", "tag"],
            "Description": ["description", "desc", "comment"],
        },
    },
    "zone": {
        "kind": "Zone",
        "sheet_aliases": ["zones", "zone"],
        "keywords": ["zones", "zone"],
        "required": ["Name"],
        "signals": [
            "Type", "Interfaces", "Zone Protection Profile", "Log Setting",
            "Enable User Identification",
        ],
        "min_signals": 1,
        "fields": {
            "Name": ["name", "zonename", "zone", "objname"],
            "Action": ["action", "operation", "op"],
            "Type": ["type", "zonetype", "mode"],
            "Interfaces": ["interfaces", "interface", "members"],
            "Zone Protection Profile": [
                "zoneprotectionprofile", "zoneprotection", "protectionprofile",
            ],
            "Log Setting": ["logsetting", "logforwarding"],
            "Enable User Identification": [
                "enableuseridentification", "useridentification", "userid",
            ],
        },
    },
    "virtual_router": {
        "kind": "Virtual Router",
        "sheet_aliases": ["virtualrouters", "virtualrouter", "routers", "router"],
        "keywords": ["virtual router", "virtualrouters", "vr"],
        "required": ["Name"],
        "signals": ["Interfaces"],
        "min_signals": 1,
        "fields": {
            "Name": ["name", "routername", "vrname"],
            "Action": ["action", "operation", "op"],
            "Interfaces": ["interfaces", "interface", "members"],
        },
    },
    "static_route": {
        "kind": "Static Route",
        "sheet_aliases": ["staticroutes", "staticroute", "routes"],
        "keywords": ["static route", "staticroutes", "routes"],
        "required": ["Name", "Virtual Router"],
        "signals": [
            "Destination", "Next Hop", "Next Hop Type", "Metric",
            "Admin Distance",
        ],
        "min_signals": 1,
        "fields": {
            "Name": ["name", "routename"],
            "Action": ["action", "operation", "op"],
            "Virtual Router": ["virtualrouter", "vr", "router"],
            "Destination": ["destination", "dest", "network", "prefix"],
            "Next Hop Type": ["nexthoptype", "gatewaytype"],
            "Next Hop": ["nexthop", "gateway", "next"],
            "Interface": ["interface"],
            "Metric": ["metric"],
            "Admin Distance": ["admindistance", "distance", "adminmetric"],
            "Version": ["version", "ipversion"],
            "Description": ["description", "desc", "comment"],
        },
    },
    "interface": {
        "kind": "Interface",
        "sheet_aliases": ["interfaces", "interface"],
        "keywords": ["interfaces", "interface"],
        "required": ["Interface"],
        "signals": ["IP Addresses", "Management Profile", "MTU"],
        "min_signals": 1,
        "fields": {
            "Interface": ["interface", "interfacename", "name"],
            "Action": ["action", "operation", "op"],
            "IP Addresses": [
                "ipaddresses", "ipaddress", "ips", "ip", "addresses", "address",
            ],
            "Management Profile": [
                "managementprofile", "mgmtprofile", "profile",
            ],
            "MTU": ["mtu"],
            "Description": ["description", "desc", "comment"],
        },
    },
    "interface_mgmt_profile": {
        "kind": "Interface Management Profile",
        "sheet_aliases": [
            "interfacemanagementprofiles", "interfacemgmtprofiles",
            "managementprofiles", "mgmtprofiles",
        ],
        "keywords": [
            "interface management", "interface mgmt", "management profile",
            "mgmt profile",
        ],
        "required": ["Name"],
        "signals": [
            "Ping", "Telnet", "Ssh", "Https", "Http", "Snmp", "Response Pages",
        ],
        "min_signals": 1,
        "fields": {
            "Name": ["name", "profilename"],
            "Action": ["action", "operation", "op"],
            "Ping": ["ping"],
            "Telnet": ["telnet"],
            "Ssh": ["ssh"],
            "Https": ["https"],
            "Http": ["http"],
            "Snmp": ["snmp"],
            "Response Pages": ["responsepages", "responsepage"],
        },
    },
    "security_rule": {
        "kind": "Security Rule",
        "sheet_aliases": [
            "securityrules", "securityrule", "securitypolicies",
            "securitypolicy", "policies",
        ],
        "keywords": [
            "security rule", "security policy", "securityrules",
            "securitypolicies", "policies",
        ],
        "required": ["Name"],
        "signals": [
            "Rule Action", "From", "To", "Source", "Destination",
            "Applications", "Services", "Categories", "Log Setting",
        ],
        "min_signals": 2,
        "fields": {
            "Name": ["name", "rulename"],
            "Action": ["action", "operation", "op"],
            "Rule Action": ["ruleaction", "permit", "permitaction", "tcpudp"],
            "From": ["from", "fromzone", "fromzones", "sourcezone", "sourcezones"],
            "To": [
                "to", "tozone", "tozones", "destinationzone",
                "destinationzones",
            ],
            "Source": ["source", "sources", "src", "sourceaddress"],
            "Destination": [
                "destination", "destinations", "dest", "dst",
                "destinationaddress",
            ],
            "Users": ["users", "sourceusers", "sourceuser", "user"],
            "Applications": ["applications", "application", "app", "apps"],
            "Services": ["services", "service"],
            "Categories": ["categories", "category", "urlcategory"],
            "Description": ["description", "desc", "comment"],
            "Log Setting": ["logsetting", "logforwarding"],
            "Disabled": ["disabled", "disable"],
        },
    },
    "nat_rule": {
        "kind": "NAT Rule",
        "sheet_aliases": ["natrules", "natrule", "natpolicies", "nat"],
        "keywords": ["nat rule", "nat policy", "natrules", "natpolicies", "nat"],
        "required": ["Name"],
        "signals": [
            "NAT Type", "Source Translation", "Translated Interface",
            "Source Translated Address", "Destination Translated Address",
            "Destination Translated Port",
        ],
        "min_signals": 1,
        "fields": {
            "Name": ["name", "rulename"],
            "Action": ["action", "operation", "op"],
            "From": ["from", "fromzone", "fromzones", "sourcezone", "sourcezones"],
            "To": [
                "to", "tozone", "tozones", "destinationzone",
                "destinationzones",
            ],
            "Source": ["source", "sources", "src", "sourceaddress"],
            "Destination": [
                "destination", "destinations", "dest", "dst",
                "destinationaddress",
            ],
            "Service": ["service"],
            "Description": ["description", "desc", "comment"],
            "NAT Type": ["nattype", "type"],
            "Source Translation": ["sourcetranslation", "srctranslation"],
            "Translated Interface": [
                "translatedinterface", "egressinterface", "interface",
            ],
            "Source Translated Address": [
                "sourcetranslatedaddress", "translatedaddress",
                "translatedsourceaddress",
            ],
            "Destination Translated Address": [
                "destinationtranslatedaddress", "translateddestinationaddress",
            ],
            "Destination Translated Port": [
                "destinationtranslatedport", "translatedport",
            ],
            "Disabled": ["disabled", "disable"],
        },
    },
}


CATEGORY_KEYS = tuple(SPEC.keys())

# Most specific first - used to break score ties in detection.
_PRIORITY = (
    "nat_rule",
    "security_rule",
    "static_route",
    "interface_mgmt_profile",
    "interface",
    "address_group",
    "service_group",
    "service",
    "address",
    "virtual_router",
    "zone",
)


def _synonym_map(category):
    spec = SPEC.get(category) or {}
    mapping = {}
    for canonical, synonyms in (spec.get("fields") or {}).items():
        mapping[norm(canonical)] = canonical
        for synonym in synonyms:
            mapping.setdefault(norm(synonym), canonical)
    return mapping


def normalize_row(values, category):
    """Return ``values`` with keys canonicalised for ``category``.

    Unknown columns are preserved unchanged so nothing is silently dropped. An
    empty value never overwrites an already-populated canonical value.
    """
    if not values:
        return {}
    mapping = _synonym_map(category)
    canonical_names = {norm(c) for c in mapping.values()}
    result = {}
    for key, value in values.items():
        if value is None:
            continue
        normalized = norm(key)
        canonical = mapping.get(normalized, key)
        if canonical in result and not str(result[canonical]).strip():
            result[canonical] = value
        elif canonical not in result:
            result[canonical] = value
        elif normalized in canonical_names:
            result[canonical] = value
    return result


def headers_of(category):
    """Canonical headers for a category (for documentation/agent help)."""
    return list((SPEC.get(category) or {}).get("fields", {}).keys())


def kind_of(category):
    return (SPEC.get(category) or {}).get("kind") or category


def _canonical_headers(headers, category):
    """Canonicalise a header list through ``category``'s synonym map."""
    mapping = _synonym_map(category)
    result = set()
    for header in headers or []:
        normalized = norm(header)
        if not normalized:
            continue
        result.add(norm(mapping.get(normalized, header)))
    return result


def detect_category(title, headers):
    """Best-effort classification of a sheet into a category key (or ``None``).

    Resolution order: exact sheet-title alias, then title keyword, then column
    signature scoring. Returns ``None`` when nothing matches confidently.
    """
    title_norm = norm(title)

    if title_norm:
        for key in CATEGORY_KEYS:
            aliases = {norm(a) for a in SPEC[key]["sheet_aliases"]}
            if title_norm in aliases:
                return key

    if title_norm:
        keyword_hits = []
        for key in CATEGORY_KEYS:
            for keyword in SPEC[key]["keywords"]:
                kw = norm(keyword)
                if kw and kw in title_norm:
                    keyword_hits.append((len(kw), key))
        if keyword_hits:
            keyword_hits.sort(reverse=True)
            return keyword_hits[0][1]

    if not headers:
        return None

    best_key = None
    best_score = -1
    for key in _PRIORITY:
        spec = SPEC[key]
        present = _canonical_headers(headers, key)
        required = {norm(h) for h in spec["required"]}
        if not required.issubset(present):
            continue
        signals = {norm(h) for h in spec["signals"]}
        score = len(signals & present)
        if score < spec.get("min_signals", 1):
            continue
        if score > best_score:
            best_score = score
            best_key = key
    return best_key


def row_category(row, default=None):
    """Per-row category override taken from a ``Category`` column."""
    for key, value in (row or {}).items():
        if norm(key) == "category":
            text = str(value or "").strip()
            if not text:
                continue
            candidate = norm(text)
            for key_name in CATEGORY_KEYS:
                if candidate in {norm(a) for a in SPEC[key_name]["sheet_aliases"]}:
                    return key_name
            for key_name in CATEGORY_KEYS:
                if norm(SPEC[key_name]["kind"]) == candidate:
                    return key_name
            for key_name in CATEGORY_KEYS:
                if candidate in (SPEC[key_name].get("keywords") or []):
                    return key_name
    return default
