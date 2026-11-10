"""Adapt Zero Trust Function App payloads into the assessment UI model."""

from __future__ import annotations

import re

from .zero_trust_test_details import enrich_test

RISK_LEVELS = ("High", "Medium", "Low")
ASSESSMENT_STATUSES = ("Passed", "Failed", "Planned", "Investigate", "Skipped")
ASSESSMENT_AREAS = ("Identity", "Devices", "Network", "Data", "Infrastructure")

RISK_WEIGHT = {"High": 5, "Medium": 3, "Low": 1}
STATUS_FACTOR = {
    "Passed": 1.0,
    "Planned": 0.5,
    "Investigate": 0.25,
    "Skipped": 0.0,
    "Failed": 0.0,
}

STATUS_SORT = {
    "Failed": 0,
    "Investigate": 1,
    "Planned": 2,
    "Skipped": 3,
    "Passed": 4,
}
RISK_SORT = {"High": 0, "Medium": 1, "Low": 2}

TRUSTED_DOC_HOSTS = (
    "learn.microsoft.com",
    "microsoft.com",
    "www.microsoft.com",
    "entra.microsoft.com",
    "intune.microsoft.com",
    "portal.azure.com",
    "security.microsoft.com",
    "purview.microsoft.com",
)

IDENTITY_CATEGORY_RULES = (
    (re.compile(r"ID-?01|ID01"), "Inventory"),
    (re.compile(r"ID-?02|ID02"), "Authentication methods"),
    (re.compile(r"ID-?03|ID03"), "Conditional Access"),
    (re.compile(r"ID-?04|ID04"), "Legacy authentication"),
    (re.compile(r"ID-?05|ID05"), "Strong authentication"),
    (re.compile(r"ID-?06|ID06"), "Privileged accounts"),
    (re.compile(r"ID-?07|ID07"), "Least privilege"),
    (re.compile(r"ID-?08|ID08"), "Identity protection"),
    (re.compile(r"ID-?09|ID09"), "External identities"),
    (re.compile(r"ID-?10|ID10"), "Application identity security"),
    (re.compile(r"ID-?11|ID11"), "Access reviews"),
    (re.compile(r"ID-?12|ID12"), "Monitoring and diagnostics"),
    (re.compile(r"CA-|CONDITIONAL"), "Conditional Access"),
    (re.compile(r"PRIVILEGED|PIM|ROLE"), "Privileged accounts"),
    (re.compile(r"AUTH-METHOD|PHISHING|FIDO|MFA"), "Authentication methods"),
    (re.compile(r"RISKY|IDENTITY-PROTECTION"), "Identity protection"),
    (re.compile(r"SECURITY-DEFAULT|AUTHORIZATION|TENANT"), "Tenant administration"),
    (re.compile(r"GUEST|EXTERNAL|CROSS-TENANT"), "External identities"),
    (re.compile(r"APP|WORKLOAD|CREDENTIAL|REDIRECT|CONSENT"), "Application identity security"),
    (re.compile(r"DIAGNOSTIC|MONITOR"), "Monitoring and diagnostics"),
    (re.compile(r"ENTITLEMENT|ACCESS-REVIEW"), "Access reviews"),
    (re.compile(r"TOKEN|LEGACY"), "Legacy authentication"),
)

DEVICE_CATEGORY_RULES = (
    (re.compile(r"DA01|ENROLL"), "Enrollment"),
    (re.compile(r"DA02-ENCRYPT|ENCRYPT"), "Encryption"),
    (re.compile(r"DA02|INVENTORY"), "Inventory"),
    (re.compile(r"DA03|COMPLIANT-DEVICE|COMPLIANCE"), "Compliance"),
    (re.compile(r"DA04-SESSION|SESSION"), "Session controls"),
    (re.compile(r"DA04|CONDITIONAL"), "Conditional Access"),
    (re.compile(r"DA05|SIGNIN"), "Sign-in evidence"),
    (re.compile(r"DA06|RECONCILE"), "Inventory reconcile"),
    (re.compile(r"FIREWALL"), "Firewall"),
    (re.compile(r"UPDATE"), "Updates"),
    (re.compile(r"ENDPOINT|DEFENDER"), "Endpoint protection"),
    (re.compile(r"AUTH"), "Platform authentication"),
    (re.compile(r"ADMIN"), "Tenant administration"),
)

DEVICE_PLATFORM_RULES = (
    (re.compile(r"windows", re.I), "Windows"),
    (re.compile(r"macos|mac os", re.I), "macOS"),
    (re.compile(r"ios|ipad", re.I), "iOS/iPadOS"),
    (re.compile(r"android", re.I), "Android"),
)

NETWORK_CATEGORY_RULES = (
    (re.compile(r"NA01|INVENTORY"), "Inventory"),
    (re.compile(r"OPEN-MGMT|MANAGEMENT"), "Network segmentation"),
    (re.compile(r"NA02|NSG"), "NSG security"),
    (re.compile(r"NA03|PUBLIC"), "Public exposure"),
    (re.compile(r"NA04|PRIVATE"), "Private connectivity"),
    (re.compile(r"NA05|FIREWALL"), "Firewall"),
    (re.compile(r"NA06|WAF"), "WAF"),
    (re.compile(r"NA07|DDOS"), "DDoS"),
    (re.compile(r"NA08|REMOTE|BASTION|VPN"), "Remote connectivity"),
    (re.compile(r"NA09|ENCRYPT"), "Encryption"),
    (re.compile(r"NA10|MONITOR|WATCHER"), "Monitoring"),
    (re.compile(r"NA11|SEGMENT"), "Segmentation"),
    (re.compile(r"NA12|ROUT"), "Routing"),
    (re.compile(r"NET"), "Network security"),
)

DATA_CATEGORY_RULES = (
    (re.compile(r"DP-?01|DP01"), "Classification"),
    (re.compile(r"DP-?02|DP02"), "Information protection"),
    (re.compile(r"DP-?03|DP03"), "Data loss prevention"),
    (re.compile(r"DP-?04|DP04"), "Encryption"),
    (re.compile(r"DP-?05|DP05"), "External sharing"),
    (re.compile(r"DP-?06|DP06"), "Retention"),
    (re.compile(r"DP-?07|DP07"), "Data risk"),
    (re.compile(r"DP-?08|DP08"), "Audit"),
    (re.compile(r"SENSITIVITY|LABEL"), "Information protection"),
    (re.compile(r"DLP"), "Data loss prevention"),
    (re.compile(r"DATA"), "Data protection"),
)

INFRASTRUCTURE_CATEGORY_RULES = (
    (re.compile(r"IA-?01|IA01"), "Inventory"),
    (re.compile(r"IA-?02|IA02"), "Governance"),
    (re.compile(r"IA-?03|IA03"), "Administrative access"),
    (re.compile(r"IA-?04|IA04"), "Workload identity"),
    (re.compile(r"IA-?05|IA05"), "Defender for Cloud"),
    (re.compile(r"IA-?06|IA06"), "VM security"),
    (re.compile(r"IA-?07|IA07"), "Vulnerability management"),
    (re.compile(r"IA-?08|IA08"), "Secrets and keys"),
    (re.compile(r"IA-?09|IA09"), "Storage security"),
    (re.compile(r"IA-?10|IA10"), "Container security"),
    (re.compile(r"IA-?11|IA11"), "Monitoring"),
    (re.compile(r"IA-?12|IA12"), "Backup and recovery"),
    (re.compile(r"IA-?13|IA13"), "Configuration drift"),
    (re.compile(r"SECURE-SCORE"), "Defender for Cloud"),
    (re.compile(r"ASSESSMENT|DEFENDER"), "Cloud security posture"),
    (re.compile(r"INFRA"), "Infrastructure security"),
)

PILLAR_CATEGORY_RULES = {
    "Identity": IDENTITY_CATEGORY_RULES,
    "Devices": DEVICE_CATEGORY_RULES,
    "Network": NETWORK_CATEGORY_RULES,
    "Data": DATA_CATEGORY_RULES,
    "Infrastructure": INFRASTRUCTURE_CATEGORY_RULES,
}

DEFAULT_CATEGORY = {
    "Identity": "Tenant administration",
    "Devices": "Secure configuration",
    "Network": "Network security",
    "Data": "Data protection",
    "Infrastructure": "Infrastructure security",
}

SECRET_RE = re.compile(
    r"(bearer\s+[a-z0-9._\-]+|eyJ[a-zA-Z0-9_\-]+=*|code=[^&\s]+|function.?key[^\s]*)",
    re.I,
)


def sanitize_text(value, limit=800):
    if value is None:
        return None
    text = SECRET_RE.sub("[redacted]", str(value)).strip()
    if not text:
        return None
    if len(text) > limit:
        return text[: limit - 1] + "…"
    return text


def mask_tenant_id(tenant_id):
    if not tenant_id:
        return None
    value = str(tenant_id).strip()
    parts = value.split("-")
    if len(parts) == 5 and len(parts[0]) >= 4 and len(parts[-1]) >= 4:
        return "{0}-****-****-****-{1}".format(parts[0], parts[-1])
    if len(value) <= 8:
        return value
    return "{0}****{1}".format(value[:4], value[-4:])


def trusted_url(url):
    if not url:
        return None
    text = str(url).strip()
    if not text.lower().startswith("https://"):
        return None
    host = text.split("/")[2].split(":")[0].lower()
    if host in TRUSTED_DOC_HOSTS or any(
        host.endswith("." + allowed) for allowed in TRUSTED_DOC_HOSTS
    ):
        return text
    return None


def map_status(raw):
    token = str(raw or "").strip().lower()
    if token in ("pass", "passed", "compliant", "healthy"):
        return "Passed"
    if token in ("fail", "failed", "non-compliant", "unhealthy"):
        return "Failed"
    if token in ("planned", "plan"):
        return "Planned"
    if token in ("skipped", "skip", "not applicable", "n/a"):
        return "Skipped"
    if token in ("error", "investigate", "unavailable", "unknown"):
        return "Investigate"
    return "Investigate"


def map_risk(raw):
    token = str(raw or "").strip().lower()
    if token in ("high", "critical"):
        return "High"
    if token in ("medium", "moderate"):
        return "Medium"
    if token in ("low", "informational", "info"):
        return "Low"
    return "Medium"


def map_area(pillar, check_id=""):
    token = str(pillar or "").strip()
    if token in ASSESSMENT_AREAS:
        return token
    lowered = (token + " " + str(check_id or "")).lower()
    if "device" in lowered or "intune" in lowered:
        return "Devices"
    if any(word in lowered for word in ("identity", "entra", "ca-", "privileged", "auth")):
        return "Identity"
    if "network" in lowered or check_id.upper().startswith("ZT-NET"):
        return "Network"
    if "data" in lowered or "purview" in lowered or check_id.upper().startswith("ZT-DATA"):
        return "Data"
    if "infra" in lowered or "defender" in lowered or check_id.upper().startswith("ZT-INFRA"):
        return "Infrastructure"
    return token or "Identity"


def category_for(area, check_id, title=""):
    haystack = "{0} {1}".format(check_id or "", title or "")
    rules = PILLAR_CATEGORY_RULES.get(area) or IDENTITY_CATEGORY_RULES
    for pattern, label in rules:
        if pattern.search(haystack):
            return label
    return DEFAULT_CATEGORY.get(area, "Tenant administration")


def platform_for(test_name, evidence_os=None):
    haystack = "{0} {1}".format(test_name or "", evidence_os or "")
    for pattern, label in DEVICE_PLATFORM_RULES:
        if pattern.search(haystack):
            return label
    return "Tenant-wide"


def test_key(area, category, name):
    return "{0}:{1}:{2}".format(
        str(area or "").strip().lower(),
        str(category or "").strip().lower(),
        str(name or "").strip().lower(),
    )


def empty_summary():
    return {
        "total": 0,
        "passed": 0,
        "failed": 0,
        "planned": 0,
        "investigate": 0,
        "skipped": 0,
        "highRiskFailed": 0,
        "mediumRiskFailed": 0,
        "lowRiskFailed": 0,
    }


def summarize_tests(tests):
    summary = empty_summary()
    summary["total"] = len(tests)
    for test in tests:
        status = test.get("status")
        key = {
            "Passed": "passed",
            "Failed": "failed",
            "Planned": "planned",
            "Investigate": "investigate",
            "Skipped": "skipped",
        }.get(status)
        if key:
            summary[key] += 1
        if status == "Failed":
            risk = test.get("risk")
            if risk == "High":
                summary["highRiskFailed"] += 1
            elif risk == "Medium":
                summary["mediumRiskFailed"] += 1
            else:
                summary["lowRiskFailed"] += 1
    return summary


def weighted_score(tests, skipped_not_applicable=True):
    numerator = 0.0
    denominator = 0.0
    for test in tests:
        status = test.get("status")
        if skipped_not_applicable and status == "Skipped":
            continue
        weight = RISK_WEIGHT.get(test.get("risk"), 1)
        denominator += weight
        numerator += weight * STATUS_FACTOR.get(status, 0.0)
    if denominator <= 0:
        return None
    return round((numerator / denominator) * 100)


def _sort_rank(test):
    risk = test.get("risk")
    status = test.get("status")
    if status == "Failed" and risk == "High":
        return 0
    if status == "Investigate" and risk == "High":
        return 1
    if status == "Failed" and risk == "Medium":
        return 2
    if status == "Failed" and risk == "Low":
        return 3
    if status == "Investigate":
        return 4
    if status == "Planned":
        return 5
    if status == "Passed":
        return 6
    if status == "Skipped":
        return 7
    return 8


def sort_tests(tests):
    return sorted(
        tests,
        key=lambda test: (_sort_rank(test), str(test.get("name") or "").lower()),
    )


def deduplicate_tests(tests):
    seen = {}
    ordered = []
    for test in tests:
        key = test.get("id") or test_key(
            test.get("area"),
            test.get("category"),
            test.get("name"),
        )
        if key in seen:
            continue
        seen[key] = True
        ordered.append(test)
    return ordered


def filter_tests(tests, query="", risks=None, statuses=None, pillars=None, categories=None, platforms=None, scopes=None):
    query_l = str(query or "").strip().lower()
    risk_set = set(risks or [])
    status_set = set(statuses or [])
    pillar_set = set(pillars or [])
    category_set = set(categories or [])
    platform_set = set(platforms or [])
    scope_set = set(scopes or [])
    results = []
    for test in tests:
        if query_l:
            haystack = " ".join(
                [
                    str(test.get("name") or ""),
                    str(test.get("category") or ""),
                    str(test.get("description") or ""),
                    str(test.get("recommendation") or ""),
                ]
            ).lower()
            if query_l not in haystack:
                continue
        if risk_set and test.get("risk") not in risk_set:
            continue
        if status_set and test.get("status") not in status_set:
            continue
        if pillar_set and not pillar_set.intersection(test.get("sfiPillars") or []):
            continue
        if category_set and test.get("category") not in category_set:
            continue
        if platform_set and test.get("platform") not in platform_set:
            continue
        if scope_set:
            if test.get("area") not in ASSESSMENT_AREAS:
                scope = "Data"
            elif test.get("area") == "Devices" and test.get("category") in (
                "Compliance",
                "Enrollment",
                "Encryption",
                "Endpoint protection",
                "Firewall",
                "Updates",
                "Secure configuration",
            ):
                scope = "Device"
            else:
                scope = "Tenant"
            if scope not in scope_set:
                continue
        results.append(test)
    return results


def priority_remediation(tests, limit=8):
    ranked = []
    for test in tests:
        status = test.get("status")
        risk = test.get("risk")
        if status == "Failed" and risk == "High":
            rank = 0
        elif status == "Investigate" and risk == "High":
            rank = 1
        elif status == "Failed" and risk == "Medium":
            rank = 2
        elif status == "Failed" and risk == "Low":
            rank = 3
        else:
            continue
        ranked.append((rank, test))
    ranked.sort(key=lambda item: (item[0], str(item[1].get("name") or "").lower()))
    return [item[1] for item in ranked[:limit]]


def _as_int(value):
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _metric(value, available=True):
    if not available:
        return None
    return _as_int(value)


def _finding_error(finding):
    if map_status(finding.get("status")) != "Investigate":
        return None
    message = sanitize_text(finding.get("detail") or finding.get("error") or finding.get("message"))
    if not message:
        return None
    return {"message": message}


def _documentation_for(area, category):
    if area == "Identity":
        return "https://learn.microsoft.com/en-us/entra/fundamentals/configure-security"
    if area == "Devices":
        return "https://learn.microsoft.com/en-us/intune/intune-service/protect/zero-trust-configure-security"
    if area == "Network":
        return "https://learn.microsoft.com/en-us/security/zero-trust/deploy/networks"
    if area == "Data":
        return "https://learn.microsoft.com/en-us/security/zero-trust/deploy/data"
    if area == "Infrastructure":
        return "https://learn.microsoft.com/en-us/security/zero-trust/deploy/infrastructure"
    return "https://learn.microsoft.com/en-us/security/zero-trust/assessment/"


def _portal_for(area, category):
    if area == "Identity":
        if category == "Conditional Access":
            return "https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade"
        if category == "Privileged accounts":
            return "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/RolesManagementMenuBlade"
        return "https://entra.microsoft.com/"
    if area == "Devices":
        return "https://intune.microsoft.com/"
    if area == "Network":
        return "https://portal.azure.com/#view/Microsoft_Azure_Network/NetworkMenuBlade"
    if area == "Data":
        return "https://purview.microsoft.com/"
    if area == "Infrastructure":
        return "https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade"
    return None


def adapt_finding(finding, evaluated_at=None):
    check_id = str(finding.get("id") or finding.get("check_id") or "").strip()
    title = sanitize_text(finding.get("title") or finding.get("name") or check_id, 200) or "Untitled control"
    area = map_area(finding.get("pillar") or finding.get("area"), check_id)
    category = finding.get("category") or category_for(area, check_id, title)
    status = map_status(finding.get("status"))
    risk = map_risk(finding.get("severity") or finding.get("risk"))
    detail = sanitize_text(finding.get("detail") or finding.get("description"))
    remediation = sanitize_text(finding.get("remediation") or finding.get("recommendation"))
    evidence = []
    if detail:
        evidence.append(detail)
    extra_evidence = finding.get("evidence")
    if isinstance(extra_evidence, list):
        for item in extra_evidence:
            cleaned = sanitize_text(item, 240)
            if cleaned:
                evidence.append(cleaned)
    elif extra_evidence:
        cleaned = sanitize_text(extra_evidence, 240)
        if cleaned:
            evidence.append(cleaned)
    test = {
        "id": check_id or test_key(area, category, title),
        "area": area if area in ASSESSMENT_AREAS else area,
        "name": title,
        "category": category,
        "risk": risk,
        "status": status,
        "sfiPillars": [area] if area else [],
        "description": detail,
        "evidence": evidence,
        "impact": detail if status in ("Failed", "Investigate") else None,
        "recommendation": remediation,
        "remediationSteps": [remediation] if remediation else [],
        "source": sanitize_text(finding.get("source"), 80),
        "documentationUrl": trusted_url(finding.get("documentationUrl")) or _documentation_for(area, category),
        "portalUrl": trusted_url(finding.get("portalUrl")) or trusted_url(_portal_for(area, category)),
        "lastEvaluatedAt": finding.get("lastEvaluatedAt") or evaluated_at,
        "platform": platform_for(title) if area == "Devices" else None,
        "error": _finding_error(finding),
        "assessmentLayer": finding.get("assessmentLayer") or finding.get("assessment_layer"),
    }
    return test


def _device_inventory(evidence):
    managed = evidence.get("managed_devices") or {}
    if not managed.get("available"):
        return {
            "available": False,
            "count": None,
            "compliant": None,
            "encrypted": None,
            "byOs": {},
            "byCompliance": {},
        }
    devices = managed.get("devices") or []
    by_os = {}
    by_compliance = {}
    for device in devices:
        os_name = platform_for("", device.get("operatingSystem"))
        if os_name == "Tenant-wide":
            raw = str(device.get("operatingSystem") or "Unknown").strip() or "Unknown"
            os_name = raw
        by_os[os_name] = by_os.get(os_name, 0) + 1
        state = str(device.get("complianceState") or "unknown").strip() or "unknown"
        by_compliance[state] = by_compliance.get(state, 0) + 1
    return {
        "available": True,
        "count": _as_int(managed.get("count")),
        "compliant": _as_int(managed.get("compliant_count")),
        "encrypted": _as_int(managed.get("encrypted_count")),
        "byOs": by_os,
        "byCompliance": by_compliance,
    }


def _short_error(message):
    text = sanitize_text(message, 240) or ""
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        return "Collector could not retrieve data."
    if "403" in text:
        return "Graph 403: this API is blocked or the managed identity lacks permission."
    return text[:240]


def _partial_errors(evidence, findings):
    domains = []
    seen = set()
    skip = {"tenant_id", "subscription_id", "tenant_name", "primary_domain"}
    for name, payload in (evidence or {}).items():
        if name in skip:
            continue
        if not isinstance(payload, dict):
            continue
        if payload.get("available") is False:
            message = _short_error(payload.get("error") or "Collector could not retrieve data.")
            if name not in seen:
                domains.append({"domain": name, "message": message})
                seen.add(name)
    for finding in findings:
        if finding.get("status") != "Investigate":
            continue
        err = finding.get("error") or {}
        message = _short_error(err.get("message"))
        if message and finding.get("id") not in seen:
            domains.append({"domain": finding.get("name") or finding.get("id"), "message": message})
            seen.add(finding.get("id"))
    return domains


def _sankey_from_inventory(inventory):
    if not inventory or not inventory.get("available"):
        return None
    by_os = inventory.get("byOs") or {}
    by_compliance = inventory.get("byCompliance") or {}
    if not by_os and not by_compliance:
        return None
    return {
        "count": inventory.get("count") or 0,
        "compliant": inventory.get("compliant") or 0,
        "encrypted": inventory.get("encrypted") or 0,
        "byOs": by_os,
        "byCompliance": by_compliance,
    }


def _available_block(source):
    if not isinstance(source, dict) or source.get("available") is not True:
        return None
    return source


def _count_metric(source, key):
    block = _available_block(source)
    if not block:
        return None
    value = _as_int(block.get(key))
    if value is None:
        return None
    return {"value": value}


def _ratio_metric(source, num_key, den_key):
    block = _available_block(source)
    if not block:
        return None
    value = _as_int(block.get(num_key))
    total = _as_int(block.get(den_key))
    if value is None and total is None:
        return None
    metric = {}
    if value is not None:
        metric["value"] = value
    if total is not None:
        metric["total"] = total
    return metric


def _bool_metric(source, key):
    block = _available_block(source)
    if not block or key not in block:
        return None
    value = block.get(key)
    if value is None:
        return None
    return {"value": bool(value)}


def _score_metric(source, key):
    block = _available_block(source)
    if not block:
        return None
    value = block.get(key)
    if value is None or value == "":
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number != number:
        return None
    if number == int(number):
        return {"value": int(number)}
    return {"value": round(number, 1)}


def _compact_metrics(mapping):
    cleaned = {key: value for key, value in mapping.items() if value is not None}
    return cleaned or None


OVERVIEW_ITEM_LIMIT = 100
_ITEM_NAME_KEYS = (
    "displayName",
    "name",
    "deviceName",
    "activityDisplayName",
    "userPrincipalName",
    "rule",
    "nsg",
    "id",
    "appId",
    "resourceId",
)
_ITEM_DETAIL_KEYS = (
    "userPrincipalName",
    "appId",
    "state",
    "operatingSystem",
    "complianceState",
    "trustType",
    "location",
    "sku",
    "assignmentType",
    "role",
    "severity",
    "endDateTime",
)


def _block_list(block, *keys):
    if not isinstance(block, dict):
        return []
    for key in keys:
        value = block.get(key)
        if isinstance(value, list) and value:
            return value
        if isinstance(value, dict):
            inner = value.get("value") or value.get("items") or value.get("results")
            if isinstance(inner, list) and inner:
                return inner
    return []


def _overview_item_name(item):
    if isinstance(item, str):
        return sanitize_text(item, 160)
    if not isinstance(item, dict):
        return None
    for key in _ITEM_NAME_KEYS:
        value = item.get(key)
        if value:
            return sanitize_text(value, 160)
    return None


def _overview_item_detail(item, extra_keys=None):
    if not isinstance(item, dict):
        return None
    keys = list(extra_keys or ()) + list(_ITEM_DETAIL_KEYS)
    parts = []
    seen = set()
    name = _overview_item_name(item)
    for key in keys:
        if key in seen:
            continue
        seen.add(key)
        value = item.get(key)
        if value in (None, "", name):
            continue
        if isinstance(value, bool):
            value = "Yes" if value else "No"
        text = sanitize_text(value, 80)
        if text and text not in parts:
            parts.append(text)
        if len(parts) >= 3:
            break
    return " · ".join(parts) if parts else None


def _overview_items(items, extra_keys=None):
    rows = []
    raw = items if isinstance(items, list) else []
    for item in raw:
        name = _overview_item_name(item)
        if not name:
            continue
        row = {"name": name}
        detail = _overview_item_detail(item, extra_keys)
        if detail:
            row["detail"] = detail
        rows.append(row)
        if len(rows) >= OVERVIEW_ITEM_LIMIT:
            break
    return rows


def _with_items(metric, items, extra_keys=None):
    if not metric:
        return None
    rows = _overview_items(items, extra_keys)
    if not rows:
        return metric
    out = dict(metric)
    out["items"] = rows
    out["itemTotal"] = len(items) if isinstance(items, list) else len(rows)
    return out


def _privileged_member_items(roles_block):
    rows = []
    for role in (roles_block or {}).get("roles") or []:
        if not isinstance(role, dict):
            continue
        role_name = role.get("displayName") or role.get("name") or ""
        members = role.get("members") or []
        if not members:
            if role_name:
                rows.append({"displayName": role_name, "role": role_name, "assignmentType": "Active"})
            continue
        for member in members:
            if isinstance(member, str):
                rows.append({"displayName": member, "role": role_name})
                continue
            if not isinstance(member, dict):
                continue
            row = dict(member)
            row["role"] = row.get("role") or role_name
            rows.append(row)
    return rows


def _pillar_metrics_from_evidence(evidence):
    evidence = evidence or {}
    registration = evidence.get("auth_registration") or {}
    ca = evidence.get("conditional_access") or {}
    roles = evidence.get("privileged_roles") or {}
    pim = evidence.get("privileged_eligibility") or {}
    risky = evidence.get("risky_users") or {}
    reviews = evidence.get("access_reviews") or {}
    identity = _compact_metrics({
        "mfaRegistered": _ratio_metric(registration, "mfa_registered_count", "count"),
        "passwordless": _ratio_metric(registration, "passwordless_count", "count"),
        "caEnabled": _ratio_metric(ca, "enabled_count", "count"),
        "mfaPolicies": _count_metric(ca, "mfa_policy_count"),
        "privilegedMembers": _count_metric(roles, "privileged_member_count"),
        "privilegedRoles": _count_metric(roles, "privileged_role_count"),
        "pimEligible": _count_metric(pim, "eligible_count"),
        "pimActive": _count_metric(pim, "active_assignment_count"),
        "highRiskUsers": _count_metric(risky, "high_count"),
        "accessReviews": _count_metric(reviews, "count"),
    })

    managed = evidence.get("managed_devices") or {}
    compliance = evidence.get("device_compliance") or {}
    entra = evidence.get("entra_devices") or {}
    devices = _compact_metrics({
        "managedDevices": _count_metric(managed, "count"),
        "compliant": _ratio_metric(managed, "compliant_count", "count"),
        "encrypted": _ratio_metric(managed, "encrypted_count", "count"),
        "compliancePolicies": _ratio_metric(compliance, "assigned_count", "count"),
        "entraDevices": _count_metric(entra, "count"),
    })

    network = evidence.get("network_security") or {}
    network_metrics = _compact_metrics({
        "nsgsAssociated": _ratio_metric(network, "nsg_associated_count", "nsg_count"),
        "subnetsWithoutNsg": _count_metric(network, "subnets_without_nsg_count"),
        "publicIps": _ratio_metric(network, "public_ip_attached_count", "public_ip_count"),
        "openManagementRules": _count_metric(network, "open_management_rule_count"),
        "internetAllowRules": _count_metric(network, "internet_allow_rule_count"),
        "firewalls": _count_metric(network, "firewall_count"),
        "wafPolicies": _count_metric(network, "waf_policy_count"),
        "privateEndpoints": _count_metric(network, "private_endpoint_count"),
    })

    labels = evidence.get("sensitivity_labels") or {}
    dlp = evidence.get("dlp_policies") or {}
    retention = evidence.get("retention_labels") or {}
    sharepoint = evidence.get("sharepoint_settings") or {}
    audits = evidence.get("directory_audits") or {}
    data = _compact_metrics({
        "sensitivityLabels": _ratio_metric(labels, "active_count", "count"),
        "dlpScopes": _ratio_metric(dlp, "enabled_count", "count"),
        "retentionLabels": _count_metric(retention, "count"),
        "anonymousSharing": _bool_metric(sharepoint, "anonymous_sharing"),
        "directoryAudits": _count_metric(audits, "count"),
    })

    infra = evidence.get("infrastructure_security") or {}
    score = evidence.get("defender_secure_score") or {}
    assessments = evidence.get("defender_assessments") or {}
    infrastructure = _compact_metrics({
        "resourceGroups": _count_metric(infra, "resource_group_count"),
        "vms": _ratio_metric(infra, "trusted_launch_count", "vm_count"),
        "storageHttps": _ratio_metric(infra, "storage_https_count", "storage_account_count"),
        "storagePublic": _count_metric(infra, "storage_public_count"),
        "keyVaultPurge": _ratio_metric(infra, "key_vault_purge_protection_count", "key_vault_count"),
        "defenderScore": _score_metric(score, "percentage"),
        "unhealthyAssessments": _count_metric(assessments, "unhealthy_count"),
        "privilegedAssignments": _count_metric(infra, "privileged_assignment_count"),
    })
    return {
        "identity": identity,
        "devices": devices,
        "network": network_metrics,
        "data": data,
        "infrastructure": infrastructure,
    }


def _identity_overview_from_evidence(evidence):
    evidence = evidence or {}
    profile = evidence.get("tenant_profile") or {}
    roles = evidence.get("privileged_roles") or {}
    pim = evidence.get("privileged_eligibility") or {}
    apps = evidence.get("application_credentials") or {}
    pim_raw = (
        pim.get("assignments")
        or pim.get("eligible")
        or pim.get("active")
        or pim.get("eligibleAssignments")
        or pim.get("activeAssignments")
        or []
    )
    if isinstance(pim_raw, dict):
        pim_raw = pim_raw.get("value") or pim_raw.get("items") or []
    pim_eligible = [
        item for item in pim_raw
        if isinstance(item, dict) and str(item.get("assignmentType") or item.get("type") or item.get("assignmentState") or "").lower() == "eligible"
    ] or pim_raw
    pim_active = [
        item for item in pim_raw
        if isinstance(item, dict) and str(item.get("assignmentType") or item.get("type") or item.get("assignmentState") or "").lower() == "active"
    ]
    creds = list(apps.get("credentials") or [])
    expired_creds = [item for item in creds if str((item or {}).get("state") or "").lower() == "expired"]
    expiring_creds = [item for item in creds if "expir" in str((item or {}).get("state") or "").lower()]
    secrets = [item for item in creds if "secret" in str((item or {}).get("type") or (item or {}).get("credentialType") or "").lower()]
    certs = [item for item in creds if "cert" in str((item or {}).get("type") or (item or {}).get("credentialType") or "").lower()]
    inventory = _compact_metrics({
        "users": _with_items(_count_metric(profile, "users"), _block_list(profile, "user_list", "users_list", "userList")),
        "guests": _with_items(_count_metric(profile, "guests"), _block_list(profile, "guest_list", "guests_list", "guestList")),
        "groups": _with_items(_count_metric(profile, "groups"), _block_list(profile, "group_list", "groups_list", "groupList")),
        "applications": _with_items(_count_metric(profile, "applications"), _block_list(profile, "application_list", "applications_list", "applicationList")),
        "servicePrincipals": _with_items(_count_metric(profile, "service_principals"), _block_list(profile, "service_principal_list", "servicePrincipals", "servicePrincipalList")),
    })
    privileged = _compact_metrics({
        "members": _with_items(_count_metric(roles, "privileged_member_count"), _privileged_member_items(roles), ("role", "userPrincipalName")),
        "roles": _with_items(_count_metric(roles, "privileged_role_count"), _block_list(roles, "roles")),
        "pimEligible": _with_items(_count_metric(pim, "eligible_count"), pim_eligible, ("role", "userPrincipalName")),
        "pimActive": _with_items(_count_metric(pim, "active_assignment_count"), pim_active or pim_raw, ("role", "userPrincipalName")),
    })
    credentials = _compact_metrics({
        "applicationsAssessed": _with_items(_count_metric(apps, "application_count"), creds),
        "expiredCredentials": _with_items(_count_metric(apps, "expired_credential_count"), expired_creds),
        "expiring30d": _with_items(_count_metric(apps, "expiring_30d_count"), expiring_creds),
        "secrets": _with_items(_count_metric(apps, "secret_count"), secrets or creds),
        "certificates": _with_items(_count_metric(apps, "certificate_count"), certs or creds),
    })
    if not inventory and not privileged and not credentials:
        return None
    return {
        "inventory": inventory,
        "privileged": privileged,
        "credentials": credentials,
    }


def _network_overview_from_evidence(evidence):
    network = (evidence or {}).get("network_security") or {}
    nsgs = _block_list(network, "nsgs")
    firewalls = _block_list(network, "firewalls")
    open_mgmt = _block_list(network, "open_management_rules")
    internet_allow = _block_list(network, "internet_allow_rules")
    private_endpoints = _block_list(network, "private_endpoints")
    public_ips = _block_list(network, "public_ips")
    inventory = _compact_metrics({
        "nsgsAssociated": _with_items(_ratio_metric(network, "nsg_associated_count", "nsg_count"), nsgs),
        "subnetsWithoutNsg": _with_items(_count_metric(network, "subnets_without_nsg_count"), _block_list(network, "subnets_without_nsg", "unprotected_subnets")),
        "publicIps": _with_items(_ratio_metric(network, "public_ip_attached_count", "public_ip_count"), public_ips),
        "privateEndpoints": _with_items(_count_metric(network, "private_endpoint_count"), private_endpoints),
    })
    perimeter = _compact_metrics({
        "firewalls": _with_items(_count_metric(network, "firewall_count"), firewalls),
        "wafPolicies": _with_items(_count_metric(network, "waf_policy_count"), _block_list(network, "waf_policies")),
    })
    exposure = _compact_metrics({
        "openManagementRules": _with_items(_count_metric(network, "open_management_rule_count"), open_mgmt, ("nsg", "rule", "destinationPortRange")),
        "internetAllowRules": _with_items(_count_metric(network, "internet_allow_rule_count"), internet_allow, ("nsg", "rule", "destinationPortRange")),
        "firewalls": _with_items(_count_metric(network, "firewall_count"), firewalls),
        "wafPolicies": _with_items(_count_metric(network, "waf_policy_count"), _block_list(network, "waf_policies")),
    })
    topology = _compact_metrics({
        "vnets": _with_items(_count_metric(network, "vnet_count"), _block_list(network, "vnets")),
        "subnets": _with_items(_count_metric(network, "subnet_count"), _block_list(network, "subnets")),
        "nics": _with_items(_count_metric(network, "nic_count"), _block_list(network, "nics")),
        "peerings": _with_items(_count_metric(network, "peering_count"), _block_list(network, "peerings")),
        "routeTables": _with_items(_count_metric(network, "route_table_count"), _block_list(network, "route_tables")),
        "associatedRouteTables": _with_items(_count_metric(network, "associated_route_table_count"), _block_list(network, "associated_route_tables")),
        "loadBalancers": _with_items(_count_metric(network, "load_balancer_count"), _block_list(network, "load_balancers")),
        "networkWatchers": _with_items(_count_metric(network, "network_watcher_count"), _block_list(network, "network_watchers")),
    })
    addressing = _compact_metrics({
        "publicIps": _with_items(_count_metric(network, "public_ip_count"), public_ips),
        "publicIpsAttached": _with_items(_ratio_metric(network, "public_ip_attached_count", "public_ip_count"), public_ips),
    })
    perimeterDetail = _compact_metrics({
        "firewallPolicies": _with_items(_count_metric(network, "firewall_policy_count"), _block_list(network, "firewall_policies")),
        "firewallsWithPolicy": _with_items(_count_metric(network, "firewall_with_policy_count"), firewalls),
        "premiumFirewalls": _with_items(_count_metric(network, "premium_firewall_count"), firewalls),
        "threatIntel": _count_metric(network, "threat_intel_count"),
        "applicationGateways": _with_items(_count_metric(network, "application_gateway_count"), _block_list(network, "application_gateways")),
        "applicationGatewayWaf": _count_metric(network, "application_gateway_waf_count"),
        "wafPrevention": _count_metric(network, "waf_prevention_count"),
        "wafAssociated": _count_metric(network, "waf_associated_count"),
        "frontDoorProfiles": _with_items(_count_metric(network, "front_door_profile_count"), _block_list(network, "front_door_profiles")),
        "ddosPlans": _with_items(_count_metric(network, "ddos_plan_count"), _block_list(network, "ddos_plans")),
        "ddosProtectedVnets": _with_items(_count_metric(network, "ddos_protected_vnet_count"), _block_list(network, "ddos_protected_vnets")),
    })
    remoteAccess = _compact_metrics({
        "vpnGateways": _with_items(_count_metric(network, "vpn_gateway_count"), _block_list(network, "vpn_gateways")),
        "bastions": _with_items(_count_metric(network, "bastion_count"), _block_list(network, "bastions")),
        "expressRoute": _with_items(_count_metric(network, "express_route_count"), _block_list(network, "express_route_circuits", "express_routes")),
    })
    paasExposure = _compact_metrics({
        "privateEndpoints": _with_items(_count_metric(network, "private_endpoint_count"), private_endpoints),
        "paasPublic": _with_items(_count_metric(network, "paas_public_count"), _block_list(network, "paas_public")),
        "paasRestricted": _with_items(_count_metric(network, "paas_restricted_count"), _block_list(network, "paas_restricted")),
        "storageAccounts": _with_items(_count_metric(network, "storage_account_count"), _block_list(network, "storage_accounts")),
        "keyVaults": _with_items(_count_metric(network, "key_vault_count"), _block_list(network, "key_vaults")),
        "sqlServers": _with_items(_count_metric(network, "sql_server_count"), _block_list(network, "sql_servers")),
    })
    if not any([inventory, perimeter, exposure, topology, addressing, perimeterDetail, remoteAccess, paasExposure]):
        return None
    return {
        "inventory": inventory,
        "perimeter": perimeter,
        "exposure": exposure,
        "topology": topology,
        "addressing": addressing,
        "perimeterDetail": perimeterDetail,
        "remoteAccess": remoteAccess,
        "paasExposure": paasExposure,
    }


def _devices_overview_from_evidence(evidence):
    evidence = evidence or {}
    managed = evidence.get("managed_devices") or {}
    compliance = evidence.get("device_compliance") or {}
    entra = evidence.get("entra_devices") or {}
    enrollment = evidence.get("device_enrollment") or {}
    managed_devices = _block_list(managed, "devices")
    entra_devices = _block_list(entra, "devices")
    policies_list = _block_list(compliance, "policies")
    configs = _block_list(enrollment, "configurations")
    inventory = _compact_metrics({
        "managedDevices": _with_items(_count_metric(managed, "count"), managed_devices, ("operatingSystem", "complianceState")),
        "entraDevices": _with_items(_count_metric(entra, "count"), entra_devices, ("operatingSystem", "trustType")),
    })
    compliance_metrics = _compact_metrics({
        "compliant": _with_items(
            _ratio_metric(managed, "compliant_count", "count"),
            [item for item in managed_devices if str((item or {}).get("complianceState") or "").lower() == "compliant"],
            ("operatingSystem", "complianceState"),
        ),
        "unknownCompliance": _with_items(
            _count_metric(managed, "unknown_compliance_count"),
            [item for item in managed_devices if "unknown" in str((item or {}).get("complianceState") or "").lower()],
            ("operatingSystem", "complianceState"),
        ),
    })
    encryption = _compact_metrics({
        "encrypted": _with_items(
            _ratio_metric(managed, "encrypted_count", "count"),
            [item for item in managed_devices if item.get("isEncrypted")],
            ("operatingSystem", "isEncrypted"),
        ),
    })
    ownership = _compact_metrics({
        "companyOwned": _with_items(
            _count_metric(managed, "company_owned_count"),
            [item for item in managed_devices if "company" in str((item or {}).get("managedDeviceOwnerType") or "").lower()],
            ("managedDeviceOwnerType",),
        ),
        "personalOwned": _with_items(
            _count_metric(managed, "personal_owned_count"),
            [item for item in managed_devices if "personal" in str((item or {}).get("managedDeviceOwnerType") or "").lower()],
            ("managedDeviceOwnerType",),
        ),
        "unknownOwner": _with_items(
            _count_metric(managed, "unknown_owner_count"),
            [item for item in managed_devices if "unknown" in str((item or {}).get("managedDeviceOwnerType") or "").lower()],
            ("managedDeviceOwnerType",),
        ),
    })
    policies = _compact_metrics({
        "policies": _with_items(_count_metric(compliance, "count"), policies_list),
        "assigned": _with_items(_ratio_metric(compliance, "assigned_count", "count"), [item for item in policies_list if item.get("assigned")]),
        "unassigned": _with_items(_count_metric(compliance, "unassigned_count"), [item for item in policies_list if item.get("assigned") is False]),
        "minOs": _with_items(_count_metric(compliance, "min_os_policy_count"), [item for item in policies_list if item.get("requires_min_os")]),
        "encryption": _with_items(_count_metric(compliance, "encryption_policy_count"), [item for item in policies_list if item.get("requires_encryption")]),
        "firewall": _with_items(_count_metric(compliance, "firewall_policy_count"), [item for item in policies_list if item.get("requires_firewall")]),
        "secureBoot": _with_items(_count_metric(compliance, "secure_boot_policy_count"), [item for item in policies_list if item.get("requires_secure_boot")]),
        "tpm": _with_items(_count_metric(compliance, "tpm_policy_count"), [item for item in policies_list if item.get("requires_tpm")]),
    })
    enrollment_metrics = _compact_metrics({
        "configurations": _with_items(_count_metric(enrollment, "count"), configs),
        "restrictions": _with_items(_count_metric(enrollment, "restriction_count"), [item for item in configs if item.get("is_restriction")]),
        "platformRestrictions": _with_items(_count_metric(enrollment, "platform_restriction_count"), [item for item in configs if item.get("is_restriction")]),
    })
    entra_state = _compact_metrics({
        "managed": _with_items(_count_metric(entra, "managed_count"), [item for item in entra_devices if item.get("isManaged")], ("trustType",)),
        "compliant": _with_items(_count_metric(entra, "compliant_count"), [item for item in entra_devices if item.get("isCompliant")], ("trustType",)),
    })
    if not any([inventory, compliance_metrics, encryption, ownership, policies, enrollment_metrics, entra_state]):
        return None
    return {
        "inventory": inventory,
        "compliance": compliance_metrics,
        "encryption": encryption,
        "ownership": ownership,
        "policies": policies,
        "enrollment": enrollment_metrics,
        "entra": entra_state,
    }


def _data_overview_from_evidence(evidence):
    evidence = evidence or {}
    labels = evidence.get("sensitivity_labels") or {}
    dlp = evidence.get("dlp_policies") or {}
    retention = evidence.get("retention_labels") or {}
    sharepoint = evidence.get("sharepoint_settings") or {}
    audits = evidence.get("directory_audits") or {}
    label_items = _block_list(labels, "labels")
    dlp_items = _block_list(dlp, "policies")
    retention_items = _block_list(retention, "labels")
    audit_items = _block_list(audits, "events")
    informationProtection = _compact_metrics({
        "labels": _with_items(_ratio_metric(labels, "active_count", "count"), label_items),
        "encrypted": _with_items(_count_metric(labels, "encrypted_count"), [item for item in label_items if item.get("encrypted") or item.get("encryption")]),
        "contentMarking": _with_items(_count_metric(labels, "content_marking_count"), [item for item in label_items if item.get("contentMarking")]),
        "autoLabel": _with_items(_count_metric(labels, "auto_label_count"), [item for item in label_items if item.get("autoLabel") or item.get("auto_label")]),
    })
    dlp_metrics = _compact_metrics({
        "scopes": _with_items(_ratio_metric(dlp, "enabled_count", "count"), dlp_items, ("executionMode", "locations")),
        "locations": _count_metric(dlp, "location_count"),
    })
    sharing = _compact_metrics({
        "anonymousSharing": _bool_metric(sharepoint, "anonymous_sharing"),
        "resharing": _bool_metric(sharepoint, "isResharingByExternalUsersEnabled"),
        "legacyAuthBlocked": _bool_metric(sharepoint, "legacy_auth_blocked"),
    })
    retention_metrics = _compact_metrics({
        "labels": _with_items(_count_metric(retention, "count"), retention_items),
        "published": _with_items(_count_metric(retention, "published_count"), [item for item in retention_items if item.get("isEnabled") or item.get("published")]),
    })
    audit = _compact_metrics({
        "directoryAudits": _with_items(_count_metric(audits, "count"), audit_items, ("activityDisplayName", "result")),
        "success": _with_items(_count_metric(audits, "success_count"), [item for item in audit_items if str((item or {}).get("result") or "").lower() in ("success", "succeeded")]),
    })
    if not any([informationProtection, dlp_metrics, sharing, retention_metrics, audit]):
        return None
    return {
        "informationProtection": informationProtection,
        "dlp": dlp_metrics,
        "sharing": sharing,
        "retention": retention_metrics,
        "audit": audit,
    }


def _infrastructure_overview_from_evidence(evidence):
    evidence = evidence or {}
    infra = evidence.get("infrastructure_security") or {}
    score = evidence.get("defender_secure_score") or {}
    assessments = evidence.get("defender_assessments") or {}
    network = evidence.get("network_security") or {}
    resource_groups = _block_list(infra, "resource_groups")
    vms = _block_list(infra, "vms")
    storage_accounts = _block_list(infra, "storage_accounts")
    key_vaults = _block_list(infra, "key_vaults")
    unhealthy = _block_list(assessments, "unhealthy_assessments")
    healthy = _block_list(assessments, "healthy_assessments")
    plans = _block_list(assessments, "defender_plans")
    inventory = _compact_metrics({
        "resourceGroups": _with_items(_count_metric(infra, "resource_group_count"), resource_groups),
        "vms": _with_items(_ratio_metric(infra, "trusted_launch_count", "vm_count"), vms),
        "storageHttps": _with_items(_ratio_metric(infra, "storage_https_count", "storage_account_count"), storage_accounts),
        "storagePublic": _with_items(_count_metric(infra, "storage_public_count"), _block_list(infra, "public_storage", "storage_public")),
    })
    privileged = _compact_metrics({
        "keyVaultPurge": _with_items(_ratio_metric(infra, "key_vault_purge_protection_count", "key_vault_count"), key_vaults),
        "privilegedAssignments": _with_items(_count_metric(infra, "privileged_assignment_count"), _block_list(infra, "privileged_assignments")),
    })
    defender = _compact_metrics({
        "defenderScore": _score_metric(score, "percentage"),
        "unhealthyAssessments": _with_items(_count_metric(assessments, "unhealthy_count"), unhealthy, ("severity", "resourceId")),
        "keyVaultPurge": _with_items(_ratio_metric(infra, "key_vault_purge_protection_count", "key_vault_count"), key_vaults),
        "privilegedAssignments": _with_items(_count_metric(infra, "privileged_assignment_count"), _block_list(infra, "privileged_assignments")),
        "healthyAssessments": _with_items(_count_metric(assessments, "healthy_count"), healthy),
        "assessmentCount": _count_metric(assessments, "assessment_count"),
        "defenderPlans": _with_items(_count_metric(assessments, "defender_plan_count"), plans),
    })
    compute = _compact_metrics({
        "vms": _with_items(_count_metric(infra, "vm_count"), vms),
        "vmss": _with_items(_count_metric(infra, "vmss_count"), _block_list(infra, "vmss")),
        "trustedLaunch": _with_items(_ratio_metric(infra, "trusted_launch_count", "vm_count"), vms),
        "encryptedOs": _with_items(_ratio_metric(infra, "encrypted_os_disk_count", "vm_count"), vms),
        "computeIdentity": _ratio_metric(infra, "compute_identity_count", "compute_count"),
        "appServices": _with_items(_count_metric(infra, "app_service_count"), _block_list(infra, "app_services")),
        "functionApps": _with_items(_count_metric(infra, "function_app_count"), _block_list(infra, "function_apps")),
    })
    storage = _compact_metrics({
        "https": _with_items(_ratio_metric(infra, "storage_https_count", "storage_account_count"), storage_accounts),
        "public": _with_items(_count_metric(infra, "storage_public_count"), _block_list(infra, "public_storage", "storage_public")),
        "noPublicBlob": _with_items(_ratio_metric(infra, "storage_no_public_blob_count", "storage_account_count"), storage_accounts),
        "identity": _count_metric(infra, "storage_identity_count"),
    })
    exposure = _compact_metrics({
        "openManagementRules": _with_items(_count_metric(network, "open_management_rule_count"), _block_list(network, "open_management_rules"), ("nsg", "rule")),
        "internetAllowRules": _with_items(_count_metric(network, "internet_allow_rule_count"), _block_list(network, "internet_allow_rules"), ("nsg", "rule")),
        "publicIps": _with_items(_ratio_metric(network, "public_ip_attached_count", "public_ip_count"), _block_list(network, "public_ips")),
        "privateEndpoints": _with_items(_count_metric(network, "private_endpoint_count"), _block_list(network, "private_endpoints")),
        "keyVaultPublic": _with_items(_count_metric(infra, "key_vault_public_count"), key_vaults),
        "aksPrivate": _with_items(_ratio_metric(infra, "aks_private_count", "aks_count"), _block_list(infra, "aks")),
        "acrPrivate": _with_items(_ratio_metric(infra, "acr_private_count", "acr_count"), _block_list(infra, "acrs")),
    })
    rbac = _compact_metrics({
        "roleAssignments": _with_items(_count_metric(infra, "role_assignment_count"), _block_list(infra, "role_assignments")),
        "privilegedAssignments": _with_items(_count_metric(infra, "privileged_assignment_count"), _block_list(infra, "privileged_assignments")),
        "subscriptionAdmins": _with_items(_count_metric(infra, "subscription_admin_count"), _block_list(infra, "subscription_admins")),
        "userAssignedIdentities": _with_items(_count_metric(infra, "user_assigned_identity_count"), _block_list(infra, "user_assigned_identities")),
    })
    key_vault = _compact_metrics({
        "vaults": _with_items(_count_metric(infra, "key_vault_count"), key_vaults),
        "rbac": _with_items(_ratio_metric(infra, "key_vault_rbac_count", "key_vault_count"), key_vaults),
        "purge": _with_items(_ratio_metric(infra, "key_vault_purge_protection_count", "key_vault_count"), key_vaults),
        "softDelete": _with_items(_ratio_metric(infra, "key_vault_soft_delete_count", "key_vault_count"), key_vaults),
        "public": _with_items(_count_metric(infra, "key_vault_public_count"), key_vaults),
    })
    governance = _compact_metrics({
        "policyAssignments": _with_items(_count_metric(infra, "policy_assignment_count"), _block_list(infra, "policy_assignments")),
        "policyExemptions": _with_items(_count_metric(infra, "policy_exemption_count"), _block_list(infra, "policy_exemptions")),
        "taggedGroups": _with_items(_ratio_metric(infra, "tagged_resource_group_count", "resource_group_count"), resource_groups),
    })
    monitoring = _compact_metrics({
        "logAnalytics": _with_items(_count_metric(infra, "log_analytics_count"), _block_list(infra, "log_analytics")),
        "diagnostics": _with_items(_count_metric(infra, "subscription_diagnostic_count"), _block_list(infra, "diagnostics")),
    })
    backup = _compact_metrics({
        "recoveryVaults": _with_items(_count_metric(infra, "recovery_vault_count"), _block_list(infra, "recovery_vaults")),
        "backupVaults": _with_items(_count_metric(infra, "backup_vault_count"), _block_list(infra, "backup_vaults")),
    })
    if not any([
        inventory, privileged, defender, compute, storage, exposure,
        rbac, key_vault, governance, monitoring, backup,
    ]):
        return None
    return {
        "inventory": inventory,
        "privileged": privileged,
        "defender": defender,
        "compute": compute,
        "storage": storage,
        "exposure": exposure,
        "rbac": rbac,
        "keyVault": key_vault,
        "governance": governance,
        "monitoring": monitoring,
        "backup": backup,
    }


def _visualizations_from_evidence(evidence, inventory):
    methods = evidence.get("authentication_methods") or {}
    registration = evidence.get("auth_registration") or {}
    ca = evidence.get("conditional_access") or {}
    sign_ins = evidence.get("sign_ins") or {}
    privileged = None
    if methods.get("available"):
        privileged = {
            "enabledMethodCount": methods.get("enabled_method_count") or 0,
            "methodCount": methods.get("method_count") or 0,
            "enabledMethods": [
                item.get("id") for item in (methods.get("enabled_methods") or []) if item.get("id")
            ][:12],
        }
    user_auth = None
    if registration.get("available"):
        user_auth = {
            "sampled": registration.get("count") or 0,
            "mfaRegistered": registration.get("mfa_registered_count") or 0,
            "passwordless": registration.get("passwordless_count") or 0,
            "ssprRegistered": registration.get("sspr_registered_count") or 0,
        }
    ca_coverage = None
    if ca.get("available"):
        ca_coverage = {
            "policies": ca.get("count") or 0,
            "enabled": ca.get("enabled_count") or 0,
            "mfaPolicies": ca.get("mfa_policy_count") or 0,
            "legacyBlock": ca.get("legacy_block_count") or 0,
            "allUsersMfa": ca.get("all_users_mfa_count") or 0,
        }
    device_sign_in = None
    if sign_ins.get("available"):
        device_sign_in = {
            "sampled": sign_ins.get("count") or 0,
            "success": sign_ins.get("success_count") or 0,
            "failure": sign_ins.get("failure_count") or 0,
            "conditionalAccessSuccess": sign_ins.get("conditional_access_success_count") or 0,
            "managedDevice": sign_ins.get("managed_device_count") or 0,
        }
    return {
        "deviceFlow": _sankey_from_inventory(inventory),
        "privilegedAuth": privileged,
        "userAuthCoverage": user_auth,
        "conditionalAccessCoverage": ca_coverage,
        "deviceSignIn": device_sign_in,
        "pillarMetrics": _pillar_metrics_from_evidence(evidence),
        "identityOverview": _identity_overview_from_evidence(evidence),
        "networkOverview": _network_overview_from_evidence(evidence),
        "devicesOverview": _devices_overview_from_evidence(evidence),
        "dataOverview": _data_overview_from_evidence(evidence),
        "infrastructureOverview": _infrastructure_overview_from_evidence(evidence),
    }


def _tenant_from_evidence(payload, evidence):
    profile = evidence.get("tenant_profile") or {}
    profile_ok = bool(profile.get("available"))
    managed = evidence.get("managed_devices") or {}
    managed_available = bool(managed.get("available"))
    entra = evidence.get("entra_devices") or {}
    entra_available = bool(entra.get("available"))
    intune_count = _metric(managed.get("count"), managed_available)
    entra_count = _metric(entra.get("count"), entra_available)
    total_devices = None
    if intune_count is not None or entra_count is not None:
        total_devices = (intune_count or 0) + (entra_count or 0)
    return {
        "tenantName": sanitize_text(
            payload.get("tenant_name")
            or payload.get("tenantName")
            or profile.get("tenant_name"),
            120,
        ),
        "tenantId": payload.get("tenant_id") or profile.get("tenant_id") or evidence.get("tenant_id"),
        "subscriptionId": payload.get("subscription_id")
        or payload.get("subscriptionId")
        or evidence.get("subscription_id"),
        "cloudProvider": sanitize_text(payload.get("cloud_provider") or payload.get("cloudProvider"), 40) or "Azure",
        "primaryDomain": sanitize_text(
            payload.get("primary_domain")
            or payload.get("primaryDomain")
            or profile.get("primary_domain"),
            120,
        ),
        "users": _metric(payload.get("users") if payload.get("users") is not None else profile.get("users"), profile_ok or payload.get("users") is not None),
        "guests": _metric(payload.get("guests") if payload.get("guests") is not None else profile.get("guests"), profile_ok or payload.get("guests") is not None),
        "groups": _metric(payload.get("groups") if payload.get("groups") is not None else profile.get("groups"), profile_ok or payload.get("groups") is not None),
        "applications": _metric(payload.get("applications") if payload.get("applications") is not None else profile.get("applications"), profile_ok or payload.get("applications") is not None),
        "servicePrincipals": _metric(profile.get("service_principals"), profile_ok),
        "devices": total_devices,
        "totalDevices": total_devices,
        "managedDevices": intune_count,
        "entraDevices": entra_count,
    }


def adapt_assessment(payload):
    payload = payload or {}
    findings = payload.get("findings") or (payload.get("report") or {}).get("findings") or []
    evidence = payload.get("evidence") or {}
    evaluated_at = payload.get("completed_at") or payload.get("updated_at")
    tests = deduplicate_tests([
        enrich_test(adapt_finding(item, evaluated_at), evidence) for item in findings
    ])
    identity_tests = [t for t in tests if t.get("area") == "Identity"]
    device_tests = [t for t in tests if t.get("area") == "Devices"]
    network_tests = [t for t in tests if t.get("area") == "Network"]
    data_tests = [t for t in tests if t.get("area") == "Data"]
    infrastructure_tests = [t for t in tests if t.get("area") == "Infrastructure"]
    other_tests = [t for t in tests if t.get("area") not in ASSESSMENT_AREAS]
    all_pillar_tests = identity_tests + device_tests + network_tests + data_tests + infrastructure_tests
    identity_summary = summarize_tests(identity_tests)
    device_summary = summarize_tests(device_tests)
    backend_score = payload.get("score")
    try:
        backend_score = int(backend_score) if backend_score is not None else None
    except (TypeError, ValueError):
        backend_score = None
    computed = weighted_score(all_pillar_tests)
    inventory = _device_inventory(evidence)
    status = str(payload.get("status") or "").strip().lower() or "queued"
    if status not in ("queued", "running", "completed", "failed"):
        status = "failed" if payload.get("error") else "completed"
    partial = _partial_errors(evidence, all_pillar_tests + other_tests)
    cache_ttl = payload.get("cache_ttl_minutes")
    cache_age = payload.get("cache_age_minutes")
    stale = False
    try:
        if cache_ttl is not None and cache_age is not None and float(cache_age) > float(cache_ttl):
            stale = True
    except (TypeError, ValueError):
        stale = False
    tenant = _tenant_from_evidence(payload, evidence)
    return {
        "assessmentId": payload.get("assessment_id") or payload.get("assessmentId"),
        "status": status,
        "progress": _as_int(payload.get("progress")) or 0,
        "message": sanitize_text(payload.get("message"), 240),
        "score": backend_score,
        "scoreSource": "backend" if backend_score is not None else "weighted",
        "weightedScore": computed,
        "startedAt": payload.get("started_at") or payload.get("startedAt"),
        "completedAt": payload.get("completed_at") or payload.get("completedAt"),
        "cached": bool(payload.get("cached")),
        "cacheTtlMinutes": cache_ttl,
        "cacheAgeMinutes": cache_age,
        "stale": stale,
        "tenant": tenant,
        "identity": {"summary": identity_summary, "tests": identity_tests},
        "devices": {"summary": device_summary, "tests": device_tests},
        "network": {"summary": summarize_tests(network_tests), "tests": network_tests},
        "data": {"summary": summarize_tests(data_tests), "tests": data_tests},
        "infrastructure": {"summary": summarize_tests(infrastructure_tests), "tests": infrastructure_tests},
        "other": {"summary": summarize_tests(other_tests), "tests": other_tests},
        "partial": partial,
        "error": sanitize_text(payload.get("error") or payload.get("message") if status == "failed" else None),
        "deviceInventory": inventory,
        "visualizations": _visualizations_from_evidence(evidence, inventory),
        "priority": priority_remediation(all_pillar_tests),
    }


def csv_rows(assessment, tests=None):
    rows = []
    selected = tests if tests is not None else []
    if tests is None:
        selected = (
            (assessment.get("identity") or {}).get("tests", [])
            + (assessment.get("devices") or {}).get("tests", [])
            + (assessment.get("network") or {}).get("tests", [])
            + (assessment.get("data") or {}).get("tests", [])
            + (assessment.get("infrastructure") or {}).get("tests", [])
        )
    for test in selected:
        rows.append(
            {
                "assessmentId": assessment.get("assessmentId"),
                "timestamp": assessment.get("completedAt") or assessment.get("startedAt"),
                "area": test.get("area"),
                "name": test.get("name"),
                "category": test.get("category"),
                "risk": test.get("risk"),
                "status": test.get("status"),
                "sfiPillar": ", ".join(test.get("sfiPillars") or []),
                "recommendation": test.get("recommendation") or "",
                "evidenceAvailable": "yes" if test.get("evidence") else "no",
            }
        )
    return rows
