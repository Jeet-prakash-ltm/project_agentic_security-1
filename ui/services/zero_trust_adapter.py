"""Adapt Zero Trust Function App payloads into the assessment UI model."""

from __future__ import annotations

import re

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
    (re.compile(r"CA-|CONDITIONAL"), "Conditional Access"),
    (re.compile(r"PRIVILEGED|PIM|ROLE"), "Privileged accounts"),
    (re.compile(r"AUTH-METHOD|PHISHING|FIDO|MFA"), "Authentication methods"),
    (re.compile(r"RISKY|IDENTITY-PROTECTION"), "High-risk users and sign-ins"),
    (re.compile(r"SECURITY-DEFAULT|AUTHORIZATION|TENANT"), "Tenant administration"),
    (re.compile(r"GUEST|EXTERNAL|CROSS-TENANT"), "External identities"),
    (re.compile(r"APP|WORKLOAD|CREDENTIAL|REDIRECT|CONSENT"), "Application identity security"),
    (re.compile(r"DIAGNOSTIC|MONITOR"), "Monitoring and diagnostics"),
    (re.compile(r"ENTITLEMENT"), "Entitlement management"),
    (re.compile(r"TOKEN|LEGACY"), "Token protection"),
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
    (re.compile(r"SENSITIVITY|LABEL"), "Information protection"),
    (re.compile(r"DLP"), "Data loss prevention"),
    (re.compile(r"DATA"), "Data protection"),
)

INFRASTRUCTURE_CATEGORY_RULES = (
    (re.compile(r"SECURE-SCORE"), "Secure score"),
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
    }


def _tenant_from_evidence(payload, evidence):
    profile = evidence.get("tenant_profile") or {}
    profile_ok = bool(profile.get("available"))
    managed = evidence.get("managed_devices") or {}
    managed_available = bool(managed.get("available"))
    return {
        "tenantName": sanitize_text(
            payload.get("tenant_name")
            or payload.get("tenantName")
            or profile.get("tenant_name"),
            120,
        ),
        "tenantId": payload.get("tenant_id") or profile.get("tenant_id") or evidence.get("tenant_id"),
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
        "devices": _metric(managed.get("count"), managed_available),
        "managedDevices": _metric(managed.get("count"), managed_available),
    }


def adapt_assessment(payload):
    payload = payload or {}
    findings = payload.get("findings") or (payload.get("report") or {}).get("findings") or []
    evidence = payload.get("evidence") or {}
    evaluated_at = payload.get("completed_at") or payload.get("updated_at")
    tests = deduplicate_tests([adapt_finding(item, evaluated_at) for item in findings])
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
