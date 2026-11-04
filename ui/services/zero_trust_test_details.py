"""Microsoft Zero Trust-style metadata and evidence tables for assessment tests."""

from __future__ import annotations

EVIDENCE_LIMIT = 100


def _d(impact, effort, license_name, checked, how, actions):
    return {
        "userImpact": impact,
        "implementationEffort": effort,
        "license": license_name,
        "whatWasChecked": checked,
        "howToCheck": how,
        "remediationActions": list(actions),
    }


TEST_DETAILS = {
    "ZT-ID-ID01-INVENTORY": _d(
        "Low", "Low", "Free",
        "If identity inventory is incomplete, orphaned users, guests, and apps stay outside Conditional Access, access reviews, and incident response. Attackers hide in untracked identities.",
        "Read Entra users, guests, groups, applications, and service principals. Confirm counts are returned and remain current.",
        ["Keep Directory.Read.All inventory collection healthy", "Review guest and application growth against expected baselines"],
    ),
    "ZT-ID-ID02-MFA": _d(
        "Medium", "High", "Free",
        "Without MFA coverage, stolen passwords grant immediate access. Threat actors use password spray and leaked credentials to sign in as users and then move laterally.",
        "List enabled authentication methods, Conditional Access policies that grant MFA, and user MFA registration. Registration should cover at least 80% of sampled users.",
        ["Require MFA for all users with Conditional Access", "Complete MFA registration for remaining users", "Exclude break-glass accounts only with monitored alternatives"],
    ),
    "ZT-ID-ID03-CONDITIONAL-ACCESS": _d(
        "Medium", "High", "Free",
        "If Conditional Access is missing or mostly report-only, apps are reachable with password-only sign-in. Attackers persist by blending into legitimate sessions.",
        "List Conditional Access policies. Confirm enabled policies, MFA or authentication-strength grants, and session controls on sensitive apps.",
        ["Enable Conditional Access for all users and apps", "Add MFA or authentication strength grants", "Use session controls on privileged and high-value apps"],
    ),
    "ZT-ID-ID04-LEGACY-AUTH": _d(
        "Low", "Medium", "Free",
        "Legacy protocols skip modern MFA. IMAP, POP, SMTP, and Exchange ActiveSync are a common path for password-spray takeovers.",
        "Find enabled Conditional Access policies that block Exchange ActiveSync or other clients. Review recent sign-ins for legacy client usage.",
        ["Create a CA policy that blocks legacy authentication for all users", "Disable legacy protocols in Exchange Online", "Investigate remaining legacy sign-ins"],
    ),
    "ZT-ID-ID05-STRONG-AUTH": _d(
        "Medium", "High", "Free",
        "Phishing kits intercept MFA approvals. Passwordless and phishing-resistant methods close that window for privileged and high-risk users.",
        "Check that FIDO2, certificate, or Microsoft Authenticator passwordless methods are enabled, and that authentication-strength policies exist.",
        ["Enable FIDO2 or certificate-based authentication", "Use authentication strengths for privileged roles", "Roll out passwordless to admin and high-value users first"],
    ),
    "ZT-ID-ID06-PRIVILEGED": _d(
        "Medium", "High", "Entra ID P2",
        "Standing Global Admin and other directory roles give attackers durable control after one compromised mailbox or device.",
        "Count privileged directory role members and PIM eligible versus active assignments. Standing privileged membership should stay small and eligible.",
        ["Convert standing admins to PIM-eligible assignments", "Reduce Global Administrator count", "Require strong authentication on privileged roles"],
    ),
    "ZT-ID-ID07-LEAST-PRIVILEGE": _d(
        "Medium", "High", "Entra ID P2",
        "Broad directory roles let a single compromised identity change security policy, mail flow, or application consent.",
        "Review privileged role members, identity type, and assignment count against a defined least-privilege baseline.",
        ["Replace broad directory roles with job-specific roles", "Remove permanent assignments where PIM eligibility is enough", "Recertify privileged access on a schedule"],
    ),
    "ZT-ID-ID08-PROTECTION": _d(
        "Low", "Medium", "Entra ID P2",
        "Unremediated risky users and sign-ins mean leaked or atypical credentials keep working. Identity Protection without CA enforcement is detection without control.",
        "Read high-risk users and detections. Confirm user-risk and sign-in-risk Conditional Access policies are enabled.",
        ["Enable user-risk and sign-in-risk Conditional Access", "Remediate high-risk users", "Investigate repeated high-risk detections"],
    ),
    "ZT-ID-ID09-EXTERNAL": _d(
        "Medium", "Medium", "Free",
        "Unrestricted guests can enumerate directory objects and inherit oversharing. Invites from anyone expand the attack surface without review.",
        "Read authorization policy guestUserRoleId and allowInvitesFrom, and compare against guest count.",
        ["Set guest access to restricted or guest", "Limit who can invite guests", "Review existing guest accounts with access reviews"],
    ),
    "ZT-ID-ID10-WORKLOAD": _d(
        "Low", "High", "Free",
        "If application certificates and secrets are not rotated, attackers who extract them keep access until expiry. Compromised app credentials blend into legitimate service traffic.",
        "Query application registrations for password and key credentials. Flag expired secrets and certificates and those expiring within 30 days.",
        ["Rotate expired application secrets and certificates", "Define an application credential policy for lifetimes", "Create a least-privileged role to rotate app credentials", "Prefer managed identity over long-lived secrets"],
    ),
    "ZT-ID-ID11-ACCESS-REVIEWS": _d(
        "Low", "Medium", "Entra ID Governance",
        "Without recertification, guests, groups, and app assignments accumulate. Stale access is a quiet privilege-escalation path.",
        "List access review definitions and confirm reviews exist for privileged roles, guests, and application assignments.",
        ["Create access reviews for privileged roles", "Review guest and application assignments on a schedule", "Act on deny and not-responded results"],
    ),
    "ZT-ID-ID12-MONITORING": _d(
        "Low", "Low", "Free",
        "Missing sign-in and audit logs hide failed attacks and successful persistence. Investigation depends on Conditional Access and directory audit evidence.",
        "Read recent sign-ins and directory audits. Confirm Conditional Access success and failure outcomes are present.",
        ["Retain Entra sign-in and audit logs", "Send logs to a SIEM", "Alert on privileged directory changes"],
    ),
    "ZT-ID-SECURITY-DEFAULTS": _d(
        "Medium", "Low", "Free",
        "Security defaults provide baseline MFA when Conditional Access is not yet in place. Disabling both leaves password-only access.",
        "Read identity security defaults. If disabled, confirm equivalent Conditional Access MFA policies are enabled.",
        ["Keep security defaults on, or replace them with equivalent CA MFA policies", "Do not disable defaults until CA coverage is verified"],
    ),
    "ZT-DEV-DA01-ENROLLMENT": _d(
        "Medium", "Medium", "Microsoft Intune",
        "Open enrollment lets unmanaged or personal devices join and then request resources. Platform restrictions and owner type separate corporate and BYOD risk.",
        "List Intune enrollment configurations and restriction objects. Confirm company versus personal owner counts on managed devices.",
        ["Configure enrollment restrictions by platform", "Separate corporate and BYOD enrollment", "Block personally owned devices where policy requires it"],
    ),
    "ZT-DEV-DA02-INVENTORY": _d(
        "Low", "Medium", "Microsoft Intune",
        "Devices missing from Intune cannot be marked compliant or encrypted. Attackers use unmanaged endpoints to keep tokens after mailbox compromise.",
        "List managed devices with compliance, encryption, and owner type. Investigate unknown owner and noncompliant records.",
        ["Remediate noncompliant Intune devices", "Populate owner type", "Retire stale device records"],
    ),
    "ZT-DEV-DA02-ENCRYPTION": _d(
        "Low", "Medium", "Microsoft Intune",
        "Unencrypted devices expose cached tokens and offline data after loss or theft.",
        "Read isEncrypted on managed devices. Require BitLocker or platform encryption in compliance policy.",
        ["Require encryption in Intune compliance policies", "Remediate devices that do not report encryption"],
    ),
    "ZT-DEV-DA03-COMPLIANCE": _d(
        "Medium", "High", "Microsoft Intune",
        "Unassigned compliance policies never mark devices noncompliant, so Conditional Access device grants cannot fail closed.",
        "List compliance policies, assignments, and whether min OS, encryption, firewall, Secure Boot, or TPM are required.",
        ["Assign compliance policies to all device groups", "Require min OS, encryption, and firewall", "Use compliant-device grants in Conditional Access"],
    ),
    "ZT-DEV-DA04-CONDITIONAL-ACCESS": _d(
        "Medium", "High", "Microsoft Intune",
        "Location-only grants let unmanaged devices sign in from trusted networks. Device trust should be required for sensitive apps.",
        "List enabled CA policies with compliant or domain-joined grants versus location-dependent grants.",
        ["Require compliant or Entra-joined devices on sensitive apps", "Avoid location-only grants as the sole control"],
    ),
    "ZT-DEV-DA04-SESSION": _d(
        "Low", "Medium", "Microsoft Intune",
        "Without session controls, unmanaged browsers keep persistent cookies on high-value apps.",
        "Find enabled CA policies with application-enforced restrictions, cloud app security, or sign-in frequency.",
        ["Add application-enforced restrictions for unmanaged access", "Use sign-in frequency on privileged apps"],
    ),
    "ZT-DEV-DA05-SIGNINS": _d(
        "Low", "Low", "Free",
        "Sign-in logs show whether device identity is present in live access. Unknown devices mean CA device grants are not observed.",
        "Sample recent sign-ins for managed, compliant, and unknown device flags plus Conditional Access success and failure.",
        ["Require device identity on sign-in", "Investigate unknown or unmanaged access to sensitive apps"],
    ),
    "ZT-DEV-DA06-RECONCILE": _d(
        "Low", "Medium", "Microsoft Intune",
        "Entra-only devices are registered but not managed. Intune-only records missing Entra IDs cannot be used in device-based CA.",
        "Compare Entra device IDs with Intune azureADDeviceId values. Investigate Entra-only and Intune-only sets.",
        ["Enroll Entra-only devices into Intune where required", "Fix Intune records missing Entra device IDs", "Disable stale Entra device objects"],
    ),
    "ZT-NET-NA01-INVENTORY": _d(
        "Low", "Low", "Azure subscription",
        "Without VNet, subnet, NIC, and NSG inventory, exposure and inspection gaps stay hidden.",
        "List virtual networks, subnets, NICs, NSGs, and firewalls in the subscription.",
        ["Keep network inventory complete", "Tag networks by environment and exposure"],
    ),
    "ZT-NET-NA02-NSG": _d(
        "Low", "Medium", "Azure subscription",
        "NSGs that allow internet to management ports expose SSH and RDP for password spray and exploit.",
        "Inspect NSG inbound allow rules. Flag internet sources to ports 22, 3389, and other management ports.",
        ["Remove internet allow rules to management ports", "Associate NSGs to every subnet", "Use Just-in-Time or Bastion for admin access"],
    ),
    "ZT-NET-NA03-PUBLIC-EXPOSURE": _d(
        "Low", "Medium", "Azure subscription",
        "Attached public IPs and internet-allow rules expand the attack surface beyond intended services.",
        "Count public IPs, attached IPs, and inbound internet-allow NSG rules.",
        ["Remove unused public IPs", "Prefer private endpoints", "Limit internet-allow rules to required services"],
    ),
    "ZT-NET-NA04-PRIVATE-CONNECTIVITY": _d(
        "Low", "High", "Azure subscription",
        "PaaS services with public network access can be reached without traversing inspection points.",
        "Check storage, Key Vault, and SQL public network access versus private endpoint count.",
        ["Disable public network access on PaaS where possible", "Create private endpoints for data services"],
    ),
    "ZT-NET-NA05-FIREWALL": _d(
        "Low", "High", "Azure subscription",
        "Without Azure Firewall or equivalent inspection, east-west and egress traffic bypasses threat intelligence and TLS inspection.",
        "List Azure Firewalls, firewall policies, Premium SKU, and threat intelligence mode.",
        ["Deploy Azure Firewall with policy", "Enable threat intelligence in alert or deny", "Route egress through the firewall"],
    ),
    "ZT-NET-NA06-WAF": _d(
        "Low", "Medium", "Azure subscription",
        "Internet-facing apps without WAF in prevention mode are exposed to OWASP-class attacks.",
        "Count Application Gateway and Front Door WAF policies and whether mode is Prevention.",
        ["Place internet apps behind Application Gateway or Front Door", "Set WAF policy mode to Prevention"],
    ),
    "ZT-NET-NA07-DDOS": _d(
        "Low", "Medium", "Azure subscription",
        "Public VNets without DDoS protection are susceptible to volumetric floods that hide intrusion.",
        "Count DDoS plans and VNets with DDoS enabled.",
        ["Enable DDoS Network Protection on internet-facing VNets"],
    ),
    "ZT-NET-NA08-REMOTE-CONNECTIVITY": _d(
        "Medium", "High", "Azure subscription",
        "Admin access over public RDP/SSH instead of Bastion, VPN, or ExpressRoute exposes management planes.",
        "Count Bastion hosts, VPN gateways, and ExpressRoute circuits.",
        ["Use Azure Bastion or VPN/ExpressRoute for administration", "Disable direct public management endpoints"],
    ),
    "ZT-NET-NA09-ENCRYPTION": _d(
        "Low", "High", "Azure subscription",
        "Uninspected TLS and cleartext admin paths let attackers hide in allowed 443 traffic.",
        "Confirm Premium firewall, WAF, or encrypted administrative paths exist for inspection.",
        ["Use Premium firewall TLS inspection where policy allows", "Encrypt administrative channels"],
    ),
    "ZT-NET-NA10-MONITORING": _d(
        "Low", "Low", "Azure subscription",
        "Without Network Watcher, flow logs and connection troubleshooting are unavailable during incidents.",
        "Count Network Watcher instances in the subscription.",
        ["Deploy Network Watcher in each region", "Enable NSG flow logs or VNet flow logs"],
    ),
    "ZT-NET-NA11-SEGMENTATION": _d(
        "Low", "High", "Azure subscription",
        "Flat subnets without NSG coverage let a single compromised VM reach data services.",
        "Count subnets and subnets without NSG association.",
        ["Associate an NSG to every subnet", "Segment workloads by trust zone"],
    ),
    "ZT-NET-NA12-ROUTING": _d(
        "Low", "High", "Azure subscription",
        "Missing route tables let traffic bypass firewalls and inspection.",
        "Count route tables and subnet associations that steer traffic to inspection points.",
        ["Use UDRs to force tunnel through Azure Firewall", "Review routes that send traffic directly to the internet"],
    ),
    "ZT-DATA-DP01-CLASSIFICATION": _d(
        "Low", "High", "Microsoft 365 E5 / Purview",
        "Without classification, DLP and encryption cannot target the right content. Sensitive data is treated as ordinary files.",
        "Count sensitivity labels and how many are active with protection settings.",
        ["Create sensitive information types", "Publish a classification taxonomy in Purview"],
    ),
    "ZT-DATA-DP02-LABELS": _d(
        "Low", "High", "Microsoft 365 E5 / Purview",
        "Unpublished labels never encrypt or mark content, so exfiltration looks like normal sharing.",
        "Count labels with encryption, content marking, and auto-label settings.",
        ["Publish sensitivity labels to users and workloads", "Enable encryption and content marking on confidential labels"],
    ),
    "ZT-DATA-DP03-DLP": _d(
        "Low", "High", "Microsoft 365 E5 / Purview",
        "Without DLP enforcement, credit cards, secrets, and regulated data leave via email, Teams, and sharing links.",
        "Read DLP protection scopes, execution mode, and locations.",
        ["Enable DLP for Exchange, SharePoint, OneDrive, and Teams", "Move policies from simulation to enforce"],
    ),
    "ZT-DATA-DP04-ENCRYPTION": _d(
        "Low", "High", "Microsoft 365 E5 / Purview",
        "Storage without HTTPS and labels without encryption expose data in transit and at rest after sharing.",
        "Check storage HTTPS, Key Vault RBAC, and labels with encryption.",
        ["Require HTTPS on storage accounts", "Enable RBAC on Key Vault", "Turn on encryption in sensitivity labels"],
    ),
    "ZT-DATA-DP05-SHARING": _d(
        "Medium", "Medium", "Microsoft 365 E5 / Purview",
        "Anonymous sharing links let anyone on the internet read files without authentication or DLP context.",
        "Read SharePoint tenant sharingCapability, anonymous sharing, and resharing by external users.",
        ["Disable anonymous sharing", "Restrict SharePoint and OneDrive external collaboration", "Block resharing by guests"],
    ),
    "ZT-DATA-DP06-RETENTION": _d(
        "Low", "Medium", "Microsoft 365 E5 / Purview",
        "Without retention, evidence and business records disappear before investigation or legal hold.",
        "Count retention labels and whether they are published.",
        ["Publish retention labels to workloads that store business and sensitive information"],
    ),
    "ZT-DATA-DP07-DATA-RISK": _d(
        "Low", "Medium", "Microsoft 365 E5 / Purview",
        "DLP without alerting hides ongoing exfiltration. Data-risk findings need policy actions or execution mode.",
        "Review DLP scopes that have policy actions or an execution mode other than none.",
        ["Review DLP alerts in Purview", "Investigate insider-risk signals when licensed"],
    ),
    "ZT-DATA-DP08-AUDIT": _d(
        "Low", "Low", "Free",
        "Missing audit telemetry prevents reconstructing who accessed or shared sensitive data.",
        "Confirm directory audit events and sign-ins are available for investigation.",
        ["Keep Purview Audit and Entra logs enabled", "Increase audit retention for regulated data"],
    ),
    "ZT-INFRA-IA01-INVENTORY": _d(
        "Low", "Low", "Azure subscription",
        "Incomplete compute, storage, and vault inventory leaves unmanaged resources outside policy and Defender.",
        "Count resource groups, VMs, storage, Key Vaults, AKS, and App Services.",
        ["Tag resource groups", "Remove orphaned resources from inventory"],
    ),
    "ZT-INFRA-IA02-GOVERNANCE": _d(
        "Low", "Medium", "Azure subscription",
        "Missing Azure Policy assignments allow resource configuration to drift from security baselines.",
        "Count policy assignments and exemptions at subscription scope.",
        ["Assign security initiatives at subscription scope", "Limit and review policy exemptions"],
    ),
    "ZT-INFRA-IA03-ADMIN-ACCESS": _d(
        "Medium", "High", "Azure subscription",
        "Standing Owner and Contributor at subscription scope turn one leaked credential into full estate control.",
        "Count role assignments, Owner/Contributor/User Access Admin, and subscription-scope admins.",
        ["Replace standing Owner/Contributor with scoped roles", "Use PIM for Azure RBAC where licensed"],
    ),
    "ZT-INFRA-IA04-WORKLOAD-IDENTITY": _d(
        "Low", "Medium", "Azure subscription",
        "Workloads without managed identity fall back to secrets in config and source control.",
        "Count VMs, App Services, and AKS clusters with managed identity versus compute totals.",
        ["Enable system- or user-assigned managed identity on compute", "Remove unused secrets after identity is in place"],
    ),
    "ZT-INFRA-IA05-DEFENDER": _d(
        "Low", "Medium", "Defender for Cloud",
        "Without Defender plans, insecure scores and unhealthy assessments are invisible until compromise.",
        "Read Standard plan count, secure score percentage, and unhealthy assessment count.",
        ["Enable Defender plans for Servers, Storage, Key Vault, and App Service", "Raise secure score above 60%"],
    ),
    "ZT-INFRA-IA06-VM-SECURITY": _d(
        "Low", "High", "Azure subscription",
        "VMs without Trusted Launch or disk encryption expose OS disks and bootkits.",
        "Count VMs with Trusted Launch/Secure Boot and encrypted OS disks.",
        ["Enable Trusted Launch on all VMs", "Encrypt OS disks with platform or customer-managed keys"],
    ),
    "ZT-INFRA-IA07-VULNERABILITY": _d(
        "Low", "High", "Defender for Cloud",
        "Unhealthy Defender assessments are known exploitable misconfigurations left unpatched.",
        "List unhealthy Defender for Cloud assessments by resource and severity.",
        ["Remediate unhealthy assessments starting at High severity", "Track remaining unhealthy resources"],
    ),
    "ZT-INFRA-IA08-SECRETS": _d(
        "Low", "Medium", "Azure subscription",
        "Key Vaults without RBAC, soft-delete, and purge protection let deleted secrets be recovered by an attacker or lost forever.",
        "Count Key Vaults with RBAC, soft-delete, and purge protection.",
        ["Enable RBAC authorization", "Turn on soft-delete and purge protection"],
    ),
    "ZT-INFRA-IA09-STORAGE": _d(
        "Low", "Medium", "Azure subscription",
        "Public blob access and HTTP on storage accounts leak data without authentication.",
        "Count storage accounts that require HTTPS and restrict public blob access.",
        ["Require HTTPS and TLS 1.2+", "Disable public blob access", "Restrict public network access"],
    ),
    "ZT-INFRA-IA10-CONTAINERS": _d(
        "Low", "High", "Azure subscription",
        "Public AKS API servers and container registries are scanned continuously for weak pull and exec paths.",
        "Count private AKS clusters and container registries with public access disabled.",
        ["Enable private AKS API server", "Disable public network access on ACR"],
    ),
    "ZT-INFRA-IA11-MONITORING": _d(
        "Low", "Low", "Azure subscription",
        "Activity logs that never reach Log Analytics cannot support incident investigation.",
        "Count subscription diagnostic settings and Log Analytics workspaces.",
        ["Send activity logs to Log Analytics", "Alert on privileged Azure activity"],
    ),
    "ZT-INFRA-IA12-BACKUP": _d(
        "Low", "High", "Azure subscription",
        "Workloads without Recovery Services or backup vaults cannot recover from ransomware.",
        "Count Recovery Services vaults and backup vaults.",
        ["Protect VMs and data services with Azure Backup", "Test restore regularly"],
    ),
    "ZT-INFRA-IA13-DRIFT": _d(
        "Low", "Medium", "Defender for Cloud",
        "Policy exemptions and unhealthy assessments together show configuration drift from the intended baseline.",
        "Compare policy exemptions with Defender unhealthy assessments and secure score.",
        ["Reduce exemptions", "Remediate drift called out by Defender assessments"],
    ),
}


def _license_for(check_id, area, category):
    token = " ".join([check_id or "", category or "", area or ""]).upper()
    if any(part in token for part in ("ID08", "PROTECTION", "RISKY")):
        return "Entra ID P2"
    if any(part in token for part in ("ID06", "ID07", "PIM", "PRIVILEGED")):
        return "Entra ID P2"
    if any(part in token for part in ("ID11", "REVIEW")):
        return "Entra ID Governance"
    if area == "Devices" or "INTUNE" in token or "DA0" in token:
        return "Microsoft Intune"
    if area == "Data" or any(part in token for part in ("DLP", "LABEL", "PURVIEW", "DP0")):
        return "Microsoft 365 E5 / Purview"
    if area == "Infrastructure" or "DEFENDER" in token or "IA0" in token:
        return "Defender for Cloud"
    if area == "Network" or "NA0" in token:
        return "Azure subscription"
    return "Free"


def catalog_for(check_id, area=None, category=None, risk=None):
    entry = TEST_DETAILS.get(check_id)
    if not entry and check_id:
        for key, value in TEST_DETAILS.items():
            if key in check_id or check_id in key:
                entry = value
                break
    entry = dict(entry or {})
    risk = risk or "Medium"
    area = area or ""
    if area in ("Network", "Infrastructure"):
        default_impact = "Low"
    elif risk == "High":
        default_impact = "Medium"
    else:
        default_impact = "Low"
    entry.setdefault("userImpact", default_impact)
    if risk == "High":
        default_effort = "High"
    elif risk == "Low":
        default_effort = "Low"
    else:
        default_effort = "Medium"
    entry.setdefault("implementationEffort", default_effort)
    entry.setdefault("license", _license_for(check_id, area, category))
    entry.setdefault("whatWasChecked", "")
    entry.setdefault("howToCheck", "")
    entry.setdefault("passRequirement", _pass_requirement(entry.get("howToCheck"), entry.get("whatWasChecked")))
    entry.setdefault("remediationActions", [])
    return entry


def _pass_requirement(how, checked):
    sentences = [part.strip() for part in str(how or "").replace("\n", " ").split(".") if part.strip()]
    keep = []
    for sentence in sentences:
        lower = sentence.lower()
        if any(token in lower for token in ("should", "must", "at least", "required")):
            keep.append(sentence)
    if keep:
        return ". ".join(keep) + "."
    if checked:
        return "This control passes when the tenant does not exhibit the exposure described for this check."
    return "The tenant configuration must meet this control."


def _fmt_cell(value):
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    if value is None or value == "":
        return ""
    if isinstance(value, (list, tuple)):
        value = ", ".join(str(item) for item in value if item not in (None, ""))
    text = str(value)
    if len(text) >= 10 and text[0:4].isdigit() and text[4] == "-":
        return text[:10]
    if len(text) > 160:
        return text[:159] + "…"
    return text


def _list_table(title, columns, items, limit=EVIDENCE_LIMIT):
    if not items:
        return None
    rows = []
    for item in items[:limit]:
        if isinstance(item, str):
            rows.append({columns[0]["key"]: _fmt_cell(item)})
            continue
        if not isinstance(item, dict):
            continue
        row = {}
        for column in columns:
            current = item
            for part in column["key"].split("."):
                current = current.get(part) if isinstance(current, dict) else None
            row[column["key"]] = _fmt_cell(current)
        rows.append(row)
    if not rows:
        return None
    return {
        "title": title,
        "columns": columns,
        "rows": rows,
        "total": len(items),
        "truncated": len(items) > limit,
    }


def _ca(evidence):
    return evidence.get("conditional_access") or {}


def _table_from_names(title, names, label="Name"):
    return _list_table(title, [{"key": "name", "label": label}], names or [])


def _ca_policies(evidence, predicate=None, title="Conditional Access policies"):
    policies = list(_ca(evidence).get("policies") or [])
    if predicate:
        policies = [item for item in policies if predicate(item)]
    return _list_table(
        title,
        [
            {"key": "displayName", "label": "Policy"},
            {"key": "state", "label": "State"},
            {"key": "hasMfa", "label": "MFA"},
            {"key": "hasDeviceGrant", "label": "Device grant"},
            {"key": "hasBlock", "label": "Block"},
        ],
        policies,
    )


def _privileged_members(evidence):
    rows = []
    for role in (evidence.get("privileged_roles") or {}).get("roles") or []:
        if not role.get("privileged"):
            continue
        members = role.get("members") or []
        if not members:
            rows.append({
                "role": role.get("displayName"),
                "member": "",
                "upn": "",
                "assignment": "Active",
                "count": role.get("member_count"),
            })
            continue
        for member in members:
            rows.append({
                "role": role.get("displayName"),
                "member": member.get("displayName"),
                "upn": member.get("userPrincipalName"),
                "assignment": member.get("assignmentType") or member.get("assignment") or "Active",
                "count": role.get("member_count"),
            })
    return _list_table(
        "Privileged directory role members",
        [
            {"key": "role", "label": "Role"},
            {"key": "member", "label": "Member"},
            {"key": "upn", "label": "User principal"},
            {"key": "assignment", "label": "Assignment"},
        ],
        rows,
    )


def _pim_row(item):
    if not isinstance(item, dict):
        return None
    role = item.get("role") or item.get("roleName") or item.get("roleDefinitionDisplayName") or item.get("roleDefinition")
    if isinstance(role, dict):
        role = role.get("displayName") or role.get("id")
    member = item.get("member") or item.get("principal") or item.get("user") or item.get("displayName")
    upn = item.get("upn") or item.get("userPrincipalName") or item.get("principalName") or item.get("principalId")
    if isinstance(member, dict):
        upn = upn or member.get("userPrincipalName") or member.get("id")
        member = member.get("displayName") or member.get("userPrincipalName")
    assignment = item.get("assignmentType") or item.get("type") or item.get("memberType") or item.get("assignmentState")
    if not assignment:
        assignment = "Eligible" if item.get("eligible") else "Active"
    return {
        "role": role,
        "member": member,
        "upn": upn,
        "assignmentType": assignment,
    }


def _pim_assignments(evidence):
    pim = evidence.get("privileged_eligibility") or {}
    raw = (
        pim.get("assignments")
        or pim.get("eligible")
        or pim.get("active")
        or pim.get("eligibleAssignments")
        or pim.get("activeAssignments")
        or []
    )
    if isinstance(raw, dict):
        raw = raw.get("value") or raw.get("items") or []
    rows = [row for row in (_pim_row(item) for item in raw) if row]
    return _list_table(
        "PIM assignments",
        [
            {"key": "role", "label": "Role"},
            {"key": "member", "label": "Member"},
            {"key": "upn", "label": "User principal"},
            {"key": "assignmentType", "label": "Assignment"},
        ],
        rows,
    )


def _managed_devices(evidence, predicate=None, title="Managed devices"):
    devices = list((evidence.get("managed_devices") or {}).get("devices") or [])
    if predicate:
        devices = [item for item in devices if predicate(item)]
    return _list_table(
        title,
        [
            {"key": "deviceName", "label": "Device"},
            {"key": "operatingSystem", "label": "OS"},
            {"key": "complianceState", "label": "Compliance"},
            {"key": "isEncrypted", "label": "Encrypted"},
            {"key": "managedDeviceOwnerType", "label": "Owner"},
        ],
        devices,
    )


def evidence_tables_for(check_id, evidence):
    evidence = evidence or {}
    ca = _ca(evidence)
    apps = evidence.get("application_credentials") or {}
    methods = evidence.get("authentication_methods") or {}
    registration = evidence.get("auth_registration") or {}
    risky = evidence.get("risky_users") or {}
    events = evidence.get("identity_risk_events") or {}
    reviews = evidence.get("access_reviews") or {}
    sign_ins = evidence.get("sign_ins") or {}
    audits = evidence.get("directory_audits") or {}
    enrollment = evidence.get("device_enrollment") or {}
    compliance = evidence.get("device_compliance") or {}
    entra = evidence.get("entra_devices") or {}
    network = evidence.get("network_security") or {}
    labels = evidence.get("sensitivity_labels") or {}
    dlp = evidence.get("dlp_policies") or {}
    retention = evidence.get("retention_labels") or {}
    assessments = evidence.get("defender_assessments") or {}
    builders = {
        "ZT-ID-ID02-MFA": [
            lambda: _table_from_names("MFA Conditional Access policies", ca.get("mfa_policies"), "Policy"),
            lambda: _list_table(
                "Enabled authentication methods",
                [{"key": "id", "label": "Method"}, {"key": "state", "label": "State"}],
                methods.get("enabled_methods") or methods.get("methods"),
            ),
            lambda: _list_table(
                "Users not registered for MFA",
                [
                    {"key": "id", "label": "User"},
                    {"key": "userType", "label": "Type"},
                    {"key": "isMfaRegistered", "label": "MFA registered"},
                ],
                [item for item in (registration.get("methods") or []) if not item.get("isMfaRegistered")],
            ),
        ],
        "ZT-ID-ID03-CONDITIONAL-ACCESS": [
            lambda: _ca_policies(evidence, title="Conditional Access policies"),
        ],
        "ZT-ID-ID04-LEGACY-AUTH": [
            lambda: _table_from_names("Legacy authentication block policies", ca.get("legacy_block_policies"), "Policy"),
            lambda: _list_table(
                "Recent legacy client sign-ins",
                [
                    {"key": "userPrincipalName", "label": "User"},
                    {"key": "appDisplayName", "label": "App"},
                    {"key": "clientAppUsed", "label": "Client"},
                    {"key": "createdDateTime", "label": "Time"},
                ],
                [
                    item for item in (sign_ins.get("events") or [])
                    if "legacy" in str(item.get("clientAppUsed") or "").lower()
                    or "exchange" in str(item.get("clientAppUsed") or "").lower()
                    or "imap" in str(item.get("clientAppUsed") or "").lower()
                ],
            ),
        ],
        "ZT-ID-ID05-STRONG-AUTH": [
            lambda: _list_table(
                "Authentication methods",
                [{"key": "id", "label": "Method"}, {"key": "state", "label": "State"}],
                methods.get("methods") or methods.get("enabled_methods"),
            ),
            lambda: _table_from_names("Authentication strength policies", ca.get("auth_strength_policies"), "Policy"),
        ],
        "ZT-ID-ID06-PRIVILEGED": [
            lambda: _privileged_members(evidence),
            lambda: _pim_assignments(evidence),
        ],
        "ZT-ID-ID07-LEAST-PRIVILEGE": [
            lambda: _privileged_members(evidence),
            lambda: _pim_assignments(evidence),
        ],
        "ZT-ID-ID08-PROTECTION": [
            lambda: _list_table(
                "Risky users",
                [
                    {"key": "userDisplayName", "label": "User"},
                    {"key": "userPrincipalName", "label": "User principal"},
                    {"key": "riskLevel", "label": "Risk"},
                    {"key": "riskState", "label": "State"},
                ],
                risky.get("users"),
            ),
            lambda: _table_from_names("User-risk Conditional Access policies", ca.get("user_risk_policies"), "Policy"),
            lambda: _list_table(
                "Risk detections",
                [
                    {"key": "riskEventType", "label": "Detection"},
                    {"key": "riskLevel", "label": "Risk"},
                    {"key": "riskState", "label": "State"},
                    {"key": "detectedDateTime", "label": "Detected"},
                ],
                events.get("events"),
            ),
        ],
        "ZT-ID-ID10-WORKLOAD": [
            lambda: _list_table(
                "Applications with expired or expiring credentials",
                [
                    {"key": "displayName", "label": "Application"},
                    {"key": "appId", "label": "App ID"},
                    {"key": "state", "label": "State"},
                    {"key": "endDateTime", "label": "Credential end date"},
                ],
                apps.get("credentials"),
            ),
        ],
        "ZT-ID-ID11-ACCESS-REVIEWS": [
            lambda: _list_table(
                "Access reviews",
                [
                    {"key": "displayName", "label": "Review"},
                    {"key": "status", "label": "Status"},
                    {"key": "scope", "label": "Scope"},
                ],
                reviews.get("reviews"),
            ),
        ],
        "ZT-ID-ID12-MONITORING": [
            lambda: _list_table(
                "Recent sign-ins",
                [
                    {"key": "userPrincipalName", "label": "User"},
                    {"key": "appDisplayName", "label": "App"},
                    {"key": "conditionalAccessStatus", "label": "Conditional Access"},
                    {"key": "createdDateTime", "label": "Time"},
                ],
                sign_ins.get("events"),
            ),
            lambda: _list_table(
                "Directory audit events",
                [
                    {"key": "activityDisplayName", "label": "Activity"},
                    {"key": "category", "label": "Category"},
                    {"key": "result", "label": "Result"},
                    {"key": "activityDateTime", "label": "Time"},
                ],
                audits.get("events"),
            ),
        ],
        "ZT-DEV-DA01-ENROLLMENT": [
            lambda: _list_table(
                "Enrollment configurations",
                [
                    {"key": "displayName", "label": "Configuration"},
                    {"key": "odata_type", "label": "Type"},
                    {"key": "is_restriction", "label": "Restriction"},
                    {"key": "priority", "label": "Priority"},
                ],
                enrollment.get("configurations"),
            ),
        ],
        "ZT-DEV-DA02-INVENTORY": [lambda: _managed_devices(evidence)],
        "ZT-DEV-DA02-ENCRYPTION": [
            lambda: _managed_devices(
                evidence,
                lambda item: not item.get("isEncrypted"),
                "Managed devices that do not report encryption",
            ),
        ],
        "ZT-DEV-DA03-COMPLIANCE": [
            lambda: _list_table(
                "Device compliance policies",
                [
                    {"key": "displayName", "label": "Policy"},
                    {"key": "assigned", "label": "Assigned"},
                    {"key": "requires_encryption", "label": "Encryption"},
                    {"key": "requires_firewall", "label": "Firewall"},
                    {"key": "requires_min_os", "label": "Min OS"},
                ],
                compliance.get("policies"),
            ),
        ],
        "ZT-DEV-DA04-CONDITIONAL-ACCESS": [
            lambda: _table_from_names("Device grant policies", ca.get("device_grant_policies"), "Policy"),
            lambda: _table_from_names("Location-dependent policies", ca.get("location_dependent_policies"), "Policy"),
            lambda: _ca_policies(evidence, lambda item: item.get("hasDeviceGrant") or item.get("locationDependent")),
        ],
        "ZT-DEV-DA04-SESSION": [
            lambda: _table_from_names("Session control policies", ca.get("session_control_policies"), "Policy"),
        ],
        "ZT-DEV-DA05-SIGNINS": [
            lambda: _list_table(
                "Sign-ins with device posture",
                [
                    {"key": "userPrincipalName", "label": "User"},
                    {"key": "appDisplayName", "label": "App"},
                    {"key": "deviceDisplayName", "label": "Device"},
                    {"key": "deviceIsManaged", "label": "Managed"},
                    {"key": "deviceIsCompliant", "label": "Compliant"},
                ],
                sign_ins.get("events"),
            ),
        ],
        "ZT-DEV-DA06-RECONCILE": [
            lambda: _list_table(
                "Entra devices",
                [
                    {"key": "displayName", "label": "Device"},
                    {"key": "operatingSystem", "label": "OS"},
                    {"key": "trustType", "label": "Trust"},
                    {"key": "isManaged", "label": "Managed"},
                    {"key": "isCompliant", "label": "Compliant"},
                ],
                entra.get("devices"),
            ),
            lambda: _managed_devices(evidence, title="Intune devices"),
        ],
        "ZT-NET-NA01-INVENTORY": [
            lambda: _list_table(
                "Network security groups",
                [{"key": "name", "label": "NSG"}, {"key": "location", "label": "Location"}],
                network.get("nsgs"),
            ),
            lambda: _list_table(
                "Azure Firewalls",
                [
                    {"key": "name", "label": "Firewall"},
                    {"key": "location", "label": "Location"},
                    {"key": "sku", "label": "SKU"},
                ],
                network.get("firewalls"),
            ),
        ],
        "ZT-NET-NA02-NSG": [
            lambda: _list_table(
                "NSG rules exposing management ports",
                [
                    {"key": "nsg", "label": "NSG"},
                    {"key": "rule", "label": "Rule"},
                    {"key": "destinationPortRange", "label": "Ports"},
                    {"key": "sourceAddressPrefix", "label": "Source"},
                ],
                network.get("open_management_rules"),
            ),
        ],
        "ZT-NET-NA03-PUBLIC-EXPOSURE": [
            lambda: _list_table(
                "Internet-allow NSG rules",
                [
                    {"key": "nsg", "label": "NSG"},
                    {"key": "rule", "label": "Rule"},
                    {"key": "destinationPortRange", "label": "Ports"},
                    {"key": "sourceAddressPrefix", "label": "Source"},
                ],
                network.get("internet_allow_rules"),
            ),
        ],
        "ZT-NET-NA05-FIREWALL": [
            lambda: _list_table(
                "Azure Firewalls",
                [
                    {"key": "name", "label": "Firewall"},
                    {"key": "location", "label": "Location"},
                    {"key": "sku", "label": "SKU"},
                ],
                network.get("firewalls"),
            ),
        ],
        "ZT-DATA-DP01-CLASSIFICATION": [
            lambda: _list_table(
                "Sensitivity labels",
                [
                    {"key": "displayName", "label": "Label"},
                    {"key": "name", "label": "Name"},
                    {"key": "isActive", "label": "Active"},
                    {"key": "sensitivity", "label": "Sensitivity"},
                ],
                labels.get("labels"),
            ),
        ],
        "ZT-DATA-DP02-LABELS": [
            lambda: _list_table(
                "Sensitivity labels",
                [
                    {"key": "displayName", "label": "Label"},
                    {"key": "isActive", "label": "Active"},
                    {"key": "tooltip", "label": "Tooltip"},
                ],
                labels.get("labels"),
            ),
        ],
        "ZT-DATA-DP03-DLP": [
            lambda: _list_table(
                "DLP protection scopes",
                [
                    {"key": "executionMode", "label": "Mode"},
                    {"key": "activities", "label": "Activities"},
                    {"key": "locations", "label": "Locations"},
                ],
                dlp.get("policies"),
            ),
        ],
        "ZT-DATA-DP07-DATA-RISK": [
            lambda: _list_table(
                "DLP policy actions",
                [
                    {"key": "executionMode", "label": "Mode"},
                    {"key": "policyActions", "label": "Actions"},
                    {"key": "locations", "label": "Locations"},
                ],
                dlp.get("policies"),
            ),
        ],
        "ZT-DATA-DP06-RETENTION": [
            lambda: _list_table(
                "Retention labels",
                [
                    {"key": "displayName", "label": "Label"},
                    {"key": "retentionDuration", "label": "Duration"},
                    {"key": "isEnabled", "label": "Enabled"},
                ],
                retention.get("labels"),
            ),
        ],
        "ZT-INFRA-IA05-DEFENDER": [
            lambda: _table_from_names("Defender Standard plans", assessments.get("defender_plans"), "Plan"),
        ],
        "ZT-INFRA-IA07-VULNERABILITY": [
            lambda: _list_table(
                "Unhealthy Defender assessments",
                [
                    {"key": "displayName", "label": "Assessment"},
                    {"key": "severity", "label": "Severity"},
                    {"key": "resourceId", "label": "Resource"},
                ],
                assessments.get("unhealthy_assessments"),
            ),
        ],
    }
    builders["ZT-DATA-DP02-LABELS"] = builders["ZT-DATA-DP01-CLASSIFICATION"]
    tables = []
    for builder in builders.get(check_id) or []:
        table = builder()
        if table:
            tables.append(table)
    return tables


def enrich_test(test, evidence):
    meta = catalog_for(test.get("id"), test.get("area"), test.get("category"), test.get("risk"))
    actions = list(meta.get("remediationActions") or [])
    if not actions and test.get("recommendation"):
        actions = [test.get("recommendation")]
    test["userImpact"] = meta.get("userImpact")
    test["implementationEffort"] = meta.get("implementationEffort")
    test["license"] = meta.get("license")
    test["whatWasChecked"] = meta.get("whatWasChecked") or test.get("description")
    test["howToCheck"] = meta.get("howToCheck")
    test["passRequirement"] = meta.get("passRequirement")
    test["remediationActions"] = actions
    test["evidenceTables"] = evidence_tables_for(test.get("id"), evidence)
    return test
