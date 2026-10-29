import os
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from services.zero_trust_adapter import (
    adapt_assessment,
    csv_rows,
    deduplicate_tests,
    filter_tests,
    mask_tenant_id,
    priority_remediation,
    sanitize_text,
    sort_tests,
    summarize_tests,
    trusted_url,
    weighted_score,
)


def _test(area, name, risk, status, category="Conditional Access", test_id=None, platform=None):
    return {
        "id": test_id or "{0}:{1}".format(area, name),
        "area": area,
        "name": name,
        "category": category,
        "risk": risk,
        "status": status,
        "sfiPillars": [area],
        "platform": platform,
        "recommendation": "Fix {0}".format(name),
        "evidence": ["sample"],
    }


class ZeroTrustAdapterTests(unittest.TestCase):
    def test_sort_risk_and_status(self):
        tests = [
            _test("Identity", "Passed high", "High", "Passed"),
            _test("Identity", "Failed low", "Low", "Failed"),
            _test("Identity", "Failed high", "High", "Failed"),
            _test("Identity", "Investigate high", "High", "Investigate"),
            _test("Identity", "Skipped", "Medium", "Skipped"),
        ]
        ordered = [t["name"] for t in sort_tests(tests)]
        self.assertEqual(
            ordered,
            ["Failed high", "Investigate high", "Failed low", "Passed high", "Skipped"],
        )

    def test_identity_filter_combinations(self):
        tests = [
            _test("Identity", "CA MFA", "High", "Failed", "Conditional Access"),
            _test("Identity", "Guest access", "Medium", "Passed", "External identities"),
            _test("Identity", "PIM", "High", "Investigate", "Privileged accounts"),
        ]
        filtered = filter_tests(tests, query="mfa", risks=["High"], statuses=["Failed"])
        self.assertEqual([t["name"] for t in filtered], ["CA MFA"])
        filtered = filter_tests(tests, categories=["Privileged accounts"], pillars=["Identity"])
        self.assertEqual([t["name"] for t in filtered], ["PIM"])

    def test_device_platform_filtering(self):
        tests = [
            _test("Devices", "Windows encryption", "High", "Failed", "Encryption", platform="Windows"),
            _test("Devices", "macOS firewall", "Medium", "Passed", "Firewall", platform="macOS"),
            _test("Devices", "Tenant compliance", "High", "Failed", "Compliance", platform="Tenant-wide"),
        ]
        filtered = filter_tests(tests, platforms=["Windows"])
        self.assertEqual([t["name"] for t in filtered], ["Windows encryption"])
        scoped = filter_tests(tests, scopes=["Device"])
        self.assertEqual(
            sorted(t["name"] for t in scoped),
            ["Tenant compliance", "Windows encryption", "macOS firewall"],
        )

    def test_deduplicate_device_tests(self):
        tests = [
            _test("Devices", "Compliance policy", "High", "Failed", test_id="ZT-DEV-1"),
            _test("Devices", "Compliance policy copy", "High", "Failed", test_id="ZT-DEV-1"),
            _test("Devices", "Encryption", "Medium", "Passed", test_id="ZT-DEV-2"),
        ]
        unique = deduplicate_tests(tests)
        self.assertEqual([t["id"] for t in unique], ["ZT-DEV-1", "ZT-DEV-2"])

    def test_summary_calculation(self):
        tests = [
            _test("Identity", "a", "High", "Failed"),
            _test("Identity", "b", "Medium", "Failed"),
            _test("Identity", "c", "Low", "Failed"),
            _test("Identity", "d", "High", "Passed"),
            _test("Identity", "e", "High", "Investigate"),
            _test("Identity", "f", "Low", "Skipped"),
            _test("Identity", "g", "Medium", "Planned"),
        ]
        summary = summarize_tests(tests)
        self.assertEqual(summary["total"], 7)
        self.assertEqual(summary["passed"], 1)
        self.assertEqual(summary["failed"], 3)
        self.assertEqual(summary["investigate"], 1)
        self.assertEqual(summary["planned"], 1)
        self.assertEqual(summary["skipped"], 1)
        self.assertEqual(summary["highRiskFailed"], 1)
        self.assertEqual(summary["mediumRiskFailed"], 1)
        self.assertEqual(summary["lowRiskFailed"], 1)

    def test_weighted_score_skips_not_applicable(self):
        tests = [
            _test("Identity", "high pass", "High", "Passed"),
            _test("Identity", "high fail", "High", "Failed"),
            _test("Identity", "skip", "High", "Skipped"),
        ]
        score = weighted_score(tests, skipped_not_applicable=True)
        self.assertEqual(score, 50)
        included = weighted_score(tests, skipped_not_applicable=False)
        self.assertEqual(included, 33)

    def test_missing_values_and_partial_payload(self):
        adapted = adapt_assessment({
            "assessment_id": "abc",
            "status": "completed",
            "score": 40,
            "findings": [
                {
                    "id": "ZT-ID-CA-ENABLED",
                    "pillar": "Identity",
                    "title": "Conditional Access policies are enabled",
                    "status": "Error",
                    "severity": "High",
                    "detail": "Graph permission missing. bearer abc.def",
                    "remediation": "Grant Policy.Read.All",
                }
            ],
            "evidence": {
                "tenant_id": "0817c655-1111-2222-3333-3a333b5b9235",
                "conditional_access": {"available": False, "error": "Graph permission missing."},
                "managed_devices": {"available": False, "error": "Intune unread"},
            },
        })
        self.assertEqual(adapted["tenant"]["devices"], None)
        self.assertEqual(adapted["tenant"]["users"], None)
        self.assertTrue(adapted["partial"])
        self.assertEqual(adapted["identity"]["tests"][0]["status"], "Investigate")
        self.assertNotIn("bearer", adapted["identity"]["tests"][0]["error"]["message"].lower())
        self.assertIsNone(adapted["visualizations"]["deviceFlow"])
        self.assertEqual(
            mask_tenant_id(adapted["tenant"]["tenantId"]),
            "0817c655-****-****-****-3a333b5b9235",
        )

    def test_tenant_profile_and_visualizations(self):
        adapted = adapt_assessment({
            "assessment_id": "tenant-1",
            "status": "completed",
            "score": 70,
            "findings": [
                {
                    "id": "ZT-ID-CA-ENABLED",
                    "pillar": "Identity",
                    "title": "Conditional Access policies are enabled",
                    "status": "Pass",
                    "severity": "High",
                    "detail": "8 of 16 policies are enabled.",
                    "remediation": "Keep CA enabled.",
                }
            ],
            "evidence": {
                "tenant_profile": {
                    "available": True,
                    "tenant_name": "LTIM SecCOE",
                    "tenant_id": "28f91c7c-d50f-4c19-9a26-0504aca35c52",
                    "primary_domain": "ltimsec.com",
                    "users": 42,
                    "guests": 3,
                    "groups": 18,
                    "applications": 9,
                    "service_principals": 12,
                },
                "conditional_access": {
                    "available": True,
                    "count": 16,
                    "enabled_count": 8,
                    "mfa_policy_count": 4,
                    "legacy_block_count": 1,
                    "all_users_mfa_count": 1,
                },
                "authentication_methods": {
                    "available": True,
                    "method_count": 5,
                    "enabled_method_count": 2,
                    "enabled_methods": [{"id": "fido2"}],
                },
                "managed_devices": {"available": True, "count": 0, "compliant_count": 0, "encrypted_count": 0, "devices": []},
            },
        })
        self.assertEqual(adapted["tenant"]["tenantName"], "LTIM SecCOE")
        self.assertEqual(adapted["tenant"]["primaryDomain"], "ltimsec.com")
        self.assertEqual(adapted["tenant"]["users"], 42)
        self.assertEqual(adapted["tenant"]["guests"], 3)
        self.assertEqual(adapted["tenant"]["servicePrincipals"], 12)
        self.assertEqual(adapted["visualizations"]["identityOverview"]["inventory"]["servicePrincipals"], {"value": 12})
        self.assertEqual(adapted["visualizations"]["conditionalAccessCoverage"]["enabled"], 8)
        self.assertEqual(adapted["visualizations"]["privilegedAuth"]["enabledMethodCount"], 2)
        self.assertIsNone(adapted["visualizations"]["deviceFlow"])

    def test_network_data_infrastructure_pillars(self):
        adapted = adapt_assessment({
            "assessment_id": "pillars-1",
            "status": "completed",
            "findings": [
                {
                    "id": "ZT-NET-OPEN-MGMT",
                    "pillar": "Network",
                    "title": "Management ports are not open to the internet",
                    "status": "Fail",
                    "severity": "High",
                    "detail": "2 NSG rules allow SSH/RDP from the internet.",
                    "remediation": "Restrict NSG inbound rules.",
                },
                {
                    "id": "ZT-DATA-SENSITIVITY-LABELS",
                    "pillar": "Data",
                    "title": "Sensitivity labels are published in Purview",
                    "status": "Pass",
                    "severity": "High",
                    "detail": "4 sensitivity labels.",
                    "remediation": "Keep labels published.",
                },
                {
                    "id": "ZT-INFRA-SECURE-SCORE",
                    "pillar": "Infrastructure",
                    "title": "Defender for Cloud secure score is healthy",
                    "status": "Fail",
                    "severity": "Medium",
                    "detail": "Secure score 40%.",
                    "remediation": "Implement recommendations.",
                },
            ],
        })
        self.assertEqual(len(adapted["network"]["tests"]), 1)
        self.assertEqual(adapted["network"]["tests"][0]["category"], "Network segmentation")
        self.assertEqual(len(adapted["data"]["tests"]), 1)
        self.assertEqual(adapted["data"]["tests"][0]["status"], "Passed")
        self.assertEqual(len(adapted["infrastructure"]["tests"]), 1)
        self.assertEqual(adapted["infrastructure"]["summary"]["failed"], 1)
        self.assertEqual(adapted["other"]["tests"], [])
        areas = {row["area"] for row in csv_rows(adapted)}
        self.assertEqual(areas, {"Network", "Data", "Infrastructure"})

    def test_network_na_findings_preserve_assessment_layer(self):
        adapted = adapt_assessment({
            "assessment_id": "na-1",
            "status": "completed",
            "findings": [
                {
                    "id": "ZT-NET-NA02-NSG",
                    "pillar": "Network",
                    "title": "NA-02 NSGs are associated and do not expose management ports",
                    "status": "Pass",
                    "severity": "High",
                    "detail": "3 NSGs associated, 0 SSH/RDP from the internet.",
                    "remediation": "Keep management ports closed.",
                    "assessmentLayer": {
                        "configured": "Yes",
                        "assigned": "Yes",
                        "observed": "Yes",
                        "validation": "Required: NT-01 segmentation test",
                    },
                },
                {
                    "id": "ZT-NET-NA05-FIREWALL",
                    "pillar": "Network",
                    "title": "NA-05 Azure Firewall is deployed with policy and inspection",
                    "status": "Fail",
                    "severity": "High",
                    "detail": "0 Azure Firewalls.",
                    "remediation": "Deploy Azure Firewall.",
                    "assessmentLayer": {
                        "configured": "No",
                        "assigned": "No",
                        "observed": "No",
                        "validation": "Required: NT-03 firewall enforcement test",
                    },
                },
            ],
        })
        tests = {t["id"]: t for t in adapted["network"]["tests"]}
        self.assertEqual(tests["ZT-NET-NA02-NSG"]["category"], "NSG security")
        self.assertEqual(tests["ZT-NET-NA02-NSG"]["assessmentLayer"]["validation"], "Required: NT-01 segmentation test")
        self.assertEqual(tests["ZT-NET-NA05-FIREWALL"]["category"], "Firewall")
        self.assertEqual(tests["ZT-NET-NA05-FIREWALL"]["status"], "Failed")

    def test_infrastructure_ia_findings_preserve_assessment_layer(self):
        adapted = adapt_assessment({
            "assessment_id": "ia-1",
            "status": "completed",
            "findings": [
                {
                    "id": "ZT-INFRA-IA05-DEFENDER",
                    "pillar": "Infrastructure",
                    "title": "IA-05 Defender for Cloud plans and secure score are healthy",
                    "status": "Pass",
                    "severity": "High",
                    "detail": "3 Standard plans, secure score 72%.",
                    "remediation": "Keep Defender plans enabled.",
                    "assessmentLayer": {
                        "configured": "Yes",
                        "assigned": "Yes",
                        "observed": "Yes",
                        "validation": "Required: IT-05 threat detection validation",
                    },
                },
                {
                    "id": "ZT-INFRA-IA08-SECRETS",
                    "pillar": "Infrastructure",
                    "title": "IA-08 Key Vaults use RBAC, soft-delete, and purge protection",
                    "status": "Fail",
                    "severity": "High",
                    "detail": "2 Key Vaults, 0 purge protection.",
                    "remediation": "Enable purge protection.",
                    "assessmentLayer": {
                        "configured": "Yes",
                        "assigned": "No",
                        "observed": "No",
                        "validation": "Required: IT-04 Key Vault access validation",
                    },
                },
            ],
        })
        tests = {t["id"]: t for t in adapted["infrastructure"]["tests"]}
        self.assertEqual(tests["ZT-INFRA-IA05-DEFENDER"]["category"], "Defender for Cloud")
        self.assertEqual(tests["ZT-INFRA-IA05-DEFENDER"]["assessmentLayer"]["validation"], "Required: IT-05 threat detection validation")
        self.assertEqual(tests["ZT-INFRA-IA08-SECRETS"]["category"], "Secrets and keys")
        self.assertEqual(tests["ZT-INFRA-IA08-SECRETS"]["status"], "Failed")

    def test_identity_id_findings_preserve_assessment_layer(self):
        adapted = adapt_assessment({
            "assessment_id": "id-1",
            "status": "completed",
            "findings": [
                {
                    "id": "ZT-ID-ID02-MFA",
                    "pillar": "Identity",
                    "title": "ID-02 MFA policy coverage and registration are in place",
                    "status": "Pass",
                    "severity": "High",
                    "detail": "2 MFA CA policies.",
                    "remediation": "Keep MFA required.",
                    "assessmentLayer": {
                        "configured": "Yes",
                        "assigned": "Yes",
                        "observed": "Yes",
                        "validation": "Required: ID-T01 MFA enforcement test",
                    },
                },
                {
                    "id": "ZT-ID-ID10-WORKLOAD",
                    "pillar": "Identity",
                    "title": "ID-10 Workload identity credentials are current",
                    "status": "Fail",
                    "severity": "High",
                    "detail": "3 expired secrets.",
                    "remediation": "Rotate secrets.",
                    "assessmentLayer": {
                        "configured": "Yes",
                        "assigned": "Yes",
                        "observed": "No",
                        "validation": "Required: ID-T06 workload identity test",
                    },
                },
            ],
        })
        tests = {t["id"]: t for t in adapted["identity"]["tests"]}
        self.assertEqual(tests["ZT-ID-ID02-MFA"]["category"], "Authentication methods")
        self.assertEqual(tests["ZT-ID-ID02-MFA"]["assessmentLayer"]["validation"], "Required: ID-T01 MFA enforcement test")
        self.assertEqual(tests["ZT-ID-ID10-WORKLOAD"]["category"], "Application identity security")
        self.assertEqual(tests["ZT-ID-ID10-WORKLOAD"]["status"], "Failed")

    def test_data_dp_findings_preserve_assessment_layer(self):
        adapted = adapt_assessment({
            "assessment_id": "dp-1",
            "status": "completed",
            "findings": [
                {
                    "id": "ZT-DATA-DP03-DLP",
                    "pillar": "Data",
                    "title": "DP-03 DLP policies are enabled across workloads",
                    "status": "Pass",
                    "severity": "High",
                    "detail": "2 of 3 DLP scopes enforcing.",
                    "remediation": "Keep DLP enabled.",
                    "assessmentLayer": {
                        "configured": "Yes",
                        "assigned": "Yes",
                        "observed": "Yes",
                        "validation": "Required: DP-T02 DLP enforcement test",
                    },
                },
                {
                    "id": "ZT-DATA-DP05-SHARING",
                    "pillar": "Data",
                    "title": "DP-05 SharePoint and OneDrive external sharing is controlled",
                    "status": "Fail",
                    "severity": "High",
                    "detail": "Anonymous sharing enabled.",
                    "remediation": "Disable anonymous sharing.",
                    "assessmentLayer": {
                        "configured": "Yes",
                        "assigned": "No",
                        "observed": "No",
                        "validation": "Required: DP-T03 external sharing test",
                    },
                },
            ],
        })
        tests = {t["id"]: t for t in adapted["data"]["tests"]}
        self.assertEqual(tests["ZT-DATA-DP03-DLP"]["category"], "Data loss prevention")
        self.assertEqual(tests["ZT-DATA-DP03-DLP"]["assessmentLayer"]["validation"], "Required: DP-T02 DLP enforcement test")
        self.assertEqual(tests["ZT-DATA-DP05-SHARING"]["category"], "External sharing")
        self.assertEqual(tests["ZT-DATA-DP05-SHARING"]["status"], "Failed")

    def test_device_da_findings_preserve_assessment_layer(self):
        adapted = adapt_assessment({
            "assessment_id": "da-1",
            "status": "completed",
            "findings": [
                {
                    "id": "ZT-DEV-DA01-ENROLLMENT",
                    "pillar": "Devices",
                    "title": "DA-01 Enrollment and ownership controls are configured",
                    "status": "Pass",
                    "severity": "High",
                    "detail": "2 enrollment configurations, 1 restriction objects.",
                    "remediation": "Keep enrollment restrictions.",
                    "assessmentLayer": {
                        "configured": "Yes",
                        "assigned": "Yes",
                        "observed": "Yes",
                        "validation": "Required: rogue enrollment test",
                    },
                },
                {
                    "id": "ZT-DEV-DA04-CONDITIONAL-ACCESS",
                    "pillar": "Devices",
                    "title": "DA-04 Conditional Access requires device trust",
                    "status": "Fail",
                    "severity": "High",
                    "detail": "0 device grants.",
                    "remediation": "Require compliant devices.",
                    "assessmentLayer": {
                        "configured": "Yes",
                        "assigned": "No",
                        "observed": "No",
                        "validation": "Required: off-network access test",
                    },
                },
            ],
        })
        tests = {t["id"]: t for t in adapted["devices"]["tests"]}
        self.assertEqual(tests["ZT-DEV-DA01-ENROLLMENT"]["category"], "Enrollment")
        self.assertEqual(tests["ZT-DEV-DA01-ENROLLMENT"]["assessmentLayer"]["configured"], "Yes")
        self.assertEqual(tests["ZT-DEV-DA04-CONDITIONAL-ACCESS"]["category"], "Conditional Access")
        self.assertEqual(tests["ZT-DEV-DA04-CONDITIONAL-ACCESS"]["status"], "Failed")

    def test_sankey_never_invented_from_tests(self):
        adapted = adapt_assessment({
            "assessment_id": "xyz",
            "status": "completed",
            "findings": [
                {
                    "id": "ZT-DEV-COMPLIANCE-POLICY",
                    "pillar": "Devices",
                    "title": "Intune device compliance policies exist",
                    "status": "Fail",
                    "severity": "High",
                    "detail": "0 policies",
                    "remediation": "Create policies",
                }
            ],
            "evidence": {"managed_devices": {"available": False}},
        })
        self.assertIsNone(adapted["visualizations"]["deviceFlow"])
        self.assertIsNone(adapted["visualizations"]["privilegedAuth"])
        self.assertIsNone(adapted["visualizations"]["identityOverview"])
        self.assertIsNone(adapted["visualizations"]["pillarMetrics"]["identity"])
        self.assertIsNone(adapted["visualizations"]["pillarMetrics"]["devices"])
        self.assertIsNone(adapted["visualizations"]["pillarMetrics"]["network"])
        self.assertIsNone(adapted["visualizations"]["pillarMetrics"]["data"])
        self.assertIsNone(adapted["visualizations"]["pillarMetrics"]["infrastructure"])

    def test_pillar_metrics_only_from_available_evidence(self):
        adapted = adapt_assessment({
            "assessment_id": "metrics-1",
            "status": "completed",
            "findings": [],
            "evidence": {
                "auth_registration": {
                    "available": True,
                    "count": 40,
                    "mfa_registered_count": 32,
                    "passwordless_count": 4,
                },
                "conditional_access": {
                    "available": True,
                    "count": 16,
                    "enabled_count": 8,
                    "mfa_policy_count": 3,
                },
                "privileged_roles": {
                    "available": True,
                    "privileged_member_count": 5,
                    "privileged_role_count": 8,
                },
                "privileged_eligibility": {
                    "available": True,
                    "eligible_count": 88,
                    "active_assignment_count": 87,
                },
                "application_credentials": {
                    "available": True,
                    "application_count": 200,
                    "expired_credential_count": 46,
                    "expiring_30d_count": 2,
                    "secret_count": 74,
                    "certificate_count": 12,
                },
                "managed_devices": {
                    "available": True,
                    "count": 12,
                    "compliant_count": 9,
                    "encrypted_count": 8,
                    "devices": [],
                },
                "network_security": {
                    "available": True,
                    "nsg_count": 6,
                    "nsg_associated_count": 4,
                    "public_ip_count": 3,
                    "public_ip_attached_count": 2,
                    "open_management_rule_count": 1,
                    "firewall_count": 0,
                },
                "dlp_policies": {
                    "available": True,
                    "count": 2,
                    "enabled_count": 1,
                },
                "sensitivity_labels": {"available": False, "error": "Graph 403"},
                "infrastructure_security": {
                    "available": True,
                    "resource_group_count": 65,
                    "vm_count": 4,
                    "trusted_launch_count": 1,
                    "storage_account_count": 7,
                    "storage_https_count": 7,
                    "storage_public_count": 2,
                    "privileged_assignment_count": 9,
                },
                "defender_secure_score": {
                    "available": True,
                    "percentage": 61.5,
                },
                "access_reviews": {"available": False, "error": "Graph 400"},
            },
        })
        metrics = adapted["visualizations"]["pillarMetrics"]
        self.assertEqual(metrics["identity"]["mfaRegistered"], {"value": 32, "total": 40})
        self.assertEqual(metrics["identity"]["caEnabled"], {"value": 8, "total": 16})
        self.assertEqual(metrics["identity"]["privilegedMembers"], {"value": 5})
        self.assertEqual(metrics["identity"]["privilegedRoles"], {"value": 8})
        self.assertEqual(metrics["identity"]["pimEligible"], {"value": 88})
        self.assertEqual(metrics["identity"]["pimActive"], {"value": 87})
        self.assertNotIn("accessReviews", metrics["identity"])
        overview = adapted["visualizations"]["identityOverview"]
        self.assertEqual(overview["privileged"]["members"], {"value": 5})
        self.assertEqual(overview["privileged"]["pimActive"], {"value": 87})
        self.assertEqual(overview["credentials"]["expiredCredentials"], {"value": 46})
        self.assertEqual(overview["credentials"]["expiring30d"], {"value": 2})
        self.assertEqual(overview["credentials"]["secrets"], {"value": 74})
        self.assertEqual(metrics["devices"]["compliant"], {"value": 9, "total": 12})
        self.assertEqual(metrics["network"]["nsgsAssociated"], {"value": 4, "total": 6})
        self.assertEqual(metrics["network"]["openManagementRules"], {"value": 1})
        self.assertEqual(metrics["data"]["dlpScopes"], {"value": 1, "total": 2})
        self.assertNotIn("sensitivityLabels", metrics["data"])
        self.assertEqual(metrics["infrastructure"]["resourceGroups"], {"value": 65})
        self.assertEqual(metrics["infrastructure"]["defenderScore"], {"value": 61.5})
        self.assertEqual(metrics["infrastructure"]["storagePublic"], {"value": 2})

    def test_csv_export_fields(self):
        adapted = adapt_assessment({
            "assessment_id": "csv-1",
            "completed_at": "2026-10-22T05:00:00+00:00",
            "status": "completed",
            "findings": [
                {
                    "id": "ZT-ID-CA-MFA",
                    "pillar": "Identity",
                    "title": "MFA is enforced",
                    "status": "Pass",
                    "severity": "High",
                    "detail": "1 policy",
                    "remediation": "Keep MFA",
                }
            ],
        })
        rows = csv_rows(adapted)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["assessmentId"], "csv-1")
        self.assertEqual(rows[0]["area"], "Identity")
        self.assertEqual(rows[0]["status"], "Passed")
        self.assertEqual(rows[0]["evidenceAvailable"], "yes")
        self.assertIn("recommendation", rows[0])

    def test_priority_order(self):
        tests = [
            _test("Identity", "low fail", "Low", "Failed"),
            _test("Identity", "high investigate", "High", "Investigate"),
            _test("Identity", "high fail", "High", "Failed"),
            _test("Identity", "medium fail", "Medium", "Failed"),
            _test("Identity", "passed", "High", "Passed"),
        ]
        names = [t["name"] for t in priority_remediation(tests)]
        self.assertEqual(names, ["high fail", "high investigate", "medium fail", "low fail"])

    def test_sanitize_and_trusted_url(self):
        self.assertIn("[redacted]", sanitize_text("token bearer abc.def.ghi"))
        self.assertTrue(trusted_url("https://learn.microsoft.com/en-us/security/zero-trust/assessment/"))
        self.assertIsNone(trusted_url("https://evil.example/docs"))
        self.assertIsNone(trusted_url("javascript:alert(1)"))


class ZeroTrustPollHelpersTests(unittest.TestCase):
    def test_poll_completion_and_cancel_contract(self):
        statuses = ["queued", "running", "completed"]
        seen = []
        cancelled = []

        def poll(status_list):
            for status in status_list:
                if cancelled:
                    return "cancelled"
                seen.append(status)
                if status in ("completed", "failed"):
                    return status
            return "running"

        self.assertEqual(poll(statuses), "completed")
        self.assertEqual(seen, ["queued", "running", "completed"])
        cancelled.append(True)
        self.assertEqual(poll(["running"]), "cancelled")

    def test_429_retry_delay(self):
        def retry_delay(retry_after):
            try:
                n = int(retry_after)
            except (TypeError, ValueError):
                return 2500
            if n > 0:
                return min(n, 30) * 1000
            return 2500

        self.assertEqual(retry_delay("5"), 5000)
        self.assertEqual(retry_delay("90"), 30000)
        self.assertEqual(retry_delay(None), 2500)


class ZeroTrustConfigTests(unittest.TestCase):
    def test_reads_key_from_process_env_aliases(self):
        from unittest.mock import patch
        from services import zero_trust_service as zts

        empty = {name: "" for name in zts._KEY_NAMES + zts._URL_NAMES}
        with patch.dict(os.environ, empty, clear=False), patch.object(
            zts.settings, "ZERO_TRUST_FUNCTION_KEY", ""
        ):
            self.assertFalse(zts._key_usable(zts._function_key()))
        with patch.dict(os.environ, dict(empty, ZT_FUNCTION_KEY="host-key-value"), clear=False):
            self.assertTrue(zts.configured())
            self.assertEqual(zts._function_key(), "host-key-value")
        with patch.dict(
            os.environ,
            dict(empty, ZERO_TRUST_FUNCTION_URL="https://example.azurewebsites.net"),
            clear=False,
        ):
            self.assertEqual(zts._base_url(), "https://example.azurewebsites.net/api")
        with patch.dict(
            os.environ,
            dict(empty, ZERO_TRUST_FUNCTION_URL="zero-trust-assessment.azurewebsites.net"),
            clear=False,
        ):
            self.assertEqual(
                zts._base_url(),
                "https://zero-trust-assessment.azurewebsites.net/api",
            )

    def test_dotenv_does_not_override_process_or_azure_env(self):
        import tempfile
        from unittest.mock import patch
        from config.settings import _load_dotenv

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, ".env")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("ZERO_TRUST_FUNCTION_KEY=from-file\n")
                handle.write("ZERO_TRUST_FUNCTION_URL=https://from-file.example/api\n")
            with patch.dict(
                os.environ,
                {
                    "ZERO_TRUST_FUNCTION_KEY": "from-process",
                    "WEBSITE_INSTANCE_ID": "azure-instance",
                },
                clear=False,
            ):
                _load_dotenv(path)
                self.assertEqual(os.environ["ZERO_TRUST_FUNCTION_KEY"], "from-process")
                self.assertNotEqual(
                    os.environ.get("ZERO_TRUST_FUNCTION_URL", ""),
                    "https://from-file.example/api",
                )

    def test_dotenv_fills_missing_local_key(self):
        import tempfile
        from unittest.mock import patch
        from config.settings import _load_dotenv

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, ".env")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("# comment\nZERO_TRUST_FUNCTION_KEY=local-only-key\n")
            env = {k: v for k, v in os.environ.items() if k != "ZERO_TRUST_FUNCTION_KEY"}
            env.pop("WEBSITE_INSTANCE_ID", None)
            with patch.dict(os.environ, env, clear=True):
                self.assertIsNone(os.environ.get("ZERO_TRUST_FUNCTION_KEY"))
                _load_dotenv(path)
                self.assertEqual(os.environ.get("ZERO_TRUST_FUNCTION_KEY"), "local-only-key")


if __name__ == "__main__":
    unittest.main()
