import unittest

from gateway.firewall_audit import extract_audit_payload, is_audit_payload, normalize_audit_payload


class FirewallAuditParseTests(unittest.TestCase):
    def test_selection_payload(self):
        payload = {
            "status": "AWAITING_FIREWALL_SELECTION",
            "action_required": "select_firewall",
            "firewalls": [{"name": "vmpafw01", "vendor": "Palo Alto", "ip": "10.1.0.5", "status": "live"}],
        }
        normalized = normalize_audit_payload(payload)
        self.assertEqual(normalized["response_type"], "firewall_selection")

    def test_down_payload(self):
        payload = {"status": "FIREWALL_DOWN", "message": "firewall down or stopped"}
        self.assertTrue(is_audit_payload(payload))
        self.assertEqual(normalize_audit_payload(payload)["response_type"], "firewall_down")

    def test_extract_json_from_reply(self):
        reply = (
            "Which firewall should I assess?\n"
            '{"response_type":"firewall_selection","status":"AWAITING_FIREWALL_SELECTION",'
            '"firewalls":[{"name":"ALL"}]}'
        )
        extracted = extract_audit_payload(reply)
        self.assertIsNotNone(extracted)
        self.assertEqual(extracted["response_type"], "firewall_selection")

    def test_assessment_payload(self):
        payload = {
            "response_type": "firewall_assessment",
            "inventory": {"hostname": "vmpafw01", "model": "PA-VM"},
            "summary": {"total_controls": 44, "compliant": 10, "non_compliant": 20, "not_assessed": 14},
            "findings": [{"control": "PA-16", "risk": "CRITICAL", "remediation": "Remove Any-Any rules."}],
        }
        self.assertTrue(is_audit_payload(payload))
        self.assertEqual(normalize_audit_payload(payload)["response_type"], "firewall_assessment")

    def test_selection_uses_options_array(self):
        payload = {
            "response_type": "firewall_selection",
            "status": "AWAITING_FIREWALL_SELECTION",
            "action_required": "select_firewall",
            "options": [
                {"name": "ALL", "vendor": "All Vendors", "ip": "all", "status": "live"},
                {"name": "vmpafw01", "vendor": "Palo Alto", "ip": "10.1.0.5", "status": "live"},
            ],
        }
        normalized = normalize_audit_payload(payload)
        self.assertEqual(len(normalized["options"]), 2)
        self.assertEqual(normalized["firewalls"][1]["name"], "vmpafw01")

    def test_compliance_score_copied_to_summary_and_posture(self):
        payload = {
            "response_type": "firewall_assessment",
            "summary": {
                "total_controls": 44,
                "compliant": 9,
                "non_compliant": 18,
                "not_assessed": 17,
                "compliance_score": "20.5%",
            },
            "overall_posture": {"label": "HIGH"},
            "findings": [
                {"control": "PA-24", "risk": "CRITICAL", "status": "NON_COMPLIANT", "remediation": "Enable threat prevention."}
            ],
        }
        normalized = normalize_audit_payload(payload)
        self.assertEqual(normalized["summary"]["compliance_score"], 20.5)
        self.assertEqual(normalized["summary"]["compliance_pct"], 20.5)
        self.assertEqual(normalized["overall_posture"]["compliance_score"], 20.5)

    def test_extract_options_json_from_reply(self):
        reply = (
            "Which firewall should I assess this time?\n"
            '{"response_type":"firewall_selection","status":"AWAITING_FIREWALL_SELECTION",'
            '"options":[{"name":"ALL","status":"live"},{"name":"vmpafw01","status":"live"}]}'
        )
        extracted = extract_audit_payload(reply)
        self.assertIsNotNone(extracted)
        self.assertEqual(extracted["options"][1]["name"], "vmpafw01")

    def test_structured_firewall_auditor_payload(self):
        payload = {
            "schema_version": "1.0",
            "source_agent": "FIREWALL_AUDITOR",
            "response_type": "FIREWALL_SELECTION",
            "title": "Select Firewall",
            "summary": "Choose a live firewall.",
            "items": [
                {"id": "ALL", "title": "ALL", "status": "live"},
                {"id": "vmpafw01", "title": "vmpafw01", "vendor": "Palo Alto", "management_ip": "10.1.0.5", "status": "live"},
            ],
            "actions": [],
        }
        self.assertTrue(is_audit_payload(payload))
        normalized = normalize_audit_payload(payload)
        self.assertEqual(normalized["source_agent"], "FIREWALL_AUDITOR")
        self.assertEqual(len(normalized["items"]), 2)

    def test_invalid_structured_payload_is_ignored(self):
        payload = {"response_type": "CAPABILITY", "items": [{"title": "Assess"}]}
        self.assertFalse(is_audit_payload(payload))
        self.assertIsNone(normalize_audit_payload(payload))


if __name__ == "__main__":
    unittest.main()
