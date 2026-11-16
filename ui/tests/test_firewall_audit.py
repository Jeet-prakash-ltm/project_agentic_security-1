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


if __name__ == "__main__":
    unittest.main()
