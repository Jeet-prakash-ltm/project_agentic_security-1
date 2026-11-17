import unittest

from gateway.foundry_client import (
    _system_prompt,
    _with_ui_blocks,
    is_firewall_audit_agent,
    is_maestro_agent,
)


AUDIT_AGENT = {
    "id": "firewall-audit-agent",
    "name": "Firewall Audit Agent",
    "type": "Network Security Agent",
    "agent_id": "Firewall-Audit-Agent",
}

MAESTRO_AGENT = {
    "id": "master-orchestrator-agent",
    "name": "Maestro AI",
    "type": "Master Orchestrator",
    "agent_id": "Maestro-AI",
}

ZERO_TRUST_AGENT = {
    "id": "zero-trust-with-endpoint-agent",
    "name": "Zero Trust with Endpoint",
    "type": "Cloud Security Agent",
    "agent_id": "Zero-trust-Agent",
}

CLOUD_AGENT = {
    "id": "cloud-security-agent",
    "name": "Cloud Security",
    "type": "Cloud Security Agent",
    "agent_id": "Cloud-Security-Agent",
}

EXECUTION_AGENT = {
    "id": "netsec-execution-agent",
    "name": "Firewall Execution Agent",
    "type": "Network Security Agent",
    "agent_id": "Firewall-Excecution-Agent",
}

SELECTION_REPLY = (
    "Which firewall should I assess this time?\n"
    '{"response_type":"firewall_selection","status":"AWAITING_FIREWALL_SELECTION",'
    '"options":[{"name":"ALL","status":"live"},{"name":"vmpafw01","status":"live"}]}'
)


class FirewallAuditAgentGateTests(unittest.TestCase):
    def test_maestro_returns_endpoint_text_unchanged(self):
        self.assertTrue(is_maestro_agent(MAESTRO_AGENT))
        reply = (
            "I can start a Zero Trust assessment.\n"
            "Please provide:\n"
            "- Tenant name\n"
            "- Scope\n"
            "```ui\n"
            '{"ui":[{"type":"form","title":"Start assessment",'
            '"fields":[{"name":"tenant","label":"Tenant","type":"text"}]}]}\n'
            "```"
        )
        result = _with_ui_blocks({"reply": reply, "audit": {"response_type": "firewall_selection"}}, MAESTRO_AGENT)
        self.assertEqual(result["reply"], reply)
        self.assertEqual(result["blocks"], [])
        self.assertIsNone(result.get("audit"))
        prompt = _system_prompt(MAESTRO_AGENT)
        self.assertNotIn("Interactive UI:", prompt)
        self.assertIn("Maestro AI", prompt)

    def test_only_audit_agent_matches(self):
        self.assertTrue(is_firewall_audit_agent(AUDIT_AGENT))
        self.assertFalse(is_firewall_audit_agent(MAESTRO_AGENT))
        self.assertFalse(is_firewall_audit_agent(ZERO_TRUST_AGENT))
        self.assertFalse(is_firewall_audit_agent(CLOUD_AGENT))
        self.assertFalse(is_firewall_audit_agent(EXECUTION_AGENT))
        self.assertFalse(is_firewall_audit_agent(None))

    def test_audit_payload_extracted_for_audit_agent(self):
        result = _with_ui_blocks({"reply": SELECTION_REPLY}, AUDIT_AGENT)
        self.assertEqual(result["audit"]["response_type"], "firewall_selection")
        self.assertEqual(result["audit"]["options"][1]["name"], "vmpafw01")

    def test_zero_trust_start_does_not_attach_audit_cards(self):
        leftover = {
            "response_type": "firewall_selection",
            "status": "AWAITING_FIREWALL_SELECTION",
            "options": [{"name": "vmpafw01", "status": "live"}],
        }
        reply = (
            "Starting Zero Trust assessment.\n"
            "**Overall Posture**\n"
            "- Total controls: 54\n"
            "- COMPLIANT: 40\n"
            "- NON_COMPLIANT: 14\n"
            "- Compliance score: 74%\n"
        )
        for agent in (MAESTRO_AGENT, ZERO_TRUST_AGENT):
            result = _with_ui_blocks({"reply": reply, "audit": leftover}, agent)
            self.assertIsNone(result.get("audit"), agent["name"])
            self.assertNotIn("firewall_selection", str(result.get("blocks") or []))

    def test_audit_payload_stripped_for_other_agents(self):
        leftover = {
            "response_type": "firewall_selection",
            "status": "AWAITING_FIREWALL_SELECTION",
            "options": [{"name": "vmpafw01", "status": "live"}],
        }
        for agent in (MAESTRO_AGENT, ZERO_TRUST_AGENT, CLOUD_AGENT, EXECUTION_AGENT):
            result = _with_ui_blocks(
                {"reply": SELECTION_REPLY, "audit": leftover},
                agent,
            )
            self.assertIsNone(result.get("audit"), agent["name"])
            self.assertIn("Which firewall", result["reply"])


if __name__ == "__main__":
    unittest.main()
