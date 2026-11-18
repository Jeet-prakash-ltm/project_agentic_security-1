var assert = require("assert");
var fs = require("fs");
var path = require("path");
var vm = require("vm");

var code = fs.readFileSync(
    path.join(__dirname, "../static/js/firewall_audit_cards.js"),
    "utf8"
);
var sandbox = { window: {}, console: console };
vm.runInNewContext(code, sandbox);
var cards = sandbox.window.FirewallAuditCards;

var AGENTS = {
    maestro: { id: "master-orchestrator-agent", name: "Maestro AI", type: "Master Orchestrator", agent_id: "test-agent" },
    zeroTrust: { id: "zero-trust-with-endpoint-agent", name: "Zero Trust with Endpoint", type: "Cloud Security Agent", agent_id: "Zero-trust-Agent" },
    cloud: { id: "cloud-security-agent", name: "Cloud Security", type: "Cloud Security Agent", agent_id: "Cloud-Security-Agent" },
    execution: { id: "netsec-execution-agent", name: "Firewall Execution Agent", type: "Network Security Agent", agent_id: "Firewall-Excecution-Agent" },
    audit: { id: "firewall-audit-agent", name: "Firewall Audit Agent", type: "Network Security Agent", agent_id: "Firewall-Audit-Agent" }
};

function isOrchestratorAgent(agent) {
    if (!agent) return false;
    var text = String(agent.id || "") + " " + String(agent.name || "") + " " + String(agent.type || "") + " " + String(agent.agent_id || "");
    return /orchestrat|maestro/i.test(text) || String(agent.id || "") === "master-orchestrator-agent";
}

function isNetsecAgent(agent) {
    if (!agent) return false;
    if (isOrchestratorAgent(agent)) return false;
    var text = String(agent.id || "") + " " + String(agent.name || "") + " " + String(agent.type || "");
    return /netsec|execution/i.test(text);
}

function isCloudSecurityOpsAgent(agent) {
    if (!agent) return false;
    var name = String(agent.name || "").toLowerCase();
    var id = String(agent.id || "").toLowerCase();
    var type = String(agent.type || "").toLowerCase();
    var agentId = String(agent.agent_id || "").toLowerCase();
    return name.indexOf("cloud security ops") !== -1 ||
        id === "incident-response-agent-cloud-security" ||
        type.indexOf("cloud incident") !== -1 ||
        agentId.indexOf("incident-response-agent-cloud-security") !== -1;
}

function isZeroTrustAgent(agent) {
    if (!agent) return false;
    var text = String(agent.id || "") + " " + String(agent.name || "") + " " + String(agent.agent_id || "");
    return /zero.?trust/i.test(text);
}

function isNamedCloudSecurityAgent(agent) {
    if (!agent || isCloudSecurityOpsAgent(agent) || isZeroTrustAgent(agent)) return false;
    var id = String(agent.id || "").toLowerCase();
    var name = String(agent.name || "").toLowerCase();
    var agentId = String(agent.agent_id || "").toLowerCase();
    return id === "cloud-security-agent" ||
        name === "cloud security" ||
        agentId === "cloud-security" ||
        agentId === "cloud-security-agent";
}

function isFirewallAgent(agent) {
    if (!agent) return false;
    if (isOrchestratorAgent(agent) || isNetsecAgent(agent) || isCloudSecurityOpsAgent(agent) || isZeroTrustAgent(agent) || isNamedCloudSecurityAgent(agent)) return false;
    var name = String(agent.name || "").toLowerCase();
    var id = String(agent.id || "").toLowerCase();
    var agentId = String(agent.agent_id || "").toLowerCase();
    return id.indexOf("firewall-audit") !== -1 ||
        agentId.indexOf("firewall-audit") !== -1 ||
        name.indexOf("firewall audit") !== -1 ||
        name.indexOf("firewall auditor") !== -1;
}

function wouldRenderAuditCards(agent, content, audit) {
    if (!isFirewallAgent(agent)) return null;
    return cards.parseBeforeDisplay(content, audit);
}

var FIREWALL_SELECTION = [
    "To start the assessment, choose which firewall to assess:",
    "",
    "1. vmpafw01 — Palo Alto — 20.44.53.215 — status: live",
    "2. vmpafw03 — Palo Alto — 20.44.53.215 — status: live"
].join("\n");

var ZERO_TRUST_ASSESSMENT = [
    "Starting Zero Trust assessment for tenant Contoso.",
    "",
    "**Overall Posture**",
    "- Total controls: **54**",
    "- COMPLIANT: **40**",
    "- NON_COMPLIANT: **14**",
    "- Compliance score: **74%**",
    "- Overall risk: **HIGH**",
    "",
    "**Key Findings**",
    "- MFA registration is below baseline.",
    "- Unmanaged endpoints are present."
].join("\n");

var ZERO_TRUST_TENANT_SELECT = [
    "I'll start a Zero Trust assessment. Please select a tenant:",
    "",
    "1. Contoso",
    "2. Fabrikam"
].join("\n");

function testDropdownClassification() {
    assert.equal(isFirewallAgent(AGENTS.audit), true);
    assert.equal(isFirewallAgent(AGENTS.maestro), false);
    assert.equal(isFirewallAgent(AGENTS.zeroTrust), false);
    assert.equal(isFirewallAgent(AGENTS.cloud), false);
    assert.equal(isFirewallAgent(AGENTS.execution), false);
}

function testZeroTrustPromptDoesNotLeakOnMaestroOrZeroTrust() {
    [AGENTS.maestro, AGENTS.zeroTrust].forEach(function (agent) {
        assert.equal(wouldRenderAuditCards(agent, ZERO_TRUST_ASSESSMENT, null), null, agent.name + " posture");
        assert.equal(wouldRenderAuditCards(agent, ZERO_TRUST_TENANT_SELECT, null), null, agent.name + " tenant");
        assert.equal(wouldRenderAuditCards(agent, FIREWALL_SELECTION, null), null, agent.name + " firewall selection");
        assert.equal(wouldRenderAuditCards(agent, FIREWALL_SELECTION, {
            response_type: "firewall_selection",
            options: [{ name: "vmpafw01", status: "live" }]
        }), null, agent.name + " leftover audit");
    });
}

function testUngatedParserWouldLeakZeroTrustPosture() {
    var parsed = cards.parseBeforeDisplay(ZERO_TRUST_ASSESSMENT, null);
    assert.ok(parsed && parsed.html, "unguarded parser still treats Zero Trust posture as an audit card");
    assert.ok(parsed.html.indexOf("ws-audit-stack") !== -1 || parsed.html.indexOf("Overall Posture") !== -1 || parsed.response_type === "firewall_assessment");
}

function testAuditAgentStillRendersFirewallSelection() {
    var parsed = wouldRenderAuditCards(AGENTS.audit, FIREWALL_SELECTION, null);
    assert.ok(parsed && parsed.html);
    assert.equal(parsed.response_type, "firewall_selection");
    assert.ok(parsed.html.indexOf("data-fw-select=\"vmpafw01\"") !== -1);
}

testDropdownClassification();
testZeroTrustPromptDoesNotLeakOnMaestroOrZeroTrust();
testUngatedParserWouldLeakZeroTrustPosture();
testAuditAgentStillRendersFirewallSelection();
console.log("ok");
