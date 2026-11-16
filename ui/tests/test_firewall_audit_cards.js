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

function testSelectionOptions() {
    var payload = cards.normalizeAuditPayload({
        response_type: "firewall_selection",
        options: [
            { name: "ALL", vendor: "All Vendors", ip: "all", status: "live" },
            { name: "vmpafw01", vendor: "Palo Alto", ip: "10.1.0.5", status: "live" }
        ]
    });
    var rendered = cards.renderAuditCards(payload);
    assert.ok(rendered.html.indexOf("data-fw-select=\"ALL\"") !== -1);
    assert.ok(rendered.html.indexOf("data-fw-select=\"vmpafw01\"") !== -1);
    assert.ok(rendered.html.indexOf("ws-fw-select-option") !== -1);
}

function testComplianceScoreNotNaN() {
    var payload = cards.normalizeAuditPayload({
        response_type: "firewall_assessment",
        summary: {
            total_controls: 44,
            compliant: 9,
            non_compliant: 18,
            not_assessed: 17,
            compliance_score: "~20%"
        },
        findings: [
            { control: "PA-24", metric: "Threat Prevention", status: "NON_COMPLIANT", risk: "CRITICAL", remediation: "Enable threat prevention." },
            { control: "PA-10", metric: "Disk", status: "NON_COMPLIANT", risk: "MEDIUM", remediation: "Reduce disk usage." }
        ]
    });
    var rendered = cards.renderAuditCards(payload);
    assert.ok(rendered.html.indexOf("NaN%") === -1);
    assert.ok(rendered.html.indexOf("20%") !== -1);
    assert.ok(rendered.html.indexOf("audit-section-count\">2<") !== -1 || rendered.html.indexOf(">2</span>") !== -1);
    assert.ok(rendered.html.indexOf("Enable threat prevention.") !== -1);
}

function testMarkdownAssessment() {
    var markdown = [
        "2. DEVICE INFORMATION",
        "- Firewall Name: vmpafw01",
        "- Vendor: Palo Alto",
        "3. OVERALL POSTURE",
        "- Total Controls Assessed: 44",
        "- COMPLIANT: 9",
        "- NON_COMPLIANT: 18",
        "- INSUFFICIENT_DATA (tool reported as NOT_ASSESSED): 17",
        "- Approx. Compliance Score: ~20% (9 / 44)",
        "4. KEY FINDINGS",
        "PA-24 | Threat Prevention Not Enabled",
        "Status: NON_COMPLIANT",
        "Risk: CRITICAL",
        "Recommendation:",
        "- Enable Threat Prevention.",
        "PA-10 | High Disk Utilization",
        "Status: NON_COMPLIANT",
        "Risk: MEDIUM",
        "Recommendation:",
        "- Offload logs.",
        "5. PRIORITY RECOMMENDATIONS",
        "1) Enable core security services"
    ].join("\n");
    var parsed = cards.parseBeforeDisplay(markdown, null);
    assert.ok(parsed);
    assert.equal(parsed.audit.summary.compliant, 9);
    assert.equal(parsed.audit.summary.non_compliant, 18);
    assert.equal(parsed.audit.summary.compliance_score, 20);
    assert.ok(parsed.audit.findings.length >= 2);
    assert.ok(parsed.html.indexOf("NaN%") === -1);
    assert.ok(parsed.html.indexOf("20%") !== -1);
    assert.ok(parsed.html.indexOf("No key findings") === -1);
}

testSelectionOptions();
testComplianceScoreNotNaN();
testMarkdownAssessment();
console.log("ok");
