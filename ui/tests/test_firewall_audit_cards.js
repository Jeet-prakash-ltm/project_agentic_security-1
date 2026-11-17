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
        device_information: { name: "vmpafw01", vendor: "Palo Alto" },
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
    assert.ok(rendered.html.indexOf("ws-mcq-card") !== -1);
    assert.ok(rendered.html.indexOf("Device Information") !== -1);
    assert.ok(rendered.html.indexOf("Overall Posture") !== -1);
    assert.ok(rendered.html.indexOf("Key Findings") !== -1);
    assert.ok(rendered.html.indexOf("Priority Recommendations") === -1);
    assert.ok(rendered.html.indexOf("PA-24") !== -1);
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

function testTopFiveFindingsOnly() {
    var findings = [];
    for (var i = 1; i <= 8; i++) {
        findings.push({
            control: "PA-0" + i,
            metric: "Control " + i,
            status: "NON_COMPLIANT",
            risk: i <= 3 ? "CRITICAL" : "MEDIUM",
            remediation: "Fix " + i
        });
    }
    var rendered = cards.renderAuditCards({
        response_type: "firewall_assessment",
        device_information: { name: "vmpafw01", vendor: "Palo Alto" },
        summary: { total_controls: 44, compliant: 9, non_compliant: 18, not_assessed: 17, compliance_score: 20 },
        findings: findings
    });
    assert.ok(rendered.html.indexOf("fw-audit-card") !== -1);
    assert.equal(rendered.findings.length, 5);
    assert.ok(rendered.html.indexOf("PA-01") !== -1);
    assert.ok(rendered.html.indexOf("PA-08") === -1);
    assert.ok(rendered.html.indexOf("Assessment Notice") === -1);
}

function testStructuredSelectionCards() {
    var rendered = cards.renderAuditCards({
        schema_version: "1.0",
        source_agent: "FIREWALL_AUDITOR",
        response_type: "FIREWALL_SELECTION",
        title: "Select Firewall",
        summary: "Choose a live firewall.",
        items: [
            { id: "ALL", title: "ALL", status: "live" },
            { id: "vmpafw01", title: "vmpafw01", vendor: "Palo Alto", management_ip: "10.1.0.5", status: "live" }
        ],
        actions: [{ label: "Run Assessment", intent: "RUN_ASSESSMENT", target_id: "vmpafw01" }]
    });
    assert.ok(rendered.html.indexOf("fw-audit-letter") !== -1);
    assert.ok(rendered.html.indexOf(">A<") !== -1);
    assert.ok(rendered.html.indexOf(">B<") !== -1);
    assert.ok(rendered.html.indexOf("data-fw-select=\"vmpafw01\"") !== -1);
    assert.ok(rendered.html.indexOf("data-fw-intent=\"RUN_ASSESSMENT\"") !== -1);
}

function testStructuredFindingsExpand() {
    var rendered = cards.renderAuditCards({
        schema_version: "1.0",
        source_agent: "FIREWALL_AUDITOR",
        response_type: "FINDINGS",
        title: "Key Findings",
        items: [
            { id: "PA-24", title: "Threat Prevention Disabled", status: "NON_COMPLIANT", risk: "CRITICAL", summary: "Threat Prevention is off.", observed_finding: "false", recommendation: "Enable it." },
            { id: "PA-10", title: "Disk", status: "NON_COMPLIANT", risk: "MEDIUM", summary: "Disk high." }
        ]
    });
    assert.ok(rendered.html.indexOf("PA-24") !== -1);
    assert.ok(rendered.html.indexOf("PA-10") !== -1);
    assert.ok(rendered.html.indexOf("Enable it.") !== -1);
}

function testStructuredReportDownloadOnlyWhenUrlExists() {
    var withUrl = cards.renderAuditCards({
        schema_version: "1.0",
        source_agent: "FIREWALL_AUDITOR",
        response_type: "REPORT_READY",
        title: "Report Ready",
        items: [{ title: "Workbook", download_url: "/api/excel?firewall=vmpafw01", file_name: "Workbook.xlsx" }]
    });
    var withoutUrl = cards.renderAuditCards({
        schema_version: "1.0",
        source_agent: "FIREWALL_AUDITOR",
        response_type: "REPORT_READY",
        title: "Report Ready",
        items: [{ title: "Workbook" }]
    });
    assert.ok(withUrl.html.indexOf("fw-audit-download") !== -1);
    assert.ok(withoutUrl.html.indexOf("fw-audit-download") === -1);
}

function testInvalidStructuredFallsBack() {
    assert.equal(cards.isStructuredAuditorPayload({ response_type: "CAPABILITY" }), false);
    assert.equal(cards.parseBeforeDisplay("Hello, I can assess firewalls.", null), null);
}

function testLiveFoundrySelectionMarkdown() {
    var markdown = [
        "To start the assessment, choose which firewall to assess:",
        "",
        "1. vmpafw01 — Palo Alto — 20.44.53.215 — status: live",
        "2. vmpafw03 — Palo Alto — 20.44.53.215 — status: live",
        "3. vmpafw04 — Palo Alto — 20.44.53.215 — status: live"
    ].join("\n");
    var parsed = cards.parseBeforeDisplay(markdown, null);
    assert.ok(parsed);
    assert.equal(parsed.response_type, "firewall_selection");
    assert.ok(parsed.html.indexOf("data-fw-select=\"vmpafw01\"") !== -1);
    assert.ok(parsed.html.indexOf("data-fw-select=\"vmpafw03\"") !== -1);
    assert.ok(parsed.html.indexOf("data-fw-select=\"vmpafw04\"") !== -1);
    assert.ok(parsed.html.indexOf("data-fw-select=\"ALL\"") !== -1);
    assert.ok(parsed.html.indexOf("ws-fw-select-option") !== -1);
}

function testLivePipeSelectionIncludesAll() {
    var markdown = [
        "To start the firewall audit assessment, please select which firewall to assess from the current inventory:",
        "",
        "1. vmpafw01 | Palo Alto | 20.44.53.215 | Status: live",
        "2. vmpafw03 | Palo Alto | 20.44.53.215 | Status: live",
        "3. vmpafw04 | Palo Alto | 20.44.53.215 | Status: live"
    ].join("\n");
    var parsed = cards.parseBeforeDisplay(markdown, null);
    assert.ok(parsed);
    assert.equal(parsed.response_type, "firewall_selection");
    ["ALL", "vmpafw01", "vmpafw03", "vmpafw04"].forEach(function (name) {
        assert.ok(parsed.html.indexOf("data-fw-select=\"" + name + "\"") !== -1, name);
    });
}

function testLiveFoundryAssessmentMarkdown() {
    var markdown = [
        "Here's the compliance audit result for firewall **vmpafw01** (Palo Alto PA-VM, PAN-OS 10.2.10-h9, IP 20.44.53.215):",
        "",
        "**Overall posture**",
        "- Assessment ID: **NS-vmpafw01-1794879675302**",
        "- Total controls: **44**",
        "- COMPLIANT: **12**",
        "- NON_COMPLIANT: **32**",
        "- Compliance score: **27.3%**",
        "- Overall risk: **CRITICAL**",
        "",
        "**Major risk drivers (examples)**",
        "- PAN-OS version not on supported baseline (PA-01).",
        "- Threat Prevention, WildFire, URL Filtering all disabled (PA-24)."
    ].join("\n");
    var parsed = cards.parseBeforeDisplay(markdown, null);
    assert.ok(parsed);
    assert.equal(parsed.response_type, "firewall_assessment");
    assert.equal(parsed.audit.summary.compliant, 12);
    assert.equal(parsed.audit.summary.non_compliant, 32);
    assert.equal(parsed.audit.summary.compliance_score, 27.3);
    assert.equal(parsed.audit.device_information.name, "vmpafw01");
    assert.ok(parsed.html.indexOf("Device Information") !== -1);
    assert.ok(parsed.html.indexOf("Overall Posture") !== -1);
    assert.ok(parsed.html.indexOf("Key Findings") !== -1);
    assert.ok(parsed.html.indexOf("27.3%") !== -1);
    assert.ok(parsed.html.indexOf("vmpafw01") !== -1);
    assert.ok(parsed.html.indexOf("NaN") === -1);
    assert.ok(parsed.audit.findings.length >= 2);
    assert.equal(parsed.audit.findings[0].control, "PA-01");
    assert.equal(parsed.audit.findings[1].control, "PA-24");
}

function testLiveAssessmentHasFindingsAndDevice() {
    var markdown = [
        "Here's the compliance audit summary for firewall **vmpafw01**:",
        "",
        "**Device & Scope**",
        "- Vendor/Model: Palo Alto PA-VM",
        "- Version: PAN-OS 10.2.10-h9",
        "- IP: 20.44.53.215",
        "- Status: live",
        "- Assessment ID: **NS-vmpafw01-1794881225793**",
        "",
        "**Overall Posture**",
        "- Total controls: **44**",
        "- COMPLIANT: **12**",
        "- NON_COMPLIANT: **32**",
        "- Compliance score: **27.3%**",
        "- Overall risk: **CRITICAL**",
        "",
        "**Major Risk Areas (evidence-based)**",
        "1. **Platform & Updates**",
        "   - PAN-OS version not on supported baseline (PA-01, NON_COMPLIANT, HIGH).",
        "   - Threat Prevention: **disabled** (PA-24, NON_COMPLIANT, CRITICAL)."
    ].join("\n");
    var parsed = cards.parseBeforeDisplay(markdown, null);
    assert.ok(parsed);
    assert.equal(parsed.response_type, "firewall_assessment");
    assert.equal(parsed.audit.device_information.name, "vmpafw01");
    assert.equal(parsed.audit.summary.compliance_score, 27.3);
    assert.ok(parsed.audit.findings.length >= 2);
    assert.ok(parsed.html.indexOf("No key findings") === -1);
    assert.ok(parsed.html.indexOf("PA-01") !== -1);
    assert.ok(parsed.html.indexOf("Device Information") !== -1);
}

function testLiveKeyFindingsReply() {
    var markdown = [
        "Here are the key findings from the vmpafw01 assessment, focused on the most material risks:",
        "",
        "1. **Core Security Services Disabled**",
        "   - **Threat Prevention profiles not enabled or not attached to rules**",
        "     - Status: **NON_COMPLIANT**",
        "     - Risk: **CRITICAL**",
        "     - Impact: Malware can pass through.",
        "   - **SSL/TLS decryption disabled**",
        "     - Status: **NON_COMPLIANT**",
        "     - Risk: **CRITICAL**",
        "     - Impact: Encrypted threats are invisible."
    ].join("\n");
    var parsed = cards.parseBeforeDisplay(markdown, null);
    assert.ok(parsed);
    assert.ok(parsed.audit.findings.length >= 2);
    assert.ok(parsed.html.indexOf("Key Findings") !== -1);
    assert.ok(parsed.html.indexOf("No key findings") === -1);
    assert.ok(parsed.html.indexOf("Threat Prevention") !== -1);
}

function testLiveExecutiveSummaryReply() {
    var markdown = [
        "Here's the executive summary for the firewall **vmpafw01** assessment (Assessment ID: **NS-vmpafw01-1794881225793**).",
        "",
        "## 1. Overall Posture",
        "- **Device:** Palo Alto Networks PA-VM (vmpafw01), IP: 20.44.53.215",
        "- **Compliance Score:** **27.3%**",
        "- **Overall Risk Rating:** **CRITICAL**",
        "",
        "## 2. Key Risk Themes",
        "### A. Core Threat Protection Not Effectively Enforced",
        "- Threat Prevention, Anti-Spyware, WildFire analysis are not enabled (PA-24)."
    ].join("\n");
    var parsed = cards.parseBeforeDisplay(markdown, null);
    assert.ok(parsed);
    assert.equal(parsed.response_type, "executive_summary");
    assert.equal(parsed.audit.device_information.name, "vmpafw01");
    assert.equal(parsed.audit.summary.compliance_score, 27.3);
    assert.ok(parsed.html.indexOf("27.3%") !== -1);
    assert.ok(parsed.html.indexOf("vmpafw01") !== -1);
    assert.ok(parsed.html.indexOf("No key findings") === -1);
}

testSelectionOptions();
testComplianceScoreNotNaN();
testMarkdownAssessment();
testTopFiveFindingsOnly();
testStructuredSelectionCards();
testStructuredFindingsExpand();
testStructuredReportDownloadOnlyWhenUrlExists();
testInvalidStructuredFallsBack();
testLiveFoundrySelectionMarkdown();
testLiveFoundryAssessmentMarkdown();
testLivePipeSelectionIncludesAll();
testLiveAssessmentHasFindingsAndDevice();
testLiveKeyFindingsReply();
testLiveExecutiveSummaryReply();
console.log("ok");
