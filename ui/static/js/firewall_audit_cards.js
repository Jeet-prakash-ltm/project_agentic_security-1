(function (root) {
    "use strict";

    var RESPONSE_TYPES = {
        firewall_selection: 1,
        firewall_down: 1,
        firewall_assessment: 1,
        executive_summary: 1
    };

    function escapeHtml(value) {
        var div = document.createElement("div");
        div.textContent = value == null ? "" : String(value);
        return div.innerHTML;
    }

    function asList(value) {
        if (!value) return [];
        if (Array.isArray(value)) return value;
        return [];
    }

    function textOf(value) {
        if (value == null) return "";
        return String(value).trim();
    }

    function tryParseJson(text) {
        if (!text || typeof text !== "string") return null;
        var trimmed = text.trim();
        if (!trimmed) return null;
        try {
            var parsed = JSON.parse(trimmed);
            return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : null;
        } catch (err) {
            return null;
        }
    }

    function extractJsonObjects(text) {
        var payloads = [];
        if (!text) return payloads;
        var fence = /```[ \t]*([A-Za-z0-9_\-]*)[ \t]*\r?\n([\s\S]*?)```/g;
        var match;
        while ((match = fence.exec(text))) {
            var fenced = tryParseJson(match[2] || "");
            if (fenced) payloads.push(fenced);
        }
        var stripped = text.replace(fence, " ");
        var start = stripped.indexOf("{");
        while (start !== -1) {
            var depth = 0;
            var inString = false;
            var escape = false;
            var end = -1;
            for (var i = start; i < stripped.length; i++) {
                var ch = stripped.charAt(i);
                if (inString) {
                    if (escape) escape = false;
                    else if (ch === "\\") escape = true;
                    else if (ch === '"') inString = false;
                    continue;
                }
                if (ch === '"') { inString = true; continue; }
                if (ch === "{") depth++;
                else if (ch === "}") {
                    depth--;
                    if (depth === 0) { end = i + 1; break; }
                }
            }
            if (end === -1) break;
            var parsed = tryParseJson(stripped.slice(start, end));
            if (parsed) payloads.push(parsed);
            start = stripped.indexOf("{", end);
        }
        return payloads;
    }

    function isAuditPayload(payload) {
        if (!payload || typeof payload !== "object") return false;
        var type = String(payload.response_type || "").trim();
        if (RESPONSE_TYPES[type]) return true;
        var status = String(payload.status || "").trim().toUpperCase();
        if (status === "AWAITING_FIREWALL_SELECTION" || status === "FIREWALL_DOWN") return true;
        if (payload.findings && (payload.summary || payload.inventory || payload.assessment)) return true;
        if (payload.top_findings && payload.device) return true;
        if (payload.firewalls && payload.action_required) return true;
        return false;
    }

    function normalizeAuditPayload(payload) {
        if (!isAuditPayload(payload)) return null;
        var data = payload;
        var status = String(data.status || "").trim().toUpperCase();
        var type = String(data.response_type || "").trim();
        if (!type) {
            if (status === "AWAITING_FIREWALL_SELECTION" || data.action_required === "select_firewall") {
                type = "firewall_selection";
            } else if (status === "FIREWALL_DOWN") {
                type = "firewall_down";
            } else if (data.top_findings != null && data.device) {
                type = "executive_summary";
            } else {
                type = "firewall_assessment";
            }
            data = Object.assign({}, data, { response_type: type });
        }
        return data;
    }

    function extractAuditPayload(text, toolPayload) {
        var fromTool = normalizeAuditPayload(toolPayload);
        if (fromTool) return fromTool;
        var objects = extractJsonObjects(text || "");
        for (var i = 0; i < objects.length; i++) {
            var normalized = normalizeAuditPayload(objects[i]);
            if (normalized) return normalized;
        }
        return null;
    }

    function unique(list) {
        var seen = {};
        var out = [];
        (list || []).forEach(function (item) {
            var key = String(item || "").trim();
            if (!key || seen[key]) return;
            seen[key] = true;
            out.push(key);
        });
        return out;
    }

    function riskKey(risk) {
        var value = String(risk || "").toLowerCase();
        if (value.indexOf("critical") !== -1) return "critical";
        if (value.indexOf("high") !== -1) return "high";
        if (value.indexOf("medium") !== -1) return "medium";
        if (value.indexOf("low") !== -1) return "low";
        return "";
    }

    function riskClass(risk) {
        var key = riskKey(risk);
        return key ? "risk-" + key : "";
    }

    function statusClass(status) {
        var value = String(status || "").toUpperCase();
        if (value === "NON_COMPLIANT") return "status-noncompliant";
        if (value === "GAP_IDENTIFIED") return "status-gap";
        if (value === "COMPLIANT") return "status-compliant";
        return "";
    }

    function deviceFrom(payload) {
        var device = payload.device_information || payload.device || {};
        var inventory = payload.inventory || {};
        var selected = payload._selected_firewall || payload.selected_firewall || {};
        return {
            name: textOf(device.name || selected.name || inventory.hostname || payload._firewall_id),
            vendor: textOf(device.vendor || inventory.vendor || selected.vendor),
            ip: textOf(device.ip || selected.management_ip || inventory.ip || inventory.management_ip),
            status: textOf(device.status || selected.status),
            scope: textOf(device.scope || payload.scope)
        };
    }

    function postureFrom(payload) {
        var posture = payload.overall_posture || {};
        var summary = payload.summary || {};
        var findings = asList(payload.findings);
        var pct = posture.compliance_pct;
        if (pct == null) pct = summary.compliance_pct;
        var severity = posture.severity || { critical: 0, high: 0, medium: 0, low: 0 };
        if (!posture.severity) {
            findings.forEach(function (finding) {
                var key = riskKey(finding.risk);
                if (key && severity[key] != null) severity[key] += 1;
            });
        }
        return {
            label: textOf(posture.label),
            compliance_pct: pct,
            severity: {
                critical: Number(severity.critical) || 0,
                high: Number(severity.high) || 0,
                medium: Number(severity.medium) || 0,
                low: Number(severity.low) || 0
            }
        };
    }

    function recommendationsFrom(payload) {
        var recs = asList(payload.recommendations);
        if (!recs.length) recs = asList(payload.remediation_priorities);
        return unique(recs);
    }

    function findingsFrom(payload) {
        var findings = asList(payload.findings);
        if (!findings.length) findings = asList(payload.top_findings);
        return findings;
    }

    function overallRisk(posture) {
        if (posture.label) {
            return posture.label.replace(/_/g, " ").replace(/\b\w/g, function (ch) {
                return ch.toUpperCase();
            });
        }
        if (posture.severity.critical) return "Critical Risk";
        if (posture.severity.high) return "High Risk";
        if (posture.severity.medium) return "Medium Risk";
        if (posture.severity.low) return "Low Risk";
        return "";
    }

    function agentHeader() {
        return '<div class="audit-card"><div class="audit-header"><div>' +
            "<h2>Firewall Auditor Agent</h2>" +
            '<div class="muted">Security, Compliance &amp; Operational Assessment</div>' +
            '</div><span class="badge readonly">READ ONLY</span></div></div>';
    }

    function wrap(inner) {
        return '<div class="audit-wrap">' + agentHeader() + (inner || "") + "</div>";
    }

    function wrapAgentOutput(innerHtml) {
        var html = innerHtml || "";
        if (html.indexOf('class="audit-wrap"') !== -1) return html;
        return wrap('<div class="audit-card">' + html + "</div>");
    }

    function badge(label, className) {
        if (!label) return "";
        return '<span class="badge ' + className + '">' + escapeHtml(label) + "</span>";
    }

    function detailCell(label, value) {
        if (!textOf(value)) return "";
        return "<div><div class=\"detail-label\">" + escapeHtml(label) + "</div>" +
            '<div class="detail-value">' + escapeHtml(value) + "</div></div>";
    }

    function FindingCard(finding) {
        var risk = textOf(finding.risk);
        var status = textOf(finding.status);
        var title = textOf(finding.metric || finding.control);
        var summary = textOf(finding.finding);
        var border = "";
        if (riskKey(risk) === "medium") border = ' style="border-left-color:#eab308;"';
        else if (riskKey(risk) === "high") border = ' style="border-left-color:#ea580c;"';
        else if (riskKey(risk) === "low") border = ' style="border-left-color:#16a34a;"';
        var html = '<div class="audit-card finding"' + border + ">";
        html += '<div class="finding-header"><div>';
        if (finding.control) html += '<div class="finding-id">' + escapeHtml(finding.control) + "</div>";
        if (title) html += '<div class="finding-title">' + escapeHtml(title) + "</div>";
        html += '</div><div class="badge-group">';
        html += badge(status, statusClass(status));
        html += badge(risk, riskClass(risk));
        html += "</div></div>";
        if (summary) html += '<div class="finding-summary">' + escapeHtml(summary) + "</div>";
        var details = detailCell("Observed Finding", finding.observed) +
            detailCell("Identified Gap", finding.finding) +
            detailCell("Business Impact", finding.business_impact || finding.impact) +
            detailCell("Recommendation", finding.remediation);
        if (details) {
            html += "<details><summary>View finding details</summary>";
            html += '<div class="details-grid">' + details + "</div></details>";
        }
        return html + "</div>";
    }

    function FindingDetailCard(finding) {
        return FindingCard(finding || {});
    }

    function AssessmentSummaryCard(payload) {
        var device = deviceFrom(payload);
        var posture = postureFrom(payload);
        var risk = overallRisk(posture);
        var html = '<div class="audit-card"><div class="audit-header"><div>';
        html += '<div class="muted">ASSESSMENT</div><h2>Firewall Audit Assessment</h2></div>';
        html += badge(risk, riskClass(risk));
        html += "</div>";
        var meta = [];
        if (device.name) meta.push("Firewall: " + device.name);
        if (device.vendor) meta.push("Vendor: " + device.vendor);
        if (device.scope) meta.push("Scope: " + device.scope);
        if (meta.length) {
            html += '<div class="muted" style="margin-top:10px;">' + escapeHtml(meta.join("  •  ")) + "</div>";
        }
        html += '<div class="posture-grid">';
        html += '<div class="metric"><div class="metric-label">Compliance</div><div class="metric-value">' +
            escapeHtml(posture.compliance_pct == null ? "" : String(posture.compliance_pct) + "%") + "</div></div>";
        html += '<div class="metric"><div class="metric-label">Critical</div><div class="metric-value" style="color:#dc2626;">' +
            escapeHtml(String(posture.severity.critical)) + "</div></div>";
        html += '<div class="metric"><div class="metric-label">High</div><div class="metric-value" style="color:#ea580c;">' +
            escapeHtml(String(posture.severity.high)) + "</div></div>";
        html += '<div class="metric"><div class="metric-label">Medium</div><div class="metric-value" style="color:#ca8a04;">' +
            escapeHtml(String(posture.severity.medium)) + "</div></div>";
        html += '<div class="metric"><div class="metric-label">Low</div><div class="metric-value" style="color:#16a34a;">' +
            escapeHtml(String(posture.severity.low)) + "</div></div>";
        html += "</div></div>";
        return html;
    }

    function ExecutiveSummaryCard(payload) {
        return assessmentCard(payload).html;
    }

    function assessmentCard(payload) {
        var findings = findingsFrom(payload);
        var recs = recommendationsFrom(payload);
        var html = AssessmentSummaryCard(payload);
        if (findings.length) {
            html += '<div class="section-title">Key Findings</div>';
            findings.forEach(function (finding) { html += FindingCard(finding); });
        }
        if (recs.length) {
            html += '<div class="audit-card"><div class="section-title">Priority Recommendations</div><ol class="recommendations">';
            recs.forEach(function (rec) { html += "<li>" + escapeHtml(rec) + "</li>"; });
            html += "</ol></div>";
        }
        return { html: wrap(html), findings: findings };
    }

    function selectionBody(payload) {
        var options = asList(payload.firewalls);
        var html = '<div class="audit-card"><div class="muted">INVENTORY</div>';
        html += "<h2>Select Firewall</h2>";
        if (payload.prompt) html += '<div class="muted" style="margin-top:10px;">' + escapeHtml(payload.prompt) + "</div>";
        else if (payload.message) html += '<div class="muted" style="margin-top:10px;">' + escapeHtml(payload.message) + "</div>";
        if (payload.invalid_selection) {
            html += '<div class="notice" style="margin-top:12px;">Firewall ' +
                escapeHtml(payload.invalid_selection) + " was not found in inventory.</div>";
        }
        html += '<div class="ws-fw-select-list" style="padding:12px 0 0;">';
        options.forEach(function (fw) {
            var name = textOf(fw.name || fw.hostname);
            var vendor = textOf(fw.vendor);
            var ip = textOf(fw.ip || fw.management_ip);
            var status = textOf(fw.status);
            html += '<button type="button" class="ws-fw-select-option" data-fw-select="' +
                escapeHtml(name) + '" data-fw-status="' + escapeHtml(status) + '">';
            html += '<span class="ws-fw-select-name">' + escapeHtml(name) +
                (status ? " · " + escapeHtml(status) : "") + "</span>";
            var meta = [vendor, ip, status].filter(Boolean).join(" · ");
            if (meta) html += '<span class="ws-fw-select-meta">' + escapeHtml(meta) + "</span>";
            if (fw.description) html += '<span class="ws-fw-select-desc">' + escapeHtml(fw.description) + "</span>";
            html += "</button>";
        });
        return html + "</div></div>";
    }

    function selectionCard(payload) {
        return wrap(selectionBody(payload));
    }

    function downCard(payload) {
        var selected = payload.selected_firewall || {};
        var html = '<div class="audit-card"><h2>Firewall down or stopped</h2>';
        html += '<div class="finding-summary">' +
            escapeHtml(payload.message || "firewall down or stopped") + "</div>";
        if (selected.name) {
            html += '<div class="muted" style="margin-top:10px;">' +
                escapeHtml(selected.name) +
                (selected.status ? " is " + escapeHtml(selected.status) : "") +
                ".</div>";
        }
        html += "</div>";
        if (asList(payload.firewalls).length) html += selectionBody(payload);
        return wrap(html);
    }

    function renderAuditCards(payload) {
        var data = normalizeAuditPayload(payload);
        if (!data) return null;
        var type = data.response_type;
        if (type === "firewall_selection") {
            return { html: selectionCard(data), findings: [], cardTitle: "Select Firewall", response_type: type };
        }
        if (type === "firewall_down") {
            return { html: downCard(data), findings: [], cardTitle: "Firewall down or stopped", response_type: type };
        }
        var rendered = assessmentCard(data);
        rendered.cardTitle = type === "executive_summary" ? "Executive Summary" : "Firewall Assessment";
        rendered.response_type = type;
        return rendered;
    }

    function parseBeforeDisplay(content, audit) {
        var payload = extractAuditPayload(content, audit);
        if (!payload) return null;
        var rendered = renderAuditCards(payload);
        if (!rendered) return null;
        rendered.audit = payload;
        rendered.lead = "";
        return rendered;
    }

    root.FirewallAuditCards = {
        isAuditPayload: isAuditPayload,
        normalizeAuditPayload: normalizeAuditPayload,
        extractAuditPayload: extractAuditPayload,
        parseBeforeDisplay: parseBeforeDisplay,
        renderAuditCards: renderAuditCards,
        wrapAgentOutput: wrapAgentOutput,
        AssessmentSummaryCard: AssessmentSummaryCard,
        FindingCard: FindingCard,
        FindingDetailCard: FindingDetailCard,
        ExecutiveSummaryCard: ExecutiveSummaryCard
    };
})(window);
