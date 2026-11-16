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
        return parseMarkdownAudit(text || "");
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
        if (value.indexOf("insufficient") !== -1) return "insufficient";
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
        if (value === "INSUFFICIENT_DATA" || value === "NOT_ASSESSED") return "status-insufficient";
        return "";
    }

    function isLiveStatus(status) {
        var value = String(status || "").toLowerCase();
        return value === "live" || value === "up" || value === "online" || value === "active" || value === "reachable";
    }

    function isInsufficientFinding(finding) {
        var status = String((finding && finding.status) || "").toUpperCase();
        var risk = String((finding && finding.risk) || "").toUpperCase();
        return status === "INSUFFICIENT_DATA" || status === "NOT_ASSESSED" || risk.indexOf("INSUFFICIENT") !== -1;
    }

    function isPriorityFinding(finding) {
        if (isInsufficientFinding(finding)) return false;
        var key = riskKey(finding && finding.risk);
        return key === "critical" || key === "high";
    }

    function stripMd(value) {
        return textOf(value)
            .replace(/\*\*/g, "")
            .replace(/`/g, "")
            .replace(/^\s*[-*]\s+/, "")
            .replace(/\s+/g, " ")
            .trim();
    }

    function parseKvLine(line) {
        var match = /^\s*[-*]?\s*\*?\*?([^:*]+)\*?\*?\s*:\s*(.+)$/.exec(line);
        if (!match) return null;
        return { key: stripMd(match[1]).toLowerCase(), value: stripMd(match[2]) };
    }

    function headingText(line) {
        return stripMd(String(line || "").replace(/^#{1,6}\s+/, "").replace(/^\d+\.\s+/, ""));
    }

    function parseFirewallLine(line) {
        var text = stripMd(line);
        var labeled = /name\s*[:=]\s*([A-Za-z0-9._-]+).*?vendor\s*[:=]\s*([^|]+).*?ip\s*[:=]\s*([^|]+).*?status\s*[:=]\s*([A-Za-z]+)/i.exec(text);
        if (labeled) {
            return {
                name: stripMd(labeled[1]),
                vendor: stripMd(labeled[2]),
                ip: stripMd(labeled[3]),
                status: stripMd(labeled[4]).toLowerCase()
            };
        }
        var named = /([A-Za-z0-9._-]+)\s*\|\s*([^|]+)\s*\|\s*([^|]+)\s*\|\s*(live|down|up|online|active|reachable)/i.exec(text);
        if (named) {
            return {
                name: stripMd(named[1]),
                vendor: stripMd(named[2]),
                ip: stripMd(named[3]),
                status: stripMd(named[4]).toLowerCase()
            };
        }
        var simple = /^(ALL|vmpafw\d+)$/i.exec(text);
        if (simple) return { name: simple[1], status: "live" };
        return null;
    }

    function parseMarkdownSelection(text) {
        var lines = String(text || "").split(/\r?\n/);
        var firewalls = [];
        var seen = {};
        lines.forEach(function (line) {
            if (!/^\s*[-*]/.test(line) && line.indexOf("|") === -1) return;
            var fw = parseFirewallLine(line.replace(/^\s*[-*]\s*/, ""));
            if (!fw || !fw.name || seen[fw.name]) return;
            seen[fw.name] = true;
            firewalls.push(fw);
        });
        var looksLikeSelect = /which firewall|select (a |the )?firewall|awaiting_firewall_selection|options:/i.test(text);
        if (!looksLikeSelect && firewalls.length < 2) return null;
        if (!firewalls.length) return null;
        return {
            response_type: "firewall_selection",
            status: "AWAITING_FIREWALL_SELECTION",
            action_required: "select_firewall",
            prompt: "Which firewall should I assess this time?",
            firewalls: firewalls
        };
    }

    function applyFindingField(finding, key, value) {
        if (!value) return;
        if (key.indexOf("evidence") !== -1) finding.evidence = value;
        else if (key.indexOf("observed") !== -1) finding.observed = value;
        else if (key.indexOf("gap") !== -1 || key === "identified gap") finding.finding = value;
        else if (key.indexOf("impact") !== -1) finding.business_impact = value;
        else if (key.indexOf("recommend") !== -1 || key === "action") finding.remediation = value;
        else if (key === "status") finding.status = value.replace(/\s+/g, "_").toUpperCase();
        else if (key === "risk" || key === "severity") finding.risk = value.toUpperCase();
    }

    function parseFindingBlock(title, body) {
        var heading = headingText(title);
        var idMatch = /(PA-\d+)/i.exec(heading);
        if (!idMatch) return null;
        var finding = {
            control: idMatch[1].toUpperCase(),
            metric: stripMd(heading.replace(idMatch[0], "").replace(/^[|\-–—:\s]+/, "")),
            status: "",
            risk: "",
            observed: "",
            finding: "",
            business_impact: "",
            remediation: "",
            evidence: ""
        };
        var statusMatch = /\b(NON[_\s-]?COMPLIANT|COMPLIANT|INSUFFICIENT[_\s-]?DATA|NOT[_\s-]?ASSESSED|GAP[_\s-]?IDENTIFIED)\b/i.exec(heading + "\n" + body);
        if (statusMatch) finding.status = statusMatch[1].replace(/[\s-]+/g, "_").toUpperCase();
        var riskMatch = /\b(CRITICAL|HIGH|MEDIUM|LOW)\b/i.exec(heading);
        if (!riskMatch) riskMatch = /\b(CRITICAL|HIGH|MEDIUM|LOW)\b/i.exec(body);
        if (riskMatch) finding.risk = riskMatch[1].toUpperCase();
        String(body || "").split(/\r?\n/).forEach(function (line) {
            var kv = parseKvLine(line);
            if (kv) applyFindingField(finding, kv.key, kv.value);
        });
        if (!finding.metric) finding.metric = finding.control;
        return finding;
    }

    function parseMarkdownAssessment(text) {
        var raw = String(text || "");
        if (!/(overall posture|device information|key findings|priority recommendations|PA-\d+)/i.test(raw)) return null;
        var chunks = raw.split(/\n(?=#{1,3}\s+)/);
        if (chunks.length < 2) {
            chunks = raw.split(/\n(?=(?:#{1,3}\s+)?(?:\d+\.\s+)?(?:Device Information|Overall Posture|Key Findings|Insufficient Data|Priority Recommendations|Assessment Notice|PA-\d+)\b)/i);
        }
        var device = {};
        var summary = {};
        var findings = [];
        var recs = [];
        var notice = "";
        var postureLabel = "";
        chunks.forEach(function (chunk) {
            var lines = chunk.split(/\r?\n/);
            var title = headingText(lines[0] || "");
            var body = lines.slice(1).join("\n");
            var lower = title.toLowerCase();
            if (/device information|inventory|firewall identity/.test(lower)) {
                body.split(/\r?\n/).forEach(function (line) {
                    var kv = parseKvLine(line);
                    if (!kv) return;
                    if (/name|hostname|firewall/.test(kv.key)) device.name = kv.value.replace(/\s*\(.*$/, "");
                    else if (kv.key === "vendor") device.vendor = kv.value;
                    else if (kv.key === "model") device.model = kv.value;
                    else if (/version|pan-os/.test(kv.key)) device.version = kv.value;
                    else if (kv.key === "ip") device.ip = kv.value;
                    else if (kv.key === "status") device.status = kv.value;
                    else if (kv.key === "serial") device.serial = kv.value;
                    else if (kv.key === "uptime") device.uptime = kv.value;
                    else if (kv.key === "scope") device.scope = kv.value;
                });
            } else if (/overall posture|compliance status|assessment overview/.test(lower)) {
                body.split(/\r?\n/).forEach(function (line) {
                    var kv = parseKvLine(line);
                    var plain = stripMd(line);
                    if (kv) {
                        if (/compliance/.test(kv.key)) summary.compliance_pct = parseFloat(kv.value);
                        else if (/total control|controls assessed|controls/.test(kv.key)) summary.total_controls = parseInt(kv.value, 10);
                        else if (/non-compliant|non compliant/.test(kv.key)) summary.non_compliant = parseInt(kv.value, 10);
                        else if (/compliant/.test(kv.key)) summary.compliant = parseInt(kv.value, 10);
                        else if (/insufficient|not assessed/.test(kv.key)) summary.not_assessed = parseInt(kv.value, 10);
                        else if (/overall risk|risk rating|posture/.test(kv.key)) postureLabel = kv.value;
                    }
                    var riskWord = /\b(CRITICAL|HIGH|MEDIUM|LOW)\b/i.exec(plain);
                    if (/overall risk|overall posture|risk rating/i.test(plain) && riskWord) postureLabel = riskWord[1];
                });
            } else if (/insufficient/.test(lower)) {
                var insuffFinding = parseFindingBlock(title, body);
                if (insuffFinding) {
                    insuffFinding.status = insuffFinding.status || "INSUFFICIENT_DATA";
                    findings.push(insuffFinding);
                } else if (body.trim()) {
                    findings.push({
                        control: "DATA",
                        metric: title || "Insufficient Data",
                        status: "INSUFFICIENT_DATA",
                        risk: "INSUFFICIENT",
                        finding: stripMd(body).slice(0, 400)
                    });
                }
            } else if (/recommend/.test(lower)) {
                body.split(/\r?\n/).forEach(function (line) {
                    if (/^\s*(\d+\.|[-*])\s+/.test(line)) recs.push(stripMd(line.replace(/^\s*(\d+\.|[-*])\s+/, "")));
                });
            } else if (/notice|assessment note/.test(lower)) {
                notice = stripMd(body);
            } else {
                var finding = parseFindingBlock(title, body);
                if (finding) findings.push(finding);
            }
        });
        if (!findings.length && !summary.total_controls && !device.name) return null;
        return {
            response_type: "firewall_assessment",
            device_information: device,
            overall_posture: {
                label: postureLabel,
                compliance_pct: summary.compliance_pct,
                total_controls: summary.total_controls,
                compliant: summary.compliant,
                non_compliant: summary.non_compliant,
                not_assessed: summary.not_assessed
            },
            summary: summary,
            findings: findings,
            recommendations: recs,
            notice: notice
        };
    }

    function parseMarkdownAudit(text) {
        if (!text || typeof text !== "string") return null;
        var trimmed = text.trim();
        if (!trimmed) return null;
        if (/firewall down or stopped/i.test(trimmed) && trimmed.length < 80) {
            return { response_type: "firewall_down", message: "firewall down or stopped" };
        }
        return parseMarkdownSelection(trimmed) || parseMarkdownAssessment(trimmed);
    }

    function deviceFrom(payload) {
        var device = payload.device_information || payload.device || {};
        var inventory = payload.inventory || {};
        var selected = payload._selected_firewall || payload.selected_firewall || {};
        return {
            name: textOf(device.name || selected.name || inventory.hostname || payload._firewall_id),
            hostname: textOf(device.hostname || inventory.hostname),
            vendor: textOf(device.vendor || inventory.vendor || selected.vendor),
            model: textOf(device.model || inventory.model || selected.model),
            version: textOf(device.version || inventory.version || inventory.pan_os_version || selected.pan_os_version),
            ip: textOf(device.ip || selected.management_ip || inventory.ip || inventory.management_ip),
            status: textOf(device.status || selected.status),
            serial: textOf(device.serial || inventory.serial || inventory.serial_number),
            uptime: textOf(device.uptime || inventory.uptime),
            scope: textOf(device.scope || payload.scope)
        };
    }

    function postureFrom(payload) {
        var posture = payload.overall_posture || {};
        var summary = payload.summary || {};
        var findings = asList(payload.findings);
        var pct = posture.compliance_pct;
        if (pct == null) pct = summary.compliance_pct;
        var total = posture.total_controls != null ? posture.total_controls : summary.total_controls;
        var compliant = posture.compliant != null ? posture.compliant : summary.compliant;
        var nonCompliant = posture.non_compliant != null ? posture.non_compliant : summary.non_compliant;
        var notAssessed = posture.not_assessed != null ? posture.not_assessed : summary.not_assessed;
        if (total == null) total = findings.length;
        if (compliant == null) compliant = 0;
        if (nonCompliant == null) {
            nonCompliant = findings.filter(function (item) {
                return String(item.status || "").toUpperCase() === "NON_COMPLIANT";
            }).length;
        }
        if (notAssessed == null) {
            notAssessed = findings.filter(isInsufficientFinding).length;
        }
        if (pct == null && total) pct = Math.round((Number(compliant) / Number(total)) * 1000) / 10;
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
            total_controls: Number(total) || 0,
            compliant: Number(compliant) || 0,
            non_compliant: Number(nonCompliant) || 0,
            not_assessed: Number(notAssessed) || 0,
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
        return unique(recs.filter(Boolean));
    }

    function findingsFrom(payload) {
        var findings = asList(payload.findings);
        if (!findings.length) findings = asList(payload.top_findings);
        return findings;
    }

    function overallRisk(posture) {
        if (posture.label) {
            var cleaned = posture.label.replace(/_/g, " ").replace(/\b\w/g, function (ch) {
                return ch.toUpperCase();
            });
            if (/critical|high|medium|low/i.test(cleaned)) return cleaned.replace(/risk/ig, "").trim();
            return cleaned;
        }
        if (posture.severity.critical) return "CRITICAL";
        if (posture.severity.high) return "HIGH";
        if (posture.severity.medium) return "MEDIUM";
        if (posture.severity.low) return "LOW";
        return "UNKNOWN";
    }

    function agentHeader() {
        return '<div class="audit-card audit-hero"><div class="audit-header"><div>' +
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
        if (html.indexOf("ws-mcq-card") !== -1 || html.indexOf("ws-tool-card") !== -1 || html.indexOf("fw-picker-card") !== -1) return html;
        if (typeof document !== "undefined") {
            var scratch = document.createElement("div");
            scratch.innerHTML = html;
            var parsed = parseBeforeDisplay(scratch.innerText || scratch.textContent || "", null);
            if (parsed && parsed.html) return parsed.html;
        }
        return wrap('<div class="audit-card audit-fallback">' + html + "</div>");
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

    function sectionCard(title, inner, options) {
        options = options || {};
        if (!inner) return "";
        var open = options.open ? " open" : "";
        var count = options.count != null ? '<span class="audit-section-count">' + escapeHtml(String(options.count)) + "</span>" : "";
        return '<details class="audit-section"' + open + ">" +
            '<summary class="audit-section-head"><span class="audit-section-title">' + escapeHtml(title) +
            "</span>" + count + '<span class="audit-section-chevron" aria-hidden="true"></span></summary>' +
            '<div class="audit-section-body">' + inner + "</div></details>";
    }

    function FindingCard(finding) {
        finding = finding || {};
        var risk = textOf(finding.risk);
        var status = textOf(finding.status);
        var title = textOf(finding.metric || finding.control);
        var control = textOf(finding.control);
        var evidence = textOf(finding.evidence);
        if (!evidence && (finding.observed || finding.expected)) {
            evidence = [finding.observed ? "Observed: " + finding.observed : "", finding.expected ? "Expected: " + finding.expected : ""]
                .filter(Boolean)
                .join(" | ");
        }
        var html = '<details class="audit-finding ' + riskClass(risk) + (isInsufficientFinding(finding) ? " risk-insufficient" : "") + '">';
        html += '<summary class="audit-finding-summary">';
        html += '<div class="audit-finding-lead">';
        if (control) html += '<span class="finding-id">' + escapeHtml(control) + "</span>";
        if (title) html += '<span class="finding-title">' + escapeHtml(title) + "</span>";
        html += '</div><div class="badge-group">';
        html += badge(status, statusClass(status));
        html += badge(risk, riskClass(risk) || (isInsufficientFinding(finding) ? "risk-insufficient" : ""));
        html += "</div></summary>";
        var details = detailCell("Evidence", evidence) +
            detailCell("Observed Finding", finding.observed) +
            detailCell("Identified Gap", finding.finding) +
            detailCell("Business Impact", finding.business_impact || finding.impact) +
            detailCell("Recommendation", finding.remediation);
        html += '<div class="audit-finding-body">';
        html += details ? '<div class="details-grid">' + details + "</div>" : '<div class="muted">No additional evidence in this finding.</div>';
        html += "</div></details>";
        return html;
    }

    function FindingDetailCard(finding) {
        return FindingCard(finding || {});
    }

    function metricCard(label, value, extraClass) {
        return '<div class="audit-metric ' + (extraClass || "") + '"><div class="audit-metric-label">' +
            escapeHtml(label) + '</div><div class="audit-metric-value">' + escapeHtml(value == null ? "—" : String(value)) +
            "</div></div>";
    }

    function deviceRows(device) {
        var rows = [
            ["Firewall", device.name],
            ["Hostname", device.hostname && device.hostname !== device.name ? device.hostname : ""],
            ["Vendor", device.vendor],
            ["Model", device.model],
            ["Version", device.version],
            ["IP", device.ip],
            ["Status", device.status],
            ["Serial", device.serial],
            ["Uptime", device.uptime],
            ["Scope", device.scope]
        ];
        var html = '<div class="audit-kv">';
        var count = 0;
        rows.forEach(function (row) {
            if (!textOf(row[1])) return;
            count += 1;
            html += '<div class="audit-kv-row"><span>' + escapeHtml(row[0]) + "</span><strong>" + escapeHtml(row[1]) + "</strong></div>";
        });
        return count ? html + "</div>" : "";
    }

    function AssessmentSummaryCard(payload) {
        var device = deviceFrom(payload);
        var posture = postureFrom(payload);
        var risk = overallRisk(posture);
        var html = "";
        if (device.name) {
            html += '<div class="audit-fw-banner"><span class="audit-fw-banner-name">' + escapeHtml(device.name) + "</span>";
            var meta = [device.vendor, device.model, device.version].filter(Boolean).join(" · ");
            if (meta) html += '<span class="muted">' + escapeHtml(meta) + "</span>";
            html += "</div>";
        }
        html += '<div class="posture-grid">';
        html += metricCard("Compliance Score", posture.compliance_pct == null ? "—" : String(posture.compliance_pct) + "%", "is-score");
        html += metricCard("Overall Risk", risk, "is-risk " + riskClass(risk));
        html += metricCard("Controls", posture.total_controls, "is-controls");
        html += metricCard("Compliant", posture.compliant, "is-ok");
        html += metricCard("Non-Compliant", posture.non_compliant, "is-bad");
        html += metricCard("Insufficient Data", posture.not_assessed, "is-muted");
        html += "</div>";
        return html;
    }

    function ExecutiveSummaryCard(payload) {
        return assessmentCard(payload).html;
    }

    function recommendationList(recs) {
        if (!recs.length) return "";
        var html = '<ol class="recommendations">';
        recs.forEach(function (rec) { html += "<li>" + escapeHtml(rec) + "</li>"; });
        return html + "</ol>";
    }

    function assessmentCard(payload) {
        var findings = findingsFrom(payload);
        var recs = recommendationsFrom(payload);
        var device = deviceFrom(payload);
        var priority = [];
        var secondary = [];
        var insufficient = [];
        findings.forEach(function (finding) {
            if (isInsufficientFinding(finding)) insufficient.push(finding);
            else if (isPriorityFinding(finding)) priority.push(finding);
            else secondary.push(finding);
        });
        var html = "";
        html += sectionCard("Device Information", deviceRows(device), { open: false });
        html += sectionCard("Overall Posture", AssessmentSummaryCard(payload), { open: true });
        var findingHtml = "";
        if (priority.length) {
            priority.forEach(function (finding) { findingHtml += FindingCard(finding); });
        } else if (!secondary.length && !insufficient.length) {
            findingHtml = '<div class="muted">No key findings in this assessment.</div>';
        }
        if (secondary.length) {
            var more = "";
            secondary.forEach(function (finding) { more += FindingCard(finding); });
            findingHtml += sectionCard("Medium / Low findings", more, { open: false, count: secondary.length });
        }
        html += sectionCard("Key Findings", findingHtml, { open: true, count: priority.length || findings.length });
        if (insufficient.length) {
            var insuffHtml = "";
            insufficient.forEach(function (finding) { insuffHtml += FindingCard(finding); });
            html += sectionCard("Insufficient Data", insuffHtml, { open: false, count: insufficient.length });
        }
        var priorityRecs = recs.slice(0, 5);
        var extraRecs = recs.slice(5);
        html += sectionCard("Priority Recommendations", recommendationList(priorityRecs), { open: true, count: priorityRecs.length || undefined });
        if (extraRecs.length) {
            html += sectionCard("Technical recommendations", recommendationList(extraRecs), { open: false, count: extraRecs.length });
        }
        var notice = textOf(payload.notice || payload.assessment_notice || payload.business_impact);
        if (notice) html += sectionCard("Assessment Notice", '<div class="notice">' + escapeHtml(notice) + "</div>", { open: false });
        return { html: wrap(html), findings: findings };
    }

    function selectionOptionHtml(fw) {
        var name = textOf(fw.name || fw.hostname || fw.device_name);
        var vendor = textOf(fw.vendor);
        var ip = textOf(fw.ip || fw.management_ip || fw.host_ip);
        var status = textOf(fw.status) || "live";
        var live = isLiveStatus(status);
        var html = '<button type="button" class="ws-fw-select-option' + (live ? "" : " is-down") + '" data-fw-select="' +
            escapeHtml(name) + '" data-fw-status="' + escapeHtml(status) + '">';
        html += '<span class="ws-fw-select-name">' + escapeHtml(name) +
            ' <span class="fw-status ' + (live ? "is-live" : "is-down") + '">' +
            escapeHtml(live ? "Live" : "Down") + "</span></span>";
        var meta = [vendor, ip, live ? "live" : "down"].filter(Boolean).join(" \u00b7 ");
        if (meta) html += '<span class="ws-fw-select-meta">' + escapeHtml(meta) + "</span>";
        if (fw.description) html += '<span class="ws-fw-select-desc">' + escapeHtml(fw.description) + "</span>";
        html += "</button>";
        return html;
    }

    function selectionBody(payload, options) {
        options = options || {};
        var firewalls = asList(payload.firewalls);
        var title = options.title || "Select Firewall";
        var subtitle = options.subtitle || "Choose a live firewall or ALL. Name, vendor, IP, and live/down status are shown for every option.";
        var html = '<div class="ws-mcq-card ns-card fw-picker-card">';
        html += '<div class="ws-mcq-head"><strong>' + escapeHtml(title) + "</strong><span>" + escapeHtml(subtitle) + "</span></div>";
        if (payload.invalid_selection) {
            html += '<div class="ns-block"><p class="ns-note-text">Firewall ' +
                escapeHtml(payload.invalid_selection) + " was not found in inventory.</p></div>";
        }
        html += '<div class="ws-fw-select-list">';
        firewalls.forEach(function (fw) { html += selectionOptionHtml(fw); });
        html += "</div></div>";
        return html;
    }

    function selectionCard(payload) {
        return selectionBody(payload);
    }

    function downCard(payload) {
        var selected = payload.selected_firewall || {};
        var subtitle = textOf(payload.message) || "firewall down or stopped";
        if (selected.name) {
            subtitle = selected.name + (selected.status ? " is " + selected.status : "") + ". " + subtitle;
        }
        if (asList(payload.firewalls).length) {
            return selectionBody(payload, {
                title: "Firewall down or stopped",
                subtitle: subtitle
            });
        }
        return '<div class="ws-mcq-card ns-card">' +
            '<div class="ws-mcq-head"><strong>Firewall down or stopped</strong>' +
            "<span>" + escapeHtml(subtitle) + "</span></div></div>";
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
