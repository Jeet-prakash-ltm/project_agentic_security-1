(function () {
    "use strict";

    var root = document.getElementById("findingsRoot");
    var searchInput = document.getElementById("findingsSearch");
    var sortSelect = document.getElementById("sortSelect");
    var viewSelect = document.getElementById("viewSelect");
    var findingsApp = document.getElementById("findingsApp");
    var PAGE_VIEW = (findingsApp && findingsApp.getAttribute("data-view")) || "firewall_audit";
    var PAGE_DOMAIN = PAGE_VIEW === "zero_trust" ? "zero_trust" : "network_security";

    var PRESET_VIEWS = PAGE_DOMAIN === "zero_trust"
        ? [
            { id: "all", name: "All Findings", filters: { severity: "all", status: "all", domain: "zero_trust", assessment: "all", pillar: "all", category: "all", firewall: "all", riskRange: "all", date: "all", search: "", sort: "severity" } },
            { id: "critical", name: "Critical Only", filters: { severity: "critical", status: "all", domain: "zero_trust", assessment: "all", pillar: "all", category: "all", firewall: "all", riskRange: "all", date: "all", search: "", sort: "severity" } },
            { id: "high", name: "High Risk", filters: { severity: "high", status: "all", domain: "zero_trust", assessment: "all", pillar: "all", category: "all", firewall: "all", riskRange: "all", date: "all", search: "", sort: "risk" } },
            { id: "open", name: "Open Issues", filters: { severity: "all", status: "open", domain: "zero_trust", assessment: "all", pillar: "all", category: "all", firewall: "all", riskRange: "all", date: "all", search: "", sort: "risk" } }
        ]
        : [
            { id: "all", name: "All Findings", filters: { severity: "all", status: "all", domain: "network_security", assessment: "all", pillar: "all", category: "all", firewall: "all", riskRange: "all", date: "all", search: "", sort: "severity" } },
            { id: "critical", name: "Critical Only", filters: { severity: "critical", status: "all", domain: "network_security", assessment: "all", pillar: "all", category: "all", firewall: "all", riskRange: "all", date: "all", search: "", sort: "severity" } },
            { id: "high", name: "High Risk", filters: { severity: "high", status: "all", domain: "network_security", assessment: "all", pillar: "all", category: "all", firewall: "all", riskRange: "all", date: "all", search: "", sort: "risk" } },
            { id: "open", name: "Open Issues", filters: { severity: "all", status: "open", domain: "network_security", assessment: "all", pillar: "all", category: "all", firewall: "all", riskRange: "all", date: "all", search: "", sort: "risk" } }
        ];

    var STORAGE_FILTERS = "findings.filters." + PAGE_VIEW + ".v3";
    var STORAGE_VIEWS = "findings.views." + PAGE_VIEW + ".v3";
    var STORAGE_REVIEWED = "findings.reviewed.v1";
    var STORAGE_ASSIGNEES = "findings.assignees.v1";

    function defaultFilters() {
        return { severity: "all", status: "all", domain: PAGE_DOMAIN, assessment: "all", pillar: "all", category: "all", firewall: "all", riskRange: "all", date: "all", search: "", sort: "severity" };
    }

    function normalizePillarParam(value) {
        var raw = String(value || "all").trim();
        if (!raw || raw.toLowerCase() === "all") return "all";
        var key = raw.toLowerCase().replace(/[\s_-]+/g, "");
        if (key === "identity") return "Identity";
        if (key === "devices" || key === "endpointdevice" || key === "endpointdevices") return "Devices";
        if (key === "network") return "Network";
        if (key === "data") return "Data";
        if (key === "infrastructure") return "Infrastructure";
        return raw;
    }

    function normalizeRiskParam(value) {
        var raw = String(value || "all").trim().toLowerCase();
        if (!raw || raw === "all") return "all";
        if (raw === "critical" || raw === "high" || raw === "medium" || raw === "low") return raw;
        return "all";
    }

    var state = {
        data: null,
        records: [],
        facets: {},
        statusVocabulary: {},
        filters: defaultFilters(),
        customViews: [],
        reviewed: {},
        assignees: {},
        collapsed: {},
        inventory: [],
        loadedFirewall: null
    };

    function lockDomain() {
        state.filters.domain = PAGE_DOMAIN;
        if (PAGE_DOMAIN !== "zero_trust") state.filters.pillar = "all";
    }

    function escapeHtml(v) {
        var d = document.createElement("div");
        d.textContent = v == null ? "" : String(v);
        return d.innerHTML;
    }

    var SEVERITY_SCORE = { critical: 95, high: 72, medium: 45, low: 20 };

    function riskScore(rec) {
        if (rec._risk_score != null) return rec._risk_score;
        var sev = String(rec.risk || "").toLowerCase();
        return SEVERITY_SCORE[sev] != null ? SEVERITY_SCORE[sev] : 10;
    }

    function isOpenStatus(rec) {
        return rec.status === "not_compliant" || rec.status === "fail" || rec.status === "not_assessed" || rec.status === "investigation";
    }

    function enrich(row) {
        var severity = String(row.severity || "").toLowerCase();
        var risk = row.status === "compliant" || row.status === "pass"
            ? (severity ? severity.toUpperCase() : "LOW")
            : (severity ? severity.toUpperCase() : "LOW");
        var cid = String(row.control_id || row.control_name || row.id || "").toUpperCase();
        var e = (typeof FINDING_ENRICHMENT !== "undefined" && FINDING_ENRICHMENT[cid]) ? FINDING_ENRICHMENT[cid] : null;
        var detail = row.detail || row.finding || "";
        var category = row.category || (e && e.domain) || "Uncategorised";
        var score = riskScore({ _risk_score: row.risk_score, risk: risk });
        var group = row.pillar || (e && e.domain) || null;

        return {
            id: row.id,
            _assessment: row.assessment_id,
            control: row.control_id || row.control_name || row.id,
            metric: category,
            observed: row.observed,
            expected: row.expected,
            operator: "",
            status: row.status,
            status_label: row.status_label,
            risk: risk,
            _compliant: row.status === "compliant" || row.status === "pass",
            _domain: row.domain_label || row.domain || "",
            _domain_key: row.domain || "",
            _pillar: row.pillar || "",
            _group: group || "",
            _category: category,
            _check: row.title || (e && e.check) || row.control_name || ("Control " + cid),
            _method: (e && e.method) || "",
            _gap: detail || (e && e.gap) || "",
            _impact: (e && e.impact) || "",
            _risk_score: score,
            _evidence: (e && e.evidence) || [],
            _finding: detail,
            _remediation: row.remediation || (e && e.remediation) || "",
            _detected: row.completed_at ? String(row.completed_at).slice(0, 10) : "\u2014",
            _collected_at: row.completed_at,
            _run_id: row.assessment_id,
            _firewall: row.firewall_id || "\u2014",
            _model: "",
            _version: "",
            _ms: row.ms_details || null
        };
    }

    var SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

    // ============================================================
    // FORMATTING HELPERS
    // ============================================================

    function formatVal(v) {
        if (typeof v === "boolean") return v ? "Enabled" : "Disabled";
        if (Array.isArray(v)) return v.join(", ");
        if (v === null || v === undefined) return "\u2014";
        return String(v);
    }

    function formatExpected(v, op) {
        if (op === "not_empty") return "Not Empty";
        if (op === "supported_version") return Array.isArray(v) ? "in (" + v.join(", ") + ")" : "in (" + String(v) + ")";
        return formatVal(v);
    }

    function isNumeric(v) {
        return typeof v === "number" || (v != null && v !== "" && !isNaN(parseFloat(v)) && isFinite(v));
    }

    function toNumber(v) {
        if (typeof v === "number") return v;
        if (isNumeric(v)) return parseFloat(v);
        return null;
    }

    var OPERATOR_SYMBOLS = {
        "==": "=", "!=": "\u2260", "<": "<", "<=": "\u2264", ">": ">", ">=": "\u2265",
        "supported_version": "\u2208", "not_empty": "\u2260"
    };

    var ICONS = {
        rem: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
        impact: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg>',
        evidence: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 21l-4.3-4.3"/><circle cx="11" cy="11" r="7"/></svg>',
        verify: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 12l2 2 4-4"/><circle cx="12" cy="12" r="9"/></svg>',
        chevron: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>',
        spark: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l1.9 4.6 4.6 1.9-4.6 1.9L12 16l-1.9-4.6L5.5 9.5l4.6-1.9L12 3z"/></svg>'
    };

    // ============================================================
    // SORTING & FILTERING
    // ============================================================

    function sortRecords(records) {
        var sort = state.filters.sort;
        var copy = records.slice();
        copy.sort(function (a, b) {
            if (sort === "severity") {
                return (SEV_ORDER[a.risk] != null ? SEV_ORDER[a.risk] : 9) - (SEV_ORDER[b.risk] != null ? SEV_ORDER[b.risk] : 9)
                    || (a.control || "").localeCompare(b.control || "");
            }
            if (sort === "risk" || sort === "riskAsc") {
                var d = a._risk_score - b._risk_score || (a.control || "").localeCompare(b.control || "");
                return sort === "riskAsc" ? d : -d;
            }
            if (sort === "recent" || sort === "oldest") {
                var at = a._detected || "", bt = b._detected || "";
                var cmp = at < bt ? -1 : at > bt ? 1 : 0;
                return sort === "recent" ? -cmp : cmp;
            }
            if (sort === "domain") {
                return (a._category || "").localeCompare(b._category || "") || (a._domain || "").localeCompare(b._domain || "") || (a.control || "").localeCompare(b.control || "");
            }
            if (sort === "firewall") {
                return (a._firewall || "").localeCompare(b._firewall || "") || (SEV_ORDER[a.risk] || 9) - (SEV_ORDER[b.risk] || 9);
            }
            return 0;
        });
        return copy;
    }

    function matchesFilters(rec) {
        var f = state.filters;
        var risk = String(rec.risk || "").toLowerCase();
        if (f.severity !== "all" && risk !== f.severity) return false;
        if (f.status !== "all") {
            if (f.status === "open") {
                if (!isOpenStatus(rec)) return false;
            } else if (rec.status !== f.status) {
                return false;
            }
        }
        if (rec._domain_key && rec._domain_key !== PAGE_DOMAIN) return false;
        if (f.domain !== "all" && rec._domain_key !== f.domain) return false;
        if (f.assessment !== "all" && rec._assessment !== f.assessment) return false;
        if (f.pillar !== "all" && (rec._pillar || "") !== f.pillar) return false;
        if (f.category !== "all" && rec._category !== f.category) return false;
        if (f.firewall !== "all" && rec._firewall !== f.firewall) return false;
        if (f.date !== "all" && rec._detected !== f.date) return false;
        if (f.riskRange !== "all") {
            var s = rec._risk_score || 0;
            if (f.riskRange === "critical" && s < 90) return false;
            if (f.riskRange === "high" && (s < 70 || s >= 90)) return false;
            if (f.riskRange === "medium" && (s < 40 || s >= 70)) return false;
            if (f.riskRange === "low" && s >= 40) return false;
        }
        if (f.search) {
            var q = f.search.toLowerCase();
            var hay = [rec.control, rec._check, rec._finding, rec._gap, rec._impact, rec._domain, rec._pillar, rec._category, rec._firewall, rec.metric, rec._remediation, (rec._evidence || []).join(" ")].join(" ").toLowerCase();
            var terms = q.split(/\s+/);
            for (var i = 0; i < terms.length; i++) {
                if (hay.indexOf(terms[i]) === -1) return false;
            }
        }
        return true;
    }

    function getVisible() {
        return sortRecords(state.records.filter(matchesFilters));
    }

    // ============================================================
    // RISK CONTEXT
    // ============================================================

    function riskContext(rec) {
        var score = rec._risk_score || 0;
        var sev = (rec.risk || "LOW").toUpperCase();
        var impact = sev === "CRITICAL" ? "Severe \u2014 potential full network compromise"
            : sev === "HIGH" ? "Major \u2014 significant exposure or outage"
            : sev === "MEDIUM" ? "Moderate \u2014 limited exposure"
            : sev === "COMPLIANT" ? "None \u2014 control is compliant" : "Minor \u2014 low exposure";
        var likelihood = score >= 80 ? "High" : score >= 55 ? "Moderate" : score >= 40 ? "Low" : "Minimal";
        var exploit = score >= 85 ? "High \u2014 active exploitation likely" : score >= 60 ? "Moderate \u2014 requires specific conditions" : score >= 40 ? "Low" : "Minimal";
        var trend = score >= 85 ? "Worsening" : score >= 60 ? "Elevated" : score >= 40 ? "Stable" : "Contained";
        return { impact: impact, likelihood: likelihood, exploit: exploit, trend: trend };
    }

    function riskContextHtml(rec) {
        var rc = riskContext(rec);
        return '<div class="finding-section"><div class="finding-section-title">' + ICONS.impact + ' Risk Context</div>' +
            '<div class="risk-context-grid">' +
            '<div class="rc-item"><span class="rc-label">Business Impact</span><span class="rc-value">' + escapeHtml(rc.impact) + '</span></div>' +
            '<div class="rc-item"><span class="rc-label">Likelihood</span><span class="rc-value">' + escapeHtml(rc.likelihood) + '</span></div>' +
            '<div class="rc-item"><span class="rc-label">Exploitability</span><span class="rc-value">' + escapeHtml(rc.exploit) + '</span></div>' +
            '<div class="rc-item"><span class="rc-label">Risk Trend</span><span class="rc-value">' + escapeHtml(rc.trend) + '</span></div>' +
            '</div></div>';
    }

    // ============================================================
    // METRIC VISUALIZATION
    // ============================================================

    function isComparisonOp(op) { return op === "<" || op === "<=" || op === ">" || op === ">="; }

    function compareBlockHtml(rec, compliant) {
        var opSym = OPERATOR_SYMBOLS[rec.operator] || "";
        var hasValue = rec.observed != null || rec.expected != null;
        if (!hasValue) return "";
        return '<div class="cmp-values">' +
            '<div class="cmp-block cmp-observed"><span class="cmp-block-label">Observed</span><span class="cmp-block-val">' + escapeHtml(formatVal(rec.observed)) + '</span></div>' +
            (rec.operator ? '<div class="cmp-op"><span class="cmp-op-sym">' + escapeHtml(opSym) + '</span><span class="cmp-op-label">' + escapeHtml(rec.operator || "") + '</span></div>' : '<div class="cmp-op"><span class="cmp-op-sym">\u2192</span><span class="cmp-op-label">expected</span></div>') +
            '<div class="cmp-block cmp-expected"><span class="cmp-block-label">Expected</span><span class="cmp-block-val">' + escapeHtml(formatExpected(rec.expected, rec.operator)) + '</span></div>' +
            '</div>';
    }

    function metricHtml(rec) {
        if (rec._compliant || !isComparisonOp(rec.operator)) return "";
        var obsN = toNumber(rec.observed);
        var expN = toNumber(rec.expected);
        if (obsN === null || expN === null || expN === 0) return "";

        var lowerBetter = rec.operator === "<" || rec.operator === "<=";
        var compliant = lowerBetter ? obsN <= expN : obsN >= expN;
        var max = Math.max(obsN, expN) * 1.15 || 1;
        var obsPct = Math.min(100, (obsN / max) * 100);
        var expPct = Math.min(100, (expN / max) * 100);
        var variance = ((obsN - expN) / expN) * 100;
        var varianceText = (variance >= 0 ? "+" : "") + Math.round(variance * 10) / 10 + "%";
        var statusLabel = compliant ? "Within threshold" : (lowerBetter ? "Over threshold" : "Below threshold");
        var statusCls = compliant ? "ok" : "bad";
        var sevCls = (rec.risk || "low").toLowerCase();

        return '<div class="finding-section"><div class="finding-section-title">' + ICONS.evidence + ' Observed vs Threshold</div>' +
            '<div class="metric-gauge">' +
            '<div class="metric-gauge-head">' +
            '<span class="metric-gauge-metric">' + escapeHtml(rec.metric || "Metric") + '</span>' +
            '<span class="metric-gauge-status ' + statusCls + '">' + statusLabel + '</span>' +
            '</div>' +
            '<div class="metric-gauge-track">' +
            '<div class="metric-gauge-fill ' + sevCls + '" style="width:' + obsPct + '%"></div>' +
            '<div class="metric-gauge-threshold" style="left:' + expPct + '%"></div>' +
            '</div>' +
            '<div class="metric-gauge-labels">' +
            '<span>Observed <strong>' + escapeHtml(formatVal(rec.observed)) + '</strong></span>' +
            '<span>Threshold <strong>' + escapeHtml(OPERATOR_SYMBOLS[rec.operator] || "") + ' ' + escapeHtml(formatVal(rec.expected)) + '</strong></span>' +
            '<span class="metric-gauge-variance ' + (compliant ? "ok" : "bad") + '">' + varianceText + '</span>' +
            '</div>' +
            '</div></div>';
    }

    // ============================================================
    // EVIDENCE
    // ============================================================

    function evidenceHtml(rec) {
        var srcs = rec._evidence || [];
        var srcChips = srcs.map(function (s) {
            return '<span class="evidence-src">' + escapeHtml(s) + '</span>';
        }).join("");

        return '<div class="finding-section"><div class="finding-section-title">' + ICONS.evidence + ' Technical Evidence</div>' +
            '<div class="evidence-item">' +
            '<div class="evidence-row">' +
            '<span class="evidence-obs">' + escapeHtml(formatVal(rec.observed)) + '</span>' +
            '<span class="evidence-arrow">\u2192 expected</span>' +
            '<span class="evidence-exp">' + escapeHtml(formatExpected(rec.expected, rec.operator)) + '</span>' +
            '</div>' +
            '<div class="evidence-meta">' +
            '<span><span class="em-label">Category</span> ' + escapeHtml(formatCategory(rec._category)) + '</span>' +
            '<span><span class="em-label">Source</span> ' + escapeHtml(srcs.length ? srcs[0] : "Assessment collector") + '</span>' +
            '<span><span class="em-label">Device</span> ' + escapeHtml(rec._firewall) + (rec._model ? " \u00b7 " + escapeHtml(rec._model) : "") + '</span>' +
            '<span><span class="em-label">Collected</span> ' + escapeHtml(formatTs(rec._collected_at || rec._detected)) + '</span>' +
            '<span><span class="em-label">Run</span> ' + escapeHtml(rec._run_id || "\u2014") + '</span>' +
            '</div>' +
            (srcChips ? '<div class="evidence-sources">' + srcChips + '</div>' : '') +
            '<button class="action-btn evidence-drill" type="button" data-act="evidence" data-assessment="' + escapeHtml(rec._assessment || "") + '" data-pillar="' + escapeHtml(rec._pillar || "") + '">' +
            ICONS.evidence + ' Open collected evidence</button>' +
            '</div></div>';
    }

    // ============================================================
    // FINDING CARD
    // ============================================================

    function findingBodyHtml(rec) {
        var html = "";

        if (!rec._compliant) {
            html += '<div class="finding-section">' +
                '<div class="finding-section-title">' + ICONS.impact + ' Issue Summary</div>' +
                '<p>' + escapeHtml(rec._gap || rec._finding || "Finding requires attention.") + '</p>' +
                compareBlockHtml(rec, false) +
                '</div>';

            if (rec._impact) {
                html += '<div class="finding-section"><div class="finding-section-title">' + ICONS.impact + ' Why It Matters</div><p>' + escapeHtml(rec._impact) + '</p></div>';
            }
            if (rec._remediation) {
                html += '<div class="finding-section"><div class="remediation-callout"><div class="finding-section-title">' + ICONS.rem + ' Recommended Fix</div><p>' + escapeHtml(rec._remediation) + '</p></div></div>';
            }
        } else {
            html += '<div class="finding-section">' +
                '<div class="finding-section-title">' + ICONS.verify + ' Compliance Check</div>' +
                '<p>Observed value meets the expected baseline.</p>' +
                compareBlockHtml(rec, true) +
                '</div>';
        }

        html += metricHtml(rec);
        html += evidenceHtml(rec);
        html += riskContextHtml(rec);

        if (rec._method) {
            html += '<div class="finding-section"><div class="verification-box"><div class="finding-section-title">' + ICONS.verify + ' Verification Method</div><p>' + escapeHtml(rec._method) + '</p></div></div>';
        }
        return html;
    }

    function actionsHtml(rec, isReviewed, isAssigned) {
        var assignee = state.assignees[recKey(rec)];
        return '<div class="finding-actions">' +
            '<button class="action-btn ai" data-act="copilot" type="button">' + ICONS.spark + ' Copilot</button>' +
            '<button class="action-btn" data-act="device" type="button">View Firewall</button>' +
            '<button class="action-btn" data-act="assign" type="button">' + (assignee ? 'Reassign' : 'Assign Owner') + '</button>' +
            '<button class="action-btn" data-act="export" type="button">Export</button>' +
            '<button class="action-btn" data-act="share" type="button">Share</button>' +
            '<button class="action-btn" data-act="report" type="button">Create Report</button>' +
            '<button class="action-btn ' + (isReviewed ? 'is-reviewed' : '') + '" data-act="review" type="button">' + (isReviewed ? 'Reviewed' : 'Mark Reviewed') + '</button>' +
            '</div>';
    }

    function findingCardHtml(rec) {
        var sev = (rec.risk || "low").toLowerCase();
        var cid = escapeHtml(rec.control);
        var title = escapeHtml(rec._check || "Untitled");
        var domain = escapeHtml(rec._domain);
        var score = rec._risk_score || 0;
        var detected = escapeHtml(rec._detected || "\u2014");
        var fw = escapeHtml(rec._firewall);
        var statusKey = rec.status_label || rec.status;
        var statusClass = rec._compliant ? "compliant" : "non-compliant";
        var isReviewed = !!state.reviewed[recKey(rec)];
        var assignee = state.assignees[recKey(rec)];

        var summary = rec._compliant
            ? "Observed value '" + formatVal(rec.observed) + "' meets the expected baseline."
            : (rec._gap || rec._finding || "Finding requires attention.");

        return '<div class="finding-card" data-control="' + cid + '" data-fw="' + fw + '" role="button" tabindex="0" aria-expanded="false">' +
            '<span class="finding-card-accent ' + sev + '"></span>' +
            '<div class="finding-card-inner">' +
            '<div class="finding-card-head">' +
            '<div class="finding-card-top">' +
            '<span class="finding-card-id">' + cid + '</span>' +
            '<span class="sev-badge sev-' + sev + '">' + escapeHtml(rec.risk) + '</span>' +
            '<span class="risk-score" title="Risk score"><span class="risk-score-meter"><span class="risk-score-fill ' + sev + '" style="width:' + score + '%"></span></span><span class="risk-score-num">' + score + '</span></span>' +
            '<span class="status-badge ' + statusClass + '">' + escapeHtml(statusKey) + '</span>' +
            (PAGE_DOMAIN === "zero_trust"
                ? '<span class="finding-card-actions">' +
                    '<button class="action-btn ai" data-act="copilot" type="button">' + ICONS.spark + ' Copilot</button>' +
                    '<button class="action-btn" data-act="export" type="button">Export</button>' +
                    '</span>'
                : '') +
            '</div>' +
            '<div class="finding-card-title">' + title + '</div>' +
            '<div class="finding-summary">' + escapeHtml(summary) + '</div>' +
            '<div class="finding-card-meta">' +
            '<div class="meta-item"><span class="meta-label">Domain</span><span class="meta-value">' + domain + '</span></div>' +
            (rec._pillar ? '<div class="meta-item"><span class="meta-label">Pillar</span><span class="meta-value">' + escapeHtml(rec._pillar) + '</span></div>' : '<div class="meta-item"><span class="meta-label">Category</span><span class="meta-value">' + escapeHtml(formatCategory(rec._category)) + '</span></div>') +
            '<div class="meta-item"><span class="meta-label">Firewall</span><span class="meta-value mono">' + fw + '</span></div>' +
            '<div class="meta-item"><span class="meta-label">Detected</span><span class="meta-value mono">' + detected + '</span></div>' +
            (isReviewed ? '<div class="meta-item"><span class="meta-label">Review</span><span class="meta-value ok">Reviewed</span></div>' : '') +
            (assignee ? '<div class="meta-item"><span class="meta-label">Owner</span><span class="meta-value owner">' + escapeHtml(assignee) + '</span></div>' : '') +
            '</div>' +
            '</div>' +
            '<span class="finding-chevron">' + ICONS.chevron + '</span>' +
            '<div class="finding-body">' +
            findingBodyHtml(rec) +
            (PAGE_DOMAIN === "zero_trust" ? "" : actionsHtml(rec, isReviewed, !!assignee)) +
            '</div>' +
            '</div>' +
            '</div>';
    }

    function groupKey(rec) {
        if (rec._pillar) return rec._pillar;
        return rec._group || formatCategory(rec._category);
    }

    function formatCategory(value) {
        var text = String(value || "Uncategorised").replace(/_/g, " ").trim();
        return text ? text.charAt(0).toUpperCase() + text.slice(1) : "Uncategorised";
    }

    function renderGroups(records) {
        if (!root) return;
        var countEl = document.getElementById("findingsCount");
        if (countEl) countEl.textContent = records.length + " finding" + (records.length === 1 ? "" : "s");

        if (!records.length) {
            root.innerHTML = '<div class="empty-state card"><h3>No findings match filters</h3><p>Adjust filters or run a fresh assessment.</p></div>';
            return;
        }

        var groups = {};
        var order = [];
        records.forEach(function (r) {
            var c = groupKey(r);
            if (!groups[c]) { groups[c] = []; order.push(c); }
            groups[c].push(r);
        });
        order.sort();

        var html = "";
        order.forEach(function (category) {
            var list = groups[category] || [];
            if (!list.length) return;
            var isCollapsed = !!state.collapsed[category];
            var badges = { critical: 0, high: 0, medium: 0, low: 0, compliant: 0 };
            list.forEach(function (r) {
                var k = r.risk.toLowerCase();
                if (badges[k] != null) badges[k]++;
            });
            var badgeHtml = "";
            ["critical", "high", "medium", "low"].forEach(function (k) {
                if (badges[k]) badgeHtml += '<span class="group-badge ' + k + '">' + badges[k] + '</span>';
            });
            html += '<section class="group-section' + (isCollapsed ? ' is-collapsed' : '') + '" data-category="' + escapeHtml(category) + '">' +
                '<div class="group-head" role="button" tabindex="0" aria-expanded="' + String(!isCollapsed) + '">' +
                '<span class="group-toggle">' + ICONS.chevron + '</span>' +
                '<span class="group-name">' + escapeHtml(category) + '</span>' +
                '<span class="group-count">' + list.length + '</span>' +
                '<span class="group-badges">' + badgeHtml + '</span>' +
                '</div>' +
                '<div class="group-body">' +
                list.map(findingCardHtml).join("") +
                '</div>' +
                '</section>';
        });
        root.innerHTML = html;
    }

    // ============================================================
    // RENDER ALL
    // ============================================================

    function renderAll() {
        var visible = getVisible();
        renderGroups(visible);
        renderActiveFilters();
    }

    // ============================================================
    // FILTERS UI
    // ============================================================

    function renderScopeChips() {
        var el = document.getElementById("scopeChips");
        if (!el) return;
        var domains = (state.facets && state.facets.domains) || [];
        var chips = '<button class="chip chip-domain' + (state.filters.domain === "all" ? " is-active" : "") + '" data-value="all">All</button>';
        domains.forEach(function (d) {
            chips += '<button class="chip chip-domain' + (state.filters.domain === d.value ? " is-active" : "") +
                '" data-value="' + escapeHtml(d.value) + '">' + escapeHtml(d.label || d.value) +
                (d.count != null ? ' <span class="chip-count">' + d.count + "</span>" : "") + "</button>";
        });
        el.innerHTML = chips;
    }

    function firewallOptionNames() {
        var names = [];
        (state.inventory || []).forEach(function (e) {
            if (e && e.device_name && names.indexOf(e.device_name) === -1) names.push(e.device_name);
        });
        ((state.facets && state.facets.firewalls) || []).forEach(function (f) {
            if (f && f.value && names.indexOf(f.value) === -1) names.push(f.value);
        });
        return names;
    }

    function populateFirewallSelect() {
        var el = document.getElementById("firewallSelect");
        if (!el) return;
        var html = '<option value="all">All</option>';
        firewallOptionNames().forEach(function (n) {
            html += '<option value="' + escapeHtml(n) + '">' + escapeHtml(n) + "</option>";
        });
        el.innerHTML = html;
        el.value = state.filters.firewall || "all";
    }

    function fillSelect(id, options, current, allLabel) {
        var el = document.getElementById(id);
        if (!el) return;
        var html = '<option value="all">' + escapeHtml(allLabel) + "</option>";
        (options || []).forEach(function (o) {
            var value = o.value != null ? o.value : o;
            var label = o.label != null ? o.label : value;
            var count = o.count != null ? " (" + o.count + ")" : "";
            html += '<option value="' + escapeHtml(value) + '">' + escapeHtml(label) + count + "</option>";
        });
        el.innerHTML = html;
        el.value = current || "all";
        if (el.value !== (current || "all")) el.value = "all";
    }

    function populateDomainSelect() {
        var facets = state.facets || {};
        fillSelect("domainSelect", facets.domains || [], state.filters.domain, "All domains");
    }

    function populateAssessmentSelect() {
        var facets = state.facets || {};
        var options = (facets.assessments || []).filter(function (a) {
            return !a.domain || a.domain === PAGE_DOMAIN;
        }).map(function (a) {
            var when = a.completed_at ? formatTs(a.completed_at) : "unknown";
            return {
                value: a.assessment_id,
                label: (a.domain_label || a.domain) + " \u00b7 " + when + " \u00b7 " + a.total_findings + " findings"
            };
        });
        fillSelect("assessmentSelect", options, state.filters.assessment, "Latest per scope");
    }

    function ztPillarOptions() {
        var pillars = (state.facets && state.facets.pillars) || [];
        if (pillars.length) return pillars;
        return [
            { value: "Identity", label: "Identity" },
            { value: "Devices", label: "Endpoint Device" },
            { value: "Network", label: "Network" },
            { value: "Data", label: "Data" },
            { value: "Infrastructure", label: "Infrastructure" }
        ];
    }

    function populatePillarSelect() {
        var field = document.getElementById("pillarField");
        var show = PAGE_DOMAIN === "zero_trust";
        if (field) field.hidden = true;
        if (!show) {
            state.filters.pillar = "all";
            return;
        }
        fillSelect("pillarSelect", ztPillarOptions(), state.filters.pillar, "All pillars");
        populateZtFilterPills();
    }

    function populateCategorySelect() {
        var facets = state.facets || {};
        var categories = facets.categories || [];
        fillSelect("categorySelect", categories, state.filters.category, "All categories");
    }

    function domainStatusOptions() {
        var vocab = state.statusVocabulary || {};
        if (state.filters.domain !== "all" && vocab[state.filters.domain]) {
            return vocab[state.filters.domain];
        }
        var seen = {};
        var merged = [{ value: "open", label: "Open (all non-passing)" }];
        Object.keys(vocab).forEach(function (domain) {
            (vocab[domain] || []).forEach(function (o) {
                if (!seen[o.value]) { seen[o.value] = true; merged.push(o); }
            });
        });
        return merged;
    }

    function populateStatusSelect() {
        var el = document.getElementById("statusSelect");
        if (el) {
            var options = domainStatusOptions();
            var html = '<option value="all">All</option>';
            options.forEach(function (o) {
                html += '<option value="' + escapeHtml(o.value) + '">' + escapeHtml(o.label) + "</option>";
            });
            el.innerHTML = html;
            el.value = state.filters.status || "all";
            if (el.value !== (state.filters.status || "all")) {
                state.filters.status = "all";
                el.value = "all";
            }
        }
        populateZtFilterPills();
        populateFaFilterPills();
    }

    function populateDateSelect() {
        var el = document.getElementById("dateSelect");
        if (el) {
            var facets = state.facets || {};
            var html = '<option value="all">All dates</option>';
            (facets.dates || []).forEach(function (d) {
                html += '<option value="' + escapeHtml(d.value) + '">' + escapeHtml(d.value) + " (" + d.count + ")</option>";
            });
            el.innerHTML = html;
            el.value = state.filters.date || "all";
        }
        var dateInput = document.getElementById("ztDateInput");
        if (dateInput) {
            dateInput.value = state.filters.date && state.filters.date !== "all" ? state.filters.date : "";
        }
    }

    function fwComboSource() {
        var inv = (state.inventory || []).filter(function (e) { return e && e.device_name; });
        if (inv.length) return inv;
        return firewallOptionNames().map(function (n) { return { device_name: n }; });
    }

    function fwComboRows(query) {
        var q = String(query || "").trim().toLowerCase();
        var out = "";
        if (!q || q.indexOf("all") !== -1 || q.indexOf("device") !== -1 || q.indexOf("inventory") !== -1) {
            out += '<li class="fw-combo-row" role="option" data-value="all">' +
                '<span class="fw-combo-name">All devices</span>' +
                '<span class="fw-combo-sub">Every managed firewall in the inventory</span></li>';
        }
        fwComboSource().forEach(function (fw) {
            var name = fw.device_name || "";
            if (!name) return;
            var hay = (name + " " + (fw.host_ip || "") + " " + (fw.clone_of || "")).toLowerCase();
            if (q && hay.indexOf(q) === -1) return;
            var bits = [fw.host_ip || "", fw.status ? (fw.status === "live" ? "Live" : "Down") : ""];
            if (fw.clone_of) bits.push("Clone of " + fw.clone_of);
            var sub = bits.filter(Boolean).join(" \u00b7 ") || "Managed device";
            var badge = fw.clone_of ? '<span class="fw-badge-clone">Clone</span>' : "";
            out += '<li class="fw-combo-row" role="option" data-value="' + escapeHtml(name) + '">' +
                '<span class="fw-combo-name">' + escapeHtml(name) + "</span>" +
                '<span class="fw-combo-sub">' + escapeHtml(sub) + "</span>" + badge +
                "</li>";
        });
        return out;
    }

    function reflectFirewallUI() {
        var input = document.getElementById("fwSearchInput");
        var clear = document.getElementById("fwSearchClear");
        var loaded = state.loadedFirewall || "all";
        if (!input) return;
        if (loaded === "all") {
            input.value = "";
            input.placeholder = "All devices \u2014 search inventory";
        } else {
            input.value = loaded;
            input.placeholder = "";
        }
        if (clear) clear.hidden = loaded === "all";
        var el = document.getElementById("firewallSelect");
        if (el) el.value = loaded;
    }

    function handleFirewallChange(value) {
        value = value || "all";
        state.filters.firewall = value;
        loadData();
    }

    function bindFirewallCombo() {
        if (PAGE_DOMAIN === "zero_trust") return;
        var input = document.getElementById("fwSearchInput");
        var list = document.getElementById("fwSearchList");
        var clear = document.getElementById("fwSearchClear");
        var wrap = document.getElementById("fwCombobox");
        if (!input || !list || !wrap) return;

        function close() {
            list.hidden = true;
            input.setAttribute("aria-expanded", "false");
            document.removeEventListener("click", outside);
        }
        function outside(e) {
            if (!wrap.contains(e.target)) close();
        }
        function open() {
            document.removeEventListener("click", outside);
            list.innerHTML = fwComboRows(input.value);
            list.hidden = false;
            input.setAttribute("aria-expanded", "true");
            document.addEventListener("click", outside);
        }

        input.addEventListener("focus", open);
        input.addEventListener("input", open);
        list.addEventListener("mousedown", function (e) { e.preventDefault(); });
        list.addEventListener("click", function (e) {
            var row = e.target.closest(".fw-combo-row");
            if (!row) return;
            handleFirewallChange(row.getAttribute("data-value") || "all");
            close();
        });
        if (clear) {
            clear.addEventListener("click", function () {
                handleFirewallChange("all");
                close();
            });
        }
        input.addEventListener("keydown", function (e) {
            if (e.key === "Escape") { close(); return; }
            if (e.key === "Enter") {
                e.preventDefault();
                var first = list.querySelector(".fw-combo-row");
                if (first) handleFirewallChange(first.getAttribute("data-value") || "all");
                close();
            }
        });
    }

    function syncFilterChips() {
        var sev = document.getElementById("severitySelect");
        if (sev) sev.value = state.filters.severity;
        var st = document.getElementById("statusSelect");
        if (st) st.value = state.filters.status;
        var dm = document.getElementById("domainSelect");
        if (dm) dm.value = state.filters.domain;
        var as = document.getElementById("assessmentSelect");
        if (as) as.value = state.filters.assessment;
        var pl = document.getElementById("pillarSelect");
        if (pl) pl.value = state.filters.pillar;
        var cat = document.getElementById("categorySelect");
        if (cat) cat.value = state.filters.category;
        syncChipGroup("scopeChips", state.filters.domain);
        var fw = document.getElementById("firewallSelect");
        if (fw) fw.value = state.filters.firewall;
        var rr = document.getElementById("riskRangeSelect");
        if (rr) rr.value = state.filters.riskRange;
        var dt = document.getElementById("dateSelect");
        if (dt) dt.value = state.filters.date;
        var dateInput = document.getElementById("ztDateInput");
        if (dateInput) dateInput.value = state.filters.date && state.filters.date !== "all" ? state.filters.date : "";
        var sortEl = document.getElementById("sortSelect");
        if (sortEl) sortEl.value = state.filters.sort;
        syncZtFilterButton();
        syncFaFilterButton();
    }

    function syncChipGroup(id, value) {
        var el = document.getElementById(id);
        if (!el) return;
        el.querySelectorAll(".chip").forEach(function (c) {
            c.classList.toggle("is-active", c.getAttribute("data-value") === value);
        });
    }

    function renderActiveFilters() {
        var el = document.getElementById("activeFilters");
        if (!el) return;
        var f = state.filters;
        var pills = [];
        var defs = [
            { key: "severity", label: "Severity" },
            { key: "status", label: "Status" },
            { key: "assessment", label: "Assessment" },
            { key: "pillar", label: "Pillar" },
            { key: "category", label: "Category" },
            { key: "firewall", label: "Firewall" },
            { key: "riskRange", label: "Risk", labels: { critical: "90\u2013100", high: "70\u201389", medium: "40\u201369", low: "0\u201339" } },
            { key: "date", label: "Assessed" }
        ];
        defs.forEach(function (d) {
            var v = f[d.key];
            if (!v || v === "all") return;
            var label = d.labels && d.labels[v] ? d.labels[v] : v;
            if (d.key === "domain") label = domainLabel(v);
            if (d.key === "status") label = statusLabel(v);
            if (d.key === "assessment") label = assessmentLabel(v);
            if (d.key === "category") label = formatCategory(v);
            pills.push('<span class="active-pill" data-key="' + d.key + '"><span class="active-pill-label">' + d.label + ':</span> ' + escapeHtml(label) + '<button class="active-pill-x" type="button" aria-label="Remove filter">&times;</button></span>');
        });
        if (f.search) {
            pills.push('<span class="active-pill" data-key="search"><span class="active-pill-label">Search:</span> ' + escapeHtml(f.search) + '<button class="active-pill-x" type="button" aria-label="Remove filter">&times;</button></span>');
        }
        el.innerHTML = pills.join("");
    }

    function assessmentLabel(value) {
        var list = (state.facets && state.facets.assessments) || [];
        for (var i = 0; i < list.length; i++) {
            if (list[i].assessment_id === value) {
                var when = list[i].completed_at ? formatTs(list[i].completed_at) : value;
                return (list[i].domain_label || list[i].domain) + " \u00b7 " + when;
            }
        }
        return value;
    }

    function assessmentDomain(value) {
        var list = (state.facets && state.facets.assessments) || [];
        for (var i = 0; i < list.length; i++) {
            if (list[i].assessment_id === value) return list[i].domain;
        }
        return null;
    }

    function domainLabel(value) {
        var domains = (state.facets && state.facets.domains) || [];
        for (var i = 0; i < domains.length; i++) {
            if (domains[i].value === value) return domains[i].label;
        }
        return value;
    }

    function statusLabel(value) {
        if (value === "open") return "Open";
        var options = domainStatusOptions();
        for (var i = 0; i < options.length; i++) {
            if (options[i].value === value) return options[i].label;
        }
        return value;
    }

    function bindChips(id, key) {
        var el = document.getElementById(id);
        if (!el) return;
        el.addEventListener("click", function (e) {
            var chip = e.target.closest(".chip");
            if (!chip) return;
            if (key === "domain") {
                lockDomain();
            } else {
                state.filters[key] = chip.getAttribute("data-value") || "all";
            }
            loadData();
        });
    }

    var ztFilterDraft = { status: "all", riskRange: "all", pillar: "all" };
    var faFilterDraft = { severity: "all", status: "all", riskRange: "all", firewall: "all" };

    function ztFilterBtn() { return document.getElementById("ztIcFilterBtn"); }
    function ztFilterPanel() { return document.getElementById("ztIcFilterPanel"); }
    function faFilterBtn() { return document.getElementById("faIcFilterBtn"); }
    function faFilterPanel() { return document.getElementById("faIcFilterPanel"); }

    function ztHasPanelFilters() {
        return state.filters.status !== "all" || state.filters.riskRange !== "all" || state.filters.pillar !== "all";
    }

    function syncZtFilterButton() {
        var btn = ztFilterBtn();
        if (!btn) return;
        btn.classList.toggle("has-filters", PAGE_DOMAIN === "zero_trust" && ztHasPanelFilters());
    }

    function faHasPanelFilters() {
        return state.filters.severity !== "all" || state.filters.status !== "all" ||
            state.filters.riskRange !== "all" || state.filters.firewall !== "all";
    }

    function syncFaFilterButton() {
        var btn = faFilterBtn();
        if (!btn) return;
        btn.classList.toggle("has-filters", PAGE_DOMAIN !== "zero_trust" && faHasPanelFilters());
    }

    function setZtPillActive(container, attr, value) {
        if (!container) return;
        container.querySelectorAll(".rep-pill").forEach(function (pill) {
            var on = (pill.getAttribute(attr) || "all") === value;
            pill.classList.toggle("is-active", on);
            pill.setAttribute("aria-pressed", on ? "true" : "false");
        });
    }

    function populateZtFilterPills() {
        if (PAGE_DOMAIN !== "zero_trust") return;
        var statusEl = document.getElementById("ztIcStatusPills");
        if (statusEl) {
            var html = '<button type="button" class="rep-pill" data-status="all">All</button>';
            domainStatusOptions().forEach(function (o) {
                html += '<button type="button" class="rep-pill" data-status="' + escapeHtml(o.value) + '">' + escapeHtml(o.label) + "</button>";
            });
            statusEl.innerHTML = html;
            setZtPillActive(statusEl, "data-status", ztFilterDraft.status);
        }
        setZtPillActive(document.getElementById("ztIcRiskPills"), "data-risk", ztFilterDraft.riskRange);
        var pillarEl = document.getElementById("ztIcPillarPills");
        if (pillarEl) {
            var htmlP = '<button type="button" class="rep-pill" data-pillar="all">All</button>';
            ztPillarOptions().forEach(function (o) {
                var label = o.value === "Devices" ? "Endpoint Device" : (o.label || o.value);
                htmlP += '<button type="button" class="rep-pill" data-pillar="' + escapeHtml(o.value) + '">' + escapeHtml(label) + "</button>";
            });
            pillarEl.innerHTML = htmlP;
            setZtPillActive(pillarEl, "data-pillar", ztFilterDraft.pillar);
        }
        syncZtFilterButton();
    }

    function syncZtFilterDraft() {
        ztFilterDraft.status = state.filters.status || "all";
        ztFilterDraft.riskRange = state.filters.riskRange || "all";
        ztFilterDraft.pillar = state.filters.pillar || "all";
        populateZtFilterPills();
    }

    function openZtFilter() {
        var panel = ztFilterPanel();
        var btn = ztFilterBtn();
        if (!panel) return;
        syncZtFilterDraft();
        panel.hidden = false;
        if (btn) {
            btn.classList.add("is-active");
            btn.setAttribute("aria-expanded", "true");
        }
    }

    function closeZtFilter() {
        var panel = ztFilterPanel();
        var btn = ztFilterBtn();
        if (!panel) return;
        panel.hidden = true;
        if (btn) {
            btn.classList.remove("is-active");
            btn.setAttribute("aria-expanded", "false");
        }
    }

    function populateFaFilterPills() {
        if (PAGE_DOMAIN === "zero_trust") return;
        var statusEl = document.getElementById("faIcStatusPills");
        if (statusEl) {
            var html = '<button type="button" class="rep-pill" data-status="all">All</button>';
            domainStatusOptions().forEach(function (o) {
                html += '<button type="button" class="rep-pill" data-status="' + escapeHtml(o.value) + '">' + escapeHtml(o.label) + "</button>";
            });
            statusEl.innerHTML = html;
            setZtPillActive(statusEl, "data-status", faFilterDraft.status);
        }
        setZtPillActive(document.getElementById("faIcSeverityPills"), "data-severity", faFilterDraft.severity);
        setZtPillActive(document.getElementById("faIcRiskPills"), "data-risk", faFilterDraft.riskRange);
        syncFaFilterButton();
    }

    function syncFaFilterDraft() {
        faFilterDraft.severity = state.filters.severity || "all";
        faFilterDraft.status = state.filters.status || "all";
        faFilterDraft.riskRange = state.filters.riskRange || "all";
        faFilterDraft.firewall = state.filters.firewall || "all";
        populateFaFilterPills();
    }

    function openFaFilter() {
        var panel = faFilterPanel();
        var btn = faFilterBtn();
        if (!panel) return;
        syncFaFilterDraft();
        panel.hidden = false;
        if (btn) {
            btn.classList.add("is-active");
            btn.setAttribute("aria-expanded", "true");
        }
    }

    function closeFaFilter() {
        var panel = faFilterPanel();
        var btn = faFilterBtn();
        if (!panel) return;
        panel.hidden = true;
        if (btn) {
            btn.classList.remove("is-active");
            btn.setAttribute("aria-expanded", "false");
        }
    }

    function applyFilters() {
        saveFilters();
        syncFilterChips();
        renderAll();
    }

    function resetFilters() {
        state.filters = defaultFilters();
        lockDomain();
        if (sortSelect) sortSelect.value = state.filters.sort;
        if (searchInput) searchInput.value = "";
        if (viewSelect) viewSelect.value = "all";
        loadData();
    }

    // ============================================================
    // SAVED VIEWS
    // ============================================================

    function loadSavedViews() {
        try {
            state.customViews = JSON.parse(localStorage.getItem(STORAGE_VIEWS) || "[]") || [];
        } catch (e) { state.customViews = []; }
    }

    function populateViewSelect() {
        if (!viewSelect) return;
        var html = "";
        PRESET_VIEWS.forEach(function (v) { html += '<option value="' + v.id + '">' + escapeHtml(v.name) + '</option>'; });
        state.customViews.forEach(function (v) { html += '<option value="custom:' + v.name + '">' + escapeHtml(v.name) + '</option>'; });
        viewSelect.innerHTML = html;
    }

    function applyView(view) {
        state.filters = Object.assign(defaultFilters(), view.filters);
        lockDomain();
        if (sortSelect) sortSelect.value = state.filters.sort;
        if (searchInput) searchInput.value = state.filters.search || "";
        loadData();
    }

    function saveView() {
        var name = window.prompt("Name this view:");
        if (!name || !name.trim()) return;
        name = name.trim();
        state.customViews = state.customViews.filter(function (v) { return v.name !== name; });
        state.customViews.push({ name: name, filters: Object.assign({}, state.filters) });
        localStorage.setItem(STORAGE_VIEWS, JSON.stringify(state.customViews));
        populateViewSelect();
        viewSelect.value = "custom:" + name;
        if (window.showToast) window.showToast("View saved as \u201c" + name + "\u201d.", "success");
    }

    // ============================================================
    // PERSISTENCE
    // ============================================================

    function loadFilters() {
        var defaults = defaultFilters();
        try {
            var saved = JSON.parse(localStorage.getItem(STORAGE_FILTERS) || "null");
            if (saved && typeof saved === "object") {
                Object.keys(defaults).forEach(function (key) {
                    if (saved[key] != null) defaults[key] = saved[key];
                });
            }
        } catch (e) { /* ignore */ }
        state.filters = defaults;
        state.filters.assessment = "all";
        try {
            var params = new URLSearchParams(window.location.search);
            ["status", "severity", "search", "assessment", "pillar", "category", "date"].forEach(function (key) {
                if (params.get(key)) state.filters[key] = params.get(key);
            });
            if (params.get("risk")) state.filters.riskRange = params.get("risk");
            if (params.get("firewall")) state.filters.firewall = params.get("firewall");
            state.filters.pillar = normalizePillarParam(state.filters.pillar);
            state.filters.riskRange = normalizeRiskParam(state.filters.riskRange);
        } catch (e) { /* ignore */ }
        lockDomain();
        try {
            state.reviewed = JSON.parse(localStorage.getItem(STORAGE_REVIEWED) || "{}") || {};
        } catch (e) { state.reviewed = {}; }
        try {
            state.assignees = JSON.parse(localStorage.getItem(STORAGE_ASSIGNEES) || "{}") || {};
        } catch (e) { state.assignees = {}; }
    }

    function saveFilters() {
        try { localStorage.setItem(STORAGE_FILTERS, JSON.stringify(state.filters)); } catch (e) { /* ignore */ }
    }
    function saveReviewed() {
        try { localStorage.setItem(STORAGE_REVIEWED, JSON.stringify(state.reviewed)); } catch (e) { /* ignore */ }
    }
    function saveAssignees() {
        try { localStorage.setItem(STORAGE_ASSIGNEES, JSON.stringify(state.assignees)); } catch (e) { /* ignore */ }
    }

    // ============================================================
    // AI COPILOT
    // ============================================================

    var copilot = { panel: document.getElementById("copilotPanel"), backdrop: document.getElementById("copilotBackdrop"), body: document.getElementById("copilotBody"), current: null };

    var ACTION_LABELS = {
        explain: "Explain Finding",
        fixplan: "Generate Fix Plan",
        importance: "Why Is This Important?",
        impact: "Security Impact Analysis",
        summarize: "Summarize for Management"
    };

    function openCopilot(rec) {
        copilot.current = rec;
        document.getElementById("copilotFindingRef").textContent = rec.control + " \u00b7 " + rec._domain;
        copilot.body.innerHTML = '<p class="copilot-placeholder">Select an action to get AI assistance for this finding.</p>';
        copilot.panel.classList.add("open");
        copilot.backdrop.classList.add("show");
        resetCopilotChips();
    }

    function closeCopilot() {
        copilot.panel.classList.remove("open");
        copilot.backdrop.classList.remove("show");
    }

    function resetCopilotChips() {
        document.querySelectorAll("#copilotActions .copilot-chip").forEach(function (c) { c.classList.remove("is-active"); });
    }

    function runCopilot(action) {
        if (!copilot.current) return;
        document.querySelectorAll("#copilotActions .copilot-chip").forEach(function (c) {
            c.classList.toggle("is-active", c.getAttribute("data-action") === action);
        });

        copilot.body.innerHTML = '<div class="copilot-loading"><span class="spin"></span> Thinking\u2026</div>';
        var rec = copilot.current;
        var prompt = buildPrompt(action, rec);

        fetch("/api/chat", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message: prompt })
        })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data && data.error) throw new Error(data.error);
                var reply = (data && data.reply) || "";
                if (reply) { renderCopilotAnswer(reply); return; }
                renderCopilotAnswer(buildLocalAnswer(action, rec));
            })
            .catch(function () {
                renderCopilotAnswer(buildLocalAnswer(action, rec));
            });
    }

    function buildPrompt(action, rec) {
        var context = [
            "Finding " + rec.control + " (" + rec._domain + ", " + rec._category + ")",
            "Check: " + rec._check,
            "Severity: " + rec.risk + ", Risk Score: " + rec._risk_score + "/100",
            "Metric: " + rec.metric,
            "Observed: " + JSON.stringify(rec.observed),
            "Expected: " + JSON.stringify(rec.expected) + " (operator " + rec.operator + ")",
            "Gap: " + rec._gap,
            "Impact: " + rec._impact,
            "Remediation: " + rec._remediation,
            "Firewall: " + rec._firewall + " (" + rec._model + ", " + rec._version + ")"
        ].join("\n");

        var instruction = {
            explain: "Explain this firewall security finding in plain, concise language for a network engineer. Include what is wrong, why it matters, and the single most important first step.",
            fixplan: "Produce a concrete, ordered fix plan (numbered steps) to remediate this finding. Include verification steps and rollback considerations.",
            importance: "Explain in 2-3 short paragraphs why this specific finding matters to the business and what could go wrong if left unaddressed.",
            impact: "Provide a focused security impact analysis of this finding: likelihood, business impact, and a recommended risk response (accept/mitigate/transfer/avoid).",
            summarize: "Summarize this finding in 2-3 crisp bullet points suitable for an executive dashboard."
        }[action] || "";

        return instruction + "\n\nFINDING CONTEXT:\n" + context;
    }

    function renderCopilotAnswer(text) {
        var html = '<div class="copilot-answer">';
        html += text.split(/\n{2,}/).map(function (para) {
            return '<p>' + escapeHtml(para).replace(/\n/g, "<br>") + '</p>';
        }).join("");
        html += '</div>';
        copilot.body.innerHTML = html;
    }

    function buildLocalAnswer(action, rec) {
        var rc = riskContext(rec);
        if (action === "explain") {
            return "Finding " + rec.control + " \u2014 " + rec._check + "\n\n" +
                "What is wrong: " + (rec._gap || "The control does not meet its baseline.") + "\n\n" +
                "Why it matters: " + (rec._impact || "This exposes the environment to risk.") + "\n\n" +
                "First step: " + (rec._remediation || "Review the control and apply the recommended remediation.");
        }
        if (action === "fixplan") {
            var steps = [
                "1. Acknowledge and scope \u2014 confirm " + rec.control + " applies to " + rec._firewall + " and capture a change ticket.",
                "2. Assess current state \u2014 " + (rec._method || "collect the current configuration and metric."),
                "3. Apply remediation \u2014 " + (rec._remediation || "align the configuration with the baseline."),
                "4. Verify \u2014 re-run the check and confirm " + rec.metric + " now satisfies " + formatExpected(rec.expected, rec.operator) + ".",
                "5. Document and close \u2014 attach evidence and schedule the next re-assessment."
            ];
            return "Fix plan for " + rec.control + "\n\n" + steps.join("\n");
        }
        if (action === "importance") {
            return "Why " + rec.control + " matters\n\n" +
                (rec._impact || "This control has a material impact on the security posture.") + "\n\n" +
                "If left unaddressed, this finding is assessed as " + rc.likelihood.toLowerCase() + " likelihood with " + rc.trend.toLowerCase() + " risk trend. " +
                "Addressing it removes a meaningful source of exposure on " + rec._firewall + ".";
        }
        if (action === "impact") {
            return "Security impact analysis \u2014 " + rec.control + "\n\n" +
                "Severity: " + rec.risk + " (risk score " + rec._risk_score + "/100)\n" +
                "Likelihood: " + rc.likelihood + "\n" +
                "Business impact: " + rc.impact + "\n" +
                "Exploitability: " + rc.exploit + "\n" +
                "Recommended response: " + (rec._risk_score >= 80 ? "Mitigate immediately" : rec._risk_score >= 40 ? "Mitigate on a planned cycle" : "Accept with monitoring") + ".";
        }
        return "Summary \u2014 " + rec.control + "\n\n" +
            "\u2022 " + rec._check + "\n" +
            "\u2022 Severity " + rec.risk + ", risk score " + rec._risk_score + "/100\n" +
            "\u2022 " + (rec._remediation || "No remediation guidance available.");
    }

    // ============================================================
    // OPERATIONAL ACTIONS
    // ============================================================

    function handleOperationalAction(act, rec) {
        if (act === "device") {
            if (window.showToast) window.showToast("Firewall: " + rec._firewall + " \u00b7 " + rec._domain, "info");
        } else if (act === "assign") {
            assignOwner(rec);
        } else if (act === "export") {
            downloadJson(rec.control + "_finding.json", buildExportPayload(rec));
            if (window.showToast) window.showToast("Exported " + rec.control + ".", "success");
        } else if (act === "report") {
            generateReport();
        } else if (act === "share") {
            shareFinding(rec);
        } else if (act === "review") {
            toggleReview(rec);
        }
    }

    // ============================================================
    // EVIDENCE DRAWER
    // ============================================================

    var evidence = {
        drawer: document.getElementById("evidenceDrawer"),
        backdrop: document.getElementById("evidenceBackdrop"),
        body: document.getElementById("evidenceBody"),
        sub: document.getElementById("evidenceDrawerSub"),
        current: null
    };

    function openEvidence(rec) {
        if (!evidence.drawer) return;
        evidence.current = rec;
        if (evidence.sub) {
            evidence.sub.textContent = (rec.control || "Finding") + " \u00b7 " + (rec._assessment || "assessment");
        }
        evidence.body.innerHTML = '<div class="section-loading"><span class="spinner"></span><span class="section-loading-text">Loading evidence\u2026</span></div>';
        evidence.drawer.classList.add("open");
        evidence.drawer.setAttribute("aria-hidden", "false");
        if (evidence.backdrop) evidence.backdrop.classList.add("show");

        var params = new URLSearchParams();
        params.set("assessment", rec._assessment || "");
        if (rec._pillar) params.set("pillar", rec._pillar);
        fetch("/api/investigation/evidence?" + params.toString())
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (!data || data.error) throw new Error((data && data.error) || "Evidence unavailable");
                renderEvidenceMenu(data, rec);
            })
            .catch(function (err) {
                evidence.body.innerHTML = '<div class="empty-state card"><h4>No evidence available</h4><p>' +
                    escapeHtml(err.message || "This assessment has no stored collector payloads.") + "</p></div>";
            });
    }

    function closeEvidence() {
        if (!evidence.drawer) return;
        evidence.drawer.classList.remove("open");
        evidence.drawer.setAttribute("aria-hidden", "true");
        if (evidence.backdrop) evidence.backdrop.classList.remove("show");
        evidence.current = null;
    }

    function renderEvidenceMenu(data, rec) {
        var entries = data.entries || [];
        var html = "";
        if (!entries.length) {
            html = '<div class="empty-state card"><h4>No collector evidence</h4>' +
                '<p>This assessment was stored without collector payloads.</p></div>';
        } else {
            html = '<p class="evidence-drawer-note">' + entries.length + " collector payload" +
                (entries.length === 1 ? "" : "s") + " stored for this assessment. Select one to inspect it.</p>" +
                '<div class="evidence-entry-list">';
            entries.forEach(function (entry, index) {
                var label = entry.pillar ? entry.pillar + " \u00b7 " + entry.collector : entry.collector;
                html += '<button class="evidence-entry" type="button" data-collector="' + escapeHtml(entry.collector || "") +
                    '" data-pillar="' + escapeHtml(entry.pillar || "") + '" data-evidence="' + escapeHtml(entry.id || "") + '">' +
                    '<span class="evidence-entry-name">' + escapeHtml(label || "Collector") + '</span>' +
                    '<span class="evidence-entry-meta">' + escapeHtml(entry.evidence_type || "payload") +
                    (entry.size ? " \u00b7 " + Math.round(entry.size / 102.4) / 10 + " KB" : "") +
                    (entry.collected_at ? " \u00b7 " + formatTs(entry.collected_at) : "") + "</span>" +
                    "</button>";
            });
            html += "</div><div class=\"evidence-payload\" id=\"evidencePayload\"></div>";
        }
        evidence.body.innerHTML = html;
    }

    function loadEvidencePayload(btn) {
        if (!evidence.current) return;
        var holder = document.getElementById("evidencePayload");
        if (!holder) return;
        holder.innerHTML = '<div class="section-loading"><span class="spinner"></span><span class="section-loading-text">Loading payload\u2026</span></div>';
        var params = new URLSearchParams();
        params.set("assessment", evidence.current._assessment || "");
        if (btn.getAttribute("data-evidence")) params.set("evidence", btn.getAttribute("data-evidence"));
        if (btn.getAttribute("data-collector")) params.set("collector", btn.getAttribute("data-collector"));
        if (btn.getAttribute("data-pillar")) params.set("pillar", btn.getAttribute("data-pillar"));
        fetch("/api/investigation/evidence?" + params.toString())
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (!data || !data.entry) throw new Error("Payload not found");
                var payload = data.entry.payload;
                if (typeof payload === "string") {
                    holder.innerHTML = '<div class="evidence-payload-head"><strong>' +
                        escapeHtml(data.entry.collector || "payload") + '</strong><span>' +
                        escapeHtml(data.entry.evidence_type || "") + "</span></div>" +
                        '<pre class="evidence-pre">' + escapeHtml(payload) + "</pre>";
                } else {
                    holder.innerHTML = '<div class="evidence-payload-head"><strong>' +
                        escapeHtml(data.entry.collector || "payload") + '</strong><span>' +
                        escapeHtml(data.entry.evidence_type || "") + "</span></div>" +
                        '<pre class="evidence-pre">' + escapeHtml(JSON.stringify(payload, null, 2)) + "</pre>";
                }
            })
            .catch(function (err) {
                holder.innerHTML = '<div class="alert alert-error"><strong>Evidence</strong><span>' +
                    escapeHtml(err.message || "Could not load payload.") + "</span></div>";
            });
    }

    function assignOwner(rec) {
        var key = recKey(rec);
        var current = state.assignees[key] || "";
        var name = window.prompt(current ? "Reassign owner for " + rec.control + " on " + rec._firewall + ":" : "Assign owner for " + rec.control + " on " + rec._firewall + ":", current);
        if (name === null) return;
        name = (name || "").trim();
        if (name) {
            state.assignees[key] = name;
        } else {
            delete state.assignees[key];
        }
        saveAssignees();
        renderAll();
        if (window.showToast) window.showToast(name ? "Assigned " + rec.control + " to " + name + "." : "Owner cleared.", "success");
    }

    function buildExportPayload(rec) {
        return {
            control: rec.control,
            status: rec.status,
            severity: rec.risk,
            risk_score: rec._risk_score,
            domain: rec._domain,
            category: rec._category,
            check: rec._check,
            metric: rec.metric,
            observed: rec.observed,
            expected: rec.expected,
            operator: rec.operator,
            gap: rec._gap,
            impact: rec._impact,
            remediation: rec._remediation,
            verification_method: rec._method,
            evidence: rec._evidence,
            risk_context: riskContext(rec),
            ms_details: rec._ms || null,
            firewall: { hostname: rec._firewall, model: rec._model, version: rec._version },
            detected_at: rec._detected,
            run_id: rec._run_id,
            assignee: state.assignees[recKey(rec)] || null,
            reviewed: !!state.reviewed[recKey(rec)]
        };
    }

    function downloadJson(filename, obj) {
        var blob = new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" });
        var url = URL.createObjectURL(blob);
        var a = document.createElement("a");
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    function generateReport() {
        fetch("/api/excel")
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data && data.error) throw new Error(data.error);
                if (window.showToast) window.showToast("Workbook generated. Download from Reports.", "success");
                if (data && data.download_url) {
                    var a = document.createElement("a");
                    a.href = data.download_url;
                    a.download = "";
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                }
            })
            .catch(function () { if (window.showToast) window.showToast("Report generation failed.", "error"); });
    }

    function shareFinding(rec) {
        var text = rec.control + " " + rec._check + " \u2014 Severity " + rec.risk + " (" + rec._risk_score + "/100) on " + rec._firewall + ". Remediation: " + rec._remediation;
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(function () {
                if (window.showToast) window.showToast("Finding copied to clipboard.", "success");
            });
        } else {
            window.prompt("Copy this finding:", text);
        }
    }

    function toggleReview(rec) {
        var key = recKey(rec);
        if (state.reviewed[key]) {
            delete state.reviewed[key];
        } else {
            state.reviewed[key] = true;
        }
        saveReviewed();
        renderAll();
    }

    function bindZtFilterEvents() {
        if (PAGE_DOMAIN !== "zero_trust") return;
        var btn = ztFilterBtn();
        var panel = ztFilterPanel();
        var closeBtn = document.getElementById("ztIcFilterClose");
        var applyBtn = document.getElementById("ztIcFilterApply");
        var resetBtn = document.getElementById("ztIcFilterReset");
        if (btn) {
            btn.addEventListener("click", function (event) {
                event.stopPropagation();
                if (panel && panel.hidden) openZtFilter(); else closeZtFilter();
            });
        }
        if (closeBtn) closeBtn.addEventListener("click", closeZtFilter);
        if (panel) {
            panel.addEventListener("click", function (event) { event.stopPropagation(); });
            panel.addEventListener("click", function (event) {
                var pill = event.target.closest(".rep-pill");
                if (!pill) return;
                if (pill.hasAttribute("data-status")) {
                    ztFilterDraft.status = pill.getAttribute("data-status") || "all";
                    setZtPillActive(document.getElementById("ztIcStatusPills"), "data-status", ztFilterDraft.status);
                } else if (pill.hasAttribute("data-risk")) {
                    ztFilterDraft.riskRange = pill.getAttribute("data-risk") || "all";
                    setZtPillActive(document.getElementById("ztIcRiskPills"), "data-risk", ztFilterDraft.riskRange);
                } else if (pill.hasAttribute("data-pillar")) {
                    ztFilterDraft.pillar = pill.getAttribute("data-pillar") || "all";
                    setZtPillActive(document.getElementById("ztIcPillarPills"), "data-pillar", ztFilterDraft.pillar);
                }
            });
        }
        if (applyBtn) {
            applyBtn.addEventListener("click", function () {
                state.filters.status = ztFilterDraft.status || "all";
                state.filters.riskRange = ztFilterDraft.riskRange || "all";
                state.filters.pillar = ztFilterDraft.pillar || "all";
                closeZtFilter();
                loadData();
            });
        }
        if (resetBtn) {
            resetBtn.addEventListener("click", function () {
                ztFilterDraft.status = "all";
                ztFilterDraft.riskRange = "all";
                ztFilterDraft.pillar = "all";
                populateZtFilterPills();
                state.filters.status = "all";
                state.filters.riskRange = "all";
                state.filters.pillar = "all";
                closeZtFilter();
                loadData();
            });
        }
        document.addEventListener("click", function () { closeZtFilter(); });
    }

    function bindFaFilterEvents() {
        if (PAGE_DOMAIN === "zero_trust") return;
        var btn = faFilterBtn();
        var panel = faFilterPanel();
        var closeBtn = document.getElementById("faIcFilterClose");
        var applyBtn = document.getElementById("faIcFilterApply");
        var resetBtn = document.getElementById("faIcFilterReset");
        if (btn) {
            btn.addEventListener("click", function (event) {
                event.stopPropagation();
                if (panel && panel.hidden) openFaFilter(); else closeFaFilter();
            });
        }
        if (closeBtn) closeBtn.addEventListener("click", closeFaFilter);
        if (panel) {
            panel.addEventListener("click", function (event) { event.stopPropagation(); });
            panel.addEventListener("click", function (event) {
                var pill = event.target.closest(".rep-pill");
                if (!pill) return;
                if (pill.hasAttribute("data-severity")) {
                    faFilterDraft.severity = pill.getAttribute("data-severity") || "all";
                    setZtPillActive(document.getElementById("faIcSeverityPills"), "data-severity", faFilterDraft.severity);
                } else if (pill.hasAttribute("data-status")) {
                    faFilterDraft.status = pill.getAttribute("data-status") || "all";
                    setZtPillActive(document.getElementById("faIcStatusPills"), "data-status", faFilterDraft.status);
                } else if (pill.hasAttribute("data-risk")) {
                    faFilterDraft.riskRange = pill.getAttribute("data-risk") || "all";
                    setZtPillActive(document.getElementById("faIcRiskPills"), "data-risk", faFilterDraft.riskRange);
                }
            });
        }
        if (applyBtn) {
            applyBtn.addEventListener("click", function () {
                state.filters.severity = faFilterDraft.severity || "all";
                state.filters.status = faFilterDraft.status || "all";
                state.filters.riskRange = faFilterDraft.riskRange || "all";
                closeFaFilter();
                loadData();
            });
        }
        if (resetBtn) {
            resetBtn.addEventListener("click", function () {
                faFilterDraft.severity = "all";
                faFilterDraft.status = "all";
                faFilterDraft.riskRange = "all";
                faFilterDraft.firewall = "all";
                populateFaFilterPills();
                state.filters.severity = "all";
                state.filters.status = "all";
                state.filters.riskRange = "all";
                handleFirewallChange("all");
                closeFaFilter();
            });
        }
        document.addEventListener("click", function () { closeFaFilter(); });
    }

    var ztDetails = {
        drawer: document.getElementById("ztIcDrawer"),
        backdrop: document.getElementById("ztIcDrawerBackdrop"),
        body: document.getElementById("ztIcDrawerBody"),
        title: document.getElementById("ztIcDrawerTitle"),
        current: null
    };

    function ztMsStatus(rec) {
        if (rec._ms && rec._ms.status) return rec._ms.status;
        if (rec.status === "pass" || rec.status === "compliant") return "Passed";
        if (rec.status === "fail" || rec.status === "not_compliant") return "Failed";
        return "Investigate";
    }

    function ztMsRisk(rec) {
        if (rec._ms && rec._ms.risk) return rec._ms.risk;
        var sev = String(rec.risk || "").toLowerCase();
        if (sev === "critical" || sev === "high") return "High";
        if (sev === "low") return "Low";
        return "Medium";
    }

    function ztMsBadge(kind, label) {
        return '<span class="zt-badge zt-badge-' + escapeHtml(kind) + '">' + escapeHtml(label || kind) + "</span>";
    }

    function ztMsRow(label, value) {
        return '<div class="zt-ms-row"><span>' + escapeHtml(label) + "</span><strong>" + escapeHtml(value || "Unavailable") + "</strong></div>";
    }

    function ztEvidenceTableHtml(table) {
        if (!table || !table.columns || !table.rows || !table.rows.length) return "";
        var head = table.columns.map(function (col) {
            return "<th>" + escapeHtml(col.label || col.key) + "</th>";
        }).join("");
        var body = table.rows.map(function (row) {
            return "<tr>" + table.columns.map(function (col) {
                return "<td>" + escapeHtml(row[col.key] == null ? "" : row[col.key]) + "</td>";
            }).join("") + "</tr>";
        }).join("");
        var more = table.truncated ? '<p class="zt-ms-more">Showing ' + table.rows.length + " of " + table.total + "</p>" : "";
        return '<section class="zt-ms-table-wrap"><h4>' + escapeHtml(table.title) + '</h4><div class="zt-ms-table-scroll"><table class="zt-ms-table"><thead><tr>' + head + '</tr></thead><tbody>' + body + '</tbody></table></div>' + more + "</section>";
    }

    function openZtDetails(rec) {
        if (!ztDetails.drawer || !rec) return;
        ztDetails.current = rec;
        var ms = rec._ms || {};
        if (ztDetails.title) ztDetails.title.textContent = ms.name || rec._check || rec.control || "Control details";
        var finding = ms.impact || rec._gap || rec._finding || ms.description || "No finding summary returned.";
        var actions = (ms.remediationActions && ms.remediationActions.length)
            ? ms.remediationActions
            : (rec._remediation ? [rec._remediation] : (ms.recommendation ? [ms.recommendation] : []));
        var tables = (ms.evidenceTables || []).map(ztEvidenceTableHtml).join("");
        var docs = [];
        if (ms.documentationUrl) docs.push('<a href="' + escapeHtml(ms.documentationUrl) + '" target="_blank" rel="noopener noreferrer">Learn more</a>');
        if (ms.portalUrl) docs.push('<a href="' + escapeHtml(ms.portalUrl) + '" target="_blank" rel="noopener noreferrer">Open portal</a>');
        var rc = riskContext(rec);
        ztDetails.body.innerHTML =
            '<div class="zt-ms">' +
            ztMsRow("Risk", ztMsRisk(rec)) +
            ztMsRow("User Impact", ms.userImpact) +
            ztMsRow("Implementation Effort", ms.implementationEffort) +
            ztMsRow("Test ID", ms.id || rec.control) +
            ztMsRow("License", ms.license) +
            '<div class="zt-ms-result"><span>Test result</span>' + ztMsBadge(ztMsStatus(rec), rec.status_label || ztMsStatus(rec)) + "</div>" +
            '<p class="zt-ms-finding">' + escapeHtml(finding) + "</p>" +
            tables +
            (ms.error ? '<section class="zt-ms-block is-error"><h4>Error</h4><p>' + escapeHtml(ms.error.message || ms.error) + "</p></section>" : "") +
            '<section class="zt-ms-block"><h4>What was checked</h4><p>' + escapeHtml(ms.whatWasChecked || rec._check || "No check summary returned.") + "</p>" +
            (ms.howToCheck ? "<p>" + escapeHtml(ms.howToCheck) + "</p>" : "") +
            "</section>" +
            '<section class="zt-ms-block"><h4>Remediation action</h4>' +
            (actions.length ? "<ul>" + actions.map(function (item) { return "<li>" + escapeHtml(item) + "</li>"; }).join("") + "</ul>" : "<p>No remediation summary returned.</p>") +
            (docs.length ? '<p class="zt-ms-links">' + docs.join(" · ") + "</p>" : "") +
            "</section>" +
            '<section class="zt-ms-block"><h4>Risk context</h4>' +
            '<div class="risk-context-grid">' +
            '<div class="rc-item"><span class="rc-label">Business Impact</span><span class="rc-value">' + escapeHtml(rc.impact) + "</span></div>" +
            '<div class="rc-item"><span class="rc-label">Likelihood</span><span class="rc-value">' + escapeHtml(rc.likelihood) + "</span></div>" +
            '<div class="rc-item"><span class="rc-label">Exploitability</span><span class="rc-value">' + escapeHtml(rc.exploit) + "</span></div>" +
            '<div class="rc-item"><span class="rc-label">Risk Trend</span><span class="rc-value">' + escapeHtml(rc.trend) + "</span></div>" +
            "</div></section>" +
            "</div>";
        ztDetails.drawer.hidden = false;
        if (ztDetails.backdrop) ztDetails.backdrop.hidden = false;
        requestAnimationFrame(function () {
            ztDetails.drawer.classList.add("is-open");
            if (ztDetails.backdrop) ztDetails.backdrop.classList.add("is-open");
        });
    }

    function closeZtDetails() {
        if (!ztDetails.drawer) return;
        ztDetails.drawer.classList.remove("is-open");
        if (ztDetails.backdrop) ztDetails.backdrop.classList.remove("is-open");
        setTimeout(function () {
            ztDetails.drawer.hidden = true;
            if (ztDetails.backdrop) ztDetails.backdrop.hidden = true;
        }, 180);
        ztDetails.current = null;
    }

    function bindZtDetailsEvents() {
        var closeBtn = document.getElementById("ztIcDrawerClose");
        if (closeBtn) closeBtn.addEventListener("click", closeZtDetails);
        if (ztDetails.backdrop) ztDetails.backdrop.addEventListener("click", closeZtDetails);
        if (ztDetails.body) {
            ztDetails.body.addEventListener("click", function (e) {
                var btn = e.target.closest("[data-zt-act]");
                if (!btn || !ztDetails.current) return;
                var act = btn.getAttribute("data-zt-act");
                if (act === "copilot") openCopilot(ztDetails.current);
                else if (act === "export") {
                    downloadJson((ztDetails.current.control || "finding") + "_finding.json", buildExportPayload(ztDetails.current));
                    if (window.showToast) window.showToast("Exported " + ztDetails.current.control + ".", "success");
                }
            });
        }
    }

    // ============================================================
    // EVENT BINDING
    // ============================================================

    function bindEvents() {
        root.addEventListener("click", function (e) {
            var groupHead = e.target.closest(".group-head");
            if (groupHead) {
                var section = groupHead.closest(".group-section");
                var category = section.getAttribute("data-category");
                var willCollapse = !section.classList.contains("is-collapsed");
                state.collapsed[category] = willCollapse;
                section.classList.toggle("is-collapsed");
                groupHead.setAttribute("aria-expanded", String(!willCollapse));
                return;
            }

            var actionBtn = e.target.closest(".action-btn");
            if (actionBtn) {
                e.stopPropagation();
                var card = actionBtn.closest(".finding-card");
                var cid = card.getAttribute("data-control");
                var rec = findRecord(cid, card.getAttribute("data-fw"));
                if (!rec) return;
                var act = actionBtn.getAttribute("data-act");
                if (act === "copilot") {
                    openCopilot(rec);
                } else if (act === "evidence") {
                    openEvidence(rec);
                } else {
                    handleOperationalAction(act, rec);
                }
                return;
            }

            var card = e.target.closest(".finding-card");
            if (card) {
                if (PAGE_DOMAIN === "zero_trust") {
                    var rec = findRecord(card.getAttribute("data-control"), card.getAttribute("data-fw"));
                    if (rec) openZtDetails(rec);
                    return;
                }
                var wasActive = card.classList.contains("is-active");
                card.classList.toggle("is-active");
                card.setAttribute("aria-expanded", String(!wasActive));
            }
        });

        root.addEventListener("keydown", function (e) {
            if ((e.key === "Enter" || e.key === " ") && e.target.classList.contains("finding-card")) {
                e.preventDefault();
                if (PAGE_DOMAIN === "zero_trust") {
                    var rec = findRecord(e.target.getAttribute("data-control"), e.target.getAttribute("data-fw"));
                    if (rec) openZtDetails(rec);
                    return;
                }
                e.target.classList.toggle("is-active");
                e.target.setAttribute("aria-expanded", String(e.target.classList.contains("is-active")));
            }
            if ((e.key === "Enter" || e.key === " ") && e.target.classList.contains("group-head")) {
                e.preventDefault();
                e.target.closest(".group-section").classList.toggle("is-collapsed");
            }
        });

        if (searchInput) {
            var t;
            searchInput.addEventListener("input", function () {
                clearTimeout(t);
                t = setTimeout(function () {
                    state.filters.search = searchInput.value.trim();
                    applyFilters();
                }, 220);
            });
        }

        if (sortSelect) {
            sortSelect.addEventListener("change", function () {
                state.filters.sort = sortSelect.value;
                applyFilters();
            });
        }

        var sevSelect = document.getElementById("severitySelect");
        if (sevSelect) {
            sevSelect.addEventListener("change", function () {
                state.filters.severity = sevSelect.value;
                loadData();
            });
        }

        var domainSelect = document.getElementById("domainSelect");
        if (domainSelect) {
            domainSelect.addEventListener("change", function () {
                lockDomain();
                state.filters.pillar = "all";
                state.filters.status = "all";
                var picked = state.filters.assessment;
                if (picked !== "all" && assessmentDomain(picked) !== PAGE_DOMAIN) {
                    state.filters.assessment = "all";
                }
                loadData();
            });
        }

        var assessmentSelect = document.getElementById("assessmentSelect");
        if (assessmentSelect) {
            assessmentSelect.addEventListener("change", function () {
                state.filters.assessment = assessmentSelect.value;
                var domain = assessmentDomain(assessmentSelect.value);
                if (domain && domain !== PAGE_DOMAIN) {
                    state.filters.assessment = "all";
                }
                lockDomain();
                loadData();
            });
        }

        var pillarSelect = document.getElementById("pillarSelect");
        if (pillarSelect) {
            pillarSelect.addEventListener("change", function () {
                state.filters.pillar = pillarSelect.value;
                loadData();
            });
        }

        var categorySelect = document.getElementById("categorySelect");
        if (categorySelect) {
            categorySelect.addEventListener("change", function () {
                state.filters.category = categorySelect.value;
                loadData();
            });
        }

        var stSelect = document.getElementById("statusSelect");
        if (stSelect) {
            stSelect.addEventListener("change", function () {
                state.filters.status = stSelect.value;
                loadData();
            });
        }

        if (viewSelect) {
            viewSelect.addEventListener("change", function () {
                var val = viewSelect.value;
                if (val.indexOf("custom:") === 0) {
                    var name = val.slice(7);
                    var v = state.customViews.find(function (x) { return x.name === name; });
                    if (v) applyView(v);
                } else {
                    var preset = PRESET_VIEWS.find(function (x) { return x.id === val; });
                    if (preset) applyView(preset);
                }
            });
        }

        var fwSelect = document.getElementById("firewallSelect");
        if (fwSelect) {
            fwSelect.addEventListener("change", function () {
                handleFirewallChange(fwSelect.value);
            });
        }

        var rrSelect = document.getElementById("riskRangeSelect");
        if (rrSelect) {
            rrSelect.addEventListener("change", function () {
                state.filters.riskRange = rrSelect.value;
                loadData();
            });
        }

        var dateSelect = document.getElementById("dateSelect");
        if (dateSelect) {
            dateSelect.addEventListener("change", function () {
                state.filters.date = dateSelect.value;
                loadData();
            });
        }
        var ztDateInput = document.getElementById("ztDateInput");
        if (ztDateInput) {
            ztDateInput.addEventListener("change", function () {
                state.filters.date = ztDateInput.value || "all";
                loadData();
            });
        }
        bindZtFilterEvents();
        bindFaFilterEvents();

        var activeFilters = document.getElementById("activeFilters");
        if (activeFilters) {
            activeFilters.addEventListener("click", function (e) {
                var pill = e.target.closest(".active-pill");
                if (!pill) return;
                var key = pill.getAttribute("data-key");
                if (key === "search") state.filters.search = "";
                else state.filters[key] = "all";
                if (searchInput && key === "search") searchInput.value = "";
                lockDomain();
                loadData();
            });
        }

        var saveViewBtn = document.getElementById("btnSaveView");
        if (saveViewBtn) saveViewBtn.addEventListener("click", saveView);
        var resetBtn = document.getElementById("btnResetFilters");
        if (resetBtn) resetBtn.addEventListener("click", resetFilters);
        document.getElementById("btnExpandAll").addEventListener("click", function () {
            state.collapsed = {};
            document.querySelectorAll(".group-section").forEach(function (s) { s.classList.remove("is-collapsed"); });
        });
        document.getElementById("btnCollapseAll").addEventListener("click", function () {
            document.querySelectorAll(".group-section").forEach(function (s) {
                state.collapsed[s.getAttribute("data-category")] = true;
                s.classList.add("is-collapsed");
            });
        });
        var exportReportBtn = document.getElementById("btnExportReport");
        if (exportReportBtn) exportReportBtn.addEventListener("click", generateReport);

        document.getElementById("copilotClose").addEventListener("click", closeCopilot);
        document.getElementById("copilotBackdrop").addEventListener("click", closeCopilot);
        document.getElementById("copilotActions").addEventListener("click", function (e) {
            var chip = e.target.closest(".copilot-chip");
            if (!chip) return;
            runCopilot(chip.getAttribute("data-action"));
        });

        if (evidence.drawer) {
            document.getElementById("evidenceClose").addEventListener("click", closeEvidence);
            if (evidence.backdrop) evidence.backdrop.addEventListener("click", closeEvidence);
            evidence.body.addEventListener("click", function (e) {
                var entry = e.target.closest(".evidence-entry");
                if (!entry) return;
                evidence.body.querySelectorAll(".evidence-entry").forEach(function (b) {
                    b.classList.toggle("is-active", b === entry);
                });
                loadEvidencePayload(entry);
            });
        }

        document.addEventListener("keydown", function (e) {
            if (e.key === "Escape") { closeCopilot(); closeEvidence(); closeZtDetails(); closeZtFilter(); }
        });
        bindZtDetailsEvents();
    }

    function findRecord(cid, fw) {
        return state.records.find(function (r) {
            return r.control === cid && (!fw || r._firewall === fw);
        });
    }

    function isEstateView() {
        return (state.loadedFirewall || "all") === "all";
    }

    function recKey(rec) {
        return (rec._assessment || "?") + "::" + (rec.control || "");
    }

    // ============================================================
    // TIME FORMATTING
    // ============================================================

    function formatTs(ts) {
        if (!ts) return "\u2014";
        var d = parseDate(ts);
        if (!d) return String(ts).slice(0, 16);
        return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
    }

    function parseDate(ts) {
        if (typeof ts === "number") return new Date(ts * 1000);
        var d = new Date(ts);
        return isNaN(d.getTime()) ? null : d;
    }

    // ============================================================
    // LOAD
    // ============================================================

    function load() {
        var start = function () {
            var params = new URLSearchParams(window.location.search);
            var presetFirewall = params.get("firewall");
            if (presetFirewall && presetFirewall !== "all" && PAGE_DOMAIN !== "zero_trust") {
                state.filters.firewall = presetFirewall;
            }
            lockDomain();
            loadData();
        };
        if (PAGE_DOMAIN === "zero_trust") {
            state.inventory = [];
            start();
            return;
        }
        fetch("/api/firewall-inventory")
            .then(function (r) { return r.json(); })
            .then(function (data) {
                state.inventory = (data && data.firewalls) || [];
            })
            .catch(function () { state.inventory = []; })
            .finally(start);
    }

    function queryString() {
        var f = state.filters;
        var params = new URLSearchParams();
        ["domain", "assessment", "pillar", "category", "firewall", "severity", "riskRange", "date", "search"].forEach(function (key) {
            if (key === "firewall" && PAGE_DOMAIN === "zero_trust") return;
            var value = f[key];
            if (value && value !== "all") params.set(key === "riskRange" ? "risk" : key, value);
        });
        if (f.sort) params.set("sort", f.sort);
        return params.toString();
    }

    function loadData() {
        lockDomain();
        state.loadedFirewall = state.filters.firewall || "all";
        if (root) {
            root.innerHTML = '<div class="empty-state card"><div class="section-loading"><span class="spinner"></span>' +
                '<span class="section-loading-text">Loading findings\u2026</span></div></div>';
        }
        var qs = queryString();
        fetch("/api/investigation/findings" + (qs ? "?" + qs : ""))
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (!data || data.error) {
                    showEmpty("No findings available", "Run an assessment from the AI Workspace or Automation to populate findings.");
                    reflectFirewallUI();
                    return;
                }
                renderRecords(data);
            })
            .catch(function () {
                showEmpty("Unable to load findings", "The investigation store could not be reached.");
                reflectFirewallUI();
            });
    }

    function showEmpty(title, body) {
        if (!root) return;
        root.innerHTML = '<div class="empty-state card"><h3>' + escapeHtml(title) + "</h3><p>" + escapeHtml(body) + "</p></div>";
    }

    function renderRecords(data) {
        state.facets = data.facets || {};
        state.statusVocabulary = data.status_vocabulary || {};
        state.summary = data.summary || {};
        state.records = (data.records || []).map(enrich).filter(function (rec) {
            return !rec._domain_key || rec._domain_key === PAGE_DOMAIN;
        });
        finishFindingsRender();
    }

    function finishFindingsRender() {
        lockDomain();
        renderScopeChips();
        populateDomainSelect();
        populateAssessmentSelect();
        populatePillarSelect();
        populateCategorySelect();
        populateStatusSelect();
        populateFirewallSelect();
        populateDateSelect();
        populateViewSelect();
        syncZtFilterDraft();
        syncFaFilterDraft();
        if (sortSelect) sortSelect.value = state.filters.sort;
        if (searchInput) searchInput.value = state.filters.search || "";
        syncFilterChips();
        saveFilters();
        reflectFirewallUI();
        reflectTabUI();
        renderAll();
    }

    function reflectTabUI() {
        var zt = PAGE_DOMAIN === "zero_trust";
        ["pillarField", "categoryField", "sortField", "viewField", "resetField"].forEach(function (id) {
            var el = document.getElementById(id);
            if (el) el.hidden = true;
        });
        var faFilterField = document.getElementById("faFilterField");
        if (faFilterField) faFilterField.hidden = zt;
        if (zt) {
            state.filters.category = "all";
            state.filters.severity = "all";
            state.filters.firewall = "all";
        } else {
            state.filters.pillar = "all";
        }
    }

    var ZT_STORAGE_KEY = "ltm_zt_assessment_id";
    var ztRun = {
        running: false,
        assessmentId: "",
        pollTimer: null,
        abort: null,
        assessment: null
    };

    function ztJsonFetch(url, body, signal) {
        return fetch(url, {
            method: "POST",
            credentials: "same-origin",
            headers: {
                "Content-Type": "application/json",
                Accept: "application/json",
                "X-Requested-With": "XMLHttpRequest"
            },
            body: JSON.stringify(body || {}),
            signal: signal
        }).then(function (res) {
            return res.json().catch(function () { return {}; }).then(function (data) {
                if (!res.ok) {
                    var err = new Error(data.error || "Request failed");
                    err.status = res.status;
                    err.retryAfter = data.retryAfter;
                    throw err;
                }
                return data;
            });
        });
    }

    function ztStopPoll() {
        if (ztRun.pollTimer) {
            clearTimeout(ztRun.pollTimer);
            ztRun.pollTimer = null;
        }
        if (ztRun.abort) {
            try { ztRun.abort.abort(); } catch (e) {}
            ztRun.abort = null;
        }
    }

    function ztSetProgress(text, hidden) {
        var el = document.getElementById("ztProgress");
        if (!el) return;
        el.hidden = !!hidden;
        el.textContent = text || "";
    }

    function ztOpenConfirm() {
        if (ztRun.running) return;
        var modal = document.getElementById("ztConfirmModal");
        if (modal) modal.hidden = false;
        var run = document.getElementById("ztConfirmRun");
        if (run) run.focus();
    }

    function ztCloseConfirm() {
        var modal = document.getElementById("ztConfirmModal");
        if (modal) modal.hidden = true;
    }

    function ztStartAssessment() {
        var forceEl = document.getElementById("ztForceRefresh");
        var force = !!(forceEl && forceEl.checked);
        var runBtn = document.getElementById("ztRunBtn");
        ztCloseConfirm();
        ztStopPoll();
        ztRun.running = true;
        if (runBtn) runBtn.disabled = true;
        ztSetProgress("Starting Zero Trust assessment\u2026", false);
        ztJsonFetch("/api/zero-trust/start", { force: force }).then(function (data) {
            ztRun.assessmentId = data.assessmentId || "";
            if (ztRun.assessmentId) {
                try { localStorage.setItem(ZT_STORAGE_KEY, ztRun.assessmentId); } catch (e) {}
            }
            if (data.status === "completed" && data.cached) {
                ztSetProgress("Using cached Zero Trust results.", false);
                ztFinishRun(true);
                return;
            }
            ztSetProgress(data.message || "Collecting Entra ID and Intune configuration\u2026", false);
            ztPollStatus();
        }).catch(function (err) {
            ztRun.running = false;
            if (runBtn) runBtn.disabled = false;
            ztSetProgress("", true);
            if (window.showToast) window.showToast(err.message || "Could not start assessment.", "error");
        });
    }

    function ztPollStatus() {
        if (!ztRun.assessmentId) return;
        ztRun.abort = new AbortController();
        ztJsonFetch("/api/zero-trust/status", { assessmentId: ztRun.assessmentId }, ztRun.abort.signal).then(function (data) {
            ztSetProgress(data.message || ("Assessment " + (data.status || "running") + "\u2026"), false);
            if (data.status === "completed") {
                ztFinishRun(true);
                return;
            }
            if (data.status === "failed") {
                ztStopPoll();
                ztRun.running = false;
                var runBtn = document.getElementById("ztRunBtn");
                if (runBtn) runBtn.disabled = false;
                ztSetProgress("", true);
                if (window.showToast) window.showToast(data.error || data.message || "Assessment failed.", "error");
                return;
            }
            ztRun.pollTimer = setTimeout(ztPollStatus, 2500);
        }).catch(function (err) {
            if (err.name === "AbortError") return;
            ztStopPoll();
            ztRun.running = false;
            var runBtn = document.getElementById("ztRunBtn");
            if (runBtn) runBtn.disabled = false;
            ztSetProgress("", true);
            if (window.showToast) window.showToast(err.message || "Status polling failed.", "error");
        });
    }

    function ztFinishRun(reload) {
        ztStopPoll();
        ztRun.running = false;
        var runBtn = document.getElementById("ztRunBtn");
        if (runBtn) runBtn.disabled = false;
        ztSetProgress("Assessment complete. Refreshing findings\u2026", false);
        if (reload) loadData();
        setTimeout(function () { ztSetProgress("", true); }, 1800);
        if (window.showToast) window.showToast("Zero Trust assessment complete.", "success");
    }

    function ztDownload(filename, text, type) {
        var blob = new Blob([text], { type: type || "text/plain" });
        var url = URL.createObjectURL(blob);
        var a = document.createElement("a");
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
    }

    function ztCsvEscape(value) {
        var text = String(value == null ? "" : value);
        if (/[",\n]/.test(text)) return '"' + text.replace(/"/g, '""') + '"';
        return text;
    }

    function ztTestsFromAssessment(assessment) {
        var out = [];
        ["identity", "devices", "network", "data", "infrastructure"].forEach(function (key) {
            var bucket = assessment && assessment[key];
            ((bucket && bucket.tests) || []).forEach(function (t) { out.push(t); });
        });
        return out;
    }

    function ztExportCsv(assessment) {
        var tests = ztTestsFromAssessment(assessment);
        var header = ["assessmentId", "timestamp", "area", "name", "category", "risk", "status", "sfiPillar", "recommendation", "evidenceAvailable"];
        var lines = [header.join(",")];
        tests.forEach(function (t) {
            lines.push([
                assessment.assessmentId, assessment.completedAt || assessment.startedAt, t.area, t.name, t.category, t.risk, t.status,
                (t.sfiPillars || []).join(" "), t.recommendation || "", t.evidence && t.evidence.length ? "yes" : "no"
            ].map(ztCsvEscape).join(","));
        });
        ztDownload("zero-trust-results.csv", lines.join("\n"), "text/csv");
    }

    function ztExportJson(assessment) {
        ztDownload("zero-trust-assessment.json", JSON.stringify(assessment || {}, null, 2), "application/json");
    }

    function ztPrintSummary(assessment, exec) {
        if (!assessment) {
            if (window.showToast) window.showToast("No assessment to export.", "error");
            return;
        }
        var w = window.open("", "_blank");
        if (!w) return;
        function line(label, bucket) {
            var s = (bucket && bucket.summary) || {};
            return label + " passed " + (s.passed || 0) + " of " + (s.total || 0);
        }
        function esc(value) {
            return String(value == null ? "" : value)
                .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
        }
        w.document.write("<html><head><title>Zero Trust Assessment</title></head><body>");
        w.document.write("<h1>" + (exec ? "Executive summary" : "Zero Trust assessment") + "</h1>");
        w.document.write("<p>Assessment ID " + esc(assessment.assessmentId) + " · " + esc(assessment.completedAt || "") + "</p>");
        w.document.write("<p>" +
            line("Identity", assessment.identity) + ". " +
            line("Endpoint Device", assessment.devices) + ". " +
            line("Network", assessment.network) + ". " +
            line("Data", assessment.data) + ". " +
            line("Infrastructure", assessment.infrastructure) + ".</p>");
        if (exec) {
            w.document.write("<h2>Priority remediation</h2><ol>");
            (assessment.priority || []).forEach(function (t) {
                w.document.write("<li>" + esc(t.name) + " (" + esc(t.risk) + " / " + esc(t.status) + ")</li>");
            });
            w.document.write("</ol>");
        }
        w.document.write("</body></html>");
        w.document.close();
        w.focus();
        w.print();
    }

    function ztLoadAssessmentThen(kind) {
        var id = ztRun.assessmentId || "";
        try { id = id || localStorage.getItem(ZT_STORAGE_KEY) || ""; } catch (e) {}
        var runExport = function (assessment) {
            if (!assessment) {
                if (window.showToast) window.showToast("No assessment to export.", "error");
                return;
            }
            ztRun.assessment = assessment;
            if (kind === "csv") ztExportCsv(assessment);
            else if (kind === "json") ztExportJson(assessment);
            else if (kind === "print") ztPrintSummary(assessment, false);
            else ztPrintSummary(assessment, true);
        };
        if (ztRun.assessment && (!id || ztRun.assessment.assessmentId === id)) {
            runExport(ztRun.assessment);
            return;
        }
        var loadById = function (assessmentId) {
            if (!assessmentId) {
                if (window.showToast) window.showToast("No assessment to export.", "error");
                return;
            }
            ztJsonFetch("/api/zero-trust/results", { assessmentId: assessmentId }).then(function (data) {
                runExport(data.assessment);
            }).catch(function (err) {
                if (window.showToast) window.showToast(err.message || "Could not export assessment.", "error");
            });
        };
        if (id) {
            loadById(id);
            return;
        }
        fetch("/api/zero-trust/latest", {
            credentials: "same-origin",
            headers: { Accept: "application/json", "X-Requested-With": "XMLHttpRequest" }
        }).then(function (res) { return res.json().catch(function () { return {}; }); }).then(function (data) {
            loadById(data && data.assessmentId);
        }).catch(function () {
            if (window.showToast) window.showToast("Could not export assessment.", "error");
        });
    }

    function bindZeroTrustActions() {
        if (PAGE_DOMAIN !== "zero_trust") return;
        var runBtn = document.getElementById("ztRunBtn");
        var confirmModal = document.getElementById("ztConfirmModal");
        var confirmCancel = document.getElementById("ztConfirmCancel");
        var confirmRun = document.getElementById("ztConfirmRun");
        var exportBtn = document.getElementById("ztExportBtn");
        var exportMenu = document.getElementById("ztExportMenu");
        if (runBtn) runBtn.addEventListener("click", ztOpenConfirm);
        if (confirmCancel) confirmCancel.addEventListener("click", ztCloseConfirm);
        if (confirmRun) confirmRun.addEventListener("click", ztStartAssessment);
        if (confirmModal) {
            confirmModal.addEventListener("click", function (e) {
                if (e.target === confirmModal) ztCloseConfirm();
            });
        }
        if (exportBtn && exportMenu) {
            exportBtn.addEventListener("click", function (e) {
                e.stopPropagation();
                var open = exportMenu.hidden;
                exportMenu.hidden = !open;
                exportBtn.setAttribute("aria-expanded", open ? "true" : "false");
            });
            exportMenu.addEventListener("click", function (e) {
                var btn = e.target.closest("[data-export]");
                if (!btn) return;
                exportMenu.hidden = true;
                exportBtn.setAttribute("aria-expanded", "false");
                ztLoadAssessmentThen(btn.getAttribute("data-export"));
            });
            document.addEventListener("click", function () {
                exportMenu.hidden = true;
                exportBtn.setAttribute("aria-expanded", "false");
            });
        }
        document.addEventListener("keydown", function (e) {
            if (e.key === "Escape") {
                ztCloseConfirm();
                if (exportMenu) exportMenu.hidden = true;
            }
        });
        window.addEventListener("beforeunload", ztStopPoll);
    }

    loadFilters();
    loadSavedViews();
    bindChips("scopeChips", "domain");
    bindEvents();
    bindFirewallCombo();
    bindZeroTrustActions();
    load();
})();
