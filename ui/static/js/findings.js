(function () {
    "use strict";

    var root = document.getElementById("findingsRoot");
    var searchInput = document.getElementById("findingsSearch");
    var sortSelect = document.getElementById("sortSelect");
    var viewSelect = document.getElementById("viewSelect");

    var CATEGORY_ORDER = [
        "Software & Platform",
        "Capacity & Performance",
        "Security Services",
        "Networking",
        "VPN & Remote Access",
        "Administration",
        "Logging & Monitoring"
    ];

    var PRESET_VIEWS = [
        { id: "all", name: "All Findings", filters: { severity: "all", status: "all", domain: "all", firewall: "all", riskRange: "all", date: "all", search: "", sort: "severity" } },
        { id: "critical", name: "Critical Only", filters: { severity: "critical", status: "all", domain: "all", firewall: "all", riskRange: "all", date: "all", search: "", sort: "severity" } },
        { id: "high", name: "High Risk", filters: { severity: "high", status: "all", domain: "all", firewall: "all", riskRange: "all", date: "all", search: "", sort: "risk" } },
        { id: "operational", name: "Operational Risks", filters: { severity: "all", status: "non-compliant", domain: "all", firewall: "all", riskRange: "all", date: "all", search: "", sort: "risk" } },
        { id: "gaps", name: "Compliance Gaps", filters: { severity: "all", status: "non-compliant", domain: "all", firewall: "all", riskRange: "all", date: "all", search: "", sort: "domain" } },
        { id: "patching", name: "Patch Related", filters: { severity: "all", status: "non-compliant", domain: "Software & Platform", firewall: "all", riskRange: "all", date: "all", search: "", sort: "severity" } }
    ];

    var STORAGE_FILTERS = "findings.filters.v1";
    var STORAGE_VIEWS = "findings.views.v1";
    var STORAGE_REVIEWED = "findings.reviewed.v1";
    var STORAGE_ASSIGNEES = "findings.assignees.v1";

    function defaultFilters() {
        return { severity: "all", status: "all", domain: "all", firewall: "all", riskRange: "all", date: "all", search: "", sort: "severity" };
    }

    var state = {
        data: null,
        records: [],
        filters: defaultFilters(),
        customViews: [],
        reviewed: {},
        assignees: {},
        collapsed: {},
        inventory: [],
        loadedFirewall: null
    };

    function escapeHtml(v) {
        var d = document.createElement("div");
        d.textContent = v == null ? "" : String(v);
        return d.innerHTML;
    }

    function categoryFor(domain) {
        if (typeof FINDING_ENRICHMENT_CATEGORIES !== "undefined" && FINDING_ENRICHMENT_CATEGORIES[domain]) {
            return FINDING_ENRICHMENT_CATEGORIES[domain];
        }
        return "Administration";
    }

    function enrich(result, finding, meta, ctx) {
        var cid = (result.control || "").toUpperCase();
        var e = (typeof FINDING_ENRICHMENT !== "undefined" && FINDING_ENRICHMENT[cid]) ? FINDING_ENRICHMENT[cid] : null;
        var domain = (e && e.domain) || "General";
        var risk = (result.risk || "LOW").toUpperCase();
        var status = (result.status || "NON_COMPLIANT").toUpperCase();
        var compliant = status === "COMPLIANT";

        return {
            control: cid,
            metric: result.metric || "",
            observed: result.observed,
            expected: result.expected,
            operator: result.operator || "",
            status: status,
            risk: compliant ? "COMPLIANT" : risk,
            _compliant: compliant,
            _domain: domain,
            _category: categoryFor(domain),
            _check: (e && e.check) || (finding && finding.finding) || "Control " + cid,
            _method: (e && e.method) || "",
            _gap: (e && e.gap) || "",
            _impact: (e && e.impact) || "",
            _risk_score: compliant ? 0 : (e && e.risk_score) || defaultRiskScore(risk),
            _evidence: (e && e.evidence) || [],
            _finding: (finding && finding.finding) || "",
            _remediation: (finding && finding.remediation) || (e && e.remediation) || "",
            _detected: ctx.detected,
            _collected_at: ctx.collected_at,
            _run_id: ctx.run_id,
            _firewall: ctx.firewall.hostname,
            _model: ctx.firewall.model,
            _version: ctx.firewall.version
        };
    }

    function defaultRiskScore(risk) {
        return risk === "CRITICAL" ? 95 : risk === "HIGH" ? 72 : risk === "MEDIUM" ? 45 : 20;
    }

    var SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, COMPLIANT: 4 };

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
        var risk = rec.risk.toLowerCase();
        if (f.severity !== "all" && risk !== f.severity) return false;
        if (f.status !== "all") {
            if (f.status === "non-compliant" && rec.status !== "NON_COMPLIANT") return false;
            if (f.status === "compliant" && rec.status !== "COMPLIANT") return false;
            if (f.status === "not-assessed" && rec.status !== "NOT_ASSESSED") return false;
        }
        if (f.domain !== "all" && rec._category !== f.domain) return false;
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
            var hay = [rec.control, rec._check, rec._finding, rec._gap, rec._impact, rec._domain, rec._category, rec._firewall, rec.metric, rec._remediation, (rec._evidence || []).join(" ")].join(" ").toLowerCase();
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
        var opSym = OPERATOR_SYMBOLS[rec.operator] || "?";
        return '<div class="cmp-values">' +
            '<div class="cmp-block cmp-observed"><span class="cmp-block-label">Observed</span><span class="cmp-block-val">' + escapeHtml(formatVal(rec.observed)) + '</span></div>' +
            '<div class="cmp-op"><span class="cmp-op-sym">' + escapeHtml(opSym) + '</span><span class="cmp-op-label">' + escapeHtml(rec.operator || "") + '</span></div>' +
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
            '<span><span class="em-label">Metric</span> ' + escapeHtml(rec.metric || "\u2014") + '</span>' +
            '<span><span class="em-label">Source</span> ' + escapeHtml(srcs.length ? srcs[0] : "Assessment scan") + '</span>' +
            '<span><span class="em-label">Device</span> ' + escapeHtml(rec._firewall) + (rec._model ? " \u00b7 " + escapeHtml(rec._model) : "") + '</span>' +
            '<span><span class="em-label">Collected</span> ' + escapeHtml(formatTs(rec._collected_at || rec._detected)) + '</span>' +
            '<span><span class="em-label">Run</span> ' + escapeHtml(rec._run_id || "\u2014") + '</span>' +
            '</div>' +
            (srcChips ? '<div class="evidence-sources">' + srcChips + '</div>' : '') +
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
        var statusKey = rec.status;
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
            '<span class="status-badge ' + statusClass + '">' + statusKey + '</span>' +
            '</div>' +
            '<div class="finding-card-title">' + title + '</div>' +
            '<div class="finding-summary">' + escapeHtml(summary) + '</div>' +
            '<div class="finding-card-meta">' +
            '<div class="meta-item"><span class="meta-label">Domain</span><span class="meta-value">' + domain + '</span></div>' +
            '<div class="meta-item"><span class="meta-label">Firewall</span><span class="meta-value mono">' + fw + '</span></div>' +
            '<div class="meta-item"><span class="meta-label">Detected</span><span class="meta-value mono">' + detected + '</span></div>' +
            (isReviewed ? '<div class="meta-item"><span class="meta-label">Review</span><span class="meta-value ok">Reviewed</span></div>' : '') +
            (assignee ? '<div class="meta-item"><span class="meta-label">Owner</span><span class="meta-value owner">' + escapeHtml(assignee) + '</span></div>' : '') +
            '</div>' +
            '</div>' +
            '<span class="finding-chevron">' + ICONS.chevron + '</span>' +
            '<div class="finding-body">' +
            findingBodyHtml(rec) +
            actionsHtml(rec, isReviewed, !!assignee) +
            '</div>' +
            '</div>' +
            '</div>';
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
        CATEGORY_ORDER.forEach(function (c) { groups[c] = []; });
        records.forEach(function (r) {
            var c = r._category || "Administration";
            if (!groups[c]) groups[c] = [];
            groups[c].push(r);
        });

        var html = "";
        CATEGORY_ORDER.forEach(function (category) {
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

    function renderDomainChips() {
        var el = document.getElementById("domainChips");
        if (!el) return;
        var chips = '<button class="chip chip-domain is-active" data-value="all">All</button>';
        CATEGORY_ORDER.forEach(function (c) {
            chips += '<button class="chip chip-domain" data-value="' + escapeHtml(c) + '">' + escapeHtml(c) + '</button>';
        });
        el.innerHTML = chips;
    }

    function firewallOptionNames() {
        var names = [];
        (state.inventory || []).forEach(function (e) {
            if (e && e.device_name && names.indexOf(e.device_name) === -1) names.push(e.device_name);
        });
        if (state.data && state.data.firewalls) {
            (state.data.firewalls || []).forEach(function (f) {
                if (f && f.hostname && names.indexOf(f.hostname) === -1) names.push(f.hostname);
            });
        }
        return names;
    }

    function populateFirewallSelect(firewalls) {
        var el = document.getElementById("firewallSelect");
        if (!el) return;
        var names = firewallOptionNames();
        var html = '<option value="all">All</option>';
        names.forEach(function (n) {
            html += '<option value="' + escapeHtml(n) + '">' + escapeHtml(n) + "</option>";
        });
        el.innerHTML = html;
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
        if (value === (state.loadedFirewall || "all")) {
            applyFilters();
            return;
        }
        loadData(value);
    }

    function bindFirewallCombo() {
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

    function populateDateSelect(history) {
        var el = document.getElementById("dateSelect");
        if (!el) return;
        var html = '<option value="all">All dates</option>';
        var seen = {};
        (history || []).forEach(function (s) {
            var key = dateKey(s.ts);
            if (!key || seen[key]) return;
            seen[key] = true;
            html += '<option value="' + key + '">' + formatShortTs(s.ts) + '</option>';
        });
        el.innerHTML = html;
    }

    function dateKey(ts) {
        var d = parseDate(ts);
        if (!d) return null;
        return d.getFullYear() + "-" + String(d.getMonth() + 1).padStart(2, "0") + "-" + String(d.getDate()).padStart(2, "0");
    }

    function syncFilterChips() {
        var sev = document.getElementById("severitySelect");
        if (sev) sev.value = state.filters.severity;
        var st = document.getElementById("statusSelect");
        if (st) st.value = state.filters.status;
        syncChipGroup("domainChips", state.filters.domain);
        var fw = document.getElementById("firewallSelect");
        if (fw) fw.value = state.filters.firewall;
        var rr = document.getElementById("riskRangeSelect");
        if (rr) rr.value = state.filters.riskRange;
        var dt = document.getElementById("dateSelect");
        if (dt) dt.value = state.filters.date;
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
            { key: "domain", label: "Domain" },
            { key: "firewall", label: "Firewall" },
            { key: "riskRange", label: "Risk", labels: { critical: "90\u2013100", high: "70\u201389", medium: "40\u201369", low: "0\u201339" } },
            { key: "date", label: "Assessment" }
        ];
        defs.forEach(function (d) {
            var v = f[d.key];
            if (!v || v === "all") return;
            var label = d.labels && d.labels[v] ? d.labels[v] : v;
            pills.push('<span class="active-pill" data-key="' + d.key + '"><span class="active-pill-label">' + d.label + ':</span> ' + escapeHtml(label) + '<button class="active-pill-x" type="button" aria-label="Remove filter">&times;</button></span>');
        });
        if (f.search) {
            pills.push('<span class="active-pill" data-key="search"><span class="active-pill-label">Search:</span> ' + escapeHtml(f.search) + '<button class="active-pill-x" type="button" aria-label="Remove filter">&times;</button></span>');
        }
        el.innerHTML = pills.join("");
    }

    function bindChips(id, key) {
        var el = document.getElementById(id);
        if (!el) return;
        el.addEventListener("click", function (e) {
            var chip = e.target.closest(".chip");
            if (!chip) return;
            state.filters[key] = chip.getAttribute("data-value") || "all";
            applyFilters();
        });
    }

    function applyFilters() {
        saveFilters();
        syncFilterChips();
        renderAll();
    }

    function resetFilters() {
        state.filters = defaultFilters();
        state.filters.firewall = state.loadedFirewall || "all";
        if (sortSelect) sortSelect.value = state.filters.sort;
        if (searchInput) searchInput.value = "";
        if (viewSelect) viewSelect.value = "all";
        applyFilters();
        reflectFirewallUI();
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
        if (sortSelect) sortSelect.value = state.filters.sort;
        if (searchInput) searchInput.value = state.filters.search || "";
        applyFilters();
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
        try {
            var saved = JSON.parse(localStorage.getItem(STORAGE_FILTERS) || "null");
            if (saved && typeof saved === "object") state.filters = Object.assign(defaultFilters(), saved);
        } catch (e) { /* ignore */ }
        try {
            var params = new URLSearchParams(window.location.search);
            if (params.get("status")) state.filters.status = params.get("status");
            if (params.get("domain")) state.filters.domain = params.get("domain");
            if (params.get("severity")) state.filters.severity = params.get("severity");
            if (params.get("search")) state.filters.search = params.get("search");
        } catch (e) { /* ignore */ }
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
            if (window.showToast) window.showToast("Firewall: " + rec._firewall + " \u00b7 " + rec._model + " \u00b7 PAN-OS " + rec._version, "info");
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
                } else {
                    handleOperationalAction(act, rec);
                }
                return;
            }

            var card = e.target.closest(".finding-card");
            if (card) {
                var wasActive = card.classList.contains("is-active");
                card.classList.toggle("is-active");
                card.setAttribute("aria-expanded", String(!wasActive));
            }
        });

        root.addEventListener("keydown", function (e) {
            if ((e.key === "Enter" || e.key === " ") && e.target.classList.contains("finding-card")) {
                e.preventDefault();
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
                applyFilters();
            });
        }

        var stSelect = document.getElementById("statusSelect");
        if (stSelect) {
            stSelect.addEventListener("change", function () {
                state.filters.status = stSelect.value;
                applyFilters();
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
                applyFilters();
            });
        }

        var dateSelect = document.getElementById("dateSelect");
        if (dateSelect) {
            dateSelect.addEventListener("change", function () {
                state.filters.date = dateSelect.value;
                applyFilters();
            });
        }

        var activeFilters = document.getElementById("activeFilters");
        if (activeFilters) {
            activeFilters.addEventListener("click", function (e) {
                var pill = e.target.closest(".active-pill");
                if (!pill) return;
                var key = pill.getAttribute("data-key");
                if (key === "search") state.filters.search = "";
                else state.filters[key] = "all";
                if (searchInput && key === "search") searchInput.value = "";
                applyFilters();
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
            CATEGORY_ORDER.forEach(function (c) { state.collapsed[c] = true; });
            document.querySelectorAll(".group-section").forEach(function (s) { s.classList.add("is-collapsed"); });
        });
        document.getElementById("btnExportReport").addEventListener("click", generateReport);

        document.getElementById("copilotClose").addEventListener("click", closeCopilot);
        document.getElementById("copilotBackdrop").addEventListener("click", closeCopilot);
        document.getElementById("copilotActions").addEventListener("click", function (e) {
            var chip = e.target.closest(".copilot-chip");
            if (!chip) return;
            runCopilot(chip.getAttribute("data-action"));
        });

        document.addEventListener("keydown", function (e) {
            if (e.key === "Escape") closeCopilot();
        });
    }

    function findRecord(cid, fw) {
        return state.records.find(function (r) {
            return r.control === cid && (!fw || !isEstateView() || r._firewall === fw);
        });
    }

    function isEstateView() {
        return (state.loadedFirewall || "all") === "all";
    }

    function recKey(rec) {
        return (isEstateView() ? (rec._firewall || "?") + "::" : "") + rec.control;
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

    function formatShortTs(ts) {
        var d = parseDate(ts);
        if (!d) return "";
        return d.toLocaleString(undefined, { month: "short", day: "numeric" });
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
        fetch("/api/firewall-inventory")
            .then(function (r) { return r.json(); })
            .then(function (data) {
                state.inventory = (data && data.firewalls) || [];
                var names = (state.inventory || []).map(function (e) { return e.device_name; }).filter(Boolean);
                var params = new URLSearchParams(window.location.search);
                var stored = (state.filters.firewall && state.filters.firewall !== "all") ? state.filters.firewall : null;
                var fw = params.get("firewall") || stored || names[0] || "vmpafw01";
                if (fw !== "all" && names.length && names.indexOf(fw) === -1) fw = "all";
                return loadData(fw);
            })
            .catch(function () {
                state.inventory = [];
                var params = new URLSearchParams(window.location.search);
                return loadData(params.get("firewall") || "all");
            });
    }

    function loadData(fw) {
        state.loadedFirewall = fw || "all";
        state.filters.firewall = state.loadedFirewall;
        if (root && window.loadingHtml) {
            root.innerHTML = '<div class="empty-state card">' + window.loadingHtml("Loading findings…") + "</div>";
        }
        var req = state.loadedFirewall === "all"
            ? "/api/estate/assessment"
            : "/api/findings?firewall=" + encodeURIComponent(state.loadedFirewall);
        fetch(req)
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (!data || data.error) {
                    if (root) root.innerHTML = '<div class="empty-state card"><h4>No findings available</h4><p>Run an assessment from the AI Workspace to populate findings.</p></div>';
                    reflectFirewallUI();
                    return;
                }
                if (state.loadedFirewall === "all") renderEstateFindings(data);
                else renderPostureFindings(data);
            })
            .catch(function () {
                if (root) root.innerHTML = '<div class="empty-state card"><h4>Unable to load findings</h4></div>';
                reflectFirewallUI();
            });
    }

    function renderPostureFindings(data) {
        state.data = data;
        var posture = data.posture || {};
        var ctx = {
            detected: data._collected_at ? String(data._collected_at).slice(0, 10) : new Date().toISOString().slice(0, 10),
            collected_at: data._collected_at || posture.collected_at,
            run_id: posture.run_id || "\u2014",
            firewall: data.firewall || { hostname: "edge-fw-01", model: "", version: "" }
        };
        var findingMap = {};
        (data.findings || []).forEach(function (f) { findingMap[(f.control || "").toUpperCase()] = f; });
        state.records = (data.assessment || []).map(function (r) {
            return enrich(r, findingMap[(r.control || "").toUpperCase()], null, ctx);
        });
        finishFindingsRender();
    }

    function renderEstateFindings(data) {
        var devices = data.devices || [];
        var cumulative = data.cumulative || {};
        var detected = data._collected_at ? String(data._collected_at).slice(0, 10) : new Date().toISOString().slice(0, 10);
        var records = [];
        devices.forEach(function (dev) {
            var ctx = {
                detected: detected,
                collected_at: dev.collected_at,
                run_id: "Estate",
                firewall: { hostname: dev.device, model: "", version: "" }
            };
            var map = {};
            (dev.findings || []).forEach(function (f) { map[(f.control || "").toUpperCase()] = f; });
            (dev.assessment || []).forEach(function (r) {
                records.push(enrich(r, map[(r.control || "").toUpperCase()], null, ctx));
            });
        });
        state.records = records;
        state.data = {
            posture: {
                run_id: "Estate",
                compliance_pct: cumulative.compliance_score_pct,
                compliant: cumulative.total_compliant,
                non_compliant: cumulative.total_non_compliant,
                not_assessed: cumulative.total_not_assessed,
                total_controls: cumulative.total_controls
            },
            firewall: { hostname: "All devices", model: "", version: "" },
            firewalls: devices.map(function (d) { return { hostname: d.device, model: "", version: "" }; }),
            findings: [],
            assessment: [],
            history: [],
            _collected_at: data._collected_at
        };
        finishFindingsRender();
    }

    function finishFindingsRender() {
        renderDomainChips();
        populateFirewallSelect(state.data ? state.data.firewalls : []);
        populateDateSelect((state.data && state.data.history) || []);
        populateViewSelect();
        if (sortSelect) sortSelect.value = state.filters.sort;
        if (searchInput) searchInput.value = state.filters.search || "";
        syncFilterChips();
        saveFilters();
        reflectFirewallUI();
        renderAll();
    }

    loadFilters();
    loadSavedViews();
    bindChips("domainChips", "domain");
    bindEvents();
    bindFirewallCombo();
    load();
})();
