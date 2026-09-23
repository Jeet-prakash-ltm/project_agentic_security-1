(function () {
    "use strict";

    var sourceBadge = document.getElementById("dataSourceBadge");
    var refreshBtn = document.getElementById("refreshBtn");

    var CATEGORY_ORDER = [
        "Software & Platform",
        "Capacity & Performance",
        "Security Services",
        "Networking",
        "VPN & Remote Access",
        "Administration",
        "Logging & Monitoring"
    ];

    var COLORS = { vmpafw01: "#ff5e4f", vmpafw02: "#2563EB" };
    var FALLBACK_COLORS = ["#ff5e4f", "#2563EB", "#16A34A", "#F59E0B", "#8B5CF6", "#06B6D4", "#EC4899", "#14B8A6"];

    var ALL = "all";

    var state = {
        firewalls: [ALL],
        inventory: [],
        source: null,
        status: {}
    };

    function isAll() {
        return !state.firewalls.length || state.firewalls.indexOf(ALL) !== -1;
    }

    function selectedFirewalls() {
        return isAll() ? [ALL] : state.firewalls.slice();
    }

    function scopeFirewall() {
        return isAll() ? ALL : state.firewalls[0];
    }

    function colorFor(fw) {
        if (fw === ALL) return "#ff5e4f";
        if (COLORS[fw]) return COLORS[fw];
        var hash = 0;
        for (var i = 0; i < fw.length; i++) hash = (hash * 31 + fw.charCodeAt(i)) % 9973;
        return FALLBACK_COLORS[hash % FALLBACK_COLORS.length];
    }

    function statusClass(fw) {
        var s = state.status[fw];
        return s === "live" ? "is-live" : s === "down" ? "is-down" : "is-pending";
    }

    function updateChipDots() {
        var chips = document.querySelectorAll("#dashSelection .dash-chip");
        for (var i = 0; i < chips.length; i++) {
            var dot = chips[i].querySelector(".dash-chip-dot");
            if (!dot) continue;
            var fw = chips[i].getAttribute("data-fw") || ALL;
            dot.className = "dash-chip-dot " + statusClass(fw);
        }
    }

    function setSource(source) {
        if (!sourceBadge) return;
        var label = source === "live" ? "Live Data" : "Sample Data";
        sourceBadge.innerHTML = '<span class="pulse-dot"></span> ' + label;
        sourceBadge.style.borderColor = source === "live" ? "rgba(34, 197, 94, 0.5)" : "rgba(245, 158, 11, 0.5)";
        sourceBadge.style.color = source === "live" ? "#059669" : "#B45309";
    }

    function escapeHtml(value) {
        var d = document.createElement("div");
        d.textContent = value == null ? "" : String(value);
        return d.innerHTML;
    }

    function loadingHtml(text) {
        if (typeof window.loadingHtml === "function") return window.loadingHtml(text);
        return '<div class="section-loading"><span class="spinner"></span><span>' + text + "</span></div>";
    }

    // Every dashboard link is scoped to the firewall group it belongs to.
    function findingsUrl(fw, key, value) {
        var params = [];
        if (key) params.push(key + "=" + encodeURIComponent(value));
        if (fw && fw !== ALL) params.push("firewall=" + encodeURIComponent(fw));
        return "/findings" + (params.length ? "?" + params.join("&") : "");
    }

    function parseDate(ts) {
        if (typeof ts === "number") return new Date(ts * 1000);
        var d = new Date(ts);
        return isNaN(d.getTime()) ? null : d;
    }

    function formatShortTs(ts) {
        var d = parseDate(ts);
        if (!d) return "";
        return d.toLocaleString(undefined, { month: "short", day: "numeric" });
    }

    // ============================================================
    // GROUP SHELL (one block of sections per selected firewall)
    // ============================================================

    function sectionPanel(title, extraHead, bodyHtml) {
        return '<section class="card dash-panel is-loading">' +
            '<div class="section-head"><h3>' + escapeHtml(title) + "</h3>" + (extraHead || "") + "</div>" +
            (bodyHtml || "") +
            '<div class="section-loading section-loading-overlay"><span class="spinner"></span><span class="section-loading-text">Loading</span></div>' +
            "</section>";
    }

    function groupShell(fw) {
        var pie =
            '<section class="dash-grid-2">' +
            '<div class="card dash-panel pie-panel is-loading">' +
            '<div class="section-head"><h3>Compliance Score</h3></div>' +
            '<div class="donut-wrap">' +
            '<svg class="compliance-pie" viewBox="0 0 200 200" aria-label="Compliance donut"></svg>' +
            '<div class="donut-center">' +
            '<strong class="donut-percent">—%</strong>' +
            "<span>Compliance Score</span>" +
            '<em class="donut-status">—</em>' +
            "</div>" +
            "</div>" +
            '<div class="donut-pills"></div>' +
            '<div class="section-loading section-loading-overlay"><span class="spinner"></span><span class="section-loading-text">Loading</span></div>' +
            "</div>" +
            sectionPanel("Findings by Severity", "", '<div class="severity-grid"></div>') +
            "</section>";

        var recent =
            '<section class="card dash-panel is-loading">' +
            '<div class="section-head"><h3>Recent Findings</h3>' +
            '<a href="' + findingsUrl(fw, null, null) + '" class="view-all">View All &rarr;</a></div>' +
            '<div class="recent-findings"></div>' +
            '<div class="section-loading section-loading-overlay"><span class="spinner"></span><span class="section-loading-text">Loading</span></div>' +
            "</section>";

        var domains = sectionPanel("Top Risk Domains", "", '<div class="vertical-bars"></div>');

        var trend =
            '<section class="compliance-trend-section card is-loading">' +
            '<div class="section-head">' +
            "<div><h3>Compliance Trend</h3>" +
            '<span class="section-sub">Historical compliance score over time</span></div>' +
            '<div class="trend-stats"></div>' +
            "</div>" +
            '<div class="trend-chart"></div>' +
            '<div class="section-loading section-loading-overlay"><span class="spinner"></span><span class="section-loading-text">Loading</span></div>' +
            "</section>";

        return '<section class="dash-group" data-fw="' + escapeHtml(fw) + '">' +
            pie + recent + domains + trend + "</section>";
    }

    function clearSection(el) {
        if (!el) return;
        el.classList.remove("is-loading");
        var overlays = el.querySelectorAll(":scope > .section-loading-overlay");
        for (var i = 0; i < overlays.length; i++) {
            overlays[i].parentNode.removeChild(overlays[i]);
        }
    }

    function groupSection(root, selector) {
        return root ? root.querySelector(selector) : null;
    }

    // ============================================================
    // COMPLIANCE PIE (square, hover/click per segment)
    // ============================================================

    function polar(cx, cy, r, angleDeg) {
        var rad = (angleDeg - 90) * Math.PI / 180;
        return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
    }

    function donutSegmentPath(cx, cy, outerR, innerR, start, end) {
        var s = polar(cx, cy, outerR, start);
        var e = polar(cx, cy, outerR, end);
        var is = polar(cx, cy, innerR, end);
        var ie = polar(cx, cy, innerR, start);
        var large = (end - start) > 180 ? 1 : 0;
        return "M" + s.x.toFixed(1) + " " + s.y.toFixed(1) +
            " A" + outerR + " " + outerR + " 0 " + large + " 1 " + e.x.toFixed(1) + " " + e.y.toFixed(1) +
            " L" + is.x.toFixed(1) + " " + is.y.toFixed(1) +
            " A" + innerR + " " + innerR + " 0 " + large + " 0 " + ie.x.toFixed(1) + " " + ie.y.toFixed(1) + " Z";
    }

    function renderCompliancePie(root, c, fw) {
        var panel = groupSection(root, ".pie-panel");
        if (!panel) return;
        var svg = panel.querySelector(".compliance-pie");
        var percentEl = panel.querySelector(".donut-percent");
        var statusEl = panel.querySelector(".donut-status");
        var pills = panel.querySelector(".donut-pills");

        var compliant = Number(c.compliant) || 0;
        var nonCompliant = Number(c.non_compliant) || 0;
        var notAssessed = Number(c.not_assessed) || 0;
        var total = compliant + nonCompliant + notAssessed;
        var pct = total ? Math.round(compliant / total * 100) : 0;

        function statusText(v) {
            return v >= 80 ? "Healthy Posture" : v >= 50 ? "At Risk" : "Critical Posture";
        }
        if (percentEl) percentEl.textContent = pct + "%";
        if (statusEl) statusEl.textContent = statusText(pct);

        var cx = 100, cy = 100, outerR = 92, innerR = 62;
        var segments = [
            { value: compliant, color: "#16A34A", label: "Compliant", status: "compliant" },
            { value: nonCompliant, color: "#DC2626", label: "Non-Compliant", status: "non-compliant" },
            { value: notAssessed, color: "#F59E0B", label: "Not Assessed", status: "not-assessed" }
        ];
        var totalSeg = Math.max(total, 1);
        var angle = 0;
        var html = "";
        segments.forEach(function (s) {
            if (s.value <= 0) return;
            var sweep = s.value / totalSeg * 360;
            html += '<path class="donut-seg" d="' + donutSegmentPath(cx, cy, outerR, innerR, angle, angle + sweep) + '" fill="' + s.color + '" ' +
                'data-status="' + s.status + '" data-label="' + s.label + '" data-value="' + s.value + '">' +
                "<title>" + s.label + ": " + s.value + "</title></path>";
            angle += sweep;
        });
        if (html === "") {
            html = '<circle class="donut-empty" cx="100" cy="100" r="92" fill="#F1F5F9"/>';
        }
        if (svg) svg.innerHTML = html;

        if (svg) {
            svg.querySelectorAll(".donut-seg").forEach(function (seg) {
                seg.addEventListener("mouseover", function () {
                    if (percentEl) percentEl.textContent = seg.getAttribute("data-value");
                    if (statusEl) statusEl.textContent = seg.getAttribute("data-label");
                });
                seg.addEventListener("mouseout", function () {
                    if (percentEl) percentEl.textContent = pct + "%";
                    if (statusEl) statusEl.textContent = statusText(pct);
                });
                seg.addEventListener("click", function () {
                    window.location.href = findingsUrl(fw, "status", seg.getAttribute("data-status"));
                });
            });
        }

        if (pills) {
            var defs = [
                { label: "Compliant", count: compliant, color: "#16A34A", status: "compliant" },
                { label: "Non-Compliant", count: nonCompliant, color: "#DC2626", status: "non-compliant" },
                { label: "Not Assessed", count: notAssessed, color: "#F59E0B", status: "not-assessed" }
            ];
            var pillHtml = "";
            defs.forEach(function (d) {
                var pctV = total ? Math.round(d.count / total * 100) : 0;
                pillHtml += '<button class="donut-pill" data-status="' + d.status + '" type="button">' +
                    '<i class="donut-dot" style="background:' + d.color + '"></i>' +
                    "<span>" + d.label + "</span>" +
                    "<strong>" + d.count + "</strong>" +
                    "<em>" + pctV + "%</em>" +
                    "</button>";
            });
            pills.innerHTML = pillHtml;
            pills.querySelectorAll(".donut-pill").forEach(function (pill) {
                pill.addEventListener("click", function () {
                    window.location.href = findingsUrl(fw, "status", pill.getAttribute("data-status"));
                });
            });
        }

        clearSection(panel);
    }

    // ============================================================
    // FINDINGS BY SEVERITY (horizontal bar graph)
    // ============================================================

    function renderSeverityGrid(root, f, fw) {
        var panel = groupSection(root, ".severity-grid");
        if (!panel) return;
        var sev = [
            { label: "Critical", color: "#DC2626", count: f.critical || 0, status: "critical" },
            { label: "High", color: "#F97316", count: f.high || 0, status: "high" },
            { label: "Medium", color: "#F59E0B", count: f.medium || 0, status: "medium" },
            { label: "Low", color: "#22C55E", count: f.low || 0, status: "low" }
        ];
        var max = 1;
        sev.forEach(function (s) { max = Math.max(max, s.count); });
        var html = "";
        sev.forEach(function (s) {
            var width = Math.round(s.count / max * 100);
            html += '<a class="sev-bar" href="' + findingsUrl(fw, "severity", s.status) + '" title="' + s.label + ': ' + s.count + ' findings">' +
                '<span class="sev-bar-head">' +
                '<span class="sev-bar-label">' + s.label + "</span>" +
                '<span class="sev-bar-count">' + s.count + "</span>" +
                "</span>" +
                '<span class="sev-bar-track">' +
                '<span class="sev-bar-fill" style="width:' + width + "%;background:" + s.color + '"></span>' +
                "</span>" +
                "</a>";
        });
        panel.innerHTML = html;
        clearSection(panel.closest(".dash-panel"));
    }

    // ============================================================
    // RECENT FINDINGS
    // ============================================================

    function renderRecentFindings(root, recent) {
        var panel = groupSection(root, ".recent-findings");
        if (!panel) return;
        if (!recent.length) {
            panel.innerHTML = '<p class="empty-inline">No findings.</p>';
            clearSection(panel.closest(".dash-panel"));
            return;
        }
        var html = "";
        recent.forEach(function (f) {
            var risk = (f.risk || "LOW").toLowerCase();
            var cls = risk === "critical" ? "bad" : risk === "high" ? "warn" : risk === "medium" ? "flat" : "good";
            html += '<div class="recent-finding">' +
                '<span class="recent-finding-control">' + escapeHtml(f.control || "") + "</span>" +
                '<span class="recent-finding-title">' + escapeHtml(f.title || "") + "</span>" +
                '<span class="recent-finding-risk ' + cls + '">' + escapeHtml(f.risk || "LOW") + "</span>" +
                "</div>";
        });
        panel.innerHTML = html;
        clearSection(panel.closest(".dash-panel"));
    }

    // ============================================================
    // TOP RISK DOMAINS (vertical bar graph, 7 categories)
    // ============================================================

    function categoryForControl(control) {
        var cid = (control || "").toUpperCase();
        var domain = (typeof FINDING_ENRICHMENT !== "undefined" && FINDING_ENRICHMENT[cid]) ? FINDING_ENRICHMENT[cid].domain : null;
        if (!domain) return null;
        return (typeof FINDING_ENRICHMENT_CATEGORIES !== "undefined" && FINDING_ENRICHMENT_CATEGORIES[domain]) || domain;
    }

    function renderVerticalBars(root, findingsList, fw) {
        var panel = groupSection(root, ".vertical-bars");
        if (!panel) return;
        var counts = {};
        (findingsList || []).forEach(function (f) {
            var cat = categoryForControl(f.control);
            if (cat) counts[cat] = (counts[cat] || 0) + 1;
        });
        var max = 1;
        CATEGORY_ORDER.forEach(function (c) { max = Math.max(max, counts[c] || 0); });

        var html = '<div class="vertical-bars-axis">';
        CATEGORY_ORDER.forEach(function (cat) {
            var n = counts[cat] || 0;
            var h = max ? Math.round(n / max * 100) : 0;
            html += '<a class="vbar" href="' + findingsUrl(fw, "domain", cat) + '" title="' + escapeHtml(cat) + ": " + n + '">' +
                '<span class="vbar-count">' + n + "</span>" +
                '<span class="vbar-track"><span class="vbar-fill" style="height:' + h + '%"></span></span>' +
                '<span class="vbar-label">' + escapeHtml(shortLabel(cat)) + "</span>" +
                "</a>";
        });
        html += "</div>";
        panel.innerHTML = html;
        clearSection(panel.closest(".dash-panel"));
    }

    function shortLabel(cat) {
        return cat.replace(" & Remote Access", "").replace(" & Platform", "").replace(" & Performance", "").replace(" & Monitoring", "").replace(" &", "");
    }

    // ============================================================
    // COMPLIANCE TREND
    // ============================================================

    function aggregateDaily(points) {
        var byDay = {};
        var order = [];
        (points || []).forEach(function (p) {
            if (p == null || typeof p.ts !== "number") return;
            var day = Math.floor(p.ts / 86400);
            if (byDay[day] === undefined) {
                byDay[day] = { ts: p.ts, value: p.value };
                order.push(day);
            } else {
                byDay[day].ts = p.ts;
                byDay[day].value = p.value;
            }
        });
        return order.sort(function (a, b) { return a - b; }).map(function (d) {
            return byDay[d];
        });
    }

    function buildTrendSeries(history, firewallId) {
        var snapshots = (history || []).filter(function (s) {
            return s && typeof s.compliance_pct === "number";
        });
        if (firewallId !== "all") {
            return [{
                name: firewallId,
                points: snapshots
                    .filter(function (s) {
                        return (s.firewall_name || "vmpafw01") === firewallId;
                    })
                    .map(function (s) { return { ts: s.ts, value: s.compliance_pct }; })
                    .sort(function (a, b) { return a.ts - b.ts; })
            }];
        }
        var byTs = {};
        snapshots.forEach(function (s) {
            if (s.ts == null) return;
            if (!byTs[s.ts]) byTs[s.ts] = [];
            byTs[s.ts].push(s.compliance_pct);
        });
        var points = Object.keys(byTs).map(function (ts) {
            var values = byTs[ts];
            var avg = values.reduce(function (a, b) { return a + b; }, 0) / values.length;
            return { ts: Number(ts), value: Math.round(avg * 10) / 10 };
        }).sort(function (a, b) { return a.ts - b.ts; });
        return [{ name: "All Firewalls", points: points }];
    }

    function renderTrendStats(root, history, firewallId, complianceScore) {
        var el = groupSection(root, ".trend-stats");
        if (!el) return;
        var series = buildTrendSeries(history, firewallId);
        var points = (series[0] && series[0].points) || [];
        var current = points.length
            ? points[points.length - 1].value
            : (typeof complianceScore === "number" ? complianceScore : null);
        if (current == null) { el.innerHTML = ""; return; }
        var prev = points.length > 1 ? points[points.length - 2].value : null;
        var improvement = prev != null ? Math.round((current - prev) * 10) / 10 : null;
        var impCls = improvement == null ? "" : improvement > 0 ? "good" : improvement < 0 ? "bad" : "flat";
        var impText = improvement == null ? "\u2014" : (improvement > 0 ? "+" : "") + improvement + "%";

        el.innerHTML =
            '<span class="trend-stat"><span>Current Score</span><strong>' + current + "%</strong></span>" +
            '<span class="trend-stat"><span>Previous Scan</span><strong>' + (prev != null ? prev + "%" : "\u2014") + "</strong></span>" +
            '<span class="trend-stat"><span>Improvement</span><strong class="' + impCls + '">' + impText + "</strong></span>";
    }

    function renderComplianceTrend(root, history, firewallId) {
        var el = groupSection(root, ".trend-chart");
        var section = groupSection(root, ".compliance-trend-section");
        if (!el) return;

        var series = buildTrendSeries(history, firewallId).filter(function (s) {
            return s.points.length > 0;
        });
        if (!series.length) {
            el.innerHTML = '<p class="trend-summary">No history yet. Run an assessment to start tracking compliance.</p>';
            clearSection(section);
            return;
        }

        var points = aggregateDaily(series[0].points);
        var times = points.map(function (p) { return p.ts; });
        if (times.length > 30) times = times.slice(times.length - 30);
        var n = times.length;

        var W = 900, H = 160;
        var PAD_LEFT = 36, PAD_RIGHT = 12, PAD_TOP = 12, PAD_BOTTOM = 22;
        var min = 0, max = 100;

        function x(ts) {
            var idx = times.indexOf(ts);
            if (n === 1) return PAD_LEFT + (W - PAD_LEFT - PAD_RIGHT) / 2;
            return PAD_LEFT + (idx / (n - 1)) * (W - PAD_LEFT - PAD_RIGHT);
        }
        function y(v) {
            return PAD_TOP + (1 - (v - min) / (max - min)) * (H - PAD_TOP - PAD_BOTTOM);
        }

        var color = firewallId === "all" ? "#ff5e4f" : colorFor(firewallId);

        var html = '<svg class="trend-line-svg" viewBox="0 0 ' + W + " " + H + '" preserveAspectRatio="none" role="img" aria-label="Compliance score over time">';

        for (var g = 0; g <= 4; g++) {
            var gv = g * 25;
            var gy = y(gv);
            html += '<line x1="' + PAD_LEFT + '" y1="' + gy.toFixed(1) + '" x2="' + (W - PAD_RIGHT) + '" y2="' + gy.toFixed(1) + '" class="trend-grid"/>';
            html += '<text x="' + (PAD_LEFT - 8) + '" y="' + (gy + 3).toFixed(1) + '" class="trend-axis-label" text-anchor="end">' + gv + "</text>";
        }

        var pts = points.filter(function (p) { return times.indexOf(p.ts) !== -1; });
        if (pts.length === 1) {
            var p = pts[0];
            html += '<circle cx="' + x(p.ts).toFixed(1) + '" cy="' + y(p.value).toFixed(1) + '" r="4" fill="' + color + '"><title>' + escapeHtml(series[0].name + ": " + p.value + "%") + "</title></circle>";
        } else if (pts.length > 1) {
            var line = "M" + pts.map(function (p) { return x(p.ts).toFixed(1) + " " + y(p.value).toFixed(1); }).join(" L");
            html += '<path d="' + line + '" fill="none" stroke="' + color + '" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" vector-effect="non-scaling-stroke"/>';
            pts.forEach(function (p) {
                html += '<circle cx="' + x(p.ts).toFixed(1) + '" cy="' + y(p.value).toFixed(1) + '" r="2.6" fill="' + color + '" vector-effect="non-scaling-stroke"><title>' + escapeHtml(series[0].name + ": " + p.value + "%") + "</title></circle>";
            });
        }

        html += "</svg>";
        html += '<div class="trend-labels">';
        times.forEach(function (ts, i) {
            if (i === 0 || i === n - 1 || i === Math.floor((n - 1) / 2)) {
                html += '<span class="trend-label">' + escapeHtml(formatShortTs(ts)) + "</span>";
            } else {
                html += '<span class="trend-label"></span>';
            }
        });
        html += "</div>";

        html += '<div class="trend-legend"><span class="trend-legend-item"><i style="background:' + color + '"></i>' + escapeHtml(series[0].name) + "</span></div>";

        el.innerHTML = html;
        clearSection(section);
    }

    // ============================================================
    // MAIN
    // ============================================================

    function updateScope() {
        var fw = scopeFirewall();
        var assess = document.getElementById("quickAssess");
        var summary = document.getElementById("quickSummary");
        var report = document.getElementById("quickReport");
        if (assess) {
            assess.href = fw === "all"
                ? "/workspace"
                : "/run-assessment?firewall=" + encodeURIComponent(fw);
        }
        if (summary) {
            summary.href = fw === "all"
                ? "/reports?firewall=all"
                : "/executive-summary?firewall=" + encodeURIComponent(fw);
        }
        if (report) report.href = "/generate-excel?firewall=" + encodeURIComponent(fw);
    }

    function applyNetsecData(root, data, fw) {
        var c = data.compliance || {};
        var cid = data.firewall_id || fw;
        state.status[fw] = c.source === "live" ? "live" : "down";
        if (c.source === "live") state.source = "live";
        else if (!state.source) state.source = "sample";
        var dot = root && root.querySelector(".dash-group-dot");
        if (dot) dot.className = "dash-group-dot " + statusClass(fw);
        updateChipDots();
        renderCompliancePie(root, c, cid);
        renderSeverityGrid(root, data.findings || {}, cid);
        renderRecentFindings(root, data.recent_findings || []);
        renderVerticalBars(root, data.findings_list || [], cid);
        renderTrendStats(root, data.history || [], cid, c.compliance_score);
        renderComplianceTrend(root, data.history || [], cid);
    }

    function applyGroupError(root, fw) {
        if (fw) state.status[fw] = "down";
        if (root) {
            var dot = root.querySelector(".dash-group-dot");
            if (dot) dot.className = "dash-group-dot " + statusClass(fw);
        }
        updateChipDots();
        var sections = root.querySelectorAll(".is-loading");
        for (var i = 0; i < sections.length; i++) {
            clearSection(sections[i]);
        }
        var recent = groupSection(root, ".recent-findings");
        if (recent) recent.innerHTML = '<p class="empty-inline">Data unavailable.</p>';
    }

    function mergeDashboardPayloads(payloads, labelId) {
        var result = {
            compliance: {
                total_controls: 0,
                compliant: 0,
                non_compliant: 0,
                not_assessed: 0,
                compliance_score: 0,
                source: "sample"
            },
            findings: { critical: 0, high: 0, medium: 0, low: 0, open: 0 },
            recent_findings: [],
            findings_list: [],
            history: [],
            firewall_id: labelId
        };
        payloads.forEach(function (data) {
            if (!data) return;
            var c = data.compliance || {};
            result.compliance.total_controls += Number(c.total_controls) || 0;
            result.compliance.compliant += Number(c.compliant) || 0;
            result.compliance.non_compliant += Number(c.non_compliant) || 0;
            result.compliance.not_assessed += Number(c.not_assessed) || 0;
            if (c.source === "live") result.compliance.source = "live";
            var f = data.findings || {};
            result.findings.critical += Number(f.critical) || 0;
            result.findings.high += Number(f.high) || 0;
            result.findings.medium += Number(f.medium) || 0;
            result.findings.low += Number(f.low) || 0;
            result.recent_findings = result.recent_findings.concat(data.recent_findings || []);
            result.findings_list = result.findings_list.concat(data.findings_list || []);
            result.history = result.history.concat(data.history || []);
        });
        var total = result.compliance.total_controls;
        result.compliance.compliance_score = total
            ? Math.round(result.compliance.compliant / total * 100)
            : 0;
        result.findings.open =
            result.findings.critical + result.findings.high +
            result.findings.medium + result.findings.low;
        var sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
        result.recent_findings.sort(function (a, b) {
            return (sevOrder[(a.risk || "").toUpperCase()] || 4) -
                (sevOrder[(b.risk || "").toUpperCase()] || 4);
        });
        result.recent_findings = result.recent_findings.slice(0, 5);
        return result;
    }

    function load() {
        var container = document.getElementById("dashGroups");
        if (!container) return Promise.resolve();
        var targets = selectedFirewalls();
        var multi = !isAll() && targets.length > 1;
        var groupId = isAll() || multi ? ALL : targets[0];
        container.innerHTML = groupShell(groupId);
        state.source = null;
        state.status = {};

        var root = container.querySelector(".dash-group");
        var fetchList = isAll() ? [ALL] : targets;

        var jobs = fetchList.map(function (fw) {
            return fetch("/api/dashboard?firewall=" + encodeURIComponent(fw))
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    if (data && data.error) throw new Error(data.error);
                    if (fw !== ALL) {
                        state.status[fw] = data.compliance && data.compliance.source === "live"
                            ? "live"
                            : "down";
                    }
                    return data;
                })
                .catch(function () {
                    if (fw !== ALL) state.status[fw] = "down";
                    if (!state.source) state.source = "sample";
                    return null;
                });
        });

        return Promise.all(jobs).then(function (payloads) {
            var ok = payloads.filter(Boolean);
            if (!ok.length) {
                if (root) applyGroupError(root, groupId);
                setSource(state.source || "sample");
                return;
            }
            var data = ok.length === 1 ? ok[0] : mergeDashboardPayloads(ok, groupId);
            applyNetsecData(root, data, groupId);
            setSource(state.source || "sample");
        });
    }

    // ---- Selection chips ----

    function renderSelection() {
        var el = document.getElementById("dashSelection");
        if (!el) return;
        if (isAll()) {
            el.innerHTML = '<span class="dash-chip is-all" data-fw="' + ALL + '"><span class="dash-chip-dot ' + statusClass(ALL) + '"></span>' +
                "All Firewalls" +
                '<span class="dash-chip-note">cumulative view</span></span>';
            return;
        }
        el.innerHTML = state.firewalls.map(function (fw) {
            return '<span class="dash-chip" data-fw="' + escapeHtml(fw) + '">' +
                '<span class="dash-chip-dot ' + statusClass(fw) + '"></span>' +
                escapeHtml(fw) +
                '<button type="button" class="dash-chip-x" data-fw="' + escapeHtml(fw) + '" aria-label="Remove ' + escapeHtml(fw) + '">&times;</button>' +
                "</span>";
        }).join("");
        el.querySelectorAll(".dash-chip-x").forEach(function (btn) {
            btn.addEventListener("click", function () {
                var name = btn.getAttribute("data-fw");
                var i = state.firewalls.indexOf(name);
                if (i !== -1) state.firewalls.splice(i, 1);
                if (!state.firewalls.length) state.firewalls = [ALL];
                reflectSelection();
                load();
            });
        });
    }

    // ---- Firewall inventory search combobox (multi-select) ----

    var wrap = document.getElementById("dashCombobox");
    var input = document.getElementById("dashFwInput");
    var list = document.getElementById("dashFwList");
    var clear = document.getElementById("dashFwClear");

    if (wrap) {
        var seed = (wrap.getAttribute("data-initial-firewall") || "").trim();
        state.firewalls = seed && seed.toLowerCase() !== "all" ? [seed] : [ALL];
    }

    function inputPlaceholder() {
        if (isAll()) return "All Firewalls — search estate";
        if (state.firewalls.length === 1) return state.firewalls[0] + " — add another";
        return state.firewalls.length + " firewalls selected — add another";
    }

    function reflectSelection() {
        if (input) {
            input.value = "";
            input.placeholder = inputPlaceholder();
        }
        if (clear) clear.hidden = true;
        renderSelection();
        updateScope();
        if (list && !list.hidden) list.innerHTML = comboRows("");
    }

    function inventorySource() {
        return (state.inventory || []).filter(function (e) { return e && e.device_name; });
    }

    function rowHtml(value, name, sub, selected, disabled) {
        var cls = "rep-combo-row is-multi" +
            (selected ? " is-selected" : "") +
            (disabled ? " is-disabled" : "");
        return '<li class="' + cls + '" role="option" aria-selected="' + (selected ? "true" : "false") +
            '" data-value="' + escapeHtml(value) + '">' +
            '<span class="rep-combo-check" aria-hidden="true">' +
            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg>' +
            "</span>" +
            '<span class="rep-combo-body">' +
            '<span class="rep-combo-name">' + escapeHtml(name) + "</span>" +
            '<span class="rep-combo-sub">' + escapeHtml(sub) + "</span>" +
            "</span>" +
            "</li>";
    }

    function comboRows(query) {
        var q = String(query || "").trim().toLowerCase();
        var allSelected = isAll();
        var out = "";
        if (!q || q.indexOf("all") !== -1 || q.indexOf("full") !== -1 || q.indexOf("device") !== -1 || q.indexOf("inventory") !== -1) {
            out += rowHtml(ALL, "All Firewalls", "Cumulative data across every managed firewall", allSelected, false);
        }
        inventorySource().forEach(function (fw) {
            var name = fw.device_name || "";
            if (!name) return;
            var hay = (name + " " + (fw.host_ip || "") + " " + (fw.clone_of || "")).toLowerCase();
            if (q && hay.indexOf(q) === -1) return;
            var bits = [fw.host_ip || "", fw.status ? (fw.status === "live" ? "Live" : "Down") : ""];
            if (fw.clone_of) bits.push("Clone of " + fw.clone_of);
            var sub = bits.filter(Boolean).join(" \u00b7 ") || "Managed device";
            var selected = state.firewalls.indexOf(name) !== -1;
            out += rowHtml(name, name, sub, selected, false);
        });
        if (!out) out = '<li class="rep-combo-empty">No firewalls match</li>';
        return out;
    }

    function selectAll() {
        state.firewalls = [ALL];
        reflectSelection();
        load();
    }

    function toggleFirewall(name) {
        if (isAll()) {
            // Picking a specific device while "All Firewalls" is active
            // replaces the estate view with that single firewall.
            state.firewalls = [name];
            reflectSelection();
            load();
            return;
        }
        var i = state.firewalls.indexOf(name);
        if (i === -1) state.firewalls.push(name);
        else state.firewalls.splice(i, 1);
        if (!state.firewalls.length) state.firewalls = [ALL];
        reflectSelection();
        load();
    }

    if (wrap && input && list) {
        var close = function () {
            list.hidden = true;
            input.setAttribute("aria-expanded", "false");
            document.removeEventListener("click", outside);
        };
        var outside = function (e) {
            if (!wrap.contains(e.target)) close();
        };
        var open = function (filter) {
            document.removeEventListener("click", outside);
            list.innerHTML = comboRows(filter ? input.value : "");
            list.hidden = false;
            input.setAttribute("aria-expanded", "true");
            document.addEventListener("click", outside);
        };
        input.addEventListener("focus", function () { open(false); });
        input.addEventListener("click", function () { if (list.hidden) open(false); });
        input.addEventListener("input", function () {
            if (clear) clear.hidden = !input.value;
            open(true);
        });
        list.addEventListener("mousedown", function (e) { e.preventDefault(); });
        list.addEventListener("click", function (e) {
            e.stopPropagation();
            var row = e.target.closest(".rep-combo-row");
            if (!row || row.classList.contains("is-disabled")) return;
            var value = row.getAttribute("data-value") || ALL;
            if (value === ALL) selectAll();
            else toggleFirewall(value);
            if (list && !list.hidden) list.innerHTML = comboRows(input.value);
        });
        if (clear) {
            clear.addEventListener("click", function () {
                input.value = "";
                clear.hidden = true;
                open(true);
                input.focus();
            });
        }
        var goBtn = document.getElementById("dashFwGo");
        var go = function () {
            var query = (input.value || "").trim();
            var lower = query.toLowerCase();
            if (!query || lower === "all") {
                open(false);
                input.focus();
                return;
            }
            var exact = null;
            var partial = null;
            inventorySource().forEach(function (fw) {
                var name = fw.device_name || "";
                var hay = name.toLowerCase();
                if (hay === lower) exact = exact || name;
                else if (!partial && hay.indexOf(lower) !== -1) partial = name;
            });
            var match = exact || partial;
            if (match) toggleFirewall(match);
            input.value = "";
            if (clear) clear.hidden = true;
            open(false);
        };

        input.addEventListener("keydown", function (e) {
            if (e.key === "Escape") { close(); return; }
            if (e.key === "Enter") {
                e.preventDefault();
                go();
            }
        });
        if (goBtn) goBtn.addEventListener("click", go);
    }

    function loadInventory() {
        return fetch("/api/firewall-inventory", { headers: { "Accept": "application/json" } })
            .then(function (res) { return res.ok ? res.json() : Promise.reject(new Error("failed")); })
            .then(function (data) {
                state.inventory = (data && data.firewalls) || [];
                if (list && !list.hidden) list.innerHTML = comboRows("");
                updateScope();
            })
            .catch(function () { state.inventory = []; });
    }

    if (window.showToast) {
        window.showToast("Welcome back, Jeet \u2014 reviewing your security posture.", "success", 5000);
    }

    if (refreshBtn) {
        refreshBtn.addEventListener("click", function () {
            window.showToast("Refreshing dashboard data...");
            load();
        });
    }

    reflectSelection();
    updateScope();
    loadInventory();
    load();
})();
