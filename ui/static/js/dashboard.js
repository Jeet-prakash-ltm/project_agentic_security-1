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

        var domainSev =
            '<section class="card dash-panel domain-risk-panel is-loading">' +
            '<div class="section-head"><h3>Top Risk Domain (Detailed View)</h3></div>' +
            '<div class="domain-cluster-chart"></div>' +
            '<div class="section-loading section-loading-overlay"><span class="spinner"></span><span class="section-loading-text">Loading</span></div>' +
            "</section>";

        var trend =
            '<section class="compliance-trend-section card is-loading" data-scale="relative">' +
            '<div class="section-head">' +
            "<div><h3>Compliance Trend</h3>" +
            '<span class="section-sub">Security posture over time</span></div>' +
            "</div>" +
            '<div class="trend-chart"></div>' +
            '<div class="section-loading section-loading-overlay"><span class="spinner"></span><span class="section-loading-text">Loading</span></div>' +
            "</section>";

        return '<section class="dash-group" data-fw="' + escapeHtml(fw) + '">' +
            pie + recent + domains + domainSev + trend + "</section>";
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

    var SEV_LEVELS = [
        { key: "critical", label: "Critical", color: "#EF4444" },
        { key: "high", label: "High", color: "#F97316" },
        { key: "medium", label: "Medium", color: "#FBBF24" },
        { key: "low", label: "Low", color: "#22C55E" }
    ];

    function emptySevCounts() {
        return { critical: 0, high: 0, medium: 0, low: 0 };
    }

    function domainSeverityCounts(findingsList) {
        var byCat = {};
        CATEGORY_ORDER.forEach(function (cat) { byCat[cat] = emptySevCounts(); });
        (findingsList || []).forEach(function (f) {
            var cat = categoryForControl(f.control);
            if (!cat || !byCat[cat]) return;
            var risk = String(f.risk || "").toLowerCase();
            if (byCat[cat][risk] !== undefined) byCat[cat][risk] += 1;
        });
        return byCat;
    }

    function domainSevLegend() {
        var html = '<div class="domain-sev-legend">';
        SEV_LEVELS.forEach(function (s) {
            html += '<span class="domain-sev-legend-item"><i style="background:' + s.color + '"></i>' + s.label + "</span>";
        });
        html += "</div>";
        return html;
    }

    function niceAxisMax(max) {
        var n = Math.max(1, Number(max) || 1);
        if (n <= 4) return 4;
        var exp = Math.pow(10, Math.floor(Math.log10(n)));
        var m = n / exp;
        var nice = m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10;
        return nice * exp;
    }

    function domainSevYAxis(top) {
        var steps = 4;
        var html = '<div class="domain-sev-yaxis" aria-hidden="true">';
        for (var i = steps; i >= 0; i--) {
            html += "<span>" + Math.round(top * i / steps) + "</span>";
        }
        html += "</div>";
        return html;
    }

    function fmtCompact(value) {
        var n = Number(value) || 0;
        if (n >= 1000000) {
            var millions = n / 1000000;
            return (millions >= 10 || millions % 1 === 0 ? millions.toFixed(0) : millions.toFixed(1)) + "M";
        }
        if (n >= 1000) {
            var thousands = n / 1000;
            return (thousands >= 10 || thousands % 1 === 0 ? thousands.toFixed(0) : thousands.toFixed(1)) + "K";
        }
        return String(n);
    }

    function domainTotals(counts) {
        return (counts.critical || 0) + (counts.high || 0) + (counts.medium || 0) + (counts.low || 0);
    }

    function domainRiskKpis(totals) {
        var cards = [
            { key: "total", label: "Total Risks", value: totals.total, tone: "total" }
        ].concat(SEV_LEVELS.map(function (s) {
            return { key: s.key, label: s.label, value: totals[s.key], tone: s.key };
        }));
        var html = '<div class="domain-risk-kpis">';
        cards.forEach(function (card) {
            html += '<div class="domain-risk-kpi is-' + card.tone + '">' +
                '<span>' + escapeHtml(card.label.toUpperCase()) + "</span>" +
                "<strong>" + fmtCompact(card.value) + "</strong>" +
                "</div>";
        });
        html += "</div>";
        return html;
    }

    function bindDomainRiskTip(panel) {
        if (panel.getAttribute("data-tip-bound") === "1") return;
        panel.setAttribute("data-tip-bound", "1");

        function tipEl() {
            return panel.querySelector(".domain-risk-tip");
        }

        function hideTip() {
            var tip = tipEl();
            if (tip) tip.hidden = true;
        }

        function showTip(group, event) {
            var tip = tipEl();
            if (!tip) return;
            var cat = group.getAttribute("data-domain") || "";
            var critical = Number(group.getAttribute("data-critical") || 0);
            var high = Number(group.getAttribute("data-high") || 0);
            var medium = Number(group.getAttribute("data-medium") || 0);
            var low = Number(group.getAttribute("data-low") || 0);
            var total = Number(group.getAttribute("data-total") || 0);
            var overall = Number(group.getAttribute("data-overall") || 0);
            var pct = overall ? Math.round(total / overall * 100) : 0;
            tip.innerHTML =
                "<strong>" + escapeHtml(cat) + "</strong>" +
                '<span class="domain-risk-tip-total">Total Findings ' + fmtCompact(total) + "</span>" +
                "<ul>" +
                '<li><i style="background:#EF4444"></i>Critical: ' + fmtCompact(critical) + "</li>" +
                '<li><i style="background:#F97316"></i>High: ' + fmtCompact(high) + "</li>" +
                '<li><i style="background:#FBBF24"></i>Medium: ' + fmtCompact(medium) + "</li>" +
                '<li><i style="background:#22C55E"></i>Low: ' + fmtCompact(low) + "</li>" +
                "</ul>" +
                "<em>" + pct + "% of Overall Risks</em>";
            tip.hidden = false;
            moveTip(event);
        }

        function moveTip(event) {
            var tip = tipEl();
            if (!tip) return;
            var x = event.clientX + 14;
            var y = event.clientY + 16;
            var width = tip.offsetWidth || 220;
            var height = tip.offsetHeight || 160;
            if (x + width > window.innerWidth - 12) x = event.clientX - width - 12;
            if (y + height > window.innerHeight - 12) y = event.clientY - height - 12;
            tip.style.left = x + "px";
            tip.style.top = y + "px";
        }

        panel.addEventListener("mouseover", function (event) {
            var group = event.target.closest(".domain-cluster-group");
            if (!group || !panel.contains(group)) return;
            showTip(group, event);
        });
        panel.addEventListener("mousemove", function (event) {
            var tip = tipEl();
            if (!tip || tip.hidden) return;
            if (!event.target.closest(".domain-cluster-group")) return;
            moveTip(event);
        });
        panel.addEventListener("mouseout", function (event) {
            var next = event.relatedTarget;
            if (next && panel.contains(next) && next.closest(".domain-cluster-group")) return;
            hideTip();
        });
    }

    function renderDomainClustered(root, findingsList, fw) {
        var panel = groupSection(root, ".domain-cluster-chart");
        if (!panel) return;
        var byCat = domainSeverityCounts(findingsList);
        var ranked = CATEGORY_ORDER.map(function (cat) {
            var counts = byCat[cat] || emptySevCounts();
            return { cat: cat, counts: counts, total: domainTotals(counts) };
        }).sort(function (a, b) {
            return b.total - a.total;
        });
        var max = 1;
        var overall = 0;
        var totals = emptySevCounts();
        ranked.forEach(function (row) {
            overall += row.total;
            SEV_LEVELS.forEach(function (s) {
                totals[s.key] += row.counts[s.key] || 0;
                max = Math.max(max, row.counts[s.key] || 0);
            });
        });
        totals.total = overall;
        var top = niceAxisMax(max);
        var highest = ranked.length && ranked[0].total > 0 ? ranked[0].cat : "";

        var html = domainRiskKpis(totals);
        html += domainSevLegend();
        html += '<div class="domain-sev-plot">';
        html += domainSevYAxis(top);
        html += '<div class="domain-cluster-stage">';
        html += '<div class="domain-sev-grid" aria-hidden="true"><span></span><span></span><span></span><span></span><span></span></div>';
        html += '<div class="domain-cluster-axis">';
        ranked.forEach(function (row) {
            var cat = row.cat;
            var counts = row.counts;
            var isHighest = cat === highest;
            html += '<div class="domain-cluster-group' + (isHighest ? " is-highest" : "") +
                '" data-domain="' + escapeHtml(cat) +
                '" data-critical="' + counts.critical +
                '" data-high="' + counts.high +
                '" data-medium="' + counts.medium +
                '" data-low="' + counts.low +
                '" data-total="' + row.total +
                '" data-overall="' + overall + '">';
            html += '<div class="domain-cluster-summary">';
            html += "<strong>" + escapeHtml(cat) + "</strong>";
            html += "<span>Total Risk: " + fmtCompact(row.total) + "</span>";
            if (isHighest) html += '<em class="domain-risk-badge">Highest Risk Domain</em>';
            html += "</div>";
            html += '<div class="domain-cluster-cols">';
            SEV_LEVELS.forEach(function (s) {
                var n = counts[s.key] || 0;
                var h = top ? Math.round(n / top * 100) : 0;
                html += '<a class="domain-cluster-col" href="' + findingsUrl(fw, "domain", cat) + "&severity=" + s.key + '">';
                if (n > 0) {
                    html += '<span class="domain-cluster-value">' + fmtCompact(n) + "</span>";
                    html += '<span class="domain-cluster-fill is-' + s.key + '" style="height:' + h + "%;background:" + s.color + '"></span>';
                }
                html += "</a>";
            });
            html += "</div>";
            html += '<span class="domain-cluster-label">' + escapeHtml(shortLabel(cat)) + "</span>";
            html += "</div>";
        });
        html += "</div></div></div>";
        html += '<div class="domain-risk-tip" hidden></div>';
        panel.innerHTML = html;
        bindDomainRiskTip(panel);
        clearSection(panel.closest(".dash-panel"));
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

    function fmtPct(value) {
        if (value == null || isNaN(value)) return "\u2014";
        return (Math.round(Number(value) * 10) / 10) + "%";
    }

    function fmtSignedPct(value) {
        if (value == null || isNaN(value)) return "\u2014";
        var n = Math.round(Number(value) * 10) / 10;
        return (n > 0 ? "+" : "") + n + "%";
    }

    function complianceColor(score) {
        if (score == null || isNaN(score)) return "#9CA3AF";
        if (score <= 30) return "#EF4444";
        if (score <= 60) return "#F97316";
        if (score <= 85) return "#FBBF24";
        return "#22C55E";
    }

    function complianceHealth(score) {
        if (score == null || isNaN(score)) return { label: "No Data", tone: "flat" };
        if (score < 25) return { label: "Critical", tone: "bad" };
        if (score < 50) return { label: "Needs Attention", tone: "warn" };
        if (score < 75) return { label: "Good", tone: "good" };
        return { label: "Excellent", tone: "excellent" };
    }

    function trendArrow(delta) {
        if (delta == null || isNaN(delta) || delta === 0) return { glyph: "\u2192", cls: "flat" };
        if (delta > 0) return { glyph: "\u2191", cls: "good" };
        return { glyph: "\u2193", cls: "bad" };
    }

    function movingAverage(points, windowSize) {
        var size = Math.max(2, windowSize || 3);
        return points.map(function (p, i) {
            var from = Math.max(0, i - size + 1);
            var slice = points.slice(from, i + 1);
            var sum = slice.reduce(function (acc, item) { return acc + item.value; }, 0);
            return { ts: p.ts, value: sum / slice.length };
        });
    }

    function forecastPoint(points) {
        if (!points || points.length < 2) return null;
        var last = points[points.length - 1];
        var prev = points[points.length - 2];
        var span = Math.max(86400, last.ts - prev.ts);
        var projected = Math.max(0, Math.min(100, last.value + (last.value - prev.value)));
        return { ts: last.ts + span, value: Math.round(projected * 10) / 10, predicted: true };
    }

    function trendEvents(points) {
        if (!points.length) return {};
        var highest = points[0];
        var lowest = points[0];
        var bestGain = null;
        var worstDrop = null;
        points.forEach(function (p, i) {
            if (p.value > highest.value) highest = p;
            if (p.value < lowest.value) lowest = p;
            if (!i) return;
            var delta = Math.round((p.value - points[i - 1].value) * 10) / 10;
            if (delta > 0 && (!bestGain || delta > bestGain.delta)) bestGain = { point: p, prev: points[i - 1], delta: delta };
            if (delta < 0 && (!worstDrop || delta < worstDrop.delta)) worstDrop = { point: p, prev: points[i - 1], delta: delta };
        });
        return { highest: highest, lowest: lowest, bestGain: bestGain, worstDrop: worstDrop };
    }

    function smoothPath(pts, xFn, yFn) {
        if (!pts.length) return "";
        if (pts.length === 1) {
            return "M" + xFn(pts[0].ts).toFixed(1) + " " + yFn(pts[0].value).toFixed(1);
        }
        var d = "M" + xFn(pts[0].ts).toFixed(1) + " " + yFn(pts[0].value).toFixed(1);
        for (var i = 0; i < pts.length - 1; i++) {
            var p0 = pts[Math.max(0, i - 1)];
            var p1 = pts[i];
            var p2 = pts[i + 1];
            var p3 = pts[Math.min(pts.length - 1, i + 2)];
            var c1x = xFn(p1.ts) + (xFn(p2.ts) - xFn(p0.ts)) / 6;
            var c1y = yFn(p1.value) + (yFn(p2.value) - yFn(p0.value)) / 6;
            var c2x = xFn(p2.ts) - (xFn(p3.ts) - xFn(p1.ts)) / 6;
            var c2y = yFn(p2.value) - (yFn(p3.value) - yFn(p1.value)) / 6;
            d += " C" + c1x.toFixed(1) + " " + c1y.toFixed(1) + " " +
                c2x.toFixed(1) + " " + c2y.toFixed(1) + " " +
                xFn(p2.ts).toFixed(1) + " " + yFn(p2.value).toFixed(1);
        }
        return d;
    }

    function trendInsight(points, current) {
        var health = complianceHealth(current);
        var events = trendEvents(points);
        var avg = points.length
            ? points.reduce(function (acc, p) { return acc + p.value; }, 0) / points.length
            : current;
        var thirtyAgo = null;
        if (points.length) {
            var cutoff = points[points.length - 1].ts - 30 * 86400;
            for (var i = 0; i < points.length; i++) {
                if (points[i].ts >= cutoff) { thirtyAgo = points[i]; break; }
            }
            if (!thirtyAgo) thirtyAgo = points[0];
        }
        var monthDelta = thirtyAgo && current != null ? Math.round((current - thirtyAgo.value) * 10) / 10 : null;
        return {
            health: health,
            highest: events.highest ? events.highest.value : current,
            lowest: events.lowest ? events.lowest.value : current,
            average: avg,
            monthDelta: monthDelta
        };
    }

    function bindTrendTip(section) {
        if (section.getAttribute("data-tip-bound") === "1") return;
        section.setAttribute("data-tip-bound", "1");

        function tipEl() {
            return section.querySelector(".trend-tip");
        }

        function hideTip() {
            var tip = tipEl();
            if (tip) tip.hidden = true;
        }

        function moveTip(event) {
            var tip = tipEl();
            if (!tip) return;
            var x = event.clientX + 14;
            var y = event.clientY + 16;
            var width = tip.offsetWidth || 220;
            var height = tip.offsetHeight || 160;
            if (x + width > window.innerWidth - 12) x = event.clientX - width - 12;
            if (y + height > window.innerHeight - 12) y = event.clientY - height - 12;
            tip.style.left = x + "px";
            tip.style.top = y + "px";
        }

        function showTip(marker, event) {
            var tip = tipEl();
            if (!tip) return;
            var date = marker.getAttribute("data-date") || "";
            var score = marker.getAttribute("data-score") || "\u2014";
            var prev = marker.getAttribute("data-prev") || "\u2014";
            var change = marker.getAttribute("data-change") || "\u2014";
            var status = marker.getAttribute("data-status") || "Unchanged";
            var eventLabel = marker.getAttribute("data-event") || "";
            tip.innerHTML =
                "<strong>" + escapeHtml(date) + "</strong>" +
                (eventLabel ? '<span class="trend-tip-event">' + escapeHtml(eventLabel) + "</span>" : "") +
                "<ul>" +
                "<li>Compliance Score: " + escapeHtml(score) + "</li>" +
                "<li>Previous Scan: " + escapeHtml(prev) + "</li>" +
                "<li>Change: " + escapeHtml(change) + "</li>" +
                "</ul>" +
                "<em>Status: " + escapeHtml(status) + "</em>";
            tip.hidden = false;
            moveTip(event);
        }

        section.addEventListener("mouseover", function (event) {
            var marker = event.target.closest(".trend-hit");
            if (!marker || !section.contains(marker)) return;
            showTip(marker, event);
        });
        section.addEventListener("mousemove", function (event) {
            var tip = tipEl();
            if (!tip || tip.hidden) return;
            if (!event.target.closest(".trend-hit")) return;
            moveTip(event);
        });
        section.addEventListener("mouseout", function (event) {
            var next = event.relatedTarget;
            if (next && section.contains(next) && next.closest(".trend-hit")) return;
            hideTip();
        });
        section.addEventListener("click", function (event) {
            var btn = event.target.closest("[data-trend-scale]");
            if (!btn || !section.contains(btn)) return;
            section.setAttribute("data-scale", btn.getAttribute("data-trend-scale") || "relative");
            var history = section._trendHistory || [];
            var firewallId = section._trendFirewallId || "all";
            var score = section._trendScore;
            renderComplianceTrend(section, history, firewallId, score);
        });
    }

    function renderComplianceTrend(root, history, firewallId, complianceScore) {
        var section = root && root.classList && root.classList.contains("compliance-trend-section")
            ? root
            : groupSection(root, ".compliance-trend-section");
        var el = section ? section.querySelector(".trend-chart") : groupSection(root, ".trend-chart");
        if (!el || !section) return;
        section._trendHistory = history || [];
        section._trendFirewallId = firewallId;
        section._trendScore = complianceScore;
        bindTrendTip(section);

        var series = buildTrendSeries(history, firewallId).filter(function (s) {
            return s.points.length > 0;
        });
        var rawPoints = series.length ? aggregateDaily(series[0].points) : [];
        if (rawPoints.length > 30) rawPoints = rawPoints.slice(rawPoints.length - 30);
        if (!rawPoints.length && typeof complianceScore !== "number") {
            el.innerHTML = '<p class="trend-empty">No historical compliance data available yet.</p>';
            clearSection(section);
            return;
        }
        if (!rawPoints.length && typeof complianceScore === "number") {
            rawPoints = [{ ts: Date.now() / 1000, value: complianceScore }];
        }

        var current = rawPoints[rawPoints.length - 1].value;
        var prev = rawPoints.length > 1 ? rawPoints[rawPoints.length - 2].value : null;
        var improvement = prev != null ? Math.round((current - prev) * 10) / 10 : null;
        var currentArrow = trendArrow(improvement);
        var prevDelta = rawPoints.length > 2
            ? Math.round((rawPoints[rawPoints.length - 2].value - rawPoints[rawPoints.length - 3].value) * 10) / 10
            : null;
        var prevArrow = trendArrow(prevDelta);
        var impArrow = trendArrow(improvement);
        var insight = trendInsight(rawPoints, current);
        var events = trendEvents(rawPoints);
        var avgPoints = movingAverage(rawPoints, 3);
        var forecast = forecastPoint(rawPoints);
        var relative = section.getAttribute("data-scale") !== "absolute";
        var values = rawPoints.map(function (p) { return p.value; });
        if (forecast) values.push(forecast.value);
        var dataMin = Math.min.apply(null, values);
        var dataMax = Math.max.apply(null, values);
        var min = relative ? Math.max(0, Math.floor((dataMin - 5) / 5) * 5) : 0;
        var max = relative ? Math.min(100, Math.ceil((dataMax + 5) / 5) * 5) : 100;
        if (max <= min) max = min + 10;

        var times = rawPoints.map(function (p) { return p.ts; });
        var n = times.length;
        var W = 920, H = 240;
        var PAD_LEFT = 44, PAD_RIGHT = 18, PAD_TOP = 28, PAD_BOTTOM = 28;
        var plotBottom = H - PAD_BOTTOM;

        function x(ts) {
            var idx = times.indexOf(ts);
            if (idx < 0 && forecast && ts === forecast.ts) {
                return W - PAD_RIGHT;
            }
            if (n === 1) return PAD_LEFT + (W - PAD_LEFT - PAD_RIGHT) / 2;
            var span = n > 1 ? n - 1 : 1;
            var extra = forecast ? 1 : 0;
            return PAD_LEFT + (idx / (span + extra)) * (W - PAD_LEFT - PAD_RIGHT);
        }
        function y(v) {
            return PAD_TOP + (1 - (v - min) / (max - min)) * (H - PAD_TOP - PAD_BOTTOM);
        }

        var uid = "tr" + Math.abs(Math.round((rawPoints[0].ts || 1) * 100 + current * 10));
        var linePath = smoothPath(rawPoints, x, y);
        var areaPath = linePath +
            " L" + x(rawPoints[rawPoints.length - 1].ts).toFixed(1) + " " + plotBottom.toFixed(1) +
            " L" + x(rawPoints[0].ts).toFixed(1) + " " + plotBottom.toFixed(1) + " Z";
        var avgPath = smoothPath(avgPoints, x, y);
        var html = "";
        html += '<div class="trend-insight">';
        html += '<span>Compliance Health: <strong class="' + insight.health.tone + '">' + escapeHtml(insight.health.label) + "</strong></span>";
        html += "<span>Highest Score Achieved: <strong>" + fmtPct(insight.highest) + "</strong></span>";
        html += "<span>Lowest Score Achieved: <strong>" + fmtPct(insight.lowest) + "</strong></span>";
        html += "<span>Average Trend: <strong>" + fmtPct(insight.average) + "</strong></span>";
        html += "<span>Last 30-Day Change: <strong class=\"" + trendArrow(insight.monthDelta).cls + "\">" + fmtSignedPct(insight.monthDelta) + "</strong></span>";
        html += "</div>";

        html += '<div class="trend-kpis">';
        html += '<div class="trend-kpi is-current"><span>Current Score</span><strong class="' + currentArrow.cls + '">' + fmtPct(current) + " <em>" + currentArrow.glyph + "</em></strong></div>";
        html += '<div class="trend-kpi"><span>Previous Scan</span><strong class="' + prevArrow.cls + '">' + fmtPct(prev) + " <em>" + prevArrow.glyph + "</em></strong></div>";
        html += '<div class="trend-kpi"><span>Improvement</span><strong class="' + impArrow.cls + '">' + fmtSignedPct(improvement) + " <em>" + impArrow.glyph + "</em></strong></div>";
        html += "</div>";

        html += '<div class="trend-toolbar">';
        html += '<button type="button" class="trend-scale-btn' + (relative ? " is-active" : "") + '" data-trend-scale="relative">Relative View</button>';
        html += '<button type="button" class="trend-scale-btn' + (relative ? "" : " is-active") + '" data-trend-scale="absolute">Absolute View</button>';
        html += "</div>";

        html += '<svg class="trend-line-svg" viewBox="0 0 ' + W + " " + H + '" preserveAspectRatio="none" role="img" aria-label="Compliance score over time">';
        html += "<defs>";
        html += '<linearGradient id="' + uid + '-stroke" x1="0%" y1="0%" x2="100%" y2="0%">';
        rawPoints.forEach(function (p, i) {
            html += '<stop offset="' + (n === 1 ? 100 : Math.round(i / (n - 1) * 100)) + '%" stop-color="' + complianceColor(p.value) + '"/>';
        });
        html += "</linearGradient>";
        html += '<linearGradient id="' + uid + '-fill" x1="0%" y1="0%" x2="0%" y2="100%">';
        html += '<stop offset="0%" stop-color="' + complianceColor(current) + '" stop-opacity="0.28"/>';
        html += '<stop offset="100%" stop-color="' + complianceColor(current) + '" stop-opacity="0.02"/>';
        html += "</linearGradient>";
        html += "</defs>";

        var zones = [
            { from: 0, to: 25, color: "rgba(239,68,68,0.10)" },
            { from: 25, to: 50, color: "rgba(249,115,22,0.10)" },
            { from: 50, to: 75, color: "rgba(251,191,36,0.08)" },
            { from: 75, to: 100, color: "rgba(34,197,94,0.08)" }
        ];
        zones.forEach(function (zone) {
            var top = Math.min(max, Math.max(min, zone.to));
            var bottom = Math.max(min, Math.min(max, zone.from));
            if (top <= bottom) return;
            html += '<rect class="trend-zone" x="' + PAD_LEFT + '" y="' + y(top).toFixed(1) + '" width="' +
                (W - PAD_LEFT - PAD_RIGHT) + '" height="' + (y(bottom) - y(top)).toFixed(1) + '" fill="' + zone.color + '"/>';
        });

        var ticks = 4;
        for (var g = 0; g <= ticks; g++) {
            var gv = min + (max - min) * g / ticks;
            var gy = y(gv);
            html += '<line x1="' + PAD_LEFT + '" y1="' + gy.toFixed(1) + '" x2="' + (W - PAD_RIGHT) + '" y2="' + gy.toFixed(1) + '" class="trend-grid"/>';
            html += '<text x="' + (PAD_LEFT - 8) + '" y="' + (gy + 3).toFixed(1) + '" class="trend-axis-label" text-anchor="end">' + Math.round(gv) + "</text>";
        }

        if (rawPoints.length === 1) {
            html += '<circle cx="' + x(rawPoints[0].ts).toFixed(1) + '" cy="' + y(rawPoints[0].value).toFixed(1) + '" r="5" fill="' + complianceColor(current) + '"/>';
        } else {
            html += '<path d="' + areaPath + '" fill="url(#' + uid + '-fill)" stroke="none"/>';
            html += '<path d="' + linePath + '" fill="none" stroke="url(#' + uid + '-stroke)" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"/>';
            html += '<path d="' + avgPath + '" fill="none" stroke="rgba(209,213,219,0.55)" stroke-width="1.6" stroke-dasharray="6 5"/>';
            if (forecast) {
                html += '<path d="M' + x(rawPoints[rawPoints.length - 1].ts).toFixed(1) + " " + y(rawPoints[rawPoints.length - 1].value).toFixed(1) +
                    " L" + x(forecast.ts).toFixed(1) + " " + y(forecast.value).toFixed(1) + '" fill="none" stroke="' +
                    complianceColor(forecast.value) + '" stroke-width="2" stroke-dasharray="5 5" opacity="0.8"/>';
            }
        }

        function markerLabel(p) {
            if (events.highest && p.ts === events.highest.ts) return "Highest Compliance";
            if (events.worstDrop && p.ts === events.worstDrop.point.ts) return "Significant Drop";
            if (events.lowest && p.ts === events.lowest.ts && events.lowest.ts !== events.highest.ts) return "Lowest Score";
            if (events.bestGain && p.ts === events.bestGain.point.ts) return "Largest Improvement";
            return "";
        }

        rawPoints.forEach(function (p, i) {
            var prevVal = i ? rawPoints[i - 1].value : null;
            var delta = prevVal != null ? Math.round((p.value - prevVal) * 10) / 10 : null;
            var status = delta == null ? "Unchanged" : delta > 0 ? "Improving" : delta < 0 ? "Declining" : "Unchanged";
            var eventName = markerLabel(p);
            html += '<circle class="trend-hit" cx="' + x(p.ts).toFixed(1) + '" cy="' + y(p.value).toFixed(1) +
                '" r="9" fill="transparent" data-date="' + escapeHtml(formatShortTs(p.ts)) +
                '" data-score="' + fmtPct(p.value) +
                '" data-prev="' + fmtPct(prevVal) +
                '" data-change="' + fmtSignedPct(delta) +
                '" data-status="' + status +
                '" data-event="' + escapeHtml(eventName) + '"/>';
            html += '<circle cx="' + x(p.ts).toFixed(1) + '" cy="' + y(p.value).toFixed(1) + '" r="3.4" fill="' +
                complianceColor(p.value) + '" class="trend-dot"/>';
            if (eventName === "Highest Compliance") {
                html += '<text class="trend-event-label" x="' + x(p.ts).toFixed(1) + '" y="' + (y(p.value) - 12).toFixed(1) + '" text-anchor="middle">Highest Compliance</text>';
            } else if (eventName === "Significant Drop") {
                html += '<text class="trend-event-label is-drop" x="' + x(p.ts).toFixed(1) + '" y="' + (y(p.value) - 12).toFixed(1) + '" text-anchor="middle">Significant Drop</text>';
            }
        });
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
        html += '<div class="trend-legend">' +
            '<span class="trend-legend-item"><i style="background:' + complianceColor(current) + '"></i>Compliance Score</span>' +
            '<span class="trend-legend-item is-avg"><i></i>Trend Average</span>' +
            (forecast ? '<span class="trend-legend-item is-forecast"><i></i>Projected Next Scan</span>' : "") +
            "</div>";
        html += '<div class="trend-tip" hidden></div>';

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
        renderDomainClustered(root, data.findings_list || [], cid);
        renderComplianceTrend(root, data.history || [], cid, c.compliance_score);
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
        var userName = String(document.body.getAttribute("data-user-name") || "").trim();
        var firstName = userName.split(/\s+/)[0] || "";
        var greeting = firstName
            ? "Welcome back, " + firstName + " \u2014 reviewing your security posture."
            : "Welcome back \u2014 reviewing your security posture.";
        window.showToast(greeting, "success", 5000);
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
