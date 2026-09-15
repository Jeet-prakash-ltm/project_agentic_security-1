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

    var DEFAULT_FW = "vmpafw01";
    var state = {
        firewall: DEFAULT_FW,
        inventory: []
    };

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

    function findingsUrl(key, value) {
        var url = "/findings?" + key + "=" + encodeURIComponent(value);
        if (state.firewall && state.firewall !== "all") {
            url += "&firewall=" + encodeURIComponent(state.firewall);
        }
        return url;
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

    function renderCompliancePie(c) {
        var svg = document.getElementById("compliancePie");
        if (!svg) return;
        var compliant = Number(c.compliant) || 0;
        var nonCompliant = Number(c.non_compliant) || 0;
        var notAssessed = Number(c.not_assessed) || 0;
        var total = compliant + nonCompliant + notAssessed;
        var pct = total ? Math.round(compliant / total * 100) : 0;

        var percentEl = document.getElementById("donutPercent");
        var statusEl = document.getElementById("donutStatus");
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
        svg.innerHTML = html;

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
                window.location.href = findingsUrl("status", seg.getAttribute("data-status"));
            });
        });

        var pills = document.getElementById("donutPills");
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
                    window.location.href = findingsUrl("status", pill.getAttribute("data-status"));
                });
            });
        }
    }

    // ============================================================
    // FINDINGS BY SEVERITY (horizontal bar graph)
    // ============================================================

    function renderSeverityGrid(f) {
        var el = document.getElementById("severityGrid");
        if (!el) return;
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
            html += '<a class="sev-bar" href="' + findingsUrl("severity", s.status) + '" title="' + s.label + ': ' + s.count + ' findings">' +
                '<span class="sev-bar-head">' +
                '<span class="sev-bar-label">' + s.label + "</span>" +
                '<span class="sev-bar-count">' + s.count + "</span>" +
                "</span>" +
                '<span class="sev-bar-track">' +
                '<span class="sev-bar-fill" style="width:' + width + "%;background:" + s.color + '"></span>' +
                "</span>" +
                "</a>";
        });
        el.innerHTML = html;
    }

    // ============================================================
    // RECENT FINDINGS
    // ============================================================

    function renderRecentFindings(recent) {
        var el = document.getElementById("recentFindings");
        if (!el) return;
        if (!recent.length) { el.innerHTML = '<p class="empty-inline">No findings.</p>'; return; }
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
        el.innerHTML = html;
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

    function renderVerticalBars(findingsList) {
        var el = document.getElementById("verticalBars");
        if (!el) return;
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
            html += '<a class="vbar" href="' + findingsUrl("domain", cat) + '" title="' + escapeHtml(cat) + ": " + n + '">' +
                '<span class="vbar-count">' + n + "</span>" +
                '<span class="vbar-track"><span class="vbar-fill" style="height:' + h + '%"></span></span>' +
                '<span class="vbar-label">' + escapeHtml(shortLabel(cat)) + "</span>" +
                "</a>";
        });
        html += "</div>";
        el.innerHTML = html;
    }

    function shortLabel(cat) {
        return cat.replace(" & Remote Access", "").replace(" & Platform", "").replace(" & Performance", "").replace(" & Monitoring", "").replace(" &", "");
    }

    // ============================================================
    // COMPLIANCE TREND
    // ============================================================

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

    function renderTrendStats(history, firewallId, complianceScore) {
        var el = document.getElementById("trendStats");
        if (!el) return;
        var series = buildTrendSeries(history, firewallId);
        var points = (series[0] && series[0].points) || [];
        var current = points.length
            ? points[points.length - 1].value
            : (typeof complianceScore === "number" ? complianceScore : null);
        if (current == null) return;
        var prev = points.length > 1 ? points[points.length - 2].value : null;
        var improvement = prev != null ? Math.round((current - prev) * 10) / 10 : null;
        var impCls = improvement == null ? "" : improvement > 0 ? "good" : improvement < 0 ? "bad" : "flat";
        var impText = improvement == null ? "\u2014" : (improvement > 0 ? "+" : "") + improvement + "%";

        el.innerHTML =
            '<span class="trend-stat"><span>Current Score</span><strong>' + current + "%</strong></span>" +
            '<span class="trend-stat"><span>Previous Scan</span><strong>' + (prev != null ? prev + "%" : "\u2014") + "</strong></span>" +
            '<span class="trend-stat"><span>Improvement</span><strong class="' + impCls + '">' + impText + "</strong></span>";
    }

    function renderComplianceTrend(history, firewallId) {
        var el = document.getElementById("trendChart");
        if (!el) return;

        var series = buildTrendSeries(history, firewallId).filter(function (s) {
            return s.points.length > 0;
        });
        if (!series.length) {
            el.innerHTML = '<p class="trend-summary">No history yet. Run an assessment to start tracking compliance.</p>';
            return;
        }

        var points = series[0].points;
        var times = points.map(function (p) { return p.ts; });
        if (times.length > 12) times = times.slice(times.length - 12);
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

        var color = firewallId === "all" ? "#ff5e4f" : (COLORS[firewallId] || "#ff5e4f");

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
    }

    // ============================================================
    // MAIN
    // ============================================================

    function updateScope(fw) {
        var assess = document.getElementById("quickAssess");
        var summary = document.getElementById("quickSummary");
        var report = document.getElementById("quickReport");
        var query = "?firewall=" + encodeURIComponent(fw || "all");
        if (assess) {
            assess.href = fw === "all"
                ? "/workspace"
                : "/run-assessment?firewall=" + encodeURIComponent(fw);
        }
        if (summary) {
            summary.href = fw === "all"
                ? "/reports?firewall=all"
                : "/executive-summary" + query;
        }
        if (report) report.href = "/generate-excel" + query;
    }

    function applyNetsecData(data) {
        var c = data.compliance || {};
        var fw = data.firewall_id || "vmpafw01";
        setSource(c.source);
        renderCompliancePie(c);
        renderSeverityGrid(data.findings || {});
        renderRecentFindings(data.recent_findings || []);
        renderVerticalBars(data.findings_list || []);
        renderTrendStats(data.history || [], fw, c.compliance_score);
        renderComplianceTrend(data.history || [], fw);
        updateScope(fw);
    }

    function load() {
        fetch("/api/dashboard?firewall=" + encodeURIComponent(state.firewall))
            .then(function (r) { return r.json(); })
            .then(function (data) { applyNetsecData(data); })
            .catch(function () { window.showToast("Dashboard data unavailable.", "error"); });
    }

    // ---- Firewall inventory search combobox ----

    var input = document.getElementById("dashFwInput");
    var list = document.getElementById("dashFwList");
    var clear = document.getElementById("dashFwClear");
    var wrap = document.getElementById("dashCombobox");

    if (input) {
        var initial = (input.value || "").trim();
        if (initial) state.firewall = initial;
    }

    function reflectFirewallUI() {
        if (!input) return;
        if (state.firewall === "all") {
            input.value = "";
            input.placeholder = "All Firewalls — search estate";
        } else {
            input.value = state.firewall;
            input.placeholder = "";
        }
        if (clear) clear.hidden = state.firewall === "all";
    }

    function inventorySource() {
        return (state.inventory || []).filter(function (e) { return e && e.device_name; });
    }

    function comboRows(query) {
        var q = String(query || "").trim().toLowerCase();
        var out = "";
        if (!q || q.indexOf("all") !== -1 || q.indexOf("full") !== -1 || q.indexOf("device") !== -1 || q.indexOf("inventory") !== -1) {
            out += '<li class="rep-combo-row' + (state.firewall === "all" ? " is-active" : "") +
                '" role="option" data-value="all">' +
                '<span class="rep-combo-name">All Firewalls</span>' +
                '<span class="rep-combo-sub">Cumulative data across every managed firewall</span></li>';
        }
        inventorySource().forEach(function (fw) {
            var name = fw.device_name || "";
            if (!name) return;
            var hay = (name + " " + (fw.host_ip || "") + " " + (fw.clone_of || "")).toLowerCase();
            if (q && hay.indexOf(q) === -1) return;
            var bits = [fw.host_ip || "", fw.status ? (fw.status === "live" ? "Live" : "Down") : ""];
            if (fw.clone_of) bits.push("Clone of " + fw.clone_of);
            var sub = bits.filter(Boolean).join(" \u00b7 ") || "Managed device";
            out += '<li class="rep-combo-row' + (state.firewall === name ? " is-active" : "") +
                '" role="option" data-value="' + escapeHtml(name) + '">' +
                '<span class="rep-combo-name">' + escapeHtml(name) + "</span>" +
                '<span class="rep-combo-sub">' + escapeHtml(sub) + "</span></li>";
        });
        return out;
    }

    function setFirewall(value) {
        state.firewall = value || "all";
        reflectFirewallUI();
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
        input.addEventListener("input", function () { open(true); });
        list.addEventListener("mousedown", function (e) { e.preventDefault(); });
        list.addEventListener("click", function (e) {
            var row = e.target.closest(".rep-combo-row");
            if (!row) return;
            setFirewall(row.getAttribute("data-value") || "all");
            close();
        });
        if (clear) {
            clear.addEventListener("click", function () {
                setFirewall("all");
                close();
            });
        }
        input.addEventListener("keydown", function (e) {
            if (e.key === "Escape") { close(); return; }
            if (e.key === "Enter") {
                e.preventDefault();
                var first = list.querySelector(".rep-combo-row");
                if (first) setFirewall(first.getAttribute("data-value") || "all");
                close();
            }
        });
    }

    function loadInventory() {
        fetch("/api/firewall-inventory", { headers: { "Accept": "application/json" } })
            .then(function (res) { return res.ok ? res.json() : Promise.reject(new Error("failed")); })
            .then(function (data) {
                state.inventory = (data && data.firewalls) || [];
                if (list && !list.hidden) list.innerHTML = comboRows("");
                updateScope(state.firewall);
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

    reflectFirewallUI();
    updateScope(state.firewall);
    loadInventory();
    load();
})();
