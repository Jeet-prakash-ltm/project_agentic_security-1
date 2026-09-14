(function () {
    "use strict";

    var historyList = document.getElementById("agentHistoryPanels");
    var refreshBtn = document.getElementById("refreshInsightsBtn");

    var costTotal = document.getElementById("costTotal");
    var costTokens = document.getElementById("costTokens");
    var costConvs = document.getElementById("costConvs");
    var costLatency = document.getElementById("costLatency");
    var costDrivers = document.getElementById("costDrivers");

    var agentHealthList = document.getElementById("agentHealthList");
    var agentHealthUpdated = document.getElementById("agentHealthUpdated");

    var POLL_MS = 5000;
    var TICKS = 5;

    var COLOR_INPUT = "#2563EB";
    var COLOR_OUTPUT = "#16A34A";
    var COLOR_TOTAL = "#7C3AED";
    var COLOR_LATENCY = "#ff5e4f";

    var CW = 720;
    var CH = 210;
    var PAD_LEFT = 52;
    var PAD_RIGHT = 14;
    var PAD_TOP = 14;
    var PAD_BOTTOM = 22;

    function fmtNumber(value) {
        if (value == null) return "-";
        return Number(value).toLocaleString("en-US");
    }

    function fmtTokens(value) {
        if (value == null) return "-";
        var n = Number(value);
        if (n >= 1000000) return (n / 1000000).toFixed(1) + "M";
        if (n >= 1000) return (n / 1000).toFixed(1) + "K";
        return String(n);
    }

    function fmtLatency(value) {
        if (value == null) return "-";
        var n = Number(value);
        if (n >= 1000) return (n / 1000).toFixed(2) + "s";
        return Math.round(n) + "ms";
    }

    function fmtCost(value) {
        if (value == null) return "-";
        var n = Number(value);
        if (n >= 1000) return "$" + (n / 1000).toFixed(2) + "K";
        if (n >= 1) return "$" + n.toFixed(2);
        return "$" + n.toFixed(4);
    }

    function fmtRelative(ts) {
        if (!ts) return "-";
        var diff = Math.floor(Date.now() / 1000 - ts);
        if (diff < 60) return "just now";
        if (diff < 3600) return Math.floor(diff / 60) + "m ago";
        if (diff < 86400) return Math.floor(diff / 3600) + "h ago";
        return Math.floor(diff / 86400) + "d ago";
    }

    function fmtStamp(ts) {
        if (!ts) return "-";
        var d = new Date(ts * 1000);
        return d.toLocaleString();
    }

    function fmtAxis(ts) {
        if (!ts) return "";
        var d = new Date(ts * 1000);
        var hh = d.getHours();
        var mm = d.getMinutes();
        var time = (hh < 10 ? "0" + hh : hh) + ":" + (mm < 10 ? "0" + mm : mm);
        var today = new Date();
        if (d.toDateString() === today.toDateString()) return time;
        var months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
        return months[d.getMonth()] + " " + d.getDate();
    }

    function escapeHtml(value) {
        var div = document.createElement("div");
        div.textContent = value == null ? "" : String(value);
        return div.innerHTML;
    }

    function avatarFor(name) {
        var parts = String(name || "").trim().split(/\s+/);
        var out = parts.map(function (p) { return p.charAt(0); }).join("").toUpperCase();
        return out.slice(0, 2) || "AG";
    }

    function sortedSeries(agent) {
        var pts = (agent && agent.series) || [];
        return pts.slice().sort(function (a, b) {
            return (a.ts || 0) - (b.ts || 0);
        });
    }

    function renderCost(totals, agents) {
        if (!totals) return;

        if (costTotal) costTotal.textContent = fmtCost(totals.cost);
        if (costTokens) costTokens.textContent = fmtTokens(totals.total_tokens);
        if (costConvs) costConvs.textContent = fmtNumber(totals.conversations);
        if (costLatency) costLatency.textContent = fmtLatency(totals.avg_latency_ms);

        if (!costDrivers) return;

        var list = (agents || [])
            .filter(function (a) { return a.cost > 0; })
            .sort(function (a, b) { return b.cost - a.cost; })
            .slice(0, 5);

        if (!list.length) {
            costDrivers.innerHTML = '<p class="cost-driver-empty">No token usage recorded yet. Chat with an agent in the AI Workspace to start tracking.</p>';
            return;
        }

        var max = list[0].cost || 1;
        var html = "";
        list.forEach(function (a) {
            var pct = Math.max(4, Math.round((a.cost / max) * 100));
            html +=
                '<div class="cost-driver">' +
                '<div class="cost-driver-head">' +
                '<span class="cost-driver-name">' + escapeHtml(a.agent_name) + "</span>" +
                '<span class="cost-driver-value">' + fmtCost(a.cost) + " \u00b7 " + fmtTokens(a.total_tokens) + " tokens</span>" +
                "</div>" +
                '<div class="cost-driver-track"><div class="cost-driver-fill" style="width:' + pct + '%"></div></div>' +
                "</div>";
        });
        costDrivers.innerHTML = html;
    }

    function chartScales(points, maxValue) {
        var n = points.length;
        if (n === 0) return null;
        var max = maxValue || 1;
        var min = 0;

        function x(ts) {
            var idx = points.indexOf(ts);
            if (n === 1) return PAD_LEFT + (CW - PAD_LEFT - PAD_RIGHT) / 2;
            return PAD_LEFT + (idx / (n - 1)) * (CW - PAD_LEFT - PAD_RIGHT);
        }

        function y(v) {
            return PAD_TOP + (1 - (v - min) / max) * (CH - PAD_TOP - PAD_BOTTOM);
        }

        return { n: n, max: max, x: x, y: y };
    }

    function gridHtml(sc, format, ticks) {
        var html = "";
        for (var g = 0; g <= ticks; g++) {
            var gv = (g / ticks) * sc.max;
            var gy = sc.y(gv);
            html += '<line class="agent-chart-grid" x1="' + PAD_LEFT + '" y1="' + gy.toFixed(1) + '" x2="' + (CW - PAD_RIGHT) + '" y2="' + gy.toFixed(1) + '"/>';
            html += '<text class="agent-chart-tick" x="' + (PAD_LEFT - 8) + '" y="' + (gy + 3).toFixed(1) + '" text-anchor="end">' + escapeHtml(format(gv)) + "</text>";
        }
        return html;
    }

    function linePath(points, sc, valueKey) {
        return "M" + points.map(function (p) {
            return sc.x(p).toFixed(1) + " " + sc.y(p[valueKey]).toFixed(1);
        }).join(" L");
    }

    function hoverDots(points, sc, tipFn) {
        var showDots = points.length <= 120;
        var html = "";
        points.forEach(function (p, i) {
            var cy = sc.y(tipFn(p)).toFixed(1);
            html += '<circle class="agent-chart-hit" cx="' + sc.x(p).toFixed(1) + '" cy="' + cy + '" r="9"><title>' + escapeHtml(agentTooltip(points, i)) + "</title></circle>";
            if (showDots) {
                html += '<circle class="agent-chart-dot" cx="' + sc.x(p).toFixed(1) + '" cy="' + cy + '" r="2.6"/>';
            }
        });
        return html;
    }

    function agentTooltip(points, i) {
        var p = points[i];
        var lines = [
            "Turn " + (i + 1) + " of " + points.length,
            "Tokens " + fmtTokens(p.total) + " (input " + fmtTokens(p.input) + " / output " + fmtTokens(p.output) + ")",
            "Latency " + fmtLatency(p.latency_ms),
            "Updated " + fmtStamp(p.ts)
        ];
        return lines.join("\n");
    }

    function axisTicks(points) {
        var n = points.length;
        var count = Math.min(TICKS, n);
        var out = [];
        for (var i = 0; i < count; i++) {
            var idx = Math.round((i / (count - 1 || 1)) * (n - 1));
            if (out.length && out[out.length - 1].idx === idx) continue;
            out.push({ idx: idx, ts: points[idx].ts });
        }
        return out;
    }

    function tokensChartSvg(points) {
        if (!points.length) {
            return '<p class="agent-chart-empty">No token usage recorded yet.</p>';
        }
        var maxTotal = points.reduce(function (m, p) { return Math.max(m, p.total || 0); }, 0);
        var sc = chartScales(points, Math.max(1, maxTotal));
        var html = '<svg class="agent-chart-svg" viewBox="0 0 ' + CW + " " + CH + '" role="img" aria-label="Token usage over time">';
        html += gridHtml(sc, fmtTokens, 4);
        html += '<path d="' + linePath(points, sc, "input") + '" fill="none" stroke="' + COLOR_INPUT + '" stroke-width="1.6" class="agent-chart-line"/>';
        html += '<path d="' + linePath(points, sc, "output") + '" fill="none" stroke="' + COLOR_OUTPUT + '" stroke-width="1.6" class="agent-chart-line"/>';
        html += '<path d="' + linePath(points, sc, "total") + '" fill="none" stroke="' + COLOR_TOTAL + '" stroke-width="2.4" class="agent-chart-line"/>';
        html += hoverDots(points, sc, function (p) { return p.total || 0; });
        axisTicks(points).forEach(function (t) {
            html += '<text class="agent-chart-axis" x="' + sc.x(points[t.idx]).toFixed(1) + '" y="' + (CH - 6) + '" text-anchor="middle">' + escapeHtml(fmtAxis(t.ts)) + "</text>";
        });
        html += "</svg>";
        return html;
    }

    function latencyChartSvg(points) {
        if (!points.length) {
            return '<p class="agent-chart-empty">No latency recorded yet.</p>';
        }
        var maxLat = points.reduce(function (m, p) { return Math.max(m, p.latency_ms || 0); }, 0);
        var sc = chartScales(points, Math.max(1, maxLat));
        var line = linePath(points, sc, "latency_ms");
        var area = line +
            " L" + sc.x(points[points.length - 1]).toFixed(1) + " " + sc.y(0).toFixed(1) +
            " L" + sc.x(points[0]).toFixed(1) + " " + sc.y(0).toFixed(1) + " Z";
        var html = '<svg class="agent-chart-svg" viewBox="0 0 ' + CW + " " + CH + '" role="img" aria-label="Latency over time">';
        html += gridHtml(sc, fmtLatency, 4);
        html += '<path d="' + area + '" fill="' + COLOR_LATENCY + '" fill-opacity="0.08" stroke="none"/>';
        html += '<path d="' + line + '" fill="none" stroke="' + COLOR_LATENCY + '" stroke-width="2.4" class="agent-chart-line"/>';
        html += hoverDots(points, sc, function (p) { return p.latency_ms || 0; });
        axisTicks(points).forEach(function (t) {
            html += '<text class="agent-chart-axis" x="' + sc.x(points[t.idx]).toFixed(1) + '" y="' + (CH - 6) + '" text-anchor="middle">' + escapeHtml(fmtAxis(t.ts)) + "</text>";
        });
        html += "</svg>";
        return html;
    }

    function chartBlock(title, legendHtml, svgHtml) {
        return '<div class="agent-chart card">' +
            '<div class="agent-chart-head">' +
            '<span class="agent-chart-title">' + escapeHtml(title) + "</span>" +
            (legendHtml ? '<span class="agent-chart-legend">' + legendHtml + "</span>" : "") +
            "</div>" +
            svgHtml +
            "</div>";
    }

    function renderAgentPanel(agent) {
        var tokens = agent.total_tokens || 0;
        var input = agent.input_tokens || 0;
        var output = agent.output_tokens || 0;
        var cached = agent.cached_tokens || 0;
        var reasoning = agent.reasoning_tokens || 0;
        var points = sortedSeries(agent);

        var stat = function (label, value) {
            return '<span class="agent-stat"><span class="agent-stat-label">' + escapeHtml(label) + '</span><strong>' + value + "</strong></span>";
        };

        var panel = document.createElement("div");
        panel.className = "agent-history-panel card";
        panel.innerHTML =
            '<div class="agent-history-head">' +
            '<span class="agent-avatar agent-avatar-blue">' + escapeHtml(avatarFor(agent.agent_name)) + "</span>" +
            '<div class="agent-history-id">' +
            "<h3>" + escapeHtml(agent.agent_name) + "</h3>" +
            "<p>" + escapeHtml(agent.agent_type || "Agent") + " \u00b7 " + escapeHtml(agent.model || "-") + "</p>" +
            "</div>" +
            '<span class="agent-cost-badge">' + fmtCost(agent.cost) + "</span>" +
            "</div>" +

            '<div class="agent-history-stats">' +
            stat("Input", fmtTokens(input)) +
            stat("Output", fmtTokens(output)) +
            stat("Total", fmtTokens(tokens)) +
            stat("Cached", fmtNumber(cached)) +
            stat("Reasoning", fmtNumber(reasoning)) +
            stat("Convos", fmtNumber(agent.conversations)) +
            stat("Turns", fmtNumber(agent.turns)) +
            stat("Avg / turn", fmtTokens(agent.avg_tokens_per_turn) + " tok") +
            stat("Avg latency", fmtLatency(agent.avg_latency_ms)) +
            stat("Last active", fmtRelative(agent.last_active)) +
            "</div>" +

            '<div class="agent-charts">' +
            chartBlock(
                "Token usage",
                '<span class="agent-chart-key"><i style="background:' + COLOR_INPUT + '"></i>Input</span>' +
                '<span class="agent-chart-key"><i style="background:' + COLOR_OUTPUT + '"></i>Output</span>' +
                '<span class="agent-chart-key"><i style="background:' + COLOR_TOTAL + '"></i>Total</span>',
                tokensChartSvg(points)
            ) +
            chartBlock(
                "Latency per turn",
                '<span class="agent-chart-key"><i style="background:' + COLOR_LATENCY + '"></i>Latency</span>',
                latencyChartSvg(points)
            ) +
            "</div>";

        return panel;
    }

    function renderHistory(agents) {
        if (!historyList) return;
        historyList.innerHTML = "";

        var list = agents || [];
        if (!list.length) {
            var empty = document.createElement("div");
            empty.className = "empty-state card";
            empty.innerHTML =
                '<div class="empty-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 18h6M10 22h4"/><path d="M12 2a7 7 0 00-4 12.7c.6.5 1 1.4 1 2.3h6c0-.9.4-1.8 1-2.3A7 7 0 0012 2z"/></svg></div>' +
                "<h3>No agent telemetry yet</h3>" +
                "<p>Chat with an agent in the AI Workspace to start collecting token and latency history.</p>" +
                '<a href="/workspace" class="btn btn-primary">Open AI Workspace</a>';
            historyList.appendChild(empty);
            return;
        }

        list.forEach(function (agent) {
            historyList.appendChild(renderAgentPanel(agent));
        });
    }

    function renderAgentHealth(agents) {
        if (!agentHealthList) return;

        var list = agents || [];
        if (!list.length) {
            agentHealthList.innerHTML = '<p class="agent-health-empty">No agents registered yet. Add one in the Settings page.</p>';
            if (agentHealthUpdated) agentHealthUpdated.textContent = "";
            return;
        }

        var checkedAt = 0;
        var html = "";
        list.forEach(function (a) {
            if (a.checked_at > checkedAt) checkedAt = a.checked_at;
            var live = a.status === "live";
            var latency = a.latency_ms == null ? "—" : fmtLatency(a.latency_ms);
            var lastActive = a.last_active ? fmtRelative(a.last_active) : "No telemetry";
            var initial = escapeHtml((a.name || "A").trim().charAt(0).toUpperCase());
            var detail = a.detail || (live ? "Reachable" : "Unreachable");
            html +=
                '<div class="agent-health-card ' + (live ? "is-live" : "is-down") + '">' +
                '<div class="agent-health-card-top">' +
                '<div class="agent-health-pill">' +
                '<span class="agent-status-dot ' + (live ? "live" : "down") + '" aria-hidden="true"></span>' +
                '<span class="agent-health-label ' + (live ? "live" : "down") + '">' + (live ? "Live" : "Down") + "</span>" +
                "</div>" +
                '<span class="agent-health-latency" title="Probe latency">' + latency + "</span>" +
                "</div>" +
                '<div class="agent-health-meta">' +
                '<span class="agent-health-avatar ' + (live ? "live" : "down") + '">' + initial + "</span>" +
                '<div class="agent-health-id">' +
                '<span class="agent-health-name">' + escapeHtml(a.name) + "</span>" +
                '<span class="agent-health-type">' + escapeHtml(a.type || "Agent") + " \u00b7 " + escapeHtml(a.model || "-") + "</span>" +
                "</div>" +
                "</div>" +
                '<div class="agent-health-cstats">' +
                '<span class="agent-health-cstat"><small>Last active</small><b>' + lastActive + "</b></span>" +
                '<span class="agent-health-cstat"><small>Convos</small><b>' + fmtNumber(a.conversations) + "</b></span>" +
                "</div>" +
                '<p class="agent-health-detail" title="' + escapeHtml(detail) + '">' + escapeHtml(detail) + "</p>" +
                "</div>";
        });
        agentHealthList.innerHTML = html;
        if (agentHealthUpdated) {
            agentHealthUpdated.textContent = checkedAt ? "Checked " + fmtRelative(checkedAt) : "";
        }
    }

    function loadAgentHealth() {
        if (!agentHealthList) return;
        if (agentHealthList.getAttribute("data-loading") === "1") return;
        agentHealthList.setAttribute("data-loading", "1");
        fetch("/api/agent-status")
            .then(function (res) { return res.json(); })
            .then(function (data) {
                agentHealthList.removeAttribute("data-loading");
                renderAgentHealth(data && data.agents);
            })
            .catch(function () {
                agentHealthList.removeAttribute("data-loading");
                agentHealthList.innerHTML = '<p class="agent-health-empty">Unable to check agent status. Backend unavailable.</p>';
            });
    }

    function render(data) {
        if (!data) return;
        renderCost(data.totals, data.agents);
        renderHistory(data.agents);
    }

    var loading = false;
    function load() {
        if (loading) return;
        loading = true;
        fetch("/api/insights")
            .then(function (res) { return res.json(); })
            .then(function (data) {
                render(data);
                loading = false;
            })
            .catch(function () {
                loading = false;
                if (historyList) historyList.innerHTML = '<div class="empty-state card"><div class="empty-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6L6 18M6 6l12 12"/></svg></div><h3>Unable to load insights</h3><p>Backend unavailable.</p></div>';
            });
    }

    if (refreshBtn) {
        refreshBtn.addEventListener("click", function () {
            load();
            loadAgentHealth();
            window.showToast("Insights refreshed.", "success");
        });
    }

    setInterval(function () {
        if (!document.hidden) load();
    }, POLL_MS);

    setInterval(function () {
        if (!document.hidden) loadAgentHealth();
    }, 30000);

    load();
    loadAgentHealth();
})();
