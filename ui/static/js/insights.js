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

    var insightsAgents = [];
    var selectedAgent = "";
    var agentRanges = {};
    var insightsRendered = false;
    var healthRendered = false;

    var POLL_MS = 5000;
    var TICKS = 5;

    var RANGES = [
        { key: "day", label: "Previous Day", seconds: 86400 },
        { key: "week", label: "Past 1 week", seconds: 7 * 86400 },
        { key: "month", label: "Past month", seconds: 30 * 86400 },
        { key: "6mo", label: "Past 6 months", seconds: 182 * 86400 },
        { key: "year", label: "Past 1 year", seconds: 365 * 86400 },
        { key: "custom", label: "Custom range" }
    ];

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

    function rangeKey(stored) {
        if (!stored) return "day";
        if (typeof stored === "string") return stored;
        return stored.key || "day";
    }

    function rangeLookup(key) {
        for (var i = 0; i < RANGES.length; i += 1) {
            if (RANGES[i].key === key) return RANGES[i];
        }
        return null;
    }

    function todayIso() {
        var d = new Date();
        var month = d.getMonth() + 1;
        var day = d.getDate();
        return d.getFullYear() + "-" + (month < 10 ? "0" + month : month) + "-" +
            (day < 10 ? "0" + day : day);
    }

    function dayBound(iso, endOfDay) {
        var parts = String(iso || "").split("-");
        if (parts.length !== 3) return 0;
        var year = Number(parts[0]);
        var month = Number(parts[1]);
        var day = Number(parts[2]);
        if (!year || !month || !day) return 0;
        var d = new Date(year, month - 1, day);
        if (endOfDay) d.setHours(23, 59, 59, 999);
        else d.setHours(0, 0, 0, 0);
        return d.getTime() / 1000;
    }

    function storedRange(name) {
        var stored = agentRanges[name] || { key: "day" };
        if (typeof stored === "string") stored = { key: stored };
        if (!rangeLookup(stored.key)) stored.key = "day";
        agentRanges[name] = stored;
        return stored;
    }

    function filterPoints(points, stored) {
        if (!stored) return points;
        var key = rangeKey(stored);
        if (key === "custom") {
            if (!stored.start || !stored.end) return [];
            var from = dayBound(stored.start, false);
            var to = dayBound(stored.end, true);
            if (!from || !to) return points;
            if (to < from) {
                var swappedFrom = dayBound(stored.end, false);
                var swappedTo = dayBound(stored.start, true);
                from = swappedFrom;
                to = swappedTo;
            }
            return points.filter(function (p) {
                var ts = p.ts || 0;
                return ts >= from && ts <= to;
            });
        }
        var range = rangeLookup(key);
        if (!range || !range.seconds) return points;
        var nowSec = Date.now() / 1000;
        return points.filter(function (p) { return (p.ts || 0) >= nowSec - range.seconds; });
    }

    function rangeSelectHtml(stored) {
        var key = rangeKey(stored);
        if (!rangeLookup(key)) key = "day";
        var options = RANGES.map(function (range) {
            return '<option value="' + range.key + '"' +
                (range.key === key ? " selected" : "") + ">" +
                escapeHtml(range.label) + "</option>";
        }).join("");
        var custom = key === "custom";
        var start = (stored && stored.start) || "";
        var end = (stored && stored.end) || "";
        var today = todayIso();
        var startMax = end && end < today ? end : today;
        var endMin = start || "";
        return '<div class="agent-range-picker">' +
            '<span class="agent-range-label">Time range</span>' +
            '<div class="agent-range-controls">' +
            '<select class="agent-range-select" data-range-select aria-label="Time range">' +
            options + "</select>" +
            '<div class="agent-range-custom"' + (custom ? "" : " hidden") + ">" +
            '<label class="agent-range-date-field">Start date' +
            '<input type="date" class="agent-range-date" data-range-start value="' +
            escapeHtml(start) + '" max="' + escapeHtml(startMax) + '"></label>' +
            '<label class="agent-range-date-field">End date' +
            '<input type="date" class="agent-range-date" data-range-end value="' +
            escapeHtml(end) + '" max="' + escapeHtml(today) + '"' +
            (endMin ? ' min="' + escapeHtml(endMin) + '"' : "") +
            "></label>" +
            "</div></div></div>";
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
        var allPoints = sortedSeries(agent);
        var selectedRange = storedRange(agent.agent_name);
        var points = filterPoints(allPoints, selectedRange);

        var stat = function (label, value) {
            return '<span class="agent-stat"><span class="agent-stat-label">' + escapeHtml(label) + '</span><strong>' + value + "</strong></span>";
        };

        var panel = document.createElement("div");
        panel.className = "agent-history-panel card";
        panel.setAttribute("data-agent-name", agent.agent_name || "");
        panel.innerHTML =
            '<div class="agent-history-head">' +
            '<span class="agent-avatar agent-avatar-blue">' + escapeHtml(avatarFor(agent.agent_name)) + "</span>" +
            '<div class="agent-history-id">' +
            "<h3>" + escapeHtml(agent.agent_name) + "</h3>" +
            "<p>" + escapeHtml(agent.agent_type || "Agent") + " \u00b7 " + escapeHtml(agent.model || "-") + "</p>" +
            "</div>" +
            '<span class="agent-cost-badge">' + fmtCost(agent.cost) + "</span>" +
            "</div>" +
            rangeSelectHtml(selectedRange) +

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

    function historyEmpty(title, message, withAction) {
        var empty = document.createElement("div");
        empty.className = "empty-state card";
        empty.innerHTML =
            '<div class="empty-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 18h6M10 22h4"/><path d="M12 2a7 7 0 00-4 12.7c.6.5 1 1.4 1 2.3h6c0-.9.4-1.8 1-2.3A7 7 0 0012 2z"/></svg></div>' +
            "<h3>" + escapeHtml(title) + "</h3>" +
            "<p>" + message + "</p>" +
            (withAction ? '<a href="/workspace" class="btn btn-primary">Open AI Workspace</a>' : "");
        return empty;
    }

    function renderSelectedHistory() {
        if (!historyList) return;
        if (historyList.contains(document.activeElement) &&
            document.activeElement.closest(".agent-range-picker")) {
            return;
        }

        if (!selectedAgent) {
            historyList.setAttribute("hidden", "");
            historyList.innerHTML = "";
            return;
        }

        historyList.removeAttribute("hidden");
        historyList.innerHTML = "";

        var agent = null;
        for (var i = 0; i < insightsAgents.length; i += 1) {
            if ((insightsAgents[i].agent_name || "") === selectedAgent) {
                agent = insightsAgents[i];
                break;
            }
        }

        if (!agent) {
            historyList.appendChild(historyEmpty(
                "No history for " + selectedAgent,
                "This agent has not recorded any usage yet. Chat with it in the AI Workspace to start tracking.",
                true
            ));
            return;
        }

        historyList.appendChild(renderAgentPanel(agent));
    }

    function renderHistory(agents) {
        insightsAgents = agents || [];
        renderSelectedHistory();
    }

    function renderAgentHealth(agents) {
        if (!agentHealthList) return;
        healthRendered = true;

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
            var initial = escapeHtml((a.name || "A").trim().charAt(0).toUpperCase());
            var active = (a.name || "") === selectedAgent;
            html +=
                '<div class="agent-health-card ' + (live ? "is-live" : "is-down") + (active ? " is-active" : "") +
                '" data-agent-name="' + escapeHtml(a.name || "") + '" role="button" tabindex="0" aria-pressed="' +
                (active ? "true" : "false") + '">' +
                '<div class="agent-health-card-top">' +
                '<span class="agent-health-avatar ' + (live ? "live" : "down") + '">' + initial + "</span>" +
                '<span class="agent-health-pill">' +
                '<span class="agent-status-dot ' + (live ? "live" : "down") + '" aria-hidden="true"></span>' +
                '<span class="agent-health-label ' + (live ? "live" : "down") + '">' + (live ? "Live" : "Down") + "</span>" +
                "</span>" +
                "</div>" +
                '<span class="agent-health-name" title="' + escapeHtml(a.name || "") + '">' + escapeHtml(a.name) + "</span>" +
                "</div>";
        });
        agentHealthList.innerHTML = html;
        if (agentHealthUpdated) {
            agentHealthUpdated.textContent = checkedAt ? "Checked " + fmtRelative(checkedAt) : "";
        }
    }

    function markActiveCards() {
        if (!agentHealthList) return;
        var cards = agentHealthList.querySelectorAll(".agent-health-card");
        for (var i = 0; i < cards.length; i += 1) {
            var on = cards[i].getAttribute("data-agent-name") === selectedAgent;
            cards[i].classList.toggle("is-active", on);
            cards[i].setAttribute("aria-pressed", on ? "true" : "false");
        }
    }

    function selectAgent(name) {
        selectedAgent = name || "";
        markActiveCards();
        renderSelectedHistory();
    }

    if (historyList) {
        historyList.addEventListener("change", function (event) {
            var panel = event.target.closest(".agent-history-panel");
            var name = panel ? panel.getAttribute("data-agent-name") : "";
            if (!name) return;
            var stored = storedRange(name);
            if (event.target.matches("[data-range-select]")) {
                stored.key = event.target.value || "day";
                if (stored.key !== "custom") {
                    stored.start = "";
                    stored.end = "";
                    agentRanges[name] = stored;
                    renderSelectedHistory();
                    return;
                }
                agentRanges[name] = stored;
                var customBox = panel.querySelector(".agent-range-custom");
                if (customBox) customBox.removeAttribute("hidden");
                return;
            }
            if (event.target.matches("[data-range-start], [data-range-end]")) {
                var startEl = panel.querySelector("[data-range-start]");
                var endEl = panel.querySelector("[data-range-end]");
                stored.key = "custom";
                stored.start = startEl ? startEl.value : "";
                stored.end = endEl ? endEl.value : "";
                agentRanges[name] = stored;
                if (startEl && endEl) {
                    var today = todayIso();
                    startEl.max = stored.end && stored.end < today ? stored.end : today;
                    endEl.max = today;
                    endEl.min = stored.start || "";
                }
                if (stored.start && stored.end) renderSelectedHistory();
            }
        });
    }

    if (agentHealthList) {
        agentHealthList.addEventListener("click", function (event) {
            var card = event.target.closest(".agent-health-card");
            if (!card) return;
            selectAgent(card.getAttribute("data-agent-name") || "");
        });
        agentHealthList.addEventListener("keydown", function (event) {
            if (event.key !== "Enter" && event.key !== " ") return;
            var card = event.target.closest(".agent-health-card");
            if (!card) return;
            event.preventDefault();
            selectAgent(card.getAttribute("data-agent-name") || "");
        });
    }

    function loadAgentHealth() {
        if (!agentHealthList) return;
        if (agentHealthList.getAttribute("data-loading") === "1") return;
        if (!healthRendered && window.loadingHtml) {
            agentHealthList.innerHTML = window.loadingHtml("Checking agents…");
        }
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
        insightsRendered = true;
        renderCost(data.totals, data.agents);
        renderHistory(data.agents);
    }

    function showInsightsLoading(force) {
        if (insightsRendered && !force) return;
        [costTotal, costTokens, costConvs, costLatency].forEach(function (el) {
            if (el) el.innerHTML = '<span class="spinner"></span>';
        });
        if (costDrivers && window.loadingHtml) {
            costDrivers.innerHTML = window.loadingHtml("Loading cost data…");
        }
        if (historyList && window.loadingHtml) {
            historyList.removeAttribute("hidden");
            historyList.innerHTML = '<div class="empty-state card">' +
                window.loadingHtml("Loading agent usage history…") + "</div>";
        }
    }

    var loading = false;
    function load(force) {
        if (loading) return;
        loading = true;
        if (force) { insightsRendered = false; healthRendered = false; }
        showInsightsLoading(force);
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
            load(true);
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
