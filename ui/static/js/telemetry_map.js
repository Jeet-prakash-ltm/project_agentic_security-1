(function () {
    "use strict";

    // Map elements
    var mapSection = document.getElementById("telemetryMapSection");
    var mapContainer = document.getElementById("telemetryMap");
    var mapEmpty = document.getElementById("mapEmpty");
    var mapAgentSelect = document.getElementById("mapAgentSelect");
    var mapDetailContent = document.getElementById("mapDetailContent");
    var mapDetailEmpty = document.getElementById("mapDetailEmpty");
    var mapNodeStatusDot = document.getElementById("mapNodeStatusDot");
    var mapNodeLabel = document.getElementById("mapNodeLabel");
    var mapNodeType = document.getElementById("mapNodeType");
    var mapNodeGroup = document.getElementById("mapNodeGroup");
    var mapNodeDesc = document.getElementById("mapNodeDesc");
    var mapNodeHealth = document.getElementById("mapNodeHealth");
    var mapNodeHealthFill = document.getElementById("mapNodeHealthFill");
    var mapTReq = document.getElementById("mapTReq");
    var mapTLat = document.getElementById("mapTLat");
    var mapTErr = document.getElementById("mapTErr");
    var mapTTok = document.getElementById("mapTTok");
    var mapTCost = document.getElementById("mapTCost");
    var mapHistory = document.getElementById("mapHistory");
    var mapHistorySlider = document.getElementById("mapHistorySlider");
    var mapHistoryDate = document.getElementById("mapHistoryDate");
    var mapHistoryOldest = document.getElementById("mapHistoryOldest");
    var mapHistoryNewest = document.getElementById("mapHistoryNewest");
    var mapKpis = document.getElementById("mapKpis");
    var mapToolbar = document.getElementById("mapToolbar");
    var mapFilters = document.getElementById("mapFilters");
    var mapStatusFilters = document.getElementById("mapStatusFilters");
    var mapZoomIn = document.getElementById("mapZoomIn");
    var mapZoomOut = document.getElementById("mapZoomOut");
    var mapZoomFit = document.getElementById("mapZoomFit");
    var ontologyPanel = document.getElementById("ontologyPanel");
    var ontologyGrid = document.getElementById("ontologyGrid");

    var STATUS_HEALTHY = "healthy";
    var STATUS_ERROR = "error";
    var STATUS_REMOVED = "removed";
    var STATUS_STOPPED = "stopped";

    var COLOR_HEALTHY = "#22c55e";
    var COLOR_ERROR = "#ef4444";
    var COLOR_STOPPED = "#f59e0b";
    var COLOR_REMOVED = "#94a3b8";

    var STATUS_LABEL = {};
    STATUS_LABEL[STATUS_HEALTHY] = "Operational";
    STATUS_LABEL[STATUS_ERROR] = "Faulted";
    STATUS_LABEL[STATUS_STOPPED] = "Stopped";
    STATUS_LABEL[STATUS_REMOVED] = "Changed";

    var TYPE_LABEL = {};
    TYPE_LABEL["agent"] = "AI Agent";
    TYPE_LABEL["platform"] = "Azure Platform";
    TYPE_LABEL["model"] = "Model Deployment";
    TYPE_LABEL["service"] = "Service";
    TYPE_LABEL["function"] = "Azure Function";
    TYPE_LABEL["device"] = "Network Device";
    TYPE_LABEL["security"] = "Security";
    TYPE_LABEL["storage"] = "Storage";

    var GROUP_LABEL = {};
    GROUP_LABEL["core"] = "Core";
    GROUP_LABEL["azure"] = "Azure";
    GROUP_LABEL["model"] = "Model";
    GROUP_LABEL["service"] = "Services";
    GROUP_LABEL["function"] = "Functions";
    GROUP_LABEL["device"] = "Devices";
    GROUP_LABEL["security"] = "Security";
    GROUP_LABEL["storage"] = "Storage";

    var GROUP_LEVEL = {};
    GROUP_LEVEL["core"] = 0;
    GROUP_LEVEL["azure"] = 1;
    GROUP_LEVEL["model"] = 2;
    GROUP_LEVEL["service"] = 2;
    GROUP_LEVEL["function"] = 3;
    GROUP_LEVEL["device"] = 3;
    GROUP_LEVEL["security"] = 3;
    GROUP_LEVEL["storage"] = 3;

    // Soft pastel fills per group (Recorded Future "Intelligence Graph" zones).
    var GROUP_FILL = {};
    GROUP_FILL["core"] = "#FDE7EA";
    GROUP_FILL["azure"] = "#E8F0FE";
    GROUP_FILL["model"] = "#F1E9FE";
    GROUP_FILL["service"] = "#E6F7FE";
    GROUP_FILL["function"] = "#FFF0E8";
    GROUP_FILL["device"] = "#EDF0F4";
    GROUP_FILL["security"] = "#F2E9FE";
    GROUP_FILL["storage"] = "#E8F8EE";

    // Accent per group (border when healthy, legend, badges).
    var GROUP_ACCENT = {};
    GROUP_ACCENT["core"] = "#ff5e4f";
    GROUP_ACCENT["azure"] = "#2563EB";
    GROUP_ACCENT["model"] = "#7C3AED";
    GROUP_ACCENT["service"] = "#0EA5E9";
    GROUP_ACCENT["function"] = "#EA580C";
    GROUP_ACCENT["device"] = "#334155";
    GROUP_ACCENT["security"] = "#9333EA";
    GROUP_ACCENT["storage"] = "#16A34A";

    var GROUP_SHAPE = {};
    GROUP_SHAPE["core"] = "hexagon";
    GROUP_SHAPE["azure"] = "ellipse";
    GROUP_SHAPE["model"] = "diamond";
    GROUP_SHAPE["service"] = "round-rectangle";
    GROUP_SHAPE["function"] = "round-rectangle";
    GROUP_SHAPE["device"] = "barrel";
    GROUP_SHAPE["security"] = "diamond";
    GROUP_SHAPE["storage"] = "ellipse";

    var cy = null;
    var mapData = null;
    var historySnapshots = [];
    var currentGroupFilter = "all";
    var currentStatusFilter = "all";
    var flowRaf = null;
    var flowOffset = 0;

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
        if (value >= 1000) return (value / 1000).toFixed(2) + "s";
        return value + "ms";
    }

    function fmtCost(value) {
        if (value == null) return "-";
        var n = Number(value);
        if (n >= 1000) return "$" + (n / 1000).toFixed(2) + "K";
        if (n >= 1) return "$" + n.toFixed(2);
        return "$" + n.toFixed(4);
    }

    function fmtDateTime(ts) {
        if (!ts) return "-";
        var d = new Date(ts * 1000);
        var pad = function (n) { return String(n).padStart(2, "0"); };
        return d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate()) + " " + pad(d.getHours()) + ":" + pad(d.getMinutes());
    }

    function escapeHtml(value) {
        var div = document.createElement("div");
        div.textContent = value == null ? "" : String(value);
        return div.innerHTML;
    }

    // ------------------------------------------------------------
    // GRAPH HELPERS
    // ------------------------------------------------------------

    function nodeColor(status) {
        if (status === STATUS_REMOVED) return COLOR_REMOVED;
        if (status === STATUS_ERROR) return COLOR_ERROR;
        if (status === STATUS_STOPPED) return COLOR_STOPPED;
        return COLOR_HEALTHY;
    }

    function groupLabel(group) {
        return GROUP_LABEL[group] || String(group || "").charAt(0).toUpperCase() + String(group || "").slice(1);
    }

    function groupAccent(group) {
        return GROUP_ACCENT[group] || "#64748b";
    }

    function groupFill(group) {
        return GROUP_FILL[group] || "#f1f5f9";
    }

    function groupShape(group) {
        return GROUP_SHAPE[group] || "ellipse";
    }

    function nodeSize(node) {
        var rps = Number((node.telemetry || {}).requests_per_min || 0);
        var base;
        if (node.type === "agent") base = 76;
        else if (node.type === "platform" || node.type === "device") base = 54;
        else if (node.type === "function") base = 40;
        else base = 44;
        return Math.min(96, base + rps * 0.6);
    }

    function nodeData(node) {
        var telemetry = node.telemetry || {};
        var group = node.group || "core";
        var type = node.type || "service";
        return {
            id: node.id,
            label: node.label,
            type: type,
            status: node.status || STATUS_HEALTHY,
            group: group,
            healthScore: node.health_score == null ? 100 : node.health_score,
            size: nodeSize(node),
            telemetry: telemetry,
            description: node.description || "",
            statusLabel: STATUS_LABEL[node.status] || node.status,
            typeLabel: TYPE_LABEL[type] || type,
            groupLabel: groupLabel(group),
            groupAccent: groupAccent(group),
            groupFill: groupFill(group),
            shape: groupShape(group),
            isAgent: type === "agent",
        };
    }

    function edgeData(edge, i) {
        return {
            id: "e" + i,
            source: edge.source,
            target: edge.target,
            label: edge.label || "",
            load: edge.load == null ? 0.25 : edge.load,
        };
    }

    function buildGraph(nodes, edges) {
        var cyNodes = nodes.map(function (node) {
            return { data: nodeData(node) };
        });
        var cyEdges = edges.map(function (edge, i) {
            return { data: edgeData(edge, i) };
        });
        return cyNodes.concat(cyEdges);
    }

    function edgeColor(load) {
        var l = Math.max(0, Math.min(1, Number(load) || 0));
        if (l < 0.35) return "#cbd5e1";
        if (l < 0.6) return "#f59e0b";
        return "#ff5e4f";
    }

    // Concentric "Intelligence Graph" placement: the agent at the core, with
    // platform/model/services/functions layered in radial rings by zone.
    function computeRadialPositions(nodes) {
        var positions = {};
        var agentId = null;
        nodes.forEach(function (n) {
            if (n.type === "agent") agentId = n.id;
        });

        var byLevel = {};
        nodes.forEach(function (n) {
            var level = GROUP_LEVEL[n.group] == null ? 3 : GROUP_LEVEL[n.group];
            (byLevel[level] = byLevel[level] || []).push(n.id);
        });

        var RADII = [0, 150, 260, 380];

        Object.keys(byLevel).forEach(function (key) {
            var level = parseInt(key, 10);
            var ids = byLevel[level];
            var count = ids.length;
            var radius = RADII[level] == null ? 380 : RADII[level];

            if (level === 0) {
                ids.forEach(function (id, i) {
                    if (id === agentId) {
                        positions[id] = { x: 0, y: 0 };
                        return;
                    }
                    var ang = (i / Math.max(count, 1)) * 2 * Math.PI;
                    positions[id] = { x: Math.cos(ang) * 110, y: Math.sin(ang) * 110 };
                });
                return;
            }

            var offset = count % 2 === 1 ? -Math.PI / 2 : 0;
            ids.forEach(function (id, i) {
                var ang = offset + (i / Math.max(count, 1)) * 2 * Math.PI;
                positions[id] = { x: Math.cos(ang) * radius, y: Math.sin(ang) * radius };
            });
        });

        return positions;
    }

    function stopFlow() {
        if (flowRaf) {
            cancelAnimationFrame(flowRaf);
            flowRaf = null;
        }
    }

    function startFlow() {
        stopFlow();
        var tick = function () {
            if (!cy || cy.destroyed) return;
            if (!document.hidden) {
                flowOffset = (flowOffset + 2) % 12;
                cy.edges().forEach(function (ele) {
                    if (!ele.hasClass("dimmed")) {
                        ele.style("line-dash-offset", flowOffset);
                    }
                });
            }
            flowRaf = requestAnimationFrame(tick);
        };
        flowRaf = requestAnimationFrame(tick);
    }

    function applyFilters() {
        if (!cy) return;
        cy.nodes().forEach(function (ele) {
            var show =
                (currentGroupFilter === "all" || ele.data("group") === currentGroupFilter) &&
                (currentStatusFilter === "all" || ele.data("status") === currentStatusFilter);
            ele.toggleClass("dimmed", !show);
        });
        cy.edges().forEach(function (ele) {
            var source = ele.source();
            var target = ele.target();
            var show = source && target && !source.hasClass("dimmed") && !target.hasClass("dimmed");
            ele.toggleClass("dimmed", !show);
        });
    }

    function focusNeighborhood(node) {
        if (!cy) return;
        var connected = node.closedNeighborhood();
        cy.nodes().forEach(function (ele) {
            if (ele !== node && !connected.has(ele)) {
                ele.addClass("dimmed");
            }
        });
        cy.edges().forEach(function (ele) {
            if (!connected.has(ele)) {
                ele.addClass("dimmed");
            }
        });
    }

    function clearFocus() {
        if (!cy) return;
        cy.$("node, edge").removeClass("dimmed");
        applyFilters();
    }

    function renderFilterChips(nodes) {
        if (!mapFilters) return;
        var groups = {};
        nodes.forEach(function (n) {
            groups[n.group] = (groups[n.group] || 0) + 1;
        });

        var html = '<button class="map-chip' + (currentGroupFilter === "all" ? " is-active" : "") + '" data-filter="group" data-value="all">All</button>';
        Object.keys(GROUP_LABEL).forEach(function (key) {
            if (!groups[key]) return;
            html +=
                '<button class="map-chip" data-filter="group" data-value="' + key + '" data-accent="' + groupAccent(key) + '">' +
                groupLabel(key) + ' <span class="map-chip-count">' + groups[key] + "</span>" +
                "</button>";
        });
        mapFilters.innerHTML = html;
    }

    function renderStatusChips() {
        if (!mapStatusFilters) return;
        var values = [["all", "All"], [STATUS_HEALTHY, "Healthy"], [STATUS_STOPPED, "Stopped"], [STATUS_ERROR, "Faulted"], [STATUS_REMOVED, "Changed"]];
        var html = "";
        values.forEach(function (pair) {
            html +=
                '<button class="map-chip' + (currentStatusFilter === pair[0] ? " is-active" : "") + '" data-filter="status" data-value="' + pair[0] + '">' +
                pair[1] + "</button>";
        });
        mapStatusFilters.innerHTML = html;
    }

    function updateKpis(summary) {
        if (!mapKpis) return;
        if (!summary) {
            mapKpis.hidden = true;
            return;
        }
        mapKpis.hidden = false;
        var set = function (id, value) {
            var el = document.getElementById(id);
            if (el) el.textContent = value;
        };
        set("mapKpiOnline", fmtNumber(summary.healthy) + " / " + fmtNumber(summary.total_nodes));
        set("mapKpiFaults", fmtNumber((summary.faults || 0) + (summary.stopped || 0)));
        set("mapKpiRps", fmtNumber(summary.requests_per_min));
        set("mapKpiLatency", fmtLatency(summary.avg_latency_ms));
        set("mapKpiHealth", summary.avg_health_score + "%");
    }

    function initCy(nodes, edges) {
        stopFlow();

        if (cy) {
            cy.destroy();
            cy = null;
        }

        var positions = computeRadialPositions(nodes);

        cy = window.cytoscape({
            container: mapContainer,
            elements: buildGraph(nodes, edges),
            style: [
                {
                    selector: "node",
                    style: {
                        width: "mapData('size')",
                        height: "mapData('size')",
                        shape: "data('shape')",
                        "background-color": "data('groupFill')",
                        "background-opacity": 1,
                        "border-width": 3,
                        "border-color": function (ele) {
                            return nodeColor(ele.data("status"));
                        },
                        "border-opacity": 0.95,
                        label: "data(label)",
                        "font-family": "Inter, sans-serif",
                        "font-size": 10.5,
                        "font-weight": 700,
                        "text-wrap": "wrap",
                        "text-max-width": "96px",
                        "text-valign": "bottom",
                        "text-halign": "center",
                        "text-margin-y": 9,
                        color: "#0B1B2B",
                        "text-outline-width": 3,
                        "text-outline-color": "#ffffff",
                        "text-outline-opacity": 0.9,
                        "overlay-opacity": 0,
                        "shadow-blur": 14,
                        "shadow-color": "data('groupAccent')",
                        "shadow-opacity": 0.35,
                    },
                },
                {
                    selector: "node[isAgent='true']",
                    style: {
                        "background-color": "#ff5e4f",
                        "border-width": 3.5,
                        "border-color": function (ele) {
                            return nodeColor(ele.data("status"));
                        },
                        "shadow-blur": 26,
                        "shadow-opacity": 0.55,
                        "font-size": 12,
                        color: "#ffffff",
                        "text-outline-width": 0,
                    },
                },
                {
                    selector: "node.dimmed",
                    style: {
                        opacity: 0.12,
                    },
                },
                {
                    selector: "node.selected, node.hovered",
                    style: {
                        "border-width": 3.5,
                        "border-color": "#0B1B2B",
                        "shadow-blur": 20,
                        "shadow-opacity": 0.45,
                    },
                },
                {
                    selector: "node[status='removed']",
                    style: {
                        "border-style": "dashed",
                        "background-opacity": 0.5,
                        opacity: 0.8,
                    },
                },
                {
                    selector: "edge",
                    style: {
                        width: "mapData('load', 1, 5.5)",
                        "line-color": function (ele) {
                            return edgeColor(ele.data("load"));
                        },
                        "line-style": "dashed",
                        "line-dash-pattern": [5, 5],
                        "line-dash-offset": 0,
                        "target-arrow-color": function (ele) {
                            return edgeColor(ele.data("load"));
                        },
                        "target-arrow-shape": "triangle",
                        "arrow-scale": 0.8,
                        "curve-style": "bezier",
                        "overlay-opacity": 0,
                    },
                },
                {
                    selector: "edge[label]",
                    style: {
                        label: "data(label)",
                        "font-size": 8.5,
                        "font-family": "Inter, sans-serif",
                        color: "#64748b",
                        "text-rotation": "autorotate",
                        "text-background-color": "#ffffff",
                        "text-background-opacity": 0.8,
                        "text-background-padding": 2,
                    },
                },
                {
                    selector: "edge.dimmed",
                    style: {
                        opacity: 0.06,
                    },
                },
            ],
            layout: {
                name: "preset",
                positions: positions,
                animate: true,
                animationDuration: 600,
                padding: 30,
            },
            wheelSensitivity: 0.25,
            minZoom: 0.25,
            maxZoom: 2.5,
        });

        cy.ready(function () {
            cy.fit(undefined, 40);
            startFlow();
        });

        cy.on("tap", "node", function (evt) {
            var node = evt.target;
            cy.$("node").unselect();
            node.select();
            focusNeighborhood(node);
            showNodeDetail(node.data());
        });

        cy.on("mouseover", "node", function (evt) {
            var node = evt.target;
            cy.$("node").removeClass("hovered");
            node.addClass("hovered");
            focusNeighborhood(node);
            showNodeDetail(node.data());
        });

        cy.on("mouseout", "node", function (evt) {
            evt.target.removeClass("hovered");
            clearFocus();
        });

        cy.on("tap", function (evt) {
            if (evt.target === cy) {
                cy.$("node").unselect();
                clearFocus();
                hideNodeDetail();
            }
        });
    }

    // ------------------------------------------------------------
    // ONTOLOGY PANEL
    // ------------------------------------------------------------

    function renderOntology(nodes, edges, agentName) {
        if (!ontologyPanel || !ontologyGrid) return;
        if (!nodes || !nodes.length) {
            ontologyPanel.hidden = true;
            return;
        }
        ontologyPanel.hidden = false;

        var byId = {};
        nodes.forEach(function (n) { byId[n.id] = n; });

        var uses = [];
        var calls = [];
        var depends = [];

        (edges || []).forEach(function (edge) {
            var source = byId[edge.source];
            var target = byId[edge.target];
            if (!source || !target) return;

            if (source.type === "agent") {
                if (target.type === "platform" || target.type === "model" || target.type === "service") {
                    uses.push(target.label);
                } else {
                    depends.push(target.label);
                }
            }
            if (source.type === "gateway" && target.type === "function") {
                calls.push(target.label);
            }
            if ((source.type === "service" || source.type === "platform") && target.type === "function") {
                calls.push(target.label);
            }
            if (target.type === "agent") {
                if (source.type === "platform" || source.type === "model" || source.type === "service") {
                    uses.push(source.label);
                } else {
                    depends.push(source.label);
                }
            }
        });

        // Functions and firewall are dependencies when only linked from functions.
        nodes.forEach(function (n) {
            if (n.type === "function") {
                var already = calls.indexOf(n.label) !== -1;
                if (!already && n.type === "function") {
                    depends.push(n.label);
                }
            }
            if (n.type === "device") depends.push(n.label);
            if (n.type === "security") depends.push(n.label);
            if (n.type === "storage") depends.push(n.label);
        });

        var unique = function (arr) {
            var seen = {};
            return arr.filter(function (item) {
                if (seen[item]) return false;
                seen[item] = true;
                return true;
            });
        };

        var production = {
            "fn-compliance": "Compliance Findings",
            "fn-summary": "Executive Summary",
            "fn-excel": "Assessment Workbook",
            "fn-assessment": "Assessment Results",
        };

        var produces = [];
        nodes.forEach(function (n) {
            if (production[n.id]) produces.push(production[n.id]);
        });
        if (!produces.length) {
            produces = ["Findings", "Reports", "Executive Summary"];
        }

        function section(title, items, accent) {
            if (!items.length) return "";
            var chips = items.map(function (item) {
                return '<span class="onto-chip" style="--onto-accent:' + accent + '">' + escapeHtml(item) + "</span>";
            }).join("");
            return (
                '<div class="onto-block">' +
                '<span class="onto-label">' + title + "</span>" +
                '<div class="onto-chips">' + chips + "</div>" +
                "</div>"
            );
        }

        ontologyGrid.innerHTML =
            section("Uses", unique(uses), "#2563EB") +
            section("Calls", unique(calls), "#EA580C") +
            section("Depends On", unique(depends), "#9333EA") +
            section("Produces", unique(produces), "#16A34A");
    }

    // ------------------------------------------------------------
    // DETAIL PANEL
    // ------------------------------------------------------------

    function healthColor(score) {
        if (score == null) return COLOR_ERROR;
        if (score >= 70) return COLOR_HEALTHY;
        if (score >= 40) return COLOR_REMOVED;
        return COLOR_ERROR;
    }

    function showNodeDetail(data) {
        if (!mapDetailContent || !mapDetailEmpty) return;
        mapDetailEmpty.hidden = true;
        mapDetailContent.hidden = false;

        var color = nodeColor(data.status);
        mapNodeStatusDot.style.background = color;
        mapNodeLabel.textContent = data.label;
        mapNodeType.textContent = data.statusLabel + " · " + data.typeLabel;
        mapNodeGroup.textContent = data.groupLabel;
        mapNodeGroup.style.background = data.groupFill || "#f1f5f9";
        mapNodeGroup.style.color = data.groupAccent || "#64748b";
        mapNodeDesc.textContent = data.description || "";

        var health = Number(data.healthScore);
        mapNodeHealth.textContent = (health == null ? "-" : health + "%");
        if (mapNodeHealthFill) {
            mapNodeHealthFill.style.width = (health == null ? 0 : Math.max(0, Math.min(100, health))) + "%";
            mapNodeHealthFill.style.background = healthColor(health);
        }

        var t = data.telemetry || {};
        mapTReq.textContent = t.requests_per_min == null ? "-" : t.requests_per_min + " / min";
        mapTLat.textContent = fmtLatency(t.latency_ms);
        mapTErr.textContent = fmtNumber(t.errors);
        mapTTok.textContent = fmtTokens(t.tokens);
        mapTCost.textContent = fmtCost(t.cost);
    }

    function hideNodeDetail() {
        if (mapDetailContent) mapDetailContent.hidden = true;
        if (mapDetailEmpty) mapDetailEmpty.hidden = false;
    }

    // ------------------------------------------------------------
    // LOADING
    // ------------------------------------------------------------

    function populateAgentSelect(agents) {
        if (!mapAgentSelect) return;
        var current = mapAgentSelect.value;
        mapAgentSelect.innerHTML = '<option value="">Select an agent…</option>';
        (agents || []).forEach(function (agent) {
            var opt = document.createElement("option");
            opt.value = agent.id;
            opt.textContent = agent.name + (agent.connected ? " · Connected" : "");
            mapAgentSelect.appendChild(opt);
        });
        if (current) mapAgentSelect.value = current;
    }

    function renderMap(nodes, edges, agentName) {
        if (!mapContainer) return;
        if (!window.cytoscape) {
            if (mapEmpty) {
                mapEmpty.style.display = "flex";
                mapEmpty.querySelector("h4").textContent = "Cytoscape.js failed to load";
            }
            return;
        }
        if (mapEmpty) mapEmpty.style.display = "none";
        if (mapToolbar) mapToolbar.hidden = false;
        renderFilterChips(nodes);
        renderStatusChips();
        renderOntology(nodes, edges, agentName);
        initCy(nodes, edges);
    }

    function renderHistorySlider() {
        if (!mapHistory || !mapHistorySlider) return;

        var snapshots = historySnapshots || [];
        if (!snapshots.length) {
            mapHistory.hidden = true;
            return;
        }
        mapHistory.hidden = false;
        mapHistorySlider.max = snapshots.length - 1;
        mapHistorySlider.value = snapshots.length - 1;
        mapHistoryOldest.textContent = snapshots[0].label || "-";
        mapHistoryNewest.textContent = snapshots[snapshots.length - 1].label || "-";
        mapHistoryDate.textContent = snapshots[snapshots.length - 1].label || "-";
    }

    function applyHistoryIndex(index) {
        if (!mapHistorySlider) return;
        index = Math.max(0, Math.min(index, historySnapshots.length - 1));
        mapHistorySlider.value = index;
        var snapshot = historySnapshots[index];
        if (!snapshot) return;
        mapHistoryDate.textContent = snapshot.label || "-";

        if (index === historySnapshots.length - 1 && mapData) {
            // Current view: live nodes only (removed nodes hidden).
            renderMap(mapData.nodes, mapData.edges, mapData.agent && mapData.agent.name);
            return;
        }

        // Historical view: show nodes as of that date.
        // Nodes no longer present in the current map render amber (changed/removed).
        var currentIds = {};
        (mapData ? mapData.nodes : []).forEach(function (n) { currentIds[n.id] = true; });

        var nodes = (snapshot.nodes || []).map(function (n) {
            var copy = Object.assign({}, n);
            if (!currentIds[n.id]) {
                copy.status = STATUS_REMOVED;
            }
            return copy;
        });
        var ids = {};
        nodes.forEach(function (n) { ids[n.id] = true; });
        var edges = mapData ? mapData.edges.filter(function (edge) {
            return ids[edge.source] && ids[edge.target];
        }) : [];
        renderMap(nodes, edges, mapData.agent && mapData.agent.name);
        hideNodeDetail();
    }

    function loadMap(agentId) {
        if (!mapSection) return;
        if (!agentId) {
            renderMap([], [], "");
            if (mapEmpty) {
                mapEmpty.style.display = "flex";
                mapEmpty.querySelector("h4").textContent = "Select an agent to view its telemetry map";
            }
            if (mapHistory) mapHistory.hidden = true;
            if (mapToolbar) mapToolbar.hidden = true;
            if (mapKpis) mapKpis.hidden = true;
            if (ontologyPanel) ontologyPanel.hidden = true;
            hideNodeDetail();
            renderSystemSource(null);
            return;
        }

        Promise.all([
            fetch("/api/telemetry-map?agent_id=" + encodeURIComponent(agentId)).then(function (r) { return r.json(); }),
            fetch("/api/telemetry-map/history?agent_id=" + encodeURIComponent(agentId)).then(function (r) { return r.json(); }),
        ]).then(function (results) {
            mapData = results[0];
            historySnapshots = results[1].snapshots || [];
            updateKpis(mapData.summary);
            renderSystemSource(mapData.system);
            if (mapData.error || !mapData.nodes || !mapData.nodes.length) {
                renderMap([], [], "");
                if (mapEmpty) {
                    mapEmpty.style.display = "flex";
                    mapEmpty.querySelector("h4").textContent = mapData.error || "No map data";
                }
                return;
            }
            renderMap(mapData.nodes, mapData.edges, mapData.agent && mapData.agent.name);
            renderHistorySlider();
            applyHistoryIndex(historySnapshots.length - 1);
        }).catch(function () {
            if (mapEmpty) {
                mapEmpty.style.display = "flex";
                mapEmpty.querySelector("h4").textContent = "Unable to load telemetry map";
            }
        });
    }

    function loadAgentsForMap() {
        fetch("/api/agents")
            .then(function (res) {
                return res.json();
            })
            .then(function (data) {
                populateAgentSelect((data && data.agents) || []);
                var connected = (data && data.agents || []).filter(function (a) { return a.connected; });
                if (connected[0]) {
                    mapAgentSelect.value = connected[0].id;
                    loadMap(connected[0].id);
                } else {
                    loadMap("");
                }
            })
            .catch(function () {
                loadMap("");
            });
    }

    function renderSystemSource(system) {
        var chip = document.getElementById("mapSourceChip");
        if (!chip) return;
        if (!system) {
            chip.hidden = true;
            return;
        }
        chip.hidden = false;
        var source = system.source || "sample";
        var live = source === "live";
        chip.textContent = live ? "Live Data" : "Sample Data";
        chip.className = "map-source-chip" + (live ? "" : " is-sample");
    }

    if (mapAgentSelect) {
        mapAgentSelect.addEventListener("change", function () {
            loadMap(mapAgentSelect.value);
        });
    }

    if (mapHistorySlider) {
        mapHistorySlider.addEventListener("input", function () {
            applyHistoryIndex(parseInt(mapHistorySlider.value, 10));
        });
    }

    if (mapFilters) {
        mapFilters.addEventListener("click", function (evt) {
            var chip = evt.target.closest(".map-chip");
            if (!chip) return;
            currentGroupFilter = chip.getAttribute("data-value");
            mapFilters.querySelectorAll(".map-chip").forEach(function (c) { c.classList.remove("is-active"); });
            chip.classList.add("is-active");
            applyFilters();
        });
    }

    if (mapStatusFilters) {
        mapStatusFilters.addEventListener("click", function (evt) {
            var chip = evt.target.closest(".map-chip");
            if (!chip) return;
            currentStatusFilter = chip.getAttribute("data-value");
            mapStatusFilters.querySelectorAll(".map-chip").forEach(function (c) { c.classList.remove("is-active"); });
            chip.classList.add("is-active");
            applyFilters();
        });
    }

    if (mapZoomIn) {
        mapZoomIn.addEventListener("click", function () {
            if (cy) cy.zoom({ level: cy.zoom() * 1.3, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
        });
    }

    if (mapZoomOut) {
        mapZoomOut.addEventListener("click", function () {
            if (cy) cy.zoom({ level: cy.zoom() / 1.3, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
        });
    }

    if (mapZoomFit) {
        mapZoomFit.addEventListener("click", function () {
            if (cy) cy.fit(undefined, 40);
        });
    }

    loadAgentsForMap();
})();
