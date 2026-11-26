/* ============================================================
   SYSTEM INFO — AI Workspace agents
   Compact Maestro hero, 4-column specialist grid, live counters,
   filters/search and a right-side detail drawer. Every health,
   latency, activity and component value comes from the backend.
   ============================================================ */

(function () {
    "use strict";

    var MASTER_ID = "master-orchestrator-agent";
    var FEAT_ID = "netsec-execution-agent";
    var RETIRED = { "zero-trust-assessment-agent": true };

    var grid = document.getElementById("sysAgentCards");
    var hero = document.getElementById("sysHero");
    var emptyNote = document.getElementById("sysEmpty");
    var loadingEl = document.getElementById("sysLoading");
    var errorEl = document.getElementById("sysError");
    var refreshBtn = document.getElementById("sysRefreshBtn");
    var refreshLabel = document.getElementById("sysRefreshLabel");
    var lastSyncEl = document.getElementById("sysLastSync");
    var searchEl = document.getElementById("sysSearch");
    var filtersEl = document.getElementById("sysFilters");

    var drawer = document.getElementById("agentDetailDrawer");
    var backdrop = document.getElementById("agentDetailBackdrop");
    var drawerBody = document.getElementById("agentDetailBody");
    var drawerTitle = document.getElementById("agentDetailTitle");
    var drawerSub = document.getElementById("agentDetailSub");
    var drawerHex = document.getElementById("agentDetailHex");
    var drawerClose = document.getElementById("agentDetailClose");

    var counters = {
        total: document.getElementById("countTotal"),
        live: document.getElementById("countLive"),
        degraded: document.getElementById("countDegraded"),
        down: document.getElementById("countDown")
    };

    var CAPABILITIES = {
        "master-orchestrator-agent":
            "Coordinates the network, cloud and firewall specialist agents so operators can assess, investigate and change security posture from one conversation.",
        "firewall-audit-agent":
            "Performs compliance assessments, generates executive summaries and reports, and returns prioritised security findings with remediation guidance.",
        "netsec-execution-agent":
            "Prepares rule and policy changes, object and network changes on Palo Alto firewalls, and queues approved jobs through the execution worker.",
        "incident-response-agent-cloud-security":
            "Delivers cloud security posture management, integrates Microsoft Defender for Cloud and Microsoft Sentinel, analyses incidents and performs containment actions.",
        "zero-trust-with-endpoint-agent":
            "Assesses Zero Trust posture with endpoint evidence across identity, devices, compliance and infrastructure, then returns findings and remediation guidance.",
        "cloud-security-agent":
            "Reviews Azure cloud security posture, exposure and configuration issues, then returns guidance for operators.",
        "heimdrix-data-agent":
            "Reads persisted Zero Trust and firewall assessment history from the HeimDRIX data store so operators can review and compare stored results."
    };

    var META = {
        "master-orchestrator-agent": { name: "Maestro AI", sub: "Master Orchestrator" },
        "heimdrix-data-agent": { name: "HeimDRIX Data" },
        "firewall-audit-agent": { name: "Firewall Audit Agent" },
        "zero-trust-with-endpoint-agent": { name: "Zero Trust" },
        "netsec-execution-agent": { name: "FEAT", sub: "Firewall Execution Agent" }
    };

    var CATEGORY_LABEL = {
        assessment: "Assessment",
        data: "Data",
        operations: "Operations"
    };

    var RANK = {
        "heimdrix-data-agent": 1,
        "firewall-audit-agent": 2,
        "zero-trust-with-endpoint-agent": 3,
        "netsec-execution-agent": 4
    };

    var state = {
        rows: [],
        registry: {},
        filter: "all",
        query: "",
        refreshing: false,
        lastSync: 0,
        openAgent: null,
        featHealth: null
    };

    function escapeHtml(value) {
        return String(value == null ? "" : value)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#39;");
    }

    function initials(name) {
        var parts = String(name || "").trim().split(/[\s_-]+/).filter(Boolean);
        if (!parts.length) {
            return "AI";
        }
        if (parts.length === 1) {
            return parts[0].slice(0, 2).toUpperCase();
        }
        return (parts[0][0] + parts[1][0]).toUpperCase();
    }

    function idOf(agent) {
        return String((agent && agent.id) || "").toLowerCase();
    }

    function isMaster(agent) {
        return idOf(agent) === MASTER_ID ||
            String(agent.type || "").toLowerCase() === "master orchestrator";
    }

    function isFeat(agent) {
        var id = idOf(agent);
        var hay = ((agent.name || "") + " " + (agent.type || "")).toLowerCase();
        return id === FEAT_ID ||
            hay.indexOf("firewall execution") !== -1 ||
            /\bfeat\b/.test(hay);
    }

    function hayOf(agent) {
        return (
            idOf(agent) + " " +
            (agent.name || "") + " " +
            (agent.type || "")
        ).toLowerCase();
    }

    function isHeimdrix(agent) {
        return hayOf(agent).indexOf("heimdrix") !== -1;
    }

    function isZeroTrust(agent) {
        var hay = hayOf(agent);
        return hay.indexOf("zero trust") !== -1 || hay.indexOf("zero-trust") !== -1;
    }

    function isAudit(agent) {
        var hay = hayOf(agent);
        return hay.indexOf("firewall audit") !== -1 ||
            (hay.indexOf("audit") !== -1 && hay.indexOf("firewall") !== -1);
    }

    function categoryOf(agent) {
        if (isFeat(agent)) {
            return "operations";
        }
        if (isHeimdrix(agent)) {
            return "data";
        }
        if (isAudit(agent) || isZeroTrust(agent)) {
            return "assessment";
        }
        return "operations";
    }

    function displayName(agent) {
        var id = idOf(agent);
        if (isHeimdrix(agent)) {
            return "HeimDRIX Data";
        }
        if (isZeroTrust(agent)) {
            return "Zero Trust";
        }
        if (isAudit(agent)) {
            return "Firewall Audit Agent";
        }
        if (isFeat(agent)) {
            return "FEAT";
        }
        if (META[id] && META[id].name) {
            return META[id].name;
        }
        return agent.name || agent.id || "Agent";
    }

    function displaySub(agent) {
        var id = idOf(agent);
        if (isFeat(agent)) {
            return "Firewall Execution Agent";
        }
        if (META[id] && META[id].sub) {
            return META[id].sub;
        }
        if (isHeimdrix(agent)) {
            return agent.type || "Data";
        }
        if (agent.type && agent.type !== displayName(agent)) {
            return agent.type;
        }
        return "";
    }

    function rankOf(agent) {
        if (isHeimdrix(agent)) {
            return RANK["heimdrix-data-agent"];
        }
        if (isAudit(agent)) {
            return RANK["firewall-audit-agent"];
        }
        if (isZeroTrust(agent)) {
            return RANK["zero-trust-with-endpoint-agent"];
        }
        if (isFeat(agent)) {
            return RANK["netsec-execution-agent"];
        }
        var id = idOf(agent);
        return RANK[id] || 9;
    }

    function capabilityFor(agent) {
        var id = idOf(agent);
        if (CAPABILITIES[id]) {
            return CAPABILITIES[id];
        }
        if (isHeimdrix(agent) && CAPABILITIES["heimdrix-data-agent"]) {
            return CAPABILITIES["heimdrix-data-agent"];
        }
        var type = agent.type || "Agent";
        return "Registered as " + type + ". The backend does not publish a capability description for this agent.";
    }

    function normalizeStatus(value) {
        var status = String(value || "").toLowerCase();
        if (status === "live" || status === "operational" || status === "healthy") {
            return "live";
        }
        if (status === "degraded" || status === "partial" || status === "warning") {
            return "degraded";
        }
        if (status === "down" || status === "offline" || status === "unreachable" || status === "fail") {
            return "down";
        }
        return "unknown";
    }

    function statusMeta(status) {
        var normalized = normalizeStatus(status);
        if (normalized === "live") {
            return { label: "Live", cls: "status-on", dot: true };
        }
        if (normalized === "degraded") {
            return { label: "Degraded", cls: "status-warn", dot: false };
        }
        if (normalized === "down") {
            return { label: "Down", cls: "status-fail", dot: false };
        }
        return { label: "Unknown", cls: "status-idle", dot: false };
    }

    function statusChip(status, title) {
        var meta = statusMeta(status);
        var attr = title ? ' title="' + escapeHtml(title) + '"' : "";
        return (
            '<span class="status-chip ' + meta.cls + '"' + attr + ">" +
            (meta.dot ? '<span class="pulse-dot"></span>' : "") +
            meta.label +
            "</span>"
        );
    }

    function fmtEpoch(value) {
        var num = Number(value);
        if (!isFinite(num) || num <= 0) {
            return "";
        }
        var ms = num > 100000000000 ? num : num * 1000;
        var date = new Date(ms);
        if (isNaN(date.getTime())) {
            return "";
        }
        return date.toLocaleString(undefined, {
            year: "numeric",
            month: "short",
            day: "2-digit",
            hour: "2-digit",
            minute: "2-digit"
        });
    }

    function fmtClock(date) {
        return date.toLocaleTimeString(undefined, {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit"
        });
    }

    function endpointHost(endpoint) {
        if (!endpoint) {
            return "";
        }
        try {
            return new URL(endpoint).host;
        } catch (err) {
            return String(endpoint).replace(/^https?:\/\//i, "").split("/")[0];
        }
    }

    function latencyText(value) {
        var num = Number(value);
        if (!isFinite(num) || num <= 0) {
            return "Not reported";
        }
        return num + " ms";
    }

    function mergedRow(row) {
        var registry = state.registry[idOf(row)] || {};
        return {
            id: row.id,
            name: row.name,
            type: row.type,
            model: row.model,
            status: normalizeStatus(row.status),
            detail: row.detail || "",
            latency_ms: row.latency_ms,
            checked_at: row.checked_at,
            last_active: row.last_active,
            conversations: row.conversations,
            connected: row.connected,
            endpoint: registry.agent_endpoint || "",
            agent_id: registry.agent_id || "",
            registry_id: registry.id || ""
        };
    }

    function allRows() {
        return state.rows.map(mergedRow);
    }

    function specialists() {
        return allRows().filter(function (agent) {
            return !isMaster(agent);
        });
    }

    function masterAgent() {
        var rows = allRows();
        for (var i = 0; i < rows.length; i += 1) {
            if (isMaster(rows[i])) {
                return rows[i];
            }
        }
        return null;
    }

    function syncLabel() {
        var rows = allRows();
        var latest = state.lastSync;
        rows.forEach(function (row) {
            var stamp = Number(row.checked_at) || 0;
            if (stamp > latest) {
                latest = stamp;
            }
        });
        if (!latest) {
            return "—";
        }
        return fmtClock(new Date(latest * 1000));
    }

    function renderCounters() {
        var rows = allRows();
        var live = 0;
        var degraded = 0;
        var down = 0;
        rows.forEach(function (row) {
            if (row.status === "live") {
                live += 1;
            } else if (row.status === "degraded") {
                degraded += 1;
            } else if (row.status === "down") {
                down += 1;
            }
        });
        counters.total.textContent = String(rows.length);
        counters.live.textContent = String(live);
        counters.degraded.textContent = String(degraded);
        counters.down.textContent = String(down);
        lastSyncEl.textContent = syncLabel();
    }

    function renderHero() {
        if (!hero) {
            return;
        }
        var master = masterAgent();
        if (!master) {
            hero.hidden = true;
            return;
        }
        var specialistsList = specialists();
        var liveSpecialists = specialistsList.filter(function (agent) {
            return agent.status === "live";
        }).length;
        document.getElementById("heroName").textContent = displayName(master);
        document.getElementById("heroSub").textContent = displaySub(master) || "Master Orchestrator";
        document.getElementById("heroHex").textContent = initials(displayName(master));
        var statusEl = document.getElementById("heroStatus");
        if (statusEl) {
            var meta = statusMeta(master.status);
            statusEl.className = "status-chip " + meta.cls;
            statusEl.innerHTML = (meta.dot ? '<span class="pulse-dot"></span>' : "") + meta.label;
            statusEl.title = master.detail || "";
        }
        document.getElementById("heroMeta").textContent =
            liveSpecialists + " of " + specialistsList.length + " specialists connected";
        hero.hidden = false;
        document.getElementById("heroAction").onclick = function () {
            openDrawer(master);
        };
    }

    function matches(agent) {
        if (state.filter !== "all" && categoryOf(agent) !== state.filter) {
            return false;
        }
        if (!state.query) {
            return true;
        }
        var hay = (
            displayName(agent) + " " +
            displaySub(agent) + " " +
            (agent.name || "") + " " +
            (agent.type || "") + " " +
            (agent.id || "")
        ).toLowerCase();
        return hay.indexOf(state.query) !== -1;
    }

    function cardHtml(agent) {
        var name = displayName(agent);
        var sub = displaySub(agent);
        var category = categoryOf(agent);
        var host = endpointHost(agent.endpoint);
        return (
            '<article class="agent-card" tabindex="0" role="button" data-agent-id="' + escapeHtml(agent.id) + '" aria-label="' + escapeHtml(name) + ' details">' +
            '<span class="agent-hex" aria-hidden="true">' + escapeHtml(initials(name)) + "</span>" +
            '<div class="agent-card-main">' +
            '<strong class="agent-card-name">' + escapeHtml(name) + "</strong>" +
            (sub ? '<span class="agent-card-sub">' + escapeHtml(sub) + "</span>" : "") +
            "</div>" +
            '<span class="agent-card-status">' + statusChip(agent.status, agent.detail) + "</span>" +
            '<div class="agent-card-foot">' +
            '<span class="agent-cat">' + escapeHtml(CATEGORY_LABEL[category] || "Operations") + "</span>" +
            '<span class="agent-endpoint">' + escapeHtml(host || "Endpoint not reported") + "</span>" +
            "</div>" +
            "</article>"
        );
    }

    function renderCards() {
        if (!grid) {
            return;
        }
        var visible = specialists().filter(matches).sort(function (a, b) {
            var rank = rankOf(a) - rankOf(b);
            if (rank !== 0) {
                return rank;
            }
            return displayName(a).localeCompare(displayName(b));
        });
        grid.innerHTML = visible.map(cardHtml).join("");
        emptyNote.hidden = visible.length !== 0;
        emptyNote.textContent = state.rows.length ? "No agents match the current filters." : "No agents are registered by the backend.";
    }

    function renderAll() {
        renderCounters();
        renderHero();
        renderCards();
    }

    function showError(message) {
        if (!errorEl) {
            return;
        }
        errorEl.textContent = message;
        errorEl.hidden = false;
    }

    function clearError() {
        if (errorEl) {
            errorEl.hidden = true;
            errorEl.textContent = "";
        }
    }

    function setRefreshing(active) {
        state.refreshing = active;
        if (!refreshBtn) {
            return;
        }
        refreshBtn.disabled = active;
        refreshBtn.classList.toggle("is-refreshing", active);
        refreshLabel.textContent = active ? "Refreshing…" : "Refresh";
    }

    function fetchJson(url) {
        return fetch(url, { headers: { Accept: "application/json" } }).then(function (response) {
            if (!response.ok) {
                throw new Error("HTTP " + response.status);
            }
            return response.json();
        });
    }

    function loadRegistry() {
        return fetchJson("/api/agents").then(function (data) {
            var map = {};
            (data && data.agents ? data.agents : []).forEach(function (agent) {
                if (agent && agent.id) {
                    map[String(agent.id).toLowerCase()] = agent;
                }
            });
            state.registry = map;
        });
    }

    function loadStatus(force) {
        var url = "/api/agent-status" + (force ? "?refresh=1" : "");
        return fetchJson(url).then(function (data) {
            if (!data || !Array.isArray(data.agents)) {
                throw new Error("Invalid status response");
            }
            state.rows = data.agents.filter(function (agent) {
                return agent && !RETIRED[idOf(agent)];
            });
            state.lastSync = Math.floor(Date.now() / 1000);
            renderAll();
        });
    }

    function refresh(force) {
        if (state.refreshing) {
            return Promise.resolve();
        }
        setRefreshing(true);
        clearError();
        var statusPromise = loadStatus(force);
        var registryPromise = force ? Promise.resolve() : loadRegistry().catch(function () {});
        return Promise.all([statusPromise, registryPromise])
            .then(function () {
                if (state.openAgent) {
                    var openId = state.openAgent.id;
                    var latest = findAgent(openId);
                    if (latest && drawer.classList.contains("is-open")) {
                        state.openAgent = latest;
                        renderDrawer(latest);
                        if (force && isFeat(latest)) {
                            loadFeatHealth(true);
                        }
                    }
                }
            })
            .catch(function (err) {
                var message = err && err.message ? err.message : "Unknown error";
                showError("Refresh failed: " + message + ". Showing the last known status.");
            })
            .finally(function () {
                if (loadingEl) {
                    loadingEl.hidden = true;
                }
                setRefreshing(false);
            });
    }

    function findAgent(id) {
        var rows = allRows();
        for (var i = 0; i < rows.length; i += 1) {
            if (String(rows[i].id) === String(id)) {
                return rows[i];
            }
        }
        return null;
    }

    /* ---- Drawer ---- */

    function detailRow(label, value, muted) {
        return (
            '<span class="detail-label">' + escapeHtml(label) + "</span>" +
            '<span class="detail-value' + (muted ? " is-muted" : "") + '">' + escapeHtml(value) + "</span>"
        );
    }

    function renderDrawer(agent) {
        var status = statusMeta(agent.status);
        drawerTitle.textContent = displayName(agent);
        drawerSub.textContent = displaySub(agent) || agent.type || "Agent";
        drawerHex.textContent = initials(displayName(agent));

        var activity = fmtEpoch(agent.last_active);
        var endpoint = agent.endpoint || "";
        var sections = [];

        sections.push(
            '<section class="detail-section">' +
            "<h4>Overview</h4>" +
            '<div class="detail-grid">' +
            detailRow("Status", status.label) +
            detailRow("Type", agent.type || "Agent") +
            detailRow("Model", agent.model && agent.model !== "-" ? agent.model : "Not reported", !agent.model || agent.model === "-") +
            detailRow("Agent ID", agent.agent_id || agent.id || "Not reported") +
            detailRow("Registered", agent.connected ? "Connected" : "Registered", !agent.connected) +
            "</div>" +
            '<p class="detail-capability">' + escapeHtml(capabilityFor(agent)) + "</p>" +
            "</section>"
        );

        sections.push(
            '<section class="detail-section">' +
            "<h4>Connection / endpoint</h4>" +
            '<div class="detail-grid">' +
            detailRow("Endpoint", endpoint || "Not reported by backend", !endpoint) +
            detailRow("Probe", agent.detail || "No probe detail", !agent.detail) +
            detailRow("Latency", latencyText(agent.latency_ms), !(Number(agent.latency_ms) > 0)) +
            detailRow("Checked", fmtEpoch(agent.checked_at) || "Not reported", !agent.checked_at) +
            "</div>" +
            "</section>"
        );

        sections.push(
            '<section class="detail-section">' +
            "<h4>Activity</h4>" +
            '<div class="detail-grid">' +
            detailRow("Last active", activity || "No recorded activity", !activity) +
            detailRow("Conversations", String(agent.conversations || 0)) +
            "</div>" +
            "</section>"
        );

        var errText = "";
        if (agent.status === "down") {
            errText = agent.detail || "The backend reports this agent as unreachable.";
        } else if (agent.status === "degraded") {
            errText = agent.detail || "The backend reports this agent as degraded.";
        } else if (agent.detail && agent.status !== "live") {
            errText = agent.detail;
        }
        var errorBlock = errText
            ? '<div class="detail-error">' + escapeHtml(errText) + "</div>"
            : '<p class="detail-value is-muted">No errors reported by the backend.</p>';
        sections.push(
            '<section class="detail-section">' +
            "<h4>Errors</h4>" +
            errorBlock +
            "</section>"
        );

        if (isFeat(agent)) {
            sections.push(
                '<section class="detail-section" id="featHealthSection">' +
                "<h4>FEAT component health</h4>" +
                '<div class="feat-list" id="featHealthList">' +
                '<div class="detail-loading"><span class="spinner"></span><span>Checking component health…</span></div>' +
                "</div>" +
                "</section>"
            );
        }

        drawerBody.innerHTML = sections.join("");
        if (isFeat(agent)) {
            loadFeatHealth(false);
        }
    }

    function featStatusLabel(status) {
        var meta = statusMeta(status);
        return '<span class="status-chip ' + meta.cls + '">' + meta.label + "</span>";
    }

    function renderFeatHealth(data) {
        var list = document.getElementById("featHealthList");
        if (!list) {
            return;
        }
        var components = (data && data.components) || [];
        if (!components.length) {
            list.innerHTML = '<p class="detail-value is-muted">No component data returned by the backend.</p>';
            return;
        }
        list.innerHTML = components.map(function (item) {
            var detail = item.detail || "Not reported";
            if (Number(item.latency_ms) > 0) {
                detail += " · " + item.latency_ms + " ms";
            }
            return (
                '<div class="feat-row">' +
                '<div class="feat-row-main">' +
                '<span class="feat-row-label">' + escapeHtml(item.label) + "</span>" +
                '<span class="feat-row-detail">' + escapeHtml(detail) + "</span>" +
                "</div>" +
                featStatusLabel(item.status) +
                "</div>"
            );
        }).join("");
    }

    function loadFeatHealth(force) {
        var list = document.getElementById("featHealthList");
        if (!list) {
            return;
        }
        if (state.featHealth && !force) {
            renderFeatHealth(state.featHealth);
            return;
        }
        list.innerHTML = '<div class="detail-loading"><span class="spinner"></span><span>Checking component health…</span></div>';
        var url = "/api/agents/feat-health" + (force ? "?refresh=1" : "");
        fetchJson(url)
            .then(function (data) {
                state.featHealth = data;
                renderFeatHealth(data);
            })
            .catch(function (err) {
                var message = err && err.message ? err.message : "Unknown error";
                renderFeatHealth({
                    components: [
                        { id: "a2a", label: "A2A endpoint", status: "unknown", detail: "Component health request failed: " + message },
                        { id: "function_app", label: "Function App / OpenAPI", status: "unknown", detail: "Component health request failed: " + message },
                        { id: "pan_os", label: "PAN-OS connectivity", status: "unknown", detail: "Component health request failed: " + message },
                        { id: "job_worker", label: "Job worker", status: "unknown", detail: "No job-worker health endpoint is exposed by the backend." }
                    ]
                });
            });
    }

    function openDrawer(agent) {
        state.openAgent = agent;
        renderDrawer(agent);
        drawer.hidden = false;
        backdrop.hidden = false;
        window.requestAnimationFrame(function () {
            drawer.classList.add("is-open");
            backdrop.classList.add("is-open");
        });
        drawerClose.focus();
    }

    function closeDrawer() {
        state.openAgent = null;
        drawer.classList.remove("is-open");
        backdrop.classList.remove("is-open");
        window.setTimeout(function () {
            if (!drawer.classList.contains("is-open")) {
                drawer.hidden = true;
                backdrop.hidden = true;
            }
        }, 220);
    }

    /* ---- Events ---- */

    if (grid) {
        grid.addEventListener("click", function (event) {
            var card = event.target.closest(".agent-card");
            if (!card) {
                return;
            }
            var agent = findAgent(card.getAttribute("data-agent-id"));
            if (agent) {
                openDrawer(agent);
            }
        });
        grid.addEventListener("keydown", function (event) {
            if (event.key !== "Enter" && event.key !== " ") {
                return;
            }
            var card = event.target.closest(".agent-card");
            if (!card) {
                return;
            }
            event.preventDefault();
            var agent = findAgent(card.getAttribute("data-agent-id"));
            if (agent) {
                openDrawer(agent);
            }
        });
    }

    if (filtersEl) {
        filtersEl.addEventListener("click", function (event) {
            var button = event.target.closest(".sys-filter");
            if (!button) {
                return;
            }
            state.filter = button.getAttribute("data-filter") || "all";
            Array.prototype.forEach.call(filtersEl.querySelectorAll(".sys-filter"), function (item) {
                item.classList.toggle("is-active", item === button);
            });
            renderCards();
        });
    }

    if (searchEl) {
        searchEl.addEventListener("input", function () {
            state.query = searchEl.value.trim().toLowerCase();
            renderCards();
        });
    }

    if (refreshBtn) {
        refreshBtn.addEventListener("click", function () {
            refresh(true);
        });
    }

    if (drawerClose) {
        drawerClose.addEventListener("click", closeDrawer);
    }
    if (backdrop) {
        backdrop.addEventListener("click", closeDrawer);
    }
    document.addEventListener("keydown", function (event) {
        if (event.key === "Escape" && drawer && drawer.classList.contains("is-open")) {
            closeDrawer();
        }
    });

    /* ---- Boot ---- */

    if (loadingEl) {
        loadingEl.hidden = false;
    }
    refresh(false).catch(function () {
        if (loadingEl) {
            loadingEl.hidden = true;
        }
    });
})();
