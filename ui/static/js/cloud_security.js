(function () {
    var app = document.getElementById("ztApp");
    if (!app) return;

    var STORAGE_KEY = "ltm_zt_assessment_id";
    var THEME_KEY = "ltm_zt_theme";
    var PAGE_SIZE = 12;
    var POLL_MS = 2500;

    var state = {
        view: app.getAttribute("data-view") || "overview",
        configured: app.getAttribute("data-configured") === "1",
        isAdmin: app.getAttribute("data-admin") === "1",
        userName: app.getAttribute("data-user") || "",
        assessmentId: localStorage.getItem(STORAGE_KEY) || "",
        status: "",
        progress: 0,
        message: "",
        assessment: null,
        loading: false,
        running: false,
        error: "",
        errorCode: "",
        retryAfter: null,
        pollTimer: null,
        abort: null,
        filters: {
            query: "",
            risk: "all",
            status: "all",
            pillar: "all",
            category: "all",
            platform: "All",
            scope: "all",
            sort: "priority",
            area: "all"
        },
        page: 1,
        selectedId: null
    };

    var draft = {
        query: "",
        risk: "all",
        status: "all",
        pillar: "all",
        category: "all",
        platform: "All",
        scope: "all",
        sort: "priority",
        area: "all"
    };

    var viewEl = document.getElementById("ztView");
    var bannerEl = document.getElementById("ztBanner");
    var progressEl = document.getElementById("ztProgress");
    var lastUpdatedEl = document.getElementById("ztLastUpdated");
    var runBtn = document.getElementById("ztRunBtn");
    var refreshBtn = document.getElementById("ztRefreshBtn");
    var orgEl = document.getElementById("ztOrgName");
    var confirmModal = document.getElementById("ztConfirmModal");
    var helpModal = document.getElementById("ztHelpModal");
    var drawer = document.getElementById("ztDrawer");
    var drawerBackdrop = document.getElementById("ztDrawerBackdrop");
    var drawerBody = document.getElementById("ztDrawerBody");
    var drawerTitle = document.getElementById("ztDrawerTitle");
    var exportMenu = document.getElementById("ztExportMenu");
    var exportBtn = document.getElementById("ztExportBtn");
    var filterBtn = document.getElementById("ztFilterBtn");
    var filterPanel = document.getElementById("ztFilterPanel");
    var filterClose = document.getElementById("ztFilterClose");
    var filterApply = document.getElementById("ztFilterApply");
    var filterReset = document.getElementById("ztFilterReset");
    var filterSearch = document.getElementById("ztFilterSearch");
    var filterCategory = document.getElementById("ztFilterCategory");
    var filterSort = document.getElementById("ztFilterSort");
    var filterAreaPills = document.getElementById("ztFilterAreaPills");
    var filterRiskPills = document.getElementById("ztFilterRiskPills");
    var filterStatusPills = document.getElementById("ztFilterStatusPills");
    var filterPlatformPills = document.getElementById("ztFilterPlatformPills");
    var filterScopePills = document.getElementById("ztFilterScopePills");
    var filterAreaSection = document.getElementById("ztFilterAreaSection");
    var filterPlatformSection = document.getElementById("ztFilterPlatformSection");
    var filterScopeSection = document.getElementById("ztFilterScopeSection");

    function esc(value) {
        return String(value == null ? "" : value)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#39;");
    }

    function toast(message, kind) {
        if (window.showToast) window.showToast(message, kind || "info");
    }

    function icon(name) {
        var paths = {
            users: '<path d="M16 21v-2a4 4 0 00-4-4H6a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75"/>',
            user: '<path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/>',
            guests: '<path d="M16 21v-2a4 4 0 00-4-4H6a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M19 8v6M22 11h-6"/>',
            groups: '<path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75"/>',
            apps: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
            devices: '<rect x="5" y="3" width="14" height="12" rx="2"/><path d="M8 21h8M12 15v6"/>',
            laptop: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M2 20h20M8 16h8"/>',
            building: '<path d="M4 21V5a2 2 0 012-2h8a2 2 0 012 2v16"/><path d="M20 21V11a2 2 0 00-2-2h-2"/><path d="M9 7h.01M13 7h.01M9 11h.01M13 11h.01M9 15h.01M13 15h.01M8 21h8"/>',
            shield: '<path d="M12 3l7 3v5c0 4.5-3 8.5-7 10-4-1.5-7-5.5-7-10V6l7-3z"/>',
            pass: '<path d="M20 6L9 17l-5-5"/>',
            fail: '<path d="M18 6L6 18M6 6l12 12"/>',
            search: '<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>',
            warn: '<path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><path d="M12 9v4"/><circle cx="12" cy="17" r="1"/>'
        };
        return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + (paths[name] || paths.shield) + "</svg>";
    }

    function formatTime(value) {
        if (!value) return "Unavailable";
        var date = new Date(value);
        if (isNaN(date.getTime())) return String(value);
        return date.toLocaleString();
    }

    function metric(value) {
        if (value === null || value === undefined || value === "") return "Unavailable";
        return String(value);
    }

    function compactNumber(value) {
        if (value === null || value === undefined || value === "") return "Unavailable";
        var n = Number(value);
        if (isNaN(n)) return String(value);
        if (Math.abs(n) >= 1000000) {
            var m = n / 1000000;
            return (m % 1 === 0 ? m.toFixed(0) : m.toFixed(1)) + "M";
        }
        if (Math.abs(n) >= 1000) {
            var k = n / 1000;
            return (k % 1 === 0 ? k.toFixed(0) : k.toFixed(1)) + "K";
        }
        return String(n);
    }

    function maskTenant(id) {
        if (!id) return "Unavailable";
        var parts = String(id).split("-");
        if (parts.length === 5) return parts[0] + "-****-****-****-" + parts[parts.length - 1];
        if (id.length <= 8) return id;
        return id.slice(0, 4) + "****" + id.slice(-4);
    }

    function badge(kind, label) {
        var cls = "zt-badge zt-badge-" + kind;
        var title = label + " " + kind;
        return '<span class="' + cls + '" title="' + esc(title) + '" aria-label="' + esc(title) + '">' + icon(kind === "Passed" ? "pass" : (kind === "Failed" || kind === "High" ? "fail" : "warn")) + esc(label) + "</span>";
    }

    function riskBadge(risk) {
        return badge(risk, risk);
    }

    function statusBadge(status) {
        return badge(status, status);
    }

    function jsonFetch(url, body, signal) {
        return fetch(url, {
            method: "POST",
            credentials: "same-origin",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-Requested-With": "XMLHttpRequest"
            },
            body: JSON.stringify(body || {}),
            signal: signal
        }).then(function (res) {
            return res.json().catch(function () { return {}; }).then(function (data) {
                if (res.status === 429) {
                    var err = new Error(data.error || "Throttled");
                    err.status = 429;
                    err.retryAfter = data.retryAfter || res.headers.get("Retry-After");
                    throw err;
                }
                if (!res.ok) {
                    var fail = new Error(data.error || "Request failed");
                    fail.status = res.status;
                    fail.retryAfter = data.retryAfter;
                    throw fail;
                }
                return data;
            });
        });
    }

    function retryDelay(retryAfter) {
        var n = parseInt(retryAfter, 10);
        if (!isNaN(n) && n > 0) return Math.min(n, 30) * 1000;
        return POLL_MS;
    }

    function stopPoll() {
        if (state.pollTimer) {
            clearTimeout(state.pollTimer);
            state.pollTimer = null;
        }
        if (state.abort) {
            try { state.abort.abort(); } catch (e) {}
            state.abort = null;
        }
        state.running = false;
        if (runBtn) runBtn.disabled = false;
    }

    function setView(view, push) {
        state.view = view;
        state.page = 1;
        if (view !== "overview") state.filters.area = "all";
        closeFilter();
        var tabs = app.querySelectorAll(".zt-tab");
        for (var i = 0; i < tabs.length; i++) {
            var active = tabs[i].getAttribute("data-view") === view;
            tabs[i].classList.toggle("is-active", active);
            if (active) tabs[i].setAttribute("aria-current", "page");
            else tabs[i].removeAttribute("aria-current");
        }
        if (push !== false) {
            var path = "/dashboard/cloud-security";
            if (view && view !== "overview") path += "/" + view;
            if (window.history && history.pushState) history.pushState({ ztView: view }, "", path);
        }
        render();
    }

    function pillarKey(view) {
        if (view === "identity") return "identity";
        if (view === "devices") return "devices";
        if (view === "network") return "network";
        if (view === "data") return "data";
        if (view === "infrastructure") return "infrastructure";
        return "";
    }

    function pillarBucket(a, view) {
        var key = pillarKey(view);
        if (!a || !key) return { summary: {}, tests: [] };
        return a[key] || { summary: {}, tests: [] };
    }

    function allTests(a) {
        if (!a) return [];
        return ((a.identity && a.identity.tests) || [])
            .concat((a.devices && a.devices.tests) || [])
            .concat((a.network && a.network.tests) || [])
            .concat((a.data && a.data.tests) || [])
            .concat((a.infrastructure && a.infrastructure.tests) || [])
            .concat((a.other && a.other.tests) || []);
    }

    function currentTests() {
        var a = state.assessment;
        if (!a) return [];
        if (state.view === "overview") return allTests(a);
        return pillarBucket(a, state.view).tests || [];
    }

    function applyFilters(tests) {
        var f = state.filters;
        var q = (f.query || "").trim().toLowerCase();
        return tests.filter(function (t) {
            if (q) {
                var hay = [t.name, t.category, t.description, t.recommendation].join(" ").toLowerCase();
                if (hay.indexOf(q) === -1) return false;
            }
            if (f.area !== "all" && t.area !== f.area) return false;
            if (f.risk !== "all" && t.risk !== f.risk) return false;
            if (f.status !== "all" && t.status !== f.status) return false;
            if (f.pillar !== "all" && (t.sfiPillars || []).indexOf(f.pillar) === -1) return false;
            if (f.category !== "all" && t.category !== f.category) return false;
            if ((state.view === "devices" || f.area === "Devices") && f.platform && f.platform !== "All" && (t.platform || "Tenant-wide") !== f.platform) return false;
            if ((state.view === "devices" || f.area === "Devices") && f.scope !== "all") {
                var scope = t.area === "Devices" && ["Compliance", "Enrollment", "Encryption", "Endpoint protection", "Firewall", "Updates", "Secure configuration"].indexOf(t.category) !== -1 ? "Device" : "Tenant";
                if (scope !== f.scope) return false;
            }
            return true;
        });
    }

    function sortTests(tests) {
        var copy = tests.slice();
        var rankStatus = { Failed: 0, Investigate: 1, Planned: 2, Skipped: 3, Passed: 4 };
        copy.sort(function (a, b) {
            if (state.filters.sort === "name") return String(a.name || "").localeCompare(String(b.name || ""));
            if (state.filters.sort === "status") return (rankStatus[a.status] || 9) - (rankStatus[b.status] || 9);
            function rank(t) {
                if (t.status === "Failed" && t.risk === "High") return 0;
                if (t.status === "Investigate" && t.risk === "High") return 1;
                if (t.status === "Failed" && t.risk === "Medium") return 2;
                if (t.status === "Failed" && t.risk === "Low") return 3;
                if (t.status === "Investigate") return 4;
                if (t.status === "Planned") return 5;
                if (t.status === "Passed") return 6;
                if (t.status === "Skipped") return 7;
                return 8;
            }
            var diff = rank(a) - rank(b);
            if (diff) return diff;
            return String(a.name || "").localeCompare(String(b.name || ""));
        });
        return copy;
    }

    function unique(values) {
        var out = [];
        values.forEach(function (v) {
            if (v && out.indexOf(v) === -1) out.push(v);
        });
        return out.sort();
    }

    function updateHeader() {
        var a = state.assessment;
        if (orgEl) {
            orgEl.textContent = (a && a.tenant && (a.tenant.tenantName || a.tenant.primaryDomain)) || state.userName || "Organization";
        }
        if (lastUpdatedEl) {
            if (state.running) lastUpdatedEl.textContent = "Assessment running";
            else if (a && a.completedAt) lastUpdatedEl.textContent = "Last assessed " + formatTime(a.completedAt);
            else lastUpdatedEl.textContent = "No assessment yet";
        }
        if (runBtn) runBtn.disabled = state.running;
    }

    function renderBanner() {
        if (!bannerEl) return;
        if (state.error) {
            bannerEl.hidden = false;
            bannerEl.className = "zt-banner is-error";
            bannerEl.innerHTML = "<strong>Assessment failed.</strong> " + esc(state.error) +
                (state.assessmentId ? " Assessment ID: " + esc(state.assessmentId) + "." : "") +
                ' <button type="button" class="zt-copy" id="ztRetryFailed">Retry</button>';
            var retry = document.getElementById("ztRetryFailed");
            if (retry) retry.onclick = function () { openConfirm(); };
            return;
        }
        if (state.assessment && state.assessment.partial && state.assessment.partial.length) {
            bannerEl.hidden = false;
            bannerEl.className = "zt-banner is-partial";
            var items = state.assessment.partial.map(function (p) {
                return esc(p.domain) + ": " + esc(p.message || "unavailable");
            }).join(" ");
            bannerEl.innerHTML = "<strong>Assessment completed with partial data.</strong> Some Microsoft Graph or Microsoft Intune information could not be retrieved. " + items;
            return;
        }
        if (state.assessment && state.assessment.stale) {
            bannerEl.hidden = false;
            bannerEl.className = "zt-banner is-stale";
            bannerEl.textContent = "These results may no longer represent the current tenant configuration.";
            return;
        }
        bannerEl.hidden = true;
        bannerEl.textContent = "";
    }

    function renderProgress() {
        if (!progressEl) return;
        if (!state.running) {
            progressEl.hidden = true;
            return;
        }
        progressEl.hidden = false;
        progressEl.textContent = "Assessment " + (state.status || "running") + " — " + (state.progress || 0) + "% " + (state.message || "");
    }

    function donutHtml(id, identity, devices) {
        var ip = identity.passed || 0, it = identity.total || 0;
        var dp = devices.passed || 0, dt = devices.total || 0;
        return '<div class="zt-donut-wrap">' +
            '<canvas id="' + id + '" width="168" height="168" role="img" aria-label="Identity assessment: ' + ip + " of " + it + " tests passed. Devices assessment: " + dp + " of " + dt + ' tests passed."></canvas>' +
            '<div class="zt-legend">' +
            "<div><b>Identity</b><span class=\"zt-muted\">Passed: " + ip + " of " + it + " tests</span></div>" +
            "<div><b>Devices</b><span class=\"zt-muted\">Passed: " + dp + " of " + dt + " tests</span></div>" +
            "</div></div>" +
            '<p class="zt-muted">Identity assessment: ' + ip + " of " + it + " tests passed. Devices assessment: " + dp + " of " + dt + " tests passed.</p>";
    }

    function paintDonut(canvas, identity, devices) {
        if (!canvas || !canvas.getContext) return;
        var ctx = canvas.getContext("2d");
        var cx = 84, cy = 84;
        function ring(radius, width, passed, total, color) {
            var rest = Math.max(total - passed, 0);
            ctx.lineWidth = width;
            ctx.lineCap = "round";
            var start = -Math.PI / 2;
            if (total <= 0) {
                ctx.strokeStyle = "#E2E8F0";
                ctx.beginPath();
                ctx.arc(cx, cy, radius, 0, Math.PI * 2);
                ctx.stroke();
                return;
            }
            var passAngle = (passed / total) * Math.PI * 2;
            ctx.strokeStyle = color;
            ctx.beginPath();
            ctx.arc(cx, cy, radius, start, start + passAngle);
            ctx.stroke();
            ctx.strokeStyle = rest ? "#DC2626" : "#E2E8F0";
            ctx.beginPath();
            ctx.arc(cx, cy, radius, start + passAngle, start + Math.PI * 2);
            ctx.stroke();
        }
        ctx.clearRect(0, 0, 168, 168);
        ring(70, 14, identity.passed || 0, identity.total || 0, "#16A34A");
        ring(50, 12, devices.passed || 0, devices.total || 0, "#0891B2");
    }

    function metricCard(label, value, ic) {
        return '<article class="zt-card zt-metric">' +
            '<div class="zt-metric-head">' + icon(ic) + esc(label) + "</div>" +
            '<div class="zt-metric-value">' + esc(metric(value)) + "</div></article>";
    }

    function emptyState(title, text) {
        return '<section class="zt-card zt-empty"><h2>' + esc(title) + "</h2><p>" + esc(text) + "</p></section>";
    }

    function skeleton() {
        return '<div class="zt-grid">' + [1, 2, 3].map(function () {
            return '<div class="zt-card"><div class="zt-skel"></div><div class="zt-skel" style="margin-top:12px;width:40%"></div></div>';
        }).join("") + "</div>";
    }

    function inventoryStat(tone, ic, label, value) {
        return '<div class="zt-inv-stat">' +
            '<span class="zt-inv-icon zt-tone-' + tone + '">' + icon(ic) + "</span>" +
            '<div><span class="zt-inv-label">' + esc(label) + '</span><strong>' + esc(compactNumber(value)) + "</strong></div></div>";
    }

    function inventoryCard(title, ic, tone, statsHtml) {
        return '<article class="zt-inv-card">' +
            '<h3><span class="zt-inv-icon zt-tone-' + tone + '">' + icon(ic) + "</span>" + esc(title) + "</h3>" +
            '<div class="zt-inv-stats">' + statsHtml + "</div></article>";
    }

    function pillarBar(name, summary, view) {
        var passed = (summary && summary.passed) || 0;
        var total = (summary && summary.total) || 0;
        var pct = total ? Math.round((passed / total) * 100) : 0;
        var clickable = view ? ' type="button" class="zt-pillar" data-view="' + esc(view) + '"' : ' class="zt-pillar is-static"';
        var tag = view ? "button" : "div";
        return "<" + tag + clickable + ">" +
            '<span class="zt-pillar-name">' + esc(name) + "</span>" +
            '<span class="zt-pillar-count"><strong>' + passed + "</strong>/" + total + " tests</span>" +
            '<span class="zt-pillar-track" aria-hidden="true"><span class="zt-pillar-fill" style="width:' + pct + '%"></span></span>' +
            "</" + tag + ">";
    }

    function renderOverview() {
        var a = state.assessment;
        if (!a) return emptyState("No assessment results are available.", "Run a Zero Trust assessment to populate this dashboard.");
        var t = a.tenant || {};
        var idSum = (a.identity && a.identity.summary) || {};
        var devSum = (a.devices && a.devices.summary) || {};
        var netSum = (a.network && a.network.summary) || {};
        var dataSum = (a.data && a.data.summary) || {};
        var infSum = (a.infrastructure && a.infrastructure.summary) || {};
        var html = '<section class="zt-tenant-strip">' +
            '<h2>' + icon("building") + " Tenant info</h2>" +
            '<div class="zt-tenant-meta">' +
            '<div><span class="zt-inv-label">Name</span><strong>' + esc(t.tenantName || t.primaryDomain || "Unavailable") + "</strong>" +
            (t.primaryDomain ? '<span class="zt-muted"> ' + esc(t.primaryDomain) + "</span>" : "") + "</div>" +
            '<div><span class="zt-inv-label">Tenant ID</span><strong>' + esc(maskTenant(t.tenantId)) + "</strong>" +
            (state.isAdmin && t.tenantId ? ' <button type="button" class="zt-copy" data-copy="' + esc(t.tenantId) + '">Copy</button>' : "") + "</div>" +
            "</div></section>";
        html += '<div class="zt-inv-grid">' +
            inventoryCard("Users", "users", "blue", inventoryStat("blue", "user", "Total users", t.users) + inventoryStat("blue", "guests", "Guest users", t.guests)) +
            inventoryCard("Devices", "devices", "purple", inventoryStat("purple", "laptop", "Total devices", t.devices) + inventoryStat("purple", "devices", "Managed", t.managedDevices)) +
            inventoryCard("Groups & apps", "groups", "teal", inventoryStat("teal", "groups", "Groups", t.groups) + inventoryStat("teal", "apps", "Apps", t.applications)) +
            "</div>";
        html += '<section class="zt-assess-strip">' +
            "<h2>" + icon("shield") + " Assessment</h2>" +
            '<div class="zt-pillar-row">' +
            pillarBar("Identity", idSum, "identity") +
            pillarBar("Devices", devSum, "devices") +
            pillarBar("Network", netSum, "network") +
            pillarBar("Data", dataSum, "data") +
            pillarBar("Infrastructure", infSum, "infrastructure") +
            "</div></section>";
        function riskTotal(key) {
            return (idSum[key] || 0) + (devSum[key] || 0) + (netSum[key] || 0) + (dataSum[key] || 0) + (infSum[key] || 0);
        }
        html += '<div class="zt-risk-grid">' +
            riskNav("Critical attention", riskTotal("highRiskFailed"), "High", "Failed") +
            riskNav("Medium-risk failures", riskTotal("mediumRiskFailed"), "Medium", "Failed") +
            riskNav("Passed tests", riskTotal("passed"), "all", "Passed") +
            riskNav("Investigate", riskTotal("investigate"), "all", "Investigate") +
            riskNav("Skipped", riskTotal("skipped"), "all", "Skipped") +
            "</div>";
        html += '<section class="zt-card"><h2>Priority remediation</h2>' + renderPriority(a.priority || []) + "</section>";
        html += '<div class="zt-viz-grid">' +
            vizCard("Privileged users authentication methods", a.visualizations && a.visualizations.privilegedAuth) +
            vizCard("User authentication coverage", a.visualizations && a.visualizations.userAuthCoverage) +
            vizCard("Conditional Access coverage", a.visualizations && a.visualizations.conditionalAccessCoverage) +
            vizCard("Device sign-in state", a.visualizations && a.visualizations.deviceSignIn) +
            "</div>";
        if (hasActiveFilters()) {
            var tests = allTests(a);
            var filtered = sortTests(applyFilters(tests));
            html += '<section class="zt-card" style="margin-top:16px"><h2>Matching tests</h2>';
            html += tableFor(filtered, tests.length, "matching tests");
            html += "</section>";
        }
        return html;
    }

    function defaultFilters() {
        return { query: "", risk: "all", status: "all", pillar: "all", category: "all", platform: "All", scope: "all", sort: "priority", area: "all" };
    }

    function copyFilters(src) {
        return {
            query: src.query || "",
            risk: src.risk || "all",
            status: src.status || "all",
            pillar: src.pillar || "all",
            category: src.category || "all",
            platform: src.platform || "All",
            scope: src.scope || "all",
            sort: src.sort || "priority",
            area: src.area || "all"
        };
    }

    function hasActiveFilters() {
        var f = state.filters;
        return Boolean((f.query || "").trim()) || f.risk !== "all" || f.status !== "all" || f.pillar !== "all" || f.category !== "all" || f.scope !== "all" || f.area !== "all" || (f.platform && f.platform !== "All");
    }

    function syncPills(container, attr, value) {
        if (!container) return;
        container.querySelectorAll(".rep-pill").forEach(function (p) {
            var on = p.getAttribute(attr) === value;
            p.classList.toggle("is-active", on);
            p.setAttribute("aria-pressed", on ? "true" : "false");
        });
    }

    function refreshFilterOptions() {
        var tests = currentTests();
        var cats = unique(tests.map(function (t) { return t.category; }));
        if (!filterCategory) return;
        var current = draft.category || "all";
        filterCategory.innerHTML = '<option value="all">All</option>' + cats.map(function (c) {
            return '<option value="' + esc(c) + '"' + (c === current ? " selected" : "") + ">" + esc(c) + "</option>";
        }).join("");
        if (current !== "all" && cats.indexOf(current) === -1) {
            draft.category = "all";
            filterCategory.value = "all";
        }
    }

    function syncFilterSections() {
        var devices = state.view === "devices";
        var overview = state.view === "overview";
        if (filterAreaSection) filterAreaSection.hidden = !overview;
        if (filterPlatformSection) filterPlatformSection.hidden = !(devices || draft.area === "Devices");
        if (filterScopeSection) filterScopeSection.hidden = !(devices || draft.area === "Devices");
    }

    function syncDraftFromState() {
        draft = copyFilters(state.filters);
        if (filterSearch) filterSearch.value = draft.query || "";
        if (filterCategory) filterCategory.value = draft.category || "all";
        if (filterSort) filterSort.value = draft.sort || "priority";
        syncPills(filterAreaPills, "data-area", draft.area || "all");
        syncPills(filterRiskPills, "data-risk", draft.risk || "all");
        syncPills(filterStatusPills, "data-status", draft.status || "all");
        syncPills(filterPlatformPills, "data-platform", draft.platform || "All");
        syncPills(filterScopePills, "data-scope", draft.scope || "all");
        syncFilterSections();
        refreshFilterOptions();
        if (filterBtn) filterBtn.classList.toggle("has-filters", hasActiveFilters());
    }

    function openFilter() {
        if (!filterPanel) return;
        syncDraftFromState();
        filterPanel.hidden = false;
        if (filterBtn) {
            filterBtn.classList.add("is-active");
            filterBtn.setAttribute("aria-expanded", "true");
        }
    }

    function closeFilter() {
        if (!filterPanel) return;
        filterPanel.hidden = true;
        if (filterBtn) {
            filterBtn.classList.remove("is-active");
            filterBtn.setAttribute("aria-expanded", "false");
            filterBtn.classList.toggle("has-filters", hasActiveFilters());
        }
    }

    function toggleFilter() {
        if (filterPanel && filterPanel.hidden) openFilter(); else closeFilter();
    }

    function riskNav(label, value, risk, status) {
        return '<button type="button" class="zt-risk" data-risk="' + esc(risk) + '" data-status="' + esc(status) + '"><div class="zt-metric-head">' + icon("warn") + esc(label) + '</div><div class="zt-metric-value">' + esc(metric(value || 0)) + "</div></button>";
    }

    function renderPriority(items) {
        if (!items.length) return '<p class="zt-muted">No failed or investigate controls requiring ranked remediation.</p>';
        return '<div class="zt-list">' + items.map(function (t) {
            return '<div class="zt-list-item"><div><strong>' + esc(t.name) + "</strong><div class=\"zt-muted\">" + esc(t.area) + " · " + esc((t.sfiPillars || []).join(", ")) + "</div><div class=\"zt-muted\">" + esc(t.recommendation || "No remediation summary returned.") + "</div></div><div>" + riskBadge(t.risk) + " " + statusBadge(t.status) + ' <button class="btn btn-ghost" type="button" data-open="' + esc(t.id) + '">View details</button></div></div>';
        }).join("") + "</div>";
    }

    function vizCard(title, data) {
        var body;
        if (!data) {
            body = '<div class="zt-viz-empty"><div><strong>Visualization unavailable</strong><p>The assessment returned configuration test results but did not return the telemetry required for this flow diagram.</p></div></div>';
        } else {
            var rows = Object.keys(data).map(function (key) {
                var value = data[key];
                if (value == null) return "";
                if (Array.isArray(value)) value = value.length ? value.join(", ") : "none";
                else if (typeof value === "object") value = Object.keys(value).map(function (k) { return k + ": " + data[key][k]; }).join(", ");
                return "<dt>" + esc(prettyKey(key)) + "</dt><dd>" + esc(value) + "</dd>";
            }).join("");
            body = '<dl class="zt-kvs">' + rows + "</dl>";
        }
        return '<section class="zt-card zt-viz-card"><h3>' + esc(title) + "</h3>" + body + "</section>";
    }

    function prettyKey(key) {
        return String(key || "").replace(/([A-Z])/g, " $1").replace(/^./, function (c) { return c.toUpperCase(); }).trim();
    }

    function countsRow(summary) {
        return '<div class="zt-chips">' +
            statusBadge("Passed") + " " + (summary.passed || 0) + " " +
            statusBadge("Failed") + " " + (summary.failed || 0) + " " +
            statusBadge("Investigate") + " " + (summary.investigate || 0) + " " +
            statusBadge("Planned") + " " + (summary.planned || 0) + " " +
            statusBadge("Skipped") + " " + (summary.skipped || 0) +
            "</div>";
    }

    function categoryCards(tests, labels) {
        return '<div class="zt-cat-grid">' + labels.map(function (label) {
            var subset = tests.filter(function (t) { return (t.category || "") === label; });
            var passed = subset.filter(function (t) { return t.status === "Passed"; }).length;
            var total = subset.length;
            var pct = total ? Math.round((passed / total) * 100) : 0;
            return '<article class="zt-cat-card"><h3>' + esc(label) + "</h3><div class=\"zt-pillar-count\"><strong>" + passed + "</strong>/" + total + '</div><span class="zt-pillar-track" aria-hidden="true"><span class="zt-pillar-fill" style="width:' + pct + '%"></span></span></article>';
        }).join("") + "</div>";
    }

    function tableFor(filtered, allCount, caption) {
        var start = (state.page - 1) * PAGE_SIZE;
        var page = filtered.slice(start, start + PAGE_SIZE);
        var showing = "Showing " + filtered.length + " of " + allCount + " " + caption;
        if (!filtered.length) {
            return '<p class="zt-muted">' + esc(showing) + '</p><div class="zt-empty">No controls match the selected filters.</div>';
        }
        var head = state.view === "devices"
            ? "<th>Test name</th><th>Category</th><th>Platform</th><th>Risk</th><th>Status</th><th>SFI pillar</th><th>Action</th>"
            : (state.view === "overview"
                ? "<th>Test name</th><th>Area</th><th>Risk</th><th>Status</th><th>Category</th><th>Last evaluated</th><th>Action</th>"
                : "<th>Test name</th><th>Risk</th><th>Status</th><th>SFI pillar</th><th>Category</th><th>Last evaluated</th><th>Action</th>");
        var rows = page.map(function (t) {
            var cols = state.view === "devices"
                ? "<td>" + esc(t.name) + "</td><td>" + esc(t.category || "") + "</td><td>" + esc(t.platform || "Tenant-wide") + "</td><td>" + riskBadge(t.risk) + "</td><td>" + statusBadge(t.status) + "</td><td>" + esc((t.sfiPillars || []).join(", ")) + "</td>"
                : (state.view === "overview"
                    ? "<td>" + esc(t.name) + "</td><td>" + esc(t.area || "") + "</td><td>" + riskBadge(t.risk) + "</td><td>" + statusBadge(t.status) + "</td><td>" + esc(t.category || "") + "</td><td>" + esc(formatTime(t.lastEvaluatedAt)) + "</td>"
                    : "<td>" + esc(t.name) + "</td><td>" + riskBadge(t.risk) + "</td><td>" + statusBadge(t.status) + "</td><td>" + esc((t.sfiPillars || []).join(", ")) + "</td><td>" + esc(t.category || "") + "</td><td>" + esc(formatTime(t.lastEvaluatedAt)) + "</td>");
            return '<tr><td colspan="0" hidden></td>' + cols + '<td><button class="btn btn-ghost" type="button" data-open="' + esc(t.id) + '">Details</button></td></tr>';
        }).join("");
        var pages = Math.ceil(filtered.length / PAGE_SIZE);
        var pager = pages > 1 ? '<div class="zt-chips" style="margin-top:10px">' + Array.from({ length: pages }, function (_, i) {
            var n = i + 1;
            return '<button type="button" class="btn btn-ghost' + (n === state.page ? " is-active" : "") + '" data-page="' + n + '">' + n + "</button>";
        }).join("") + "</div>" : "";
        var cards = '<div class="zt-mobile-cards">' + page.map(function (t) {
            return '<article class="zt-card"><strong>' + esc(t.name) + "</strong><div>" + riskBadge(t.risk) + " " + statusBadge(t.status) + '</div><p class="zt-muted">' + esc(t.category || "") + '</p><button class="btn btn-ghost" type="button" data-open="' + esc(t.id) + '">Details</button></article>';
        }).join("") + "</div>";
        return '<p class="zt-muted">' + esc(showing) + '</p><div class="zt-table-wrap"><table class="zt-table"><caption>' + esc(caption) + "</caption><thead><tr>" + head + "</tr></thead><tbody>" + rows.replace(/<td colspan="0" hidden><\/td>/g, "") + "</tbody></table></div>" + cards + pager;
    }

    function renderIdentity() {
        var a = state.assessment;
        if (!a) return emptyState("No assessment results are available.", "Run a Zero Trust assessment to populate this dashboard.");
        var tests = (a.identity && a.identity.tests) || [];
        var summary = (a.identity && a.identity.summary) || {};
        var filtered = sortTests(applyFilters(tests));
        var html = '<div class="zt-page-head"><div><h1>Identity</h1><p>' + tests.length + " checks · high-risk failed " + (summary.highRiskFailed || 0) + " · last evaluated " + formatTime(a.completedAt) + "</p></div>" + countsRow(summary) + "</div>";
        html += categoryCards(tests, ["Privileged accounts", "Authentication methods", "Conditional Access", "Application identity security", "External identities", "Monitoring and diagnostics", "Tenant administration"]);
        html += tableFor(filtered, tests.length, "identity tests");
        return html;
    }

    function renderDevices() {
        var a = state.assessment;
        if (!a) return emptyState("No assessment results are available.", "Run a Zero Trust assessment to populate this dashboard.");
        var tests = (a.devices && a.devices.tests) || [];
        var summary = (a.devices && a.devices.summary) || {};
        var inv = a.deviceInventory || {};
        var filtered = sortTests(applyFilters(tests));
        var platforms = ["All", "Windows", "macOS", "iOS/iPadOS", "Android", "Tenant-wide"];
        var html = '<div class="zt-page-head"><div><h1>Devices</h1><p>' + tests.length + " tests · high-risk failed " + (summary.highRiskFailed || 0) + " · devices " + metric(inv.count) + " · managed " + metric(inv.count) + " · last evaluated " + formatTime(a.completedAt) + "</p></div>" + countsRow(summary) + "</div>";
        html += categoryCards(tests, ["Enrollment", "Inventory", "Encryption", "Compliance", "Conditional Access", "Session controls", "Sign-in evidence", "Inventory reconcile"]);
        html += '<div class="zt-platform-tabs" role="tablist">' + platforms.map(function (p) {
            var subset = p === "All" ? tests : tests.filter(function (t) { return (t.platform || "Tenant-wide") === p; });
            var failedHigh = subset.filter(function (t) { return t.status === "Failed" && t.risk === "High"; }).length;
            var passed = subset.filter(function (t) { return t.status === "Passed"; }).length;
            return '<button type="button" role="tab" data-platform="' + esc(p) + '" class="' + (state.filters.platform === p ? "is-active" : "") + '" aria-selected="' + (state.filters.platform === p ? "true" : "false") + '">' + esc(p) + " · " + subset.length + " / " + passed + " passed / " + failedHigh + " high-risk</button>";
        }).join("") + "</div>";
        html += '<section class="zt-card" style="margin-bottom:14px"><h2>Device join and compliance flow</h2>' + (a.visualizations && a.visualizations.deviceFlow
            ? '<p class="zt-muted">Device inventory flow is available.</p>'
            : '<div class="zt-viz-empty"><div><strong>Visualization unavailable</strong><p>The assessment returned configuration test results but did not return the telemetry required for this flow diagram.</p></div></div>') + "</section>";
        html += tableFor(filtered, tests.length, "device tests");
        return html;
    }

    var PILLAR_META = {
        network: {
            title: "Network",
            caption: "network tests",
            categories: ["Inventory", "NSG security", "Public exposure", "Private connectivity", "Firewall", "WAF", "DDoS", "Remote connectivity", "Encryption", "Monitoring", "Segmentation", "Routing"]
        },
        data: {
            title: "Data",
            caption: "data tests",
            categories: ["Information protection", "Data loss prevention", "Data protection"]
        },
        infrastructure: {
            title: "Infrastructure",
            caption: "infrastructure tests",
            categories: ["Secure score", "Cloud security posture", "Infrastructure security"]
        }
    };

    function renderPillar(view) {
        var a = state.assessment;
        if (!a) return emptyState("No assessment results are available.", "Run a Zero Trust assessment to populate this dashboard.");
        var meta = PILLAR_META[view] || { title: view, caption: "tests", categories: [] };
        var bucket = pillarBucket(a, view);
        var tests = bucket.tests || [];
        var summary = bucket.summary || {};
        var filtered = sortTests(applyFilters(tests));
        var html = '<div class="zt-page-head"><div><h1>' + esc(meta.title) + "</h1><p>" + tests.length + " checks · high-risk failed " + (summary.highRiskFailed || 0) + " · last evaluated " + formatTime(a.completedAt) + "</p></div>" + countsRow(summary) + "</div>";
        html += categoryCards(tests, meta.categories);
        html += tableFor(filtered, tests.length, meta.caption);
        return html;
    }

    function render() {
        updateHeader();
        renderBanner();
        renderProgress();
        if (!viewEl) return;
        if (state.loading && !state.assessment) {
            viewEl.innerHTML = skeleton();
            return;
        }
        if (state.view === "identity") viewEl.innerHTML = renderIdentity();
        else if (state.view === "devices") viewEl.innerHTML = renderDevices();
        else if (PILLAR_META[state.view]) viewEl.innerHTML = renderPillar(state.view);
        else viewEl.innerHTML = renderOverview();
        bindViewEvents();
        if (filterBtn) filterBtn.classList.toggle("has-filters", hasActiveFilters());
    }

    function bindViewEvents() {
        viewEl.querySelectorAll("[data-open]").forEach(function (btn) {
            btn.addEventListener("click", function () { openDrawer(btn.getAttribute("data-open")); });
        });
        viewEl.querySelectorAll("[data-page]").forEach(function (btn) {
            btn.addEventListener("click", function () { state.page = parseInt(btn.getAttribute("data-page"), 10) || 1; render(); });
        });
        viewEl.querySelectorAll("[data-risk]").forEach(function (btn) {
            btn.addEventListener("click", function () {
                state.filters.risk = btn.getAttribute("data-risk") === "all" ? "all" : btn.getAttribute("data-risk");
                state.filters.status = btn.getAttribute("data-status") || "all";
                state.page = 1;
                render();
            });
        });
        viewEl.querySelectorAll("[data-view]").forEach(function (btn) {
            btn.addEventListener("click", function () {
                var view = btn.getAttribute("data-view");
                if (view) setView(view);
            });
        });
        viewEl.querySelectorAll("[data-platform]").forEach(function (btn) {
            btn.addEventListener("click", function () {
                state.filters.platform = btn.getAttribute("data-platform");
                state.page = 1;
                render();
            });
        });
        viewEl.querySelectorAll("[data-copy]").forEach(function (btn) {
            btn.addEventListener("click", function () {
                var value = btn.getAttribute("data-copy");
                if (navigator.clipboard) navigator.clipboard.writeText(value).then(function () { toast("Copied.", "success"); });
            });
        });
    }

    function findTest(id) {
        var tests = currentTests();
        for (var i = 0; i < tests.length; i++) if (tests[i].id === id) return tests[i];
        var a = state.assessment;
        if (!a) return null;
        var all = allTests(a);
        for (var j = 0; j < all.length; j++) if (all[j].id === id) return all[j];
        return null;
    }

    function openDrawer(id) {
        var test = findTest(id);
        if (!test || !drawer) return;
        state.selectedId = id;
        drawerTitle.textContent = test.name;
        var evidence = (test.evidence || []).map(function (e) { return "<li>" + esc(e) + "</li>"; }).join("") || "<li>Evidence was not returned.</li>";
        var steps = (test.remediationSteps || []).map(function (e) { return "<li>" + esc(e) + "</li>"; }).join("") || "<li>No remediation steps returned.</li>";
        drawerBody.innerHTML = "<dl>" +
            "<dt>Risk</dt><dd>" + riskBadge(test.risk) + "</dd>" +
            "<dt>Status</dt><dd>" + statusBadge(test.status) + "</dd>" +
            "<dt>Category</dt><dd>" + esc(test.category || "Unavailable") + "</dd>" +
            (test.assessmentLayer ? "<dt>Assessment layer</dt><dd>Configured " + esc(test.assessmentLayer.configured || "Not assessed") + " · Assigned " + esc(test.assessmentLayer.assigned || "Not assessed") + " · Observed " + esc(test.assessmentLayer.observed || "Not assessed") + " · Validation " + esc(test.assessmentLayer.validation || "Required") + "</dd>" : "") +
            "<dt>SFI pillar</dt><dd>" + esc((test.sfiPillars || []).join(", ") || "Unavailable") + "</dd>" +
            (test.platform ? "<dt>Platform</dt><dd>" + esc(test.platform) + "</dd>" : "") +
            "<dt>What it validates</dt><dd>" + esc(test.description || "Not returned") + "</dd>" +
            "<dt>Why it matters</dt><dd>" + esc(test.impact || test.description || "Not returned") + "</dd>" +
            "<dt>Evidence</dt><dd><ul>" + evidence + "</ul></dd>" +
            "<dt>Recommended remediation</dt><dd>" + esc(test.recommendation || "Not returned") + "</dd>" +
            "<dt>Remediation steps</dt><dd><ul>" + steps + "</ul></dd>" +
            "<dt>Documentation</dt><dd>" + (test.documentationUrl ? '<a href="' + esc(test.documentationUrl) + '" target="_blank" rel="noopener noreferrer">Open documentation</a>' : "Unavailable") + "</dd>" +
            "<dt>Related portal</dt><dd>" + (test.portalUrl ? '<a href="' + esc(test.portalUrl) + '" target="_blank" rel="noopener noreferrer">Open portal</a>' : "Unavailable") + "</dd>" +
            "<dt>Last evaluated</dt><dd>" + esc(formatTime(test.lastEvaluatedAt)) + "</dd>" +
            (test.error ? "<dt>Error</dt><dd>" + esc(test.error.message) + "</dd>" : "") +
            "</dl>";
        drawer.hidden = false;
        if (drawerBackdrop) drawerBackdrop.hidden = false;
        requestAnimationFrame(function () {
            drawer.classList.add("is-open");
            if (drawerBackdrop) drawerBackdrop.classList.add("is-open");
        });
    }

    function closeDrawer() {
        if (!drawer) return;
        drawer.classList.remove("is-open");
        if (drawerBackdrop) drawerBackdrop.classList.remove("is-open");
        setTimeout(function () {
            drawer.hidden = true;
            if (drawerBackdrop) drawerBackdrop.hidden = true;
        }, 180);
    }

    function openConfirm() {
        if (state.running) return;
        confirmModal.hidden = false;
        var run = document.getElementById("ztConfirmRun");
        if (run) run.focus();
    }

    function closeConfirm() {
        confirmModal.hidden = true;
    }

    function startAssessment() {
        var force = document.getElementById("ztForceRefresh").checked;
        closeConfirm();
        stopPoll();
        state.running = true;
        state.loading = true;
        state.error = "";
        if (runBtn) runBtn.disabled = true;
        render();
        jsonFetch("/api/zero-trust/start", { force: force }).then(function (data) {
            state.assessmentId = data.assessmentId || "";
            if (state.assessmentId) localStorage.setItem(STORAGE_KEY, state.assessmentId);
            state.status = data.status;
            state.progress = data.progress || 0;
            state.message = data.message || "";
            if (data.status === "completed" && data.cached) {
                return loadResults(state.assessmentId);
            }
            pollStatus();
        }).catch(function (err) {
            state.running = false;
            state.loading = false;
            state.error = err.message || "Could not start assessment.";
            if (runBtn) runBtn.disabled = false;
            render();
        });
    }

    function pollStatus() {
        if (!state.assessmentId) return;
        state.abort = new AbortController();
        jsonFetch("/api/zero-trust/status", { assessmentId: state.assessmentId }, state.abort.signal).then(function (data) {
            state.status = data.status;
            state.progress = data.progress || 0;
            state.message = data.message || "";
            renderProgress();
            if (data.status === "completed") return loadResults(state.assessmentId);
            if (data.status === "failed") {
                stopPoll();
                state.loading = false;
                state.error = data.error || data.message || "Assessment failed.";
                render();
                return;
            }
            state.pollTimer = setTimeout(pollStatus, retryDelay(data.retryAfter));
        }).catch(function (err) {
            if (err.name === "AbortError") return;
            if (err.status === 429) {
                state.pollTimer = setTimeout(pollStatus, retryDelay(err.retryAfter));
                return;
            }
            stopPoll();
            state.loading = false;
            state.error = err.message || "Status polling failed.";
            render();
        });
    }

    function loadResults(id) {
        return jsonFetch("/api/zero-trust/results", { assessmentId: id }).then(function (data) {
            stopPoll();
            state.loading = false;
            if (data.status !== "completed" || !data.assessment) {
                state.error = data.message || "Results are not ready.";
                render();
                return;
            }
            state.assessment = data.assessment;
            state.status = "completed";
            state.progress = 100;
            render();
        }).catch(function (err) {
            stopPoll();
            state.loading = false;
            state.error = err.message || "Could not load assessment results.";
            render();
        });
    }

    function restore() {
        fetch("/api/zero-trust/config", {
            credentials: "same-origin",
            headers: { "Accept": "application/json", "X-Requested-With": "XMLHttpRequest" }
        }).then(function (res) { return res.json().catch(function () { return {}; }); }).then(function (data) {
            if (data && typeof data.configured === "boolean") state.configured = data.configured;
            if (!state.configured || !state.assessmentId) {
                render();
                return;
            }
            state.loading = true;
            render();
            loadResults(state.assessmentId);
        }).catch(function () {
            if (!state.assessmentId) {
                render();
                return;
            }
            state.loading = true;
            render();
            loadResults(state.assessmentId);
        });
    }

    function download(filename, text, type) {
        var blob = new Blob([text], { type: type || "text/plain" });
        var url = URL.createObjectURL(blob);
        var a = document.createElement("a");
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
    }

    function csvEscape(value) {
        var text = String(value == null ? "" : value);
        if (/[",\n]/.test(text)) return '"' + text.replace(/"/g, '""') + '"';
        return text;
    }

    function exportCsv() {
        var tests = sortTests(applyFilters(currentTests()));
        var a = state.assessment || {};
        var header = ["assessmentId", "timestamp", "area", "name", "category", "risk", "status", "sfiPillar", "recommendation", "evidenceAvailable"];
        var lines = [header.join(",")];
        tests.forEach(function (t) {
            lines.push([
                a.assessmentId, a.completedAt || a.startedAt, t.area, t.name, t.category, t.risk, t.status,
                (t.sfiPillars || []).join(" "), t.recommendation || "", t.evidence && t.evidence.length ? "yes" : "no"
            ].map(csvEscape).join(","));
        });
        download("zero-trust-results.csv", lines.join("\n"), "text/csv");
    }

    function exportJson() {
        download("zero-trust-assessment.json", JSON.stringify(state.assessment || {}, null, 2), "application/json");
    }

    function printSummary(exec) {
        var a = state.assessment;
        if (!a) return toast("No assessment to export.", "error");
        var w = window.open("", "_blank");
        if (!w) return;
        function line(label, bucket) {
            var s = (bucket && bucket.summary) || {};
            return label + " passed " + (s.passed || 0) + " of " + (s.total || 0);
        }
        w.document.write("<html><head><title>Zero Trust Assessment</title></head><body>");
        w.document.write("<h1>" + (exec ? "Executive summary" : "Zero Trust assessment") + "</h1>");
        w.document.write("<p>Assessment ID " + esc(a.assessmentId) + " · " + esc(formatTime(a.completedAt)) + "</p>");
        w.document.write("<p>" +
            line("Identity", a.identity) + ". " +
            line("Devices", a.devices) + ". " +
            line("Network", a.network) + ". " +
            line("Data", a.data) + ". " +
            line("Infrastructure", a.infrastructure) + ".</p>");
        if (exec) {
            w.document.write("<h2>Priority remediation</h2><ol>");
            (a.priority || []).forEach(function (t) {
                w.document.write("<li>" + esc(t.name) + " (" + esc(t.risk) + " / " + esc(t.status) + ")</li>");
            });
            w.document.write("</ol>");
        }
        w.document.write("</body></html>");
        w.document.close();
        w.focus();
        w.print();
    }

    function applyTheme() {
        var dark = localStorage.getItem(THEME_KEY) === "dark";
        app.classList.toggle("is-dark", dark);
    }

    function bindPillGroup(container, attr, key) {
        if (!container) return;
        container.addEventListener("click", function (event) {
            var pill = event.target.closest(".rep-pill");
            if (!pill) return;
            draft[key] = pill.getAttribute(attr) || "all";
            syncPills(container, attr, draft[key]);
            if (key === "area") syncFilterSections();
        });
    }

    bindPillGroup(filterAreaPills, "data-area", "area");
    bindPillGroup(filterRiskPills, "data-risk", "risk");
    bindPillGroup(filterStatusPills, "data-status", "status");
    bindPillGroup(filterPlatformPills, "data-platform", "platform");
    bindPillGroup(filterScopePills, "data-scope", "scope");

    if (filterSearch) {
        filterSearch.addEventListener("input", function () {
            draft.query = filterSearch.value || "";
        });
    }
    if (filterCategory) {
        filterCategory.addEventListener("change", function () {
            draft.category = filterCategory.value || "all";
        });
    }
    if (filterSort) {
        filterSort.addEventListener("change", function () {
            draft.sort = filterSort.value || "priority";
        });
    }
    if (filterBtn) {
        filterBtn.addEventListener("click", function (event) {
            event.stopPropagation();
            toggleFilter();
        });
    }
    if (filterClose) filterClose.addEventListener("click", closeFilter);
    if (filterPanel) {
        filterPanel.addEventListener("click", function (event) { event.stopPropagation(); });
    }
    document.addEventListener("click", function () { closeFilter(); });
    if (filterApply) {
        filterApply.addEventListener("click", function () {
            state.filters = copyFilters(draft);
            state.page = 1;
            render();
            closeFilter();
        });
    }
    if (filterReset) {
        filterReset.addEventListener("click", function () {
            state.filters = defaultFilters();
            state.page = 1;
            syncDraftFromState();
            render();
        });
    }

    document.querySelectorAll(".zt-tab").forEach(function (tab) {
        tab.addEventListener("click", function (event) {
            event.preventDefault();
            setView(tab.getAttribute("data-view"));
        });
    });
    window.addEventListener("popstate", function () {
        var path = location.pathname;
        if (path.indexOf("/identity") !== -1) setView("identity", false);
        else if (path.indexOf("/devices") !== -1) setView("devices", false);
        else if (path.indexOf("/network") !== -1) setView("network", false);
        else if (path.indexOf("/data") !== -1) setView("data", false);
        else if (path.indexOf("/infrastructure") !== -1) setView("infrastructure", false);
        else setView("overview", false);
    });
    if (runBtn) runBtn.addEventListener("click", openConfirm);
    if (refreshBtn) refreshBtn.addEventListener("click", openConfirm);
    document.getElementById("ztConfirmCancel").addEventListener("click", closeConfirm);
    document.getElementById("ztConfirmRun").addEventListener("click", startAssessment);
    document.getElementById("ztHelpBtn").addEventListener("click", function () { helpModal.hidden = false; });
    document.getElementById("ztHelpClose").addEventListener("click", function () { helpModal.hidden = true; });
    document.getElementById("ztDrawerClose").addEventListener("click", closeDrawer);
    if (drawerBackdrop) drawerBackdrop.addEventListener("click", closeDrawer);
    document.getElementById("ztThemeBtn").addEventListener("click", function () {
        var next = app.classList.contains("is-dark") ? "light" : "dark";
        localStorage.setItem(THEME_KEY, next);
        applyTheme();
    });
    if (exportBtn) exportBtn.addEventListener("click", function () {
        var open = exportMenu.hidden;
        exportMenu.hidden = !open;
        exportBtn.setAttribute("aria-expanded", open ? "true" : "false");
    });
    if (exportMenu) exportMenu.addEventListener("click", function (event) {
        var btn = event.target.closest("[data-export]");
        if (!btn) return;
        exportMenu.hidden = true;
        var kind = btn.getAttribute("data-export");
        if (kind === "csv") exportCsv();
        else if (kind === "json") exportJson();
        else if (kind === "print") printSummary(false);
        else printSummary(true);
    });
    document.addEventListener("keydown", function (event) {
        if (event.key === "Escape") {
            closeDrawer();
            closeConfirm();
            closeFilter();
            helpModal.hidden = true;
            exportMenu.hidden = true;
        }
    });
    window.addEventListener("beforeunload", stopPoll);
    applyTheme();
    setView(state.view, false);
    restore();
})();
