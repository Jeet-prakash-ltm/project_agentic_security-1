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
            sort: "priority"
        },
        page: 1,
        selectedId: null
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
            guests: '<path d="M16 21v-2a4 4 0 00-4-4H6a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M19 8v6M22 11h-6"/>',
            groups: '<path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75"/>',
            apps: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
            devices: '<rect x="5" y="3" width="14" height="12" rx="2"/><path d="M8 21h8M12 15v6"/>',
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
        var tabs = app.querySelectorAll(".zt-tab");
        for (var i = 0; i < tabs.length; i++) {
            var active = tabs[i].getAttribute("data-view") === view;
            tabs[i].classList.toggle("is-active", active);
            if (active) tabs[i].setAttribute("aria-current", "page");
            else tabs[i].removeAttribute("aria-current");
        }
        if (push !== false) {
            var path = "/dashboard/cloud-security";
            if (view === "identity") path += "/identity";
            if (view === "devices") path += "/devices";
            if (window.history && history.pushState) history.pushState({ ztView: view }, "", path);
        }
        render();
    }

    function currentTests() {
        var a = state.assessment;
        if (!a) return [];
        if (state.view === "identity") return (a.identity && a.identity.tests) || [];
        if (state.view === "devices") return (a.devices && a.devices.tests) || [];
        return ((a.identity && a.identity.tests) || []).concat((a.devices && a.devices.tests) || []);
    }

    function applyFilters(tests) {
        var f = state.filters;
        var q = (f.query || "").trim().toLowerCase();
        return tests.filter(function (t) {
            if (q) {
                var hay = [t.name, t.category, t.description, t.recommendation].join(" ").toLowerCase();
                if (hay.indexOf(q) === -1) return false;
            }
            if (f.risk !== "all" && t.risk !== f.risk) return false;
            if (f.status !== "all" && t.status !== f.status) return false;
            if (f.pillar !== "all" && (t.sfiPillars || []).indexOf(f.pillar) === -1) return false;
            if (f.category !== "all" && t.category !== f.category) return false;
            if (state.view === "devices" && f.platform && f.platform !== "All" && (t.platform || "Tenant-wide") !== f.platform) return false;
            if (state.view === "devices" && f.scope !== "all") {
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

    function renderOverview() {
        var a = state.assessment;
        if (!a) return emptyState("No assessment results are available.", "Run a Zero Trust assessment to populate this dashboard.");
        var t = a.tenant || {};
        var idSum = (a.identity && a.identity.summary) || {};
        var devSum = (a.devices && a.devices.summary) || {};
        var score = a.score != null ? a.score : a.weightedScore;
        var scoreLabel = a.scoreSource === "backend" ? "Assessment score from backend" : "Weighted posture score";
        var html = '<div class="zt-grid">';
        html += '<section class="zt-card"><h2>Tenant summary</h2><dl class="zt-kvs">' +
            "<dt>Tenant</dt><dd>" + esc(t.tenantName || t.primaryDomain || "Unavailable") + "</dd>" +
            "<dt>Primary domain</dt><dd>" + esc(t.primaryDomain || "Unavailable") + "</dd>" +
            "<dt>Tenant ID</dt><dd>" + esc(maskTenant(t.tenantId)) +
            (state.isAdmin && t.tenantId ? ' <button type="button" class="zt-copy" data-copy="' + esc(t.tenantId) + '">Copy</button>' : "") + "</dd>" +
            "<dt>Assessment ID</dt><dd>" + esc(a.assessmentId || "Unavailable") + "</dd>" +
            "<dt>Last assessment</dt><dd>" + esc(formatTime(a.completedAt)) + "</dd>" +
            "<dt>State</dt><dd>" + esc(a.status || "completed") + "</dd></dl></section>";
        html += '<section class="zt-card"><h2>Assessment summary</h2>' + donutHtml("ztDonut", idSum, devSum) + "</section>";
        html += '<section class="zt-card"><h2>Posture score</h2><div class="zt-metric-value">' + esc(metric(score)) + (score != null ? "%" : "") + '</div><p class="zt-muted">' + esc(scoreLabel) + "</p></section>";
        html += "</div>";
        html += '<div class="zt-grid-6" style="margin-top:14px">' +
            metricCard("Users", t.users, "users") +
            metricCard("Guests", t.guests, "guests") +
            metricCard("Groups", t.groups, "groups") +
            metricCard("Applications", t.applications, "apps") +
            metricCard("Devices", t.devices, "devices") +
            metricCard("Managed devices", t.managedDevices, "devices") +
            "</div>";
        html += '<div class="zt-risk-grid" style="margin-top:14px">' +
            riskNav("Critical attention", idSum.highRiskFailed + devSum.highRiskFailed, "High", "Failed") +
            riskNav("Medium-risk failures", idSum.mediumRiskFailed + devSum.mediumRiskFailed, "Medium", "Failed") +
            riskNav("Passed tests", idSum.passed + devSum.passed, "all", "Passed") +
            riskNav("Investigate", idSum.investigate + devSum.investigate, "all", "Investigate") +
            riskNav("Skipped", idSum.skipped + devSum.skipped, "all", "Skipped") +
            "</div>";
        html += '<section class="zt-card" style="margin-top:14px"><h2>Priority remediation</h2>' + renderPriority(a.priority || []) + "</section>";
        html += '<div class="zt-grid-2" style="margin-top:14px">' + vizCard("Privileged users authentication methods", a.visualizations && a.visualizations.privilegedAuth) + vizCard("User authentication coverage", a.visualizations && a.visualizations.userAuthCoverage) + vizCard("Conditional Access coverage", a.visualizations && a.visualizations.conditionalAccessCoverage) + vizCard("Device sign-in state", a.visualizations && a.visualizations.deviceSignIn) + "</div>";
        return html;
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
        var body = data
            ? '<p class="zt-muted">Telemetry visualization is available for this assessment.</p>'
            : '<div class="zt-viz-empty"><div><strong>Visualization unavailable</strong><p>The assessment returned configuration test results but did not return the telemetry required for this flow diagram.</p></div></div>';
        return '<section class="zt-card"><h3>' + esc(title) + "</h3>" + body + "</section>";
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
        return '<div class="zt-grid" style="margin:14px 0">' + labels.map(function (label) {
            var subset = tests.filter(function (t) { return (t.category || "") === label; });
            var passed = subset.filter(function (t) { return t.status === "Passed"; }).length;
            return '<article class="zt-card"><h3>' + esc(label) + "</h3><div class=\"zt-metric-value\">" + subset.length + '</div><p class="zt-muted">' + passed + " passed</p></article>";
        }).join("") + "</div>";
    }

    function toolbar(tests) {
        var cats = unique(tests.map(function (t) { return t.category; }));
        var pillars = unique(tests.reduce(function (acc, t) { return acc.concat(t.sfiPillars || []); }, []));
        var html = '<div class="zt-toolbar" id="ztFilters">';
        html += field("Search", '<input type="search" id="ztQuery" value="' + esc(state.filters.query) + '" placeholder="Search by test name" aria-label="Search by test name">');
        html += selectField("Risk", "ztRisk", ["all", "High", "Medium", "Low"], state.filters.risk);
        html += selectField("Status", "ztStatus", ["all", "Passed", "Failed", "Planned", "Investigate", "Skipped"], state.filters.status);
        html += selectField("SFI pillar", "ztPillar", ["all"].concat(pillars), state.filters.pillar);
        html += selectField("Category", "ztCategory", ["all"].concat(cats), state.filters.category);
        if (state.view === "devices") {
            html += selectField("Scope", "ztScope", ["all", "Device", "Tenant", "Data"], state.filters.scope);
            html += selectField("Sort", "ztSort", ["priority", "name", "status"], state.filters.sort);
        } else {
            html += selectField("Sort", "ztSort", ["priority", "name", "status"], state.filters.sort);
        }
        html += '<div class="zt-field"><label>&nbsp;</label><button class="btn btn-ghost" type="button" id="ztClearFilters">Clear all filters</button></div>';
        html += "</div>";
        return html;
    }

    function field(label, control) {
        return '<div class="zt-field"><label>' + esc(label) + "</label>" + control + "</div>";
    }

    function selectField(label, id, options, value) {
        var opts = options.map(function (o) {
            return '<option value="' + esc(o) + '"' + (String(o) === String(value) ? " selected" : "") + ">" + esc(o === "all" ? "All" : o) + "</option>";
        }).join("");
        return field(label, '<select id="' + id + '" aria-label="' + esc(label) + '">' + opts + "</select>");
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
            : "<th>Test name</th><th>Risk</th><th>Status</th><th>SFI pillar</th><th>Category</th><th>Last evaluated</th><th>Action</th>";
        var rows = page.map(function (t) {
            var cols = state.view === "devices"
                ? "<td>" + esc(t.name) + "</td><td>" + esc(t.category || "") + "</td><td>" + esc(t.platform || "Tenant-wide") + "</td><td>" + riskBadge(t.risk) + "</td><td>" + statusBadge(t.status) + "</td><td>" + esc((t.sfiPillars || []).join(", ")) + "</td>"
                : "<td>" + esc(t.name) + "</td><td>" + riskBadge(t.risk) + "</td><td>" + statusBadge(t.status) + "</td><td>" + esc((t.sfiPillars || []).join(", ")) + "</td><td>" + esc(t.category || "") + "</td><td>" + esc(formatTime(t.lastEvaluatedAt)) + "</td>";
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
        var html = '<div class="page-head"><h1>Identity Assessment</h1><p>' + tests.length + " checks · high-risk failed " + (summary.highRiskFailed || 0) + " · last evaluated " + formatTime(a.completedAt) + "</p>" + countsRow(summary) + "</div>";
        html += categoryCards(tests, ["Privileged accounts", "Authentication methods", "Conditional Access", "Application identity security", "External identities", "Monitoring and diagnostics", "Tenant administration"]);
        html += toolbar(tests);
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
        var html = '<div class="page-head"><h1>Device Assessment</h1><p>' + tests.length + " tests · high-risk failed " + (summary.highRiskFailed || 0) + " · devices " + metric(inv.count) + " · managed " + metric(inv.count) + " · last evaluated " + formatTime(a.completedAt) + "</p>" + countsRow(summary) + "</div>";
        html += categoryCards(tests, ["Compliance", "Enrollment", "Endpoint protection", "Encryption", "Firewall", "Secure configuration", "Updates", "Platform authentication", "Tenant administration"]);
        html += '<div class="zt-platform-tabs" role="tablist">' + platforms.map(function (p) {
            var subset = p === "All" ? tests : tests.filter(function (t) { return (t.platform || "Tenant-wide") === p; });
            var failedHigh = subset.filter(function (t) { return t.status === "Failed" && t.risk === "High"; }).length;
            var passed = subset.filter(function (t) { return t.status === "Passed"; }).length;
            return '<button type="button" role="tab" data-platform="' + esc(p) + '" class="' + (state.filters.platform === p ? "is-active" : "") + '" aria-selected="' + (state.filters.platform === p ? "true" : "false") + '">' + esc(p) + " · " + subset.length + " / " + passed + " passed / " + failedHigh + " high-risk</button>";
        }).join("") + "</div>";
        html += '<section class="zt-card" style="margin-bottom:14px"><h2>Device join and compliance flow</h2>' + (a.visualizations && a.visualizations.deviceFlow
            ? '<p class="zt-muted">Device inventory flow is available.</p>'
            : '<div class="zt-viz-empty"><div><strong>Visualization unavailable</strong><p>The assessment returned configuration test results but did not return the telemetry required for this flow diagram.</p></div></div>') + "</section>";
        html += toolbar(tests);
        html += tableFor(filtered, tests.length, "device tests");
        return html;
    }

    function bindFilters() {
        function set(id, key) {
            var el = document.getElementById(id);
            if (!el) return;
            el.addEventListener("change", function () {
                state.filters[key] = el.value;
                state.page = 1;
                render();
            });
            if (el.tagName === "INPUT") {
                var t;
                el.addEventListener("input", function () {
                    clearTimeout(t);
                    t = setTimeout(function () {
                        state.filters.query = el.value;
                        state.page = 1;
                        render();
                    }, 180);
                });
            }
        }
        set("ztQuery", "query");
        set("ztRisk", "risk");
        set("ztStatus", "status");
        set("ztPillar", "pillar");
        set("ztCategory", "category");
        set("ztScope", "scope");
        set("ztSort", "sort");
        var clear = document.getElementById("ztClearFilters");
        if (clear) clear.onclick = function () {
            state.filters = { query: "", risk: "all", status: "all", pillar: "all", category: "all", platform: state.view === "devices" ? "All" : "All", scope: "all", sort: "priority" };
            state.page = 1;
            render();
        };
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
        else viewEl.innerHTML = renderOverview();
        var canvas = document.getElementById("ztDonut");
        if (canvas && state.assessment) {
            paintDonut(canvas, (state.assessment.identity || {}).summary || {}, (state.assessment.devices || {}).summary || {});
        }
        bindFilters();
        bindViewEvents();
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
                setView("identity");
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
        var all = ((a.identity && a.identity.tests) || []).concat((a.devices && a.devices.tests) || []).concat((a.other && a.other.tests) || []);
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
        if (!state.configured) {
            toast("Zero Trust Assessment is not configured on the server.", "error");
            return;
        }
        if (state.running) return;
        confirmModal.hidden = false;
        document.getElementById("ztConfirmRun").focus();
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
        if (!state.configured || !state.assessmentId) {
            render();
            return;
        }
        state.loading = true;
        render();
        loadResults(state.assessmentId);
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
        var idSum = (a.identity && a.identity.summary) || {};
        var devSum = (a.devices && a.devices.summary) || {};
        w.document.write("<html><head><title>Zero Trust Assessment</title></head><body>");
        w.document.write("<h1>" + (exec ? "Executive summary" : "Zero Trust assessment") + "</h1>");
        w.document.write("<p>Assessment ID " + esc(a.assessmentId) + " · " + esc(formatTime(a.completedAt)) + "</p>");
        w.document.write("<p>Identity passed " + (idSum.passed || 0) + " of " + (idSum.total || 0) + ". Devices passed " + (devSum.passed || 0) + " of " + (devSum.total || 0) + ".</p>");
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
            helpModal.hidden = true;
            exportMenu.hidden = true;
        }
    });
    window.addEventListener("beforeunload", stopPoll);
    applyTheme();
    setView(state.view, false);
    restore();
})();
