(function () {
    var app = document.getElementById("ztApp");
    if (!app) return;

    var STORAGE_KEY = "ltm_zt_assessment_id";
    var PAGE_SIZE = 12;
    var OVERVIEW_FINDINGS = 5;
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
        selectedId: null,
        pillarTab: "overview",
        drawerTab: "overview",
        drawerPages: {},
        drawerOpen: {},
        drawerEvidenceKey: "",
        drawerEvidenceQuery: "",
        overviewSection: null
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
    var bannerEl = document.getElementById("ztStatusPill");
    var progressEl = document.getElementById("ztProgress");
    var runBtn = document.getElementById("ztRunBtn");
    var refreshBtn = document.getElementById("ztRefreshBtn");
    var confirmModal = document.getElementById("ztConfirmModal");
    var drawer = document.getElementById("ztDrawer");
    var drawerBackdrop = document.getElementById("ztDrawerBackdrop");
    var drawerBody = document.getElementById("ztDrawerBody");
    var drawerTitle = document.getElementById("ztDrawerTitle");
    var drawerBadges = document.getElementById("ztDrawerBadges");
    var drawerTabs = document.getElementById("ztDrawerTabs");
    var drawerDownload = document.getElementById("ztDrawerDownload");
    var EVIDENCE_PAGE_SIZE = 25;
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
    var filterWrap = document.getElementById("ztFilterWrap");
    var filterAreaSection = document.getElementById("ztFilterAreaSection");
    var filterPlatformSection = document.getElementById("ztFilterPlatformSection");
    var filterScopeSection = document.getElementById("ztFilterScopeSection");
    var tenantBtn = document.getElementById("ztTenantBtn");
    var tenantPop = document.getElementById("ztTenantPop");
    var assessBtn = document.getElementById("ztAssessBtn");
    var assessPop = document.getElementById("ztAssessPop");

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
            key: '<path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>',
            lock: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/>',
            cert: '<rect x="4" y="3" width="16" height="13" rx="2"/><path d="M9 21l3-2 3 2v-6H9z"/>',
            clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
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

    var PILLAR_VIEW_KEYS = ["identity", "devices", "network", "data", "infrastructure"];
    var PAGE_PATH = "/dashboard/cloud-security";

    function viewPath(view) {
        if (!view || view === "overview") return PAGE_PATH;
        return PAGE_PATH + "?view=" + encodeURIComponent(view);
    }

    function pathToView(href) {
        try {
            var url = new URL(href, location.origin);
            var view = (url.searchParams.get("view") || "").toLowerCase();
            if (PILLAR_VIEW_KEYS.indexOf(view) !== -1) return view;
        } catch (e) {}
        return "overview";
    }

    function setView(view, push) {
        if (push !== false) {
            var path = viewPath(view);
            if (location.pathname + location.search !== path) {
                window.location.href = path;
                return;
            }
        }
        state.view = view;
        state.page = 1;
        state.pillarTab = "overview";
        if (view !== "overview") state.filters.area = "all";
        syncPageTabs();
        closeFilter();
        render();
    }

    function syncPageTabs() {
        var tabs = document.querySelectorAll("#ztPageTabs [data-tab]");
        for (var i = 0; i < tabs.length; i++) {
            var active = tabs[i].getAttribute("data-tab") === state.view;
            tabs[i].classList.toggle("is-active", active);
            tabs[i].setAttribute("aria-selected", active ? "true" : "false");
        }
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
                var hay = [t.id, t.name, t.category, t.description, t.recommendation].join(" ").toLowerCase();
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
        if (runBtn) runBtn.disabled = state.running;
        if (filterWrap) filterWrap.hidden = state.view === "overview";
        if (filterBtn) filterBtn.hidden = state.view === "overview";
        if (state.view === "overview") closeFilter();
        var topnav = document.getElementById("ztTopNav");
        if (topnav) {
            topnav.hidden = state.view !== "overview";
            topnav.classList.toggle("is-compact", state.view !== "overview");
        }
        syncPageTabs();
    }

    function statusInfoButton(label, tipHtml) {
        return '<button type="button" class="zt-info-btn" id="ztStatusInfo" aria-label="' + label + '" aria-expanded="false">' +
            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 8h.01"/><path d="M11 12h1v4h1"/></svg>' +
            '<span class="zt-info-tip" role="tooltip">' + tipHtml + "</span></button>";
    }

    function bindStatusInfo() {
        var infoBtn = document.getElementById("ztStatusInfo");
        if (!infoBtn || !bannerEl) return;
        infoBtn.onclick = function (ev) {
            ev.stopPropagation();
            var open = bannerEl.classList.toggle("is-open");
            infoBtn.setAttribute("aria-expanded", open ? "true" : "false");
        };
    }

    function renderBanner() {
        if (!bannerEl) return;
        bannerEl.classList.remove("is-open");
        if (state.running || state.loading) {
            bannerEl.hidden = true;
            bannerEl.textContent = "";
            return;
        }
        if (state.error) {
            bannerEl.hidden = false;
            bannerEl.className = "zt-status-pill is-error";
            bannerEl.innerHTML = '<span class="zt-status-dot" aria-hidden="true"></span><strong>Failed</strong>';
            return;
        }
        if (state.assessment && state.assessment.partial && state.assessment.partial.length) {
            bannerEl.hidden = false;
            bannerEl.className = "zt-status-pill is-partial";
            bannerEl.innerHTML = '<span class="zt-status-dot" aria-hidden="true"></span><strong>Partial</strong>';
            return;
        }
        if (state.assessment && (state.status === "completed" || state.assessment.completedAt)) {
            bannerEl.hidden = false;
            if (state.assessment.stale) {
                bannerEl.className = "zt-status-pill is-stale";
                bannerEl.innerHTML = '<span class="zt-status-dot" aria-hidden="true"></span><strong>Partial</strong>';
                return;
            }
            bannerEl.className = "zt-status-pill is-success";
            bannerEl.innerHTML = '<span class="zt-status-dot" aria-hidden="true"></span><strong>Completed</strong>';
            return;
        }
        if (state.assessmentId || state.status) {
            bannerEl.hidden = false;
            bannerEl.className = "zt-status-pill is-error";
            bannerEl.innerHTML = '<span class="zt-status-dot" aria-hidden="true"></span><strong>Failed</strong>';
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

    var PILLAR_ORDER = [
        { key: "identity", name: "Identity", view: "identity" },
        { key: "devices", name: "Endpoint Device", view: "devices" },
        { key: "network", name: "Network", view: "network" },
        { key: "data", name: "Data", view: "data" },
        { key: "infrastructure", name: "Infrastructure", view: "infrastructure" }
    ];

    var STATUS_COLORS = {
        Passed: "#22C55E",
        Failed: "#EF4444",
        Investigate: "#FBBF24",
        Planned: "#A78BFA",
        Skipped: "#9CA3AF"
    };

    var RISK_COLORS = {
        High: "#F97316",
        Medium: "#FBBF24",
        Low: "#22C55E"
    };

    function pct(num, den) {
        if (num == null || den == null || den <= 0) return null;
        return Math.round((Number(num) / Number(den)) * 100);
    }

    function scoreModel(a) {
        if (a && a.score != null && a.score !== "") {
            return { value: Number(a.score), label: "Zero Trust score", source: "Returned by the assessment API." };
        }
        if (a && a.weightedScore != null && a.weightedScore !== "") {
            return { value: Number(a.weightedScore), label: "Weighted control score", source: "Derived from control results. Skipped controls are excluded. This is not a separate backend maturity model." };
        }
        return { value: null, label: "Zero Trust score", source: "No score was returned for this assessment." };
    }

    function scoreTone(value) {
        if (value == null || isNaN(value)) return "unknown";
        if (value >= 80) return "strong";
        if (value >= 60) return "moderate";
        if (value >= 40) return "weak";
        return "critical";
    }

    function coverageModel(tests) {
        var total = tests.length;
        var passed = 0, failed = 0, planned = 0, investigate = 0, skipped = 0;
        tests.forEach(function (t) {
            if (t.status === "Passed") passed += 1;
            else if (t.status === "Failed") failed += 1;
            else if (t.status === "Planned") planned += 1;
            else if (t.status === "Investigate") investigate += 1;
            else if (t.status === "Skipped") skipped += 1;
        });
        var assessed = passed + failed + planned;
        return {
            total: total,
            passed: passed,
            failed: failed,
            planned: planned,
            investigate: investigate,
            skipped: skipped,
            assessed: assessed,
            coveragePct: pct(assessed, total)
        };
    }

    function pillarModels(a) {
        return PILLAR_ORDER.map(function (p) {
            var bucket = (a && a[p.key]) || {};
            var summary = bucket.summary || {};
            var tests = bucket.tests || [];
            var total = summary.total || tests.length || 0;
            var passed = summary.passed || 0;
            return {
                key: p.key,
                name: p.name,
                view: p.view,
                summary: summary,
                tests: tests,
                total: total,
                passed: passed,
                failed: summary.failed || 0,
                investigate: summary.investigate || 0,
                high: summary.highRiskFailed || 0,
                passRate: pct(passed, total)
            };
        });
    }

    function severityCounts(tests) {
        var counts = { High: 0, Medium: 0, Low: 0 };
        tests.forEach(function (t) {
            if (t.status !== "Failed") return;
            if (counts[t.risk] != null) counts[t.risk] += 1;
        });
        return counts;
    }

    function heatmapCounts(a) {
        return pillarModels(a).map(function (p) {
            var row = { name: p.name, view: p.view, High: 0, Medium: 0, Low: 0 };
            (p.tests || []).forEach(function (t) {
                if (t.status !== "Failed") return;
                if (row[t.risk] != null) row[t.risk] += 1;
            });
            row.total = row.High + row.Medium + row.Low;
            return row;
        });
    }

    function pillarRiskChart(heat) {
        var levels = [
            { key: "High", color: "#EF4444" },
            { key: "Medium", color: "#FBBF24" },
            { key: "Low", color: "#22C55E" }
        ];
        var ranked = (heat || []).slice().sort(function (a, b) { return (b.total || 0) - (a.total || 0); });
        var max = 1;
        ranked.forEach(function (row) {
            levels.forEach(function (s) { max = Math.max(max, row[s.key] || 0); });
        });
        var top = max <= 4 ? 4 : (max <= 8 ? 8 : Math.ceil(max / 5) * 5);
        var highest = ranked.length && ranked[0].total > 0 ? ranked[0].name : "";
        var html = '<section class="zt-card zt-pillar-risk"><h2>Pillar risk</h2>';
        html += '<div class="zt-domain-legend">';
        levels.forEach(function (s) {
            html += '<span class="zt-domain-legend-item"><i style="background:' + s.color + '"></i>' + s.key + "</span>";
        });
        html += "</div>";
        html += '<div class="zt-domain-plot"><div class="zt-domain-yaxis">';
        [top, Math.round(top * 0.75), Math.round(top * 0.5), Math.round(top * 0.25), 0].forEach(function (n) {
            html += "<span>" + n + "</span>";
        });
        html += '</div><div class="zt-domain-stage"><div class="zt-domain-grid" aria-hidden="true"><span></span><span></span><span></span><span></span><span></span></div>';
        html += '<div class="zt-domain-axis">';
        ranked.forEach(function (row) {
            html += '<div class="zt-domain-group' + (row.name === highest ? " is-highest" : "") + '">';
            html += '<a class="zt-domain-summary" href="' + esc(investigationUrl(row.view || row.name)) + '"><strong>' + esc(row.name) + "</strong><span>Total Risk: " + (row.total || 0) + "</span>";
            if (row.name === highest) html += '<em class="zt-domain-badge">Highest Risk Pillar</em>';
            html += '</a><div class="zt-domain-cols">';
            levels.forEach(function (s) {
                var n = row[s.key] || 0;
                var h = top ? Math.round(n / top * 100) : 0;
                html += '<a class="zt-domain-col" href="' + esc(investigationUrl(row.view || row.name, s.key)) + '" aria-label="' + esc(row.name + " " + s.key) + '">';
                if (n > 0) html += '<span class="zt-domain-value">' + n + '</span><span class="zt-domain-fill" style="height:' + h + "%;background:" + s.color + '"></span>';
                html += "</a>";
            });
            html += '</div><a class="zt-domain-label" href="' + esc(investigationUrl(row.view || row.name)) + '">' + esc(row.name) + "</a></div>";
        });
        html += "</div></div></div></section>";
        return html;
    }

    function progressRow(label, num, den, tone) {
        if (num == null || den == null) {
            return '<div class="zt-progress-row"><span>' + esc(label) + '</span><strong>Unavailable</strong><span class="zt-pillar-track"><span class="zt-pillar-fill is-unknown" style="width:0"></span></span></div>';
        }
        var p = pct(num, den);
        var width = p == null ? 0 : p;
        var shown = p == null ? "—" : (p + "%");
        return '<div class="zt-progress-row"><span>' + esc(label) + "</span><strong>" + esc(String(num)) + " / " + esc(String(den)) + " · " + shown + '</strong><span class="zt-pillar-track" aria-hidden="true"><span class="zt-pillar-fill is-' + (tone || "info") + '" style="width:' + width + '%"></span></span></div>';
    }

    function paintRing(canvas, value, tone) {
        if (!canvas || !canvas.getContext) return;
        var ctx = canvas.getContext("2d");
        var size = canvas.width;
        var cx = size / 2, cy = size / 2, r = size / 2 - 10;
        var colors = { strong: "#22C55E", moderate: "#FBBF24", weak: "#F97316", critical: "#EF4444", unknown: "#6B7280" };
        ctx.clearRect(0, 0, size, size);
        ctx.lineWidth = 10;
        ctx.strokeStyle = "rgba(255, 255, 255, 0.12)";
        ctx.beginPath();
        ctx.arc(cx, cy, r, 0, Math.PI * 2);
        ctx.stroke();
        if (value == null || isNaN(value)) return;
        var start = -Math.PI / 2;
        ctx.strokeStyle = colors[tone] || colors.unknown;
        ctx.beginPath();
        ctx.arc(cx, cy, r, start, start + (Math.max(0, Math.min(value, 100)) / 100) * Math.PI * 2);
        ctx.stroke();
    }

    function paintSegments(canvas, segments) {
        if (!canvas || !canvas.getContext) return;
        var ctx = canvas.getContext("2d");
        var size = canvas.width;
        var cx = size / 2, cy = size / 2, r = size / 2 - 15;
        var total = 0;
        segments.forEach(function (s) { total += s.value || 0; });
        ctx.clearRect(0, 0, size, size);
        ctx.lineWidth = 17;
        if (total <= 0) {
            ctx.strokeStyle = "rgba(255, 255, 255, 0.12)";
            ctx.beginPath();
            ctx.arc(cx, cy, r, 0, Math.PI * 2);
            ctx.stroke();
            return;
        }
        var angle = -Math.PI / 2;
        segments.forEach(function (s) {
            var sweep = ((s.value || 0) / total) * Math.PI * 2;
            ctx.strokeStyle = s.color;
            ctx.beginPath();
            ctx.arc(cx, cy, r, angle, angle + sweep);
            ctx.stroke();
            angle += sweep;
        });
    }

    function paintOverviewCharts() {
        var scoreEl = document.getElementById("ztScoreRing");
        if (scoreEl) {
            paintSegments(scoreEl, [
                { value: Number(scoreEl.getAttribute("data-passed") || 0), color: "#16A34A" },
                { value: Number(scoreEl.getAttribute("data-failed") || 0), color: "#DC2626" },
                { value: Number(scoreEl.getAttribute("data-investigate") || 0), color: "#F59E0B" }
            ]);
        }
        var statusEl = document.getElementById("ztStatusDonut");
        if (statusEl) {
            paintSegments(statusEl, [
                { value: Number(statusEl.getAttribute("data-passed") || 0), color: STATUS_COLORS.Passed },
                { value: Number(statusEl.getAttribute("data-failed") || 0), color: STATUS_COLORS.Failed },
                { value: Number(statusEl.getAttribute("data-investigate") || 0), color: STATUS_COLORS.Investigate },
                { value: Number(statusEl.getAttribute("data-planned") || 0), color: STATUS_COLORS.Planned },
                { value: Number(statusEl.getAttribute("data-skipped") || 0), color: STATUS_COLORS.Skipped }
            ]);
        }
        var signEl = document.getElementById("ztSignInDonut");
        if (signEl) {
            paintSegments(signEl, [
                { value: Number(signEl.getAttribute("data-success") || 0), color: STATUS_COLORS.Passed },
                { value: Number(signEl.getAttribute("data-failure") || 0), color: STATUS_COLORS.Failed }
            ]);
        }
    }

    function investigationPillar(value) {
        var key = String(value || "").toLowerCase().replace(/[\s_-]+/g, "");
        if (key === "identity") return "Identity";
        if (key === "devices" || key === "endpointdevice" || key === "endpointdevices") return "Devices";
        if (key === "network") return "Network";
        if (key === "data") return "Data";
        if (key === "infrastructure") return "Infrastructure";
        return "";
    }

    function investigationUrl(pillar, risk) {
        var params = new URLSearchParams();
        params.set("view", "zero_trust");
        var p = investigationPillar(pillar);
        if (p) params.set("pillar", p);
        var r = String(risk || "").toLowerCase();
        if (r && r !== "all") params.set("risk", r);
        return "/findings?" + params.toString();
    }

    function setFindingFilter(area, risk, status) {
        state.filters.area = area || "all";
        state.filters.risk = risk || "all";
        state.filters.status = status || "all";
        state.page = 1;
        render();
        var el = document.getElementById("ztFindings");
        if (el && el.scrollIntoView) el.scrollIntoView({ behavior: "smooth", block: "start" });
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
        return '<article class="zt-inv-tile is-' + tone + '">' +
            '<span class="zt-inv-icon zt-tone-' + tone + '">' + icon(ic) + "</span>" +
            '<span class="zt-inv-label">' + esc(label) + "</span>" +
            "<strong>" + esc(compactNumber(value)) + "</strong></article>";
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
        var tests = allTests(a);
        var cover = coverageModel(tests);
        var pillars = pillarModels(a);
        var score = scoreModel(a);
        var heat = heatmapCounts(a);
        var viz = a.visualizations || {};
        var html = "";

        var passedPct = pct(cover.passed, cover.total);
        var failedPct = pct(cover.failed, cover.total);
        var investPct = pct(cover.investigate, cover.total);
        html += '<section class="zt-exec">' +
            '<section class="zt-inventory-card">' +
            "<h2>Tenant inventory</h2>" +
            '<div class="zt-inv-metrics">' +
            inventoryStat("blue", "user", "Users", t.users) +
            inventoryStat("sky", "guests", "Guest users", t.guests) +
            inventoryStat("purple", "laptop", "Total device", t.totalDevices != null ? t.totalDevices : t.devices) +
            inventoryStat("violet", "devices", "Intune Managed Devices", t.managedDevices) +
            inventoryStat("sky", "laptop", "Entra Devices", t.entraDevices) +
            inventoryStat("teal", "groups", "Groups", t.groups) +
            inventoryStat("mint", "apps", "Applications", t.applications) +
            "</div></section>" +
            '<article class="zt-score-card">' +
            "<h2>Zero Trust Score</h2>" +
            '<div class="zt-score-ring-wrap">' +
            '<canvas id="ztScoreRing" width="220" height="220" data-passed="' + cover.passed + '" data-failed="' + cover.failed + '" data-investigate="' + cover.investigate + '" role="img" aria-label="' + esc(score.label) + " " + (score.value == null ? "unavailable" : score.value + " of 100") + '"></canvas>' +
            '<div class="zt-score-center"><strong>' + (score.value == null ? "—" : esc(String(score.value))) + "%</strong></div>" +
            "</div>" +
            '<div class="zt-donut-pills">' +
            '<button type="button" class="zt-donut-pill" data-risk="all" data-status="Passed"><i class="zt-donut-dot is-passed"></i><span>Passed</span><strong>' + cover.passed + "</strong><em>" + (passedPct == null ? "—" : passedPct + "%") + "</em></button>" +
            '<button type="button" class="zt-donut-pill" data-risk="all" data-status="Failed"><i class="zt-donut-dot is-failed"></i><span>Failed</span><strong>' + cover.failed + "</strong><em>" + (failedPct == null ? "—" : failedPct + "%") + "</em></button>" +
            '<button type="button" class="zt-donut-pill" data-risk="all" data-status="Investigate"><i class="zt-donut-dot is-investigate"></i><span>Investigate</span><strong>' + cover.investigate + "</strong><em>" + (investPct == null ? "—" : investPct + "%") + "</em></button>" +
            "</div></article></section>";

        html += '<div class="zt-pillar-cards">' + pillars.map(function (p) {
            return '<a class="zt-pillar-card" href="' + esc(investigationUrl(p.key)) + '">' +
                "<h3>" + esc(p.name) + "</h3>" +
                '<div class="zt-pillar-count"><strong>' + (p.passRate == null ? "—" : p.passRate + "%") + "</strong></div>" +
                '<p class="zt-muted">' + p.passed + " passed · " + p.failed + " failed · " + p.high + " high</p>" +
                '<span class="zt-pillar-track"><span class="zt-pillar-fill is-' + scoreTone(p.passRate) + '" style="width:' + (p.passRate || 0) + '%"></span></span></a>';
        }).join("") + "</div>";

        html += pillarRiskChart(heat);

        var ranked = sortTests(tests);
        var top = ranked.slice(0, OVERVIEW_FINDINGS);
        html += '<div class="zt-grid-2 zt-health-findings">' +
            collectorHealthCard(a) +
            '<section class="zt-card" id="ztFindings"><div class="zt-findings-head"><h2>Top findings</h2></div>' +
            tableFor(top, tests.length, "controls", { limit: OVERVIEW_FINDINGS, totalFiltered: ranked.length }) + "</section></div>";
        return html;
    }

    var PILLAR_METRIC_FIELDS = {
        identity: [
            { key: "mfaRegistered", label: "MFA registered" },
            { key: "passwordless", label: "Passwordless" },
            { key: "caEnabled", label: "CA enabled" },
            { key: "mfaPolicies", label: "MFA policies" },
            { key: "privilegedMembers", label: "Privileged members" },
            { key: "pimEligible", label: "PIM eligible" },
            { key: "highRiskUsers", label: "High-risk users" },
            { key: "accessReviews", label: "Access reviews" }
        ],
        devices: [
            { key: "managedDevices", label: "Endpoint Managed devices" },
            { key: "compliant", label: "Compliant" },
            { key: "encrypted", label: "Encrypted" },
            { key: "compliancePolicies", label: "Compliance policies" },
            { key: "entraDevices", label: "Endpoint Devices" }
        ],
        network: [
            { key: "nsgsAssociated", label: "NSGs associated" },
            { key: "subnetsWithoutNsg", label: "Subnets without NSG" },
            { key: "publicIps", label: "Public IPs attached" },
            { key: "openManagementRules", label: "Open management rules" },
            { key: "internetAllowRules", label: "Internet allow rules" },
            { key: "firewalls", label: "Azure Firewalls" },
            { key: "wafPolicies", label: "WAF policies" },
            { key: "privateEndpoints", label: "Private endpoints" }
        ],
        data: [
            { key: "sensitivityLabels", label: "Sensitivity labels" },
            { key: "dlpScopes", label: "DLP scopes" },
            { key: "retentionLabels", label: "Retention labels" },
            { key: "anonymousSharing", label: "Anonymous sharing" },
            { key: "directoryAudits", label: "Directory audits" }
        ],
        infrastructure: [
            { key: "resourceGroups", label: "Resource groups" },
            { key: "vms", label: "Trusted Launch VMs" },
            { key: "storageHttps", label: "Storage HTTPS" },
            { key: "storagePublic", label: "Public storage" },
            { key: "keyVaultPurge", label: "Key Vault purge protection" },
            { key: "defenderScore", label: "Defender secure score" },
            { key: "unhealthyAssessments", label: "Unhealthy assessments" },
            { key: "privilegedAssignments", label: "Privileged ARM assignments" }
        ]
    };

    function formatPillarMetric(item) {
        if (!item) return null;
        if (typeof item.value === "boolean") return item.value ? "Yes" : "No";
        if (item.total != null && item.value != null) {
            var p = pct(item.value, item.total);
            return metric(item.value) + " / " + metric(item.total) + (p == null ? "" : " · " + p + "%");
        }
        if (item.value != null) return metric(item.value);
        return null;
    }

    function kpiFilter(label, value, risk, status, ic) {
        return '<button type="button" class="zt-kpi" data-risk="' + esc(risk) + '" data-status="' + esc(status) + '">' +
            '<div class="zt-metric-head">' + icon(ic) + esc(label) + "</div>" +
            '<div class="zt-metric-value">' + esc(metric(value)) + "</div></button>";
    }

    function statusLegend(label, value, total, risk, status) {
        var p = pct(value, total);
        return '<button type="button" class="zt-legend-btn" data-risk="' + esc(risk) + '" data-status="' + esc(status) + '"><b>' + esc(label) + "</b><span class=\"zt-muted\">" + value + (p == null ? "" : " · " + p + "%") + "</span></button>";
    }

    function sevCard(label, value, total, risk) {
        var p = pct(value, total) || 0;
        var tone = label === "High" ? "high" : (label === "Medium" ? "medium" : "low");
        return '<button type="button" class="zt-sev-card is-' + tone + '" data-risk="' + esc(risk) + '" data-status="Failed">' +
            '<span class="zt-sev-card-label">' + esc(label) + "</span>" +
            '<span class="zt-sev-card-count">' + value + "</span>" +
            '<span class="zt-sev-card-hint">Failed controls</span>' +
            '<span class="zt-sev-card-track"><span class="zt-sev-card-fill" style="width:' + p + '%"></span></span></button>';
    }

    function heatCell(area, risk, value) {
        var level = !value ? "none" : (value >= 4 ? "hot" : (value >= 2 ? "warm" : "cool"));
        return '<td><a class="zt-heat-cell is-' + level + '" href="' + esc(investigationUrl(area, risk)) + '">' + value + "</a></td>";
    }

    function authCoverageCard(userAuth, privileged) {
        if (!userAuth && !privileged) {
            return '<section class="zt-card zt-viz-card"><h3>Authentication coverage</h3><div class="zt-viz-empty"><div><strong>Visualization unavailable</strong><p>Authentication telemetry was not returned.</p></div></div></section>';
        }
        var body = "";
        if (userAuth) {
            var den = userAuth.sampled;
            body += progressRow("MFA registered", userAuth.mfaRegistered, den, "strong");
            body += progressRow("SSPR registered", userAuth.ssprRegistered, den, "info");
            body += progressRow("Passwordless", userAuth.passwordless, den, "info");
            body += '<p class="zt-muted">Sampled users: ' + metric(den) + "</p>";
        }
        if (privileged) {
            var methods = privileged.enabledMethods || [];
            body += '<p class="zt-muted">Enabled methods: ' + metric(privileged.enabledMethodCount) + " of " + metric(privileged.methodCount) + "</p>";
            if (methods.length) {
                body += '<div class="zt-chips">' + methods.map(function (m) {
                    return '<span class="zt-chip">' + esc(m) + "</span>";
                }).join("") + "</div>";
            }
        }
        return '<section class="zt-card zt-viz-card"><h3>Authentication coverage</h3>' + body + "</section>";
    }

    function caCoverageCard(ca) {
        if (!ca) {
            return '<section class="zt-card zt-viz-card"><h3>Conditional Access</h3><div class="zt-viz-empty"><div><strong>Visualization unavailable</strong><p>Conditional Access telemetry was not returned.</p></div></div></section>';
        }
        var den = ca.policies;
        return '<section class="zt-card zt-viz-card"><h3>Conditional Access</h3>' +
            progressRow("Enabled policies", ca.enabled, den, "strong") +
            progressRow("MFA policies", ca.mfaPolicies, den, "info") +
            '<p class="zt-muted">All users MFA: ' + metric(ca.allUsersMfa) + " · Legacy block: " + metric(ca.legacyBlock) + "</p></section>";
    }

    function deviceSignInCard(sign) {
        if (!sign) {
            return '<section class="zt-card zt-viz-card"><h3>Device sign-in state</h3><div class="zt-viz-empty"><div><strong>Visualization unavailable</strong><p>Sign-in telemetry was not returned.</p></div></div></section>';
        }
        var outcomeDen = (sign.success || 0) + (sign.failure || 0);
        return '<section class="zt-card zt-viz-card"><h3>Device sign-in state</h3>' +
            '<div class="zt-donut-wrap">' +
            '<canvas id="ztSignInDonut" width="132" height="132" data-success="' + (sign.success || 0) + '" data-failure="' + (sign.failure || 0) + '" role="img" aria-label="Sign-in outcomes. Success ' + (sign.success || 0) + ", failure " + (sign.failure || 0) + '."></canvas>' +
            "<div>" +
            '<p class="zt-muted">Sampled: ' + metric(sign.sampled) + "</p>" +
            '<p>Success ' + metric(sign.success) + (outcomeDen ? " · " + (pct(sign.success, outcomeDen) || 0) + "%" : "") + "</p>" +
            "<p>Failure " + metric(sign.failure) + (outcomeDen ? " · " + (pct(sign.failure, outcomeDen) || 0) + "%" : "") + "</p>" +
            '<p class="zt-muted">CA success: ' + metric(sign.conditionalAccessSuccess) + " · Managed device: " + metric(sign.managedDevice) + "</p>" +
            "</div></div></section>";
    }

    function healthInfoButton(title, message) {
        return '<button type="button" class="zt-info-btn zt-health-info" aria-label="Why ' + esc(title) + ' is partial" aria-expanded="false">' +
            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 8h.01"/><path d="M11 12h1v4h1"/></svg>' +
            '<span class="zt-info-tip" role="tooltip"><p>' + esc(title) + "</p><p>" + esc(message) + "</p></span></button>";
    }

    function collectorHealthCard(a) {
        var partial = a.partial || [];
        var rows;
        if (!partial.length) {
            rows = '<p class="zt-muted">No collector failures were reported for this assessment.</p>';
        } else {
            rows = '<table class="zt-health"><thead><tr><th>Source</th><th>Status</th></tr></thead><tbody>' +
                partial.map(function (p) {
                    return "<tr><td>" + esc(p.domain) + '</td><td><span class="zt-health-status"><span class="zt-health-pill">Partial</span>' +
                        healthInfoButton(p.domain, p.message || "unavailable") + "</span></td></tr>";
                }).join("") + "</tbody></table>";
        }
        return '<section class="zt-card zt-health-card"><h2>Assessment data health</h2>' + rows + "</section>";
    }

    function renderGaps(items) {
        if (!items.length) return '<p class="zt-muted">No failed or investigate controls requiring ranked remediation.</p>';
        return '<ol class="zt-gaps">' + items.slice(0, 8).map(function (t) {
            return '<li><button type="button" data-open="' + esc(t.id) + '"><strong>' + esc(t.id) + "</strong> " + esc(t.name) +
                '<span class="zt-muted"> ' + esc(t.area) + "</span> " + riskBadge(t.risk) + " " + statusBadge(t.status) + "</button></li>";
        }).join("") + "</ol>";
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
        if (filterAreaSection) filterAreaSection.hidden = true;
        if (filterPlatformSection) filterPlatformSection.hidden = !(devices || draft.area === "Devices");
        if (filterScopeSection) filterScopeSection.hidden = !(devices || draft.area === "Devices");
    }

    function placePop(pop, anchor) {
        if (!pop || !anchor) return;
        var rect = anchor.getBoundingClientRect();
        var popRect = pop.getBoundingClientRect();
        var left = Math.min(Math.max(12, rect.left), window.innerWidth - popRect.width - 12);
        var top = rect.bottom + 8;
        if (top + popRect.height > window.innerHeight - 12) {
            top = Math.max(12, rect.top - popRect.height - 8);
        }
        pop.style.left = left + "px";
        pop.style.top = top + "px";
    }

    function closeTenantPop() {
        if (tenantPop) tenantPop.hidden = true;
        if (tenantBtn) tenantBtn.setAttribute("aria-expanded", "false");
    }

    function closeAssessPop() {
        if (assessPop) assessPop.hidden = true;
        if (assessBtn) assessBtn.setAttribute("aria-expanded", "false");
    }

    function tenantValue(value) {
        return value == null || value === "" ? "Unavailable" : String(value);
    }

    function openTenantPop(anchor) {
        if (!tenantPop) return;
        var a = state.assessment || {};
        var t = a.tenant || {};
        var rows = [
            ["Tenant name", tenantValue(t.tenantName)],
            ["Tenant ID", tenantValue(state.isAdmin ? t.tenantId : maskTenant(t.tenantId))],
            ["Cloud provider name", "Azure"],
            ["Host name", tenantValue(t.hostName || t.hostname || t.primaryDomain)],
            ["Domain", tenantValue(t.primaryDomain)]
        ];
        tenantPop.innerHTML =
            '<div class="rep-device-pop-head">' +
            '<span class="rep-device-pop-name">' +
            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M3 21h18"/><path d="M5 21V8l7-4 7 4v13"/><path d="M9 21v-8h6v8"/><path d="M9 9h.01M15 9h.01M9 13h.01M15 13h.01"/></svg>' +
            "Tenant Info</span>" +
            '<button type="button" class="rep-device-pop-close" aria-label="Close">' +
            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M18 6L6 18M6 6l12 12"/></svg>' +
            "</button></div>" +
            rows.map(function (row) {
                return '<div class="rep-device-pop-row"><span>' + esc(row[0]) + "</span><span>" + esc(row[1]) + "</span></div>";
            }).join("");
        tenantPop.hidden = false;
        if (tenantBtn) tenantBtn.setAttribute("aria-expanded", "true");
        placePop(tenantPop, anchor || tenantBtn);
        var closeBtn = tenantPop.querySelector(".rep-device-pop-close");
        if (closeBtn) closeBtn.addEventListener("click", closeTenantPop);
    }

    function openAssessPop(anchor) {
        if (!assessPop) return;
        var a = state.assessment || {};
        var rows = [
            ["Assessment ID", tenantValue(a.assessmentId || state.assessmentId)],
            ["Assessment date", tenantValue(formatTime(a.completedAt || a.startedAt))]
        ];
        assessPop.innerHTML =
            '<div class="rep-device-pop-head">' +
            '<span class="rep-device-pop-name">' +
            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M8 3h8a2 2 0 012 2v16l-6-3-6 3V5a2 2 0 012-2z"/><path d="M9 8h6M9 12h6"/></svg>' +
            "Assessment details</span>" +
            '<button type="button" class="rep-device-pop-close" aria-label="Close">' +
            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M18 6L6 18M6 6l12 12"/></svg>' +
            "</button></div>" +
            rows.map(function (row) {
                return '<div class="rep-device-pop-row"><span>' + esc(row[0]) + "</span><span>" + esc(row[1]) + "</span></div>";
            }).join("");
        assessPop.hidden = false;
        if (assessBtn) assessBtn.setAttribute("aria-expanded", "true");
        placePop(assessPop, anchor || assessBtn);
        var closeBtn = assessPop.querySelector(".rep-device-pop-close");
        if (closeBtn) closeBtn.addEventListener("click", closeAssessPop);
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
        if (state.view === "overview") return;
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
        var high = items.filter(function (t) { return t.risk === "High"; }).length;
        var medium = items.filter(function (t) { return t.risk === "Medium"; }).length;
        var low = items.filter(function (t) { return t.risk === "Low"; }).length;
        return '<div class="zt-remed-head"><span>High ' + high + "</span><span>Medium " + medium + "</span><span>Low " + low + "</span><span>Open " + items.length + "</span></div>" +
            '<div class="zt-remed-list">' + items.map(function (t) {
                var rec = t.recommendation || "No remediation summary returned.";
                if (rec.length > 140) rec = rec.slice(0, 139) + "…";
                var pillar = t.area || "";
                return '<article class="zt-remed-row">' +
                    '<div><strong>' + esc(t.id) + "</strong> " + esc(t.name) +
                    '<div class="zt-muted">' + esc(pillar) + " · " + esc(rec) + "</div></div>" +
                    "<div>" + riskBadge(t.risk) + " " + statusBadge(t.status) +
                    ' <button class="btn btn-ghost" type="button" data-open="' + esc(t.id) + '">View details</button></div></article>';
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

    function tableFor(filtered, allCount, caption, opts) {
        opts = opts || {};
        var limit = opts.limit || PAGE_SIZE;
        var start = opts.limit ? 0 : (state.page - 1) * PAGE_SIZE;
        var page = filtered.slice(start, start + limit);
        var filteredTotal = opts.totalFiltered != null ? opts.totalFiltered : filtered.length;
        var showing = opts.limit
            ? "Showing top " + page.length + " of " + filteredTotal + " matching " + caption
            : "Showing " + filtered.length + " of " + allCount + " " + caption;
        var showingHtml = state.view === "overview" ? '<p class="zt-muted">' + esc(showing) + "</p>" : "";
        if (!filtered.length) {
            return showingHtml + '<div class="zt-empty">No controls match the selected filters.</div>';
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
        var pages = opts.limit ? 1 : Math.ceil(filtered.length / PAGE_SIZE);
        var pager = pages > 1 ? '<div class="zt-chips" style="margin-top:10px">' + Array.from({ length: pages }, function (_, i) {
            var n = i + 1;
            return '<button type="button" class="btn btn-ghost' + (n === state.page ? " is-active" : "") + '" data-page="' + n + '">' + n + "</button>";
        }).join("") + "</div>" : "";
        var cards = '<div class="zt-mobile-cards">' + page.map(function (t) {
            return '<article class="zt-card"><strong>' + esc(t.name) + "</strong><div>" + riskBadge(t.risk) + " " + statusBadge(t.status) + '</div><p class="zt-muted">' + esc(t.category || "") + '</p><button class="btn btn-ghost" type="button" data-open="' + esc(t.id) + '">Details</button></article>';
        }).join("") + "</div>";
        return showingHtml + '<div class="zt-table-wrap"><table class="zt-table"><caption>' + esc(caption) + "</caption><thead><tr>" + head + "</tr></thead><tbody>" + rows.replace(/<td colspan="0" hidden><\/td>/g, "") + "</tbody></table></div>" + cards + pager;
    }

    function pillarTabs(title) {
        var overviewOn = state.pillarTab !== "assessment";
        return '<div class="zt-page-head"><div><h1>' + esc(title) + "</h1></div></div>" +
            '<div class="zt-pillar-tabs" role="tablist" aria-label="' + esc(title) + ' views">' +
            '<button type="button" role="tab" data-pillar-tab="overview" class="' + (overviewOn ? "is-active" : "") + '" aria-selected="' + (overviewOn ? "true" : "false") + '">Overview metrics</button>' +
            '<button type="button" role="tab" data-pillar-tab="assessment" class="' + (overviewOn ? "" : "is-active") + '" aria-selected="' + (overviewOn ? "false" : "true") + '">Assessment data</button>' +
            "</div>";
    }

    function metricValue(item) {
        if (!item) return null;
        if (item.value != null) return item.value;
        return null;
    }

    function identityInventoryCard(overview, tenant) {
        var inv = (overview && overview.inventory) || {};
        var users = metricValue(inv.users);
        var guests = metricValue(inv.guests);
        var groups = metricValue(inv.groups);
        var applications = metricValue(inv.applications);
        var sps = metricValue(inv.servicePrincipals);
        if (users == null && tenant) users = tenant.users;
        if (guests == null && tenant) guests = tenant.guests;
        if (groups == null && tenant) groups = tenant.groups;
        if (applications == null && tenant) applications = tenant.applications;
        if (sps == null && tenant) sps = tenant.servicePrincipals;
        if (users == null && guests == null && groups == null && applications == null && sps == null) {
            return '<section class="zt-inventory-card"><h2>Identity inventory</h2><p class="zt-muted">Identity inventory was not returned.</p></section>';
        }
        return '<section class="zt-inventory-card">' +
            "<h2>Identity inventory</h2>" +
            '<div class="zt-inv-metrics">' +
            inventoryStat("blue", "user", "Users", users) +
            inventoryStat("sky", "guests", "Guest users", guests) +
            inventoryStat("teal", "groups", "Groups", groups) +
            inventoryStat("mint", "apps", "Applications", applications) +
            inventoryStat("violet", "key", "Service principals", sps) +
            "</div></section>";
    }

    function privilegedAccessCard(overview) {
        var priv = (overview && overview.privileged) || {};
        var members = metricValue(priv.members);
        var roles = metricValue(priv.roles);
        var eligible = metricValue(priv.pimEligible);
        var active = metricValue(priv.pimActive);
        if (members == null && roles == null && eligible == null && active == null) {
            return '<section class="zt-inventory-card"><h2>Privileged access / PIM</h2><p class="zt-muted">Privileged access telemetry was not returned.</p></section>';
        }
        return '<section class="zt-inventory-card">' +
            "<h2>Privileged access / PIM</h2>" +
            '<div class="zt-inv-metrics">' +
            inventoryStat("purple", "shield", "Privileged members", members) +
            inventoryStat("violet", "lock", "Privileged roles", roles) +
            inventoryStat("teal", "users", "PIM eligible assignments", eligible) +
            inventoryStat("mint", "pass", "PIM active assignments", active) +
            "</div></section>";
    }

    function credentialHealthCard(overview) {
        var creds = (overview && overview.credentials) || {};
        var assessed = metricValue(creds.applicationsAssessed);
        var expired = metricValue(creds.expiredCredentials);
        var expiring = metricValue(creds.expiring30d);
        var secrets = metricValue(creds.secrets);
        var certs = metricValue(creds.certificates);
        if (assessed == null && expired == null && expiring == null && secrets == null && certs == null) {
            return '<section class="zt-inventory-card"><h2>Application identity and credential hygiene</h2><p class="zt-muted">Application credential telemetry was not returned.</p></section>';
        }
        var tone = "healthy";
        var label = "Healthy";
        if ((expired || 0) > 0) {
            tone = "expired";
            label = "Expired credentials";
        } else if ((expiring || 0) > 0) {
            tone = "expiring";
            label = "Expiring soon";
        }
        return '<section class="zt-inventory-card zt-cred-card">' +
            "<h2>Application identity and credential hygiene</h2>" +
            '<div class="zt-cred-health is-' + tone + '">' +
            '<span class="zt-cred-dot" aria-hidden="true"></span>' +
            "<strong>" + esc(label) + "</strong>" +
            '<span>Expiring ≤30 days: ' + esc(compactNumber(expiring)) + "</span>" +
            "<span>Expired credentials: " + esc(compactNumber(expired)) + "</span>" +
            "</div>" +
            '<div class="zt-inv-metrics">' +
            inventoryStat("mint", "apps", "Applications assessed", assessed) +
            inventoryStat("sky", "clock", "Expiring within 30 days", expiring) +
            inventoryStat("purple", "fail", "Expired credentials", expired) +
            inventoryStat("teal", "key", "Secrets", secrets) +
            inventoryStat("violet", "cert", "Certificates", certs) +
            "</div></section>";
    }

    function identityOverviewSections(a) {
        var viz = (a && a.visualizations) || {};
        var overview = viz.identityOverview || {};
        return '<div class="zt-id-overview">' +
            '<div class="zt-id-overview-row">' +
            withOverviewSection("identity-inventory", identityInventoryCard(overview, a.tenant || {})) +
            withOverviewSection("identity-privileged", privilegedAccessCard(overview)) +
            "</div>" +
            withOverviewSection("identity-credentials", credentialHealthCard(overview)) +
            "</div>";
    }

    function formatOverviewValue(item) {
        if (!item || item.value == null) return null;
        if (typeof item.value === "boolean") return item.value ? "Yes" : "No";
        if (item.total != null) {
            var p = pct(item.value, item.total);
            return compactNumber(item.value) + " / " + compactNumber(item.total) + (p == null ? "" : " · " + p + "%");
        }
        return compactNumber(item.value);
    }

    function overviewStat(tone, ic, label, item) {
        var shown = formatOverviewValue(item);
        if (shown == null) return "";
        return '<article class="zt-inv-tile is-' + tone + '">' +
            '<span class="zt-inv-icon zt-tone-' + tone + '">' + icon(ic) + "</span>" +
            '<span class="zt-inv-label">' + esc(label) + "</span>" +
            "<strong>" + esc(shown) + "</strong></article>";
    }

    function overviewCard(title, tilesHtml, emptyMsg) {
        if (!tilesHtml) {
            return '<section class="zt-inventory-card"><h2>' + esc(title) + '</h2><p class="zt-muted">' + esc(emptyMsg) + "</p></section>";
        }
        return '<section class="zt-inventory-card">' +
            "<h2>" + esc(title) + "</h2>" +
            '<div class="zt-inv-metrics">' + tilesHtml + "</div></section>";
    }

    function overviewHealth(tone, label, lines) {
        return '<div class="zt-cred-health is-' + tone + '">' +
            '<span class="zt-cred-dot" aria-hidden="true"></span>' +
            "<strong>" + esc(label) + "</strong>" +
            lines.join("") +
            "</div>";
    }

    function networkInventoryCard(overview) {
        var inv = (overview && overview.inventory) || {};
        var tiles = overviewStat("blue", "shield", "NSGs associated", inv.nsgsAssociated) +
            overviewStat("sky", "building", "Subnets without NSG", inv.subnetsWithoutNsg) +
            overviewStat("teal", "laptop", "Public IPs attached", inv.publicIps) +
            overviewStat("violet", "lock", "Private endpoints", inv.privateEndpoints);
        return overviewCard("Network inventory", tiles, "Network inventory was not returned.");
    }

    function networkPerimeterCard(overview) {
        var per = (overview && overview.perimeter) || {};
        var tiles = overviewStat("purple", "shield", "Azure Firewalls", per.firewalls) +
            overviewStat("mint", "pass", "WAF policies", per.wafPolicies);
        return overviewCard("Perimeter controls", tiles, "Perimeter telemetry was not returned.");
    }

    function networkExposureCard(overview) {
        var exp = (overview && overview.exposure) || {};
        var open = metricValue(exp.openManagementRules);
        var internet = metricValue(exp.internetAllowRules);
        var tiles = overviewStat("purple", "fail", "Open management rules", exp.openManagementRules) +
            overviewStat("sky", "warn", "Internet allow rules", exp.internetAllowRules);
        if (!tiles) {
            return overviewCard("Internet exposure", "", "Internet exposure telemetry was not returned.");
        }
        var tone = "healthy";
        var label = "No open internet management";
        if ((open || 0) > 0) {
            tone = "expired";
            label = "Open management paths";
        } else if ((internet || 0) > 0) {
            tone = "expiring";
            label = "Internet allow rules";
        }
        return '<section class="zt-inventory-card zt-cred-card">' +
            "<h2>Internet exposure</h2>" +
            overviewHealth(tone, label, [
                "<span>Open management rules: " + esc(compactNumber(open)) + "</span>",
                "<span>Internet allow rules: " + esc(compactNumber(internet)) + "</span>"
            ]) +
            '<div class="zt-inv-metrics">' + tiles + "</div></section>";
    }

    function networkTopologyCard(overview) {
        var top = (overview && overview.topology) || {};
        var tiles = overviewStat("blue", "building", "Virtual networks", top.vnets) +
            overviewStat("sky", "shield", "Subnets", top.subnets) +
            overviewStat("teal", "laptop", "Network interfaces", top.nics) +
            overviewStat("violet", "lock", "Peerings", top.peerings) +
            overviewStat("mint", "pass", "Route tables", top.routeTables) +
            overviewStat("purple", "search", "Associated route tables", top.associatedRouteTables) +
            overviewStat("sky", "apps", "Load balancers", top.loadBalancers) +
            overviewStat("teal", "clock", "Network Watchers", top.networkWatchers);
        return extraOverviewCard("Segmentation and topology", tiles);
    }

    function networkAddressingCard(overview) {
        var addr = (overview && overview.addressing) || {};
        var tiles = overviewStat("blue", "laptop", "Public IPs", addr.publicIps) +
            overviewStat("teal", "lock", "Public IPs attached", addr.publicIpsAttached);
        return extraOverviewCard("Addressing", tiles);
    }

    function networkPerimeterDetailCard(overview) {
        var per = (overview && overview.perimeterDetail) || {};
        var tiles = overviewStat("purple", "shield", "Firewall policies", per.firewallPolicies) +
            overviewStat("mint", "pass", "Firewalls with policy", per.firewallsWithPolicy) +
            overviewStat("violet", "lock", "Premium firewalls", per.premiumFirewalls) +
            overviewStat("sky", "warn", "Threat intelligence", per.threatIntel) +
            overviewStat("blue", "apps", "Application Gateways", per.applicationGateways) +
            overviewStat("teal", "shield", "Gateway WAF enabled", per.applicationGatewayWaf) +
            overviewStat("mint", "pass", "WAF prevention", per.wafPrevention) +
            overviewStat("purple", "lock", "WAF associated", per.wafAssociated) +
            overviewStat("sky", "building", "Front Door profiles", per.frontDoorProfiles) +
            overviewStat("violet", "fail", "DDoS plans", per.ddosPlans) +
            overviewStat("teal", "shield", "DDoS-protected VNets", per.ddosProtectedVnets);
        return extraOverviewCard("Perimeter detail", tiles);
    }

    function networkRemoteAccessCard(overview) {
        var remote = (overview && overview.remoteAccess) || {};
        var tiles = overviewStat("blue", "lock", "VPN gateways", remote.vpnGateways) +
            overviewStat("mint", "shield", "Bastion hosts", remote.bastions) +
            overviewStat("violet", "building", "ExpressRoute circuits", remote.expressRoute);
        return extraOverviewCard("Remote access", tiles);
    }

    function networkPaasCard(overview) {
        var paas = (overview && overview.paasExposure) || {};
        var tiles = overviewStat("violet", "lock", "Private endpoints", paas.privateEndpoints) +
            overviewStat("purple", "warn", "Publicly accessible PaaS", paas.paasPublic) +
            overviewStat("mint", "pass", "Restricted PaaS", paas.paasRestricted) +
            overviewStat("teal", "apps", "Storage accounts", paas.storageAccounts) +
            overviewStat("sky", "key", "Key Vaults", paas.keyVaults) +
            overviewStat("blue", "building", "SQL servers", paas.sqlServers);
        return extraOverviewCard("Private access and PaaS exposure", tiles);
    }

    function networkOverviewSections(a) {
        var viz = (a && a.visualizations) || {};
        var overview = viz.networkOverview || {};
        return '<div class="zt-id-overview">' +
            '<div class="zt-id-overview-row">' +
            withOverviewSection("network-inventory", networkInventoryCard(overview)) +
            withOverviewSection("network-perimeter", networkPerimeterCard(overview)) +
            "</div>" +
            withOverviewSection("network-exposure", networkExposureCard(overview)) +
            overviewPair(withOverviewSection("network-topology", networkTopologyCard(overview)), withOverviewSection("network-addressing", networkAddressingCard(overview))) +
            overviewPair(withOverviewSection("network-perimeter-detail", networkPerimeterDetailCard(overview)), withOverviewSection("network-remote", networkRemoteAccessCard(overview))) +
            withOverviewSection("network-paas", networkPaasCard(overview)) +
            "</div>";
    }

    function devicesInventoryCard(overview) {
        var inv = (overview && overview.inventory) || {};
        var tiles = overviewStat("blue", "devices", "Intune managed devices", inv.managedDevices) +
            overviewStat("sky", "laptop", "Entra devices", inv.entraDevices);
        return extraOverviewCard("Device inventory", tiles);
    }

    function devicesComplianceCard(overview) {
        var comp = (overview && overview.compliance) || {};
        var tiles = overviewStat("mint", "pass", "Compliant devices", comp.compliant) +
            overviewStat("violet", "warn", "Unknown compliance", comp.unknownCompliance);
        return extraOverviewCard("Device compliance", tiles);
    }

    function devicesEncryptionCard(overview) {
        var enc = (overview && overview.encryption) || {};
        var tiles = overviewStat("teal", "lock", "Encrypted devices", enc.encrypted);
        return extraOverviewCard("Encryption", tiles);
    }

    function devicesOwnershipCard(overview) {
        var own = (overview && overview.ownership) || {};
        var tiles = overviewStat("blue", "building", "Company owned", own.companyOwned) +
            overviewStat("sky", "users", "Personal owned", own.personalOwned) +
            overviewStat("violet", "search", "Unknown owner", own.unknownOwner);
        return extraOverviewCard("Ownership", tiles);
    }

    function devicesPoliciesCard(overview) {
        var pol = (overview && overview.policies) || {};
        var tiles = overviewStat("mint", "shield", "Compliance policies", pol.policies) +
            overviewStat("teal", "pass", "Assigned policies", pol.assigned) +
            overviewStat("violet", "warn", "Unassigned policies", pol.unassigned) +
            overviewStat("blue", "clock", "Minimum OS", pol.minOs) +
            overviewStat("sky", "lock", "Encryption required", pol.encryption) +
            overviewStat("purple", "shield", "Firewall required", pol.firewall) +
            overviewStat("mint", "pass", "Secure Boot required", pol.secureBoot) +
            overviewStat("teal", "key", "TPM required", pol.tpm);
        return extraOverviewCard("Compliance policies", tiles);
    }

    function devicesEnrollmentCard(overview) {
        var enr = (overview && overview.enrollment) || {};
        var tiles = overviewStat("blue", "apps", "Enrollment configurations", enr.configurations) +
            overviewStat("violet", "lock", "Restriction configs", enr.restrictions) +
            overviewStat("sky", "shield", "Platform restrictions", enr.platformRestrictions);
        return extraOverviewCard("Enrollment", tiles);
    }

    function devicesEntraCard(overview) {
        var entra = (overview && overview.entra) || {};
        var tiles = overviewStat("mint", "devices", "Entra managed", entra.managed) +
            overviewStat("teal", "pass", "Entra compliant", entra.compliant);
        return extraOverviewCard("Entra device state", tiles);
    }

    function devicesOverviewSections(a) {
        var viz = (a && a.visualizations) || {};
        var overview = viz.devicesOverview || {};
        var html = overviewPair(withOverviewSection("devices-inventory", devicesInventoryCard(overview)), withOverviewSection("devices-compliance", devicesComplianceCard(overview))) +
            overviewPair(withOverviewSection("devices-encryption", devicesEncryptionCard(overview)), withOverviewSection("devices-ownership", devicesOwnershipCard(overview))) +
            overviewPair(withOverviewSection("devices-policies", devicesPoliciesCard(overview)), withOverviewSection("devices-enrollment", devicesEnrollmentCard(overview))) +
            withOverviewSection("devices-entra", devicesEntraCard(overview));
        if (!html) {
            return '<section class="zt-card"><h2>Overview metrics</h2><p class="zt-muted">No telemetry was returned for this pillar.</p></section>';
        }
        return '<div class="zt-id-overview">' + html + "</div>";
    }

    function dataProtectionCard(overview) {
        var ip = (overview && overview.informationProtection) || {};
        var tiles = overviewStat("violet", "lock", "Sensitivity labels", ip.labels) +
            overviewStat("mint", "shield", "Encrypted labels", ip.encrypted) +
            overviewStat("teal", "pass", "Content marking", ip.contentMarking) +
            overviewStat("sky", "search", "Auto-labeling", ip.autoLabel);
        return extraOverviewCard("Information protection", tiles);
    }

    function dataDlpCard(overview) {
        var dlp = (overview && overview.dlp) || {};
        var tiles = overviewStat("mint", "shield", "DLP scopes", dlp.scopes) +
            overviewStat("blue", "building", "Protected locations", dlp.locations);
        return extraOverviewCard("Data loss prevention", tiles);
    }

    function dataSharingCard(overview) {
        var sharing = (overview && overview.sharing) || {};
        var tiles = overviewStat("purple", "warn", "Anonymous sharing", sharing.anonymousSharing) +
            overviewStat("sky", "users", "External resharing", sharing.resharing) +
            overviewStat("teal", "lock", "Legacy auth blocked", sharing.legacyAuthBlocked);
        return extraOverviewCard("Sharing and collaboration", tiles);
    }

    function dataRetentionCard(overview) {
        var ret = (overview && overview.retention) || {};
        var tiles = overviewStat("blue", "clock", "Retention labels", ret.labels) +
            overviewStat("mint", "pass", "Published labels", ret.published);
        return extraOverviewCard("Retention and records", tiles);
    }

    function dataAuditCard(overview) {
        var audit = (overview && overview.audit) || {};
        var tiles = overviewStat("teal", "search", "Directory audit records", audit.directoryAudits) +
            overviewStat("mint", "pass", "Successful audit events", audit.success);
        return extraOverviewCard("Audit and visibility", tiles);
    }

    function dataOverviewSections(a) {
        var viz = (a && a.visualizations) || {};
        var overview = viz.dataOverview || {};
        var html = overviewPair(withOverviewSection("data-protection", dataProtectionCard(overview)), withOverviewSection("data-dlp", dataDlpCard(overview))) +
            overviewPair(withOverviewSection("data-sharing", dataSharingCard(overview)), withOverviewSection("data-retention", dataRetentionCard(overview))) +
            withOverviewSection("data-audit", dataAuditCard(overview));
        if (!html) {
            return '<section class="zt-card"><h2>Overview metrics</h2><p class="zt-muted">No telemetry was returned for this pillar.</p></section>';
        }
        return '<div class="zt-id-overview">' + html + "</div>";
    }

    function infrastructureInventoryCard(overview) {
        var inv = (overview && overview.inventory) || {};
        var tiles = overviewStat("blue", "building", "Resource groups", inv.resourceGroups) +
            overviewStat("sky", "devices", "Trusted Launch VMs", inv.vms) +
            overviewStat("teal", "lock", "Storage HTTPS", inv.storageHttps) +
            overviewStat("violet", "warn", "Public storage", inv.storagePublic);
        return overviewCard("Infrastructure inventory", tiles, "Infrastructure inventory was not returned.");
    }

    function infrastructurePrivilegedCard(overview) {
        var priv = (overview && overview.privileged) || {};
        var tiles = overviewStat("purple", "key", "Key Vault purge protection", priv.keyVaultPurge) +
            overviewStat("mint", "users", "Privileged ARM assignments", priv.privilegedAssignments);
        return overviewCard("Privileged access", tiles, "Privileged access telemetry was not returned.");
    }

    function infrastructureDefenderCard(overview) {
        var defn = (overview && overview.defender) || {};
        var score = metricValue(defn.defenderScore);
        var unhealthy = metricValue(defn.unhealthyAssessments);
        var tiles = overviewStat("mint", "shield", "Defender secure score", defn.defenderScore) +
            overviewStat("purple", "fail", "Unhealthy assessments", defn.unhealthyAssessments);
        if (!tiles) {
            return overviewCard("Defender for Cloud", "", "Defender telemetry was not returned.");
        }
        var tone = "healthy";
        var label = "Healthy";
        if ((unhealthy || 0) > 0) {
            tone = "expired";
            label = "Unhealthy assessments";
        }
        return '<section class="zt-inventory-card zt-cred-card">' +
            "<h2>Defender for Cloud</h2>" +
            overviewHealth(tone, label, [
                "<span>Secure score: " + esc(compactNumber(score)) + "</span>",
                "<span>Unhealthy assessments: " + esc(compactNumber(unhealthy)) + "</span>"
            ]) +
            '<div class="zt-inv-metrics">' + tiles + "</div></section>";
    }

    function extraOverviewCard(title, tiles) {
        if (!tiles) return "";
        return overviewCard(title, tiles, "");
    }

    function withOverviewSection(id, html) {
        if (!html) return "";
        return html.replace(
            /^(<section class="zt-inventory-card[^"]*")/,
            '$1 data-overview-section="' + esc(id) + '" role="button" tabindex="0"'
        );
    }

    function overviewPair(left, right) {
        if (!left && !right) return "";
        if (!right) return left;
        if (!left) return right;
        return '<div class="zt-id-overview-row">' + left + right + "</div>";
    }

    function infrastructureDefenderCoverageCard(overview) {
        var defn = (overview && overview.defender) || {};
        var tiles = overviewStat("mint", "pass", "Healthy assessments", defn.healthyAssessments) +
            overviewStat("blue", "search", "Assessments", defn.assessmentCount) +
            overviewStat("purple", "shield", "Standard plans", defn.defenderPlans);
        return extraOverviewCard("Defender coverage", tiles);
    }

    function infrastructureComputeCard(overview) {
        var compute = (overview && overview.compute) || {};
        var tiles = overviewStat("blue", "devices", "Virtual machines", compute.vms) +
            overviewStat("sky", "laptop", "VM scale sets", compute.vmss) +
            overviewStat("teal", "shield", "Trusted Launch", compute.trustedLaunch) +
            overviewStat("mint", "lock", "Encrypted OS disks", compute.encryptedOs) +
            overviewStat("violet", "key", "Compute managed identity", compute.computeIdentity) +
            overviewStat("purple", "apps", "App Services", compute.appServices) +
            overviewStat("sky", "apps", "Function Apps", compute.functionApps);
        return extraOverviewCard("Compute", tiles);
    }

    function infrastructureStorageCard(overview) {
        var storage = (overview && overview.storage) || {};
        var tiles = overviewStat("teal", "lock", "HTTPS required", storage.https) +
            overviewStat("violet", "warn", "Public network access", storage.public) +
            overviewStat("mint", "shield", "Blob public access disabled", storage.noPublicBlob) +
            overviewStat("blue", "key", "Storage managed identity", storage.identity);
        return extraOverviewCard("Storage", tiles);
    }

    function infrastructureExposureCard(overview) {
        var exp = (overview && overview.exposure) || {};
        var open = metricValue(exp.openManagementRules);
        var internet = metricValue(exp.internetAllowRules);
        var tiles = overviewStat("purple", "fail", "Open management rules", exp.openManagementRules) +
            overviewStat("sky", "warn", "Internet allow rules", exp.internetAllowRules) +
            overviewStat("teal", "laptop", "Public IPs attached", exp.publicIps) +
            overviewStat("violet", "lock", "Private endpoints", exp.privateEndpoints) +
            overviewStat("blue", "key", "Public Key Vaults", exp.keyVaultPublic) +
            overviewStat("mint", "shield", "Private AKS", exp.aksPrivate) +
            overviewStat("purple", "apps", "Private ACR", exp.acrPrivate);
        if (!tiles) return "";
        if (open == null && internet == null) {
            return extraOverviewCard("Network exposure", tiles);
        }
        var tone = "healthy";
        var label = "No open internet management";
        if ((open || 0) > 0) {
            tone = "expired";
            label = "Open management paths";
        } else if ((internet || 0) > 0) {
            tone = "expiring";
            label = "Internet allow rules";
        }
        return '<section class="zt-inventory-card zt-cred-card">' +
            "<h2>Network exposure</h2>" +
            overviewHealth(tone, label, [
                "<span>Open management rules: " + esc(compactNumber(open)) + "</span>",
                "<span>Internet allow rules: " + esc(compactNumber(internet)) + "</span>"
            ]) +
            '<div class="zt-inv-metrics">' + tiles + "</div></section>";
    }

    function infrastructureKeyVaultCard(overview) {
        var kv = (overview && overview.keyVault) || {};
        var tiles = overviewStat("violet", "key", "Key Vaults", kv.vaults) +
            overviewStat("mint", "lock", "RBAC authorization", kv.rbac) +
            overviewStat("purple", "shield", "Purge protection", kv.purge) +
            overviewStat("teal", "pass", "Soft-delete", kv.softDelete) +
            overviewStat("sky", "warn", "Public network enabled", kv.public);
        return extraOverviewCard("Key Vault", tiles);
    }

    function infrastructureRbacCard(overview) {
        var rbac = (overview && overview.rbac) || {};
        var tiles = overviewStat("purple", "users", "Role assignments", rbac.roleAssignments) +
            overviewStat("mint", "shield", "Privileged ARM assignments", rbac.privilegedAssignments) +
            overviewStat("sky", "warn", "Subscription admins", rbac.subscriptionAdmins) +
            overviewStat("teal", "key", "User-assigned identities", rbac.userAssignedIdentities);
        return extraOverviewCard("Privileged access detail", tiles);
    }

    function infrastructureGovernanceCard(overview) {
        var gov = (overview && overview.governance) || {};
        var tiles = overviewStat("blue", "building", "Policy assignments", gov.policyAssignments) +
            overviewStat("violet", "warn", "Policy exemptions", gov.policyExemptions) +
            overviewStat("teal", "pass", "Tagged resource groups", gov.taggedGroups);
        return extraOverviewCard("Governance", tiles);
    }

    function infrastructureMonitoringCard(overview) {
        var mon = (overview && overview.monitoring) || {};
        var tiles = overviewStat("mint", "search", "Log Analytics workspaces", mon.logAnalytics) +
            overviewStat("sky", "clock", "Subscription diagnostics", mon.diagnostics);
        return extraOverviewCard("Monitoring", tiles);
    }

    function infrastructureBackupCard(overview) {
        var backup = (overview && overview.backup) || {};
        var tiles = overviewStat("blue", "shield", "Recovery Services vaults", backup.recoveryVaults) +
            overviewStat("teal", "lock", "Backup vaults", backup.backupVaults);
        return extraOverviewCard("Backup", tiles);
    }

    function infrastructureOverviewSections(a) {
        var viz = (a && a.visualizations) || {};
        var overview = viz.infrastructureOverview || {};
        return '<div class="zt-id-overview">' +
            '<div class="zt-id-overview-row">' +
            withOverviewSection("infra-inventory", infrastructureInventoryCard(overview)) +
            withOverviewSection("infra-privileged", infrastructurePrivilegedCard(overview)) +
            "</div>" +
            withOverviewSection("infra-defender", infrastructureDefenderCard(overview)) +
            withOverviewSection("infra-defender-coverage", infrastructureDefenderCoverageCard(overview)) +
            overviewPair(withOverviewSection("infra-compute", infrastructureComputeCard(overview)), withOverviewSection("infra-storage", infrastructureStorageCard(overview))) +
            overviewPair(withOverviewSection("infra-exposure", infrastructureExposureCard(overview)), withOverviewSection("infra-keyvault", infrastructureKeyVaultCard(overview))) +
            overviewPair(withOverviewSection("infra-rbac", infrastructureRbacCard(overview)), withOverviewSection("infra-governance", infrastructureGovernanceCard(overview))) +
            overviewPair(withOverviewSection("infra-monitoring", infrastructureMonitoringCard(overview)), withOverviewSection("infra-backup", infrastructureBackupCard(overview))) +
            "</div>";
    }

    function pillarOverviewMetrics(view) {
        if (view === "identity") return identityOverviewSections(state.assessment);
        if (view === "network") return networkOverviewSections(state.assessment);
        if (view === "devices") return devicesOverviewSections(state.assessment);
        if (view === "data") return dataOverviewSections(state.assessment);
        if (view === "infrastructure") return infrastructureOverviewSections(state.assessment);
        var a = state.assessment;
        var viz = (a && a.visualizations) || {};
        var metrics = (viz.pillarMetrics && viz.pillarMetrics[view]) || {};
        var fields = PILLAR_METRIC_FIELDS[view] || [];
        var cards = "";
        fields.forEach(function (field) {
            var shown = formatPillarMetric(metrics[field.key]);
            if (shown == null) return;
            cards += '<article class="zt-card zt-metric"><div class="zt-metric-head">' + esc(field.label) + '</div><div class="zt-metric-value">' + esc(shown) + "</div></article>";
        });
        if (!cards) {
            return '<section class="zt-card"><h2>Overview metrics</h2><p class="zt-muted">No telemetry was returned for this pillar.</p></section>';
        }
        return '<div class="zt-grid">' + cards + "</div>";
    }

    function pillarOverviewVisuals(view) {
        var a = state.assessment;
        var viz = (a && a.visualizations) || {};
        if (view === "identity") {
            return '<div class="zt-viz-grid">' +
                authCoverageCard(viz.userAuthCoverage, viz.privilegedAuth) +
                caCoverageCard(viz.conditionalAccessCoverage) +
                deviceSignInCard(viz.deviceSignIn) +
                "</div>";
        }
        if (view === "devices") {
            return '<section class="zt-card"><h2>Device join and compliance flow</h2>' + (viz.deviceFlow
                ? '<p class="zt-muted">Device inventory flow is available.</p>'
                : '<div class="zt-viz-empty"><div><strong>Visualization unavailable</strong><p>The assessment returned configuration test results but did not return the telemetry required for this flow diagram.</p></div></div>') + "</section>";
        }
        return "";
    }

    function renderIdentity() {
        var a = state.assessment;
        if (!a) return emptyState("No assessment results are available.", "Run a Zero Trust assessment to populate this dashboard.");
        var tests = (a.identity && a.identity.tests) || [];
        var html = pillarTabs("Identity");
        if (state.pillarTab === "assessment") {
            html += tableFor(sortTests(applyFilters(tests)), tests.length, "identity tests");
            return html;
        }
        html += pillarOverviewMetrics("identity");
        html += pillarOverviewVisuals("identity");
        return html;
    }

    function renderDevices() {
        var a = state.assessment;
        if (!a) return emptyState("No assessment results are available.", "Run a Zero Trust assessment to populate this dashboard.");
        var tests = (a.devices && a.devices.tests) || [];
        var html = pillarTabs("Endpoint Device");
        if (state.pillarTab === "assessment") {
            var platforms = ["All", "Windows", "macOS", "iOS/iPadOS", "Android", "Tenant-wide"];
            html += '<div class="zt-platform-tabs" role="tablist">' + platforms.map(function (p) {
                var subset = p === "All" ? tests : tests.filter(function (t) { return (t.platform || "Tenant-wide") === p; });
                var failedHigh = subset.filter(function (t) { return t.status === "Failed" && t.risk === "High"; }).length;
                var passed = subset.filter(function (t) { return t.status === "Passed"; }).length;
                return '<button type="button" role="tab" data-platform="' + esc(p) + '" class="' + (state.filters.platform === p ? "is-active" : "") + '" aria-selected="' + (state.filters.platform === p ? "true" : "false") + '">' + esc(p) + " · " + subset.length + " / " + passed + " passed / " + failedHigh + " high-risk</button>";
            }).join("") + "</div>";
            html += tableFor(sortTests(applyFilters(tests)), tests.length, "device tests");
            return html;
        }
        html += pillarOverviewMetrics("devices");
        html += pillarOverviewVisuals("devices");
        return html;
    }

    var PILLAR_META = {
        network: {
            title: "Network",
            caption: "network tests"
        },
        data: {
            title: "Data",
            caption: "data tests"
        },
        infrastructure: {
            title: "Infrastructure",
            caption: "infrastructure tests"
        }
    };

    function renderPillar(view) {
        var a = state.assessment;
        if (!a) return emptyState("No assessment results are available.", "Run a Zero Trust assessment to populate this dashboard.");
        var meta = PILLAR_META[view] || { title: view, caption: "tests" };
        var bucket = pillarBucket(a, view);
        var tests = bucket.tests || [];
        var html = pillarTabs(meta.title);
        if (state.pillarTab === "assessment") {
            html += tableFor(sortTests(applyFilters(tests)), tests.length, meta.caption);
            return html;
        }
        html += pillarOverviewMetrics(view);
        html += pillarOverviewVisuals(view);
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
        if (state.view === "overview" || (state.view === "identity" && state.pillarTab !== "assessment")) paintOverviewCharts();
        if (filterBtn) filterBtn.classList.toggle("has-filters", hasActiveFilters());
    }

    function bindViewEvents() {
        viewEl.querySelectorAll("[data-open]").forEach(function (btn) {
            btn.addEventListener("click", function () { openDrawer(btn.getAttribute("data-open")); });
        });
        viewEl.querySelectorAll("[data-overview-section]").forEach(function (card) {
            card.addEventListener("click", function () {
                openOverviewSection(card.getAttribute("data-overview-section"));
            });
            card.addEventListener("keydown", function (ev) {
                if (ev.key === "Enter" || ev.key === " ") {
                    ev.preventDefault();
                    openOverviewSection(card.getAttribute("data-overview-section"));
                }
            });
        });
        viewEl.querySelectorAll(".zt-health-info").forEach(function (btn) {
            btn.addEventListener("click", function (ev) {
                ev.stopPropagation();
                var open = btn.classList.toggle("is-open");
                btn.setAttribute("aria-expanded", open ? "true" : "false");
                viewEl.querySelectorAll(".zt-health-info").forEach(function (other) {
                    if (other === btn) return;
                    other.classList.remove("is-open");
                    other.setAttribute("aria-expanded", "false");
                });
            });
        });
        viewEl.querySelectorAll("[data-page]").forEach(function (btn) {
            btn.addEventListener("click", function () { state.page = parseInt(btn.getAttribute("data-page"), 10) || 1; render(); });
        });
        viewEl.querySelectorAll("[data-risk]").forEach(function (btn) {
            btn.addEventListener("click", function () {
                setFindingFilter(
                    btn.getAttribute("data-area") || "all",
                    btn.getAttribute("data-risk") === "all" ? "all" : btn.getAttribute("data-risk"),
                    btn.getAttribute("data-status") || "all"
                );
            });
        });
        var clearFindings = document.getElementById("ztClearFindings");
        if (clearFindings) {
            clearFindings.addEventListener("click", function () {
                state.filters = defaultFilters();
                state.page = 1;
                render();
            });
        }
        viewEl.querySelectorAll("[data-view]").forEach(function (btn) {
            btn.addEventListener("click", function () {
                var view = btn.getAttribute("data-view");
                if (view) setView(view);
            });
        });
        viewEl.querySelectorAll("[data-pillar-tab]").forEach(function (btn) {
            btn.addEventListener("click", function () {
                state.pillarTab = btn.getAttribute("data-pillar-tab") || "overview";
                state.page = 1;
                render();
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

    function drawerFact(label, value, extraClass) {
        return '<article class="zt-dd-fact' + (extraClass ? " " + extraClass : "") + '"><span>' + esc(label) + "</span><strong>" + esc(value || "Unavailable") + "</strong></article>";
    }

    function azureLogo() {
        return '<svg class="zt-dd-azure" viewBox="0 0 18 18" aria-hidden="true"><path fill="#0078D4" d="M7.6 1.4L.8 16.6h4.8L16.9 1.4H7.6z"/><path fill="#50E6FF" d="M9.2 6.8L6.1 16.6h11.1L9.2 6.8z"/></svg>';
    }

    function subscriptionFact(tenant) {
        var name = tenant.subscriptionId || tenant.tenantName || tenant.primaryDomain || "Unavailable";
        return '<article class="zt-dd-fact zt-dd-fact-sub"><span>Subscription</span><strong>' + azureLogo() + "<span>" + esc(name) + "</span></strong></article>";
    }

    function sentences(text) {
        return String(text || "").split(/\.\s+/).map(function (part) {
            return part.replace(/\.$/, "").trim();
        }).filter(Boolean);
    }

    function controlSummary(test) {
        return test.controlSummary || test.whatWasChecked || test.description ||
            "This control checks whether the tenant meets the Zero Trust requirement described by this assessment.";
    }

    function whyItMatters(test) {
        return test.whyItMatters || test.whatWasChecked || test.description ||
            "This control reduces exposure in the assessed tenant.";
    }

    function passRequirement(test) {
        if (test.baseline) return test.baseline;
        if (test.passRequirement) return test.passRequirement;
        var parts = sentences(test.howToCheck).filter(function (part) {
            var lower = part.toLowerCase();
            return /should|must|at least|required/.test(lower);
        });
        if (parts.length) return parts.join(". ") + ".";
        if (test.whatWasChecked) return "This control passes when the tenant does not exhibit the exposure described for this check.";
        return "The tenant configuration must meet this control.";
    }

    function observedSummary(test) {
        if (test.error) return test.error.message || String(test.error);
        if (test.impact) return test.impact;
        if (test.description) return test.description;
        return "No observed configuration was returned for this control.";
    }

    function resultWhy(test) {
        var status = test.status || "Skipped";
        var observed = observedSummary(test);
        if (status === "Passed") return "This control passed because the collected configuration met the requirement to pass. " + observed;
        if (status === "Failed") return "This control failed because the collected configuration did not meet the requirement to pass. " + observed;
        if (status === "Investigate") return "This control needs investigation because a pass or fail could not be assigned from the collected configuration. " + observed;
        if (status === "Planned") return "This control is planned and was not scored as a live pass or fail. " + observed;
        if (status === "Skipped") return "This control was skipped because the data required to score it was not returned. " + observed;
        return "This control returned a " + status + " result. " + observed;
    }

    function pillarKey(area) {
        var token = String(area || "").toLowerCase();
        if (token.indexOf("device") >= 0) return "devices";
        if (token.indexOf("identity") >= 0) return "identity";
        if (token.indexOf("network") >= 0) return "network";
        if (token.indexOf("data") >= 0) return "data";
        if (token.indexOf("infra") >= 0) return "infrastructure";
        return token;
    }

    function kpiTile(tone, ic, label, value) {
        return '<article class="zt-dd-kpi is-' + tone + '">' +
            '<span class="zt-inv-icon zt-tone-' + tone + '">' + icon(ic) + "</span>" +
            '<span class="zt-inv-label">' + esc(label) + "</span>" +
            "<strong>" + esc(value) + "</strong></article>";
    }

    function pushKpi(items, label, metricItem, ic, tone) {
        var shown = formatPillarMetric(metricItem);
        if (shown == null) return;
        items.push(kpiTile(tone, ic, label, shown));
    }

    function controlKpis(test, assessment) {
        var viz = (assessment && assessment.visualizations) || {};
        var pillar = (viz.pillarMetrics && viz.pillarMetrics[pillarKey(test.area)]) || {};
        var identity = ((viz.identityOverview || {}).privileged) || {};
        var network = viz.networkOverview || {};
        var infra = viz.infrastructureOverview || {};
        var id = String(test.id || "").toUpperCase();
        var items = [];
        if (id.indexOf("ID06") >= 0 || id.indexOf("ID07") >= 0 || id.indexOf("PRIVILEGED") >= 0 || id.indexOf("LEAST") >= 0) {
            pushKpi(items, "Privileged members", identity.members || pillar.privilegedMembers, "users", "purple");
            pushKpi(items, "Privileged roles", identity.roles || pillar.privilegedRoles, "lock", "violet");
            pushKpi(items, "PIM eligible", identity.pimEligible || pillar.pimEligible, "users", "teal");
            pushKpi(items, "PIM active", identity.pimActive || pillar.pimActive, "pass", "mint");
        } else if (id.indexOf("ID02") >= 0 || id.indexOf("-MFA") >= 0) {
            pushKpi(items, "MFA registered", pillar.mfaRegistered, "shield", "mint");
            pushKpi(items, "MFA policies", pillar.mfaPolicies, "lock", "purple");
            pushKpi(items, "CA enabled", pillar.caEnabled, "pass", "teal");
        } else if (id.indexOf("ID03") >= 0 || id.indexOf("CONDITIONAL") >= 0) {
            pushKpi(items, "CA enabled", pillar.caEnabled, "pass", "teal");
            pushKpi(items, "MFA policies", pillar.mfaPolicies, "lock", "purple");
        } else if (id.indexOf("ID05") >= 0 || id.indexOf("STRONG") >= 0) {
            pushKpi(items, "Passwordless", pillar.passwordless, "key", "mint");
            pushKpi(items, "MFA registered", pillar.mfaRegistered, "shield", "teal");
        } else if (id.indexOf("ID08") >= 0 || id.indexOf("PROTECTION") >= 0) {
            pushKpi(items, "High-risk users", pillar.highRiskUsers, "warn", "purple");
        } else if (id.indexOf("ID11") >= 0 || id.indexOf("REVIEW") >= 0) {
            pushKpi(items, "Access reviews", pillar.accessReviews, "users", "teal");
        } else if (id.indexOf("DA0") >= 0 || pillarKey(test.area) === "devices") {
            pushKpi(items, "Managed devices", pillar.managedDevices, "devices", "blue");
            pushKpi(items, "Compliant", pillar.compliant, "pass", "mint");
            pushKpi(items, "Encrypted", pillar.encrypted, "lock", "teal");
        } else if (pillarKey(test.area) === "network") {
            pushKpi(items, "NSGs associated", (network.inventory || {}).nsgsAssociated || pillar.nsgsAssociated, "shield", "blue");
            pushKpi(items, "Open management rules", (network.exposure || {}).openManagementRules || pillar.openManagementRules, "fail", "purple");
            pushKpi(items, "Internet allow rules", (network.exposure || {}).internetAllowRules || pillar.internetAllowRules, "warn", "sky");
        } else if (pillarKey(test.area) === "infrastructure") {
            pushKpi(items, "Resource groups", (infra.inventory || {}).resourceGroups || pillar.resourceGroups, "building", "blue");
            pushKpi(items, "Unhealthy assessments", (infra.defender || {}).unhealthyAssessments || pillar.unhealthyAssessments, "fail", "purple");
            pushKpi(items, "Defender secure score", (infra.defender || {}).defenderScore || pillar.defenderScore, "shield", "mint");
        } else if (pillarKey(test.area) === "data") {
            pushKpi(items, "Sensitivity labels", pillar.sensitivityLabels, "lock", "violet");
            pushKpi(items, "DLP scopes", pillar.dlpScopes, "shield", "teal");
            pushKpi(items, "Anonymous sharing", pillar.anonymousSharing, "warn", "purple");
        }
        if (!items.length) {
            (test.evidenceTables || []).slice(0, 4).forEach(function (table) {
                if (!table) return;
                items.push(kpiTile("teal", "search", table.title, compactNumber(table.total || (table.rows || []).length)));
            });
        }
        return items;
    }

    function evidenceTabLabel(table) {
        var title = String((table && table.title) || "");
        if (/privileged directory role members/i.test(title)) return "Role members";
        if (/pim assignments/i.test(title)) return "PIM assignments";
        return title || "Evidence";
    }

    function evidenceSources(test) {
        var tables = (test.evidenceTables || []).filter(function (table) {
            return table && table.columns && table.rows && table.rows.length;
        });
        var sources = tables.map(function (table, index) {
            return { key: "table-" + index, label: evidenceTabLabel(table), table: table };
        });
        var raw = (test.evidence || []).filter(Boolean);
        sources.push({
            key: "raw",
            label: "Raw evidence",
            table: raw.length ? {
                title: "Raw evidence",
                columns: [{ key: "detail", label: "Detail" }],
                rows: raw.map(function (item) { return { detail: item }; }),
                total: raw.length
            } : null
        });
        return sources;
    }

    function filterEvidenceRows(rows, query) {
        if (!query) return rows;
        var needle = query.toLowerCase();
        return rows.filter(function (row) {
            return Object.keys(row).some(function (key) {
                return String(row[key] == null ? "" : row[key]).toLowerCase().indexOf(needle) >= 0;
            });
        });
    }

    function evidencePager(total, page, filtered) {
        var pages = Math.max(1, Math.ceil(filtered / EVIDENCE_PAGE_SIZE));
        var start = filtered ? ((page - 1) * EVIDENCE_PAGE_SIZE) + 1 : 0;
        var end = Math.min(page * EVIDENCE_PAGE_SIZE, filtered);
        var range = '<p class="zt-dd-range">' + (filtered ? (start + "–" + end + " of " + filtered) : "0 records") +
            (filtered !== total ? " (filtered from " + total + ")" : "") + "</p>";
        if (pages <= 1) return range;
        var buttons = "";
        for (var i = 1; i <= pages; i++) {
            buttons += '<button type="button" class="zt-dd-page' + (i === page ? " is-active" : "") + '" data-evidence-page="' + i + '">' + i + "</button>";
        }
        return range + '<div class="zt-dd-pager" role="navigation" aria-label="Evidence pages">' + buttons + "</div>";
    }

    function evidenceTableHtml(table, query, page) {
        if (!table || !table.columns) {
            return '<p class="zt-dd-muted">No collected records were returned for this view.</p>';
        }
        var total = (table.rows || []).length;
        var rows = filterEvidenceRows(table.rows || [], query);
        var filtered = rows.length;
        var pages = Math.max(1, Math.ceil(filtered / EVIDENCE_PAGE_SIZE));
        if (page > pages) page = pages;
        var start = (page - 1) * EVIDENCE_PAGE_SIZE;
        var slice = rows.slice(start, start + EVIDENCE_PAGE_SIZE);
        var head = table.columns.map(function (col) {
            return "<th>" + esc(col.label || col.key) + "</th>";
        }).join("");
        var body = slice.length ? slice.map(function (row) {
            return "<tr>" + table.columns.map(function (col) {
                return "<td>" + esc(row[col.key] == null ? "" : row[col.key]) + "</td>";
            }).join("") + "</tr>";
        }).join("") : '<tr><td colspan="' + table.columns.length + '">No matching records.</td></tr>';
        var more = table.truncated ? '<p class="zt-dd-muted">Collector returned ' + table.rows.length + " of " + table.total + " records.</p>" : "";
        return '<div class="zt-dd-table-scroll"><table class="zt-dd-table"><thead><tr>' + head + '</tr></thead><tbody>' + body + "</tbody></table></div>" +
            evidencePager(total, page, filtered) + more;
    }

    function overviewTabHtml(test) {
        var evaluate = [
            "The assessment scores this control from collected tenant configuration.",
            "A pass requires the tenant to meet the control baseline, not merely that evidence was collected.",
            passRequirement(test)
        ];
        return '<section class="zt-dd-card"><h4>Control summary</h4><p>' + esc(controlSummary(test)) + "</p></section>" +
            '<section class="zt-dd-card"><h4>Why it matters</h4><p>' + esc(whyItMatters(test)) + "</p></section>" +
            '<section class="zt-dd-card"><h4>Baseline</h4><p>' + esc(passRequirement(test)) + "</p></section>" +
            '<section class="zt-dd-card"><h4>How this control is evaluated</h4><div class="zt-dd-minis">' +
            evaluate.map(function (item, i) {
                return '<article class="zt-dd-mini"><em>0' + (i + 1) + "</em><p>" + esc(item) + "</p></article>";
            }).join("") + "</div></section>";
    }

    function profileTabHtml(test, tenant, tenantId, assessedAt) {
        return '<section class="zt-dd-card zt-dd-profile"><h4>Control information</h4><div class="zt-dd-facts">' +
            drawerFact("Control ID", test.id) +
            drawerFact("Tenant ID", tenantId) +
            subscriptionFact(tenant) +
            drawerFact("Category", test.category) +
            drawerFact("Pillar", test.area) +
            drawerFact("Risk", test.risk) +
            drawerFact("User Impact", test.userImpact) +
            drawerFact("Implementation Effort", test.implementationEffort) +
            drawerFact("License", test.license) +
            drawerFact("Date", assessedAt) +
            "</div></section>" +
            '<section class="zt-dd-card"><h4>Assessment scope</h4><p>' +
            esc("This control is assessed for the current " + (test.area || "Cloud Security") + " pillar in the selected Azure tenant. Evidence is limited to configuration collected during the latest assessment run.") +
            "</p></section>";
    }

    function assessmentTabHtml(test, assessment) {
        var kpis = controlKpis(test, assessment);
        var resultSummary = test.resultSummary || "Shows collected measurements for this control and identifies gaps against the baseline.";
        return '<section class="zt-dd-hero is-' + esc(test.status || "Skipped") + '">' +
            '<div class="zt-dd-hero-top"><span>Result</span>' + statusBadge(test.status) + "</div>" +
            "<p>" + esc(resultWhy(test)) + "</p></section>" +
            (kpis.length ? '<section class="zt-dd-card"><h4>Key measurements</h4><div class="zt-dd-kpis">' + kpis.join("") + "</div></section>" : "") +
            '<section class="zt-dd-card"><h4>Result summary</h4><p>' + esc(resultSummary) + "</p></section>" +
            '<section class="zt-dd-card"><h4>Observed concerns</h4><p>' + esc(observedSummary(test)) + "</p></section>" +
            '<section class="zt-dd-card"><h4>Baseline / requirement to pass</h4><p>' + esc(passRequirement(test)) + "</p></section>";
    }

    function evidenceTabHtml(test) {
        var sources = evidenceSources(test);
        var active = state.drawerEvidenceKey;
        if (!sources.some(function (item) { return item.key === active; })) active = sources[0].key;
        state.drawerEvidenceKey = active;
        var current = sources.filter(function (item) { return item.key === active; })[0] || sources[0];
        var query = state.drawerEvidenceQuery || "";
        var page = state.drawerPages[active] || 1;
        var tabs = sources.map(function (item) {
            var on = item.key === active;
            return '<button type="button" role="tab" class="' + (on ? "is-active" : "") + '" data-evidence-tab="' + esc(item.key) + '" aria-selected="' + (on ? "true" : "false") + '">' +
                esc(item.label) + "</button>";
        }).join("");
        return '<section class="zt-dd-card"><h4>Collected evidence</h4>' +
            '<nav class="zt-dd-subtabs" role="tablist" aria-label="Evidence views">' + tabs + "</nav>" +
            '<label class="zt-dd-search"><span class="zt-inv-icon zt-tone-teal">' + icon("search") + "</span>" +
            '<input type="search" data-evidence-search placeholder="Search evidence" value="' + esc(query) + '" aria-label="Search evidence"></label>' +
            evidenceTableHtml(current.table, query, page) +
            "</section>";
    }

    function remediationTabHtml(test) {
        var actions = test.remediationActions && test.remediationActions.length
            ? test.remediationActions
            : (test.recommendation ? [test.recommendation] : []);
        return '<section class="zt-dd-card"><h4>Required actions</h4>' +
            (actions.length
                ? '<ol class="zt-dd-steps">' + actions.map(function (item, i) {
                    return "<li><em>0" + (i + 1) + "</em><span>" + esc(item) + "</span></li>";
                }).join("") + "</ol>"
                : "<p>No remediation summary returned.</p>") +
            "</section>" +
            '<section class="zt-dd-card"><h4>Where to change this</h4>' +
            '<div class="zt-dd-actions">' +
            (test.portalUrl ? '<a class="btn btn-primary" href="' + esc(test.portalUrl) + '" target="_blank" rel="noopener noreferrer">Open portal</a>' : "") +
            (test.documentationUrl ? '<a class="btn btn-ghost" href="' + esc(test.documentationUrl) + '" target="_blank" rel="noopener noreferrer">Learn more</a>' : "") +
            '<a class="btn btn-ghost" href="' + esc(investigationUrl(test.area || state.view, test.risk)) + '">Investigate</a>' +
            "</div>" +
            (!test.portalUrl && !test.documentationUrl ? '<p class="zt-dd-muted">No portal link was returned for this control.</p>' : "") +
            "</section>";
    }

    function syncDrawerTabs() {
        if (!drawerTabs) return;
        drawerTabs.querySelectorAll("[data-drawer-tab]").forEach(function (btn) {
            var on = btn.getAttribute("data-drawer-tab") === state.drawerTab;
            btn.classList.toggle("is-active", on);
            btn.setAttribute("aria-selected", on ? "true" : "false");
        });
    }

    function setDrawerChrome(isMetrics) {
        if (drawer) drawer.classList.toggle("is-metrics", !!isMetrics);
        if (drawerTabs) drawerTabs.hidden = !!isMetrics;
        if (drawerDownload) drawerDownload.hidden = !!isMetrics;
    }

    function evidenceDumpHtml(test) {
        var sources = evidenceSources(test);
        return sources.map(function (item) {
            var table = item.table;
            if (!table || !table.columns) {
                return '<section class="zt-dd-card"><h4>' + esc(item.label) + "</h4><p class=\"zt-dd-muted\">No collected records were returned for this view.</p></section>";
            }
            var rows = table.rows || [];
            var head = table.columns.map(function (col) {
                return "<th>" + esc(col.label || col.key) + "</th>";
            }).join("");
            var body = rows.length ? rows.map(function (row) {
                return "<tr>" + table.columns.map(function (col) {
                    return "<td>" + esc(row[col.key] == null ? "" : row[col.key]) + "</td>";
                }).join("") + "</tr>";
            }).join("") : '<tr><td colspan="' + table.columns.length + '">No matching records.</td></tr>';
            return '<section class="zt-dd-card"><h4>' + esc(item.label) + "</h4>" +
                '<div class="zt-dd-table-scroll"><table class="zt-dd-table"><thead><tr>' + head +
                '</tr></thead><tbody>' + body + "</tbody></table></div></section>";
        }).join("");
    }

    function controlPdfHtml(test) {
        var a = state.assessment || {};
        var tenant = a.tenant || {};
        var tenantId = state.isAdmin ? (tenant.tenantId || "Unavailable") : maskTenant(tenant.tenantId);
        var assessedAt = formatTime(test.lastEvaluatedAt || a.completedAt || a.startedAt);
        return '<header class="zt-pdf-head"><h1>' + esc(test.name || "Control details") + "</h1>" +
            '<div class="zt-dd-head-badges">' + riskBadge(test.risk) + statusBadge(test.status) + "</div></header>" +
            '<section class="zt-pdf-section"><h2>Overview</h2>' + overviewTabHtml(test) + "</section>" +
            '<section class="zt-pdf-section"><h2>Control profile</h2>' + profileTabHtml(test, tenant, tenantId, assessedAt) + "</section>" +
            '<section class="zt-pdf-section"><h2>Assessment</h2>' + assessmentTabHtml(test, a) + "</section>" +
            '<section class="zt-pdf-section"><h2>Evidence</h2>' + evidenceDumpHtml(test) + "</section>" +
            '<section class="zt-pdf-section"><h2>Remediation</h2>' + remediationTabHtml(test) + "</section>";
    }

    function printControlPdf(test) {
        if (!test) {
            toast("No control details to download.", "error");
            return;
        }
        var w = window.open("", "_blank");
        if (!w) {
            toast("Allow pop-ups to download the control PDF.", "error");
            return;
        }
        var cssLinks = Array.prototype.map.call(document.querySelectorAll('link[rel="stylesheet"]'), function (link) {
            return '<link rel="stylesheet" href="' + esc(link.href) + '">';
        }).join("");
        w.document.write("<!DOCTYPE html><html><head><title>" + esc(test.name || "Control details") + "</title>" + cssLinks +
            "<style>html,body{background:#121218;color:#e8e8ee;margin:0;padding:0;}" +
            "body{padding:24px 28px 40px;}" +
            ".zt-pdf-head{margin:0 0 18px;padding-bottom:16px;border-bottom:1px solid rgba(255,255,255,0.1);}" +
            ".zt-pdf-head h1{margin:0 0 10px;font-size:22px;font-weight:800;}" +
            ".zt-pdf-section{margin:22px 0 0;}" +
            ".zt-pdf-section > h2{margin:0 0 12px;font-size:13px;font-weight:800;letter-spacing:0.08em;text-transform:uppercase;color:#8A94A3;}" +
            ".zt-dd{display:flex;flex-direction:column;gap:14px;}" +
            ".zt-dd-table-scroll{max-height:none;overflow:visible;}" +
            ".zt-dd-actions,.zt-dd-search,.zt-dd-pager,.zt-dd-subtabs{display:none !important;}" +
            "@media print{html,body{background:#fff;color:#111;} .zt-dd-card,.zt-dd-hero,.zt-dd-fact,.zt-dd-mini,.zt-dd-kpi,.zt-dd-steps li{background:#f6f7f9;border-color:#d8dbe2;color:#111;} .zt-pdf-section > h2,.zt-dd-card h4,.zt-dd-fact span,.zt-dd-muted{color:#5b6472;} a{color:#111;}}</style></head><body>" +
            '<div class="zt-dd zt-pdf">' + controlPdfHtml(test) + "</div></body></html>");
        w.document.close();
        w.focus();
        setTimeout(function () { w.print(); }, 250);
    }

    function bindDrawerBody() {
        if (!drawerBody) return;
        drawerBody.querySelectorAll("[data-evidence-tab]").forEach(function (btn) {
            btn.addEventListener("click", function () {
                state.drawerEvidenceKey = btn.getAttribute("data-evidence-tab") || "";
                state.drawerEvidenceQuery = "";
                renderDrawerBody();
            });
        });
        drawerBody.querySelectorAll("[data-evidence-page]").forEach(function (btn) {
            btn.addEventListener("click", function () {
                var page = parseInt(btn.getAttribute("data-evidence-page"), 10) || 1;
                state.drawerPages[state.drawerEvidenceKey || "raw"] = page;
                renderDrawerBody();
            });
        });
        var search = drawerBody.querySelector("[data-evidence-search]");
        if (search) {
            search.addEventListener("input", function () {
                state.drawerEvidenceQuery = search.value || "";
                state.drawerPages[state.drawerEvidenceKey || "raw"] = 1;
                renderDrawerBody();
                var next = drawerBody.querySelector("[data-evidence-search]");
                if (next) {
                    next.focus();
                    if (typeof next.setSelectionRange === "function") next.setSelectionRange(next.value.length, next.value.length);
                }
            });
        }
    }

    function ovGroup(key, label, source, ic, tone) {
        return { key: key, label: label, source: source, ic: ic || "search", tone: tone || "teal" };
    }

    var OVERVIEW_SECTIONS = {
        "identity-inventory": {
            title: "Identity inventory",
            summary: "Directory inventory for users, guests, groups, applications, and service principals in the assessed tenant.",
            groups: [
                ovGroup("users", "Users", ["identityOverview", "inventory", "users"], "user", "blue"),
                ovGroup("guests", "Guest users", ["identityOverview", "inventory", "guests"], "guests", "sky"),
                ovGroup("groups", "Groups", ["identityOverview", "inventory", "groups"], "groups", "teal"),
                ovGroup("applications", "Applications", ["identityOverview", "inventory", "applications"], "apps", "mint"),
                ovGroup("servicePrincipals", "Service principals", ["identityOverview", "inventory", "servicePrincipals"], "key", "violet")
            ]
        },
        "identity-privileged": {
            title: "Privileged access / PIM",
            summary: "Privileged directory roles and PIM eligibility for standing and eligible admin access.",
            groups: [
                ovGroup("members", "Privileged members", ["identityOverview", "privileged", "members"], "shield", "purple"),
                ovGroup("roles", "Privileged roles", ["identityOverview", "privileged", "roles"], "lock", "violet"),
                ovGroup("pimEligible", "PIM eligible assignments", ["identityOverview", "privileged", "pimEligible"], "users", "teal"),
                ovGroup("pimActive", "PIM active assignments", ["identityOverview", "privileged", "pimActive"], "pass", "mint")
            ]
        },
        "identity-credentials": {
            title: "Application identity and credential hygiene",
            summary: "Application registrations and credential lifetime for secrets and certificates.",
            groups: [
                ovGroup("applicationsAssessed", "Applications assessed", ["identityOverview", "credentials", "applicationsAssessed"], "apps", "mint"),
                ovGroup("expiring30d", "Expiring within 30 days", ["identityOverview", "credentials", "expiring30d"], "clock", "sky"),
                ovGroup("expiredCredentials", "Expired credentials", ["identityOverview", "credentials", "expiredCredentials"], "fail", "purple"),
                ovGroup("secrets", "Secrets", ["identityOverview", "credentials", "secrets"], "key", "teal"),
                ovGroup("certificates", "Certificates", ["identityOverview", "credentials", "certificates"], "cert", "violet")
            ]
        },
        "network-inventory": {
            title: "Network inventory",
            summary: "Network security groups, public IPs, and private endpoints collected for this tenant.",
            groups: [
                ovGroup("nsgsAssociated", "NSGs associated", ["networkOverview", "inventory", "nsgsAssociated"], "shield", "blue"),
                ovGroup("subnetsWithoutNsg", "Subnets without NSG", ["networkOverview", "inventory", "subnetsWithoutNsg"], "building", "sky"),
                ovGroup("publicIps", "Public IPs attached", ["networkOverview", "inventory", "publicIps"], "laptop", "teal"),
                ovGroup("privateEndpoints", "Private endpoints", ["networkOverview", "inventory", "privateEndpoints"], "lock", "violet")
            ]
        },
        "network-perimeter": {
            title: "Perimeter controls",
            summary: "Azure Firewall and WAF coverage at the network perimeter.",
            groups: [
                ovGroup("firewalls", "Azure Firewalls", ["networkOverview", "perimeter", "firewalls"], "shield", "purple"),
                ovGroup("wafPolicies", "WAF policies", ["networkOverview", "perimeter", "wafPolicies"], "pass", "mint")
            ]
        },
        "network-exposure": {
            title: "Internet exposure",
            summary: "Inbound management and internet-allow rules that expand the network attack surface.",
            groups: [
                ovGroup("openManagementRules", "Open management rules", ["networkOverview", "exposure", "openManagementRules"], "fail", "purple"),
                ovGroup("internetAllowRules", "Internet allow rules", ["networkOverview", "exposure", "internetAllowRules"], "warn", "sky")
            ]
        },
        "network-topology": {
            title: "Segmentation and topology",
            summary: "Virtual networks, subnets, routing, and load-balancing topology.",
            groups: [
                ovGroup("vnets", "Virtual networks", ["networkOverview", "topology", "vnets"], "building", "blue"),
                ovGroup("subnets", "Subnets", ["networkOverview", "topology", "subnets"], "shield", "sky"),
                ovGroup("nics", "Network interfaces", ["networkOverview", "topology", "nics"], "laptop", "teal"),
                ovGroup("peerings", "Peerings", ["networkOverview", "topology", "peerings"], "lock", "violet"),
                ovGroup("routeTables", "Route tables", ["networkOverview", "topology", "routeTables"], "pass", "mint"),
                ovGroup("associatedRouteTables", "Associated route tables", ["networkOverview", "topology", "associatedRouteTables"], "search", "purple"),
                ovGroup("loadBalancers", "Load balancers", ["networkOverview", "topology", "loadBalancers"], "apps", "sky"),
                ovGroup("networkWatchers", "Network Watchers", ["networkOverview", "topology", "networkWatchers"], "clock", "teal")
            ]
        },
        "network-addressing": {
            title: "Addressing",
            summary: "Public IP inventory and attachment state.",
            groups: [
                ovGroup("publicIps", "Public IPs", ["networkOverview", "addressing", "publicIps"], "laptop", "blue"),
                ovGroup("publicIpsAttached", "Public IPs attached", ["networkOverview", "addressing", "publicIpsAttached"], "lock", "teal")
            ]
        },
        "network-perimeter-detail": {
            title: "Perimeter detail",
            summary: "Firewall policy, WAF, Front Door, and DDoS posture behind the perimeter controls.",
            groups: [
                ovGroup("firewallPolicies", "Firewall policies", ["networkOverview", "perimeterDetail", "firewallPolicies"], "shield", "purple"),
                ovGroup("firewallsWithPolicy", "Firewalls with policy", ["networkOverview", "perimeterDetail", "firewallsWithPolicy"], "pass", "mint"),
                ovGroup("premiumFirewalls", "Premium firewalls", ["networkOverview", "perimeterDetail", "premiumFirewalls"], "lock", "violet"),
                ovGroup("threatIntel", "Threat intelligence", ["networkOverview", "perimeterDetail", "threatIntel"], "warn", "sky"),
                ovGroup("applicationGateways", "Application Gateways", ["networkOverview", "perimeterDetail", "applicationGateways"], "apps", "blue"),
                ovGroup("applicationGatewayWaf", "Gateway WAF enabled", ["networkOverview", "perimeterDetail", "applicationGatewayWaf"], "shield", "teal"),
                ovGroup("wafPrevention", "WAF prevention", ["networkOverview", "perimeterDetail", "wafPrevention"], "pass", "mint"),
                ovGroup("wafAssociated", "WAF associated", ["networkOverview", "perimeterDetail", "wafAssociated"], "lock", "purple"),
                ovGroup("frontDoorProfiles", "Front Door profiles", ["networkOverview", "perimeterDetail", "frontDoorProfiles"], "building", "sky"),
                ovGroup("ddosPlans", "DDoS plans", ["networkOverview", "perimeterDetail", "ddosPlans"], "fail", "violet"),
                ovGroup("ddosProtectedVnets", "DDoS-protected VNets", ["networkOverview", "perimeterDetail", "ddosProtectedVnets"], "shield", "teal")
            ]
        },
        "network-remote": {
            title: "Remote access",
            summary: "VPN, Bastion, and ExpressRoute paths into the tenant network.",
            groups: [
                ovGroup("vpnGateways", "VPN gateways", ["networkOverview", "remoteAccess", "vpnGateways"], "lock", "blue"),
                ovGroup("bastions", "Bastion hosts", ["networkOverview", "remoteAccess", "bastions"], "shield", "mint"),
                ovGroup("expressRoute", "ExpressRoute circuits", ["networkOverview", "remoteAccess", "expressRoute"], "building", "violet")
            ]
        },
        "network-paas": {
            title: "Private access and PaaS exposure",
            summary: "Private endpoints and public PaaS services that can bypass network segmentation.",
            groups: [
                ovGroup("privateEndpoints", "Private endpoints", ["networkOverview", "paasExposure", "privateEndpoints"], "lock", "violet"),
                ovGroup("paasPublic", "Publicly accessible PaaS", ["networkOverview", "paasExposure", "paasPublic"], "warn", "purple"),
                ovGroup("paasRestricted", "Restricted PaaS", ["networkOverview", "paasExposure", "paasRestricted"], "pass", "mint"),
                ovGroup("storageAccounts", "Storage accounts", ["networkOverview", "paasExposure", "storageAccounts"], "apps", "teal"),
                ovGroup("keyVaults", "Key Vaults", ["networkOverview", "paasExposure", "keyVaults"], "key", "sky"),
                ovGroup("sqlServers", "SQL servers", ["networkOverview", "paasExposure", "sqlServers"], "building", "blue")
            ]
        },
        "devices-inventory": {
            title: "Device inventory",
            summary: "Intune-managed and Entra-registered devices in the tenant.",
            groups: [
                ovGroup("managedDevices", "Intune managed devices", ["devicesOverview", "inventory", "managedDevices"], "devices", "blue"),
                ovGroup("entraDevices", "Entra devices", ["devicesOverview", "inventory", "entraDevices"], "laptop", "sky")
            ]
        },
        "devices-compliance": {
            title: "Device compliance",
            summary: "Compliance state reported by managed devices.",
            groups: [
                ovGroup("compliant", "Compliant devices", ["devicesOverview", "compliance", "compliant"], "pass", "mint"),
                ovGroup("unknownCompliance", "Unknown compliance", ["devicesOverview", "compliance", "unknownCompliance"], "warn", "violet")
            ]
        },
        "devices-encryption": {
            title: "Encryption",
            summary: "Managed devices that report disk encryption.",
            groups: [
                ovGroup("encrypted", "Encrypted devices", ["devicesOverview", "encryption", "encrypted"], "lock", "teal")
            ]
        },
        "devices-ownership": {
            title: "Ownership",
            summary: "Company, personal, and unknown ownership for managed devices.",
            groups: [
                ovGroup("companyOwned", "Company owned", ["devicesOverview", "ownership", "companyOwned"], "building", "blue"),
                ovGroup("personalOwned", "Personal owned", ["devicesOverview", "ownership", "personalOwned"], "users", "sky"),
                ovGroup("unknownOwner", "Unknown owner", ["devicesOverview", "ownership", "unknownOwner"], "search", "violet")
            ]
        },
        "devices-policies": {
            title: "Compliance policies",
            summary: "Intune compliance policies and the controls they require.",
            groups: [
                ovGroup("policies", "Compliance policies", ["devicesOverview", "policies", "policies"], "shield", "mint"),
                ovGroup("assigned", "Assigned policies", ["devicesOverview", "policies", "assigned"], "pass", "teal"),
                ovGroup("unassigned", "Unassigned policies", ["devicesOverview", "policies", "unassigned"], "warn", "violet"),
                ovGroup("minOs", "Minimum OS", ["devicesOverview", "policies", "minOs"], "clock", "blue"),
                ovGroup("encryption", "Encryption required", ["devicesOverview", "policies", "encryption"], "lock", "sky"),
                ovGroup("firewall", "Firewall required", ["devicesOverview", "policies", "firewall"], "shield", "purple"),
                ovGroup("secureBoot", "Secure Boot required", ["devicesOverview", "policies", "secureBoot"], "pass", "mint"),
                ovGroup("tpm", "TPM required", ["devicesOverview", "policies", "tpm"], "key", "teal")
            ]
        },
        "devices-enrollment": {
            title: "Enrollment",
            summary: "Enrollment configurations and platform restrictions.",
            groups: [
                ovGroup("configurations", "Enrollment configurations", ["devicesOverview", "enrollment", "configurations"], "apps", "blue"),
                ovGroup("restrictions", "Restriction configs", ["devicesOverview", "enrollment", "restrictions"], "lock", "violet"),
                ovGroup("platformRestrictions", "Platform restrictions", ["devicesOverview", "enrollment", "platformRestrictions"], "shield", "sky")
            ]
        },
        "devices-entra": {
            title: "Entra device state",
            summary: "Entra-managed and compliant device counts.",
            groups: [
                ovGroup("managed", "Entra managed", ["devicesOverview", "entra", "managed"], "devices", "mint"),
                ovGroup("compliant", "Entra compliant", ["devicesOverview", "entra", "compliant"], "pass", "teal")
            ]
        },
        "data-protection": {
            title: "Information protection",
            summary: "Sensitivity labels and protection settings collected from Purview.",
            groups: [
                ovGroup("labels", "Sensitivity labels", ["dataOverview", "informationProtection", "labels"], "lock", "violet"),
                ovGroup("encrypted", "Encrypted labels", ["dataOverview", "informationProtection", "encrypted"], "shield", "mint"),
                ovGroup("contentMarking", "Content marking", ["dataOverview", "informationProtection", "contentMarking"], "pass", "teal"),
                ovGroup("autoLabel", "Auto-labeling", ["dataOverview", "informationProtection", "autoLabel"], "search", "sky")
            ]
        },
        "data-dlp": {
            title: "Data loss prevention",
            summary: "DLP scopes and protected locations.",
            groups: [
                ovGroup("scopes", "DLP scopes", ["dataOverview", "dlp", "scopes"], "shield", "mint"),
                ovGroup("locations", "Protected locations", ["dataOverview", "dlp", "locations"], "building", "blue")
            ]
        },
        "data-sharing": {
            title: "Sharing and collaboration",
            summary: "Anonymous sharing, external resharing, and legacy authentication controls.",
            groups: [
                ovGroup("anonymousSharing", "Anonymous sharing", ["dataOverview", "sharing", "anonymousSharing"], "warn", "purple"),
                ovGroup("resharing", "External resharing", ["dataOverview", "sharing", "resharing"], "users", "sky"),
                ovGroup("legacyAuthBlocked", "Legacy auth blocked", ["dataOverview", "sharing", "legacyAuthBlocked"], "lock", "teal")
            ]
        },
        "data-retention": {
            title: "Retention and records",
            summary: "Retention labels published in the tenant.",
            groups: [
                ovGroup("labels", "Retention labels", ["dataOverview", "retention", "labels"], "clock", "blue"),
                ovGroup("published", "Published labels", ["dataOverview", "retention", "published"], "pass", "mint")
            ]
        },
        "data-audit": {
            title: "Audit and visibility",
            summary: "Directory audit records collected for this assessment.",
            groups: [
                ovGroup("directoryAudits", "Directory audit records", ["dataOverview", "audit", "directoryAudits"], "search", "teal"),
                ovGroup("success", "Successful audit events", ["dataOverview", "audit", "success"], "pass", "mint")
            ]
        },
        "infra-inventory": {
            title: "Infrastructure inventory",
            summary: "Resource groups, compute, and storage inventory for the subscription.",
            groups: [
                ovGroup("resourceGroups", "Resource groups", ["infrastructureOverview", "inventory", "resourceGroups"], "building", "blue"),
                ovGroup("vms", "Trusted Launch VMs", ["infrastructureOverview", "inventory", "vms"], "devices", "sky"),
                ovGroup("storageHttps", "Storage HTTPS", ["infrastructureOverview", "inventory", "storageHttps"], "lock", "teal"),
                ovGroup("storagePublic", "Public storage", ["infrastructureOverview", "inventory", "storagePublic"], "warn", "violet")
            ]
        },
        "infra-privileged": {
            title: "Privileged access",
            summary: "Key Vault purge protection and privileged ARM assignments.",
            groups: [
                ovGroup("keyVaultPurge", "Key Vault purge protection", ["infrastructureOverview", "privileged", "keyVaultPurge"], "key", "purple"),
                ovGroup("privilegedAssignments", "Privileged ARM assignments", ["infrastructureOverview", "privileged", "privilegedAssignments"], "users", "mint")
            ]
        },
        "infra-defender": {
            title: "Defender for Cloud",
            summary: "Defender secure score and unhealthy assessments.",
            groups: [
                ovGroup("defenderScore", "Defender secure score", ["infrastructureOverview", "defender", "defenderScore"], "shield", "mint"),
                ovGroup("unhealthyAssessments", "Unhealthy assessments", ["infrastructureOverview", "defender", "unhealthyAssessments"], "fail", "purple")
            ]
        },
        "infra-defender-coverage": {
            title: "Defender coverage",
            summary: "Healthy assessments, total assessments, and Defender plans.",
            groups: [
                ovGroup("healthyAssessments", "Healthy assessments", ["infrastructureOverview", "defender", "healthyAssessments"], "pass", "mint"),
                ovGroup("assessmentCount", "Assessments", ["infrastructureOverview", "defender", "assessmentCount"], "search", "blue"),
                ovGroup("defenderPlans", "Standard plans", ["infrastructureOverview", "defender", "defenderPlans"], "shield", "purple")
            ]
        },
        "infra-compute": {
            title: "Compute",
            summary: "Virtual machines, scale sets, App Services, and managed identity coverage.",
            groups: [
                ovGroup("vms", "Virtual machines", ["infrastructureOverview", "compute", "vms"], "devices", "blue"),
                ovGroup("vmss", "VM scale sets", ["infrastructureOverview", "compute", "vmss"], "laptop", "sky"),
                ovGroup("trustedLaunch", "Trusted Launch", ["infrastructureOverview", "compute", "trustedLaunch"], "shield", "teal"),
                ovGroup("encryptedOs", "Encrypted OS disks", ["infrastructureOverview", "compute", "encryptedOs"], "lock", "mint"),
                ovGroup("computeIdentity", "Compute managed identity", ["infrastructureOverview", "compute", "computeIdentity"], "key", "violet"),
                ovGroup("appServices", "App Services", ["infrastructureOverview", "compute", "appServices"], "apps", "purple"),
                ovGroup("functionApps", "Function Apps", ["infrastructureOverview", "compute", "functionApps"], "apps", "sky")
            ]
        },
        "infra-storage": {
            title: "Storage",
            summary: "HTTPS, public network access, and storage identity settings.",
            groups: [
                ovGroup("https", "HTTPS required", ["infrastructureOverview", "storage", "https"], "lock", "teal"),
                ovGroup("public", "Public network access", ["infrastructureOverview", "storage", "public"], "warn", "violet"),
                ovGroup("noPublicBlob", "Blob public access disabled", ["infrastructureOverview", "storage", "noPublicBlob"], "shield", "mint"),
                ovGroup("identity", "Storage managed identity", ["infrastructureOverview", "storage", "identity"], "key", "blue")
            ]
        },
        "infra-exposure": {
            title: "Network exposure",
            summary: "Open management paths, public IPs, and private service endpoints.",
            groups: [
                ovGroup("openManagementRules", "Open management rules", ["infrastructureOverview", "exposure", "openManagementRules"], "fail", "purple"),
                ovGroup("internetAllowRules", "Internet allow rules", ["infrastructureOverview", "exposure", "internetAllowRules"], "warn", "sky"),
                ovGroup("publicIps", "Public IPs attached", ["infrastructureOverview", "exposure", "publicIps"], "laptop", "teal"),
                ovGroup("privateEndpoints", "Private endpoints", ["infrastructureOverview", "exposure", "privateEndpoints"], "lock", "violet"),
                ovGroup("keyVaultPublic", "Public Key Vaults", ["infrastructureOverview", "exposure", "keyVaultPublic"], "key", "blue"),
                ovGroup("aksPrivate", "Private AKS", ["infrastructureOverview", "exposure", "aksPrivate"], "shield", "mint"),
                ovGroup("acrPrivate", "Private ACR", ["infrastructureOverview", "exposure", "acrPrivate"], "apps", "purple")
            ]
        },
        "infra-keyvault": {
            title: "Key Vault",
            summary: "Key Vault authorization, purge protection, and public network state.",
            groups: [
                ovGroup("vaults", "Key Vaults", ["infrastructureOverview", "keyVault", "vaults"], "key", "violet"),
                ovGroup("rbac", "RBAC authorization", ["infrastructureOverview", "keyVault", "rbac"], "lock", "mint"),
                ovGroup("purge", "Purge protection", ["infrastructureOverview", "keyVault", "purge"], "shield", "purple"),
                ovGroup("softDelete", "Soft-delete", ["infrastructureOverview", "keyVault", "softDelete"], "pass", "teal"),
                ovGroup("public", "Public network enabled", ["infrastructureOverview", "keyVault", "public"], "warn", "sky")
            ]
        },
        "infra-rbac": {
            title: "Privileged access detail",
            summary: "ARM role assignments and subscription administrators.",
            groups: [
                ovGroup("roleAssignments", "Role assignments", ["infrastructureOverview", "rbac", "roleAssignments"], "users", "purple"),
                ovGroup("privilegedAssignments", "Privileged ARM assignments", ["infrastructureOverview", "rbac", "privilegedAssignments"], "shield", "mint"),
                ovGroup("subscriptionAdmins", "Subscription admins", ["infrastructureOverview", "rbac", "subscriptionAdmins"], "warn", "sky"),
                ovGroup("userAssignedIdentities", "User-assigned identities", ["infrastructureOverview", "rbac", "userAssignedIdentities"], "key", "teal")
            ]
        },
        "infra-governance": {
            title: "Governance",
            summary: "Policy assignments, exemptions, and tagged resource groups.",
            groups: [
                ovGroup("policyAssignments", "Policy assignments", ["infrastructureOverview", "governance", "policyAssignments"], "building", "blue"),
                ovGroup("policyExemptions", "Policy exemptions", ["infrastructureOverview", "governance", "policyExemptions"], "warn", "violet"),
                ovGroup("taggedGroups", "Tagged resource groups", ["infrastructureOverview", "governance", "taggedGroups"], "pass", "teal")
            ]
        },
        "infra-monitoring": {
            title: "Monitoring",
            summary: "Log Analytics workspaces and subscription diagnostics.",
            groups: [
                ovGroup("logAnalytics", "Log Analytics workspaces", ["infrastructureOverview", "monitoring", "logAnalytics"], "search", "mint"),
                ovGroup("diagnostics", "Subscription diagnostics", ["infrastructureOverview", "monitoring", "diagnostics"], "clock", "sky")
            ]
        },
        "infra-backup": {
            title: "Backup",
            summary: "Recovery Services and backup vaults.",
            groups: [
                ovGroup("recoveryVaults", "Recovery Services vaults", ["infrastructureOverview", "backup", "recoveryVaults"], "shield", "blue"),
                ovGroup("backupVaults", "Backup vaults", ["infrastructureOverview", "backup", "backupVaults"], "lock", "teal")
            ]
        }
    };

    function resolveOverviewMetric(group) {
        var viz = ((state.assessment || {}).visualizations) || {};
        var cur = viz;
        var path = (group && group.source) || [];
        for (var i = 0; i < path.length; i++) {
            if (!cur) return null;
            cur = cur[path[i]];
        }
        if (group && path[0] === "identityOverview" && path[1] === "inventory") {
            if (!cur || cur.value == null) {
                var tenant = (state.assessment || {}).tenant || {};
                var fallback = tenant[group.key];
                if (fallback != null) return { value: fallback, items: (cur && cur.items) || [] };
            }
        }
        return cur || null;
    }

    function overviewGroupHtml(group, index) {
        var metric = resolveOverviewMetric(group);
        var shown = formatOverviewValue(metric);
        if (shown == null && metricValue(metric) == null) shown = "Unavailable";
        var items = (metric && metric.items) || [];
        var total = (metric && metric.itemTotal != null) ? metric.itemTotal : items.length;
        var open = state.drawerOpen[group.key];
        if (open == null) open = index === 0;
        var body;
        if (items.length) {
            body = '<ul class="zt-ov-list">' + items.map(function (item) {
                var name = item && (item.name || item.displayName) || "Unnamed";
                var detail = item && item.detail ? '<em>' + esc(item.detail) + "</em>" : "";
                return "<li><span>" + esc(name) + "</span>" + detail + "</li>";
            }).join("") + "</ul>";
            if (total > items.length) {
                body += '<p class="zt-dd-muted">Showing ' + items.length + " of " + compactNumber(total) + ".</p>";
            }
        } else {
            body = '<p class="zt-dd-muted">No item list was returned for this metric. Count: ' + esc(shown) + ".</p>";
        }
        return '<details class="zt-ov-acc" data-ov-group="' + esc(group.key) + '"' + (open ? " open" : "") + ">" +
            "<summary>" +
            '<span class="zt-inv-icon zt-tone-' + esc(group.tone) + '">' + icon(group.ic) + "</span>" +
            "<span>" + esc(group.label) + "</span>" +
            "<strong>" + esc(shown) + "</strong>" +
            "</summary>" + body + "</details>";
    }

    function overviewSectionHtml(id) {
        var section = OVERVIEW_SECTIONS[id];
        if (!section) return "<p>Overview details were not found.</p>";
        var groups = (section.groups || []).map(function (group, index) {
            return overviewGroupHtml(group, index);
        }).join("");
        return '<section class="zt-dd-card"><h4>Summary</h4><p>' + esc(section.summary) + "</p></section>" +
            '<section class="zt-dd-card"><h4>Metrics</h4>' + (groups || "<p>No metrics were returned.</p>") + "</section>";
    }

    function bindOverviewDrawer() {
        if (!drawerBody) return;
        drawerBody.querySelectorAll("[data-ov-group]").forEach(function (el) {
            el.addEventListener("toggle", function () {
                state.drawerOpen[el.getAttribute("data-ov-group")] = el.open;
            });
        });
    }

    function openOverviewSection(id) {
        if (!OVERVIEW_SECTIONS[id] || !drawer) return;
        state.overviewSection = id;
        state.selectedId = null;
        state.drawerTab = "overview";
        state.drawerOpen = {};
        state.drawerPages = {};
        state.drawerEvidenceKey = "";
        state.drawerEvidenceQuery = "";
        if (drawerTitle) drawerTitle.textContent = OVERVIEW_SECTIONS[id].title;
        if (drawerBadges) drawerBadges.innerHTML = "";
        setDrawerChrome(true);
        renderDrawerBody();
        drawer.hidden = false;
        if (drawerBackdrop) drawerBackdrop.hidden = false;
        requestAnimationFrame(function () {
            drawer.classList.add("is-open");
            if (drawerBackdrop) drawerBackdrop.classList.add("is-open");
        });
    }

    function renderDrawerBody() {
        if (state.overviewSection) {
            if (!drawerBody) return;
            drawerBody.innerHTML = '<div class="zt-dd">' + overviewSectionHtml(state.overviewSection) + "</div>";
            drawerBody.scrollTop = 0;
            bindOverviewDrawer();
            return;
        }
        var test = findTest(state.selectedId);
        if (!test || !drawerBody) return;
        var a = state.assessment || {};
        var tenant = a.tenant || {};
        var tenantId = state.isAdmin ? (tenant.tenantId || "Unavailable") : maskTenant(tenant.tenantId);
        var assessedAt = formatTime(test.lastEvaluatedAt || a.completedAt || a.startedAt);
        var html = "";
        if (state.drawerTab === "profile") html = profileTabHtml(test, tenant, tenantId, assessedAt);
        else if (state.drawerTab === "assessment") html = assessmentTabHtml(test, a);
        else if (state.drawerTab === "evidence") html = evidenceTabHtml(test);
        else if (state.drawerTab === "remediation") html = remediationTabHtml(test);
        else html = overviewTabHtml(test);
        drawerBody.innerHTML = '<div class="zt-dd">' + html + "</div>";
        drawerBody.scrollTop = 0;
        bindDrawerBody();
    }

    function setDrawerTab(tab) {
        if (tab === "result" || tab === "output") tab = "assessment";
        if (tab !== "overview" && tab !== "profile" && tab !== "assessment" && tab !== "evidence" && tab !== "remediation") tab = "overview";
        state.drawerTab = tab;
        syncDrawerTabs();
        renderDrawerBody();
    }

    function openDrawer(id) {
        var test = findTest(id);
        if (!test || !drawer) return;
        state.overviewSection = null;
        state.selectedId = id;
        state.drawerTab = "overview";
        state.drawerPages = {};
        state.drawerOpen = {};
        state.drawerEvidenceKey = "";
        state.drawerEvidenceQuery = "";
        setDrawerChrome(false);
        if (drawerTitle) drawerTitle.textContent = test.name;
        if (drawerBadges) drawerBadges.innerHTML = riskBadge(test.risk) + statusBadge(test.status);
        syncDrawerTabs();
        renderDrawerBody();
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
        state.overviewSection = null;
        setTimeout(function () {
            drawer.hidden = true;
            if (drawerBackdrop) drawerBackdrop.hidden = true;
            setDrawerChrome(false);
            if (drawerDownload) drawerDownload.hidden = true;
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
            if (err.status === 429 || err.status === 404) {
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
            loadLatest();
        }).catch(function () {
            loadLatest();
        });
    }

    function loadLatest() {
        fetch("/api/zero-trust/latest", {
            credentials: "same-origin",
            headers: { "Accept": "application/json", "X-Requested-With": "XMLHttpRequest" }
        }).then(function (res) { return res.json().catch(function () { return {}; }); }).then(function (data) {
            if (data && data.hasData && data.assessmentId) {
                state.assessmentId = data.assessmentId;
                try { localStorage.setItem(STORAGE_KEY, state.assessmentId); } catch (e) {}
                state.loading = true;
                render();
                loadResults(state.assessmentId);
                return;
            }
            if (!state.assessmentId) {
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
            line("Endpoint Device", a.devices) + ". " +
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

    window.addEventListener("popstate", function () {
        setView(pathToView(location.href), false);
    });
    if (runBtn) runBtn.addEventListener("click", openConfirm);
    if (refreshBtn) refreshBtn.addEventListener("click", openConfirm);
    document.getElementById("ztConfirmCancel").addEventListener("click", closeConfirm);
    document.getElementById("ztConfirmRun").addEventListener("click", startAssessment);
    if (tenantBtn) {
        tenantBtn.addEventListener("click", function (event) {
            event.stopPropagation();
            closeAssessPop();
            if (tenantPop && !tenantPop.hidden) closeTenantPop();
            else openTenantPop(tenantBtn);
        });
    }
    if (assessBtn) {
        assessBtn.addEventListener("click", function (event) {
            event.stopPropagation();
            closeTenantPop();
            if (assessPop && !assessPop.hidden) closeAssessPop();
            else openAssessPop(assessBtn);
        });
    }
    document.addEventListener("click", function (event) {
        if (!event.target.closest(".zt-health-info")) {
            document.querySelectorAll(".zt-health-info.is-open").forEach(function (btn) {
                btn.classList.remove("is-open");
                btn.setAttribute("aria-expanded", "false");
            });
        }
        if (tenantPop && !tenantPop.hidden && tenantPop.contains(event.target)) return;
        if (tenantBtn && tenantBtn.contains(event.target)) return;
        closeTenantPop();
        if (assessPop && !assessPop.hidden && assessPop.contains(event.target)) return;
        if (assessBtn && assessBtn.contains(event.target)) return;
        closeAssessPop();
    });
    document.getElementById("ztDrawerClose").addEventListener("click", closeDrawer);
    if (drawerDownload) {
        drawerDownload.addEventListener("click", function () {
            printControlPdf(findTest(state.selectedId));
        });
    }
    if (drawerBackdrop) drawerBackdrop.addEventListener("click", closeDrawer);
    if (drawerTabs) {
        drawerTabs.addEventListener("click", function (event) {
            var btn = event.target.closest("[data-drawer-tab]");
            if (!btn) return;
            setDrawerTab(btn.getAttribute("data-drawer-tab"));
        });
    }
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
            closeTenantPop();
            closeAssessPop();
            exportMenu.hidden = true;
        }
    });
    window.addEventListener("beforeunload", stopPoll);
    setView(state.view, false);
    restore();
})();
