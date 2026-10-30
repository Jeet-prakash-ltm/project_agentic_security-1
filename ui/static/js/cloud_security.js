(function () {
    var app = document.getElementById("ztApp");
    if (!app) return;

    var STORAGE_KEY = "ltm_zt_assessment_id";
    var THEME_KEY = "ltm_zt_theme";
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
        pillarTab: "overview"
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

    function viewPath(view) {
        if (!view || view === "overview") return "/zero-trust/dashboard";
        return "/zero-trust/" + view;
    }

    function pathToView(path) {
        var parts = String(path || "").replace(/\/+$/, "").split("/");
        var last = parts[parts.length - 1] || "";
        if (last === "identity" || last === "devices" || last === "network" || last === "data" || last === "infrastructure") {
            return last;
        }
        return "overview";
    }

    function setView(view, push) {
        if (push !== false) {
            var path = viewPath(view);
            var current = location.pathname.replace(/\/+$/, "");
            if (current !== path) {
                window.location.href = path;
                return;
            }
        }
        state.view = view;
        state.page = 1;
        state.pillarTab = "overview";
        if (view !== "overview") state.filters.area = "all";
        closeFilter();
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
        var brand = topnav && topnav.querySelector(".zt-brand");
        var isOverview = state.view === "overview";
        if (brand) brand.hidden = !isOverview;
        if (topnav) {
            topnav.hidden = !isOverview;
            topnav.classList.toggle("is-compact", !isOverview);
        }
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
        { key: "devices", name: "Devices", view: "devices" },
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
            html += '<button type="button" class="zt-domain-group' + (row.name === highest ? " is-highest" : "") + '" data-area="' + esc(row.name) + '" data-risk="all" data-status="Failed">';
            html += '<div class="zt-domain-summary"><strong>' + esc(row.name) + "</strong><span>Total Risk: " + (row.total || 0) + "</span>";
            if (row.name === highest) html += '<em class="zt-domain-badge">Highest Risk Pillar</em>';
            html += '</div><div class="zt-domain-cols">';
            levels.forEach(function (s) {
                var n = row[s.key] || 0;
                var h = top ? Math.round(n / top * 100) : 0;
                html += '<span class="zt-domain-col">';
                if (n > 0) html += '<span class="zt-domain-value">' + n + '</span><span class="zt-domain-fill" style="height:' + h + "%;background:" + s.color + '"></span>';
                html += "</span>";
            });
            html += '</div><span class="zt-domain-label">' + esc(row.name) + "</span></button>";
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
            inventoryStat("purple", "laptop", "Devices", t.devices) +
            inventoryStat("violet", "devices", "Managed devices", t.managedDevices) +
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
            return '<button type="button" class="zt-pillar-card" data-view="' + esc(p.view) + '">' +
                "<h3>" + esc(p.name) + "</h3>" +
                '<div class="zt-pillar-count"><strong>' + (p.passRate == null ? "—" : p.passRate + "%") + "</strong></div>" +
                '<p class="zt-muted">' + p.passed + " passed · " + p.failed + " failed · " + p.high + " high</p>" +
                '<span class="zt-pillar-track"><span class="zt-pillar-fill is-' + scoreTone(p.passRate) + '" style="width:' + (p.passRate || 0) + '%"></span></span></button>';
        }).join("") + "</div>";

        html += pillarRiskChart(heat);

        html += pillarTelemetrySection(viz);

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
            { key: "managedDevices", label: "Managed devices" },
            { key: "compliant", label: "Compliant" },
            { key: "encrypted", label: "Encrypted" },
            { key: "compliancePolicies", label: "Compliance policies" },
            { key: "entraDevices", label: "Entra devices" }
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

    function pillarTelemetrySection(viz) {
        var metrics = (viz && viz.pillarMetrics) || {};
        var cards = [];
        PILLAR_ORDER.forEach(function (p) {
            var fields = PILLAR_METRIC_FIELDS[p.key] || [];
            var data = metrics[p.key];
            if (!data) return;
            var rows = "";
            fields.forEach(function (field) {
                var shown = formatPillarMetric(data[field.key]);
                if (shown == null) return;
                rows += '<div class="zt-metric-row"><span>' + esc(field.label) + "</span><strong>" + esc(shown) + "</strong></div>";
            });
            if (!rows) return;
            cards.push(
                '<button type="button" class="zt-metric-pillar" data-view="' + esc(p.view) + '">' +
                "<h3>" + esc(p.name) + "</h3>" + rows + "</button>"
            );
        });
        if (!cards.length) return "";
        return '<section class="zt-card zt-metric-section"><h2>Pillar telemetry</h2><div class="zt-metric-pillars">' + cards.join("") + "</div></section>";
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
        return '<td><button type="button" class="zt-heat-cell is-' + level + '" data-area="' + esc(area) + '" data-risk="' + esc(risk) + '" data-status="Failed">' + value + "</button></td>";
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
        return '<section class="zt-card"><h2>Assessment data health</h2>' + rows + "</section>";
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
            identityInventoryCard(overview, a.tenant || {}) +
            privilegedAccessCard(overview) +
            "</div>" +
            credentialHealthCard(overview) +
            "</div>";
    }

    function formatOverviewValue(item) {
        if (!item || item.value == null) return null;
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

    function networkOverviewSections(a) {
        var viz = (a && a.visualizations) || {};
        var overview = viz.networkOverview || {};
        return '<div class="zt-id-overview">' +
            '<div class="zt-id-overview-row">' +
            networkInventoryCard(overview) +
            networkPerimeterCard(overview) +
            "</div>" +
            networkExposureCard(overview) +
            "</div>";
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

    function infrastructureOverviewSections(a) {
        var viz = (a && a.visualizations) || {};
        var overview = viz.infrastructureOverview || {};
        return '<div class="zt-id-overview">' +
            '<div class="zt-id-overview-row">' +
            infrastructureInventoryCard(overview) +
            infrastructurePrivilegedCard(overview) +
            "</div>" +
            infrastructureDefenderCard(overview) +
            "</div>";
    }

    function pillarOverviewMetrics(view) {
        if (view === "identity") return identityOverviewSections(state.assessment);
        if (view === "network") return networkOverviewSections(state.assessment);
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
        var html = pillarTabs("Devices");
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

    function layerChip(label, value) {
        var v = value || "Not assessed";
        var tone = v === "Yes" ? "yes" : (v === "No" ? "no" : "na");
        return '<span class="zt-layer-chip is-' + tone + '"><em>' + esc(label) + "</em><strong>" + esc(v) + "</strong></span>";
    }

    function openDrawer(id) {
        var test = findTest(id);
        if (!test || !drawer) return;
        state.selectedId = id;
        drawerTitle.textContent = test.name;
        var layer = test.assessmentLayer || {};
        var evidenceItems = test.evidence || [];
        var evidenceLine = evidenceItems.length ? evidenceItems.slice(0, 2).join(" · ") : "Evidence was not returned.";
        var finding = test.impact || test.description || "No finding summary returned.";
        var kpis = [];
        if (test.category) kpis.push(["Category", test.category]);
        if (test.platform) kpis.push(["Platform", test.platform]);
        if (test.area) kpis.push(["Area", test.area]);
        kpis.push(["Evaluated", formatTime(test.lastEvaluatedAt)]);
        kpis = kpis.slice(0, 4);
        var meta = "";
        if (test.id) meta += '<div class="zt-assess-meta-row"><span>Control ID</span><strong>' + esc(test.id) + "</strong></div>";
        meta += '<div class="zt-assess-meta-row"><span>SFI pillar</span><strong>' + esc((test.sfiPillars || []).join(", ") || "Unavailable") + "</strong></div>";
        meta += '<div class="zt-assess-meta-row"><span>Documentation</span>' + (test.documentationUrl ? '<a href="' + esc(test.documentationUrl) + '" target="_blank" rel="noopener noreferrer">Open docs</a>' : "<strong>Unavailable</strong>") + "</div>";
        meta += '<div class="zt-assess-meta-row"><span>Portal</span>' + (test.portalUrl ? '<a href="' + esc(test.portalUrl) + '" target="_blank" rel="noopener noreferrer">Open portal</a>' : "<strong>Unavailable</strong>") + "</div>";
        if (layer.validation) meta += '<div class="zt-assess-meta-row"><span>Validation</span><strong>' + esc(layer.validation) + "</strong></div>";
        drawerBody.innerHTML =
            '<div class="zt-assess">' +
            '<div class="zt-assess-outcome">' + statusBadge(test.status) + riskBadge(test.risk) + "</div>" +
            '<div class="zt-assess-kpis">' + kpis.map(function (row) {
                return '<article><span>' + esc(row[0]) + "</span><strong>" + esc(row[1]) + "</strong></article>";
            }).join("") + "</div>" +
            '<div class="zt-assess-layers" aria-label="Assessment posture">' +
            layerChip("Configured", layer.configured) +
            layerChip("Assigned", layer.assigned) +
            layerChip("Observed", layer.observed) +
            "</div>" +
            '<section class="zt-assess-block"><h4>Finding</h4><p>' + esc(finding) + "</p></section>" +
            '<section class="zt-assess-block"><h4>Evidence</h4><p class="zt-assess-evidence">' + esc(evidenceLine) + "</p></section>" +
            '<section class="zt-assess-block"><h4>Action</h4><p>' + esc(test.recommendation || "No remediation summary returned.") + "</p></section>" +
            (test.error ? '<section class="zt-assess-block is-error"><h4>Error</h4><p>' + esc(test.error.message) + "</p></section>" : "") +
            '<details class="zt-assess-more"><summary>Docs, portal, and identifiers</summary>' + meta + "</details>" +
            "</div>";
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

    window.addEventListener("popstate", function () {
        setView(pathToView(location.pathname), false);
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
            closeTenantPop();
            closeAssessPop();
            exportMenu.hidden = true;
        }
    });
    window.addEventListener("beforeunload", stopPoll);
    applyTheme();
    setView(state.view, false);
    restore();
})();
