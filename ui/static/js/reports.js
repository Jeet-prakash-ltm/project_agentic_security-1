(function () {
    "use strict";

    var body = document.getElementById("reportHistoryBody");
    var countEl = document.getElementById("reportsCount");
    var chips = document.getElementById("reportTypeChips");
    var paginationEl = document.getElementById("reportsPagination");
    if (!body || !chips) return;

    var PAGE_SIZE = 8;
    var DEVICE_NAME = "vmpafw01";

    var reports = (window.REPORT_DATA || []).slice();
    // Assign a stable, display-friendly Report Id (newest = highest).
    reports.forEach(function (report, index) {
        report._rid = "RPT-" + String(reports.length - index).padStart(4, "0");
    });

    var state = {
        domain: "network",
        type: "all",
        search: "",
        dateFrom: "",
        dateTo: "",
        page: 1,
        inventory: []
    };

    // Pending filter selection; committed to `state` only on Apply.
    var draft = {
        domain: "network",
        type: "all",
        search: "",
        dateFrom: "",
        dateTo: ""
    };

    function escapeHtml(value) {
        return String(value == null ? "" : value)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
    }

    function formatTs(ts) {
        if (!ts) return "\u2014";
        var date = new Date((parseFloat(ts) + 5.5 * 3600) * 1000);
        function pad(n) { return (n < 10 ? "0" : "") + n; }
        return date.getUTCFullYear() + "-" + pad(date.getUTCMonth() + 1) + "-" +
            pad(date.getUTCDate()) + " " + pad(date.getUTCHours()) + ":" + pad(date.getUTCMinutes());
    }

    function normalizeType(type) {
        if (type === "Executive Summary") return "PDF Executive Summary";
        if (type === "Workbook") return "Excel Report";
        return type || "";
    }

    function statusClass(report) {
        if (report.status === "Failed") return "status-fail";
        if (report.status === "Completed") return "status-on";
        return "status-warn";
    }

    function istBoundary(dateStr, endOfDay) {
        if (!dateStr) return null;
        var suffix = endOfDay ? "T23:59:59+05:30" : "T00:00:00+05:30";
        var ms = Date.parse(dateStr + suffix);
        return isNaN(ms) ? null : ms / 1000;
    }

    function matchesType(report) {
        if (state.type === "all") return true;
        var t = normalizeType(report.type);
        if (state.type === "excel") return t === "Excel Report";
        if (state.type === "pdf") return t === "PDF Executive Summary";
        return true;
    }

    function matchesSearch(report) {
        if (!state.search) return true;
        var q = state.search.toLowerCase();
        var hay = [
            report.name || "",
            report._rid || "",
            DEVICE_NAME,
            report.firewall || ""
        ].join(" ").toLowerCase();
        return hay.indexOf(q) !== -1;
    }

    function matchesDate(report) {
        var from = istBoundary(state.dateFrom, false);
        var to = istBoundary(state.dateTo, true);
        if (from === null && to === null) return true;
        var ts = parseFloat(report.ts);
        if (isNaN(ts)) return true;
        if (from !== null && ts < from) return false;
        if (to !== null && ts > to) return false;
        return true;
    }

    function filteredReports() {
        return reports.filter(function (report) {
            return matchesType(report) && matchesSearch(report) && matchesDate(report);
        });
    }

    // ---- Pagination ----

    function pageWindow(current, total) {
        var out = [];
        if (total <= 7) {
            for (var i = 1; i <= total; i++) out.push(i);
            return out;
        }
        out.push(1);
        var start = Math.max(2, current - 1);
        var end = Math.min(total - 1, current + 1);
        if (start > 2) out.push("\u2026");
        for (var j = start; j <= end; j++) out.push(j);
        if (end < total - 1) out.push("\u2026");
        out.push(total);
        return out;
    }

    function renderPagination(totalPages) {
        if (!paginationEl) return;
        if (totalPages <= 1) {
            paginationEl.hidden = true;
            paginationEl.innerHTML = "";
            return;
        }
        var html =
            '<button type="button" class="rep-page-nav" data-page="prev"' +
            (state.page === 1 ? " disabled" : "") +
            ' aria-label="Previous page">\u2039</button>';
        pageWindow(state.page, totalPages).forEach(function (item) {
            if (item === "\u2026") {
                html += '<span class="rep-page-ellipsis">\u2026</span>';
            } else {
                html += '<button type="button" class="rep-page-btn' +
                    (item === state.page ? " is-active" : "") +
                    '" data-page="' + item + '"' +
                    (item === state.page ? ' aria-current="page"' : "") +
                    ">" + item + "</button>";
            }
        });
        html +=
            '<button type="button" class="rep-page-nav" data-page="next"' +
            (state.page === totalPages ? " disabled" : "") +
            ' aria-label="Next page">\u203a</button>';
        paginationEl.innerHTML = html;
        paginationEl.hidden = false;
    }

    function renderRows() {
        var list = filteredReports();
        var total = list.length;
        var totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
        if (state.page > totalPages) state.page = totalPages;
        if (state.page < 1) state.page = 1;

        if (countEl) {
            countEl.textContent = total + (total === 1 ? " report" : " reports");
        }

        if (!total) {
            body.innerHTML =
                '<tr><td colspan="8" class="empty-state">' +
                "No reports match the current filters." +
                '<div class="reports-empty-action"><a href="/workspace" class="btn btn-primary">Open AI Workspace</a></div>' +
                "</td></tr>";
            renderPagination(1);
            return;
        }

        var start = (state.page - 1) * PAGE_SIZE;
        var pageItems = list.slice(start, start + PAGE_SIZE);

        var html = "";
        pageItems.forEach(function (report) {
            var label = normalizeType(report.type);
            var isPdf = label === "PDF Executive Summary";
            var statusClassValue = statusClass(report);
            var icon = isPdf ? "PDF" : "XLS";
            var iconClass = isPdf ? "file-icon-purple" : "file-icon-green";
            var downloadHref = report.id
                ? "/report-download/" + report.id
                : (report.download_url ? "/static/" + report.download_url : "");
            var download = downloadHref
                ? '<a class="rep-action-btn" href="' + downloadHref +
                    '" download title="Download"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12M7 10l5 5 5-5"/><path d="M4 21h16"/></svg></a>'
                : '<span class="rep-action-btn muted" title="No file available"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12M7 10l5 5 5-5"/><path d="M4 21h16"/></svg></span>';
            html +=
                "<tr>" +
                '<td><span class="rep-report-id">' + escapeHtml(report._rid) + "</span></td>" +
                '<td><span class="report-name"><span class="file-icon ' + iconClass + '">' + icon + "</span>" +
                escapeHtml(report.name || "") + "</span></td>" +
                '<td><span class="tag">' + escapeHtml(label) + "</span></td>" +
                '<td><span class="rep-device">' + escapeHtml(DEVICE_NAME) +
                '<button type="button" class="rep-device-info" data-device="' + escapeHtml(DEVICE_NAME) +
                '" aria-label="Device information" title="Device information">' +
                '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 8h.01"/><path d="M11 12h1v4h1"/></svg>' +
                "</button></span></td>" +
                "<td>" + escapeHtml(formatTs(report.ts)) + "</td>" +
                '<td><span class="status-chip ' + statusClassValue + '">' + escapeHtml(report.status || "Completed") + "</span></td>" +
                "<td>" + escapeHtml(report.size || "\u2014") + "</td>" +
                '<td class="text-right"><span class="rep-row-actions">' + download + "</span></td>" +
                "</tr>";
        });
        body.innerHTML = html;
        renderPagination(totalPages);
    }

    // ---- Report type pills ----

    function syncTypePills() {
        chips.querySelectorAll(".rep-pill").forEach(function (p) {
            var on = p.getAttribute("data-value") === draft.type;
            p.classList.toggle("is-active", on);
            p.setAttribute("aria-pressed", on ? "true" : "false");
        });
    }

    chips.addEventListener("click", function (event) {
        var pill = event.target.closest(".rep-pill");
        if (!pill) return;
        draft.type = pill.getAttribute("data-value") || "all";
        syncTypePills();
    });

    // ---- Filter panel open / close ----

    var filterBtn = document.getElementById("reportsFilterBtn");
    var filterPanel = document.getElementById("reportsFilterPanel");
    var filterClose = document.getElementById("repFilterClose");

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
        }
    }
    function toggleFilter() {
        if (filterPanel && filterPanel.hidden) openFilter(); else closeFilter();
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
    document.addEventListener("keydown", function (event) {
        if (event.key === "Escape") { closeFilter(); closeDevicePop(); }
    });

    // ---- Domain navigation (Network Security / Cloud Security) ----

    var domainNav = document.getElementById("reportsDomainNav");
    var networkPanel = document.getElementById("reportsDomainNetwork");
    var cloudPanel = document.getElementById("reportsDomainCloud");

    function syncDomainPills() {
        if (!domainNav) return;
        domainNav.querySelectorAll(".rep-pill").forEach(function (b) {
            var on = b.getAttribute("data-domain") === draft.domain;
            b.classList.toggle("is-active", on);
            b.setAttribute("aria-pressed", on ? "true" : "false");
        });
    }

    function applyDomainPanels() {
        if (networkPanel) networkPanel.hidden = state.domain !== "network";
        if (cloudPanel) cloudPanel.hidden = state.domain !== "cloud";
    }

    if (domainNav) {
        domainNav.addEventListener("click", function (event) {
            var button = event.target.closest(".rep-pill");
            if (!button) return;
            draft.domain = button.getAttribute("data-domain") || "network";
            syncDomainPills();
        });
    }

    // ---- Date range ----

    var dateFrom = document.getElementById("repDateFrom");
    var dateTo = document.getElementById("repDateTo");

    function onDateChange() {
        draft.dateFrom = dateFrom ? dateFrom.value : "";
        draft.dateTo = dateTo ? dateTo.value : "";
    }
    if (dateFrom) dateFrom.addEventListener("change", onDateChange);
    if (dateTo) dateTo.addEventListener("change", onDateChange);

    // ---- Search ----

    var searchEl = document.getElementById("repFilterSearch");
    if (searchEl) {
        searchEl.addEventListener("input", function () {
            draft.search = searchEl.value.trim();
        });
    }

    // Reflect the currently applied filters back into the panel controls.
    function syncDraftFromState() {
        draft.domain = state.domain;
        draft.type = state.type;
        draft.search = state.search;
        draft.dateFrom = state.dateFrom;
        draft.dateTo = state.dateTo;
        if (searchEl) searchEl.value = state.search;
        if (dateFrom) dateFrom.value = state.dateFrom;
        if (dateTo) dateTo.value = state.dateTo;
        syncTypePills();
        syncDomainPills();
    }

    // ---- Reset / Apply ----

    var resetBtn = document.getElementById("repFilterReset");
    if (resetBtn) {
        resetBtn.addEventListener("click", function () {
            state.domain = "network";
            state.type = "all";
            state.search = "";
            state.dateFrom = "";
            state.dateTo = "";
            state.page = 1;
            syncDraftFromState();
            applyDomainPanels();
            renderRows();
        });
    }

    var applyBtn = document.getElementById("repFilterApply");
    if (applyBtn) {
        applyBtn.addEventListener("click", function () {
            state.domain = draft.domain;
            state.type = draft.type;
            state.search = draft.search;
            state.dateFrom = draft.dateFrom;
            state.dateTo = draft.dateTo;
            state.page = 1;
            syncTypePills();
            applyDomainPanels();
            renderRows();
            closeFilter();
        });
    }

    // ---- Pagination ----

    if (paginationEl) {
        paginationEl.addEventListener("click", function (event) {
            var btn = event.target.closest("button");
            if (!btn || btn.disabled) return;
            var value = btn.getAttribute("data-page");
            if (value === "prev") {
                state.page = Math.max(1, state.page - 1);
            } else if (value === "next") {
                state.page = state.page + 1;
            } else {
                state.page = parseInt(value, 10) || 1;
            }
            renderRows();
        });
    }

    // ---- Device info popover ----

    var devicePop = document.getElementById("repDevicePop");

    function deviceMatches() {
        return reports.filter(function (r) { return true; }).length;
    }

    function deviceInfo() {
        var inv = (state.inventory || []).filter(function (e) {
            return e && e.device_name === DEVICE_NAME;
        })[0] || {};
        return {
            name: DEVICE_NAME,
            ip: inv.host_ip || "Not available",
            status: inv.status ? (inv.status === "live" ? "Live" : "Down") : "Unknown",
            clone: inv.clone_of || "",
            reports: deviceMatches()
        };
    }

    function closeDevicePop() {
        if (devicePop) devicePop.hidden = true;
    }

    function openDevicePop(anchor) {
        if (!devicePop) return;
        var info = deviceInfo();
        var rows = [
            ["Device", info.name],
            ["IP Address", info.ip],
            ["Status", info.status],
            ["Reports", info.reports + (info.reports === 1 ? " report" : " reports")]
        ];
        if (info.clone) rows.push(["Clone of", info.clone]);
        devicePop.innerHTML =
            '<div class="rep-device-pop-head">' +
            '<span class="rep-device-pop-name">' +
            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/></svg>' +
            escapeHtml(info.name) + "</span>" +
            '<button type="button" class="rep-device-pop-close" aria-label="Close">' +
            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M18 6L6 18M6 6l12 12"/></svg>' +
            "</button></div>" +
            rows.map(function (row) {
                return '<div class="rep-device-pop-row"><span>' + escapeHtml(row[0]) +
                    "</span><span>" + escapeHtml(row[1]) + "</span></div>";
            }).join("");

        devicePop.hidden = false;
        var rect = anchor.getBoundingClientRect();
        var popRect = devicePop.getBoundingClientRect();
        var left = Math.min(
            Math.max(12, rect.left),
            window.innerWidth - popRect.width - 12
        );
        var top = rect.bottom + 8;
        if (top + popRect.height > window.innerHeight - 12) {
            top = Math.max(12, rect.top - popRect.height - 8);
        }
        devicePop.style.left = left + "px";
        devicePop.style.top = top + "px";

        var closeBtn = devicePop.querySelector(".rep-device-pop-close");
        if (closeBtn) closeBtn.addEventListener("click", closeDevicePop);
    }

    body.addEventListener("click", function (event) {
        var btn = event.target.closest(".rep-device-info");
        if (!btn) return;
        event.stopPropagation();
        if (devicePop && !devicePop.hidden) {
            closeDevicePop();
        } else {
            openDevicePop(btn);
        }
    });
    document.addEventListener("click", function (event) {
        if (devicePop && !devicePop.hidden && !devicePop.contains(event.target)) {
            closeDevicePop();
        }
    });

    // ---- Inventory (device metadata for the info popover) ----

    function loadInventory() {
        fetch("/api/firewall-inventory", { headers: { "Accept": "application/json" } })
            .then(function (res) { return res.ok ? res.json() : Promise.reject(new Error("failed")); })
            .then(function (data) {
                state.inventory = (data && data.firewalls) || [];
            })
            .catch(function () {
                state.inventory = [];
            });
    }

    syncDraftFromState();
    applyDomainPanels();
    loadInventory();
    renderRows();
})();
