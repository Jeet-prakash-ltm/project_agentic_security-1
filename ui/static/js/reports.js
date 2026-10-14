(function () {
    "use strict";

    var body = document.getElementById("reportHistoryBody");
    var countEl = document.getElementById("reportsCount");
    var chips = document.getElementById("reportTypeChips");
    var paginationEl = document.getElementById("reportsPagination");
    if (!body || !chips) return;

    var DEFAULT_FW = "all";
    var PAGE_SIZE = 8;
    var state = {
        firewall: DEFAULT_FW,
        type: "all",
        page: 1,
        inventory: []
    };

    var requested = new URLSearchParams(window.location.search).get("firewall");
    if (requested) state.firewall = requested;

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

    function statusClass(report) {
        if (report.status === "Failed") return "status-fail";
        if (report.status === "Completed") return "status-on";
        return "status-warn";
    }

    function firewallLabel(firewall) {
        if (!firewall) return "\u2014";
        if (firewall === "estate") return "Estate (all devices)";
        return firewall;
    }

    function filteredReports() {
        return (window.REPORT_DATA || []).filter(function (report) {
            if (state.type !== "all" && (report.type || "") !== state.type) return false;
            if (state.firewall === "all") return true;
            return (report.firewall || "") === state.firewall;
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
            var isAll = state.firewall === "all";
            var label = isAll ? "" : " for <strong>" + escapeHtml(state.firewall) + "</strong>";
            body.innerHTML =
                "<tr><td colspan=\"7\" class=\"empty-state\">" +
                "No Executive Summary or Workbook generated" + label +
                " yet. Open the AI Workspace to create one." +
                '<div class="reports-empty-action"><a href="/workspace" class="btn btn-primary">Open AI Workspace</a></div>' +
                "</td></tr>";
            renderPagination(1);
            return;
        }

        var start = (state.page - 1) * PAGE_SIZE;
        var pageItems = list.slice(start, start + PAGE_SIZE);

        var html = "";
        pageItems.forEach(function (report) {
            var isSummary = report.type === "Executive Summary";
            var statusClassValue = statusClass(report);
            var icon = isSummary ? "PDF" : "XLS";
            var iconClass = isSummary ? "file-icon-purple" : "file-icon-green";
            var download = report.download_url
                ? '<a class="rep-action-btn" href="/static/' + encodeURIComponent(report.download_url) +
                    '" download title="Download"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12M7 10l5 5 5-5"/><path d="M4 21h16"/></svg></a>'
                : '<span class="rep-action-btn muted" title="No file available"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12M7 10l5 5 5-5"/><path d="M4 21h16"/></svg></span>';
            html +=
                "<tr>" +
                '<td><span class="report-name"><span class="file-icon ' + iconClass + '">' + icon + "</span>" +
                escapeHtml(report.name || "") + "</span></td>" +
                '<td><span class="tag">' + escapeHtml(report.type || "") + "</span></td>" +
                "<td>" + escapeHtml(firewallLabel(report.firewall)) + "</td>" +
                "<td>" + escapeHtml(formatTs(report.ts)) + "</td>" +
                '<td><span class="status-chip ' + statusClassValue + '">' + escapeHtml(report.status || "Completed") + "</span></td>" +
                "<td>" + escapeHtml(report.size || "\u2014") + "</td>" +
                '<td class="text-right"><span class="rep-row-actions">' + download + "</span></td>" +
                "</tr>";
        });
        body.innerHTML = html;
        renderPagination(totalPages);
    }

    // ---- Report type chips ----

    function syncChips() {
        chips.querySelectorAll(".chip").forEach(function (c) {
            var on = c.getAttribute("data-value") === state.type;
            c.classList.toggle("is-active", on);
            c.setAttribute("aria-selected", on ? "true" : "false");
        });
    }

    chips.addEventListener("click", function (event) {
        var chip = event.target.closest(".chip");
        if (!chip) return;
        state.type = chip.getAttribute("data-value") || "all";
        state.page = 1;
        syncChips();
        renderRows();
    });

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

    // ---- Domain navigation (Network Security / Cloud Security) ----

    var domainNav = document.getElementById("reportsDomainNav");
    var networkPanel = document.getElementById("reportsDomainNetwork");
    var cloudPanel = document.getElementById("reportsDomainCloud");

    if (domainNav) {
        domainNav.addEventListener("click", function (event) {
            var button = event.target.closest(".reports-domain-btn");
            if (!button) return;
            var domain = button.getAttribute("data-domain") || "network";
            domainNav.querySelectorAll(".reports-domain-btn").forEach(function (b) {
                var on = b === button;
                b.classList.toggle("is-active", on);
                b.setAttribute("aria-pressed", on ? "true" : "false");
            });
            if (networkPanel) networkPanel.hidden = domain !== "network";
            if (cloudPanel) cloudPanel.hidden = domain !== "cloud";
        });
    }

    // ---- Firewall estate search combobox ----

    var input = document.getElementById("repFwInput");
    var list = document.getElementById("repFwList");
    var clear = document.getElementById("repFwClear");
    var wrap = document.getElementById("repCombobox");

    function inventorySource() {
        return (state.inventory || []).filter(function (e) { return e && e.device_name; });
    }

    function comboRows(query) {
        var q = String(query || "").trim().toLowerCase();
        var out = '<li class="rep-combo-row' + (state.firewall === "all" ? " is-active" : "") +
            '" role="option" data-value="all">' +
            '<span class="rep-combo-name">All devices</span>' +
            '<span class="rep-combo-sub">Every report across the managed estate</span></li>';
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

    function reflectFirewallUI() {
        if (!input) return;
        if (state.firewall === "all") {
            input.value = "";
            input.placeholder = "All devices \u2014 search estate";
        } else {
            input.value = state.firewall;
            input.placeholder = "";
        }
        if (clear) clear.hidden = state.firewall === "all";
    }

    function setFirewall(value) {
        state.firewall = value || "all";
        state.page = 1;
        reflectFirewallUI();
        renderRows();
    }

    if (wrap && input && list) {
        function close() {
            list.hidden = true;
            input.setAttribute("aria-expanded", "false");
            document.removeEventListener("click", outside);
        }
        function outside(e) {
            if (!wrap.contains(e.target)) close();
        }
        function open(filter) {
            document.removeEventListener("click", outside);
            list.innerHTML = comboRows(filter ? input.value : "");
            list.hidden = false;
            input.setAttribute("aria-expanded", "true");
            document.addEventListener("click", outside);
        }
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
                reflectFirewallUI();
            })
            .catch(function () {
                state.inventory = [];
                reflectFirewallUI();
            });
    }

    reflectFirewallUI();
    loadInventory();
    renderRows();
})();
