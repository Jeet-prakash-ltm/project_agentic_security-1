(function () {
    "use strict";

    var body = document.getElementById("reportHistoryBody");
    var countEl = document.getElementById("reportsCount");
    var chips = document.getElementById("reportTypeChips");
    if (!body || !chips) return;

    var DEFAULT_FW = "all";
    var state = {
        firewall: DEFAULT_FW,
        type: "all",
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

    function renderRows() {
        var list = (window.REPORT_DATA || []).filter(function (report) {
            if (state.type !== "all" && (report.type || "") !== state.type) return false;
            if (state.firewall === "all") return true;
            return (report.firewall || "") === state.firewall;
        });

        if (countEl) {
            countEl.textContent = list.length + (list.length === 1 ? " report" : " reports");
        }

        if (!list.length) {
            var isAll = state.firewall === "all";
            var label = isAll ? "" : " for <strong>" + escapeHtml(state.firewall) + "</strong>";
            body.innerHTML =
                "<tr><td colspan=\"7\" class=\"empty-state\">" +
                "No Executive Summary or Workbook generated" + label +
                " yet. Open the AI Workspace to create one." +
                '<div class="reports-empty-action"><a href="/workspace" class="btn btn-primary">Open AI Workspace</a></div>' +
                "</td></tr>";
            return;
        }

        var html = "";
        list.forEach(function (report) {
            var isSummary = report.type === "Executive Summary";
            var statusClassValue = statusClass(report);
            var icon = isSummary ? "PDF" : "XLS";
            var iconClass = isSummary ? "file-icon-purple" : "file-icon-green";
            var download = report.download_url
                ? '<a class="icon-btn" href="/static/' + encodeURIComponent(report.download_url) +
                    '" download title="Download"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12M7 10l5 5 5-5"/><path d="M4 21h16"/></svg></a>'
                : '<span class="icon-btn muted" title="No file available"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12M7 10l5 5 5-5"/><path d="M4 21h16"/></svg></span>';
            html +=
                "<tr>" +
                '<td><span class="report-name"><span class="file-icon ' + iconClass + '">' + icon + "</span>" +
                escapeHtml(report.name || "") + "</span></td>" +
                '<td><span class="tag">' + escapeHtml(report.type || "") + "</span></td>" +
                "<td>" + escapeHtml(firewallLabel(report.firewall)) + "</td>" +
                "<td>" + escapeHtml(formatTs(report.ts)) + "</td>" +
                '<td><span class="status-chip ' + statusClassValue + '">' + escapeHtml(report.status || "Completed") + "</span></td>" +
                "<td>" + escapeHtml(report.size || "\u2014") + "</td>" +
                '<td class="text-right">' + download + "</td>" +
                "</tr>";
        });
        body.innerHTML = html;
    }

    // ---- Report type chips ----

    function syncChips() {
        chips.querySelectorAll(".chip").forEach(function (c) {
            c.classList.toggle("is-active", c.getAttribute("data-value") === state.type);
        });
    }

    chips.addEventListener("click", function (event) {
        var chip = event.target.closest(".chip");
        if (!chip) return;
        state.type = chip.getAttribute("data-value") || "all";
        syncChips();
        renderRows();
    });

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
