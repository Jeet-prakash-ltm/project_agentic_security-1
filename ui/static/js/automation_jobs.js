(function () {
    "use strict";

    var body = document.getElementById("autoJobsBody");
    var countEl = document.getElementById("autoJobsCount");
    var logModal = document.getElementById("autoJobLogModal");
    var logTitle = document.getElementById("autoJobLogTitle");
    var logSub = document.getElementById("autoJobLogSub");
    var logBody = document.getElementById("autoJobLogBody");
    var logClose = document.getElementById("autoJobLogClose");
    var deviceModal = document.getElementById("autoJobDeviceModal");
    var deviceTitle = document.getElementById("autoJobDeviceTitle");
    var deviceSub = document.getElementById("autoJobDeviceSub");
    var deviceBody = document.getElementById("autoJobDeviceBody");
    var deviceClose = document.getElementById("autoJobDeviceClose");
    var numberInput = document.getElementById("autoJobsNumber");
    var deviceInput = document.getElementById("autoJobsDevice");
    var domainTabs = document.getElementById("autoJobsDomainTabs");
    var statusTabs = document.getElementById("autoJobsStatusTabs");
    var jobsById = {};
    var allJobs = [];
    var inventory = [];
    var filters = {
        number: "",
        domain: "all",
        device: "",
        status: "all"
    };

    function esc(value) {
        return String(value == null ? "" : value)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
    }

    function joinList(values) {
        return (values || []).filter(Boolean).join(", ") || "—";
    }

    function opActions(op) {
        var actions = (op && op.actions) || [];
        if (actions.length) return actions.filter(Boolean);
        if (op && op.action) return [op.action];
        var fromRows = [];
        (op && op.row_errors || []).forEach(function (item) {
            var action = item && item.action;
            if (action && fromRows.indexOf(action) === -1) fromRows.push(action);
        });
        return fromRows;
    }

    function failedOpCount(job) {
        return (job.operations || []).filter(isFailedOp).length;
    }

    function statusChip(status, failCount) {
        var ok = String(status || "").toLowerCase() === "successful";
        var label = ok ? "Successful" : "Failed";
        if (!ok && failCount) label += " (" + failCount + ")";
        return '<span class="auto-job-status ' + (ok ? "is-ok" : "is-err") + '">' +
            esc(label) + "</span>";
    }

    function countsText(counts) {
        counts = counts || {};
        return (counts.created || 0) + " created, " +
            (counts.updated || 0) + " updated, " +
            (counts.deleted || 0) + " deleted, " +
            (counts.errors || 0) + " errors";
    }

    function isFailedOp(op) {
        if (!op) return false;
        if (String(op.status || "").toLowerCase() === "failed") return true;
        if (op.commit_error) return true;
        return !!((op.counts || {}).errors);
    }

    function looksLikeSummary(text) {
        return /^applied playbook |^dry-run playbook /i.test(String(text || "").trim());
    }

    function opReason(op) {
        if (!isFailedOp(op)) return "Successful";
        var parts = [];
        if (op.commit_error) parts.push("Commit failed: " + op.commit_error);
        (op.row_errors || []).forEach(function (item) {
            if (!item) return;
            var msg = item.error || item;
            parts.push((item.row != null ? "Row " + item.row + ": " : "") + msg);
        });
        if (parts.length) return parts.join("; ");
        if (op.error_reason && !looksLikeSummary(op.error_reason)) return String(op.error_reason);
        var counts = op.counts || {};
        if (counts.errors) {
            return counts.errors + " row error(s) were reported, but the firewall error text was not stored for this job.";
        }
        return "Failed";
    }

    function opExecutedAt(op, job) {
        return op.executed_at || job.created_display || "";
    }

    function opStatusLabel(op) {
        return isFailedOp(op) ? "Failed" : "Successful";
    }

    function logsText(job) {
        var ops = job.operations || [];
        if (!ops.length) return "No operations recorded for this job.\n";
        return ops.map(function (op, index) {
            return [
                "order_of_execution: " + (index + 1),
                "change: " + (op.playbook_title || op.playbook_id || ""),
                "action: " + opActions(op).filter(Boolean).join(", "),
                "result: " + countsText(op.counts),
                "status: " + opStatusLabel(op),
                "reason: " + opReason(op),
                "time_of_execution: " + opExecutedAt(op, job)
            ].join("\n");
        }).join("\n\n");
    }

    function downloadLogs(job) {
        var blob = new Blob([logsText(job)], { type: "text/plain" });
        var url = URL.createObjectURL(blob);
        var a = document.createElement("a");
        a.href = url;
        a.download = (job.job_number || ("job-" + job.id)) + "-logs.txt";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(function () { URL.revokeObjectURL(url); }, 4000);
    }

    function logsCell(job) {
        if (!(job.operations || []).length) return "—";
        return '<div class="auto-job-log-actions">' +
            '<button type="button" class="auto-job-fail-dl" data-fail-dl="' + esc(job.id) + '" title="Download log">' +
            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12"/><path d="M7 10l5 5 5-5"/><path d="M5 21h14"/></svg>' +
            "</button>" +
            '<button type="button" class="auto-job-fail-dl" data-fail-view="' + esc(job.id) + '" title="View log">' +
            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>' +
            "</button>" +
            "</div>";
    }

    function openLogModal(job) {
        if (!logModal || !job) return;
        if (logTitle) logTitle.textContent = (job.job_number || "Job") + " log";
        if (logSub) {
            logSub.textContent = [job.firewall_name, job.created_display].filter(Boolean).join(" · ");
        }
        if (logBody) logBody.textContent = logsText(job);
        logModal.hidden = false;
    }

    function closeLogModal() {
        if (logModal) logModal.hidden = true;
    }

    function securityDomain(job) {
        var value = String((job && job.security_domain) || "").trim();
        if (/cloud/i.test(value)) return "Cloud security";
        return "Network security";
    }

    function normalizeToken(value) {
        return String(value == null ? "" : value).trim().toLowerCase();
    }

    function deviceTokens(value) {
        var text = String(value == null ? "" : value).trim();
        if (!text) return [];
        var tokens = [text];
        var match = text.match(/^(.*)\s+\(([^)]+)\)\s*$/);
        if (match) {
            tokens.push(match[1], match[2]);
        }
        return tokens.map(normalizeToken).filter(Boolean);
    }

    function findInventoryDevice(job) {
        var tokens = deviceTokens(job && job.firewall_name);
        if (!tokens.length) return null;
        var exact = null;
        var partial = null;
        (inventory || []).forEach(function (fw) {
            var fields = [
                fw.device_name,
                fw.host_ip,
                fw.host_name
            ].map(normalizeToken).filter(Boolean);
            if (fields.some(function (field) { return tokens.indexOf(field) !== -1; })) {
                exact = exact || fw;
                return;
            }
            if (!partial && fields.some(function (field) {
                return tokens.some(function (token) {
                    return field.indexOf(token) !== -1 || token.indexOf(field) !== -1;
                });
            })) {
                partial = fw;
            }
        });
        return exact || partial;
    }

    function deviceDisplayName(job) {
        var device = findInventoryDevice(job);
        if (device && device.device_name) return device.device_name;
        var label = String((job && job.firewall_name) || "").trim();
        if (!label) return "—";
        var match = label.match(/^(.*)\s+\(([^)]+)\)\s*$/);
        return match ? match[1] : label;
    }

    function deviceInfoRows(job) {
        var device = findInventoryDevice(job);
        if (!device) {
            return [
                ["Device name", deviceDisplayName(job)],
                ["IP", "—"],
                ["Status", "Not found in Asset Inventory"]
            ];
        }
        return [
            ["Device name", device.device_name || "—"],
            ["Device type", device.device_type || "Firewall"],
            ["Vendor", device.vendor || "Palo Alto Networks"],
            ["Host name", device.host_name || "—"],
            ["IP", device.host_ip || "—"],
            ["Port", device.port == null || device.port === "" ? "—" : String(device.port)],
            ["Status", device.status === "live" ? "Live" : "Down"]
        ];
    }

    function deviceCell(job) {
        return '<span class="auto-job-device">' +
            '<span>' + esc(deviceDisplayName(job)) + "</span>" +
            '<button type="button" class="auto-job-device-info" data-device-info="' + esc(job.id) + '" title="Device info" aria-label="Show device info">' +
            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 11v5"/><path d="M12 8h.01"/></svg>' +
            "</button></span>";
    }

    function openDeviceModal(job) {
        if (!deviceModal || !job) return;
        var name = deviceDisplayName(job);
        if (deviceTitle) deviceTitle.textContent = name === "—" ? "Device info" : name;
        if (deviceSub) {
            deviceSub.textContent = [securityDomain(job), job.created_display].filter(Boolean).join(" · ");
        }
        if (deviceBody) {
            deviceBody.innerHTML = deviceInfoRows(job).map(function (row) {
                return "<div><dt>" + esc(row[0]) + "</dt><dd>" + esc(row[1]) + "</dd></div>";
            }).join("");
        }
        deviceModal.hidden = false;
    }

    function closeDeviceModal() {
        if (deviceModal) deviceModal.hidden = true;
    }

    function jobStatusKey(job) {
        return String((job && job.status) || "").toLowerCase() === "successful" ? "successful" : "failed";
    }

    function jobDomainKey(job) {
        return /cloud/i.test(securityDomain(job)) ? "cloud" : "network";
    }

    function matchesFilters(job) {
        var number = normalizeToken(filters.number);
        if (number && normalizeToken(job.job_number).indexOf(number) === -1) return false;
        if (filters.domain !== "all" && jobDomainKey(job) !== filters.domain) return false;
        var device = normalizeToken(filters.device);
        if (device) {
            var haystack = [
                deviceDisplayName(job),
                job.firewall_name
            ].map(normalizeToken).join(" ");
            if (haystack.indexOf(device) === -1) return false;
        }
        if (filters.status !== "all" && jobStatusKey(job) !== filters.status) return false;
        return true;
    }

    function filteredJobs() {
        return (allJobs || []).filter(matchesFilters);
    }

    function setTab(group, value) {
        if (!group) return;
        var buttons = group.querySelectorAll(".auto-jobs-tab");
        for (var i = 0; i < buttons.length; i++) {
            var active = buttons[i].getAttribute("data-value") === value;
            buttons[i].classList.toggle("is-active", active);
            buttons[i].setAttribute("aria-selected", active ? "true" : "false");
        }
    }

    function opsHtml(job) {
        var ops = job.operations || [];
        if (!ops.length) {
            return '<div class="auto-jobs-empty">No operations recorded for this job.</div>';
        }
        var rows = ops.map(function (op, index) {
            return "<tr>" +
                "<td>" + (index + 1) + "</td>" +
                "<td>" + esc(op.playbook_title || op.playbook_id || "—") + "</td>" +
                "<td>" + esc(joinList(opActions(op))) + "</td>" +
                "<td>" + esc(countsText(op.counts)) + "</td>" +
                "<td>" + statusChip(op.status, (op.counts || {}).errors) + "</td>" +
                "</tr>";
        }).join("");
        return '<table class="auto-job-ops-table"><thead><tr>' +
            "<th>#</th><th>Change</th><th>Actions</th><th>Result</th><th>Status</th>" +
            "</tr></thead><tbody>" + rows + "</tbody></table>";
    }

    function render(jobs) {
        jobsById = {};
        (allJobs || []).forEach(function (job) { jobsById[String(job.id)] = job; });
        countEl.textContent = (jobs.length || 0) + " job" + (jobs.length === 1 ? "" : "s");
        if (!allJobs.length) {
            body.innerHTML = '<tr><td colspan="9" class="auto-jobs-empty">No Change Excution jobs yet. Execute a bulk workbook on Automation Hub / Network Security.</td></tr>';
            return;
        }
        if (!jobs.length) {
            body.innerHTML = '<tr><td colspan="9" class="auto-jobs-empty">No jobs match the selected filters.</td></tr>';
            return;
        }
        body.innerHTML = jobs.map(function (job) {
            var hasOps = (job.operations || []).length > 0;
            return '<tr class="auto-job-row" data-job="' + esc(job.id) + '">' +
                '<td><button type="button" class="auto-job-toggle" data-job-toggle="' + esc(job.id) + '"' +
                (hasOps ? "" : " disabled") + ' aria-expanded="false">' +
                '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M9 6l6 6-6 6"/></svg>' +
                "</button></td>" +
                '<td class="auto-job-number">' + esc(job.job_number) + "</td>" +
                "<td>" + esc(securityDomain(job)) + "</td>" +
                "<td>" + deviceCell(job) + "</td>" +
                "<td>" + esc(joinList(job.actions)) + "</td>" +
                "<td>" + esc(joinList(job.playbooks)) + "</td>" +
                "<td>" + esc(job.created_display || "—") + "</td>" +
                "<td>" + statusChip(job.status, failedOpCount(job)) + "</td>" +
                "<td>" + logsCell(job) + "</td>" +
                "</tr>" +
                '<tr class="auto-job-ops" data-job-ops="' + esc(job.id) + '" hidden><td colspan="9">' +
                opsHtml(job) +
                "</td></tr>";
        }).join("");
    }

    body.addEventListener("click", function (e) {
        var info = e.target.closest("[data-device-info]");
        if (info) {
            var infoJob = jobsById[info.getAttribute("data-device-info")];
            if (infoJob) openDeviceModal(infoJob);
            return;
        }
        var view = e.target.closest("[data-fail-view]");
        if (view) {
            var viewJob = jobsById[view.getAttribute("data-fail-view")];
            if (viewJob) openLogModal(viewJob);
            return;
        }
        var dl = e.target.closest("[data-fail-dl]");
        if (dl) {
            var job = jobsById[dl.getAttribute("data-fail-dl")];
            if (job) downloadLogs(job);
            return;
        }
        var btn = e.target.closest("[data-job-toggle]");
        if (!btn || btn.disabled) return;
        var id = btn.getAttribute("data-job-toggle");
        var row = body.querySelector('.auto-job-row[data-job="' + id + '"]');
        var ops = body.querySelector('[data-job-ops="' + id + '"]');
        if (!ops) return;
        var open = ops.hidden;
        ops.hidden = !open;
        if (row) row.classList.toggle("is-open", open);
        btn.setAttribute("aria-expanded", open ? "true" : "false");
    });

    if (logClose) logClose.addEventListener("click", closeLogModal);
    if (logModal) {
        logModal.addEventListener("click", function (e) {
            if (e.target === logModal) closeLogModal();
        });
    }
    if (deviceClose) deviceClose.addEventListener("click", closeDeviceModal);
    if (deviceModal) {
        deviceModal.addEventListener("click", function (e) {
            if (e.target === deviceModal) closeDeviceModal();
        });
    }

    function applyFilters() {
        render(filteredJobs());
    }

    if (numberInput) {
        numberInput.addEventListener("input", function () {
            filters.number = numberInput.value || "";
            applyFilters();
        });
    }
    if (deviceInput) {
        deviceInput.addEventListener("input", function () {
            filters.device = deviceInput.value || "";
            applyFilters();
        });
    }
    if (domainTabs) {
        domainTabs.addEventListener("click", function (e) {
            var tab = e.target.closest("[data-filter='domain']");
            if (!tab) return;
            filters.domain = tab.getAttribute("data-value") || "all";
            setTab(domainTabs, filters.domain);
            applyFilters();
        });
    }
    if (statusTabs) {
        statusTabs.addEventListener("click", function (e) {
            var tab = e.target.closest("[data-filter='status']");
            if (!tab) return;
            filters.status = tab.getAttribute("data-value") || "all";
            setTab(statusTabs, filters.status);
            applyFilters();
        });
    }
    document.addEventListener("keydown", function (e) {
        if (e.key === "Escape") {
            closeLogModal();
            closeDeviceModal();
        }
    });

    Promise.all([
        fetch("/api/automation/jobs").then(function (r) { return r.json(); }),
        fetch("/api/admin/firewalls", { headers: { "Accept": "application/json" } })
            .then(function (r) { return r.ok ? r.json() : { firewalls: [] }; })
            .catch(function () { return { firewalls: [] }; })
    ]).then(function (results) {
        var data = results[0] || {};
        inventory = (results[1] && results[1].firewalls) || [];
        if (data && data.error) throw new Error(data.error);
        allJobs = data.jobs || [];
        render(filteredJobs());
    }).catch(function (err) {
        countEl.textContent = "0 jobs";
        body.innerHTML = '<tr><td colspan="9" class="auto-jobs-empty">Could not load jobs. ' +
            esc(err.message || "Request failed") + "</td></tr>";
    });
})();
