(function () {
    "use strict";

    var body = document.getElementById("autoJobsBody");
    var countEl = document.getElementById("autoJobsCount");
    var jobsById = {};

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

    function statusChip(status) {
        var ok = String(status || "").toLowerCase() === "successful";
        return '<span class="auto-job-status ' + (ok ? "is-ok" : "is-err") + '">' +
            esc(ok ? "Successful" : "Failed") + "</span>";
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
        return '<button type="button" class="auto-job-fail-dl" data-fail-dl="' + esc(job.id) + '" title="Download logs">' +
            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12"/><path d="M7 10l5 5 5-5"/><path d="M5 21h14"/></svg>' +
            "</button>";
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
                "<td>" + statusChip(op.status) + "</td>" +
                "</tr>";
        }).join("");
        return '<table class="auto-job-ops-table"><thead><tr>' +
            "<th>#</th><th>Change</th><th>Actions</th><th>Result</th><th>Status</th>" +
            "</tr></thead><tbody>" + rows + "</tbody></table>";
    }

    function render(jobs) {
        jobsById = {};
        (jobs || []).forEach(function (job) { jobsById[String(job.id)] = job; });
        countEl.textContent = (jobs.length || 0) + " job" + (jobs.length === 1 ? "" : "s");
        if (!jobs.length) {
            body.innerHTML = '<tr><td colspan="8" class="auto-jobs-empty">No Firewall Execution jobs yet. Execute a bulk workbook on Automation / Network Security.</td></tr>';
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
                "<td>" + esc(job.firewall_name || "—") + "</td>" +
                "<td>" + esc(joinList(job.actions)) + "</td>" +
                "<td>" + esc(joinList(job.playbooks)) + "</td>" +
                "<td>" + esc(job.created_display || "—") + "</td>" +
                "<td>" + statusChip(job.status) + "</td>" +
                "<td>" + logsCell(job) + "</td>" +
                "</tr>" +
                '<tr class="auto-job-ops" data-job-ops="' + esc(job.id) + '" hidden><td colspan="8">' +
                opsHtml(job) +
                "</td></tr>";
        }).join("");
    }

    body.addEventListener("click", function (e) {
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

    fetch("/api/automation/jobs")
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data && data.error) throw new Error(data.error);
            render(data.jobs || []);
        })
        .catch(function (err) {
            countEl.textContent = "0 jobs";
            body.innerHTML = '<tr><td colspan="8" class="auto-jobs-empty">Could not load jobs. ' +
                esc(err.message || "Request failed") + "</td></tr>";
        });
})();
