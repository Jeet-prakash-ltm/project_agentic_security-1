(function () {
    "use strict";

    var body = document.getElementById("autoJobsBody");
    var countEl = document.getElementById("autoJobsCount");

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

    function opsHtml(job) {
        var ops = job.operations || [];
        if (!ops.length) {
            return '<div class="auto-jobs-empty">No playbook operations recorded for this job.</div>';
        }
        var rows = ops.map(function (op, index) {
            return "<tr>" +
                "<td>" + (index + 1) + "</td>" +
                "<td>" + esc(op.playbook_title || op.playbook_id || "—") + "</td>" +
                "<td>" + esc(joinList(op.actions || [op.action])) + "</td>" +
                "<td>" + esc(op.sheet || "—") + "</td>" +
                "<td>" + esc(countsText(op.counts)) + "</td>" +
                "<td>" + statusChip(op.status) + "</td>" +
                "</tr>";
        }).join("");
        return '<table class="auto-job-ops-table"><thead><tr>' +
            "<th>#</th><th>Playbook</th><th>Actions</th><th>Sheet</th><th>Result</th><th>Status</th>" +
            "</tr></thead><tbody>" + rows + "</tbody></table>";
    }

    function render(jobs) {
        countEl.textContent = (jobs.length || 0) + " job" + (jobs.length === 1 ? "" : "s");
        if (!jobs.length) {
            body.innerHTML = '<tr><td colspan="8" class="auto-jobs-empty">No Firewall Execution jobs yet. Commit a bulk workbook on Automation · Network Security.</td></tr>';
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
                "<td>" + esc(joinList(job.sheets)) + "</td>" +
                "<td>" + esc(job.created_display || "—") + "</td>" +
                "<td>" + statusChip(job.status) + "</td>" +
                "</tr>" +
                '<tr class="auto-job-ops" data-job-ops="' + esc(job.id) + '" hidden><td colspan="8">' +
                opsHtml(job) +
                "</td></tr>";
        }).join("");
    }

    body.addEventListener("click", function (e) {
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
