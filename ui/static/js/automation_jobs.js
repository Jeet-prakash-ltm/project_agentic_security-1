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

    function failedOps(job) {
        return (job.operations || []).filter(isFailedOp);
    }

    function opReason(op) {
        if (op.error_reason) return String(op.error_reason);
        if (op.commit_error) return String(op.commit_error);
        if (op.summary && String(op.status || "").toLowerCase() === "failed") return String(op.summary);
        var counts = op.counts || {};
        if (counts.errors) return countsText(counts);
        return "Failed";
    }

    function opExecutedAt(op, job) {
        return op.executed_at || job.created_display || "";
    }

    function failurePayload(job) {
        return failedOps(job).map(function (op) {
            var index = (job.operations || []).indexOf(op);
            return {
                order_of_execution: index + 1,
                playbook: op.playbook_title || op.playbook_id || "",
                action: joinList(op.actions || [op.action]),
                sheet: op.sheet || "",
                result: countsText(op.counts),
                reason: opReason(op),
                time_of_execution: opExecutedAt(op, job)
            };
        });
    }

    function downloadFailures(job) {
        var payload = failurePayload(job);
        if (!payload.length) return;
        var blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
        var url = URL.createObjectURL(blob);
        var a = document.createElement("a");
        a.href = url;
        a.download = (job.job_number || ("job-" + job.id)) + "-failures.json";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(function () { URL.revokeObjectURL(url); }, 4000);
    }

    function failuresCell(job) {
        var n = failedOps(job).length;
        if (!n) return "—";
        return '<button type="button" class="auto-job-fail-dl" data-fail-dl="' + esc(job.id) + '" title="Download failed executions JSON">' +
            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v12"/><path d="M7 10l5 5 5-5"/><path d="M5 21h14"/></svg>' +
            "<span>" + n + "</span></button>";
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
        jobsById = {};
        (jobs || []).forEach(function (job) { jobsById[String(job.id)] = job; });
        countEl.textContent = (jobs.length || 0) + " job" + (jobs.length === 1 ? "" : "s");
        if (!jobs.length) {
            body.innerHTML = '<tr><td colspan="9" class="auto-jobs-empty">No Firewall Execution jobs yet. Commit a bulk workbook on Automation / Network Security.</td></tr>';
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
                "<td>" + failuresCell(job) + "</td>" +
                "</tr>" +
                '<tr class="auto-job-ops" data-job-ops="' + esc(job.id) + '" hidden><td colspan="9">' +
                opsHtml(job) +
                "</td></tr>";
        }).join("");
    }

    body.addEventListener("click", function (e) {
        var dl = e.target.closest("[data-fail-dl]");
        if (dl) {
            var job = jobsById[dl.getAttribute("data-fail-dl")];
            if (job) downloadFailures(job);
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
            body.innerHTML = '<tr><td colspan="9" class="auto-jobs-empty">Could not load jobs. ' +
                esc(err.message || "Request failed") + "</td></tr>";
        });
})();
