(function () {
    "use strict";

    var URLS = {
        info: "/api/netsec/info",
        template: "/api/netsec/workbook/template",
        upload: "/api/netsec/workbook",
        run: "/api/netsec/playbooks/run",
        jobs: "/api/automation/jobs"
    };

    var terminal = document.getElementById("autoNsTerminal");
    var terminalCard = document.getElementById("autoNsTerminalCard");
    var statusEl = document.getElementById("autoNsStatus");
    var modeEl = document.getElementById("autoNsMode");
    var downloadBtn = document.getElementById("autoNsDownload");
    var fileInput = document.getElementById("autoNsFile");
    var fileLabel = document.getElementById("autoNsFileLabel");
    var commitBtn = document.getElementById("autoNsCommit");
    var firewallSelect = document.getElementById("autoNsFirewall");

    var state = {
        info: null,
        summary: null,
        matches: [],
        workbookName: "",
        busy: false
    };

    function esc(value) {
        return String(value == null ? "" : value)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
    }

    function setStatus(text, kind) {
        statusEl.textContent = text;
        statusEl.className = "auto-ns-terminal-status" + (kind ? " is-" + kind : "");
    }

    function line(text, kind) {
        var span = document.createElement("span");
        if (kind) span.className = "auto-ns-line-" + kind;
        span.textContent = text + "\n";
        terminal.appendChild(span);
        terminal.scrollTop = terminal.scrollHeight;
    }

    function blank() {
        terminal.appendChild(document.createTextNode("\n"));
        terminal.scrollTop = terminal.scrollHeight;
    }

    function sheetKey(name) {
        return String(name || "").toLowerCase().replace(/\s+/g, "");
    }

    function matchPlaybooks(summary, info) {
        var sheets = {};
        ((summary && summary.sheets) || []).forEach(function (s) {
            sheets[sheetKey(s.sheet)] = s;
        });
        var matches = [];
        ((info && info.playbooks) || []).forEach(function (pb) {
            var sheet = sheets[sheetKey(pb.sheet)];
            if (sheet && sheet.rows) {
                matches.push({ playbook: pb, sheet: sheet });
            }
        });
        return matches;
    }

    function showTerminal() {
        if (terminalCard) terminalCard.hidden = false;
    }

    function renderMode(info) {
        if (!modeEl) return;
        if (!info || !info.configured) {
            modeEl.innerHTML = '<span class="auto-ns-pill auto-ns-pill-off">OFFLINE</span><span>Firewall Execution Agent is not connected.</span>';
            modeEl.hidden = false;
            return;
        }
        if (info.dry_run) {
            modeEl.innerHTML = '<span class="auto-ns-pill auto-ns-pill-warn">DRY RUN</span><span>Every change is previewed; nothing is sent to the firewall.</span>';
            modeEl.hidden = false;
            return;
        }
        modeEl.innerHTML = "";
        modeEl.hidden = true;
    }

    function selectedFirewall() {
        var option = firewallSelect && firewallSelect.options[firewallSelect.selectedIndex];
        if (!option || !option.value) return null;
        return {
            id: option.getAttribute("data-id") || option.value,
            host: option.getAttribute("data-host") || option.value,
            label: option.textContent || option.value,
            status: option.getAttribute("data-status") || ""
        };
    }

    function renderFirewalls(info) {
        if (!firewallSelect) return;
        var firewalls = (info && info.firewalls) || [];
        if (!firewalls.length) {
            firewallSelect.innerHTML = '<option value="">No managed firewalls</option>';
            firewallSelect.disabled = true;
            return;
        }
        firewallSelect.disabled = false;
        firewallSelect.innerHTML = firewalls.map(function (fw) {
            var host = fw.host || fw.host_ip || fw.host_name || "";
            var label = fw.label || ((fw.device_name || host) + (host && fw.device_name && fw.device_name !== host ? " (" + host + ")" : ""));
            var status = String(fw.status || "").toLowerCase();
            return '<option value="' + esc(fw.id || fw.device_name || host) + '"' +
                ' data-id="' + esc(fw.id || "") + '"' +
                ' data-host="' + esc(host) + '"' +
                ' data-status="' + esc(status) + '"' +
                (status === "live" ? " selected" : "") +
                ">" + esc(label) + (status ? " · " + status : "") + "</option>";
        }).join("");
        var live = firewalls.filter(function (fw) {
            return String(fw.status || "").toLowerCase() === "live";
        })[0];
        if (live) firewallSelect.value = live.id || live.device_name || live.host || "";
    }

    function logPreview(summary) {
        var changes = (summary && summary.changes) || [];
        var errors = (summary && summary.errors) || [];
        if (changes.length) {
            blank();
            line("Preview (" + changes.length + " change" + (changes.length === 1 ? "" : "s") + ")", "head");
            changes.forEach(function (item) {
                line(
                    (item.action || "create") + " " + (item.category || "object") + " " + (item.name || "(unnamed)") +
                    (item.source_sheet ? " · " + item.source_sheet + " row " + (item.source_row || "") : ""),
                    "muted"
                );
            });
        }
        errors.forEach(function (item) {
            line((item.sheet || "Workbook") + " row " + (item.row || "?") + ": " + (item.error || "Invalid row"), "err");
        });
    }

    function logUpload(summary, fileName) {
        line('Upload workbook "' + fileName + '"');
        blank();
        line("Workbook uploaded", "head");
        line(
            (summary.total_rows || 0) + " data row" + ((summary.total_rows || 0) === 1 ? "" : "s") +
            " across " + ((summary.sheets || []).length) + " sheet" +
            (((summary.sheets || []).length) === 1 ? "" : "s")
        );
        (summary.sheets || []).forEach(function (s) {
            line(s.sheet + " · " + s.rows + " row" + (s.rows === 1 ? "" : "s"), "muted");
        });
        blank();
        state.matches.forEach(function (item) {
            line(item.playbook.title + " (" + item.playbook.sheet + ", " + item.sheet.rows + " row" + (item.sheet.rows === 1 ? "" : "s") + ")");
        });
        if (!state.matches.length) {
            line("None of the uploaded sheets match a playbook in the catalogue.", "err");
        }
        logPreview(summary);
    }

    function unique(values) {
        var seen = [];
        (values || []).forEach(function (value) {
            var text = String(value == null ? "" : value).trim();
            if (text && seen.indexOf(text) === -1) seen.push(text);
        });
        return seen;
    }

    function rowAction(row) {
        var action = String((row && row.action) || "").trim();
        if (action) return action;
        var op = String((row && row.op) || "").trim();
        if (op && op.toLowerCase() !== "error" && op.toLowerCase() !== "skipped") return op;
        return "";
    }

    function opActions(data) {
        var actions = [];
        ((data && data.rows) || []).forEach(function (row) {
            var action = rowAction(row);
            if (action) actions.push(action);
        });
        var counts = (data && data.counts) || {};
        if (!actions.length) {
            if (counts.created) actions.push("create");
            if (counts.updated) actions.push("update");
            if (counts.deleted) actions.push("delete");
        }
        return unique(actions);
    }

    function opFailed(data) {
        return !!(data && (data.commit_error || ((data.counts || {}).errors)));
    }

    function rowErrors(data) {
        var errs = [];
        ((data && data.rows) || []).forEach(function (row) {
            if (row && row.error) {
                errs.push({
                    row: row.row != null ? row.row : null,
                    action: rowAction(row),
                    error: String(row.error)
                });
            }
        });
        return errs;
    }

    function failureReason(data, fallback) {
        var parts = [];
        if (data && data.commit_error) {
            parts.push("Commit failed: " + data.commit_error);
        }
        rowErrors(data).forEach(function (item) {
            parts.push((item.row != null ? "Row " + item.row + ": " : "") + item.error);
        });
        if (parts.length) return parts.join("; ");
        return fallback || "Playbook failed";
    }

    function nowIso() {
        return new Date().toISOString();
    }

    function logResult(item, data) {
        var counts = (data && data.counts) || {};
        line(item.playbook.title + " (" + item.playbook.sheet + ", " + item.sheet.rows + " row" + (item.sheet.rows === 1 ? "" : "s") + ")", "head");
        if (data && data.summary) line(data.summary);
        line(
            (counts.created || 0) + " created · " +
            (counts.updated || 0) + " updated · " +
            (counts.deleted || 0) + " deleted · " +
            (counts.errors || 0) + " errors",
            counts.errors ? "warn" : "muted"
        );
        if (data && data.committed) {
            line("Changes committed to the running firewall configuration.", "ok");
        } else if (data && data.commit_error) {
            line("Commit failed: " + data.commit_error, "err");
        } else if (data && data.dry_run) {
            line("Commit skipped: dry-run preview only.", "warn");
        }
        ((data && data.rows) || []).forEach(function (row) {
            if (row.error) {
                line("Row " + row.row + " error: " + row.error, "err");
            }
        });
        blank();
        return !opFailed(data);
    }

    function loadInfo() {
        return fetch(URLS.info)
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data && data.error) throw new Error(data.error);
                state.info = data;
                renderMode(data);
                renderFirewalls(data);
                if (!data.configured) setStatus("Offline", "err");
                else setStatus("Idle");
            })
            .catch(function () {
                renderMode(null);
                setStatus("Offline", "err");
            });
    }

    function setDownloadBusy(busy) {
        if (!downloadBtn) return;
        downloadBtn.classList.toggle("is-disabled", !!busy);
        if (busy) downloadBtn.setAttribute("aria-disabled", "true");
        else downloadBtn.removeAttribute("aria-disabled");
    }

    function downloadTemplate(event) {
        if (event) event.preventDefault();
        if (state.busy) return;
        state.busy = true;
        setDownloadBusy(true);
        setStatus("Preparing", "run");
        line("Preparing Excel template…", "muted");
        fetch(URLS.template)
            .then(function (r) {
                if (!r.ok) throw new Error("HTTP " + r.status);
                return r.blob();
            })
            .then(function (blob) {
                var url = URL.createObjectURL(blob);
                var a = document.createElement("a");
                a.href = url;
                a.download = "netsec-playbook-template.xlsx";
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                setTimeout(function () { URL.revokeObjectURL(url); }, 4000);
                line("Template downloaded — netsec-playbook-template.xlsx", "ok");
                if (window.showToast) window.showToast("Template downloaded - open it in Excel.", "success");
                setStatus("Idle");
            })
            .catch(function () {
                line("Could not download the template.", "err");
                if (window.showToast) window.showToast("Could not download the template.");
                setStatus("Failed", "err");
            })
            .finally(function () {
                state.busy = false;
                setDownloadBusy(false);
            });
    }

    function uploadWorkbook() {
        var file = fileInput.files && fileInput.files[0];
        if (!file || state.busy) return;
        state.busy = true;
        commitBtn.disabled = true;
        fileLabel.textContent = file.name;
        setStatus("Uploading", "run");
        var fd = new FormData();
        fd.append("file", file);
        fetch(URLS.upload, { method: "POST", body: fd })
            .then(function (r) {
                return r.json().then(function (d) { return { ok: r.ok, data: d }; });
            })
            .then(function (res) {
                if (!res.ok) throw new Error(res.data && res.data.error ? res.data.error : "Upload failed");
                state.summary = res.data.summary;
                state.workbookName = file.name;
                state.matches = matchPlaybooks(state.summary, state.info);
                showTerminal();
                logUpload(state.summary, file.name);
                var previewOk = state.matches.length && !((state.summary && state.summary.errors) || []).length;
                commitBtn.disabled = !(state.info && state.info.configured && previewOk);
                setStatus(previewOk ? "Ready" : "Failed", previewOk ? "ok" : "err");
            })
            .catch(function (err) {
                showTerminal();
                line("The workbook could not be uploaded. " + (err.message || "Upload failed."), "err");
                commitBtn.disabled = true;
                setStatus("Failed", "err");
                if (window.showToast) window.showToast(err.message || "Upload failed.");
            })
            .finally(function () {
                state.busy = false;
                fileInput.value = "";
            });
    }

    function runPlaybook(item) {
        return fetch(URLS.run, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ playbook_id: item.playbook.id, commit: true })
        }).then(function (r) {
            return r.json().then(function (d) { return { ok: r.ok, data: d }; });
        }).then(function (res) {
            if (!res.ok) throw new Error(res.data && res.data.error ? res.data.error : "Run failed");
            var pass = logResult(item, res.data);
            return {
                playbook_id: item.playbook.id,
                playbook_title: item.playbook.title,
                sheet: item.playbook.sheet,
                actions: opActions(res.data),
                counts: res.data.counts || {},
                committed: !!res.data.committed,
                commit_error: res.data.commit_error || "",
                summary: res.data.summary || "",
                row_errors: rowErrors(res.data),
                error_reason: pass ? "" : failureReason(res.data, "Playbook failed"),
                executed_at: nowIso(),
                status: pass ? "successful" : "failed"
            };
        }).catch(function (err) {
            line(item.playbook.title + " failed: " + (err.message || "Run failed"), "err");
            blank();
            return {
                playbook_id: item.playbook.id,
                playbook_title: item.playbook.title,
                sheet: item.playbook.sheet,
                actions: [],
                counts: { errors: 1 },
                committed: false,
                commit_error: err.message || "Run failed",
                summary: err.message || "Run failed",
                row_errors: [],
                error_reason: err.message || "Run failed",
                executed_at: nowIso(),
                status: "failed"
            };
        });
    }

    function commitAll() {
        if (state.busy || !state.matches.length) return;
        if (!(state.info && state.info.configured)) {
            line("Firewall Execution Agent is not connected.", "err");
            return;
        }
        var target = selectedFirewall();
        if (!target || !target.host) {
            line("Select a managed firewall before preparing the job.", "err");
            setStatus("Failed", "err");
            return;
        }
        if (((state.summary && state.summary.errors) || []).length) {
            line("Fix workbook preview errors before preparing the job.", "err");
            setStatus("Failed", "err");
            return;
        }
        state.busy = true;
        commitBtn.disabled = true;
        setDownloadBusy(true);
        setStatus("Preparing", "run");
        line("Execute", "head");
        line("Target " + target.label, "muted");
        line("Queuing a bulk firewall job. Watch status on the Jobs page.", "muted");
        blank();

        fetch(URLS.run, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                playbook_id: (state.matches[0] && state.matches[0].playbook && state.matches[0].playbook.id) || "",
                source_type: "automation_hub",
                source_name: state.workbookName || "Automation Hub",
                firewall_id: target.id || "",
                firewall_host: target.host || ""
            })
        }).then(function (r) {
            return r.json().then(function (d) { return { ok: r.ok, data: d }; });
        }).then(function (res) {
            if (!res.ok) throw new Error((res.data && res.data.error) || "Prepare failed");
            var data = res.data || {};
            var jobNumber = data.job_number || "";
            var ops = (data.changes || data.rows || []).length || ((data.counts && (data.counts.created + data.counts.updated + data.counts.deleted)) || 0);
            line("Queued " + ops + " operation(s) as " + (jobNumber || "a Jobs entry") + ".", "ok");
            if (data.operation) line("operation=" + data.operation + " source_type=" + (data.source_type || "automation_hub"), "muted");
            line("Open Automation Hub · Jobs to watch queued, running, successful, or failed.", "muted");
            setStatus("Queued", "ok");
            if (window.showToast) window.showToast("Job queued. Watch status on the Jobs page.", "success");
        }).catch(function (err) {
            line("The workbook job could not be prepared. " + (err.message || "Prepare failed."), "err");
            setStatus("Failed", "err");
            if (window.showToast) window.showToast(err.message || "Prepare failed.");
        }).finally(function () {
            state.busy = false;
            setDownloadBusy(false);
            var previewOk = state.matches.length && !((state.summary && state.summary.errors) || []).length;
            commitBtn.disabled = !(state.info && state.info.configured && previewOk);
        });
    }

    if (downloadBtn) downloadBtn.addEventListener("click", downloadTemplate);
    if (fileInput) fileInput.addEventListener("change", uploadWorkbook);
    if (commitBtn) commitBtn.addEventListener("click", commitAll);

    loadInfo();
})();
