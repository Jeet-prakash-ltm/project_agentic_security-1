(function () {
    "use strict";

    var URLS = {
        info: "/api/netsec/info",
        template: "/api/netsec/workbook/template",
        upload: "/api/netsec/workbook",
        run: "/api/netsec/playbooks/run"
    };

    var terminal = document.getElementById("autoNsTerminal");
    var statusEl = document.getElementById("autoNsStatus");
    var modeEl = document.getElementById("autoNsMode");
    var downloadBtn = document.getElementById("autoNsDownload");
    var fileInput = document.getElementById("autoNsFile");
    var fileLabel = document.getElementById("autoNsFileLabel");
    var summaryEl = document.getElementById("autoNsSummary");
    var commitBtn = document.getElementById("autoNsCommit");

    var state = {
        info: null,
        summary: null,
        matches: [],
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

    function renderMode(info) {
        if (!info || !info.configured) {
            modeEl.innerHTML = '<span class="auto-ns-pill auto-ns-pill-off">OFFLINE</span><span>Firewall Execution Agent is not connected.</span>';
            return;
        }
        if (info.dry_run) {
            modeEl.innerHTML = '<span class="auto-ns-pill auto-ns-pill-warn">DRY RUN</span><span>Every change is previewed; nothing is sent to the firewall.</span>';
            return;
        }
        modeEl.innerHTML = '<span class="auto-ns-pill auto-ns-pill-apply">APPLY</span><span>Commit writes changes to the firewall candidate configuration.</span>';
    }

    function renderSummary(summary) {
        if (!summary) {
            summaryEl.hidden = true;
            summaryEl.innerHTML = "";
            return;
        }
        var chips = (summary.sheets || []).map(function (s) {
            return '<span class="auto-ns-chip">' + esc(s.sheet) + " · " + esc(s.rows) + " row" + (s.rows === 1 ? "" : "s") + "</span>";
        }).join("");
        summaryEl.innerHTML =
            '<div class="auto-ns-summary-title">Workbook uploaded · ' +
            esc(summary.total_rows) + " data row" + (summary.total_rows === 1 ? "" : "s") +
            " across " + esc((summary.sheets || []).length) + " sheet" +
            ((summary.sheets || []).length === 1 ? "" : "s") + "</div>" +
            '<div class="auto-ns-chips">' + chips + "</div>";
        summaryEl.hidden = false;
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
        if (state.info && state.info.configured) {
            if (state.info.dry_run) {
                line("DRY RUN", "warn");
                line("Every change is previewed; nothing is sent to the firewall.", "muted");
            } else {
                line("APPLY", "ok");
                line("Running writes changes and commits them to the firewall candidate configuration.", "muted");
            }
        }
        blank();
        state.matches.forEach(function (item) {
            line(item.playbook.title + " (" + item.playbook.sheet + ", " + item.sheet.rows + " row" + (item.sheet.rows === 1 ? "" : "s") + ")");
        });
        if (!state.matches.length) {
            line("None of the uploaded sheets match a playbook in the catalogue.", "err");
        }
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
        (data.rows || []).forEach(function (row) {
            if (row.error) {
                line("Row " + row.row + " error: " + row.error, "err");
            }
        });
        blank();
        return !(data && (data.commit_error || (data.counts && data.counts.errors)));
    }

    function loadInfo() {
        return fetch(URLS.info)
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data && data.error) throw new Error(data.error);
                state.info = data;
                renderMode(data);
                line("Bulk operation", "head");
                line("Download the Excel workbook template, fill in one row per firewall change, then upload it to run a sheet against the firewall.", "muted");
                blank();
                if (!data.configured) {
                    line("Firewall Execution Agent is not connected.", "err");
                    setStatus("Offline", "err");
                } else if (data.dry_run) {
                    line("DRY RUN", "warn");
                    line("Every change is previewed; nothing is sent to the firewall.", "muted");
                    setStatus("Idle");
                } else {
                    line("APPLY", "ok");
                    line("Running writes changes and commits them to the firewall candidate configuration.", "muted");
                    setStatus("Idle");
                }
                blank();
            })
            .catch(function (err) {
                renderMode(null);
                line("Could not reach the Firewall Execution Agent.", "err");
                line(err.message || "Service unavailable", "muted");
                setStatus("Offline", "err");
            });
    }

    function downloadTemplate() {
        if (state.busy) return;
        state.busy = true;
        downloadBtn.disabled = true;
        setStatus("Preparing", "run");
        line("Preparing bulk ops template…", "muted");
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
                downloadBtn.disabled = false;
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
                state.matches = matchPlaybooks(state.summary, state.info);
                renderSummary(state.summary);
                logUpload(state.summary, file.name);
                commitBtn.disabled = !(state.info && state.info.configured && state.matches.length);
                setStatus("Ready", state.matches.length ? "ok" : "err");
            })
            .catch(function (err) {
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
            return logResult(item, res.data);
        }).catch(function (err) {
            line(item.playbook.title + " failed: " + (err.message || "Run failed"), "err");
            blank();
            return false;
        });
    }

    function commitAll() {
        if (state.busy || !state.matches.length) return;
        if (!(state.info && state.info.configured)) {
            line("Firewall Execution Agent is not connected.", "err");
            return;
        }
        state.busy = true;
        commitBtn.disabled = true;
        downloadBtn.disabled = true;
        setStatus("Committing", "run");
        line("Commit", "head");
        line("Running uploaded sheets against the firewall.", "muted");
        blank();

        var chain = Promise.resolve(true);
        var ok = true;
        state.matches.forEach(function (item) {
            chain = chain.then(function () {
                return runPlaybook(item).then(function (pass) {
                    if (!pass) ok = false;
                });
            });
        });
        chain.then(function () {
            if (ok) {
                line("Bulk operation completed.", "ok");
                setStatus("Completed", "ok");
                if (window.showToast) window.showToast("Bulk operation completed.", "success");
            } else {
                line("Bulk operation finished with errors.", "err");
                setStatus("Failed", "err");
                if (window.showToast) window.showToast("Bulk operation finished with errors.");
            }
        }).finally(function () {
            state.busy = false;
            downloadBtn.disabled = false;
            commitBtn.disabled = !(state.info && state.info.configured && state.matches.length);
        });
    }

    if (downloadBtn) downloadBtn.addEventListener("click", downloadTemplate);
    if (fileInput) fileInput.addEventListener("change", uploadWorkbook);
    if (commitBtn) commitBtn.addEventListener("click", commitAll);

    loadInfo();
})();
