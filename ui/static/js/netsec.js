/* Firewall Execution Agent - chat-first manual & bulk firewall operations.
 *
 * Loaded before workspace.js. It exposes window.NetsecPanel, the namespace
 * workspace.js calls for agent detection, activation and chat action runs
 * ("Action" chip -> manual / bulk operation chooser).
 *
 * All in-chat UI is appended through the window.WsChat bridge that workspace.js
 * registers, so flows live on the Firewall Execution Agent conversation itself.
 *
 * Backend contract (app.py / services/netsec_service.py):
 *   GET  /api/netsec/info                -> config + playbook catalogue
 *   GET  /api/netsec/workbook/template   -> .xlsx template (blob download)
 *   POST /api/netsec/workbook            -> save uploaded workbook -> summary
 *   POST /api/netsec/playbooks/run       -> run a playbook -> per-row results
 *   POST /api/netsec/manual              -> run a single chat row -> results
 */
(function () {
    "use strict";

    var NETSEC_AGENT_ID = "netsec-execution-agent";
    var state = { info: null, uploading: false };

    /* Enum picker options keyed by workbook column header. */
    var ENUM_FIELDS = {
        "Address Type": ["ip-netmask", "ip-range", "fqdn"],
        "Group Type": ["static", "dynamic"],
        "Protocol": ["tcp", "udp", "sctp"],
        "Type": ["layer3", "layer2", "tap", "virtual-wire", "external"],
        "Version": ["ipv4", "ipv6"],
        "Next Hop Type": ["ip-address", "discard", "next-vr", "fqdn"],
        "Rule Action": ["allow", "deny", "drop", "reset-client", "reset-server", "reset-both"],
        "NAT Type": ["source", "destination"],
        "Source Translation": ["dynamic-ip-and-port", "dynamic-ip", "static-ip"],
        "Enable User Identification": ["yes", "no"],
        "Disabled": ["no", "yes"],
        "Ping": ["yes", "no"],
        "Telnet": ["yes", "no"],
        "SSH": ["yes", "no"],
        "HTTPS": ["yes", "no"],
        "HTTP": ["yes", "no"],
        "SNMP": ["yes", "no"],
        "Response Pages": ["yes", "no"]
    };

    /* Columns that take a comma-separated member list. */
    var LIST_FIELDS = {
        "Tags": true, "Members": true, "Interfaces": true, "IP Addresses": true,
        "From": true, "To": true, "Source": true, "Destination": true,
        "Users": true, "Applications": true, "Services": true, "Categories": true,
        "Source Translated Address": true
    };

    /* Identifying columns; the only fields delete actually reads. */
    var IDENTITY = {
        "network-interfaces": ["Interface"],
        "network-static-routes": ["Name", "Virtual Router"],
        "default": ["Name"]
    };

    var URLS = {
        info: "/api/netsec/info",
        template: "/api/netsec/workbook/template",
        upload: "/api/netsec/workbook",
        run: "/api/netsec/playbooks/run",
        manual: "/api/netsec/manual"
    };

    var ICON_DOWNLOAD = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/></svg>';
    var ICON_UPLOAD = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><path d="M17 8l-5-5-5 5"/><path d="M12 3v12"/></svg>';
    var ICON_RUN = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M7 17L17 7M9 7h8v8"/></svg>';
    var ICON_BACK = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5"/><path d="M11 18l-6-6 6-6"/></svg>';

    function backControlHtml() {
        return '<div class="ws-fw-back-wrap"><button type="button" class="ws-back-run" data-fw-back="1">' + ICON_BACK + "Back</button></div>";
    }

    /* ---------------------------------------------------------------- utils */

    function esc(value) {
        return String(value == null ? "" : value)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
    }

    function toast(msg, kind) {
        if (window.showToast) window.showToast(msg, kind || "error");
    }

    function chat() {
        return window.WsChat || null;
    }

    function isNetsecId(id) {
        return id === NETSEC_AGENT_ID;
    }

    function isNetsecAgent(agent) {
        if (!agent) return false;
        var text = String(agent.id || "") + " " + String(agent.name || "") + " " + String(agent.type || "");
        return isNetsecId(agent.id) || /netsec|execution/i.test(text);
    }

    function nsSession() {
        var bridge = chat();
        if (!bridge) return false;
        var agent = bridge.activeAgent();
        if (!agent) return true;
        return isNetsecAgent(agent);
    }

    function cardHead(title, subtitle) {
        return '<div class="ws-mcq-head"><strong>' + esc(title) + "</strong><span>" + esc(subtitle || "") + "</span></div>";
    }

    function noteHtml(text) {
        return '<p class="ns-note-text">' + text + "</p>";
    }

    /* ------------------------------------------------------------ info / config */

    function loadInfo(force) {
        if (state.info && !force) return Promise.resolve(state.info);
        return fetch(URLS.info)
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data && data.error) throw new Error(data.error);
                state.info = data;
                return data;
            })
            .catch(function (err) {
                state.info = null;
                throw (err && err.message) ? err : new Error("Could not reach the NetSec service.");
            });
    }

    function modeNote(info) {
        if (!info || !info.configured) return "";
        if (info.dry_run) {
            return '<span class="ns-pill ns-pill-warn">DRY RUN</span><span class="ns-note-text">Every change is previewed; nothing is sent to the firewall. Apply mode requires NETSEC_FW_DRY_RUN=0.</span>';
        }
        return '<span class="ns-pill ns-pill-apply">APPLY</span><span class="ns-note-text">Running writes changes and commits them to the firewall candidate configuration.</span>';
    }

    function connErrorHtml(info) {
        var missing = (info && info.missing) || [];
        var missingHtml = missing.length
            ? "<code>" + missing.map(esc).join("</code>, <code>") + "</code>"
            : "configuration";
        return '<div class="ws-mcq-card">' +
            '<div class="ws-mcq-head"><strong>Firewall not connected</strong>' +
            "<span>The Firewall Execution agent could not reach a Palo Alto firewall.</span></div>" +
            '<div class="ns-block">' + noteHtml(
                "The platform is missing " + missingHtml +
                 ". Set these on the App Service (NETSEC_FUNCTION_KEY, or NETSEC_FW_*), then reload this page."
            ) + "</div></div>";
    }

    function playbookById(id) {
        if (!state.info || !state.info.playbooks) return null;
        for (var i = 0; i < state.info.playbooks.length; i++) {
            if (state.info.playbooks[i].id === id) return state.info.playbooks[i];
        }
        return null;
    }

    function withInfo(cb) {
        if (state.info) { cb(state.info); return; }
        loadInfo().then(cb).catch(function () { cb(null); });
    }

    function identityFor(playbookId) {
        return (IDENTITY[playbookId] || IDENTITY.default).slice();
    }

    /* ------------------------------------------------------------ shared helpers */

    function persist(pair) {
        var bridge = chat();
        if (!bridge || !pair || !pair.length) return Promise.resolve();
        return bridge.persist(pair);
    }

    function opWord(op) {
        return { create: "Create", update: "Update", delete: "Delete" }[op] || "Change";
    }

    function primaryName(row) {
        return (row && (row.Name || row.Interface || row["Virtual Router"] || row.Destination)) || "";
    }

    function describeRow(pb, op, row) {
        var name = primaryName(row);
        return opWord(op) + " " + (pb ? pb.title : "object") + (name ? ": " + name : "");
    }

    /* ------------------------------------------------------------ run results html */

    function countChip(n, label, warn) {
        n = n || 0;
        return '<span class="netsec-count' + (warn && n ? " netsec-count-warn" : "") + '">' + n + " " + label + "</span>";
    }

    function resultsHtml(data) {
        var c = data.counts || {};
        var dry = !!data.dry_run;
        var badgeClass = dry ? "netsec-ok" : (c.errors ? "netsec-partial" : "netsec-ok");
        var pill = dry ? "Dry-run" : (c.errors ? "Applied with errors" : "Applied");

        var html = '<div class="netsec-result-card">' +
            '<div class="netsec-result-head"><span class="netsec-result-title">' + esc(data.playbook_title || data.playbook_id || "Playbook") + "</span>" +
            '<span class="netsec-pill ' + badgeClass + '">' + esc(pill) + "</span></div>" +
            '<div class="netsec-result-counts">' +
            countChip(c.created, "created", false) + countChip(c.updated, "updated", false) +
            countChip(c.deleted, "deleted", false) + countChip(c.errors, "errors", true) +
            "</div>" +
            (data.summary ? "<p class=\"netsec-result-summary\">" + esc(data.summary) + "</p>" : "") +
            (data.committed
                ? '<p class="netsec-commit netsec-commit-ok">Changes committed to the running firewall configuration.</p>'
                : (data.commit_error
                    ? '<p class="netsec-commit netsec-commit-err">Commit failed: ' + esc(data.commit_error) + "</p>"
                    : "")) +
            (data.host ? '<p class="netsec-result-meta">Firewall: ' + esc(data.host) + "</p>" : "") +
            "</div>";

        var rows = data.rows || [];
        if (!rows.length) return html;

        var head = "<tr><th>Row</th><th>Op</th><th>Object</th><th>Detail</th></tr>";
        var body = rows.map(function (row) {
            var op = row.op === "error" ? "error" : (row.dry_run ? "dry-run" : row.op);
            var name = row.error ? "Error" : (row.kind ? row.kind : "");
            var detail = row.error || row.detail || "";
            return "<tr><td>" + esc(row.row) + "</td>" +
                "<td><span class=\"netsec-op netsec-op-" + esc(op) + "\">" + esc(op) + "</span></td>" +
                "<td>" + esc(name) + (row.name ? " <code>" + esc(row.name) + "</code>" : "") + "</td>" +
                "<td class=\"netsec-cell-detail\">" + esc(detail) + "</td></tr>";
        }).join("");
        return html + '<div class="netsec-results-table"><table><thead>' + head + "</thead><tbody>" + body + "</tbody></table></div>";
    }

    function resultMessage(data, pb) {
        var bridge = chat();
        if (data && data.error) {
            return bridge.assistantHtml(
                '<div class="ws-mcq-card"><div class="ws-mcq-head"><strong>' + esc(describeRow(pb, (data.op || "create"), (data.row || {}))) + "</strong></div>" +
                '<div class="ns-block">' + noteHtml(esc(data.error)) + "</div></div>",
                pb ? pb.title : "Firewall Execution"
            );
        }
        return bridge.assistantHtml(resultsHtml(data), data.playbook_title || (pb ? pb.title : "Firewall Execution"));
    }

    /* ================================================================
     * ACTION CHOOSER (Action chip)
     * ================================================================ */

    function chooserCardHtml(info) {
        var configured = !!(info && info.configured);
        var html = '<div class="ws-mcq-card ns-card">' +
            cardHead("Firewall Execution Agent", "How do you want to make firewall changes?") +
            '<div class="ns-block"><div class="ns-mode-row">' + (configured
                ? modeNote(info)
                : '<span class="ns-pill ns-pill-off">OFFLINE</span><span class="ns-note-text">Firewall Execution Agent is not connected - manual and bulk operations are unavailable until NETSEC_FUNCTION_KEY is set.</span>') + "</div></div>";
        if (!configured) {
            html += backControlHtml() + "</div>";
            return html;
        }
        html += '<div class="ws-mcq-options">' +
            '<button type="button" class="mcq-option fw-select-btn" data-ns-flow="manual">' +
            '<span class="mcq-option-label">Manual operation</span>' +
            '<span class="mcq-option-arrow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M7 17L17 7M9 7h8v8"/></svg></span>' +
            "</button>" +
            '<button type="button" class="mcq-option fw-select-btn" data-ns-flow="bulk">' +
            '<span class="mcq-option-label">Bulk operation</span>' +
            '<span class="mcq-option-arrow"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M7 17L17 7M9 7h8v8"/></svg></span>' +
            "</button>" +
            "</div>" + backControlHtml() + "</div>";
        return html;
    }

    function openChooser() {
        if (!nsSession()) return;
        var bridge = chat();
        if (!bridge) { toast("Chat is still loading."); return; }
        var userMsg = bridge.user("Action");
        loadInfo().then(function (info) {
            var asstMsg = bridge.assistantHtml(chooserCardHtml(info), "Firewall Execution");
            persist([userMsg, asstMsg]);
        }).catch(function (err) {
            var asstMsg = bridge.assistantHtml(connErrorHtml(null), "Firewall Execution");
            persist([userMsg, asstMsg]);
            toast(err.message, "error");
        });
    }

    /* ================================================================
     * MANUAL OPERATION
     * ================================================================ */

    function manualTypesCardHtml(info) {
        var groups = {};
        (info.playbooks || []).forEach(function (pb) {
            (groups[pb.category || "Playbooks"] = groups[pb.category || "Playbooks"] || []).push(pb);
        });

        var html = '<div class="ws-mcq-card ns-card">' +
            cardHead("Manual operation", "Choose an object type, then fill in the fields for one firewall change.") +
            '<div class="ns-block"><div class="ns-mode-row">' + modeNote(info) + "</div></div>";
        Object.keys(groups).forEach(function (category) {
            html += '<div class="ns-opts-list ns-opts-cat">' +
                '<div class="ns-opts-cat-label">' + esc(category) + "</div>";
            groups[category].forEach(function (pb) {
                html += '<button type="button" class="ns-pb-opt" data-ns-playbook="' + esc(pb.id) + '">' +
                    '<span class="ns-pb-title">' + esc(pb.title) + "</span>" +
                    '<span class="ns-pb-sheet">create \u00b7 update \u00b7 delete \u2014 sheet &ldquo;' + esc(pb.sheet) + "&rdquo;</span>" +
                    "</button>";
            });
            html += "</div>";
        });
        html += backControlHtml() + "</div>";
        return html;
    }

    function openManualTypes() {
        if (!nsSession()) return;
        var bridge = chat();
        if (!bridge) { toast("Chat is still loading."); return; }
        var userMsg = bridge.user("Manual operation");
        loadInfo().then(function (info) {
            if (!info.configured) {
                var errMsg = bridge.assistantHtml(connErrorHtml(info), "Firewall Execution");
                persist([userMsg, errMsg]);
                return;
            }
            var asstMsg = bridge.assistantHtml(manualTypesCardHtml(info), "Manual operation");
            persist([userMsg, asstMsg]);
        }).catch(function (err) {
            var errMsg = bridge.assistantHtml(connErrorHtml(null), "Firewall Execution");
            persist([userMsg, errMsg]);
            toast(err.message, "error");
        });
    }

    function fieldControlHtml(pb, col) {
        var opts = ENUM_FIELDS[col];
        var multi = !!LIST_FIELDS[col];
        var example = (pb.example && pb.example[col]) ? String(pb.example[col]) : "";
        var identity = identityFor(pb.id).indexOf(col) !== -1;

        var html = '<div class="ns-field" data-ns-col-row="' + esc(col) + '" data-ns-ident="' + (identity ? "1" : "0") + '">' +
            "<label>" + esc(col) + (identity ? ' <em class="ns-req">required</em>' : "") + "</label>";

        var ph = example || (multi ? "comma separated members" : (identity ? "" : "optional"));
        if (opts) {
            html += '<select class="ws-cloud-input ns-control" data-ns-col="' + esc(col) + '"><option value="">(leave blank to skip)</option>';
            opts.forEach(function (opt) {
                html += '<option value="' + esc(opt) + '">' + esc(opt) + "</option>";
            });
            html += "</select>";
        } else {
            html += '<input class="ws-cloud-input ns-control" type="text" data-ns-col="' + esc(col) + '" placeholder="' + esc(ph) + '" autocomplete="off">';
        }
        if (multi) html += '<span class="ns-hint">comma separated members</span>';
        html += "</div>";
        return html;
    }

    function manualFormHtml(pb) {
        var cols = (pb.columns || []).filter(function (c) { return c !== "Action"; });
        var fields = cols.map(function (col) { return fieldControlHtml(pb, col); }).join("");

        var html = '<div class="ws-mcq-card ns-card ns-form-card" data-ns-playbook="' + esc(pb.id) + '" data-ns-op="create">' +
            cardHead(pb.title, pb.summary || "Manual operation") +
            '<div class="ns-block"><div class="ns-mode-row">' + modeNote(state.info) + "</div></div>" +
            '<div class="ns-block">' +
            '<div class="ns-ops" role="group" aria-label="Action">' +
            '<button type="button" class="ws-cloud-run ns-op-btn is-active" data-ns-formop="create">Create</button>' +
            '<button type="button" class="ws-cloud-run ns-op-btn" data-ns-formop="update">Update</button>' +
            '<button type="button" class="ws-cloud-run ns-op-btn" data-ns-formop="delete">Delete</button>' +
            "</div>" +
            '<div class="ns-form-note" data-ns-note></div>' +
            '<div class="ns-fields">' + fields + "</div>" +
            "</div>" +
            '<div class="ns-form-foot">' +
            '<button type="button" class="ws-cloud-run ns-run" data-ns-run="manual">' + ICON_RUN + "Run on firewall</button>" +
            "</div>" +
            backControlHtml() + "</div>";
        return html;
    }

    function openManualForm(pbId) {
        if (!nsSession()) return;
        withInfo(function () {
            var pb = playbookById(pbId);
            if (!pb) { toast("Unknown object type."); return; }
            if (!state.info || !state.info.configured) {
                chat().assistantHtml(connErrorHtml(state.info), "Firewall Execution");
                return;
            }
            var bridge = chat();
            var userMsg = bridge.user(pb.title + " \u2014 manual operation");
            var asstMsg = bridge.assistantHtml(manualFormHtml(pb), pb.title);
            persist([userMsg, asstMsg]);
            bridge.scrollBottom();
        });
    }

    function syncOpState(card) {
        var op = card.getAttribute("data-ns-op") || "create";
        var identity = identityFor(card.getAttribute("data-ns-playbook")).slice();
        card.querySelectorAll("[data-ns-formop]").forEach(function (btn) {
            btn.classList.toggle("is-active", btn.getAttribute("data-ns-formop") === op);
        });
        card.querySelectorAll("[data-ns-col-row]").forEach(function (field) {
            var ident = field.getAttribute("data-ns-ident") === "1";
            field.style.display = (op === "delete" && !ident) ? "none" : "";
        });
        var note = card.querySelector("[data-ns-note]");
        if (note) {
            note.innerHTML = op === "delete"
                ? noteHtml("Delete uses only <strong>" + esc(identity.join(", ")) + "</strong>; the other fields are ignored.")
                : "";
        }
    }

    function setOp(card, op) {
        card.setAttribute("data-ns-op", op);
        syncOpState(card);
    }

    function gatherRow(card) {
        var row = { Action: card.getAttribute("data-ns-op") || "create" };
        card.querySelectorAll("[data-ns-col]").forEach(function (field) {
            var key = field.getAttribute("data-ns-col");
            row[key] = (field.value || "").trim();
        });
        return row;
    }

    function runManual(btn) {
        if (!nsSession()) return;
        var bridge = chat();
        var card = btn.closest(".ns-form-card");
        if (!card) return;
        var pbId = card.getAttribute("data-ns-playbook");
        var op = card.getAttribute("data-ns-op") || "create";
        var row = gatherRow(card);

        var identity = identityFor(pbId);
        var missing = identity.filter(function (key) { return !row[key]; });
        if (missing.length) {
            toast("Enter " + missing.join(", ") + (op === "delete" ? " to identify the object." : " first."), "error");
            return;
        }

        btn.disabled = true;
        withInfo(function () {
            var pb = playbookById(pbId);
            var userMsg = bridge.user(describeRow(pb, op, row));
            var typing = bridge.typingStart();

            fetch(URLS.manual, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ playbook_id: pbId, row: row })
            })
                .then(function (r) {
                    return r.json().then(function (d) { return { ok: r.ok, data: d }; });
                })
                .then(function (res) {
                    if (!res.ok) throw new Error(res.data && res.data.error ? res.data.error : "Run failed");
                    var asstMsg = resultMessage(res.data, pb);
                    persist([userMsg, asstMsg]);
                })
                .catch(function (err) {
                    var asstMsg = bridge.assistantText("The operation could not be completed. " + (err.message || "Run failed."));
                    persist([userMsg, asstMsg]);
                })
                .finally(function () {
                    bridge.typingEnd(typing);
                    btn.disabled = false;
                });
        });
    }

    /* ================================================================
     * BULK OPERATION
     * ================================================================ */

    function bulkFileCardHtml(info) {
        var configured = !!(info && info.configured);
        if (!configured) {
            return '<div class="ws-mcq-card ns-card">' +
                cardHead("Bulk operation", "Download the template and upload a filled workbook to run a sheet against the firewall.") +
                '<div class="ns-block"><div class="ns-mode-row">' +
                '<span class="ns-pill ns-pill-off">OFFLINE</span><span class="ns-note-text">Firewall Execution Agent is not connected - the workbook template can still be downloaded, but playbooks can only be run once NETSEC_FUNCTION_KEY or NETSEC_FW_* is set.</span>' +
                "</div></div>" +
                '<div class="ns-file-grid">' +
                '<button type="button" class="ns-file-card" data-ns-action="bulk-download">' +
                ICON_DOWNLOAD + "<strong>Bulk Ops File</strong><span>.xlsx template with every sheet</span></button>" +
                "</div>" + backControlHtml() + "</div>";
        }
        var html = '<div class="ws-mcq-card ns-card">' +
            cardHead("Bulk operation",
                "Download the Excel workbook template, fill in one row per firewall change, then upload it to run a sheet against the firewall.") +
            '<div class="ns-block"><div class="ns-mode-row">' + modeNote(info) + "</div></div>" +
            '<div class="ns-file-grid">' +
            '<button type="button" class="ns-file-card" data-ns-action="bulk-download">' +
            ICON_DOWNLOAD + "<strong>Bulk Ops File</strong><span>.xlsx template with every sheet</span></button>" +
            '<label class="ns-file-card">' +
            ICON_UPLOAD + "<strong>Upload Bulk Ops File</strong><span>filled workbook from the template</span>" +
            '<input type="file" class="ns-file-input" accept=".xlsx,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" data-ns-file>' +
            "</label>" +
            "</div>" + backControlHtml() + "</div>";
        return html;
    }

    function openBulkFile() {
        if (!nsSession()) return;
        var bridge = chat();
        if (!bridge) { toast("Chat is still loading."); return; }
        var userMsg = bridge.user("Bulk operation");
        loadInfo().then(function (info) {
            var asstMsg = bridge.assistantHtml(bulkFileCardHtml(info), "Bulk operation");
            persist([userMsg, asstMsg]);
        }).catch(function (err) {
            var errMsg = bridge.assistantHtml(connErrorHtml(null), "Firewall Execution");
            persist([userMsg, errMsg]);
            toast(err.message, "error");
        });
    }

    function triggerDownload(blob, filename) {
        var url = URL.createObjectURL(blob);
        var a = document.createElement("a");
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(function () { URL.revokeObjectURL(url); }, 4000);
    }

    function downloadTemplate(btn) {
        btn.disabled = true;
        var original = btn.innerHTML;
        btn.textContent = "Preparing\u2026";
        fetch(URLS.template)
            .then(function (r) {
                if (!r.ok) throw new Error("HTTP " + r.status);
                return r.blob();
            })
            .then(function (blob) {
                triggerDownload(blob, "netsec-playbook-template.xlsx");
                toast("Template downloaded - open it in Excel.", "success");
            })
            .catch(function () { toast("Could not download the template."); })
            .finally(function () {
                btn.disabled = false;
                btn.innerHTML = original;
            });
    }

    function bulkRunCardHtml(summary) {
        var info = state.info || {};
        var sheets = {};
        (summary && summary.sheets || []).forEach(function (s) {
            sheets[String(s.sheet || "").toLowerCase().replace(/\s+/g, "")] = s;
        });

        var options = "";
        var matched = 0;
        (info.playbooks || []).forEach(function (pb) {
            var key = String(pb.sheet || "").toLowerCase().replace(/\s+/g, "");
            var sheet = sheets[key];
            if (!sheet) return;
            matched++;
            options += '<option value="' + esc(pb.id) + '">' + esc(pb.title) + " (" + esc(pb.sheet) + ", " + sheet.rows + " row" + (sheet.rows === 1 ? "" : "s") + ")</option>";
        });

        var sheetChips = (summary && summary.sheets || []).map(function (s) {
            return '<span class="ns-wb-chip">' + esc(s.sheet) + " \u00b7 " + esc(s.rows) + " row" + (s.rows === 1 ? "" : "s") + "</span>";
        }).join("");

        var html = '<div class="ws-mcq-card ns-card ns-summary-card">' +
            cardHead("Workbook uploaded",
                (summary && summary.total_rows != null
                    ? summary.total_rows + " data row" + (summary.total_rows === 1 ? "" : "s") + " across " + (summary.sheets || []).length + " sheet" + ((summary.sheets || []).length === 1 ? "" : "s")
                    : "Choose the object type to execute.")) +
            (sheetChips ? '<div class="ns-block"><div class="ns-wb-chips">' + sheetChips + "</div></div>" : "");

        if (!matched) {
            html += '<div class="ns-block">' + noteHtml(
                "None of the uploaded sheets match a playbook in the catalogue. Download the template and fill in its sheets, then upload it again."
            ) + "</div></div>";
            return html;
        }

        html += '<div class="ns-block">' +
            '<div class="ns-mode-row">' + modeNote(info) + "</div>" +
            '<select class="ws-cloud-input ns-select" data-ns-pb>' + options + "</select>" +
            "</div>" +
            '<div class="ns-form-foot">' +
            '<button type="button" class="ws-cloud-run ns-run" data-ns-run="bulk">' + ICON_RUN + "Run playbook</button>" +
            "</div>" + backControlHtml() + "</div>";
        return html;
    }

    function runBulk(btn) {
        if (!nsSession()) return;
        var bridge = chat();
        var card = btn.closest(".ns-summary-card");
        if (!card) return;
        var select = card.querySelector("[data-ns-pb]");
        var pbId = select && select.value;
        if (!pbId) { toast("Choose an object type to run."); return; }

        btn.disabled = true;
        withInfo(function () {
            var pb = playbookById(pbId);
            var userMsg = bridge.user("Run playbook \u2014 " + (pb ? pb.title : pbId));
            var typing = bridge.typingStart();

            fetch(URLS.run, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ playbook_id: pbId })
            })
                .then(function (r) {
                    return r.json().then(function (d) { return { ok: r.ok, data: d }; });
                })
                .then(function (res) {
                    if (!res.ok) throw new Error(res.data && res.data.error ? res.data.error : "Run failed");
                    var asstMsg = resultMessage(res.data, pb);
                    persist([userMsg, asstMsg]);
                })
                .catch(function (err) {
                    var asstMsg = bridge.assistantText("The playbook could not be run. " + (err.message || "Run failed."));
                    persist([userMsg, asstMsg]);
                })
                .finally(function () {
                    bridge.typingEnd(typing);
                    btn.disabled = false;
                });
        });
    }

    function uploadWorkbook(input) {
        if (state.uploading) return;
        var file = input.files && input.files[0];
        if (!file) return;
        var bridge = chat();
        state.uploading = true;

        var userMsg = bridge.user("Upload workbook \u201c" + file.name + "\u201d");
        var typing = bridge.typingStart();

        var fd = new FormData();
        fd.append("file", file);

        fetch(URLS.upload, { method: "POST", body: fd })
            .then(function (r) {
                return r.json().then(function (d) { return { ok: r.ok, data: d }; });
            })
            .then(function (res) {
                if (!res.ok) throw new Error(res.data && res.data.error ? res.data.error : "Upload failed");
                var asstMsg = bridge.assistantHtml(bulkRunCardHtml(res.data.summary), "Bulk operation");
                persist([userMsg, asstMsg]);
            })
            .catch(function (err) {
                var asstMsg = bridge.assistantText("The workbook could not be uploaded. " + (err.message || "Upload failed."));
                persist([userMsg, asstMsg]);
            })
            .finally(function () {
                state.uploading = false;
                bridge.typingEnd(typing);
            });
    }

    /* ================================================================
     * EVENT DELEGATION (in-chat elements survive reload via these)
     * ================================================================ */

    function onDocClick(e) {
        if (!nsSession()) return;
        if (!e.target || !e.target.closest) return;
        var chatWindowEl = document.getElementById("chatWindow");
        if (chatWindowEl && !chatWindowEl.contains(e.target)) return;

        var flow = e.target.closest("[data-ns-flow]");
        if (flow) {
            if (flow.getAttribute("data-ns-flow") === "manual") openManualTypes();
            else openBulkFile();
            return;
        }

        var pick = e.target.closest(".ns-pb-opt[data-ns-playbook]");
        if (pick) {
            openManualForm(pick.getAttribute("data-ns-playbook"));
            return;
        }

        var opBtn = e.target.closest("[data-ns-formop]");
        if (opBtn) {
            var card = opBtn.closest(".ns-form-card");
            if (card) setOp(card, opBtn.getAttribute("data-ns-formop"));
            return;
        }

        var runBtn = e.target.closest("[data-ns-run]");
        if (runBtn) {
            if (runBtn.getAttribute("data-ns-run") === "manual") runManual(runBtn);
            else runBulk(runBtn);
            return;
        }

        var dl = e.target.closest('[data-ns-action="bulk-download"]');
        if (dl) downloadTemplate(dl);
    }

    function onDocChange(e) {
        if (!nsSession()) return;
        if (!e.target || !e.target.classList) return;
        if (e.target.classList.contains("ns-file-input") && e.target.files && e.target.files[0]) {
            uploadWorkbook(e.target);
        }
    }

    /* ================================================================
     * PUBLIC SURFACE
     * ================================================================ */

    function onActivated() {
        if (!nsSession()) return;
        /* Warm the catalogue so the first flow renders instantly. */
        loadInfo().catch(function () {});
    }

    window.NetsecPanel = {
        agentId: NETSEC_AGENT_ID,
        isNetsecId: isNetsecId,
        isNetsecAgent: isNetsecAgent,
        onAgentActivated: onActivated,
        startChat: function (action) {
            if (action === "ns-manual") { openManualTypes(); return; }
            if (action === "ns-bulk") { openBulkFile(); return; }
            openChooser(); /* ns-action */
        },
        activate: onActivated
    };

    document.addEventListener("click", onDocClick);
    document.addEventListener("change", onDocChange);
})();
