(function () {
    "use strict";

    // ---- User accounts (administrators manage; members view name + role) ----

    var usersBody = document.getElementById("usersBody");
    if (!usersBody) return;

    var selfCard = document.getElementById("userAccountsCard");
    var isUsersAdmin = selfCard
        ? selfCard.getAttribute("data-is-admin") === "true"
        : false;
    var selfUserId = selfCard ? (selfCard.getAttribute("data-self-user") || "") : "";

    function chipClass(status) {
        if (status === "pending") return "status-chip status-warn";
        if (status === "rejected" || status === "disabled") return "status-chip status-idle";
        return "status-chip status-on";
    }

    function chipLabel(status) {
        if (status === "disabled") return "Removed";
        return capitalize(status || "approved");
    }

    function renderUsers(users) {
        var rows = users.map(function (user) {
            if (isUsersAdmin) {
                var actions = "";
                if (user.status === "pending") {
                    actions =
                        '<button class="btn btn-sm btn-primary" data-action="approve" data-id="' + user.id + '">Approve</button>' +
                        '<button class="btn btn-sm btn-danger" data-action="reject" data-id="' + user.id + '">Reject</button>';
                } else if (selfUserId && user.id === selfUserId) {
                    actions = '<span class="users-none">This is you</span>';
                } else {
                    actions =
                        '<button class="btn btn-sm btn-danger" data-action="remove" data-id="' + user.id + '">Remove</button>';
                }
                return (
                    "<tr>" +
                    "<td>" + escapeHtml(user.name || "") + "</td>" +
                    "<td>" + escapeHtml(user.email || "") + "</td>" +
                    "<td>" + escapeHtml(user.role || "") + "</td>" +
                    "<td class=\"users-actions\">" + actions + "</td>" +
                    "</tr>"
                );
            }
            return (
                "<tr>" +
                "<td>" + escapeHtml(user.name || "") + "</td>" +
                "<td>" + escapeHtml(user.role || "") + "</td>" +
                "</tr>"
            );
        }).join("");

        usersBody.innerHTML = rows ||
            '<tr><td colspan="' + (isUsersAdmin ? 4 : 2) + '" class="users-empty">No accounts yet.</td></tr>';
    }

    function capitalize(value) {
        return value.charAt(0).toUpperCase() + value.slice(1);
    }

    function escapeHtml(value) {
        return String(value)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
    }

    function loadUsers() {
        fetch("/api/admin/users", { headers: { "Accept": "application/json" } })
            .then(function (res) { return res.ok ? res.json() : Promise.reject(new Error("Failed to load accounts")); })
            .then(function (data) { renderUsers(data.users || []); })
            .catch(function (err) {
                usersBody.innerHTML = '<tr><td colspan="' + (isUsersAdmin ? 4 : 2) + '" class="users-empty">' + escapeHtml(err.message) + '</td></tr>';
            });
    }

    function postJson(url, payload) {
        return fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json", "Accept": "application/json" },
            body: JSON.stringify(payload || {})
        }).then(function (res) {
            return res.json().then(function (data) {
                if (!res.ok) throw new Error(data.error || "Request failed");
                return data;
            });
        });
    }

    if (isUsersAdmin) {
        usersBody.addEventListener("click", function (event) {
            var button = event.target.closest("[data-action]");
            if (!button) return;
            var action = button.getAttribute("data-action");
            var userId = button.getAttribute("data-id");
            var row = button.closest("tr");
            var userName = row ? row.cells[0].textContent.trim() : "account";

            if (action === "remove") {
                if (!window.confirm(
                    "Remove \"" + userName + "\"? They will no longer be able to sign in. " +
                    "The account and its data are retained in the database but hidden from the platform."
                )) return;
                postJson("/api/admin/users/" + encodeURIComponent(userId) + "/remove")
                    .then(function () {
                        window.showToast("Account removed. Sign-in is disabled.", "success");
                        loadUsers();
                    })
                    .catch(function (err) {
                        window.showToast(err.message, "error");
                    });
                return;
            }

            var verb = action === "approve" ? "approve" : "reject";
            postJson("/api/admin/users/" + encodeURIComponent(userId) + "/" + verb)
                .then(function () {
                    window.showToast("Account " + verb + "d.", "success");
                    loadUsers();
                })
                .catch(function (err) {
                    window.showToast(err.message, "error");
                });
        });
    }

    var inviteBtn = document.getElementById("inviteBtn");
    if (inviteBtn) {
        inviteBtn.addEventListener("click", function () {
            var name = (document.getElementById("inviteName").value || "").trim();
            var email = (document.getElementById("inviteEmail").value || "").trim();
            var password = document.getElementById("invitePassword").value || "";
            var role = document.getElementById("inviteRole").value || "Security Analyst";

            if (!name || !email || !password) {
                window.showToast("Name, email, and password are required.", "error");
                return;
            }
            postJson("/api/admin/users", { name: name, email: email, password: password, role: role })
                .then(function () {
                    window.showToast("Account created and approved.", "success");
                    document.getElementById("inviteName").value = "";
                    document.getElementById("inviteEmail").value = "";
                    document.getElementById("invitePassword").value = "";
                    loadUsers();
                })
                .catch(function (err) {
                    window.showToast(err.message, "error");
                });
        });
    }

    loadUsers();
})();

// ---- Firewall inventory (administrators manage; members view read-only) ----

(function () {
    "use strict";

    var body = document.getElementById("fwInventoryBody");
    if (!body) return;

    var card = document.getElementById("fwInventoryCard");
    var isFwAdmin = card
        ? card.getAttribute("data-is-admin") === "true"
        : false;
    var countChip = document.getElementById("fwCountChip");

    // ---- Add/bulk inventory side drawer ----
    var drawer = document.getElementById("fwDrawer");
    var drawerBackdrop = document.getElementById("fwDrawerBackdrop");
    var drawerTitle = document.getElementById("fwDrawerTitle");
    var drawerClose = document.getElementById("fwDrawerClose");
    var singularBtn = document.getElementById("fwSingularBtn");
    var bulkBtn = document.getElementById("fwBulkBtn");
    var panelSingular = document.getElementById("fwPanelSingular");
    var panelBulk = document.getElementById("fwPanelBulk");

    function openDrawer(mode) {
        if (!drawer) return;
        var singular = mode !== "bulk";
        if (drawerTitle) drawerTitle.textContent = singular ? "Add a single firewall" : "Bulk firewall addition";
        if (panelSingular) panelSingular.hidden = !singular;
        if (panelBulk) panelBulk.hidden = singular;
        if (singularBtn) {
            singularBtn.classList.toggle("is-active", singular);
            singularBtn.setAttribute("aria-pressed", singular ? "true" : "false");
        }
        if (bulkBtn) {
            bulkBtn.classList.toggle("is-active", !singular);
            bulkBtn.setAttribute("aria-pressed", !singular ? "true" : "false");
        }
        drawer.hidden = false;
        if (drawerBackdrop) drawerBackdrop.hidden = false;
        window.requestAnimationFrame(function () {
            drawer.classList.add("is-open");
            if (drawerBackdrop) drawerBackdrop.classList.add("is-open");
        });
    }

    function closeDrawer() {
        if (!drawer) return;
        drawer.classList.remove("is-open");
        if (drawerBackdrop) drawerBackdrop.classList.remove("is-open");
        window.setTimeout(function () {
            drawer.hidden = true;
            if (drawerBackdrop) drawerBackdrop.hidden = true;
        }, 220);
    }

    if (singularBtn) singularBtn.addEventListener("click", function () { openDrawer("singular"); });
    if (bulkBtn) bulkBtn.addEventListener("click", function () { openDrawer("bulk"); });
    if (drawerClose) drawerClose.addEventListener("click", closeDrawer);
    if (drawerBackdrop) drawerBackdrop.addEventListener("click", closeDrawer);
    document.addEventListener("keydown", function (event) {
        if (event.key === "Escape" && drawer && !drawer.hidden) closeDrawer();
    });

    function escapeHtml(value) {
        return String(value == null ? "" : value)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
    }

    function statusHtml(status) {
        var live = status === "live";
        var color = live ? "#059669" : "#dc2626";
        var border = live ? "rgba(34, 197, 94, 0.5)" : "rgba(239, 68, 68, 0.5)";
        var label = live ? "Live" : "Down";
        return '<span class="hero-chip" style="border-color: ' + border + '; color: ' + color + ';">' +
            '<span class="pulse-dot" style="background: ' + color + ';"></span> ' + label + "</span>";
    }

    function deviceHtml(fw) {
        var name = '<span class="fw-device">' + escapeHtml(fw.device_name || "") + "</span>";
        if (fw.clone_of) {
            name += '<span class="fw-clone-tag">clone of ' + escapeHtml(fw.clone_of) + "</span>";
        }
        return name;
    }

    function renderFirewalls(firewalls) {
        var rows = firewalls.map(function (fw) {
            var cells =
                "<td>" + deviceHtml(fw) + "</td>" +
                "<td>" + escapeHtml(fw.vendor || "Palo Alto Networks") + "</td>" +
                "<td class=\"fw-ip\">" + escapeHtml(fw.host_ip || "—") + "</td>" +
                "<td>" + statusHtml(fw.status) + "</td>";
            if (isFwAdmin) {
                var cloneButton = fw.clone_of
                    ? ""
                    : '<button class="btn btn-sm btn-ghost" data-action="clone" data-id="' + fw.id + '">Clone</button>';
                cells +=
                    "<td class=\"users-actions\">" +
                    cloneButton +
                    '<button class="btn btn-sm btn-danger" data-action="remove" data-id="' + fw.id + '">Remove</button>' +
                    "</td>";
            }
            return "<tr data-id=\"" + fw.id + "\">" + cells + "</tr>";
        }).join("");

        body.innerHTML = rows ||
            '<tr><td colspan="' + (isFwAdmin ? 5 : 4) + '" class="users-empty">No firewalls registered yet.</td></tr>';

        if (countChip) countChip.textContent = "Total " + firewalls.length;
    }

    function removeCloneRows() {
        var rows = body.querySelectorAll("tr.fw-clone-row");
        for (var i = 0; i < rows.length; i += 1) rows[i].remove();
    }

    function beginClone(fw, anchorRow) {
        removeCloneRows();
        var tr = document.createElement("tr");
        tr.className = "fw-clone-row";
        tr.setAttribute("data-source-id", fw.id);
        tr.innerHTML =
            '<td colspan="5">' +
            '<div class="fw-clone-form">' +
            '<span class="fw-clone-form-label">Clone of <strong>' + escapeHtml(fw.device_name || "") + "</strong></span>" +
            '<input type="text" class="fw-clone-input" placeholder="Enter a device name for the clone" autocomplete="off" value="' + escapeHtml(fw.device_name + "-clone") + '">' +
            '<button type="button" class="btn btn-sm btn-primary" data-clone-confirm>Clone</button>' +
            '<button type="button" class="btn btn-sm btn-ghost" data-clone-cancel>Cancel</button>' +
            "</div>" +
            "</td>";

        var confirmBtn = tr.querySelector("[data-clone-confirm]");
        var cancelBtn = tr.querySelector("[data-clone-cancel]");
        var input = tr.querySelector(".fw-clone-input");

        confirmBtn.addEventListener("click", function () {
            var name = (input.value || "").trim();
            if (!name) {
                window.showToast("A device name is required to clone.", "error");
                input.focus();
                return;
            }
            confirmBtn.disabled = true;
            postJson("/api/admin/firewalls/" + encodeURIComponent(fw.id) + "/clone", { device_name: name })
                .then(function () {
                    window.showToast("Firewall cloned as " + name + ".", "success");
                    removeCloneRows();
                    loadFirewalls();
                })
                .catch(function (err) {
                    confirmBtn.disabled = false;
                    window.showToast(err.message, "error");
                    input.focus();
                });
        });

        cancelBtn.addEventListener("click", function () {
            removeCloneRows();
        });

        input.addEventListener("keydown", function (event) {
            if (event.key === "Enter") {
                event.preventDefault();
                confirmBtn.click();
            } else if (event.key === "Escape") {
                event.preventDefault();
                removeCloneRows();
            }
        });

        if (anchorRow && anchorRow.nextSibling) {
            anchorRow.parentNode.insertBefore(tr, anchorRow.nextSibling);
        } else {
            body.appendChild(tr);
        }
        input.focus();
        input.select();
    }

    function loadFirewalls() {
        fetch("/api/admin/firewalls", { headers: { "Accept": "application/json" } })
            .then(function (res) { return res.ok ? res.json() : Promise.reject(new Error("Failed to load firewall inventory")); })
            .then(function (data) { renderFirewalls(data.firewalls || []); })
            .catch(function (err) {
                body.innerHTML = '<tr><td colspan="' + (isFwAdmin ? 5 : 4) + '" class="users-empty">' + escapeHtml(err.message) + '</td></tr>';
            });
    }

    function postJson(url, payload) {
        return fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json", "Accept": "application/json" },
            body: JSON.stringify(payload || {})
        }).then(function (res) {
            return res.json().then(function (data) {
                if (!res.ok) throw new Error(data.error || "Request failed");
                return data;
            });
        });
    }

    var addBtn = document.getElementById("fwAddBtn");
    if (addBtn) {
        addBtn.addEventListener("click", function () {
            var deviceName = (document.getElementById("fwDeviceName").value || "").trim();
            var vendor = (document.getElementById("fwVendor").value || "").trim();
            var hostIp = (document.getElementById("fwHostIp").value || "").trim();
            var username = (document.getElementById("fwUsername").value || "").trim();
            var password = document.getElementById("fwPassword").value || "";
            var port = (document.getElementById("fwPort").value || "").trim();

            if (!deviceName || !hostIp) {
                window.showToast("Device name and IP address are required.", "error");
                return;
            }
            postJson("/api/admin/firewalls", {
                device_name: deviceName,
                vendor: vendor,
                host_ip: hostIp,
                username: username,
                password: password,
                port: port
            }).then(function () {
                window.showToast("Firewall added to the inventory.", "success");
                document.getElementById("fwDeviceName").value = "";
                document.getElementById("fwHostIp").value = "";
                document.getElementById("fwUsername").value = "";
                document.getElementById("fwPassword").value = "";
                document.getElementById("fwPort").value = "";
                loadFirewalls();
            }).catch(function (err) {
                window.showToast(err.message, "error");
            });
        });
    }

    if (isFwAdmin) {
        body.addEventListener("click", function (event) {
            var button = event.target.closest("[data-action]");
            if (!button) return;
            var action = button.getAttribute("data-action");
            var id = button.getAttribute("data-id");
            var anchorRow = button.closest("tr");
            var deviceName = anchorRow && anchorRow.querySelector(".fw-device")
                ? anchorRow.querySelector(".fw-device").textContent.trim()
                : "";

            if (action === "clone") {
                var firewalls = Array.prototype.map.call(
                    body.querySelectorAll("tr[data-id]"),
                    function (tr) {
                        return {
                            id: tr.getAttribute("data-id"),
                            device_name: tr.querySelector(".fw-device") ? tr.querySelector(".fw-device").textContent.trim() : ""
                        };
                    }
                );
                var fw = null;
                for (var i = 0; i < firewalls.length; i += 1) {
                    if (firewalls[i].id === id) { fw = firewalls[i]; break; }
                }
                if (!fw) return;
                beginClone(fw, anchorRow);
                return;
            }

            if (action === "remove") {
                if (!window.confirm("Remove \"" + deviceName + "\" from the firewall inventory?")) return;
                fetch("/api/admin/firewalls/" + encodeURIComponent(id), { method: "DELETE" })
                    .then(function (res) {
                        return res.json().then(function (data) {
                            if (!res.ok) throw new Error(data.error || "Request failed");
                            return data;
                        });
                    })
                    .then(function () {
                        window.showToast("Firewall removed from the inventory.", "success");
                        loadFirewalls();
                    })
                    .catch(function (err) {
                        window.showToast(err.message, "error");
                    });
            }
        });
    }

    // ---- Bulk import: download template / upload workbook ----
    var bulkMessages = document.getElementById("fwBulkMessages");
    var uploadInput = document.getElementById("fwUploadInput");
    var uploadBtn = document.getElementById("fwUploadBtn");
    var bulkTimer = null;

    function renderBulkMessages(summary) {
        if (!bulkMessages) return;
        var lines = [];

        if (summary && summary.error) {
            lines.push('<p class="bulk-message bulk-message-error">' + escapeHtml(summary.error) + "</p>");
        } else if (summary) {
            lines.push(
                '<p class="bulk-summary">Added ' + (summary.added || 0) +
                " · Removed " + (summary.removed || 0) +
                " · Failed " + (summary.failed || 0) + "</p>"
            );
        }

        ((summary && summary.results) || []).forEach(function (result) {
            var cls = result.status === "success" ? "bulk-message-success" : "bulk-message-error";
            lines.push('<p class="bulk-message ' + cls + '">' + escapeHtml(result.message) + "</p>");
        });

        bulkMessages.innerHTML = lines.join("");

        if (bulkTimer) window.clearTimeout(bulkTimer);
        bulkTimer = window.setTimeout(function () {
            bulkMessages.innerHTML = "";
        }, 20000);
    }

    function uploadWorkbook(file) {
        if (bulkMessages) {
            bulkMessages.innerHTML = '<p class="bulk-message bulk-message-pending">Processing ' +
                escapeHtml(file.name) + "…</p>";
        }
        if (bulkTimer) window.clearTimeout(bulkTimer);
        if (uploadBtn) uploadBtn.disabled = true;

        var formData = new FormData();
        formData.append("file", file);

        fetch("/api/admin/firewalls/bulk", {
            method: "POST",
            headers: { "Accept": "application/json" },
            body: formData
        }).then(function (res) {
            return res.json().then(function (data) {
                if (!res.ok) throw new Error(data.error || "Upload failed");
                return data;
            });
        }).then(function (data) {
            renderBulkMessages(data);
            loadFirewalls();
        }).catch(function (err) {
            renderBulkMessages({ error: err.message });
        }).then(function () {
            if (uploadBtn) uploadBtn.disabled = false;
        });
    }

    if (uploadBtn && uploadInput) {
        uploadBtn.addEventListener("click", function () {
            uploadInput.click();
        });
        uploadInput.addEventListener("change", function () {
            var file = uploadInput.files && uploadInput.files[0];
            uploadInput.value = "";
            if (file) uploadWorkbook(file);
        });
    }

    loadFirewalls();
})();

// ---- AI Agents (administrators manage; members view status only) ----

(function () {
    "use strict";

    var body = document.getElementById("agentsBody");
    if (!body) return;

    var agentsCard = document.getElementById("agentsCard");
    var isAgentsAdmin = agentsCard
        ? agentsCard.getAttribute("data-is-admin") === "true"
        : false;
    var countChip = document.getElementById("agentCountChip");

    function escapeHtml(value) {
        return String(value == null ? "" : value)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
    }

    function statusHtml(agent) {
        var live = agent.status === "live";
        var color = live ? "#059669" : "#dc2626";
        var border = live ? "rgba(34, 197, 94, 0.5)" : "rgba(239, 68, 68, 0.5)";
        var label = live ? "Live" : "Down";
        var detail = agent.detail || "";
        var latency = "";
        if (live && typeof agent.latency_ms === "number") {
            latency = " · " + agent.latency_ms + " ms";
        }
        var title = detail + latency;
        return '<span class="hero-chip" style="border-color: ' + border + '; color: ' + color + ';" title="' + escapeHtml(title) + '">' +
            '<span class="pulse-dot" style="background: ' + color + ';"></span> ' + label + "</span>";
    }

    function renderAgents(agents) {
        var rows = agents.map(function (agent) {
            var actions = isAgentsAdmin
                ? '<td class="users-actions">' +
                  '<button class="btn btn-sm btn-danger" data-action="remove" data-id="' + escapeHtml(agent.id || "") + '">Remove</button>' +
                  "</td>"
                : "";
            return "<tr data-id=\"" + escapeHtml(agent.id || "") + "\">" +
                "<td>" + escapeHtml(agent.name || "") + "</td>" +
                "<td>" + escapeHtml(agent.type || "Custom Agent") + "</td>" +
                "<td>" + statusHtml(agent) + "</td>" +
                actions +
                "</tr>";
        }).join("");

        body.innerHTML = rows ||
            '<tr><td colspan="' + (isAgentsAdmin ? 4 : 3) + '" class="users-empty">No agents configured yet.</td></tr>';

        if (countChip) countChip.textContent = "Total " + agents.length;
    }

    function loadAgents() {
        fetch("/api/agent-status", { headers: { "Accept": "application/json" } })
            .then(function (res) { return res.ok ? res.json() : Promise.reject(new Error("Failed to load agent status")); })
            .then(function (data) { renderAgents(data.agents || []); })
            .catch(function (err) {
                body.innerHTML = '<tr><td colspan="' + (isAgentsAdmin ? 4 : 3) + '" class="users-empty">' + escapeHtml(err.message) + "</td></tr>";
            });
    }

    function postJson(url, payload, method) {
        return fetch(url, {
            method: method || "POST",
            headers: { "Content-Type": "application/json", "Accept": "application/json" },
            body: JSON.stringify(payload || {})
        }).then(function (res) {
            return res.json().then(function (data) {
                if (!res.ok) throw new Error(data.error || "Request failed");
                return data;
            });
        });
    }

    body.addEventListener("click", function (event) {
        if (!isAgentsAdmin) return;
        var button = event.target.closest("[data-action]");
        if (!button || button.getAttribute("data-action") !== "remove") return;
        var id = button.getAttribute("data-id") || "";
        var row = button.closest("tr");
        var agentName = row ? row.cells[0].textContent.trim() : "agent";

        if (!window.confirm("Remove \"" + agentName + "\" from the AI Workspace? It will no longer appear in chat.")) return;
        fetch("/api/agents/" + encodeURIComponent(id), { method: "DELETE", headers: { "Accept": "application/json" } })
            .then(function (res) {
                return res.json().then(function (data) {
                    if (!res.ok) throw new Error(data.error || "Request failed");
                    return data;
                });
            })
            .then(function () {
                window.showToast("Agent removed from the workspace.", "success");
                loadAgents();
            })
            .catch(function (err) {
                window.showToast(err.message, "error");
            });
    });

    var addBtn = document.getElementById("agentAddBtn");
    if (addBtn) {
        addBtn.addEventListener("click", function () {
            var name = (document.getElementById("agentName").value || "").trim();
            var endpoint = (document.getElementById("agentEndpoint").value || "").trim();
            var key = document.getElementById("agentKey").value || "";

            if (!name || !endpoint || !key) {
                window.showToast("Agent name, endpoint, and API key are required.", "error");
                return;
            }
            postJson("/api/agents", { name: name, endpoint: endpoint, api_key: key })
                .then(function () {
                    window.showToast("Agent added to the workspace.", "success");
                    document.getElementById("agentName").value = "";
                    document.getElementById("agentEndpoint").value = "";
                    document.getElementById("agentKey").value = "";
                    loadAgents();
                })
                .catch(function (err) {
                    window.showToast(err.message, "error");
                });
        });
    }

    loadAgents();
})();
