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
                    actions = '<span class="users-none">Logged in</span>';
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
        if (window.loadingRow) usersBody.innerHTML = window.loadingRow(isUsersAdmin ? 4 : 2, "Loading accounts…");
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

    var userDrawer = document.getElementById("userDrawer");
    var userDrawerBackdrop = document.getElementById("userDrawerBackdrop");
    var userDrawerClose = document.getElementById("userDrawerClose");
    var userAddBtn = document.getElementById("userAddBtn");

    function openUserDrawer() {
        if (!userDrawer) return;
        if (userAddBtn) {
            userAddBtn.classList.add("is-active");
            userAddBtn.setAttribute("aria-pressed", "true");
        }
        userDrawer.hidden = false;
        if (userDrawerBackdrop) userDrawerBackdrop.hidden = false;
        window.requestAnimationFrame(function () {
            userDrawer.classList.add("is-open");
            if (userDrawerBackdrop) userDrawerBackdrop.classList.add("is-open");
        });
    }

    function closeUserDrawer() {
        if (!userDrawer) return;
        userDrawer.classList.remove("is-open");
        if (userDrawerBackdrop) userDrawerBackdrop.classList.remove("is-open");
        if (userAddBtn) {
            userAddBtn.classList.remove("is-active");
            userAddBtn.setAttribute("aria-pressed", "false");
        }
        window.setTimeout(function () {
            userDrawer.hidden = true;
            if (userDrawerBackdrop) userDrawerBackdrop.hidden = true;
        }, 220);
    }

    if (userAddBtn) userAddBtn.addEventListener("click", openUserDrawer);
    if (userDrawerClose) userDrawerClose.addEventListener("click", closeUserDrawer);
    if (userDrawerBackdrop) userDrawerBackdrop.addEventListener("click", closeUserDrawer);
    document.addEventListener("keydown", function (event) {
        if (event.key === "Escape" && userDrawer && !userDrawer.hidden) closeUserDrawer();
    });

    var inviteBtn = document.getElementById("inviteBtn");
    if (inviteBtn) {
        inviteBtn.addEventListener("click", function () {
            var name = (document.getElementById("inviteName").value || "").trim();
            var email = (document.getElementById("inviteEmail").value || "").trim();
            var password = document.getElementById("invitePassword").value || "";
            var roleSelect = document.getElementById("inviteRole");
            var role = roleSelect ? (roleSelect.value || "").trim() : "";

            if (!name || !email || !role || !password) {
                window.showToast("Name, email, role, and password are required.", "error");
                return;
            }
            postJson("/api/admin/users", { name: name, email: email, password: password, role: role })
                .then(function () {
                    window.showToast("Account created and approved.", "success");
                    document.getElementById("inviteName").value = "";
                    document.getElementById("inviteEmail").value = "";
                    document.getElementById("invitePassword").value = "";
                    if (roleSelect) roleSelect.selectedIndex = 0;
                    closeUserDrawer();
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
    var sectionsRoot = document.getElementById("fwInventorySections");

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
        if (drawerTitle) drawerTitle.textContent = singular ? "Add device" : "Bulk firewall addition";
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

    function typeKey(deviceType) {
        return String(deviceType || "Firewall").trim() || "Firewall";
    }

    function sectionTitle(deviceType) {
        return typeKey(deviceType) + " Inventory";
    }

    function findSection(deviceType) {
        if (!sectionsRoot) return null;
        var type = typeKey(deviceType);
        var cards = sectionsRoot.querySelectorAll("[data-device-type]");
        for (var i = 0; i < cards.length; i += 1) {
            if (cards[i].getAttribute("data-device-type") === type) return cards[i];
        }
        return null;
    }

    function ensureSection(deviceType) {
        var type = typeKey(deviceType);
        var existing = findSection(type);
        if (existing) return existing;
        if (!sectionsRoot) return null;

        var cardEl = document.createElement("div");
        cardEl.className = "settings-card card settings-card-wide";
        cardEl.setAttribute("data-device-type", type);
        cardEl.innerHTML =
            '<div class="settings-card-head">' +
            '<span class="settings-icon settings-icon-cyan">' +
            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01"/><path d="M7 16.5h.01"/><path d="M10.5 7.5h.01"/><path d="M10.5 16.5h.01"/></svg>' +
            "</span>" +
            "<div><h3>" + escapeHtml(sectionTitle(type)) + "</h3></div>" +
            '<span class="status-chip status-on" data-count-chip>Total 0</span>' +
            "</div>" +
            '<div class="settings-body"><div class="users-table-wrap">' +
            '<table class="users-table"><thead><tr>' +
            "<th>Device Name</th><th>Vendor</th><th>IP</th><th>Status</th>" +
            (isFwAdmin ? "<th>Actions</th>" : "") +
            "</tr></thead><tbody></tbody></table></div></div>";
        sectionsRoot.appendChild(cardEl);
        return cardEl;
    }

    function renderDeviceRows(tbody, devices) {
        var colSpan = isFwAdmin ? 5 : 4;
        var rows = (devices || []).map(function (fw) {
            var cells =
                "<td>" + deviceHtml(fw) + "</td>" +
                "<td>" + escapeHtml(fw.vendor || "Palo Alto Networks") + "</td>" +
                "<td class=\"fw-ip\">" + escapeHtml(fw.host_ip || "—") + "</td>" +
                "<td>" + statusHtml(fw.status) + "</td>";
            if (isFwAdmin) {
                cells +=
                    "<td class=\"users-actions\">" +
                    '<button class="btn btn-sm btn-danger" data-action="remove" data-id="' + fw.id + '">Remove</button>' +
                    "</td>";
            }
            return "<tr data-id=\"" + fw.id + "\">" + cells + "</tr>";
        }).join("");
        tbody.innerHTML = rows ||
            '<tr><td colspan="' + colSpan + '" class="users-empty">No devices registered yet.</td></tr>';
    }

    function renderSection(deviceType, devices) {
        var cardEl = ensureSection(deviceType);
        if (!cardEl) return;
        var tbody = cardEl.querySelector("tbody");
        var chip = cardEl.querySelector("[data-count-chip]");
        if (tbody) renderDeviceRows(tbody, devices);
        if (chip) chip.textContent = "Total " + (devices ? devices.length : 0);
    }

    function renderInventory(devices) {
        var groups = {};
        (devices || []).forEach(function (fw) {
            var type = typeKey(fw.device_type);
            if (!groups[type]) groups[type] = [];
            groups[type].push(fw);
        });

        renderSection("Firewall", groups.Firewall || []);

        var seen = { Firewall: true };
        Object.keys(groups).forEach(function (type) {
            if (type === "Firewall") return;
            seen[type] = true;
            renderSection(type, groups[type]);
        });

        if (!sectionsRoot) return;
        var cards = sectionsRoot.querySelectorAll("[data-device-type]");
        for (var i = 0; i < cards.length; i += 1) {
            var type = cards[i].getAttribute("data-device-type");
            if (type !== "Firewall" && !seen[type]) cards[i].remove();
        }
    }

    function loadFirewalls() {
        var colSpan = isFwAdmin ? 5 : 4;
        if (window.loadingRow) body.innerHTML = window.loadingRow(colSpan, "Loading inventory…");
        fetch("/api/admin/firewalls", { headers: { "Accept": "application/json" } })
            .then(function (res) { return res.ok ? res.json() : Promise.reject(new Error("Failed to load inventory")); })
            .then(function (data) { renderInventory(data.firewalls || []); })
            .catch(function (err) {
                body.innerHTML = '<tr><td colspan="' + colSpan + '" class="users-empty">' + escapeHtml(err.message) + '</td></tr>';
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
            var deviceTypeEl = document.getElementById("fwDeviceType");
            var deviceType = deviceTypeEl ? (deviceTypeEl.value || "").trim() : "";
            var deviceName = (document.getElementById("fwDeviceName").value || "").trim();
            var vendor = (document.getElementById("fwVendor").value || "").trim();
            var hostIp = (document.getElementById("fwHostIp").value || "").trim();
            var username = (document.getElementById("fwUsername").value || "").trim();
            var password = document.getElementById("fwPassword").value || "";
            var port = (document.getElementById("fwPort").value || "").trim();

            if (!deviceType || !deviceName || !hostIp) {
                window.showToast("Device type, device name, and IP address are required.", "error");
                return;
            }
            postJson("/api/admin/firewalls", {
                device_type: deviceType,
                device_name: deviceName,
                vendor: vendor,
                host_ip: hostIp,
                username: username,
                password: password,
                port: port
            }).then(function () {
                window.showToast("Device added to the inventory.", "success");
                if (deviceTypeEl) deviceTypeEl.selectedIndex = 0;
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

    if (isFwAdmin && sectionsRoot) {
        sectionsRoot.addEventListener("click", function (event) {
            var button = event.target.closest("[data-action]");
            if (!button) return;
            var action = button.getAttribute("data-action");
            var id = button.getAttribute("data-id");
            var anchorRow = button.closest("tr");
            var deviceName = anchorRow && anchorRow.querySelector(".fw-device")
                ? anchorRow.querySelector(".fw-device").textContent.trim()
                : "";

            if (action === "remove") {
                if (!window.confirm("Remove \"" + deviceName + "\" from the inventory?")) return;
                fetch("/api/admin/firewalls/" + encodeURIComponent(id), { method: "DELETE" })
                    .then(function (res) {
                        return res.json().then(function (data) {
                            if (!res.ok) throw new Error(data.error || "Request failed");
                            return data;
                        });
                    })
                    .then(function () {
                        window.showToast("Device removed from the inventory.", "success");
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
            bulkMessages.innerHTML = '<p class="bulk-message bulk-message-pending">' +
                '<span class="table-loading"><span class="spinner"></span>Processing ' +
                escapeHtml(file.name) + "…</span></p>";
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
        if (window.loadingRow) body.innerHTML = window.loadingRow(isAgentsAdmin ? 4 : 3, "Loading agents…");
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

    var agentDrawer = document.getElementById("agentDrawer");
    var agentDrawerBackdrop = document.getElementById("agentDrawerBackdrop");
    var agentDrawerClose = document.getElementById("agentDrawerClose");
    var agentOpenBtn = document.getElementById("agentOpenBtn");

    function openAgentDrawer() {
        if (!agentDrawer) return;
        if (agentOpenBtn) {
            agentOpenBtn.classList.add("is-active");
            agentOpenBtn.setAttribute("aria-pressed", "true");
        }
        agentDrawer.hidden = false;
        if (agentDrawerBackdrop) agentDrawerBackdrop.hidden = false;
        window.requestAnimationFrame(function () {
            agentDrawer.classList.add("is-open");
            if (agentDrawerBackdrop) agentDrawerBackdrop.classList.add("is-open");
        });
    }

    function closeAgentDrawer() {
        if (!agentDrawer) return;
        agentDrawer.classList.remove("is-open");
        if (agentDrawerBackdrop) agentDrawerBackdrop.classList.remove("is-open");
        if (agentOpenBtn) {
            agentOpenBtn.classList.remove("is-active");
            agentOpenBtn.setAttribute("aria-pressed", "false");
        }
        window.setTimeout(function () {
            agentDrawer.hidden = true;
            if (agentDrawerBackdrop) agentDrawerBackdrop.hidden = true;
        }, 220);
    }

    if (agentOpenBtn) agentOpenBtn.addEventListener("click", openAgentDrawer);
    if (agentDrawerClose) agentDrawerClose.addEventListener("click", closeAgentDrawer);
    if (agentDrawerBackdrop) agentDrawerBackdrop.addEventListener("click", closeAgentDrawer);
    document.addEventListener("keydown", function (event) {
        if (event.key === "Escape" && agentDrawer && !agentDrawer.hidden) closeAgentDrawer();
    });

    var addBtn = document.getElementById("agentAddBtn");
    if (addBtn) {
        addBtn.addEventListener("click", function () {
            var name = (document.getElementById("agentName").value || "").trim();
            var typeSelect = document.getElementById("agentType");
            var typeName = typeSelect ? (typeSelect.value || "").trim() : "";
            var endpoint = (document.getElementById("agentEndpoint").value || "").trim();
            var key = document.getElementById("agentKey").value || "";

            if (!name || !typeName || !endpoint || !key) {
                window.showToast("Agent name, type, API endpoint, and API key are required.", "error");
                return;
            }
            postJson("/api/agents", { name: name, type: typeName, endpoint: endpoint, api_key: key })
                .then(function () {
                    window.showToast("Agent added to the workspace.", "success");
                    document.getElementById("agentName").value = "";
                    if (typeSelect) typeSelect.selectedIndex = 0;
                    document.getElementById("agentEndpoint").value = "";
                    document.getElementById("agentKey").value = "";
                    closeAgentDrawer();
                    loadAgents();
                })
                .catch(function (err) {
                    window.showToast(err.message, "error");
                });
        });
    }

    loadAgents();
})();
