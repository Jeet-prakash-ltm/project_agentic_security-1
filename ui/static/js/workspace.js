(function () {
    "use strict";

    // ============================================================
    // DOM REFERENCES
    // ============================================================

    var sidebar = document.getElementById("wsSidebar");
    var insights = document.getElementById("wsInsights");
    var sidebarToggle = document.getElementById("wsSidebarToggle");
    var insightsToggle = document.getElementById("insightsToggle");
    var insightsClose = document.getElementById("insightsClose");
    var newChatBtn = document.getElementById("newChatBtn");
    var convSearch = document.getElementById("convSearch");
    var convList = document.getElementById("convList");
    var wsAgentSelect = document.getElementById("wsAgentSelect");

    var chatWindow = document.getElementById("chatWindow");
    var chatAgentTitle = document.getElementById("chatAgentTitle");
    var chatAgentSub = document.getElementById("chatAgentSub");
    var chatAgentAvatar = document.getElementById("chatAgentAvatar");
    var clearBtn = document.getElementById("clearChatBtn");
    var promptInput = document.getElementById("promptInput");
    var sendBtn = document.getElementById("sendBtn");
    var promptChips = document.getElementById("promptChips");
    var composerAgentBadge = document.getElementById("composerAgentBadge");
    var composerWrap = document.querySelector(".ws-composer-wrap");

    var insightMessages = document.getElementById("insightMessages");
    var insightTokens = document.getElementById("insightTokens");
    var insightCost = document.getElementById("insightCost");

    // ============================================================
    // CONSTANTS — firewall actions, prompts, tool metadata
    // ============================================================

    var FIREWALL_ACTIONS = {
        assess: { label: "Compliance Assessment" },
        summary: { label: "Executive Summary" },
        excel: { label: "Report Generation" },
        ha: { label: "HA Configuration" }
    };

    var FIREWALL_CHIP_ORDER = ["assess"];

    function fwActionIcon(action) {
        if (TOOL_META[action] && TOOL_META[action].icon) return TOOL_META[action].icon;
        if (action === "ha") {
            return '<rect x="3" y="3" width="8" height="8" rx="1.5"/><rect x="13" y="3" width="8" height="8" rx="1.5"/><rect x="3" y="13" width="8" height="8" rx="1.5"/><rect x="13" y="13" width="8" height="8" rx="1.5"/>';
        }
        return '<path d="M12 5v14M5 12h14"/>';
    }

    function fwChipEntries() {
        return FIREWALL_CHIP_ORDER.map(function (action) {
            var meta = FIREWALL_ACTIONS[action] || {};
            return { action: action, label: meta.label, icon: fwActionIcon(action) };
        });
    }

    var SUGGESTIONS = FIREWALL_CHIP_ORDER.map(function (action) {
        return { label: (FIREWALL_ACTIONS[action] || {}).label || action, action: action };
    });

    // Cloud Incident Response agent entries (Incidents + Virtual Machine).
    var CLOUD_CHIPS = [
        { id: "incidents", label: "Incidents", icon: '<path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><path d="M12 9v4"/><circle cx="12" cy="17" r="1"/>' },
        { id: "vm", label: "Virtual Machine", icon: '<rect x="4" y="4" width="16" height="16" rx="2"/><path d="M9 1v3M15 1v3M9 20v3M15 20v3"/>' }
    ];

    var CLOUD_SUGGESTIONS = [
        { label: "Incidents", action: "incidents" },
        { label: "Virtual Machine", action: "vm" }
    ];

    // NetSec Execution Agent entries: one Action chip that opens the manual /
    // bulk operation chooser inside the chat.
    var NETSEC_CHIPS = [
        { id: "ns-action", label: "Action", icon: '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/>' }
    ];

    var NETSEC_SUGGESTIONS = [
        { label: "Manual operation", action: "ns-manual" },
        { label: "Bulk operation", action: "ns-bulk" }
    ];

    var CLOUD_KPI_PERIODS = [
        { id: "daily", label: "Daily", sub: "Today" },
        { id: "weekly", label: "Weekly", sub: "Last 7 days" },
        { id: "monthly", label: "Monthly", sub: "Last 30 days" }
    ];

    var ASSESSMENT_SECTIONS = [
        { id: "inventory", label: "Inventory", endpoint: "/api/firewall/inventory", domains: ["Software & Platform Currency", "Hardware & Capacity"] },
        { id: "health", label: "Health Status", endpoint: "/api/firewall/health", domains: ["Hardware & Capacity"] },
        { id: "ha", label: "HA Configuration", endpoint: "/api/firewall/ha", domains: ["High Availability"] },
        { id: "policy", label: "Security Policy", endpoint: "/api/firewall/policy", domains: ["Security Policy & Rule Base"] },
        { id: "segmentation", label: "Network Segmentation", endpoint: "/api/firewall/policy", domains: ["Network Segmentation & Zones"] },
        { id: "services", label: "Security Services", endpoint: "/api/firewall/services", domains: ["Threat Prevention", "SSL/TLS Decryption"] },
        { id: "routing", label: "Routing", endpoint: "/api/firewall/routing", domains: ["NAT & Routing"] },
        { id: "vpn", label: "VPN", endpoint: "/api/firewall/vpn", domains: ["VPN"] },
        { id: "logging", label: "Logging", endpoint: "/api/firewall/logging", domains: ["Logging & Monitoring"] },
        { id: "administration", label: "Administration", endpoint: "/api/firewall/administration", domains: ["Admin Access & Hardening"] },
        { id: "zone_protection", label: "Zone Protection", endpoint: "/api/firewall/zone-protection", domains: ["Zone Protection & DoS"] },
        { id: "backup", label: "Backup", endpoint: "/api/firewall/backup", domains: ["Backup & Change Management"] },
        { id: "report", label: "Report Generation", action: "report" },
        { id: "summary", label: "Executive Summary", action: "summary" }
    ];

    var TOOL_META = {
        assess: {
            name: "Compliance Assessment",
            link: { label: "View findings", href: "/findings" },
            icon: '<path d="M12 3l7 3v5c0 4.5-3 8.5-7 10-4-1.5-7-5.5-7-10V6l7-3z"/>'
        },
        summary: {
            name: "Executive Summary",
            link: { label: "Open reports", href: "/reports" },
            icon: '<path d="M20 6L9 17l-5-5"/>'
        },
        excel: {
            name: "Report Generation",
            link: { label: "Download workbook", href: "/download-workbook" },
            icon: '<path d="M6 2.5h8l4 4V21.5H6V2.5z"/><path d="M14 2.5v4h4"/>'
        },
        findings: {
            name: "Compliance Findings",
            link: { label: "View findings", href: "/findings" },
            icon: '<path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><path d="M12 9v4"/><circle cx="12" cy="17" r="1"/>'
        },
        incident_list: {
            name: "Sentinel Incidents",
            icon: '<path d="M12 3l1.9 4.6 4.6 1.9-4.6 1.9L12 16l-1.9-4.6L5.5 9.5l4.6-1.9L12 3z"/>'
        },
        investigate: {
            name: "Incident Investigation",
            icon: '<path d="M12 3l1.9 4.6 4.6 1.9-4.6 1.9L12 16l-1.9-4.6L5.5 9.5l4.6-1.9L12 3z"/><circle cx="12" cy="12" r="9"/>'
        },
        incident_summary: {
            name: "Incident Summary",
            icon: '<path d="M12 3l1.9 4.6 4.6 1.9-4.6 1.9L12 16l-1.9-4.6L5.5 9.5l4.6-1.9L12 3z"/><path d="M9 12l2 2 4-4"/>'
        },
        vm_context: {
            name: "VM Configuration",
            icon: '<path d="M12 3l1.9 4.6 4.6 1.9-4.6 1.9L12 16l-1.9-4.6L5.5 9.5l4.6-1.9L12 3z"/><rect x="8" y="12" width="8" height="8" rx="1.5"/>'
        },
        vm_instance_view: {
            name: "VM Status & Health",
            icon: '<path d="M12 3l1.9 4.6 4.6 1.9-4.6 1.9L12 16l-1.9-4.6L5.5 9.5l4.6-1.9L12 3z"/><path d="M12 11v4M12 18h.01"/>'
        },
        isolate: {
            name: "VM Isolation",
            icon: '<path d="M12 3l1.9 4.6 4.6 1.9-4.6 1.9L12 16l-1.9-4.6L5.5 9.5l4.6-1.9L12 3z"/><path d="M5 21h14"/>'
        },
        start_vm: {
            name: "Start VM",
            icon: '<path d="M12 3v18M5 12h14"/>'
        },
        stop_vm: {
            name: "Stop VM",
            icon: '<path d="M6 4h12v16H6z"/>'
        },
        restart_vm: {
            name: "Restart VM",
            icon: '<path d="M12 3a9 9 0 109 9M21 3v6h-6"/>'
        },
        reconnect_vm: {
            name: "Restore VM Connectivity",
            icon: '<path d="M8 12h8M12 8l4 4-4 4"/>'
        }
    };

    var COPY_ICON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 012-2h10"/></svg>';
    var ARROW_ICON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M7 17L17 7M9 7h8v8"/></svg>';

    var BACK_ICON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5"/><path d="M11 18l-6-6 6-6"/></svg>';

    function backButtonHtml() {
        return '<div class="ws-fw-back-wrap"><button type="button" class="ws-back-run" data-fw-back="1">' + BACK_ICON + "Back</button></div>";
    }

    function isInteractiveCardMessage(msg) {
        return !!(msg && msg.role === "assistant" && msg.html);
    }

    function findCardMessageIndex(index) {
        for (var i = index - 1; i >= 0; i--) {
            if (isInteractiveCardMessage(state.messages[i])) return i;
        }
        return -1;
    }

    function goBackFromCard(row) {
        if (!row || !state.activeId) return;
        var idx = parseInt(row.getAttribute("data-index"), 10);
        if (isNaN(idx)) return;
        var parentIndex = findCardMessageIndex(idx);
        if (parentIndex === -1) {
            clearConversationToStart();
            return;
        }
        var keep = parentIndex + 1;
        var removed = state.messages.slice(keep);
        if (!removed.length) return;
        state.messages = state.messages.slice(0, keep);
        if (chatWindow) {
            Array.prototype.forEach.call(chatWindow.querySelectorAll(".ws-message[data-index]"), function (node) {
                var nodeIndex = parseInt(node.getAttribute("data-index"), 10);
                if (nodeIndex >= keep && node.parentNode) node.parentNode.removeChild(node);
            });
        }
        fetch("/api/conversations/" + encodeURIComponent(state.activeId) + "/truncate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ keep: keep })
        }).catch(function () {}).then(function () {
            loadConversations();
            loadConversationInsights();
        });
        updateSessionMetrics();
        scrollToBottom();
    }

    function clearConversationToStart() {
        if (!state.activeId) return;
        var id = state.activeId;
        fetch("/api/conversations/" + encodeURIComponent(id) + "/clear", { method: "POST" })
            .then(function (r) { return r.json(); })
            .then(function () {
                if (state.activeId !== id) return;
                state.messages = [];
                renderActiveConversation();
                loadConversations();
                loadConversationInsights();
            })
            .catch(function () {});
    }
    var DEFAULT_TOOL_ICON = '<path d="M12 3l1.9 4.6 4.6 1.9-4.6 1.9L12 16l-1.9-4.6L5.5 9.5l4.6-1.9L12 3z"/><path d="M18.5 15.5l.9 2.1 2.1.9-2.1.9-.9 2.1-.9-2.1-2.1-.9 2.1-.9.9-2.1z"/>';
    var LOGO_ICON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l1.9 4.6 4.6 1.9-4.6 1.9L12 16l-1.9-4.6L5.5 9.5l4.6-1.9L12 3z"/></svg>';

    // ============================================================
    // STATE
    // ============================================================

    var state = {
        conversations: [],
        messages: [],
        activeId: null,
        activeAgentId: null,
        activeAgent: null,
        agents: []
    };

    // ============================================================
    // STORAGE
    // ============================================================

    function now() {
        return Math.floor(Date.now() / 1000);
    }

    function newConvId() {
        return "conv-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 8);
    }

    // ============================================================
    // CONVERSATION MANAGEMENT
    // ============================================================

    function createConversation() {
        state.activeId = null;
        state.messages = [];
        renderConversationList();
        renderActiveConversation();
        updateSessionMetrics();
        return null;
    }

    function ensureActiveId() {
        if (!state.activeId) {
            state.activeId = newConvId();
            state.conversations.unshift({ id: state.activeId, title: "New chat", created: now(), updated: now(), message_count: 0 });
            renderConversationList();
        }
        return state.activeId;
    }

    function setActive(id) {
        state.activeId = id;
        state.messages = [];
        renderConversationList();
        renderActiveConversation();
        updateSessionMetrics();
        if (id) {
            loadMessages(id);
            loadConversationInsights();
        }
    }

    function loadMessages(id) {
        fetch("/api/conversations/" + encodeURIComponent(id) + "/messages")
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (state.activeId !== id) return;
                state.messages = (data && data.messages) || [];
                var bound = agentFromMessages(state.messages);
                if (bound && state.activeAgentId !== bound.id) {
                    setActiveAgent(bound);
                    if (window.setGlobalAgent) window.setGlobalAgent(bound);
                }
                renderActiveConversation();
                updateSessionMetrics();
            })
            .catch(function () {});
    }

    function loadConversations() {
        return fetch("/api/conversations")
            .then(function (r) { return r.json(); })
            .then(function (data) {
                state.conversations = (data && data.conversations) || [];
                renderConversationList();
                return state.conversations;
            })
            .catch(function () { return []; });
    }

    function persistMessages(messages) {
        if (!state.activeId) return;
        var payload = (messages || []).map(function (m) {
            return {
                role: m.role,
                content: m.content || "",
                ts: m.ts,
                html: m.html,
                cardTitle: m.cardTitle,
                tool: m.tool,
                usage: m.usage,
                agentName: m.agentName
            };
        });
        return fetch("/api/conversations/" + encodeURIComponent(state.activeId) + "/messages", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ messages: payload })
        }).catch(function () {});
    }

    // ============================================================
    // CONVERSATION LIST RENDERING
    // ============================================================

    function sameDay(a, b) {
        return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
    }

    function dateGroup(ts) {
        var d = new Date(ts * 1000);
        var today = new Date();
        var msgMidnight = new Date(d.getFullYear(), d.getMonth(), d.getDate());
        var todayMidnight = new Date(today.getFullYear(), today.getMonth(), today.getDate());
        var diff = Math.round((todayMidnight - msgMidnight) / 86400000);
        if (diff <= 0) return "Today";
        if (diff === 1) return "Yesterday";
        if (diff < 7) return "Previous 7 Days";
        return "Older";
    }

    function convItemTime(ts) {
        var d = new Date(ts * 1000);
        if (sameDay(d, new Date())) {
            return d.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
        }
        return d.toLocaleDateString([], { month: "short", day: "numeric" });
    }

    function renderConversationList() {
        if (!convList) return;
        var q = (convSearch.value || "").trim().toLowerCase();

        var list = state.conversations.slice().sort(function (a, b) {
            return (b.updated || 0) - (a.updated || 0);
        });

        if (q) {
            list = list.filter(function (c) {
                return (c.title || "").toLowerCase().indexOf(q) !== -1;
            });
        }

        convList.innerHTML = "";

        if (!list.length) {
            var empty = document.createElement("div");
            empty.className = "ws-conv-empty";
            empty.textContent = q ? "No conversations found." : "No conversations yet. Start a new chat.";
            convList.appendChild(empty);
            return;
        }

        var groups = ["Today", "Yesterday", "Previous 7 Days", "Older"];
        var grouped = {};
        list.forEach(function (c) {
            var g = dateGroup(c.updated || c.created);
            if (!grouped[g]) grouped[g] = [];
            grouped[g].push(c);
        });

        groups.forEach(function (g) {
            var items = grouped[g];
            if (!items || !items.length) return;
            var label = document.createElement("div");
            label.className = "ws-conv-group-label";
            label.textContent = g;
            convList.appendChild(label);

            var groupEl = document.createElement("div");
            groupEl.className = "ws-conv-group";
            convList.appendChild(groupEl);

            items.forEach(function (c) {
                var item = document.createElement("button");
                item.className = "ws-conv-item" + (c.id === state.activeId ? " active" : "");
                item.setAttribute("data-conv-id", c.id);
                item.innerHTML =
                    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z"/></svg>' +
                    '<span class="ws-conv-item-title">' + escapeHtml(c.title || "New chat") + "</span>" +
                    '<span class="ws-conv-item-time">' + convItemTime(c.updated || c.created) + "</span>";
                item.addEventListener("click", function () { setActive(c.id); });
                groupEl.appendChild(item);
            });
        });
    }

    // ============================================================
    // MESSAGE RENDERING
    // ============================================================

    function scrollToBottom() {
        if (chatWindow) chatWindow.scrollTop = chatWindow.scrollHeight;
    }

    function buildRow(role) {
        var row = document.createElement("div");
        row.className = "ws-message" + (role === "user" ? " ws-message-user" : "");
        return row;
    }

    function metaRow(msg) {
        var row = document.createElement("div");
        row.className = "ws-msg-meta";
        var time = document.createElement("span");
        time.className = "ws-msg-time";
        time.textContent = msg.ts ? formatTime(msg.ts) : "";
        row.appendChild(time);
        if (msg.content) {
            var copy = document.createElement("button");
            copy.className = "ws-msg-copy";
            copy.innerHTML = COPY_ICON + " Copy";
            copy.addEventListener("click", function () { copyText(msg.content); });
            row.appendChild(copy);
        }
        return row;
    }

    function renderUserMessage(msg, index) {
        var row = buildRow("user");
        if (typeof index === "number") row.dataset.index = String(index);
        var avatar = document.createElement("div");
        avatar.className = "ws-msg-avatar";
        avatar.innerHTML = '<span class="ws-user-avatar">You</span>';
        var body = document.createElement("div");
        body.className = "ws-msg-body";
        var text = document.createElement("div");
        text.className = "ws-msg-text";
        var p = document.createElement("p");
        p.textContent = msg.content;
        text.appendChild(p);
        body.appendChild(text);
        body.appendChild(metaRow(msg));
        row.appendChild(avatar);
        row.appendChild(body);
        chatWindow.appendChild(row);
    }

    function toolCardHtml(name, bodyHtml, link, icon) {
        var h = '<div class="ws-tool-card">';
        h += '<div class="ws-tool-card-head">';
        h += '<span class="ws-tool-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">' + (icon || DEFAULT_TOOL_ICON) + "</svg></span>";
        h += '<span class="ws-tool-name">' + escapeHtml(name) + "</span>";
        h += '<span class="ws-tool-status"><span class="pulse-dot"></span>Completed</span>';
        h += "</div>";
        h += '<div class="ws-tool-card-body ws-msg-text">' + bodyHtml + "</div>";
        if (link) {
            h += '<div class="ws-tool-card-foot"><a class="ws-tool-link" href="' + link.href + '">' + escapeHtml(link.label) + " " + ARROW_ICON + "</a></div>";
        }
        h += "</div>";
        return h;
    }

    function assistantBodyHtml(msg) {
        if (msg.html) {
            return toolCardHtml(msg.cardTitle || "Firewall Data", msg.html, null);
        }
        if (msg.tool && TOOL_META[msg.tool]) {
            var meta = TOOL_META[msg.tool];
            var link = msg.link || meta.link;
            return toolCardHtml(meta.name, formatAgentReply(msg.content), link, meta.icon);
        }
        return '<div class="ws-msg-text">' + formatAgentReply(msg.content || "") + "</div>";
    }

    function renderAssistantMessage(msg, index) {
        var row = buildRow("assistant");
        if (typeof index === "number") row.dataset.index = String(index);
        var agentName = resolveAgentName(msg.agentName) || (state.activeAgent ? state.activeAgent.name : "Firewall Audit Agent");
        var avatar = document.createElement("div");
        avatar.className = "ws-msg-avatar";
        avatar.innerHTML = '<span class="agent-avatar agent-avatar-blue">' + escapeHtml(avatarFor(agentName)) + "</span>";

        var body = document.createElement("div");
        body.className = "ws-msg-body";
        var agent = document.createElement("span");
        agent.className = "ws-msg-agent";
        agent.textContent = agentName;
        body.appendChild(agent);

        var rich = document.createElement("div");
        rich.innerHTML = assistantBodyHtml(msg);
        body.appendChild(rich);

        if (msg.usage && Object.keys(msg.usage).length) {
            var usage = document.createElement("div");
            usage.className = "ws-msg-usage";
            usage.textContent = usageText(msg.usage);
            body.appendChild(usage);
        }

        body.appendChild(metaRow(msg));

        row.appendChild(avatar);
        row.appendChild(body);
        chatWindow.appendChild(row);
    }

    function renderMessage(msg, index) {
        if (!chatWindow) return;
        if (msg.role === "user") renderUserMessage(msg, index);
        else renderAssistantMessage(msg, index);
        scrollToBottom();
    }

    function renderActiveConversation() {
        if (!chatWindow) return;
        chatWindow.innerHTML = "";
        if (!state.messages.length) {
            renderEmptyState();
            updateSessionMetrics();
            return;
        }
        state.messages.forEach(renderMessage);
        updateSessionMetrics();
    }

    function appendMessage(msg) {
        state.messages.push(msg);
        renderMessage(msg, state.messages.length - 1);
        updateSessionMetrics();
    }

    function appendTyping(agentName) {
        var row = buildRow("assistant");
        row.dataset.typing = "true";
        var name = resolveAgentName(agentName) || (state.activeAgent ? state.activeAgent.name : "Firewall Audit Agent");
        var avatar = document.createElement("div");
        avatar.className = "ws-msg-avatar";
        avatar.innerHTML = '<span class="agent-avatar agent-avatar-blue">' + escapeHtml(avatarFor(name)) + "</span>";
        var body = document.createElement("div");
        body.className = "ws-msg-body";
        body.innerHTML = '<span class="ws-msg-agent">' + escapeHtml(name) + '</span><div class="ws-typing"><span></span><span></span><span></span></div>';
        row.appendChild(avatar);
        row.appendChild(body);
        chatWindow.appendChild(row);
        scrollToBottom();
        return row;
    }

    function removeTyping(node) {
        if (node && node.parentNode) node.parentNode.removeChild(node);
    }

    function usageText(usage) {
        var parts = [];
        if (usage.total_tokens != null) parts.push(usage.total_tokens.toLocaleString("en-US") + " tokens");
        if (usage.input_tokens != null) parts.push(usage.input_tokens.toLocaleString("en-US") + " in");
        if (usage.output_tokens != null) parts.push(usage.output_tokens.toLocaleString("en-US") + " out");
        return parts.length ? parts.join(" \u00b7 ") : "Token usage tracked";
    }

    // ============================================================
    // EMPTY STATE
    // ============================================================

    function renderEmptyState() {
        if (!chatWindow) return;
        chatWindow.innerHTML = "";
        var wrap = document.createElement("div");
        wrap.className = "ws-empty";
        wrap.innerHTML =
            '<div class="ws-empty-mark">' + LOGO_ICON + "</div>" +
            "<h2>How can I help secure your environment today?</h2>" +
            "<p>Talk to your security copilot \u2014 run compliance assessments, review findings, and generate executive reports.</p>" +
            '<div class="ws-suggestions"></div>';
        chatWindow.appendChild(wrap);

        var sug = wrap.querySelector(".ws-suggestions");
        if (isFirewallAgent(state.activeAgent)) {
            SUGGESTIONS.forEach(function (s) {
                var b = document.createElement("button");
                b.className = "ws-suggestion";
                b.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5v14M5 12h14"/></svg>' + escapeHtml(s.label);
                b.addEventListener("click", function () { runAction(s.action); });
                sug.appendChild(b);
            });
        } else if (isCloudAgent(state.activeAgent)) {
            CLOUD_SUGGESTIONS.forEach(function (s) {
                var b = document.createElement("button");
                b.className = "ws-suggestion";
                b.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5v14M5 12h14"/></svg>' + escapeHtml(s.label);
                b.addEventListener("click", function () { runAction(s.action); });
                sug.appendChild(b);
            });
        } else if (isNetsecAgent(state.activeAgent)) {
            NETSEC_SUGGESTIONS.forEach(function (s) {
                var b = document.createElement("button");
                b.className = "ws-suggestion";
                b.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5v14M5 12h14"/></svg>' + escapeHtml(s.label);
                b.addEventListener("click", function () { runAction(s.action); });
                sug.appendChild(b);
            });
        }
    }

    // ============================================================
    // PROMPT CHIPS
    // ============================================================

    function renderPromptChips() {
        if (!promptChips) return;
        promptChips.innerHTML = "";
        var entries = [];
        if (isFirewallAgent(state.activeAgent)) {
            entries = fwChipEntries();
        } else if (isCloudAgent(state.activeAgent)) {
            entries = CLOUD_CHIPS;
        } else if (isNetsecAgent(state.activeAgent)) {
            entries = NETSEC_CHIPS;
        }
        entries.forEach(function (a) {
            var b = document.createElement("button");
            b.className = "ws-chip";
            b.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">' + (a.icon || '<path d="M12 5v14M5 12h14"/>') + "</svg>" + escapeHtml(a.label);
            b.addEventListener("click", function () { runAction(a.action || a.id); });
            promptChips.appendChild(b);
        });
    }

    function runAction(action) {
        if (FIREWALL_ACTIONS[action]) {
            startFirewallFlow(action);
            return;
        }
        if (action === "incidents") {
            showCloudIncidentsPanel();
            return;
        }
        if (action === "vm") {
            showCloudVmPanel();
            return;
        }
        if (window.NetsecPanel && (action === "ns-action" || action === "ns-manual" || action === "ns-bulk")) {
            window.NetsecPanel.startChat(action);
            return;
        }
    }

    // ============================================================
    // COMPLIANCE ASSESSMENT MCQ
    // ============================================================

    var selectedFirewall = "vmpafw01";
    var assessmentCache = {};
    var estateCache = null;
    var inventoryPromise = null;

    // ------------------------------------------------------------
    // Inventory search + device-first flow (works for every action)
    // ------------------------------------------------------------

    function fetchFirewallInventory() {
        if (inventoryPromise) return inventoryPromise;
        inventoryPromise = fetch("/api/firewall-inventory")
            .then(function (r) { return r.json(); })
            .then(function (data) { return (data && data.firewalls) || []; })
            .catch(function () { return []; });
        return inventoryPromise;
    }

    function intentLabel(intent) {
        var meta = FIREWALL_ACTIONS[intent];
        return meta ? meta.label : "Firewall operation";
    }

    function fwPickerCardHtml(intent) {
        return '<div class="ws-mcq-card fw-picker-card">' +
            '<div class="ws-mcq-head"><strong>Select Firewall</strong>' +
            "<span>" + escapeHtml(intentLabel(intent)) + " \u2014 type a device name or IP, or enter \u201cfull inventory\u201d to assess every managed firewall.</span></div>" +
            '<form class="fw-search-box" data-fw-go="1">' +
            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>' +
            '<input type="text" class="fw-search-input" placeholder="Search device name / IP, or type full inventory" autocomplete="off" aria-label="Search firewall inventory">' +
            '<button type="submit" class="fw-search-go" title="Run assessment for selection" aria-label="Go">' +
            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12h14"/><path d="M13 6l6 6-6 6"/></svg>' +
            "</button>" +
            "</form>" +
            '<div class="fw-search-hint" role="status"></div>' +
            backButtonHtml() +
            "</div>";
    }

    function startFirewallFlow(intent) {
        ensureActiveId();
        appendMessage({ role: "user", content: intentLabel(intent), ts: now() });
        renderConversationList();
        openFwPicker(intent);
    }

    function openFwPicker(intent) {
        ensureActiveId();
        fetchFirewallInventory().then(function (list) {
            if (!list || !list.length) {
                appendMessage({
                    role: "assistant",
                    content: "No firewalls are registered in the inventory yet. An administrator can add devices from Settings > Firewall Inventory.",
                    agentName: "Firewall Audit Agent",
                    ts: now()
                });
                renderConversationList();
                return;
            }
            appendMessage({ role: "assistant", content: "", html: fwPickerCardHtml(intent), cardTitle: "Select Firewall", agentName: "Firewall Audit Agent", ts: now() });
            renderConversationList();
            scrollToBottom();

            var bodies = chatWindow.querySelectorAll(".ws-msg-body");
            var last = bodies[bodies.length - 1];
            var card = last ? last.querySelector(".fw-picker-card") : null;
            if (card) wireFwPicker(card, list, intent);
        });
    }

    function resolveFwQuery(list, rawQuery) {
        var q = String(rawQuery || "").trim().toLowerCase();
        if (!q) {
            return { kind: "none", reason: "Type a firewall device name or IP, or enter \u201cfull inventory\u201d to assess every device." };
        }
        if (q === "all" || q === "full" || q === "estate" || q === "all devices" ||
            q === "full inventory" || q.indexOf("inventory") !== -1) {
            return { kind: "all" };
        }
        var exact = [], partial = [];
        list.forEach(function (fw) {
            var name = fw.device_name || "";
            var hay = (name + " " + (fw.host_ip || "") + " " + (fw.clone_of || "")).toLowerCase();
            if (name.toLowerCase() === q) { exact.push(fw); return; }
            if (hay.indexOf(q) !== -1) partial.push(fw);
        });
        if (exact.length === 1) return { kind: "device", name: exact[0].device_name };
        if (exact.length > 1) return { kind: "device", name: exact[0].device_name };
        if (partial.length === 1) return { kind: "device", name: partial[0].device_name };
        if (partial.length > 1) {
            var names = partial.slice(0, 3).map(function (f) { return f.device_name; }).join(", ");
            if (partial.length > 3) names += ", \u2026";
            return { kind: "none", reason: "Multiple firewalls match \u201c" + String(rawQuery).trim() + "\u201d (" + names + "). Type a full device name, or enter \u201cfull inventory\u201d for all devices." };
        }
        return { kind: "none", reason: "No firewall matches \u201c" + String(rawQuery).trim() + "\u201d. Check the device name or IP, or enter \u201cfull inventory\u201d to assess every device." };
    }

    function wireFwPicker(card, list, intent) {
        var input = card.querySelector(".fw-search-input");
        var hint = card.querySelector(".fw-search-hint");
        var form = card.querySelector('[data-fw-go="1"]');
        if (!input || !form) return;

        function go() {
            var res = resolveFwQuery(list, input.value);
            if (hint) {
                hint.textContent = "";
                hint.classList.remove("is-error");
            }
            if (res.kind === "all") { handleFwPick(intent, { all: true }); return; }
            if (res.kind === "device") { handleFwPick(intent, { name: res.name }); return; }
            if (hint) {
                hint.textContent = res.reason || "";
                hint.classList.add("is-error");
            }
            input.focus();
        }

        form.addEventListener("submit", function (e) { e.preventDefault(); go(); });
        if (hint) {
            input.addEventListener("input", function () {
                hint.textContent = "";
                hint.classList.remove("is-error");
            });
        }
        setTimeout(function () { if (input) input.focus(); }, 80);
    }

    function busy(node) {
        if (sendBtn) sendBtn.disabled = true;
        return node || appendTyping("Firewall Audit Agent");
    }

    function idle(node) {
        if (node) removeTyping(node);
        if (sendBtn) sendBtn.disabled = false;
        if (promptInput) promptInput.focus();
    }

    function handleFwPick(intent, pick) {
        if (pick.all) { loadEstateCard(); return; }
        selectedFirewall = pick.name || selectedFirewall;
        if (intent === "summary") { runSummaryForDevice(selectedFirewall); return; }
        if (intent === "excel") { runReportForDevice(selectedFirewall); return; }
        if (intent === "ha") { showSectionForDevice("ha", selectedFirewall); return; }
        showMcqCard(selectedFirewall, true);
    }

    function runSummaryForDevice(device) {
        selectedFirewall = device || selectedFirewall;
        var node = busy();
        fetch("/executive-summary?firewall=" + encodeURIComponent(selectedFirewall))
            .then(function (r) { return r.ok; })
            .then(function (ok) {
                idle(node);
                if (!ok) throw new Error("failed");
                appendMessage({ role: "assistant", content: "Executive summary for **" + selectedFirewall + "** generated and stored in Reports.", tool: "summary", ts: now() });
                loadConversations();
            })
            .catch(function () {
                idle(node);
                appendMessage({ role: "assistant", content: "Executive summary generation failed.", ts: now() });
            });
    }

    function runReportForDevice(device) {
        selectedFirewall = device || selectedFirewall;
        var node = busy();
        fetch("/api/excel?firewall=" + encodeURIComponent(selectedFirewall))
            .then(function (r) { return r.json(); })
            .then(function (data) {
                idle(node);
                if (data && data.error) throw new Error(data.error);
                appendMessage({ role: "assistant", content: "Assessment workbook for **" + selectedFirewall + "** generated and stored in Reports.", tool: "excel", ts: now() });
                loadConversations();
            })
            .catch(function () {
                idle(node);
                appendMessage({ role: "assistant", content: "Report generation failed.", ts: now() });
            });
    }

    function showSectionForDevice(sectionId, device) {
        var section = null;
        for (var i = 0; i < ASSESSMENT_SECTIONS.length; i++) {
            if (ASSESSMENT_SECTIONS[i].id === sectionId) { section = ASSESSMENT_SECTIONS[i]; break; }
        }
        if (!section) return;
        selectedFirewall = device || selectedFirewall;
        if (section.action === "report") { runReportForDevice(selectedFirewall); return; }
        if (section.action === "summary") { runSummaryForDevice(selectedFirewall); return; }
        loadSectionData(section, true);
    }

    // ------------------------------------------------------------
    // Full Inventory (estate) assessment
    // ------------------------------------------------------------

    function estateKpiHtml(c) {
        var rows = [
            { label: "Compliant", sub: "Avg across " + c.device_count + " device" + (c.device_count === 1 ? "" : "s"), value: (c.avg_compliance_pct == null ? "-" : c.avg_compliance_pct + "%") },
            { label: "Non-Compliant", sub: "Average", value: (c.avg_non_compliant_pct == null ? "-" : c.avg_non_compliant_pct + "%") },
            { label: "Not Assessed", sub: "Average", value: (c.avg_not_assessed_pct == null ? "-" : c.avg_not_assessed_pct + "%") },
            { label: "Findings", sub: "Full inventory", value: c.total_findings }
        ];
        return '<div class="ws-kpi-row">' + rows.map(function (k) { return kpiCard(k.label, k.sub, k.value); }).join("") + "</div>";
    }

    function estateStatusPill(status) {
        return '<span class="fw-status ' + (status === "live" ? "is-live" : "is-down") + '">' + escapeHtml(status === "live" ? "Live" : "Down") + "</span>";
    }

    function estateDeviceRows(devices) {
        var html = devices.map(function (d) {
            var sev = d.severity || {};
            var tag = d.is_clone ? '<span class="fw-badge-clone">Clone of ' + escapeHtml(d.clone_of || "parent") + "</span>" : "";
            return '<div class="ws-estate-dev">' +
                '<div class="ws-estate-dev-name">' + escapeHtml(d.device) + " " + tag + " " + estateStatusPill(d.status) + "</div>" +
                '<div class="ws-estate-dev-meta">' +
                d.compliance_pct + "% compliant \u00b7 " + d.compliant + "/" + d.total_controls + " controls \u00b7 " +
                d.non_compliant + " non-compliant \u00b7 " + d.not_assessed + " not assessed \u00b7 " + d.findings_count + " findings" +
                " (C:" + sev.critical + " H:" + sev.high + " M:" + sev.medium + " L:" + sev.low + ")" +
                "</div>" +
                "</div>";
        }).join("");
        return '<div class="ws-estate-devices">' + html + "</div>";
    }

    function estateActionsHtml(c) {
        var count = (c && c.device_count) || 0;
        return '<div class="ws-estate-actions">' +
            '<button type="button" class="ws-estate-run" data-estate-action="summary">' + ARROW_ICON + "Executive Summary (all " + count + ")</button>" +
            '<button type="button" class="ws-estate-run" data-estate-action="excel">' + ARROW_ICON + "Generate Report (all " + count + ")</button>" +
            "</div>";
    }

    function estateCardHtml(data) {
        var c = data.cumulative || {};
        return estateKpiHtml(c) +
            '<div class="ws-mcq-head"><strong>Devices Assessed</strong><span>Per-device compliance across the managed inventory.</span></div>' +
            estateDeviceRows(data.devices || []) +
            '<div class="ws-mcq-head"><strong>Full Inventory Outputs</strong><span>Generate a summary or workbook that covers every firewall.</span></div>' +
            estateActionsHtml(c) +
            backButtonHtml();
    }

    function loadEstateCard() {
        ensureActiveId();
        var node = busy();
        fetch("/api/estate/assessment?refresh=1")
            .then(function (r) { return r.json(); })
            .then(function (data) {
                idle(node);
                if (!data || data.error) throw new Error((data && data.error) || "Full inventory assessment failed.");
                estateCache = data;
                appendMessage({
                    role: "assistant",
                    content: "",
                    html: estateCardHtml(data),
                    cardTitle: "Full Inventory \u2014 Cumulative Compliance",
                    agentName: "Firewall Audit Agent",
                    ts: now()
                });
                renderConversationList();
            })
            .catch(function (err) {
                idle(node);
                appendMessage({
                    role: "assistant",
                    content: (err && err.message) || "Full inventory assessment failed. Try again.",
                    agentName: "Firewall Audit Agent",
                    ts: now()
                });
                renderConversationList();
            });
    }

    function estateSummaryHtml(data) {
        var c = data.cumulative || {};
        var html = estateKpiHtml(c);
        html += '<div class="ws-mcq-head"><strong>Device-by-device details</strong><span>Compliance and key remediation actions for every managed firewall.</span></div>';
        (data.devices || []).forEach(function (d) {
            var tone = d.compliance_pct >= 80 ? "good" : (d.compliance_pct >= 50 ? "warn" : "bad");
            html += '<div class="ws-section-card">' +
                '<div class="ws-section-title">' + escapeHtml(d.device) +
                (d.is_clone ? ' <span class="fw-badge-clone">Clone of ' + escapeHtml(d.clone_of || "parent") + "</span>" : "") +
                " " + estateStatusPill(d.status) + "</div>";
            html += '<div class="ws-section-compliance"><span class="ws-comp-badge ' + tone + '">' + d.compliant + " / " + d.total_controls + " compliant</span>" +
                '<span class="ws-comp-pct">' + d.compliance_pct + "%</span></div>";
            var recs = remediationList(d.findings || []);
            if (recs.length) {
                html += '<div class="ws-section-recs"><strong>Key remediations</strong><ul>' +
                    recs.map(function (r) { return "<li>" + escapeHtml(r) + "</li>"; }).join("") +
                    "</ul></div>";
            } else if (d.compliance_pct >= 80) {
                html += '<div class="ws-section-recs"><strong>All compliant</strong> \u2014 no recommendations needed.</div>';
            }
            html += "</div>";
        });
        return html + backButtonHtml();
    }

    function remediationList(findings) {
        var recs = [];
        var seen = {};
        (findings || []).forEach(function (f) {
            var r = f.remediation || (typeof FINDING_ENRICHMENT !== "undefined" && FINDING_ENRICHMENT[(f.control || "").toUpperCase()] ? FINDING_ENRICHMENT[(f.control || "").toUpperCase()].remediation : "") || "";
            if (r && !seen[r]) { seen[r] = true; recs.push(r); }
        });
        return recs.slice(0, 5);
    }

    function showEstateSummary() {
        if (!estateCache) { loadEstateCard(); return; }
        ensureActiveId();
        appendMessage({ role: "user", content: "Executive Summary \u2014 Full Inventory", ts: now() });
        renderConversationList();
        appendMessage({
            role: "assistant",
            content: "",
            html: estateSummaryHtml(estateCache),
            cardTitle: "Executive Summary \u2014 Full Inventory",
            agentName: "Firewall Audit Agent",
            ts: now()
        });
        renderConversationList();
    }

    function generateEstateWorkbook() {
        if (!estateCache) { loadEstateCard(); return; }
        ensureActiveId();
        appendMessage({ role: "user", content: "Report Generation \u2014 Full Inventory", ts: now() });
        renderConversationList();
        var node = busy();
        fetch("/api/estate/excel?refresh=1")
            .then(function (r) { return r.json(); })
            .then(function (data) {
                idle(node);
                if (!data || data.error) throw new Error((data && data.error) || "Workbook generation failed.");
                appendMessage({
                    role: "assistant",
                    content: "Full inventory assessment workbook generated and stored in Reports.",
                    tool: "excel",
                    link: { label: "Download workbook", href: data.download_url || "/download-workbook" },
                    ts: now()
                });
                loadConversations();
            })
            .catch(function (err) {
                idle(node);
                appendMessage({
                    role: "assistant",
                    content: (err && err.message) || "Full inventory workbook generation failed.",
                    agentName: "Firewall Audit Agent",
                    ts: now()
                });
            });
    }

    function runEstateAction(action) {
        if (action === "summary") { showEstateSummary(); return; }
        if (action === "excel") { generateEstateWorkbook(); return; }
    }

    function loadAssessmentData() {
        if (assessmentCache[selectedFirewall]) return Promise.resolve(assessmentCache[selectedFirewall]);
        return fetch("/api/findings?firewall=" + encodeURIComponent(selectedFirewall))
            .then(function (r) { return r.json(); })
            .then(function (data) { assessmentCache[selectedFirewall] = data; return data; })
            .catch(function () { return null; });
    }

    function kpiCard(label, sub, value) {
        return '<div class="ws-kpi"><span class="ws-kpi-label">' + escapeHtml(label) + '</span>' +
            '<strong class="ws-kpi-value">' + escapeHtml(value == null ? "-" : String(value)) + '</strong>' +
            '<span class="ws-kpi-sub">' + escapeHtml(sub) + '</span></div>';
    }

    function loadKpiCards() {
        return fetch("/api/dashboard?firewall=" + encodeURIComponent(selectedFirewall))
            .then(function (r) { return r.json(); })
            .then(function (data) {
                var c = data.compliance || {};
                return '<div class="ws-kpi-row">' +
                    kpiCard("Scope", "Total Controls", c.total_controls) +
                    kpiCard("Compliant", "Compliant", c.compliant) +
                    kpiCard("Issues", "Non-Compliant", c.non_compliant) +
                    kpiCard("Pending", "Not Assessed", c.not_assessed) +
                    kpiCard("Score", "Compliance Score", (c.compliance_score == null ? "-" : c.compliance_score + "%")) +
                    "</div>";
            })
            .catch(function () { return '<div class="ws-kpi-row"></div>'; });
    }

    function showMcqCard(firewall, skipUser) {
        if (firewall) selectedFirewall = firewall;
        ensureActiveId();
        if (!skipUser) {
            appendMessage({ role: "user", content: "Compliance Assessment \u2014 " + selectedFirewall, ts: now() });
            renderConversationList();
        }

        loadKpiCards().then(function (kpiHtml) {
            var options = ASSESSMENT_SECTIONS.map(function (s) {
                return '<button class="mcq-option" type="button" data-section="' + s.id + '">' +
                    '<span class="mcq-option-label">' + escapeHtml(s.label) + '</span>' +
                    '<span class="mcq-option-arrow">' + ARROW_ICON + '</span>' +
                    '</button>';
            }).join("");

            var html = '<div class="ws-mcq-card">' +
                kpiHtml +
                '<div class="ws-mcq-head"><strong>Compliance Assessment</strong><span>Select a section to review</span></div>' +
                '<div class="ws-mcq-options">' + options + '</div>' +
                backButtonHtml() +
                '</div>';

            appendMessage({ role: "assistant", content: "", html: html, cardTitle: "Compliance Assessment", agentName: "Firewall Audit Agent", ts: now() });
            renderConversationList();
        });
    }

    function showSection(sectionId) {
        var section = null;
        for (var i = 0; i < ASSESSMENT_SECTIONS.length; i++) {
            if (ASSESSMENT_SECTIONS[i].id === sectionId) { section = ASSESSMENT_SECTIONS[i]; break; }
        }
        if (!section) return;

        if (section.action === "report") { generateReportFromMcq(); return; }
        if (section.action === "summary") { generateSummaryFromMcq(); return; }
        loadSectionData(section);
    }

    function generateReportFromMcq() {
        ensureActiveId();
        appendMessage({ role: "user", content: "Report Generation", ts: now() });
        renderConversationList();
        var typing = appendTyping();
        sendBtn.disabled = true;
        fetch("/api/excel?firewall=" + encodeURIComponent(selectedFirewall))
            .then(function (r) { return r.json(); })
            .then(function (data) {
                removeTyping(typing);
                if (data && data.error) throw new Error(data.error);
                appendMessage({ role: "assistant", content: "Assessment workbook generated and stored in Reports.", tool: "excel", ts: now() });
                loadConversations();
            })
            .catch(function () {
                removeTyping(typing);
                appendMessage({ role: "assistant", content: "Report generation failed.", ts: now() });
            })
            .finally(function () { sendBtn.disabled = false; promptInput.focus(); });
    }

    function generateSummaryFromMcq() {
        ensureActiveId();
        appendMessage({ role: "user", content: "Executive Summary", ts: now() });
        renderConversationList();
        var typing = appendTyping();
        sendBtn.disabled = true;
        fetch("/executive-summary?firewall=" + encodeURIComponent(selectedFirewall))
            .then(function (r) { return r.ok; })
            .then(function (ok) {
                removeTyping(typing);
                if (!ok) throw new Error("failed");
                appendMessage({ role: "assistant", content: "Executive summary generated and stored in Reports.", tool: "summary", ts: now() });
                loadConversations();
            })
            .catch(function () {
                removeTyping(typing);
                appendMessage({ role: "assistant", content: "Executive summary generation failed.", ts: now() });
            })
            .finally(function () { sendBtn.disabled = false; promptInput.focus(); });
    }

    function loadSectionData(section, skipUser) {
        ensureActiveId();
        if (!skipUser) {
            appendMessage({ role: "user", content: section.label, ts: now() });
            renderConversationList();
        }
        var typing = appendTyping("Firewall Audit Agent");
        sendBtn.disabled = true;

        var dataPromise = section.endpoint
            ? fetch(section.endpoint + "?firewall=" + encodeURIComponent(selectedFirewall)).then(function (r) { return r.json(); }).catch(function () { return null; })
            : Promise.resolve(null);
        var assessPromise = loadAssessmentData();

        Promise.all([dataPromise, assessPromise]).then(function (results) {
            removeTyping(typing);
            var sectionData = results[0];
            var assess = results[1];
            var html = buildSectionHtml(section, sectionData, assess);
            appendMessage({ role: "assistant", content: "", html: html, cardTitle: section.label, agentName: "Firewall Audit Agent", ts: now() });
            renderConversationList();
        }).finally(function () { sendBtn.disabled = false; promptInput.focus(); });
    }

    function controlDomain(cid) {
        if (typeof FINDING_ENRICHMENT !== "undefined" && FINDING_ENRICHMENT[cid]) {
            return FINDING_ENRICHMENT[cid].domain;
        }
        return null;
    }

    function computeSectionCompliance(assess, domains) {
        var total = 0, compliant = 0;
        var controls = (assess && assess.assessment) || [];
        controls.forEach(function (c) {
            var cid = (c.control || "").toUpperCase();
            var domain = controlDomain(cid);
            if (domain && domains.indexOf(domain) !== -1) {
                total++;
                if ((c.status || "").toUpperCase() === "COMPLIANT") compliant++;
            }
        });
        var pct = total ? Math.round(compliant / total * 100) : 0;
        return { total: total, compliant: compliant, pct: pct };
    }

    function collectRecommendations(assess, domains) {
        var recs = [];
        var seen = {};
        var findings = (assess && assess.findings) || [];
        findings.forEach(function (f) {
            var cid = (f.control || "").toUpperCase();
            var domain = controlDomain(cid);
            if (domain && domains.indexOf(domain) !== -1) {
                var r = f.remediation || (typeof FINDING_ENRICHMENT !== "undefined" && FINDING_ENRICHMENT[cid] ? FINDING_ENRICHMENT[cid].remediation : "") || "";
                if (r && !seen[r]) { seen[r] = true; recs.push(r); }
            }
        });
        return recs.slice(0, 5);
    }

    function buildSectionHtml(section, sectionData, assess) {
        var compliance = computeSectionCompliance(assess, section.domains);
        var recs = collectRecommendations(assess, section.domains);

        var tone = compliance.pct >= 80 ? "good" : (compliance.pct >= 50 ? "warn" : "bad");

        var html = '<div class="ws-section-card">';
        html += '<div class="ws-section-title">' + escapeHtml(section.label) + '</div>';
        html += '<div class="ws-section-compliance">' +
            '<span class="ws-comp-badge ' + tone + '">' + compliance.compliant + ' / ' + compliance.total + ' compliant</span>' +
            '<span class="ws-comp-pct">' + compliance.pct + '%</span>' +
            '</div>';

        if (recs.length) {
            html += '<div class="ws-section-recs"><strong>Recommendations</strong><ul>';
            recs.forEach(function (r) { html += '<li>' + escapeHtml(r) + '</li>'; });
            html += '</ul></div>';
        } else if (compliance.total) {
            html += '<div class="ws-section-recs"><strong>All compliant</strong> \u2014 no recommendations needed.</div>';
        }

        if (sectionData && typeof sectionData === "object") {
            html += '<div class="ws-section-data"><strong>Section Data</strong><div class="ws-section-kv">';
            for (var k in sectionData) {
                if (sectionData.hasOwnProperty(k)) {
                    var v = sectionData[k];
                    var display = v === null ? "\u2014" : typeof v === "object" ? JSON.stringify(v).substring(0, 140) : String(v);
                    html += '<div class="ws-kv-row"><span>' + escapeHtml(k) + '</span><span>' + escapeHtml(display) + '</span></div>';
                }
            }
            html += '</div></div>';
        }
        html += '</div>';
        return html + backButtonHtml();
    }

    // ============================================================
    // CLOUD INCIDENT RESPONSE — INCIDENTS + VIRTUAL MACHINE
    // ============================================================

    function cloudAgentLabel() {
        if (state.activeAgent) return state.activeAgent.name;
        return "Cloud Security Ops Agent";
    }

    function cloudAssistMessage(content, tool, usage) {
        return {
            role: "assistant",
            content: content || "",
            tool: tool || null,
            usage: usage || null,
            agentName: cloudAgentLabel(),
            ts: now()
        };
    }

    function runCloudAction(userLabel, action, params, tool, opts) {
        opts = opts || {};
        ensureActiveId();
        var userMsg = { role: "user", content: userLabel, ts: now() };
        appendMessage(userMsg);
        renderConversationList();
        var typing = appendTyping(cloudAgentLabel());
        sendBtn.disabled = true;

        fetch("/api/cloudsec/action", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                action: action,
                params: params || {},
                agent_id: state.activeAgentId,
                conversation_id: state.activeId
            })
        })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                removeTyping(typing);
                if (data && data.error) throw new Error(data.error);
                var asstMsg = cloudAssistMessage(data.reply, action, data.usage);
                appendMessage(asstMsg);
                if (opts.persist !== false) {
                    persistMessages([userMsg, asstMsg]).then(function () {
                        loadConversations();
                        loadConversationInsights();
                    });
                } else {
                    loadConversations();
                }
            })
            .catch(function (error) {
                removeTyping(typing);
                var message = (error && error.message) || "Cloud operation failed.";
                var asstMsg = cloudAssistMessage("The cloud operation could not be completed. " + message, action, null);
                appendMessage(asstMsg);
                if (opts.persist !== false) {
                    persistMessages([userMsg, asstMsg]).then(function () {
                        loadConversations();
                    });
                }
                window.showToast("Cloud operation failed.", "error");
            })
            .finally(function () {
                sendBtn.disabled = false;
                if (promptInput) promptInput.focus();
            });
    }

    function cloudKpiHtml(period, count) {
        var icon = period.id === "daily"
            ? '<path d="M12 3v3M12 21v-3M3 12h3M21 12h-3M5.6 5.6l2.1 2.1M18.4 5.6l-2.1 2.1M5.6 18.4l2.1-2.1M18.4 18.4l-2.1-2.1"/><circle cx="12" cy="12" r="3.2"/>'
            : period.id === "weekly"
                ? '<path d="M6 3v2M18 3v2M3 8h18M5 5h14a2 2 0 012 2v12a2 2 0 01-2 2H5a2 2 0 01-2-2V7a2 2 0 012-2z"/>'
                : '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/>';
        return '<button class="ws-kpi ws-cloud-kpi" type="button" data-cloud-period="' + period.id + '">' +
            '<span class="ws-kpi-label"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">' + icon + "</svg>" + escapeHtml(period.label) + "</span>" +
            '<strong class="ws-kpi-value" data-cloud-count="' + period.id + '">' + (count == null ? "\u2014" : String(count)) + "</strong>" +
            '<span class="ws-kpi-sub">' + escapeHtml(period.sub) + " \u00b7 click to view</span>" +
            "</button>";
    }

    function cloudPanelMsg(html, cardTitle) {
        return { role: "assistant", content: "", html: html, cardTitle: cardTitle, agentName: cloudAgentLabel(), ts: now() };
    }

    function cloudIncidentsPanelHtml(counts) {
        counts = counts || {};
        var kpis = CLOUD_KPI_PERIODS.map(function (p) { return cloudKpiHtml(p, counts[p.id]); }).join("");
        return '<div class="ws-cloud-card ws-mcq-card">' +
            '<div class="ws-mcq-head"><strong>Incident Response</strong><span>Daily, weekly, and monthly Sentinel incident counts. Open a period to view the latest five incidents.</span></div>' +
            '<div class="ws-kpi-row ws-cloud-kpi-row">' + kpis + "</div>" +
            '<div class="ws-mcq-head"><strong>Investigate Incident</strong><span>Enter a Sentinel incident ID to investigate.</span></div>' +
            '<div class="ws-cloud-block">' +
            '<div class="ws-cloud-fields">' +
            '<input class="ws-cloud-input" type="text" data-cloud-param="incident_id" placeholder="Sentinel incident ID" autocomplete="off">' +
            "</div>" +
            '<button class="ws-cloud-run" type="button" data-cloud-action="investigate">' + ARROW_ICON + "Investigate</button>" +
            "</div>" +
            '<div class="ws-mcq-head"><strong>Incident Summary</strong><span>Generate an investigation summary for a Sentinel incident.</span></div>' +
            '<div class="ws-cloud-block">' +
            '<div class="ws-cloud-fields">' +
            '<input class="ws-cloud-input" type="text" data-cloud-param="incident_id" placeholder="Sentinel incident ID" autocomplete="off">' +
            "</div>" +
            '<button class="ws-cloud-run" type="button" data-cloud-action="incident_summary">' + ARROW_ICON + "Generate Summary</button>" +
            "</div>" +
            '<div class="ws-mcq-head"><strong>Take Action \u2014 Isolate VM</strong><span>Contain a compromised virtual machine.</span></div>' +
            '<div class="ws-cloud-block">' +
            '<div class="ws-cloud-fields ws-cloud-fields-duo">' +
            '<input class="ws-cloud-input" type="text" data-cloud-param="vm_name" placeholder="VM name" autocomplete="off">' +
            '<input class="ws-cloud-input" type="text" data-cloud-param="resource_group" placeholder="Resource group" autocomplete="off">' +
            "</div>" +
            '<button class="ws-cloud-run ws-cloud-run-danger" type="button" data-cloud-action="isolate">' + ARROW_ICON + "Isolate VM</button>" +
            "</div>" +
            "</div>" +
            backButtonHtml() +
            "</div>";
    }

    function showCloudIncidentsPanel() {
        ensureActiveId();
        var userMsg = { role: "user", content: "Incidents", ts: now() };
        appendMessage(userMsg);
        renderConversationList();

        var typing = appendTyping(cloudAgentLabel());
        sendBtn.disabled = true;

        fetch("/api/cloudsec/action", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                action: "incident_counts",
                params: {},
                agent_id: state.activeAgentId,
                conversation_id: state.activeId
            })
        })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                removeTyping(typing);
                if (data && data.error) throw new Error(data.error);
                var counts = (data && data.counts) || {};
                appendIncidentPanel(userMsg, counts);
            })
            .catch(function () {
                removeTyping(typing);
                appendIncidentPanel(userMsg, {});
                window.showToast("Incident counts are unavailable right now.", "error");
            })
            .finally(function () {
                sendBtn.disabled = false;
                if (promptInput) promptInput.focus();
            });
    }

    function appendIncidentPanel(userMsg, counts) {
        var panelMsg = cloudPanelMsg(cloudIncidentsPanelHtml(counts), "Incident Response");
        appendMessage(panelMsg);
        persistMessages([userMsg, panelMsg]).then(function () {
            loadConversations();
            loadConversationInsights();
        });
        if (chatWindow) chatWindow.scrollTop = chatWindow.scrollHeight;
    }

    function showCloudVmPanel() {
        ensureActiveId();
        var userMsg = { role: "user", content: "Virtual Machine", ts: now() };
        appendMessage(userMsg);
        renderConversationList();

        var vmBtns = [
            { action: "vm_instance_view", label: "Status / Health", cls: "" },
            { action: "vm_context", label: "Config / Context", cls: "" },
            { action: "start_vm", label: "Start", cls: "ws-cloud-run-ok" },
            { action: "restart_vm", label: "Restart", cls: "" },
            { action: "stop_vm", label: "Stop", cls: "ws-cloud-run-warn" },
            { action: "reconnect_vm", label: "Reconnect", cls: "" }
        ].map(function (b) {
            return '<button class="ws-cloud-run ' + b.cls + '" type="button" data-cloud-action="' + b.action + '">' + escapeHtml(b.label) + "</button>";
        }).join("");

        var html = '<div class="ws-cloud-card ws-mcq-card">' +
            '<div class="ws-mcq-head"><strong>Virtual Machine</strong><span>Check status and health, view configuration, or start, restart, stop, and restore connectivity for an Azure VM.</span></div>' +
            '<div class="ws-cloud-block">' +
            '<div class="ws-cloud-fields ws-cloud-fields-duo">' +
            '<input class="ws-cloud-input" type="text" data-cloud-param="vm_name" placeholder="VM name" autocomplete="off">' +
            '<input class="ws-cloud-input" type="text" data-cloud-param="resource_group" placeholder="Resource group" autocomplete="off">' +
            "</div>" +
            '<div class="ws-cloud-actions">' + vmBtns + "</div>" +
            "</div>" +
            backButtonHtml() +
            "</div>";

        var panelMsg = cloudPanelMsg(html, "Virtual Machine");
        appendMessage(panelMsg);
        persistMessages([userMsg, panelMsg]).then(function () {
            loadConversations();
            loadConversationInsights();
        });
        if (promptInput) promptInput.focus();
    }

    function cloudPanelParams(panel) {
        var params = {};
        if (!panel) return params;
        panel.querySelectorAll("input[data-cloud-param]").forEach(function (input) {
            var key = input.getAttribute("data-cloud-param");
            params[key] = (input.value || "").trim();
        });
        return params;
    }

    function cloudRequiresParams(action) {
        if (action === "investigate" || action === "incident_summary") return ["incident_id"];
        if (action === "isolate") return ["vm_name", "resource_group"];
        if (action === "start_vm" || action === "stop_vm" || action === "restart_vm" || action === "reconnect_vm" ||
            action === "vm_context" || action === "vm_instance_view") {
            return ["vm_name", "resource_group"];
        }
        return [];
    }

    function cloudUserLabel(action, params) {
        if (action === "investigate") return "Investigate incident " + (params.incident_id || "");
        if (action === "incident_summary") return "Generate summary for incident " + (params.incident_id || "");
        if (action === "isolate") return "Isolate VM " + (params.vm_name || "") + " in " + (params.resource_group || "");
        if (action === "vm_context") return "Retrieve configuration for VM " + (params.vm_name || "");
        if (action === "vm_instance_view") return "Check status/health of VM " + (params.vm_name || "");
        var names = { start_vm: "Start", restart_vm: "Restart", stop_vm: "Stop", reconnect_vm: "Reconnect" };
        return (names[action] || action) + " VM " + (params.vm_name || "");
    }

    function handleCloudActionButton(btn) {
        var action = btn.getAttribute("data-cloud-action");
        if (!action) return;
        var panel = btn.closest(".ws-cloud-card");
        var params = cloudPanelParams(panel);
        var required = cloudRequiresParams(action);
        var missing = required.filter(function (k) { return !params[k]; });
        if (missing.length) {
            window.showToast("Please fill in the required field" + (missing.length > 1 ? "s" : "") + " first.", "error");
            return;
        }
        runCloudAction(cloudUserLabel(action, params), action, params, action);
    }

    // ============================================================
    // CHAT / SEND
    // ============================================================

    function isOwnershipError(message) {
        return /does not exist or belongs to another account/i.test(String(message || ""));
    }

    function requestChat(text, opts, typing, retried) {
        var convId = state.activeId;
        fetch("/api/chat", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message: text, conversation_id: convId, agent_id: state.activeAgentId, tool: opts.tool || null })
        })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                removeTyping(typing);
                if (data && data.error) throw new Error(data.error);
                if (data.conversation_id) state.activeId = data.conversation_id;
                var reply = (data && data.reply) || buildAssistantReply(text);
                appendMessage({ role: "assistant", content: reply, tool: opts.tool || null, usage: (data && data.usage) || null, agentName: (data && data.agent && data.agent.name) || null, ts: now() });
                loadConversations();
                loadConversationInsights();
            })
            .catch(function (error) {
                removeTyping(typing);

                // A stored/clicked conversation can become inaccessible (e.g.
                // it was cleared or belongs to a different account after the
                // multi-tenant rework). Retry once on a fresh conversation
                // instead of falling back to a preview response.
                if (!retried && error && isOwnershipError(error.message)) {
                    if (state.activeId) {
                        state.conversations = state.conversations.filter(function (c) { return c.id !== state.activeId; });
                    }
                    state.activeId = null;
                    state.messages = [];
                    renderConversationList();
                    renderActiveConversation();
                    appendMessage({ role: "user", content: text, ts: now() });
                    var retryTyping = appendTyping();
                    window.showToast("Starting a new conversation.", "info");
                    requestChat(text, opts, retryTyping, true);
                    return;
                }

                var fallback = buildAssistantReply(text);
                appendMessage({ role: "assistant", content: fallback, tool: opts.tool || null, ts: now() });
                if (error && error.message) {
                    window.showToast("Agent unavailable \u2014 showing preview response.", "error");
                }
            })
            .finally(function () { sendBtn.disabled = false; promptInput.focus(); });
    }

    function sendPrompt(prompt, opts) {
        opts = opts || {};
        var text = (prompt || "").trim();
        if (!text) return;

        ensureActiveId();
        appendMessage({ role: "user", content: text, ts: now() });
        renderConversationList();
        promptInput.value = "";
        autoResize();

        sendBtn.disabled = true;
        requestChat(text, opts, appendTyping(), false);
    }

    // ============================================================
    // AGENTS
    // ============================================================

    function avatarFor(name) {
        var parts = String(name || "").trim().split(/\s+/);
        return parts.map(function (p) { return p.charAt(0); }).join("").toUpperCase().slice(0, 2) || "AG";
    }

    function isFirewallAgent(agent) {
        if (!agent) return false;
        if (isNetsecAgent(agent) || isCloudAgent(agent)) return false;
        var type = String(agent.type || "").toLowerCase();
        var name = String(agent.name || "").toLowerCase();
        var id = String(agent.id || "").toLowerCase();
        return id.indexOf("firewall-audit") !== -1 ||
            type.indexOf("firewall") !== -1 || name.indexOf("firewall") !== -1;
    }

    function isCloudAgent(agent) {
        if (!agent) return false;
        var type = String(agent.type || "").toLowerCase();
        var name = String(agent.name || "").toLowerCase();
        var id = String(agent.id || "").toLowerCase();
        return type.indexOf("cloud") !== -1 || name.indexOf("cloud") !== -1 ||
            name.indexOf("incident") !== -1 || id.indexOf("cloud") !== -1;
    }

    function normalizeAgentKey(value) {
        return String(value || "").toLowerCase().replace(/[^a-z0-9]/g, "");
    }

    // Historical labels that no longer match a registry name/type/id.
    var LEGACY_AGENT_ALIASES = {
        firewallauditor: "firewall-audit-agent"
    };

    function resolveAgentName(name) {
        var raw = String(name || "").trim();
        if (!raw) return "";
        var key = normalizeAgentKey(raw);
        if (LEGACY_AGENT_ALIASES[key]) key = normalizeAgentKey(LEGACY_AGENT_ALIASES[key]);
        for (var i = 0; i < state.agents.length; i++) {
            var a = state.agents[i];
            if (normalizeAgentKey(a.name) === key ||
                normalizeAgentKey(a.id) === key ||
                normalizeAgentKey(a.type) === key) {
                return a.name || raw;
            }
        }
        return raw;
    }

    function agentFromMessages(msgs) {
        msgs = msgs || [];
        for (var i = msgs.length - 1; i >= 0; i--) {
            var name = String((msgs[i] && msgs[i].agentName) || "").trim();
            if (!name) continue;
            var key = normalizeAgentKey(name);
            if (LEGACY_AGENT_ALIASES[key]) key = normalizeAgentKey(LEGACY_AGENT_ALIASES[key]);
            for (var j = 0; j < state.agents.length; j++) {
                var a = state.agents[j];
                if (normalizeAgentKey(a.name) === key ||
                    normalizeAgentKey(a.id) === key ||
                    normalizeAgentKey(a.type) === key) {
                    return a;
                }
            }
        }
        return null;
    }

    function conversationBoundAgent() {
        var fromMsgs = agentFromMessages(state.messages);
        if (fromMsgs) return fromMsgs;
        return state.activeAgent;
    }

    function setActiveAgent(agent) {
        if (!agent) return;
        state.activeAgent = agent;
        state.activeAgentId = agent.id || null;

        if (chatAgentTitle) chatAgentTitle.textContent = agent.name || "Firewall Audit Agent";
        if (chatAgentSub) chatAgentSub.textContent = ((agent.model ? agent.model + " \u00b7 " : "") + (agent.type || "Copilot")).trim();
        if (chatAgentAvatar) chatAgentAvatar.textContent = avatarFor(agent.name);

        if (composerAgentBadge) {
            composerAgentBadge.innerHTML = '<span class="pulse-dot"></span>' + escapeHtml(agent.name || "Agent");
        }

        if (wsAgentSelect && agent.id && wsAgentSelect.value !== agent.id) {
            wsAgentSelect.value = agent.id;
        }

        renderPromptChips();
        if (chatWindow && !state.messages.length) renderEmptyState();
        applyNetsecMode(agent);
    }

    function isNetsecAgent(agent) {
        if (!agent) return false;
        if (window.NetsecPanel && window.NetsecPanel.isNetsecAgent(agent)) return true;
        var text = String(agent.id || "") + " " + String(agent.name || "") + " " + String(agent.type || "");
        return /netsec|execution/i.test(text);
    }

    function applyNetsecMode(agent) {
        var active = isNetsecAgent(agent);
        if (!active) return;
        if (window.NetsecPanel && window.NetsecPanel.onAgentActivated) {
            window.NetsecPanel.onAgentActivated();
        }
    }

    function populateAgentSelect() {
        if (!wsAgentSelect) return;
        wsAgentSelect.innerHTML = "";
        state.agents.forEach(function (a) {
            var opt = document.createElement("option");
            opt.value = a.id;
            opt.textContent = a.name;
            wsAgentSelect.appendChild(opt);
        });
        if (!state.agents.length) {
            var empty = document.createElement("option");
            empty.value = "";
            empty.textContent = "No agents configured";
            wsAgentSelect.appendChild(empty);
        }
    }

    function resolveInitialAgent() {
        var global = window.getGlobalAgent ? window.getGlobalAgent() : null;
        if (global) {
            for (var i = 0; i < state.agents.length; i++) {
                if (state.agents[i].id === global.id) return state.agents[i];
            }
        }
        var connected = state.agents.filter(function (a) { return a.connected; });
        if (connected[0]) return connected[0];
        return state.agents[0] || null;
    }

    function loadAgents() {
        fetch("/api/agents")
            .then(function (r) { return r.json(); })
            .then(function (data) {
                state.agents = (data && data.agents) || [];
                populateAgentSelect();
                var agent = resolveInitialAgent();
                if (agent) setActiveAgent(agent);
            })
            .catch(function () {});
    }

    // ============================================================
    // INSIGHTS PANEL
    // ============================================================

    function fmtNum(n) {
        return Number(n).toLocaleString("en-US");
    }

    function updateSessionMetrics() {
        if (!insightMessages) return;
        insightMessages.textContent = String(state.messages.length);
    }

    function loadConversationInsights() {
        if (!state.activeId) {
            if (insightTokens) insightTokens.textContent = "—";
            if (insightCost) insightCost.textContent = "—";
            updateSessionMetrics();
            return;
        }
        fetch("/api/insights/conversation/" + encodeURIComponent(state.activeId))
            .then(function (r) { return r.json(); })
            .then(function (data) {
                var c = (data && data.conversation) || null;
                if (insightTokens) insightTokens.textContent = c ? fmtNum(c.total_tokens || 0) : "—";
                if (insightCost) insightCost.textContent = c ? "$" + Number(c.cost || 0).toFixed(2) : "—";
                updateSessionMetrics();
            })
            .catch(function () {});
    }

    // ============================================================
    // HELPERS — text formatting
    // ============================================================

    function formatTime(ts) {
        var d = new Date(ts * 1000);
        return d.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
    }

    function copyText(text) {
        if (!text) return;
        function done() { window.showToast("Copied to clipboard.", "success"); }
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(done).catch(function () { fallbackCopy(text); });
        } else {
            fallbackCopy(text);
        }
    }

    function fallbackCopy(text) {
        try {
            var ta = document.createElement("textarea");
            ta.value = text;
            ta.style.position = "fixed";
            ta.style.opacity = "0";
            document.body.appendChild(ta);
            ta.select();
            document.execCommand("copy");
            document.body.removeChild(ta);
            window.showToast("Copied to clipboard.", "success");
        } catch (e) { /* ignore */ }
    }

    function escapeHtml(value) {
        var div = document.createElement("div");
        div.textContent = value == null ? "" : String(value);
        return div.innerHTML;
    }

    function inlineFormat(raw) {
        var s = escapeHtml(raw);
        s = s.replace(/`([^`]+)`/g, function (m, code) { return '<code class="msg-code">' + code + "</code>"; });
        s = s.replace(/\*\*([^*]+)\*\*/g, function (m, bold) { return "<strong>" + bold + "</strong>"; });
        s = s.replace(/(^|[^*])\*([^*\n]+)\*/g, function (m, pre, em) { return pre + "<em>" + em + "</em>"; });
        return s;
    }

    function kvFormat(line) {
        var idx = line.indexOf(":");
        if (idx > 0) {
            var key = line.slice(0, idx).trim(), rest = line.slice(idx + 1).trim();
            if (key && rest && !/[`*]/.test(key)) return '<span class="msg-key">' + inlineFormat(key) + "</span> " + inlineFormat(rest);
        }
        return inlineFormat(line);
    }

    function renderTable(rows) {
        var html = '<div class="msg-table-wrap"><table class="msg-table">';
        for (var r = 0; r < rows.length; r++) {
            var row = rows[r];
            if (r === 1 && /^[\s:|\-]+$/.test(row)) continue;
            var cells = row.replace(/^\||\|$/g, "").split("|");
            var tag = r === 0 ? "th" : "td";
            html += "<tr>";
            for (var c = 0; c < cells.length; c++) html += "<" + tag + ">" + inlineFormat(cells[c].trim()) + "</" + tag + ">";
            html += "</tr>";
        }
        return html + "</table></div>";
    }

    function formatAgentReply(text) {
        if (!text) return "";
        var raw = String(text).replace(/\r\n/g, "\n").replace(/\r/g, "\n");
        var lines = raw.split("\n");
        var html = [], listStack = [], lastIndent = -1;

        function closeList() {
            while (listStack.length) { html.push("</" + listStack.pop() + ">"); }
            listStack = []; lastIndent = -1;
        }

        for (var i = 0, n = lines.length; i < n; i++) {
            var line = lines[i].replace(/\s+$/, ""), trimmed = line.trim();
            if (!trimmed) { closeList(); continue; }

            var heading = /^(#{1,6})\s+(.*)$/.exec(trimmed);
            if (heading) {
                closeList();
                var level = Math.min(heading[1].length + 2, 6);
                html.push("<h" + level + " class='msg-h msg-h-" + level + "'>" + inlineFormat(heading[2]) + "</h" + level + ">");
                continue;
            }

            if (trimmed.indexOf("|") === 0 && trimmed.indexOf("|", 1) !== -1) {
                closeList();
                var rows = [];
                while (i < n) {
                    var t = lines[i].trim();
                    if (t.indexOf("|") === 0 && t.lastIndexOf("|") > 0) { rows.push(t); i++; }
                    else { i--; break; }
                }
                html.push(renderTable(rows));
                continue;
            }

            var bullet = /^(\s*)[-*]\s+(.*)$/.exec(line);
            if (bullet) {
                var indent = bullet[1].replace(/\t/g, "  ").length;
                if (listStack.length === 0 || indent > lastIndent) { listStack.push("ul"); html.push("<ul class='msg-list'>"); }
                else if (indent < lastIndent) { while (listStack.length > 1 && indent < lastIndent) { html.push("</" + listStack.pop() + ">"); lastIndent = listStack.length === 1 ? 0 : lastIndent - 2; } }
                lastIndent = indent;
                html.push("<li>" + kvFormat(bullet[2]) + "</li>");
                continue;
            }

            var ordered = /^(\s*)\d+\.\s+(.*)$/.exec(line);
            if (ordered) {
                var oIndent = ordered[1].replace(/\t/g, "  ").length;
                if (listStack.length === 0 || listStack[listStack.length - 1] !== "ol") { listStack.push("ol"); html.push("<ol class='msg-list'>"); }
                lastIndent = oIndent;
                html.push("<li>" + kvFormat(ordered[2]) + "</li>");
                continue;
            }

            if (/^[-*_]{3,}$/.test(trimmed)) { html.push('<hr class="msg-hr">'); continue; }

            if (trimmed.length >= 4 && trimmed === trimmed.toUpperCase() && /^[A-Z0-9][A-Z0-9\s&\-/()]{2,}$/.test(trimmed)) {
                html.push('<div class="msg-section">' + escapeHtml(trimmed) + "</div>");
                continue;
            }
            html.push("<p>" + inlineFormat(trimmed) + "</p>");
        }
        closeList();
        return html.join("");
    }

    function buildAssistantReply(prompt) {
        var lower = prompt.toLowerCase();
        if (lower.indexOf("hello") !== -1 || lower.indexOf("hi ") !== -1 || lower.indexOf("hey") !== -1)
            return "Hello. I'm the Firewall Audit Agent, connected to your Palo Alto firewall (vmpafw01, PAN-OS 10.2.10-h9). Ask me about your security posture, inventory, compliance status, or any firewall configuration.";
        if (lower.indexOf("thanks") !== -1 || lower.indexOf("thank you") !== -1)
            return "You're welcome. I'm here whenever you need to review your security posture.";
        return null;
    }

    // ============================================================
    // SIDEBAR / INSIGHTS TOGGLES
    // ============================================================

    function setSidebarOpen(open) {
        if (sidebar) sidebar.classList.toggle("open", open);
        if (sidebarToggle) sidebarToggle.classList.toggle("is-active", open);
    }

    function setInsightsOpen(open) {
        if (insights) insights.classList.toggle("open", open);
        if (insightsToggle) insightsToggle.classList.toggle("is-active", open);
    }

    // ============================================================
    // COMPOSER
    // ============================================================

    function autoResize() {
        if (!promptInput) return;
        promptInput.style.height = "auto";
        promptInput.style.height = Math.min(promptInput.scrollHeight, 160) + "px";
    }

    // ============================================================
    // WIRING
    // ============================================================

    if (chatWindow) {
        chatWindow.addEventListener("click", function (e) {
            var cloudBtn = e.target.closest(".ws-cloud-run");
            if (cloudBtn) {
                handleCloudActionButton(cloudBtn);
                return;
            }
            var cloudKpi = e.target.closest(".ws-cloud-kpi");
            if (cloudKpi) {
                var period = cloudKpi.getAttribute("data-cloud-period");
                if (period) {
                    runCloudAction("View " + period + " incidents", "incident_list", { period: period }, "incident_list");
                }
                return;
            }
            var estateBtn = e.target.closest(".ws-estate-run");
            if (estateBtn) {
                var estateAction = estateBtn.getAttribute("data-estate-action");
                if (estateAction) runEstateAction(estateAction);
                return;
            }
            var backBtn = e.target.closest("[data-fw-back]");
            if (backBtn) {
                var backRow = backBtn.closest(".ws-message[data-index]");
                goBackFromCard(backRow);
                return;
            }
            var option = e.target.closest(".mcq-option");
            if (!option) return;
            var sectionId = option.getAttribute("data-section");
            if (sectionId) showSection(sectionId);
        });
    }

    if (newChatBtn) newChatBtn.addEventListener("click", function () { createConversation(); promptInput.focus(); });

    if (sidebarToggle) sidebarToggle.addEventListener("click", function () {
        setSidebarOpen(!sidebar.classList.contains("open"));
    });

    if (insightsToggle) insightsToggle.addEventListener("click", function () {
        setInsightsOpen(!insights.classList.contains("open"));
    });

    if (insightsClose) insightsClose.addEventListener("click", function () { setInsightsOpen(false); });

    if (convSearch) convSearch.addEventListener("input", renderConversationList);

    if (wsAgentSelect) {
        wsAgentSelect.addEventListener("change", function () {
            var id = wsAgentSelect.value;
            var next = null;
            for (var i = 0; i < state.agents.length; i++) {
                if (state.agents[i].id === id) {
                    next = state.agents[i];
                    break;
                }
            }
            if (!next) return;

            var hasMessages = state.messages.length > 0;
            var bound = conversationBoundAgent();

            setActiveAgent(next);
            if (window.setGlobalAgent) window.setGlobalAgent(next);

            if (hasMessages && bound && bound.id !== next.id) {
                createConversation();
                if (promptInput) promptInput.focus();
            }
        });
    }

    if (sendBtn) sendBtn.addEventListener("click", function () { sendPrompt(promptInput.value); });

    if (promptInput) {
        promptInput.addEventListener("keydown", function (e) {
            if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendPrompt(promptInput.value); }
        });
        promptInput.addEventListener("input", autoResize);
    }

    if (clearBtn) {
        clearBtn.addEventListener("click", function () {
            if (!state.activeId) {
                window.showToast("Nothing to clear.", "success");
                return;
            }
            var id = state.activeId;
            fetch("/api/conversations/" + encodeURIComponent(id) + "/clear", { method: "POST" })
                .then(function (r) { return r.json(); })
                .then(function () {
                    state.messages = [];
                    renderActiveConversation();
                    loadConversations();
                    loadConversationInsights();
                    window.showToast("Conversation cleared.", "success");
                })
                .catch(function () {
                    window.showToast("Failed to clear conversation.", "error");
                });
        });
    }

    document.addEventListener("agent-changed", function (e) {
        var agent = e.detail;
        if (agent) setActiveAgent(agent);
    });

    // ============================================================
    // CHAT BRIDGE (used by netsec.js chat-first flows)
    // ============================================================

    window.WsChat = {
        ensureId: function () {
            ensureActiveId();
            return state.activeId;
        },
        activeAgent: function () {
            return state.activeAgent;
        },
        agentName: function () {
            if (state.activeAgent && state.activeAgent.name) return state.activeAgent.name;
            return "Firewall Execution Agent";
        },
        user: function (content) {
            ensureActiveId();
            var msg = { role: "user", content: content || "", ts: now() };
            appendMessage(msg);
            renderConversationList();
            return msg;
        },
        assistantHtml: function (html, cardTitle) {
            ensureActiveId();
            var msg = {
                role: "assistant",
                content: "",
                html: html,
                cardTitle: cardTitle || "Firewall Execution",
                agentName: this.agentName(),
                ts: now()
            };
            appendMessage(msg);
            return msg;
        },
        assistantText: function (content) {
            ensureActiveId();
            var msg = {
                role: "assistant",
                content: content || "",
                agentName: this.agentName(),
                ts: now()
            };
            appendMessage(msg);
            return msg;
        },
        typingStart: function () {
            var node = appendTyping(this.agentName());
            if (sendBtn) sendBtn.disabled = true;
            return node;
        },
        typingEnd: function (node) {
            removeTyping(node);
            if (sendBtn) sendBtn.disabled = false;
            if (promptInput) promptInput.focus();
        },
        setBusy: function (busy) {
            if (sendBtn) sendBtn.disabled = !!busy;
        },
        persist: function (msgs) {
            if (!msgs || !msgs.length) return Promise.resolve();
            return persistMessages(msgs).then(function () {
                loadConversations();
                loadConversationInsights();
            }).catch(function () {});
        },
        scrollBottom: function () { scrollToBottom(); }
    };

    // ============================================================
    // INIT
    // ============================================================

    renderPromptChips();

    renderConversationList();
    renderActiveConversation();

    loadAgents();
    loadConversations().then(function () {
        loadConversationInsights();
    });
})();
