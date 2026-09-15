/* ============================================================
   SYSTEM INFO — agent cards
   Renders registered agents as medium square cards with the full
   agent name and a live/down badge; hovering (or focusing) a card
   reveals its core capabilities.
   ============================================================ */

(function () {
    "use strict";

    var grid = document.getElementById("sysAgentCards");
    var countChip = document.getElementById("agentCountChip");

    /* Core capabilities, keyed by the agent registry id. */
    var CAPABILITIES = {
        "firewall-audit-agent":
            "Performs compliance assessments, generates executive summaries and reports, and delivers prioritised security findings with clear remediation recommendations.",
        "netsec-execution-agent":
            "Automates rule and policy lifecycle management, object management and network management across Palo Alto firewalls.",
        "incident-response-agent-cloud-security":
            "Delivers cloud security posture management (CSPM), integrates Microsoft Defender for Cloud and Microsoft Sentinel, analyses incidents, and performs cloud containment actions and security responses."
    };

    /* Fallback matching for agents that are not in the registry map. */
    var CAPABILITY_RULES = [
        {
            keys: ["audit", "firewall audit"],
            text: CAPABILITIES["firewall-audit-agent"]
        },
        {
            keys: ["execution", "netsec", "firewall execution"],
            text: CAPABILITIES["netsec-execution-agent"]
        },
        {
            keys: ["cloud", "sentinel", "defender"],
            text: CAPABILITIES["incident-response-agent-cloud-security"]
        }
    ];

    function escapeHtml(value) {
        return String(value == null ? "" : value)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#39;");
    }

    function initials(name) {
        var parts = String(name || "").trim().split(/[\s_-]+/).filter(Boolean);
        if (!parts.length) {
            return "AI";
        }
        if (parts.length === 1) {
            return parts[0].slice(0, 2).toUpperCase();
        }
        return (parts[0][0] + parts[1][0]).toUpperCase();
    }

    function capabilityFor(agent) {
        var id = String(agent.id || "").toLowerCase();
        if (CAPABILITIES[id]) {
            return CAPABILITIES[id];
        }
        var hay = ((agent.name || "") + " " + (agent.type || "")).toLowerCase();
        var i;
        var j;
        for (i = 0; i < CAPABILITY_RULES.length; i += 1) {
            for (j = 0; j < CAPABILITY_RULES[i].keys.length; j += 1) {
                if (hay.indexOf(CAPABILITY_RULES[i].keys[j]) !== -1) {
                    return CAPABILITY_RULES[i].text;
                }
            }
        }
        var model = agent.model && agent.model !== "-" ? agent.model : "the configured model";
        return "General-purpose security copilot (" + model + ") for assessments, findings review and report generation.";
    }

    function statusBadge(agent) {
        var live = agent.status === "live";
        var detail = agent.detail ? ' title="' + escapeHtml(agent.detail) + '"' : "";
        return (
            '<span class="status-chip ' + (live ? "status-on" : "status-fail") + '"' + detail + ">" +
            '<span class="pulse-dot"></span>' +
            (live ? "Live" : "Down") +
            "</span>"
        );
    }

    function cardHtml(agent) {
        var name = agent.name || "Agent";
        var type = agent.type && agent.type !== name
            ? '<span class="agent-card-type">' + escapeHtml(agent.type) + "</span>"
            : "";
        return (
            '<article class="agent-card" tabindex="0" aria-label="' + escapeHtml(name) + '">' +
            '<div class="agent-card-body">' +
            '<span class="agent-avatar" aria-hidden="true">' + escapeHtml(initials(name)) + "</span>" +
            '<strong class="agent-card-name">' + escapeHtml(name) + "</strong>" +
            type +
            statusBadge(agent) +
            "</div>" +
            '<div class="agent-card-capability">' +
            '<span class="agent-cap-label">Core Capabilities</span>' +
            "<p>" + escapeHtml(capabilityFor(agent)) + "</p>" +
            "</div>" +
            "</article>"
        );
    }

    function render(agents) {
        if (!grid) {
            return;
        }
        if (!agents.length) {
            grid.innerHTML = '<p class="sys-agent-note">No agents configured yet.</p>';
            if (countChip) {
                countChip.textContent = "Total 0";
            }
            return;
        }
        if (countChip) {
            countChip.textContent = "Total " + agents.length;
        }
        grid.innerHTML = agents.map(cardHtml).join("");
    }

    function load() {
        if (!grid) {
            return;
        }
        fetch("/api/agent-status", { headers: { Accept: "application/json" } })
            .then(function (response) {
                if (!response.ok) {
                    throw new Error("HTTP " + response.status);
                }
                return response.json();
            })
            .then(function (data) {
                render((data && data.agents) || []);
            })
            .catch(function () {
                grid.innerHTML = '<p class="sys-agent-note">Unable to load agent status.</p>';
                if (countChip) {
                    countChip.textContent = "Total \u2014";
                }
            });
    }

    load();
})();
