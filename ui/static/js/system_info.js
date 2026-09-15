/* ============================================================
   SYSTEM INFO — agent cards
   Renders registered agents as small cards with a live/down
   badge; hovering (or focusing) a card reveals its capability.
   ============================================================ */

(function () {
    "use strict";

    var grid = document.getElementById("sysAgentCards");
    var countChip = document.getElementById("agentCountChip");

    var CAPABILITIES = [
        {
            keys: ["firewall", "audit", "assessment"],
            text: "Runs firewall compliance assessments, triages findings and drafts executive summaries."
        },
        {
            keys: ["cloud", "aws", "azure", "gcp"],
            text: "Audits cloud workload posture and surfaces misconfigurations across accounts."
        },
        {
            keys: ["network", "vpn", "remote", "perimeter"],
            text: "Reviews network, VPN and remote-access controls for policy drift."
        },
        {
            keys: ["insight", "telemetry", "monitor", "observ", "cost", "token"],
            text: "Analyses agent telemetry, token usage and cost across the platform."
        },
        {
            keys: ["policy", "compliance", "governance", "control"],
            text: "Maps controls to compliance frameworks and tracks remediation progress."
        },
        {
            keys: ["incident", "threat", "soc", "alert"],
            text: "Correlates security events and supports incident triage."
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
        var hay = ((agent.name || "") + " " + (agent.type || "") + " " + (agent.model || "")).toLowerCase();
        var i;
        var j;
        for (i = 0; i < CAPABILITIES.length; i += 1) {
            for (j = 0; j < CAPABILITIES[i].keys.length; j += 1) {
                if (hay.indexOf(CAPABILITIES[i].keys[j]) !== -1) {
                    return CAPABILITIES[i].text;
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
        return (
            '<article class="agent-card" tabindex="0" aria-label="' + escapeHtml(name) + '">' +
            '<div class="agent-card-head">' +
            '<span class="agent-avatar" aria-hidden="true">' + escapeHtml(initials(name)) + "</span>" +
            '<div class="agent-card-id">' +
            '<strong class="agent-card-name">' + escapeHtml(name) + "</strong>" +
            '<span class="agent-card-type">' + escapeHtml(agent.type || "Agent") + "</span>" +
            "</div>" +
            statusBadge(agent) +
            "</div>" +
            '<div class="agent-card-capability">' +
            '<span class="agent-cap-label">Capability</span>' +
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
                    countChip.textContent = "Total —";
                }
            });
    }

    load();
})();
