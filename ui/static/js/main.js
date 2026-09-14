(function () {
    "use strict";

    var sidebar = document.getElementById("sidebar");
    var backdrop = document.getElementById("sidebarBackdrop");
    var menuToggle = document.getElementById("menuToggle");

    function isDesktop() {
        return window.innerWidth > 768;
    }

    function toggleSidebar(open) {
        if (!sidebar || !backdrop) return;
        sidebar.classList.toggle("open", open);
        backdrop.classList.toggle("show", open);
        document.body.style.overflow = open ? "hidden" : "";
    }

    function toggleDesktopSidebar(expanded) {
        if (!sidebar) return;
        sidebar.classList.toggle("expanded", expanded);
        document.body.classList.toggle("sidebar-expanded", expanded);
        try { sessionStorage.setItem("ltm.sidebar.expanded", expanded ? "1" : "0"); } catch (e) { /* ignore */ }
    }

    function restoreDesktopSidebar() {
        if (!isDesktop() || !sidebar) return;
        var expanded = true;
        try {
            var saved = sessionStorage.getItem("ltm.sidebar.expanded");
            if (saved === "0") expanded = false;
            else if (saved === "1") expanded = true;
        } catch (e) { /* ignore */ }
        toggleDesktopSidebar(expanded);
    }

    if (menuToggle) {
        menuToggle.addEventListener("click", function () {
            if (isDesktop()) {
                var isExpanded = sidebar.classList.contains("expanded");
                toggleDesktopSidebar(!isExpanded);
            } else {
                var isOpen = sidebar.classList.contains("open");
                toggleSidebar(!isOpen);
            }
        });
    }

    if (backdrop) {
        backdrop.addEventListener("click", function () {
            toggleSidebar(false);
        });
    }

    window.addEventListener("resize", function () {
        if (window.innerWidth > 768 && sidebar) {
            sidebar.classList.remove("open");
            if (backdrop) backdrop.classList.remove("show");
            document.body.style.overflow = "";
        } else if (sidebar) {
            sidebar.classList.remove("expanded");
            document.body.classList.remove("sidebar-expanded");
        }
    });

    restoreDesktopSidebar();

    // ------------------------------------------------------------
    // SIDEBAR NAV GROUP — Dashboard expands to its sub-pages
    // ------------------------------------------------------------
    var dashGroup = document.getElementById("navDashboardGroup");
    var dashToggle = document.getElementById("navDashboardToggle");

    if (dashGroup && dashToggle) {
        dashToggle.addEventListener("click", function () {
            var willOpen = !dashGroup.classList.contains("is-open");
            dashGroup.classList.toggle("is-open", willOpen);
            dashToggle.setAttribute("aria-expanded", willOpen ? "true" : "false");
            if (willOpen && isDesktop() && sidebar && !sidebar.classList.contains("expanded")) {
                toggleDesktopSidebar(true);
            }
        });
    }

    window.showToast = function (message, type, duration) {
        var container = document.getElementById("toastContainer");
        if (!container) return;

        var toast = document.createElement("div");
        toast.className = "toast" + (type ? " toast-" + type : "");
        toast.textContent = message;
        container.appendChild(toast);

        var ms = (typeof duration === "number" && duration > 0) ? duration : 3400;
        setTimeout(function () {
            toast.classList.add("hide");
            setTimeout(function () {
                if (toast.parentNode) toast.parentNode.removeChild(toast);
            }, 300);
        }, ms);
    };

    document.addEventListener("click", function (event) {
        var trigger = event.target.closest("[data-toast]");
        if (trigger) {
            window.showToast(trigger.getAttribute("data-toast"));
        }
    });

    // ------------------------------------------------------------
    // SYSTEM STATUS — sidebar + topbar live/sample indicator
    // ------------------------------------------------------------

    function setSystemStatus(status) {
        var systemStatus = document.getElementById("systemStatus");
        var systemDot = document.getElementById("systemStatusDot");
        var systemLabel = document.getElementById("systemStatusLabel");
        var liveBadge = document.getElementById("liveBadge");
        var liveBadgeDot = document.getElementById("liveBadgeDot");
        var liveBadgeText = document.getElementById("liveBadgeText");

        if (!systemStatus && !liveBadge) return;

        var overall = status.overall || "operational";
        var source = status.source || "live";

        var systemClass = overall === "offline" ? "is-offline" : (overall === "degraded" ? "is-degraded" : "");
        if (systemStatus) {
            systemStatus.classList.remove("is-offline", "is-degraded");
            if (systemClass) systemStatus.classList.add(systemClass);
        }
        if (systemDot) {
            systemDot.className = "pulse-dot";
        }
        if (systemLabel) {
            if (overall === "offline") systemLabel.textContent = "Systems Offline";
            else if (overall === "degraded") systemLabel.textContent = "Partial Systems Operational";
            else systemLabel.textContent = "All Systems Operational";
        }

        var badgeClass = source === "live" ? "" : (overall === "offline" ? "is-offline" : "is-sample");
        if (liveBadge) {
            liveBadge.classList.remove("is-sample", "is-offline");
            if (badgeClass) liveBadge.classList.add(badgeClass);
        }
        if (liveBadgeDot) {
            liveBadgeDot.className = "pulse-dot";
        }
        if (liveBadgeText) {
            liveBadgeText.textContent = source === "live" ? "Live" : "Sample";
        }
    }

    function loadSystemStatus() {
        fetch("/api/system-status")
            .then(function (res) {
                return res.json();
            })
            .then(function (data) {
                if (data && !data.error) {
                    setSystemStatus(data);
                }
            })
            .catch(function () {
                // keep default UI on failure
            });
    }

    loadSystemStatus();

    setInterval(loadSystemStatus, 30000);
    document.addEventListener("visibilitychange", function () {
        if (!document.hidden) loadSystemStatus();
    });

    // ------------------------------------------------------------
    // GLOBAL AGENT SELECTOR — drives all page context
    // ------------------------------------------------------------

    window.getGlobalAgentId = function () {
        return localStorage.getItem("ltm_global_agent_id") || null;
    };

    window.getGlobalAgent = function () {
        try {
            return JSON.parse(localStorage.getItem("ltm_global_agent") || "null");
        } catch (e) {
            return null;
        }
    };

    window.setGlobalAgent = function (agent) {
        if (agent) {
            localStorage.setItem("ltm_global_agent_id", agent.id);
            localStorage.setItem("ltm_global_agent", JSON.stringify(agent));
        } else {
            localStorage.removeItem("ltm_global_agent_id");
            localStorage.removeItem("ltm_global_agent");
        }
        window.dispatchEvent(new CustomEvent("agent-changed", { detail: agent }));
    };

    window.onGlobalAgentChange = function () {
        var sel = document.getElementById("globalAgentSelect");
        if (!sel) return;
        var agentId = sel.value;
        var agents = window._cachedAgents || [];
        var agent = null;
        for (var i = 0; i < agents.length; i++) {
            if (agents[i].id === agentId) { agent = agents[i]; break; }
        }
        window.setGlobalAgent(agent);
    };

    function loadGlobalAgentSelector() {
        var sel = document.getElementById("globalAgentSelect");
        if (!sel) return;
        fetch("/api/agents")
            .then(function (r) { return r.json(); })
            .then(function (data) {
                var agents = (data && data.agents) || [];
                window._cachedAgents = agents;
                sel.innerHTML = agents.map(function (a) {
                    return '<option value="' + a.id + '">' + a.name + '</option>';
                }).join("");
                if (agents.length === 0) {
                    sel.innerHTML = '<option value="">No agents configured</option>';
                    return;
                }
                var savedId = window.getGlobalAgentId();
                if (savedId && agents.some(function (a) { return a.id === savedId; })) {
                    sel.value = savedId;
                } else {
                    var connected = agents.filter(function (a) { return a.connected; });
                    sel.value = connected[0] ? connected[0].id : agents[0].id;
                }
                window.onGlobalAgentChange();
            })
            .catch(function () {
                sel.innerHTML = '<option value="">Failed to load</option>';
            });
    }

    loadGlobalAgentSelector();

    document.addEventListener("agent-changed", function () {
        var sel = document.getElementById("globalAgentSelect");
        var agent = window.getGlobalAgent();
        if (sel && agent && sel.value !== agent.id) {
            sel.value = agent.id;
        }
    });

    // ------------------------------------------------------------
    // INACTIVITY SIGN-OUT — after 5 idle minutes the session ends
    // and the user is returned to sign-in, then back to this page.
    // ------------------------------------------------------------
    (function idleSignOut() {
        var logoutUrl = document.body.getAttribute("data-logout-url");
        if (!logoutUrl) return;

        var LIMIT_MS = 5 * 60 * 1000;
        var timer = null;
        var events = ["mousemove", "mousedown", "click", "keydown", "scroll", "touchstart", "wheel"];

        function resumeTarget() {
            return window.location.pathname + window.location.search;
        }

        function signOut() {
            window.location.href = logoutUrl + "?expired=1&next=" + encodeURIComponent(resumeTarget());
        }

        function reset() {
            if (timer) clearTimeout(timer);
            timer = setTimeout(signOut, LIMIT_MS);
        }

        for (var i = 0; i < events.length; i++) {
            window.addEventListener(events[i], reset, { passive: true });
        }
        reset();
    })();

    // Redirect to sign-in when an API call reports an expired session.
    (function handleExpiredSession() {
        var logoutUrl = document.body.getAttribute("data-logout-url");
        if (!logoutUrl || typeof window.fetch !== "function") return;
        var originalFetch = window.fetch;
        window.fetch = function () {
            return originalFetch.apply(this, arguments).then(function (response) {
                if (response && response.status === 401) {
                    window.location.href = logoutUrl + "?expired=1&next=" +
                        encodeURIComponent(window.location.pathname + window.location.search);
                }
                return response;
            });
        };
    })();
})();
