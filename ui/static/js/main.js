(function () {
    "use strict";

    var sidebar = document.getElementById("sidebar");
    var backdrop = document.getElementById("sidebarBackdrop");
    var menuToggle = document.getElementById("menuToggle");
    var expandToggle = document.getElementById("sidebarExpandToggle");
    var SIDEBAR_STATE_KEY = "ltm_sidebar_expanded";

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
        if (expandToggle) {
            expandToggle.setAttribute("aria-expanded", expanded ? "true" : "false");
            expandToggle.setAttribute(
                "aria-label",
                expanded ? "Collapse navigation" : "Expand navigation"
            );
        }
    }

    function rememberDesktopSidebar(expanded) {
        try {
            localStorage.setItem(SIDEBAR_STATE_KEY, expanded ? "1" : "0");
        } catch (e) { /* ignore */ }
    }

    function restoreDesktopSidebar() {
        if (!isDesktop()) return;
        var saved = null;
        try { saved = localStorage.getItem(SIDEBAR_STATE_KEY); } catch (e) { saved = null; }
        toggleDesktopSidebar(saved === "1");
    }

    if (menuToggle) {
        menuToggle.addEventListener("click", function () {
            var isOpen = sidebar.classList.contains("open");
            toggleSidebar(!isOpen);
        });
    }

    if (backdrop) {
        backdrop.addEventListener("click", function () {
            toggleSidebar(false);
        });
    }

    // The sidebar stays collapsed to an icon rail. It is expanded only from
    // the dedicated toggle above the rail and keeps that state across pages.
    if (expandToggle) {
        expandToggle.addEventListener("click", function () {
            var next = !sidebar.classList.contains("expanded");
            toggleDesktopSidebar(next);
            rememberDesktopSidebar(next);
            window.dispatchEvent(new CustomEvent("sidebar-toggled", { detail: { expanded: next } }));
        });
    }

    restoreDesktopSidebar();

    window.addEventListener("resize", function () {
        if (window.innerWidth > 768 && sidebar) {
            sidebar.classList.remove("open");
            if (backdrop) backdrop.classList.remove("show");
            document.body.style.overflow = "";
        } else if (sidebar) {
            toggleDesktopSidebar(false);
        }
    });

    // ------------------------------------------------------------
    // SIDEBAR NAV GROUPS — expand/collapse to their sub-pages
    // ------------------------------------------------------------
    var navGroups = [
        { group: document.getElementById("navDashboardGroup"), toggle: document.getElementById("navDashboardToggle") },
        { group: document.getElementById("navSettingsGroup"), toggle: document.getElementById("navSettingsToggle") }
    ];

    navGroups.forEach(function (entry) {
        if (!entry.group || !entry.toggle) return;

        (function (group, toggle) {
            var submenu = group.querySelector(".nav-submenu");
            var closeTimer = null;
            var FLYOUT_GAP = 12;

            function collapsedRail() {
                return isDesktop() && sidebar && !sidebar.classList.contains("expanded");
            }

            function clearFlyoutPosition() {
                if (!submenu) return;
                submenu.style.top = "";
                submenu.style.left = "";
            }

            function positionFlyout() {
                if (!submenu || !sidebar) return;
                var g = group.getBoundingClientRect();
                var s = sidebar.getBoundingClientRect();
                var cs = window.getComputedStyle(sidebar);
                var originX = s.left + parseFloat(cs.borderLeftWidth || 0);
                var originY = s.top + parseFloat(cs.borderTopWidth || 0);
                submenu.style.top = Math.round(g.top - originY) + "px";
                submenu.style.left = Math.round(g.right + FLYOUT_GAP - originX) + "px";
            }

            function closeGroup() {
                if (closeTimer) { clearTimeout(closeTimer); closeTimer = null; }
                group.classList.remove("is-open");
                group.classList.remove("flyout-open");
                clearFlyoutPosition();
                toggle.setAttribute("aria-expanded", "false");
            }

            function openGroup() {
                if (closeTimer) { clearTimeout(closeTimer); closeTimer = null; }
                group.classList.add("is-open");
                toggle.setAttribute("aria-expanded", "true");
                if (collapsedRail()) {
                    positionFlyout();
                    group.classList.add("flyout-open");
                }
            }

            toggle.addEventListener("click", function () {
                if (group.classList.contains("is-open")) closeGroup();
                else openGroup();
            });

            // Collapsed rail: keep the flyout open while the pointer travels
            // from the icon across the gap and onto one of the sub-options.
            group.addEventListener("mouseenter", function () {
                if (!collapsedRail()) return;
                if (closeTimer) { clearTimeout(closeTimer); closeTimer = null; }
                positionFlyout();
                group.classList.add("flyout-open");
            });

            group.addEventListener("mouseleave", function () {
                if (!collapsedRail()) return;
                if (closeTimer) clearTimeout(closeTimer);
                closeTimer = setTimeout(function () {
                    closeTimer = null;
                    if (group.matches(":hover") || group.contains(document.activeElement)) return;
                    group.classList.remove("flyout-open");
                    group.classList.remove("is-open");
                    toggle.setAttribute("aria-expanded", "false");
                }, 160);
            });

            document.addEventListener("click", function (event) {
                if (!group.contains(event.target)) closeGroup();
            });

            window.addEventListener("sidebar-toggled", function (event) {
                if (event.detail && event.detail.expanded) closeGroup();
                else clearFlyoutPosition();
            });

            window.addEventListener("resize", function () {
                closeGroup();
            });
        })(entry.group, entry.toggle);
    });

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
