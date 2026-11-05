(function () {
    "use strict";

    var root = document.getElementById("baselineApp");
    if (!root) return;

    var catalog = window.BASELINE_CATALOG || {};
    var controls = catalog.controls || [];
    var profiles = catalog.profiles || [];
    var storageKey = catalog.storageKey || "heimdrix.assessmentBaseline";

    var profileBox = document.getElementById("baselineProfiles");
    var pillarSelect = document.getElementById("baselinePillar");
    var searchInput = document.getElementById("baselineSearch");
    var body = document.getElementById("baselineBody");
    var versionChip = document.getElementById("baselineVersionChip");
    var versionSelect = document.getElementById("baselineVersionSelect");
    var lockNote = document.getElementById("baselineLockNote");
    var countEl = document.getElementById("baselineCount");
    var disclaimer = document.getElementById("baselineDisclaimer");
    var impactText = document.getElementById("baselineImpactText");
    var stricterEl = document.getElementById("baselineStricter");
    var looserEl = document.getElementById("baselineLooser");
    var unchangedEl = document.getElementById("baselineUnchanged");
    var resetBtn = document.getElementById("baselineResetBtn");
    var saveBtn = document.getElementById("baselineSaveBtn");

    var state = {
        profile: "balanced",
        pillar: "all",
        query: "",
        values: {},
        versions: [],
        dirty: false
    };

    function clone(value) {
        return JSON.parse(JSON.stringify(value));
    }

    function same(a, b) {
        return JSON.stringify(a) === JSON.stringify(b);
    }

    function escapeHtml(value) {
        return String(value)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
    }

    function controlById(id) {
        for (var i = 0; i < controls.length; i++) {
            if (controls[i].id === id) return controls[i];
        }
        return null;
    }

    function profileValue(control, profileId) {
        if (profileId === "custom") return state.values[control.id];
        return clone(control.profiles[profileId]);
    }

    function loadProfileValues(profileId) {
        var values = {};
        controls.forEach(function (control) {
            values[control.id] = clone(control.profiles[profileId === "custom" ? "balanced" : profileId]);
        });
        return values;
    }

    function passLabel(control) {
        if (control.kind === "percent") return control.pass === "gte" ? "Pass >=" : "Pass <=";
        if (control.kind === "count") {
            var unit = control.unit ? " " + control.unit : "";
            return (control.pass === "gte" ? "Pass >=" : "Pass <=") + unit;
        }
        if (control.kind === "toggle") return "Required";
        return "All selected";
    }

    function formatValue(control, value) {
        if (control.kind === "percent") return String(value) + "%";
        if (control.kind === "count") return String(value) + (control.unit ? " " + control.unit : "");
        if (control.kind === "toggle") return value ? "On" : "Off";
        return (value || []).join(", ");
    }

    function compareToBalanced(control, value) {
        var balanced = control.profiles.balanced;
        if (same(value, balanced)) return "same";
        if (control.kind === "percent" || (control.kind === "count" && control.pass === "gte")) {
            return value > balanced ? "strict" : "lenient";
        }
        if (control.kind === "count" && control.pass === "lte") {
            return value < balanced ? "strict" : "lenient";
        }
        if (control.kind === "toggle") {
            return value && !balanced ? "strict" : "lenient";
        }
        var current = value || [];
        var base = balanced || [];
        if (current.length > base.length) return "strict";
        if (current.length < base.length) return "lenient";
        return "strict";
    }

    function isLocked() {
        return state.profile !== "custom";
    }

    function persist() {
        try {
            window.localStorage.setItem(storageKey, JSON.stringify({
                profile: state.profile,
                values: state.values,
                versions: state.versions,
                dirty: state.dirty
            }));
        } catch (err) {
            return;
        }
    }

    function fillMissingValues() {
        controls.forEach(function (control) {
            if (typeof state.values[control.id] === "undefined") {
                state.values[control.id] = clone(control.profiles.balanced);
            }
        });
    }

    function restore() {
        try {
            var raw = window.localStorage.getItem(storageKey);
            if (!raw) return;
            var saved = JSON.parse(raw);
            if (saved && saved.values) state.values = saved.values;
            if (saved && saved.profile) state.profile = saved.profile;
            if (saved && Array.isArray(saved.versions)) state.versions = saved.versions;
            state.dirty = !!saved.dirty;
            fillMissingValues();
        } catch (err) {
            state.values = loadProfileValues("balanced");
        }
    }

    function currentVersionLabel() {
        if (!state.versions.length) return "Version 1";
        return "Version " + state.versions.length;
    }

    function renderProfiles() {
        profileBox.innerHTML = profiles.map(function (profile) {
            var active = profile.id === state.profile ? " is-active" : "";
            return '<button type="button" class="bl-pill' + active + '" data-profile="' + escapeHtml(profile.id) + '" aria-pressed="' + (profile.id === state.profile ? "true" : "false") + '">' + escapeHtml(profile.label) + "</button>";
        }).join("");
    }

    function renderPillars() {
        var options = ['<option value="all">All pillars</option>'];
        (catalog.pillars || []).forEach(function (pillar) {
            options.push('<option value="' + escapeHtml(pillar) + '"' + (state.pillar === pillar ? " selected" : "") + ">" + escapeHtml(pillar) + "</option>");
        });
        pillarSelect.innerHTML = options.join("");
    }

    function renderVersions() {
        if (!state.versions.length) {
            versionSelect.hidden = true;
            versionSelect.innerHTML = "";
            return;
        }
        versionSelect.hidden = false;
        versionSelect.innerHTML = state.versions.map(function (version, index) {
            var label = "v" + version.id + " " + version.profile;
            var selected = index === state.versions.length - 1 ? " selected" : "";
            return '<option value="' + version.id + '"' + selected + ">" + escapeHtml(label) + "</option>";
        }).join("");
    }

    function filteredControls() {
        var query = (state.query || "").trim().toLowerCase();
        return controls.filter(function (control) {
            if (state.pillar !== "all" && control.pillar !== state.pillar) return false;
            if (!query) return true;
            return (control.code + " " + control.name + " " + control.id).toLowerCase().indexOf(query) !== -1;
        });
    }

    function widgetHtml(control, value, locked) {
        var disabled = locked ? " disabled" : "";
        if (control.kind === "percent" || control.kind === "count") {
            return (
                '<div class="bl-slider-row">' +
                '<input type="range" min="' + control.min + '" max="' + control.max + '" step="' + control.step + '" value="' + escapeHtml(value) + '" data-id="' + escapeHtml(control.id) + '"' + disabled + '>' +
                '<span class="bl-value">' + escapeHtml(formatValue(control, value)) + "</span>" +
                "</div>"
            );
        }
        if (control.kind === "toggle") {
            return (
                '<label class="bl-toggle">' +
                '<span class="switch"><input type="checkbox" data-id="' + escapeHtml(control.id) + '"' + (value ? " checked" : "") + disabled + '><span class="slider"></span></span>' +
                "<span>" + (value ? "Required" : "Not required") + "</span>" +
                "</label>"
            );
        }
        var options = (control.options || []).map(function (option) {
            var checked = (value || []).indexOf(option) !== -1 ? " checked" : "";
            return (
                '<label class="bl-option">' +
                '<input type="checkbox" data-id="' + escapeHtml(control.id) + '" value="' + escapeHtml(option) + '"' + checked + disabled + ">" +
                escapeHtml(option) +
                "</label>"
            );
        }).join("");
        return '<div class="bl-options">' + options + "</div>";
    }

    function impactLabel(kind) {
        if (kind === "strict") return '<span class="bl-impact-cell bl-impact-strict">Stricter</span>';
        if (kind === "lenient") return '<span class="bl-impact-cell bl-impact-lenient">More lenient</span>';
        return '<span class="bl-impact-cell bl-impact-same">Same as Balanced</span>';
    }

    function renderTable() {
        var locked = isLocked();
        var rows = filteredControls();
        countEl.textContent = rows.length + " of " + controls.length + " controls";
        if (!rows.length) {
            body.innerHTML = '<tr><td colspan="5" class="bl-empty">No controls match the current filter.</td></tr>';
            return;
        }
        body.innerHTML = rows.map(function (control) {
            var value = state.values[control.id];
            var impact = compareToBalanced(control, value);
            return (
                '<tr class="bl-row' + (locked ? " is-locked" : "") + '" data-id="' + escapeHtml(control.id) + '">' +
                '<td><div class="bl-control"><span class="bl-code">' + escapeHtml(control.code) + '</span><span class="bl-name">' + escapeHtml(control.name) + '</span><span class="bl-help">' + escapeHtml(control.help) + "</span></div></td>" +
                "<td>" + escapeHtml(control.pillar) + "</td>" +
                '<td><span class="bl-rule">' + escapeHtml(passLabel(control)) + "</span></td>" +
                '<td><div class="bl-widget">' + widgetHtml(control, value, locked) + "</div></td>" +
                "<td>" + impactLabel(impact) + "</td>" +
                "</tr>"
            );
        }).join("");
    }

    function renderImpact() {
        var stricter = 0;
        var looser = 0;
        var unchanged = 0;
        controls.forEach(function (control) {
            var kind = compareToBalanced(control, state.values[control.id]);
            if (kind === "strict") stricter += 1;
            else if (kind === "lenient") looser += 1;
            else unchanged += 1;
        });
        stricterEl.textContent = String(stricter);
        looserEl.textContent = String(looser);
        unchangedEl.textContent = String(unchanged);
        var profile = profiles.filter(function (item) { return item.id === state.profile; })[0];
        impactText.textContent = (profile ? profile.blurb : "Compared with Balanced.") +
            (state.dirty ? " Unsaved changes stay in this browser until you save a version." : "");
    }

    function renderMeta() {
        versionChip.textContent = currentVersionLabel() + (state.dirty ? " · unsaved" : "");
        versionChip.className = "status-chip " + (state.dirty ? "status-warn" : "status-on");
        lockNote.textContent = isLocked()
            ? "Named profiles are read-only. Choose Custom to edit sliders, toggles, and selectors."
            : "Custom is unlocked. Save creates a new version instead of overwriting history.";
        if (disclaimer) disclaimer.textContent = catalog.disclaimer || "";
        renderVersions();
    }

    function render() {
        renderProfiles();
        renderTable();
        renderImpact();
        renderMeta();
        persist();
    }

    function switchProfile(profileId) {
        if (profileId === state.profile) return;
        if (profileId === "custom") {
            state.profile = "custom";
            render();
            return;
        }
        state.profile = profileId;
        state.values = loadProfileValues(profileId);
        state.dirty = false;
        render();
    }

    function markCustom() {
        if (state.profile !== "custom") state.profile = "custom";
        state.dirty = true;
    }

    function readControlValue(control, source) {
        if (control.kind === "percent" || control.kind === "count") {
            return Number(source.value);
        }
        if (control.kind === "toggle") {
            return !!source.checked;
        }
        var selected = [];
        body.querySelectorAll('input[type="checkbox"][data-id="' + control.id + '"]').forEach(function (input) {
            if (input.checked) selected.push(input.value);
        });
        return selected;
    }

    profileBox.addEventListener("click", function (event) {
        var button = event.target.closest("[data-profile]");
        if (!button) return;
        switchProfile(button.getAttribute("data-profile"));
    });

    pillarSelect.addEventListener("change", function () {
        state.pillar = pillarSelect.value || "all";
        renderTable();
    });

    searchInput.addEventListener("input", function () {
        state.query = searchInput.value || "";
        renderTable();
    });

    function applyValue(id, value, rebuild) {
        var control = controlById(id);
        if (!control) return;
        markCustom();
        state.values[id] = value;
        if (rebuild) {
            render();
            return;
        }
        var row = body.querySelector('tr[data-id="' + id + '"]');
        if (row) {
            var valueEl = row.querySelector(".bl-value");
            if (valueEl) valueEl.textContent = formatValue(control, value);
            var toggleLabel = row.querySelector(".bl-toggle span:last-child");
            if (toggleLabel) toggleLabel.textContent = value ? "Required" : "Not required";
            var impactCell = row.querySelector("td:last-child");
            if (impactCell) impactCell.innerHTML = impactLabel(compareToBalanced(control, value));
        }
        renderImpact();
        renderMeta();
        persist();
    }

    body.addEventListener("input", function (event) {
        var input = event.target;
        var id = input.getAttribute("data-id");
        if (!id || isLocked()) return;
        var control = controlById(id);
        if (!control) return;
        applyValue(id, readControlValue(control, input), false);
    });

    body.addEventListener("change", function (event) {
        var input = event.target;
        var id = input.getAttribute("data-id");
        if (!id || isLocked()) return;
        var control = controlById(id);
        if (!control) return;
        applyValue(id, readControlValue(control, input), control.kind === "select" || control.kind === "toggle");
    });

    resetBtn.addEventListener("click", function () {
        var profileId = state.profile === "custom" ? "balanced" : state.profile;
        state.profile = profileId;
        state.values = loadProfileValues(profileId);
        state.dirty = false;
        render();
        if (window.showToast) window.showToast("Baseline reset to " + profileId + ".", "success");
    });

    saveBtn.addEventListener("click", function () {
        var version = {
            id: state.versions.length + 1,
            profile: state.profile,
            savedAt: new Date().toISOString(),
            values: clone(state.values)
        };
        state.versions.push(version);
        state.dirty = false;
        render();
        if (window.showToast) {
            window.showToast("Saved " + currentVersionLabel() + " locally. Live scoring is unchanged.", "success");
        }
    });

    versionSelect.addEventListener("change", function () {
        var versionId = Number(versionSelect.value);
        var version = state.versions.filter(function (item) { return item.id === versionId; })[0];
        if (!version) return;
        state.profile = version.profile;
        state.values = clone(version.values);
        state.dirty = false;
        render();
    });

    if (!controls.length) {
        body.innerHTML = '<tr><td colspan="5" class="bl-empty">Baseline catalog is unavailable.</td></tr>';
        return;
    }

    state.values = loadProfileValues("balanced");
    restore();
    if (!state.values || !Object.keys(state.values).length) {
        state.values = loadProfileValues("balanced");
    }
    renderPillars();
    render();
})();
