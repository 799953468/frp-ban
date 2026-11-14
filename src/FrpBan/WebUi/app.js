"use strict";

(() => {
    const element = (id) => document.getElementById(id);
    const state = {token: "", page: 1, total: 0, pageSize: 25, generation: 0, listRequest: 0, pending: false, removing: null};
    const requests = new Set();
    const number = new Intl.NumberFormat();
    let searchTimer;
    element("server-label").textContent = window.location.host;

    function notice(id, message = "") {
        element(id).textContent = message;
        element(id).hidden = !message;
    }

    function lock(message = "") {
        state.generation++;
        state.listRequest++;
        state.token = "";
        state.removing = null;
        state.pending = false;
        clearTimeout(searchTimer);
        for (const controller of requests) {
            controller.abort();
        }
        element("remove-dialog").close();
        element("management-panel").hidden = true;
        element("lock-button").hidden = true;
        element("login-panel").hidden = false;
        element("ban-rows").replaceChildren();
        element("login-form").reset();
        element("create-form").reset();
        element("search").value = "";
        element("kind").value = "all";
        element("create-panel").hidden = true;
        element("add-button").setAttribute("aria-expanded", "false");
        element("custom-duration-field").hidden = true;
        element("custom-duration").required = false;
        element("custom-duration").disabled = true;
        setPending(false);
        for (const id of ["feedback", "list-error", "create-error", "remove-error"]) {
            notice(id);
        }
        notice("login-error", message);
        element("token").focus();
    }

    async function api(path, options = {}) {
        const controller = new AbortController();
        const generation = state.generation;
        requests.add(controller);
        const timeout = setTimeout(() => controller.abort(), 15000);
        try {
            const response = await fetch(new URL(`api/${path}`, window.location.href), {
                ...options,
                headers: {"Authorization": `Bearer ${state.token}`, ...options.headers},
                signal: controller.signal,
                cache: "no-store",
                credentials: "omit",
                redirect: "error"
            });
            if (generation !== state.generation) {
                throw new Error("Session closed.");
            }
            if (response.status === 401) {
                lock("The management token was rejected. Enter a valid token to continue.");
                throw new Error("Authentication required.");
            }
            if (!response.ok) {
                const body = await response.json().catch(() => null);
                throw new Error(body?.error || `Request failed (${response.status}). Refresh and try again.`);
            }
            return response.status === 204 ? null : await response.json();
        } catch (error) {
            if (error.name === "AbortError") {
                throw new Error("The request timed out. Refresh to check whether the change was applied before retrying.");
            }
            if (error instanceof TypeError) {
                throw new Error("Cannot reach the server. Check your connection, then refresh before retrying.");
            }
            throw error;
        } finally {
            clearTimeout(timeout);
            requests.delete(controller);
        }
    }

    function appendTime(cell, value) {
        const date = new Date(value);
        const time = document.createElement("time");
        time.dateTime = value;
        time.title = date.toISOString();
        time.textContent = date.toLocaleDateString(undefined, {month: "short", day: "numeric", year: "numeric"});
        const detail = document.createElement("span");
        detail.className = "time-detail";
        detail.textContent = date.toLocaleTimeString(undefined, {hour: "2-digit", minute: "2-digit", timeZoneName: "short"});
        time.append(detail);
        cell.append(time);
    }

    function render(data) {
        state.page = data.page;
        state.total = data.total;
        element("active-count").textContent = number.format(data.activeCount);
        element("temporary-count").textContent = number.format(data.activeCount - data.permanentCount);
        element("permanent-count").textContent = number.format(data.permanentCount);
        element("duration").options[0].textContent = data.defaultBanDurationSeconds === 0
            ? "Server default (permanent)" : `Server default (${number.format(data.defaultBanDurationSeconds)} seconds)`;
        const rows = document.createDocumentFragment();
        for (const ban of data.items) {
            const row = document.createElement("tr");
            const cells = Array.from({length: 5}, () => row.insertCell());
            cells[0].className = "address";
            cells[0].textContent = ban.ip;
            cells[1].textContent = ban.reason;
            appendTime(cells[2], ban.bannedAt);
            if (ban.expiresAt) {
                appendTime(cells[3], ban.expiresAt);
            } else {
                const badge = document.createElement("span");
                badge.className = "badge";
                badge.textContent = "Permanent";
                cells[3].append(badge);
            }
            const remove = document.createElement("button");
            remove.type = "button";
            remove.className = "button remove-button";
            remove.textContent = "Remove";
            remove.setAttribute("aria-label", `Remove ban for ${ban.ip}`);
            remove.disabled = state.pending;
            remove.addEventListener("click", () => {
                state.removing = ban.ip;
                element("remove-ip").textContent = ban.ip;
                notice("remove-error");
                element("remove-dialog").showModal();
            });
            cells[4].append(remove);
            rows.append(row);
        }
        element("ban-rows").replaceChildren(rows);
        const filtered = element("search").value.trim() || element("kind").value !== "all";
        element("empty-state").hidden = data.items.length !== 0;
        element("empty-heading").textContent = filtered ? "No matching bans" : "No active bans";
        element("empty-description").textContent = filtered
            ? "Try another IP address or reason, or clear the filters."
            : "Addresses banned by your monitoring clients will appear here. You can also add a ban manually.";
        element("clear-filters").hidden = !filtered;
        const first = data.total ? (data.page - 1) * data.pageSize + 1 : 0;
        const last = Math.min(data.page * data.pageSize, data.total);
        element("page-summary").textContent = `${number.format(first)}–${number.format(last)} of ${number.format(data.total)} bans`;
        element("previous-button").disabled = data.page <= 1;
        element("next-button").disabled = last >= data.total;
        element("list-status").textContent = `Updated ${new Date().toLocaleTimeString()}`;
    }

    async function loadBans(page = state.page) {
        const generation = state.generation;
        const request = ++state.listRequest;
        element("ban-table").setAttribute("aria-busy", "true");
        element("refresh-button").disabled = true;
        element("previous-button").disabled = true;
        element("next-button").disabled = true;
        element("list-status").textContent = "Loading bans…";
        notice("list-error");
        try {
            const query = new URLSearchParams({page, pageSize: state.pageSize, search: element("search").value.trim(), kind: element("kind").value});
            const data = await api(`bans?${query}`);
            if (generation !== state.generation || request !== state.listRequest) {
                return false;
            }
            render(data);
            return true;
        } catch (error) {
            if (generation === state.generation && request === state.listRequest) {
                notice(element("management-panel").hidden ? "login-error" : "list-error", error.message);
                element("list-status").textContent = "Could not update the list. Displayed data may be out of date.";
            }
            return false;
        } finally {
            if (generation === state.generation && request === state.listRequest) {
                element("refresh-button").disabled = false;
                element("ban-table").setAttribute("aria-busy", "false");
            }
        }
    }

    function setPending(pending) {
        state.pending = pending;
        element("create-fields").disabled = pending;
        element("confirm-remove").disabled = pending;
        element("cancel-remove").disabled = pending;
        element("add-button").disabled = pending;
        element("save-button").textContent = pending ? "Saving…" : "Add ban";
        element("confirm-remove").textContent = pending ? "Removing…" : "Remove ban";
        for (const button of document.querySelectorAll(".remove-button")) {
            button.disabled = pending;
        }
    }

    function closeCreate() {
        element("create-panel").hidden = true;
        element("add-button").setAttribute("aria-expanded", "false");
        element("add-button").focus();
    }

    element("login-form").addEventListener("submit", async (event) => {
        event.preventDefault();
        state.token = element("token").value;
        element("token").value = "";
        element("unlock-button").disabled = true;
        element("unlock-button").textContent = "Unlocking…";
        notice("login-error");
        const loaded = await loadBans(1);
        if (loaded && state.token) {
            element("login-panel").hidden = true;
            element("management-panel").hidden = false;
            element("lock-button").hidden = false;
            element("bans-heading").focus();
        } else {
            state.token = "";
            element("token").focus();
        }
        element("unlock-button").disabled = false;
        element("unlock-button").textContent = "Unlock management";
    });

    element("lock-button").addEventListener("click", () => lock());
    window.addEventListener("pagehide", () => lock());
    element("refresh-button").addEventListener("click", () => loadBans());
    element("search").addEventListener("input", () => {
        clearTimeout(searchTimer);
        state.listRequest++;
        searchTimer = setTimeout(() => loadBans(1), 300);
    });
    element("kind").addEventListener("change", () => {
        clearTimeout(searchTimer);
        loadBans(1);
    });
    element("clear-filters").addEventListener("click", () => {
        clearTimeout(searchTimer);
        element("search").value = "";
        element("kind").value = "all";
        loadBans(1);
    });
    element("previous-button").addEventListener("click", () => loadBans(state.page - 1));
    element("next-button").addEventListener("click", () => loadBans(state.page + 1));
    element("add-button").addEventListener("click", () => {
        const opening = element("create-panel").hidden;
        element("create-panel").hidden = !opening;
        element("add-button").setAttribute("aria-expanded", String(opening));
        if (opening) {
            notice("create-error");
            element("ip").focus();
        }
    });
    element("cancel-create").addEventListener("click", closeCreate);
    element("duration").addEventListener("change", () => {
        const custom = element("duration").value === "custom";
        element("custom-duration-field").hidden = !custom;
        element("custom-duration").required = custom;
        element("custom-duration").disabled = !custom;
    });

    element("create-form").addEventListener("submit", async (event) => {
        event.preventDefault();
        if (state.pending) {
            return;
        }
        const generation = state.generation;
        const duration = element("duration").value;
        const durationSeconds = duration === "default" ? null : Number(duration === "custom" ? element("custom-duration").value : duration);
        const ip = element("ip").value.trim();
        setPending(true);
        notice("create-error");
        notice("feedback");
        try {
            await api("bans", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({ip, reason: element("reason").value.trim(), durationSeconds})});
            if (generation !== state.generation) {
                return;
            }
            element("create-form").reset();
            element("custom-duration-field").hidden = true;
            element("custom-duration").required = false;
            element("custom-duration").disabled = true;
            closeCreate();
            notice("feedback", `Ban applied for ${ip}. Any existing longer or permanent ban is preserved.`);
            await loadBans(1);
        } catch (error) {
            if (generation === state.generation) {
                notice("create-error", error.message);
            }
        } finally {
            if (generation === state.generation) {
                setPending(false);
                if (element("create-panel").hidden) {
                    element("add-button").focus();
                }
            }
        }
    });

    element("cancel-remove").addEventListener("click", () => element("remove-dialog").close());
    element("remove-dialog").addEventListener("cancel", (event) => {
        if (state.pending) {
            event.preventDefault();
        }
    });
    element("confirm-remove").addEventListener("click", async () => {
        if (state.pending || !state.removing) {
            return;
        }
        const generation = state.generation;
        const ip = state.removing;
        setPending(true);
        notice("remove-error");
        notice("feedback");
        try {
            await api(`bans/${encodeURIComponent(ip)}`, {method: "DELETE"});
            if (generation !== state.generation) {
                return;
            }
            element("remove-dialog").close();
            state.removing = null;
            notice("feedback", `Ban removed for ${ip}.`);
            await loadBans();
            element("bans-heading").focus();
        } catch (error) {
            if (generation === state.generation) {
                notice("remove-error", error.message);
            }
        } finally {
            if (generation === state.generation) {
                setPending(false);
            }
        }
    });
})();
