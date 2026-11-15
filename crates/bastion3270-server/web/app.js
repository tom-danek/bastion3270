// bastion3270 thin web client (protocol bastion3270.v1).
//
// Zero-Trust design: this script contains NO 3270 logic. It renders the server-side
// SafeScreenView projection and forwards keystrokes. Field attributes, protection and hidden
// fields are enforced by bastion3270-core on the server; nothing here can bypass them.
//
// This module only wires the DOM, the WebSockets and the canvas; the key mapping, the screen
// helpers, the texts and the status messages are pure modules. ES modules are strict and
// deferred.
//
// Several sessions run in tabs of one page: every tab has its own WebSocket, screen, status
// and reconnect state; the canvas, the status line and the keyboard belong to the active tab.

import { LANGUAGES, pickLanguage, t } from "./i18n.js";
import { BROWSER, HELP, PRESETS, ctrlTap, keyToMessage } from "./keymap.js";
import {
  MAX_ZOOM, MIN_ZOOM, THEMES, cellAt as cellAtPoint, fitCell, oiaText, printText, runStyle,
  selectionFrom, selectionText,
} from "./screen.js";
import { closedMessage, errorMessage, reconnectDelay } from "./status.js";

{
  const $ = (id) => document.getElementById(id);
  const PROTOCOL = "bastion3270.v1";
  const BEARER = "bastion3270.bearer.";
  const SESSIONS_KEY = "bastion3270.sessions";
  const ACTIVE_KEY = "bastion3270.active";
  const TOKEN_KEY = "bastion3270.token";
  const LANG_KEY = "bastion3270.lang";
  const ZOOM_KEY = "bastion3270.zoom";
  const RECENT_KEY = "bastion3270.recent";
  const CONNECTIONS_KEY = "bastion3270.connections";
  const INFO_MS = 10000;
  const RECENT_MAX = 5;
  const FILTER_FROM = 8;
  // A bearer token travels as a WebSocket sub-protocol name, which must be an HTTP token
  // (RFC 9110 §5.6.2); anything else would make `new WebSocket` throw.
  const TOKEN_CHARS = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
  const DISPLAY_KEY = "bastion3270.display";
  const SESSION_KEY = "bastion3270.session-options.";
  // Display and keyboard preferences of this browser. `blankFill`: "" (as configured), "on",
  // "off"; it applies to the open sessions at once and to every new one.
  const DISPLAY_DEFAULTS = Object.freeze({
    theme: "classic", cursor: "block", blink: false, crosshair: false, keybar: true,
    blankFill: "",
  });

  const state = {
    token: sessionStorage.getItem(TOKEN_KEY) || "",
    authRequired: false,
    // Session tabs in display order, and the active one (or null: picker / login shown).
    tabs: [],
    active: null,
    nextTabId: 1,
    maxTabs: 4,
    cell: { font: 16, w: 10, h: 20, ascent: 15 },
    // Glyph metrics of the screen font at 100 px, measured once.
    metrics: { w: 60, ascent: 75, descent: 20 },
    zoom: 0,
    // Rectangular mouse selection in screen cells: { r0, c0, r1, c1 } (inclusive), or null.
    selection: null,
    // Cell where the mouse button went down; a drag starts once the pointer leaves it.
    anchor: null,
    lang: "en",
    // The gateway's `resume_grace_secs`: how long resuming after a lost connection can work.
    graceSecs: 300,
    // Profile of the last session that ended, for "Connect again".
    lastProfile: null,
    profiles: new Map(),
    // The message on screen ({ key, params, level, again, profile }), re-rendered on a
    // language change.
    message: null,
    // Display settings (this browser), see DISPLAY_DEFAULTS.
    display: { ...DISPLAY_DEFAULTS },
    // What the gateway lets a user choose for a session (`choices` of /api/profiles).
    choices: null,
    // Blinking cursor phase.
    cursorOn: true,
  };

  const canvas = $("screen");
  const ctx = canvas.getContext("2d");

  // The active tab's screen and status (null without an active tab).
  const screen = () => (state.active ? state.active.screen : null);
  const status = () => (state.active ? state.active.status : null);
  // Profile the settings and the keyboard layout apply to: the active tab's, else the last.
  const currentProfile = () => (state.active ? state.active.profile : state.lastProfile);

  // ── UI helpers ───────────────────────────────────────────────────────────────
  function show(id) {
    for (const s of ["login", "picker", "terminal"]) $(s).hidden = s !== id;
    const terminal = id === "terminal";
    $("btn-disconnect").hidden = !terminal;
    $("btn-fullscreen").hidden = !terminal;
    $("btn-help").hidden = !terminal;
    $("btn-print").hidden = !terminal;
    $("btn-logout").hidden = !state.authRequired || id === "login";
    $("btn-new").hidden = id === "login" || state.tabs.length === 0;
    $("picker-back").hidden = !(id === "picker" && state.tabs.length > 0);
    renderTabs();
  }

  // `localStorage` may be unavailable (private window, blocked site data): a choice is then
  // simply not remembered.
  function stored(key) {
    try { return localStorage.getItem(key); } catch (_) { return null; }
  }
  function store(key, value) {
    try { localStorage.setItem(key, value); } catch (_) { /* not remembered */ }
  }

  // ── Language ─────────────────────────────────────────────────────────────────
  const tr = (key, params) => t(state.lang, key, params);

  function applyLanguage() {
    document.documentElement.lang = state.lang;
    for (const el of document.querySelectorAll("[data-i18n]")) el.textContent = tr(el.dataset.i18n);
    for (const el of document.querySelectorAll("[data-i18n-placeholder]")) {
      el.placeholder = tr(el.dataset.i18nPlaceholder);
    }
    for (const el of document.querySelectorAll("[data-i18n-label]")) {
      el.setAttribute("aria-label", tr(el.dataset.i18nLabel));
    }
    $("tabs").setAttribute("aria-label", tr("tabs.label"));
    renderTabs();
    if (state.message) renderMessage();
  }

  const langSelect = $("lang");
  for (const [code, name] of Object.entries(LANGUAGES)) langSelect.add(new Option(name, code));
  langSelect.addEventListener("change", () => {
    state.lang = langSelect.value;
    store(LANG_KEY, state.lang);
    applyLanguage();
  });

  // ── Message line ─────────────────────────────────────────────────────────────
  let messageTimer = 0;

  /**
   * Shows a client message: `info` expires, `warn` / `error` stay until dismissed or replaced.
   * `again` offers "Connect again" with `profile` (or the last profile); a message about a
   * session names its profile while other sessions are open.
   */
  function message(key, params = {}, level = "info", again = false, profile = null) {
    state.message = { key, params, level, again, profile };
    clearTimeout(messageTimer);
    if (level === "info") messageTimer = setTimeout(clearMessage, INFO_MS);
    renderMessage();
  }

  function renderMessage() {
    const m = state.message;
    $("message").hidden = !m;
    if (!m) return;
    $("message").className = "message " + m.level;
    const text = tr(m.key, m.params);
    const named = m.profile && state.tabs.some((tab) => tab.profile.id !== m.profile.id);
    $("message-text").textContent = named ? tr("msg.prefixed", { profile: m.profile.name, text }) : text;
    $("message-again").hidden = !(m.again && (m.profile || state.lastProfile));
  }

  function clearMessage() {
    state.message = null;
    clearTimeout(messageTimer);
    renderMessage();
  }

  $("message-close").addEventListener("click", clearMessage);
  $("message-again").addEventListener("click", () => {
    const profile = (state.message && state.message.profile) || state.lastProfile;
    clearMessage();
    if (profile) open(profile);
  });

  function authHeaders() {
    return state.token ? { Authorization: "Bearer " + state.token } : {};
  }

  // ── Session list in the tab's storage (resumed after a reload) ───────────────
  function persist() {
    const saved = state.tabs.filter((tab) => tab.saved)
      .map((tab) => ({ ...tab.saved, profile: tab.profile }));
    if (saved.length) sessionStorage.setItem(SESSIONS_KEY, JSON.stringify(saved));
    else sessionStorage.removeItem(SESSIONS_KEY);
    const index = state.tabs.filter((tab) => tab.saved).indexOf(state.active);
    sessionStorage.setItem(ACTIVE_KEY, String(Math.max(index, 0)));
  }

  function savedSessions() {
    try {
      const list = JSON.parse(sessionStorage.getItem(SESSIONS_KEY) || "[]");
      return Array.isArray(list) ? list.filter((s) => s && s.session_id && s.token) : [];
    } catch (_) {
      return [];
    }
  }

  // ── Boot: config → (login) → resume or profile picker ────────────────────────
  async function boot() {
    const cfg = await (await fetch("/api/config")).json();
    state.authRequired = cfg.auth_required;
    if (Number.isFinite(cfg.resume_grace_secs)) state.graceSecs = cfg.resume_grace_secs;
    if (Number.isFinite(cfg.max_tabs)) state.maxTabs = cfg.max_tabs;
    if (state.authRequired && !state.token) return show("login");

    const saved = savedSessions();
    if (saved.length) {
      const active = Number.parseInt(sessionStorage.getItem(ACTIVE_KEY) || "0", 10) || 0;
      for (const s of saved) {
        const tab = newTab(s.profile || { id: "", name: "" });
        tab.saved = { session_id: s.session_id, token: s.token };
        connect(tab, { type: "resume", session_id: s.session_id, token: s.token });
      }
      activate(state.tabs[Math.min(active, state.tabs.length - 1)]);
      return;
    }
    await loadProfiles(true);
  }

  // ── Profile picker ───────────────────────────────────────────────────────────
  /** The profiles of the last sessions opened, most recent first. */
  function recent() {
    try {
      const ids = JSON.parse(stored(RECENT_KEY) || "[]");
      return Array.isArray(ids) ? ids.filter((id) => state.profiles.has(id)) : [];
    } catch (_) {
      return [];
    }
  }

  function remember(profile) {
    const ids = [profile.id, ...recent().filter((id) => id !== profile.id)].slice(0, RECENT_MAX);
    store(RECENT_KEY, JSON.stringify(ids));
  }

  function profileButton(p, small) {
    const b = document.createElement("button");
    b.type = "button";
    b.textContent = p.name;
    if (small) {
      const s = document.createElement("small");
      s.textContent = p.description;
      b.appendChild(s);
    }
    b.addEventListener("click", () => open(state.profiles.get(p.id)));
    return b;
  }

  /** A picker entry: connect button, and the profile's session options folded below it. */
  function profileEntry(p) {
    const li = document.createElement("li");
    const connect = profileButton(p, true);
    connect.classList.add("profile");
    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "options-toggle";
    toggle.id = "options-" + p.id;
    toggle.textContent = "⚙ " + tr("picker.options");
    toggle.setAttribute("aria-expanded", "false");
    const panel = document.createElement("div");
    panel.className = "profile-options";
    panel.hidden = true;
    toggle.addEventListener("click", () => {
      if (!state.choices) return;
      panel.hidden = !panel.hidden;
      toggle.setAttribute("aria-expanded", String(!panel.hidden));
      if (!panel.hidden) panel.replaceChildren(sessionForm(state.profiles.get(p.id), "opt-" + p.id));
    });
    li.append(connect, toggle, panel);
    return li;
  }

  /**
   * Loads the profile list and shows the picker. On the first start with exactly one profile
   * (`autoOpen`) that profile is opened at once.
   */
  async function loadProfiles(autoOpen = false) {
    const res = await fetch("/api/profiles", { headers: authHeaders() });
    if (res.status === 401) {
      sessionStorage.removeItem(TOKEN_KEY);
      state.token = "";
      message("login.invalid", {}, "warn");
      return show("login");
    }
    if (!res.ok) return message("msg.profiles_failed", { status: res.status }, "error");
    const body = await res.json();
    $("build").textContent = body.build + " " + body.version;
    state.choices = body.choices || null;
    state.customPolicy = body.custom_connections || { enabled: false };
    state.profiles = new Map(body.profiles.map((p) => [p.id, {
      id: p.id, name: p.name, keyboard: p.keyboard, description: p.description,
      lu_names: p.lu_names,
    }]));
    if (autoOpen && body.profiles.length === 1 && state.tabs.length === 0) {
      return open(state.profiles.get(body.profiles[0].id));
    }
    renderPicker();
    renderCustom();
    show("picker");
  }

  function renderPicker() {
    const all = [...state.profiles.values()];
    const filter = $("picker-filter");
    filter.hidden = all.length <= FILTER_FROM;
    const needle = filter.hidden ? "" : filter.value.trim().toLowerCase();
    const shown = all.filter((p) => !needle
      || (p.name + " " + p.description).toLowerCase().includes(needle));
    $("profiles").replaceChildren(...shown.map(profileEntry));
    const recents = all.length > 1 ? recent().map((id) => state.profiles.get(id)) : [];
    $("recent").hidden = recents.length === 0 || Boolean(needle);
    $("recent").replaceChildren(...recents.map((p) => {
      const li = document.createElement("li");
      li.appendChild(profileButton(p, false));
      return li;
    }));
    $("recent").setAttribute("aria-label", tr("picker.recent"));
  }

  $("picker-filter").addEventListener("input", renderPicker);
  $("picker-back").addEventListener("click", () => activate(state.active || state.tabs[0]));
  $("btn-new").addEventListener("click", () => {
    if (state.tabs.length >= state.maxTabs) {
      return message("tabs.limit", { max: state.maxTabs }, "warn");
    }
    loadProfiles().catch(() => message("msg.unreachable", {}, "error"));
  });

  $("login-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const token = $("token").value.trim();
    if (!TOKEN_CHARS.test(token)) return message("login.bad_chars", {}, "warn");
    state.token = token;
    sessionStorage.setItem(TOKEN_KEY, state.token);
    boot();
  });

  // ── Connections the user defines (host, port, TLS) ───────────────────────────
  // Saved in this browser; the gateway checks every one against its policy when it opens
  // (`[custom_connections]`): what this page shows about that policy is only a hint.
  const customPolicy = () => state.customPolicy || { enabled: false };

  function customConnections() {
    try {
      const list = JSON.parse(stored(CONNECTIONS_KEY) || "[]");
      return Array.isArray(list)
        ? list.filter((c) => c && c.id && c.custom && c.custom.host && c.custom.port) : [];
    } catch (_) {
      return [];
    }
  }

  function saveConnections(list) {
    store(CONNECTIONS_KEY, JSON.stringify(list));
  }

  function renderCustom() {
    const enabled = Boolean(customPolicy().enabled);
    const list = enabled ? customConnections() : [];
    $("btn-custom-new").hidden = !enabled;
    $("custom-title").hidden = list.length === 0;
    $("custom-list").hidden = list.length === 0;
    $("custom-list").replaceChildren(...list.map((c) => {
      const li = document.createElement("li");
      const connect = document.createElement("button");
      connect.type = "button";
      connect.className = "profile";
      connect.textContent = c.name;
      const small = document.createElement("small");
      small.textContent = c.custom.host + ":" + c.custom.port + (c.custom.tls ? " · TLS" : "");
      connect.append(small);
      connect.addEventListener("click", () => open(c));
      const edit = document.createElement("button");
      edit.type = "button";
      edit.textContent = "✎ " + tr("custom.edit");
      edit.addEventListener("click", () => editConnection(c));
      const del = document.createElement("button");
      del.type = "button";
      del.textContent = "✕";
      del.setAttribute("aria-label", tr("custom.delete"));
      del.addEventListener("click", () => {
        if (!window.confirm(tr("custom.delete_confirm", { name: c.name }))) return;
        saveConnections(customConnections().filter((x) => x.id !== c.id));
        try { localStorage.removeItem(SESSION_KEY + c.id); } catch (_) { /* nothing stored */ }
        renderCustom();
      });
      li.append(connect, edit, del);
      return li;
    }));
  }

  // The connection being edited in the dialog (`isNew`: not in the saved list yet).
  let editing = null;

  function editConnection(conn) {
    const policy = customPolicy();
    const isNew = !conn;
    const c = conn || {
      id: "custom-" + Date.now().toString(36), name: "",
      custom: { host: "", port: policy.allow_plain ? 23 : 992, tls: !policy.allow_plain },
    };
    editing = { conn: c, isNew };
    $("custom-dialog-title").textContent = tr(isNew ? "custom.title_new" : "custom.title_edit");
    $("custom-name").value = c.name;
    $("custom-host").value = c.custom.host;
    $("custom-port").value = c.custom.port;
    $("custom-tls").checked = c.custom.tls || !policy.allow_plain;
    $("custom-tls").disabled = !policy.allow_plain;
    const notes = [];
    if (!policy.allow_plain) notes.push(tr("custom.tls_required"));
    if (policy.restricted) notes.push(tr("custom.restricted"));
    $("custom-note").textContent = notes.join(" ");
    $("custom-note").hidden = notes.length === 0;
    $("custom-error").hidden = true;
    $("custom-options").replaceChildren(sessionForm(c, "custom-opt"));
    $("custom-dialog").showModal();
  }

  /** Reads the dialog into the connection being edited and saves it; `null` if incomplete. */
  function saveEditing() {
    const host = $("custom-host").value.trim();
    const port = Number($("custom-port").value);
    if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
      $("custom-error").textContent = tr("custom.invalid");
      $("custom-error").hidden = false;
      return null;
    }
    const c = editing.conn;
    c.custom = { host, port, tls: $("custom-tls").checked };
    c.name = $("custom-name").value.trim() || host + ":" + port;
    const list = customConnections().filter((x) => x.id !== c.id);
    saveConnections([...list, c]);
    editing = null;
    $("custom-dialog").close();
    renderCustom();
    return c;
  }

  $("btn-custom-new").addEventListener("click", () => editConnection(null));
  $("custom-save").addEventListener("click", saveEditing);
  $("custom-connect").addEventListener("click", () => {
    const c = saveEditing();
    if (c) open(c);
  });
  $("custom-cancel").addEventListener("click", () => $("custom-dialog").close());
  $("custom-dialog").addEventListener("close", () => {
    // A new connection that was not saved leaves no session options behind.
    if (editing && editing.isNew) {
      try { localStorage.removeItem(SESSION_KEY + editing.conn.id); } catch (_) { /* none */ }
    }
    editing = null;
  });

  // ── Tabs ─────────────────────────────────────────────────────────────────────
  function newTab(profile) {
    const tab = {
      id: state.nextTabId++, profile, ws: null, screen: null, status: null, saved: null,
      resuming: false, reconnect: null, lastError: null, connected: false, unread: false,
    };
    state.tabs.push(tab);
    return tab;
  }

  /** Shows `tab` in the terminal (its screen, status line and keyboard layout). */
  function activate(tab) {
    if (!tab) return;
    state.active = tab;
    tab.unread = false;
    state.selection = null;
    show("terminal");
    if (tab.screen) layout();
    else clearCanvas();
    renderOia();
    persist();
    canvas.focus();
  }

  function renderTabs() {
    const nav = $("tabs");
    nav.replaceChildren(...state.tabs.map((tab, i) => {
      const el = document.createElement("div");
      el.className = "tab" + (tab === state.active && !$("terminal").hidden ? " active" : "")
        + (tab.connected ? "" : " connecting") + (tab.unread ? " unread" : "");
      const main = document.createElement("button");
      main.type = "button";
      main.className = "tab-main";
      main.title = "Alt+" + (i + 1);
      const dot = document.createElement("span");
      dot.className = "dot";
      main.append(dot, document.createTextNode(tab.profile.name));
      main.addEventListener("click", () => activate(tab));
      const close = document.createElement("button");
      close.type = "button";
      close.className = "tab-close";
      close.textContent = "✕";
      close.setAttribute("aria-label", tr("tabs.close"));
      close.addEventListener("click", () => {
        if (!tab.connected || window.confirm(tr("tabs.close_confirm", { profile: tab.profile.name }))) {
          closeTab(tab);
        }
      });
      el.append(main, close);
      return el;
    }));
  }

  /** Removes a tab; the next one (or the picker) is shown when it was the active one. */
  function removeTab(tab) {
    const i = state.tabs.indexOf(tab);
    if (i < 0) return;
    stopReconnect(tab);
    state.tabs.splice(i, 1);
    if (state.active === tab) {
      state.active = null;
      wipeScreen();
      const next = state.tabs[Math.min(i, state.tabs.length - 1)];
      if (next) activate(next);
    }
    persist();
    renderTabs();
  }

  /**
   * Ends the session of `tab` (the user closed it) and removes the tab; after the last tab the
   * picker is shown, unless the caller shows something else (log out: the login screen).
   */
  function closeTab(tab, thenPicker = true) {
    const ws = tab.ws;
    tab.ws = null;
    if (ws) {
      if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: "disconnect" }));
      ws.close();
    }
    removeTab(tab);
    if (thenPicker && !state.tabs.length) loadProfiles().catch(() => {});
  }

  // ── WebSocket ────────────────────────────────────────────────────────────────
  /** Opens a new session on `profile` ({ id, name, ... }) in a new tab. */
  function open(profile) {
    if (state.tabs.length >= state.maxTabs) {
      return message("tabs.limit", { max: state.maxTabs }, "warn");
    }
    remember(profile);
    $("picker-filter").value = ""; // the next visit to the picker starts unfiltered
    const tab = newTab(profile);
    message("msg.connecting", { profile: profile.name });
    const options = sessionOptions(profile);
    if (state.display.blankFill) options.blank_fill = state.display.blankFill === "on";
    connect(tab, profile.custom
      ? { type: "open_custom", target: profile.custom, options }
      : { type: "open", profile: profile.id, options });
    activate(tab);
  }

  function connect(tab, first) {
    const scheme = location.protocol === "https:" ? "wss:" : "ws:";
    const protocols = [PROTOCOL];
    if (state.token) protocols.push(BEARER + state.token);
    const ws = new WebSocket(scheme + "//" + location.host + "/ws", protocols);
    tab.ws = ws;
    tab.resuming = first.type === "resume";
    tab.lastError = null;
    // `ended`: the gateway said why the session ended (`closed`), or the user left.
    ws.ended = false;
    ws.addEventListener("open", () => ws.send(JSON.stringify(first)));
    // A socket the client has let go of (tab closed, log out) no longer drives the page.
    ws.addEventListener("message", (ev) => { if (tab.ws === ws) onMessage(tab, ws, JSON.parse(ev.data)); });
    ws.addEventListener("close", () => {
      if (tab.ws !== ws) return;
      tab.ws = null;
      tab.connected = false;
      renderTabs();
      // Lost without a word from the gateway (network, proxy, laptop asleep): resume.
      if (!ws.ended && tab.saved) startReconnect(tab);
      else if (!ws.ended && tab.reconnect) nextReconnect(tab);
    });
  }

  // ── Reconnect after a lost connection ────────────────────────────────────────
  function startReconnect(tab) {
    if (!tab.reconnect) tab.reconnect = { attempt: 0, since: Date.now(), timer: 0 };
    nextReconnect(tab);
  }

  function nextReconnect(tab) {
    const r = tab.reconnect;
    if (!r) return;
    r.attempt += 1;
    const delay = reconnectDelay(r.attempt, Date.now() - r.since, state.graceSecs);
    if (delay === null) return sessionEnded(tab, "closed.ended", {});
    message("msg.reconnecting", { attempt: r.attempt }, "warn", false, tab.profile);
    r.timer = setTimeout(() => {
      if (!tab.saved) return sessionEnded(tab, "closed.ended", {});
      connect(tab, { type: "resume", session_id: tab.saved.session_id, token: tab.saved.token });
    }, delay);
  }

  function stopReconnect(tab) {
    if (tab.reconnect) clearTimeout(tab.reconnect.timer);
    tab.reconnect = null;
  }

  /**
   * The session of `tab` has ended: the tab goes, the message explains why and offers a new
   * session with the same profile.
   */
  function sessionEnded(tab, key, params, level = "warn", again = true) {
    state.lastProfile = tab.profile;
    tab.saved = null;
    removeTab(tab);
    message(key, params, level, again, tab.profile);
    // The message on screen already explains what happened (e.g. a gateway restart); a
    // failed reload of the picker must not replace it.
    if (!state.tabs.length) loadProfiles().catch(() => {});
  }

  function clearCanvas() {
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.clearRect(0, 0, canvas.width, canvas.height);
  }

  // The last screen may hold customer data: when a session ends or the user switches away,
  // nothing of it stays in the canvas, the status line or the banner of the page.
  function wipeScreen() {
    state.selection = null;
    clearCanvas();
    $("oia").replaceChildren();
    $("banner").textContent = "";
    $("banner").hidden = true;
  }

  function send(msg) {
    const ws = state.active && state.active.ws;
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(msg));
  }

  function onMessage(tab, ws, m) {
    const isActive = tab === state.active;
    switch (m.type) {
      case "session": {
        // A connection of the user's own keeps its entry (the gateway names it
        // `custom:<host>:<port>`).
        const known = state.profiles.get(m.profile);
        if (known) tab.profile = known;
        else if (!tab.profile.custom && tab.profile.id !== m.profile) {
          tab.profile = { id: m.profile, name: m.profile };
        }
        if (m.resume_token) tab.saved = { session_id: m.session_id, token: m.resume_token };
        tab.connected = true;
        if (tab.reconnect) message("msg.reconnected", {}, "info", false, tab.profile);
        else if (!tab.resuming) message("msg.connected", { profile: tab.profile.name });
        stopReconnect(tab);
        persist();
        renderTabs();
        if (isActive) {
          show("terminal");
          canvas.focus();
        }
        break;
      }
      case "frame":
        if (m.screen) {
          const resized = !tab.screen || tab.screen.rows !== m.screen.rows
            || tab.screen.cols !== m.screen.cols;
          tab.screen = m.screen;
          if (isActive) {
            // A new screen invalidates the selection (it may no longer match the content).
            state.selection = null;
            if (resized) layout();
          }
        }
        tab.status = m.status;
        if (isActive) {
          if (m.alarm) beep();
          render();
        } else if (m.screen && !tab.unread) {
          tab.unread = true;
          renderTabs();
        }
        break;
      case "error":
        if (m.code === "session_not_found" && tab.resuming) {
          ws.ended = true;
          tab.resuming = false;
          // After a lost connection the session is gone; on a page load there was simply
          // nothing to resume.
          if (tab.reconnect) return sessionEnded(tab, "closed.ended", {});
          tab.saved = null;
          removeTab(tab);
          if (!state.tabs.length) loadProfiles();
        } else if (m.code === "auth_failed") {
          ws.ended = true;
          sessionStorage.removeItem(TOKEN_KEY);
          state.token = "";
          for (const other of [...state.tabs]) closeTab(other, false);
          message("error.auth_failed", {}, "error");
          show(state.authRequired ? "login" : "picker");
        } else {
          tab.lastError = m.code;
          const e = errorMessage(m.code, m.message);
          message(e.key, e.params, e.level, e.level === "error", tab.profile);
        }
        break;
      case "closed": {
        ws.ended = true;
        stopReconnect(tab);
        if (m.reason === "session_not_found") break;
        if (m.reason === "taken_over") {
          tab.saved = null;
          removeTab(tab);
          message("msg.taken_over", {}, "warn", false, tab.profile);
          if (!state.tabs.length) loadProfiles().catch(() => {});
          break;
        }
        // An error message about the same cause is already on screen (e.g. the host could not
        // be reached): keep its text, it says more than the close reason.
        if (m.reason === tab.lastError) {
          state.lastProfile = tab.profile;
          tab.saved = null;
          removeTab(tab);
          if (!state.tabs.length) loadProfiles().catch(() => {});
          break;
        }
        const c = closedMessage(m.reason);
        sessionEnded(tab, c.key, c.params, c.level, c.again);
        break;
      }
    }
  }

  // ── Rendering ────────────────────────────────────────────────────────────────
  const mono = () => getComputedStyle(document.body).getPropertyValue("--mono");

  /** Glyph metrics of the screen font at 100 px (scaled for every font size). */
  function measure() {
    ctx.font = "100px " + mono();
    const m = ctx.measureText("M");
    const box = ctx.measureText("Mgjpq|ÁÉ");
    state.metrics = {
      w: m.width,
      ascent: box.actualBoundingBoxAscent || 75,
      descent: box.actualBoundingBoxDescent || 20,
    };
  }

  /**
   * Fits the screen into the window: the space below the canvas's top edge, minus the status
   * line, banner and key bar under it. The zoom of `Ctrl +` / `Ctrl -` scales on top.
   */
  function layout() {
    const s = screen();
    if (!s) return;
    const term = $("terminal");
    const under = ["oia", "banner", "keybar"]
      .map((id) => $(id))
      .filter((el) => !el.hidden)
      .reduce((sum, el) => sum + el.offsetHeight + 6, 0);
    const top = canvas.getBoundingClientRect().top;
    const availW = term.clientWidth - 4;
    const availH = window.innerHeight - top - under - 16;
    state.cell = fitCell(availW, availH, s.rows, s.cols, state.metrics, state.zoom);
    $("oia").style.fontSize = state.cell.font + "px";
    render();
  }

  function setZoom(zoom) {
    state.zoom = Math.min(Math.max(zoom, MIN_ZOOM), MAX_ZOOM);
    store(ZOOM_KEY, String(state.zoom));
    layout();
  }

  let resizeFrame = 0;
  const relayout = () => {
    cancelAnimationFrame(resizeFrame);
    resizeFrame = requestAnimationFrame(layout);
  };
  window.addEventListener("resize", relayout);
  // The space for the screen also changes without a window resize: the message line appears
  // or goes, the tabs wrap to a second line, the banner or the key bar is shown. The status
  // line is not observed: its height follows the font that `layout` chooses.
  if (typeof ResizeObserver === "function") {
    const around = new ResizeObserver(relayout);
    for (const el of [document.querySelector("header.bar"), $("message"), $("banner"), $("keybar")]) {
      if (el) around.observe(el);
    }
  }

  // ── Printing ─────────────────────────────────────────────────────────────────
  // Every way of printing (the button, Ctrl+P, the browser's menu) goes through `beforeprint`:
  // the print view gets the active screen, the gateway is told (audit, the copy policy), and
  // the text leaves the page again after printing.
  window.addEventListener("beforeprint", () => {
    const s = screen();
    const view = $("print-view");
    if (!s || $("terminal").hidden) {
      view.textContent = "";
      return;
    }
    send({ type: "print" });
    if (!s.copy_allowed) {
      // The gateway answers with `print_denied` (and audits it); the message line shows it.
      view.textContent = tr("msg.print_disabled") + "\n";
      return;
    }
    const title = state.active.profile.name + " — " + new Date().toLocaleString(state.lang);
    view.textContent = printText(s, title, $("oia").textContent);
  });
  window.addEventListener("afterprint", () => { $("print-view").textContent = ""; });
  $("btn-print").addEventListener("click", () => window.print());

  $("btn-fullscreen").addEventListener("click", () => {
    if (document.fullscreenElement) document.exitFullscreen();
    else document.documentElement.requestFullscreen().catch(() => {});
    canvas.focus();
  });

  function render() {
    const s = screen();
    if (!s) return;
    const { font, w, h, ascent } = state.cell;
    const dpr = window.devicePixelRatio || 1;
    const cw = s.cols * w;
    const ch = s.rows * h;
    if (canvas.width !== cw * dpr || canvas.height !== ch * dpr) {
      canvas.width = cw * dpr;
      canvas.height = ch * dpr;
      canvas.style.width = cw + "px";
      canvas.style.height = ch + "px";
    }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.font = font + "px " + mono();
    ctx.textBaseline = "alphabetic";
    const theme = THEMES[state.display.theme] || THEMES.classic;
    ctx.fillStyle = theme.bg;
    ctx.fillRect(0, 0, cw, ch);

    for (const r of s.runs) {
      const { fg, bg, underline } = runStyle(r, theme);
      for (let i = r.s; i < r.s + r.n; i++) {
        const row = Math.floor(i / s.cols);
        const col = i % s.cols;
        const x = col * w;
        const y = row * h;
        if (bg) { ctx.fillStyle = bg; ctx.fillRect(x, y, w, h); }
        const c = s.text[row] ? s.text[row][col] : " ";
        if (c && c !== " ") { ctx.fillStyle = fg; ctx.fillText(c, x, y + ascent); }
        if (underline) { ctx.fillStyle = fg; ctx.fillRect(x, y + h - 2, w, 1); }
      }
    }

    const [cr, cc] = s.cursor;
    // Crosshair: the cursor's row and column, faintly.
    if (state.display.crosshair) {
      ctx.globalAlpha = 0.12;
      ctx.fillStyle = theme.cursor;
      ctx.fillRect(0, cr * h, cw, h);
      ctx.fillRect(cc * w, 0, w, ch);
      ctx.globalAlpha = 1;
    }
    // Cursor: block or underline; hidden in the off phase of blinking.
    if (state.cursorOn || !state.display.blink) {
      ctx.globalAlpha = state.display.cursor === "underline" ? 1 : 0.55;
      ctx.fillStyle = theme.cursor;
      if (state.display.cursor === "underline") ctx.fillRect(cc * w, cr * h + h - 3, w, 3);
      else ctx.fillRect(cc * w, cr * h, w, h);
      ctx.globalAlpha = 1;
    }

    // Selection overlay
    const sel = state.selection;
    if (sel) {
      ctx.globalAlpha = 0.35;
      ctx.fillStyle = theme.selection;
      ctx.fillRect(sel.c0 * w, sel.r0 * h, (sel.c1 - sel.c0 + 1) * w, (sel.r1 - sel.r0 + 1) * h);
      ctx.globalAlpha = 1;
      ctx.strokeStyle = theme.selection;
      ctx.lineWidth = 1;
      ctx.strokeRect(sel.c0 * w + 0.5, sel.r0 * h + 0.5, (sel.c1 - sel.c0 + 1) * w - 1, (sel.r1 - sel.r0 + 1) * h - 1);
    }

    renderOia();
  }

  function renderOia() {
    const st = status();
    const s = screen();
    const oia = $("oia");
    const banner = $("banner");
    if (!st || !s) {
      oia.replaceChildren();
      banner.hidden = true;
      banner.textContent = "";
      return;
    }
    oia.replaceChildren();
    const text = oiaText(st, s);
    oia.append(document.createTextNode(text.left));
    const lock = document.createElement("span");
    lock.className = "lock";
    lock.textContent = text.lock;
    oia.append(lock);
    oia.append(document.createTextNode(text.cursor));
    // NVT text from the host (plain text, never interpreted as HTML).
    banner.hidden = !st.banner;
    banner.textContent = st.banner || "";
  }

  function beep() {
    try {
      const ac = new AudioContext();
      const o = ac.createOscillator();
      o.frequency.value = 880;
      o.connect(ac.destination);
      o.start();
      o.stop(ac.currentTime + 0.12);
    } catch (_) { /* audio unavailable */ }
  }

  // ── Keyboard layout ──────────────────────────────────────────────────────────
  const presetKey = (profile) => "bastion3270.keyboard." + profile.id;

  /** The user's layout for the current profile, else the profile's default, else x3270. */
  function preset() {
    const p = currentProfile();
    const chosen = p && stored(presetKey(p));
    if (chosen && PRESETS.includes(chosen)) return chosen;
    return p && PRESETS.includes(p.keyboard) ? p.keyboard : "x3270";
  }

  function renderKeyHelp() {
    const select = $("preset");
    select.replaceChildren(...PRESETS.map((id) => new Option(tr("preset." + id), id)));
    select.value = preset();
    const table = $("keyhelp-table");
    table.replaceChildren(...HELP[preset()].map(([fn, keys]) => {
      const row = document.createElement("tr");
      for (const text of [tr(fn), keys]) {
        const cell = document.createElement("td");
        cell.textContent = text;
        row.append(cell);
      }
      return row;
    }));
  }

  $("btn-help").addEventListener("click", () => {
    renderKeyHelp();
    $("keyhelp").showModal();
  });
  $("preset").addEventListener("change", () => {
    const p = currentProfile();
    if (p) store(presetKey(p), $("preset").value);
    renderKeyHelp();
  });
  $("keyhelp").addEventListener("close", () => canvas.focus());

  // ── Settings ─────────────────────────────────────────────────────────────────
  function loadDisplay() {
    let saved = {};
    try { saved = JSON.parse(stored(DISPLAY_KEY) || "{}") || {}; } catch (_) { saved = {}; }
    state.display = { ...DISPLAY_DEFAULTS, ...saved };
    if (!Object.hasOwn(THEMES, state.display.theme)) state.display.theme = "classic";
  }

  /** Applies the display settings to the page (theme of the chrome, key bar). */
  function applyDisplay() {
    document.documentElement.dataset.theme = state.display.theme;
    // The title bar of the installed application follows the header bar.
    const chrome = document.querySelector('meta[name="theme-color"]');
    if (chrome) {
      chrome.content = getComputedStyle(document.documentElement).getPropertyValue("--panel").trim();
    }
    $("keybar").hidden = !state.display.keybar;
    layout();
  }

  /** The session choices the user made for `profile` (only those that differ from it). */
  function sessionOptions(profile) {
    try {
      const saved = JSON.parse(stored(SESSION_KEY + profile.id) || "{}") || {};
      const options = {};
      for (const key of ["model", "rows", "cols", "codepage", "lu_name"]) {
        if (saved[key] !== undefined && saved[key] !== null && saved[key] !== "") options[key] = saved[key];
      }
      if (options.model !== "dynamic") { delete options.rows; delete options.cols; }
      return options;
    } catch (_) {
      return {};
    }
  }

  const option = (value, key, params) => new Option(tr(key, params), value);

  function renderSettings() {
    const d = state.display;
    $("set-theme").replaceChildren(...Object.keys(THEMES).map((id) => option(id, "theme." + id)));
    $("set-theme").value = d.theme;
    $("set-cursor").replaceChildren(option("block", "cursor.block"), option("underline", "cursor.underline"));
    $("set-cursor").value = d.cursor;
    $("set-blink").checked = d.blink;
    $("set-crosshair").checked = d.crosshair;
    $("set-keybar").checked = d.keybar;

    $("set-blank").replaceChildren(option("", "choice.default"), option("on", "choice.on"),
      option("off", "choice.off"));
    $("set-blank").value = d.blankFill;
  }

  /**
   * The choices that must be made before a session opens (screen, code page, LU name) as a
   * form whose controls are `<prefix>-model`, `-rows`, `-cols`, `-codepage`, `-lu`; every
   * change is saved for the profile at once. Shown folded under each profile of the picker.
   */
  function sessionForm(profile, prefix) {
    const o = sessionOptions(profile);
    const form = document.createElement("div");
    form.className = "session-form";
    const labelled = (key, ...controls) => {
      const label = document.createElement("label");
      const text = document.createElement("span");
      text.textContent = tr(key);
      label.append(text, ...controls);
      return label;
    };
    const select = (id, options, value) => {
      const el = document.createElement("select");
      el.id = prefix + "-" + id;
      el.replaceChildren(...options);
      el.value = value;
      return el;
    };

    const model = select("model", [option("", "model.default"),
      ...["2", "3", "4", "5", "dynamic"].map((m) => option(m, "model." + m))], o.model || "");
    const [minRows, minCols] = state.choices.min_dynamic;
    const [maxRows, maxCols] = state.choices.max_dynamic;
    const number = (id, min, max, value) => Object.assign(document.createElement("input"),
      { id: prefix + "-" + id, type: "number", min, max, value });
    const rows = number("rows", minRows, maxRows, o.rows || maxRows);
    const cols = number("cols", minCols, maxCols, o.cols || maxCols);
    const colsLabel = document.createElement("span");
    colsLabel.textContent = tr("settings.cols");
    const size = labelled("settings.rows", rows, colsLabel, cols);
    size.id = prefix + "-size";
    const codepage = select("codepage", [option("", "choice.default"),
      ...state.choices.codepages.map((c) => new Option(c.label, c.name))], o.codepage || "");
    form.append(labelled("settings.model", model), size, labelled("settings.codepage", codepage));

    // LU name: free unless the administrator restricted it; an empty list: not selectable.
    let lu = null;
    const allowed = Array.isArray(profile.lu_names) ? profile.lu_names : null;
    if (!allowed || allowed.length) {
      lu = Object.assign(document.createElement("input"), {
        id: prefix + "-lu", type: "text", maxLength: 8, value: o.lu_name || "",
        placeholder: tr("lu.placeholder"), autocomplete: "off", spellcheck: false,
      });
      const controls = [lu];
      if (allowed) {
        const list = document.createElement("datalist");
        list.id = prefix + "-lu-list";
        list.replaceChildren(...allowed.filter((n) => !n.endsWith("*")).map((n) => new Option(n)));
        lu.setAttribute("list", list.id);
        const hint = document.createElement("small");
        hint.className = "muted";
        hint.textContent = tr("lu.allowed", { list: allowed.join(", ") });
        controls.push(list, hint);
      }
      form.append(labelled("settings.lu", ...controls));
    }

    const toggleSize = () => { size.hidden = model.value !== "dynamic"; };
    form.addEventListener("change", () => {
      const options = {
        model: model.value || undefined,
        rows: model.value === "dynamic" ? Number(rows.value) : undefined,
        cols: model.value === "dynamic" ? Number(cols.value) : undefined,
        codepage: codepage.value || undefined,
        lu_name: lu && lu.value.trim() ? lu.value.trim().toUpperCase() : undefined,
      };
      store(SESSION_KEY + profile.id, JSON.stringify(options));
      toggleSize();
    });
    toggleSize();
    return form;
  }

  function saveDisplay() {
    state.display = {
      theme: $("set-theme").value,
      cursor: $("set-cursor").value,
      blink: $("set-blink").checked,
      crosshair: $("set-crosshair").checked,
      keybar: $("set-keybar").checked,
      blankFill: $("set-blank").value,
    };
    store(DISPLAY_KEY, JSON.stringify(state.display));
    applyDisplay();
    // Blank fill applies to the open sessions at once (an operator preference, as in x3270).
    if (state.display.blankFill) {
      const msg = JSON.stringify({ type: "blank_fill", on: state.display.blankFill === "on" });
      for (const tab of state.tabs) {
        if (tab.ws && tab.ws.readyState === WebSocket.OPEN && tab.connected) tab.ws.send(msg);
      }
    }
  }

  $("btn-settings").addEventListener("click", () => {
    renderSettings();
    $("settings").showModal();
  });
  for (const id of ["set-theme", "set-cursor", "set-blink", "set-crosshair", "set-keybar", "set-blank"]) {
    $(id).addEventListener("change", saveDisplay);
  }
  $("settings").addEventListener("close", () => { if (!$("terminal").hidden) canvas.focus(); });

  // Blinking cursor: redraw in phases (only while a screen is shown and blinking is on).
  setInterval(() => {
    if (!state.display.blink || !screen()) return;
    state.cursorOn = !state.cursorOn;
    render();
  }, 530);

  // ── Input ────────────────────────────────────────────────────────────────────
  /** Alt+1..9 and Alt+PageUp / Alt+PageDown switch tabs (Alt+PageUp is PCOMM's "next session"). */
  function switchTab(e) {
    if (!e.altKey || e.ctrlKey || e.metaKey || state.tabs.length < 2) return false;
    const i = state.tabs.indexOf(state.active);
    let target = null;
    if (/^[1-9]$/.test(e.key)) target = state.tabs[Number(e.key) - 1];
    else if (e.key === "PageUp") target = state.tabs[(i + 1) % state.tabs.length];
    else if (e.key === "PageDown") target = state.tabs[(i - 1 + state.tabs.length) % state.tabs.length];
    if (!target) return false;
    e.preventDefault();
    activate(target);
    return true;
  }

  // A Ctrl key pressed and released alone (PCOMM: Right Ctrl = Enter, Left Ctrl = Reset); any
  // other key in between makes it a modifier (Ctrl+C).
  let ctrlAlone = null;

  canvas.addEventListener("keyup", (e) => {
    if (e.key !== "Control" || !ctrlAlone || ctrlAlone !== e.code) return;
    ctrlAlone = null;
    const msg = ctrlTap(e.code, preset());
    if (msg) {
      send(msg);
      e.preventDefault();
    }
  });

  canvas.addEventListener("keydown", (e) => {
    if (e.key === "Control") {
      if (!e.repeat) ctrlAlone = e.code;
      return;
    }
    ctrlAlone = null;
    if (switchTab(e)) return;
    // Ctrl+P prints the screen (through `beforeprint`), not the page with its controls.
    if ((e.ctrlKey || e.metaKey) && !e.altKey && (e.key === "p" || e.key === "P")) {
      e.preventDefault();
      window.print();
      return;
    }
    // Ctrl + / Ctrl - / Ctrl 0 zoom the terminal, not the whole page.
    if ((e.ctrlKey || e.metaKey) && !e.altKey && ["+", "=", "-", "0"].includes(e.key)) {
      e.preventDefault();
      setZoom(e.key === "0" ? 0 : state.zoom + (e.key === "-" ? -1 : 1));
      return;
    }
    const msg = keyToMessage(e, preset());
    if (msg === BROWSER) return; // let copy / paste events fire
    if (state.selection && !["Shift", "Control", "Alt", "Meta"].includes(e.key)) {
      state.selection = null; // any real keystroke drops the selection
      render();
    }
    if (msg) {
      send(msg);
      e.preventDefault();
    }
  });

  // Clipboard events are listened for on the document, not the canvas: the canvas is not
  // editable, and for a non-editable focus the browser may fire them at the body instead (W3C
  // Clipboard API, "fire a clipboard event"; Firefox does). The focus check keeps other
  // elements' clipboard use (the login field) untouched.
  document.addEventListener("paste", (e) => {
    if (document.activeElement !== canvas) return;
    e.preventDefault();
    const text = (e.clipboardData && e.clipboardData.getData("text/plain")) || "";
    if (text) send({ type: "text", text });
  });

  document.addEventListener("copy", (e) => {
    const s = screen();
    if (document.activeElement !== canvas || !s) return;
    e.preventDefault();
    if (!s.copy_allowed) return message("msg.copy_disabled", {}, "warn");
    // Copies only text the server already sent (SafeScreenView): hidden fields are blank.
    e.clipboardData.setData("text/plain", selectionText(s, state.selection));
  });

  // ── Mouse: click moves the cursor, drag selects a rectangle ──────────────────
  /** Screen cell under the pointer, clamped to the screen so a drag may leave the canvas. */
  function cellAt(e) {
    const s = screen();
    return cellAtPoint(e.clientX, e.clientY, canvas.getBoundingClientRect(), state.cell, s.rows, s.cols);
  }

  canvas.addEventListener("pointerdown", (e) => {
    if (!screen() || e.button !== 0) return;
    e.preventDefault(); // no native text selection / drag image
    canvas.setPointerCapture(e.pointerId);
    state.anchor = cellAt(e);
    if (state.selection) {
      state.selection = null;
      render();
    }
    canvas.focus();
  });

  canvas.addEventListener("pointermove", (e) => {
    const a = state.anchor;
    if (!a || !screen()) return;
    const p = cellAt(e);
    if (!state.selection && p.row === a.row && p.col === a.col) return; // still a click
    state.selection = selectionFrom(a, p);
    render();
  });

  canvas.addEventListener("pointerup", (e) => {
    const a = state.anchor;
    state.anchor = null;
    if (!a || !screen()) return;
    if (canvas.hasPointerCapture(e.pointerId)) canvas.releasePointerCapture(e.pointerId);
    if (!state.selection) send({ type: "move_cursor", row: a.row, col: a.col }); // plain click
  });

  canvas.addEventListener("pointercancel", () => { state.anchor = null; });

  // Clickable 3270 key bar
  const KEYS = [
    ["Enter", { type: "aid", aid: "enter" }], ["Clear", { type: "aid", aid: "clear" }],
    ["Reset", { type: "action", action: "reset" }], ["PA1", { type: "aid", aid: "pa1" }],
    ["PA2", { type: "aid", aid: "pa2" }], ["PA3", { type: "aid", aid: "pa3" }],
    ["EraseEOF", { type: "action", action: "erase_eof" }],
    ["EraseInp", { type: "action", action: "erase_input" }],
    ["Attn", { type: "attention", key: "attn" }], ["SysReq", { type: "attention", key: "sysreq" }],
    ["Dup", { type: "action", action: "dup" }], ["FM", { type: "action", action: "field_mark" }],
  ];
  for (let i = 1; i <= 12; i++) KEYS.push(["PF" + i, { type: "aid", aid: "pf" + i }]);
  for (const [label, msg] of KEYS) {
    const b = document.createElement("button");
    b.type = "button";
    b.textContent = label;
    b.addEventListener("click", () => { send(msg); canvas.focus(); });
    $("keybar").appendChild(b);
  }

  // Disconnect: ends the active tab's session; the gateway confirms with `closed` (user).
  $("btn-disconnect").addEventListener("click", () => {
    const tab = state.active;
    if (!tab) return;
    stopReconnect(tab);
    tab.saved = null;
    persist();
    send({ type: "disconnect" });
  });

  // Log out: end every session and forget every credential of this tab, so the next person at
  // a shared workstation starts at the login screen.
  $("btn-logout").addEventListener("click", () => {
    clearMessage();
    for (const tab of [...state.tabs]) closeTab(tab, false);
    sessionStorage.removeItem(SESSIONS_KEY);
    sessionStorage.removeItem(ACTIVE_KEY);
    sessionStorage.removeItem(TOKEN_KEY);
    state.token = "";
    wipeScreen();
    $("token").value = "";
    show("login");
  });

  state.lang = pickLanguage(stored(LANG_KEY), navigator.languages);
  state.zoom = Number.parseInt(stored(ZOOM_KEY) || "0", 10) || 0;
  loadDisplay();
  langSelect.value = state.lang;
  applyLanguage();
  measure();
  applyDisplay();
  boot().catch(() => message("msg.unreachable", {}, "error"));
}
