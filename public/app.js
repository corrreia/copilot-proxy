const state = {
  dashboard: null,
  models: [],
  socket: null,
  socketGeneration: 0,
  reconnectDelay: 1000,
  pollTimer: null,
  toastTimer: null,
};

const $ = (id) => document.getElementById(id);

document.addEventListener("DOMContentLoaded", () => {
  bindActions();
  void loadDashboard();
});

function bindActions() {
  $("copy-endpoint").addEventListener("click", () => copyText($("endpoint").textContent, "Base URL copied"));
  $("connect-github").addEventListener("click", startGitHubFlow);
  $("copy-device-code").addEventListener("click", () => copyText($("device-code").textContent, "Device code copied"));
  $("disconnect-github").addEventListener("click", disconnectGitHub);
  $("settings-form").addEventListener("submit", saveSettings);
  $("refresh-models").addEventListener("click", () => void loadModels());
  $("new-key").addEventListener("click", () => {
    $("key-form").hidden = false;
    $("key-name").focus();
  });
  $("cancel-key").addEventListener("click", () => {
    $("key-form").hidden = true;
    $("key-form").reset();
    $("new-key").focus();
  });
  $("key-form").addEventListener("submit", createKey);
  $("copy-secret").addEventListener("click", () => copyText($("new-secret").value, "Private key copied"));
  $("close-dialog").addEventListener("click", closeKeyDialog);
  $("key-dialog").addEventListener("close", () => { $("new-secret").value = ""; });
}

async function loadDashboard() {
  try {
    const data = await api("/api/dashboard");
    state.dashboard = data;
    $("user-email").textContent = data.user.email;
    $("endpoint").textContent = data.endpoint;
    $("account-type").value = data.settings.accountType;
    renderGitHub(data.github);
    renderKeys(data.keys);
    renderMetrics(data.metrics);
    void connectEvents();
    if (data.github.connected) {
      void loadUsage();
      void loadModels();
    } else {
      renderModels([]);
    }
  } catch (error) {
    showPageError(messageOf(error));
  }
}

function renderGitHub(github) {
  $("github-stat").textContent = github.connected ? `@${github.login}` : "Required";
  $("github-badge").textContent = github.connected ? "Connected" : "Not connected";
  $("github-badge").classList.toggle("connected", github.connected);
  $("github-disconnected").hidden = github.connected;
  $("github-connected").hidden = !github.connected;
  $("github-device").hidden = true;
  $("github-login").textContent = github.login || "";
  $("new-key").disabled = !github.connected;
  $("refresh-models").disabled = !github.connected;
}

async function startGitHubFlow() {
  const button = $("connect-github");
  setBusy(button, true, "Starting…");
  try {
    const flow = await api("/api/github/device", { method: "POST" });
    $("github-disconnected").hidden = true;
    $("github-device").hidden = false;
    $("device-code").textContent = flow.userCode;
    $("open-github").href = flow.verificationUri;
    $("device-status").textContent = "Waiting for authorization…";
    scheduleDevicePoll(flow.sessionId, flow.interval);
  } catch (error) {
    showToast(messageOf(error));
  } finally {
    setBusy(button, false, "Connect GitHub");
  }
}

function scheduleDevicePoll(sessionId, seconds) {
  clearTimeout(state.pollTimer);
  state.pollTimer = setTimeout(() => void pollGitHub(sessionId), Math.max(seconds, 1) * 1000);
}

async function pollGitHub(sessionId) {
  try {
    const result = await api("/api/github/device/poll", {
      method: "POST",
      body: JSON.stringify({ sessionId }),
    });
    if (result.state === "complete") {
      $("device-status").textContent = "Connected.";
      const github = { connected: true, login: result.login };
      state.dashboard.github = github;
      renderGitHub(github);
      showToast(`Connected as @${result.login}`);
      void loadUsage();
      void loadModels();
      return;
    }
    scheduleDevicePoll(sessionId, result.retryAfter || 5);
  } catch (error) {
    if (error.status === 429) {
      scheduleDevicePoll(sessionId, error.retryAfter || 5);
      return;
    }
    $("device-status").textContent = messageOf(error);
    showToast(messageOf(error));
  }
}

async function loadUsage() {
  const target = $("quota-summary");
  target.textContent = "Loading Copilot usage…";
  try {
    const { usage } = await api("/api/usage");
    const pieces = [];
    if (usage && usage.copilot_plan) pieces.push(`Plan: ${usage.copilot_plan}`);
    if (usage && usage.quota_reset_date) pieces.push(`Resets ${formatDate(usage.quota_reset_date)}`);
    if (usage && usage.quota_snapshots) {
      for (const [name, quota] of Object.entries(usage.quota_snapshots)) {
        const label = name.replaceAll("_", " ");
        pieces.push(quota.unlimited ? `${label}: unlimited` : `${label}: ${Math.round(quota.percent_remaining || 0)}% remaining`);
      }
    }
    target.textContent = pieces.length ? pieces.join(" · ") : "Copilot is connected. Usage details are unavailable for this plan.";
  } catch (error) {
    target.textContent = messageOf(error);
  }
}

async function loadModels() {
  const target = $("models-loading");
  const button = $("refresh-models");
  target.hidden = false;
  target.textContent = "Loading available GitHub Copilot models…";
  $("models-table-wrap").hidden = true;
  setBusy(button, true, "Refreshing…");
  try {
    const result = await api("/api/models");
    state.models = Array.isArray(result.data) ? result.data : [];
    renderModels(state.models);
  } catch (error) {
    state.models = [];
    renderModels([]);
    target.hidden = false;
    target.textContent = messageOf(error);
  } finally {
    setBusy(button, false, "Refresh models");
  }
}

function renderModels(models) {
  const sorted = [...models].sort((left, right) => {
    const providerOrder = String(left.vendor || left.owned_by || "").localeCompare(String(right.vendor || right.owned_by || ""));
    return providerOrder || String(left.id || "").localeCompare(String(right.id || ""));
  });
  $("models-count").textContent = sorted.length ? `(${sorted.length})` : "";
  $("models-loading").hidden = sorted.length > 0;
  $("models-table-wrap").hidden = sorted.length === 0;
  const body = $("models-body");
  body.replaceChildren();
  for (const model of sorted) {
    const row = document.createElement("tr");
    row.append(
      codeCell(model.id || "—"),
      cell(model.name || model.id || "—"),
      cell(model.vendor || model.owned_by || "—"),
      modelEndpointsCell(model.supported_endpoints),
      cell(formatTokenLimit(model.capabilities?.limits?.max_context_window_tokens), "tabular"),
    );
    const actions = document.createElement("td");
    actions.className = "model-actions";
    const copyId = modelAction("Copy ID", `Copy model ID ${model.id || ""}`, () => {
      void copyText(model.id || "", "Model ID copied");
    });
    const copySetup = modelAction("Copy setup", `Copy setup for ${model.id || "model"}`, () => {
      const snippet = [
        `OPENAI_BASE_URL=${state.dashboard.endpoint}`,
        "OPENAI_API_KEY=cpp_REPLACE_ME",
        `OPENAI_MODEL=${model.id || ""}`,
      ].join("\n");
      void copyText(snippet, "Model setup copied");
    });
    actions.append(copyId, copySetup);
    row.append(actions);
    body.append(row);
  }
}

function modelEndpointsCell(endpoints) {
  const element = document.createElement("td");
  const list = document.createElement("div");
  list.className = "endpoint-list";
  const values = Array.isArray(endpoints) && endpoints.length ? endpoints : ["—"];
  for (const endpoint of values) {
    const tag = document.createElement("span");
    tag.className = "endpoint-tag";
    tag.textContent = String(endpoint);
    list.append(tag);
  }
  element.append(list);
  return element;
}

function modelAction(label, accessibleLabel, action) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "model-action";
  button.textContent = label;
  button.setAttribute("aria-label", accessibleLabel);
  button.addEventListener("click", action);
  return button;
}

function formatTokenLimit(value) {
  return Number.isFinite(value) && value > 0 ? formatNumber(value) : "—";
}

async function disconnectGitHub() {
  if (!window.confirm("Disconnect GitHub? Existing API keys will stop working until you connect again.")) return;
  try {
    await api("/api/github", { method: "DELETE" });
    state.dashboard.github = { connected: false, login: null };
    state.models = [];
    renderGitHub(state.dashboard.github);
    renderModels([]);
    showToast("GitHub disconnected");
  } catch (error) {
    showToast(messageOf(error));
  }
}

async function saveSettings(event) {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"]');
  setBusy(button, true, "Saving…");
  try {
    await api("/api/settings", {
      method: "PUT",
      body: JSON.stringify({ accountType: $("account-type").value }),
    });
    showToast("Account type saved");
  } catch (error) {
    showToast(messageOf(error));
  } finally {
    setBusy(button, false, "Save account type");
  }
}

async function createKey(event) {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button[type="submit"]');
  setBusy(button, true, "Generating…");
  try {
    const created = await api("/api/keys", {
      method: "POST",
      body: JSON.stringify({ name: $("key-name").value }),
    });
    state.dashboard.keys.unshift({
      id: created.id,
      name: created.name,
      prefix: created.prefix,
      createdAt: new Date().toISOString(),
      lastUsedAt: null,
    });
    renderKeys(state.dashboard.keys);
    $("key-form").reset();
    $("key-form").hidden = true;
    $("new-secret").value = created.secret;
    $("key-dialog").showModal();
    $("copy-secret").focus();
  } catch (error) {
    showToast(messageOf(error));
  } finally {
    setBusy(button, false, "Generate key");
  }
}

function closeKeyDialog() {
  $("key-dialog").close();
  $("new-key").focus();
}

function renderKeys(keys) {
  $("active-keys").textContent = String(keys.length);
  $("keys-empty").hidden = keys.length > 0;
  $("keys-table-wrap").hidden = keys.length === 0;
  const body = $("keys-body");
  body.replaceChildren();
  for (const key of keys) {
    const row = document.createElement("tr");
    row.append(cell(key.name), codeCell(key.prefix), cell(formatDate(key.createdAt)), cell(key.lastUsedAt ? formatDate(key.lastUsedAt) : "Never"));
    const actionCell = document.createElement("td");
    const revoke = document.createElement("button");
    revoke.type = "button";
    revoke.className = "table-action";
    revoke.textContent = "Revoke";
    revoke.setAttribute("aria-label", `Revoke ${key.name}`);
    revoke.addEventListener("click", () => revokeKey(key, revoke));
    actionCell.append(revoke);
    row.append(actionCell);
    body.append(row);
  }
}

async function revokeKey(key, button) {
  if (!window.confirm(`Revoke “${key.name}”? Clients using it will immediately lose access.`)) return;
  setBusy(button, true, "Revoking…");
  try {
    await api(`/api/keys/${encodeURIComponent(key.id)}`, { method: "DELETE" });
    state.dashboard.keys = state.dashboard.keys.filter((candidate) => candidate.id !== key.id);
    renderKeys(state.dashboard.keys);
    showToast("API key revoked");
  } catch (error) {
    setBusy(button, false, "Revoke");
    showToast(messageOf(error));
  }
}

function renderMetrics(metrics) {
  $("total-requests").textContent = formatNumber(metrics.totalRequests);
  $("successful-requests").textContent = formatNumber(metrics.successfulRequests);
  renderActivity(metrics.recent);
}

function renderActivity(recent) {
  $("activity-empty").hidden = recent.length > 0;
  $("activity-table-wrap").hidden = recent.length === 0;
  const body = $("activity-body");
  body.replaceChildren();
  for (const metric of recent.slice(0, 30)) body.append(metricRow(metric));
}

function metricRow(metric) {
  const row = document.createElement("tr");
  row.append(cell(formatDate(metric.createdAt)), codeCell(metric.endpoint), codeCell(metric.model || "—"));
  const statusCell = document.createElement("td");
  const status = document.createElement("span");
  status.className = `status-code${metric.status >= 200 && metric.status < 300 ? "" : " error"}`;
  status.textContent = String(metric.status);
  statusCell.append(status);
  row.append(statusCell, cell(`${formatNumber(metric.latencyMs)} ms`, "tabular"));
  return row;
}

async function connectEvents() {
  const generation = ++state.socketGeneration;
  const previous = state.socket;
  state.socket = null;
  previous?.close();
  setLiveState("connecting", "Connecting");

  let ticket;
  try {
    ticket = await api("/api/socket-ticket", { method: "POST" });
  } catch {
    scheduleEventReconnect(generation);
    return;
  }
  if (generation !== state.socketGeneration) return;

  const transport = location.protocol === "https:" ? "wss:" : "ws:";
  const socketProtocol = `copilot-dashboard.${ticket.token}`;
  const socket = new WebSocket(`${transport}//${location.host}/v1/dashboard/events`, socketProtocol);
  state.socket = socket;
  socket.addEventListener("open", () => {
    state.reconnectDelay = 1000;
    setLiveState("live", "Live");
  });
  socket.addEventListener("message", (event) => {
    if (event.data === "pong") return;
    try {
      const message = JSON.parse(event.data);
      if (message.type === "request") receiveMetric(message.metric);
    } catch {
      // Ignore unknown event envelopes so future server versions remain compatible.
    }
  });
  socket.addEventListener("close", () => {
    if (state.socket !== socket) return;
    state.socket = null;
    scheduleEventReconnect(generation);
  });
  socket.addEventListener("error", () => socket.close());
}

function scheduleEventReconnect(generation) {
  if (generation !== state.socketGeneration) return;
  setLiveState("offline", "Reconnecting");
  const delay = state.reconnectDelay;
  state.reconnectDelay = Math.min(state.reconnectDelay * 2, 30000);
  setTimeout(() => void connectEvents(), delay);
}

function receiveMetric(metric) {
  const metrics = state.dashboard.metrics;
  metrics.totalRequests += 1;
  if (metric.status >= 200 && metric.status < 300) metrics.successfulRequests += 1;
  metrics.recent.unshift(metric);
  metrics.recent = metrics.recent.slice(0, 30);
  renderMetrics(metrics);
}

function setLiveState(kind, label) {
  $("live-dot").className = `presence-dot ${kind === "connecting" ? "" : kind}`;
  $("live-label").textContent = label;
}

function cell(value, className = "") {
  const element = document.createElement("td");
  element.textContent = value;
  if (className) element.className = className;
  return element;
}

function codeCell(value) {
  const element = document.createElement("td");
  const code = document.createElement("code");
  code.textContent = value;
  element.append(code);
  return element;
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.body) headers.set("Content-Type", "application/json");
  const response = await fetch(path, { ...options, headers });
  if (response.status === 204) return null;
  let body;
  try { body = await response.json(); } catch { body = {}; }
  if (!response.ok) {
    const error = new Error(body.error || `Request failed (${response.status})`);
    error.status = response.status;
    error.retryAfter = Number(response.headers.get("retry-after") || body.retryAfter || 0);
    throw error;
  }
  return body;
}

async function copyText(value, successMessage) {
  try {
    await navigator.clipboard.writeText(value);
    showToast(successMessage);
  } catch {
    showToast("Copy failed. Select and copy the value manually.");
  }
}

function setBusy(button, busy, label) {
  button.disabled = busy;
  button.textContent = label;
}

function showPageError(message) {
  $("page-error").hidden = false;
  $("page-error").textContent = message;
}

function showToast(message) {
  clearTimeout(state.toastTimer);
  const toast = $("toast");
  toast.textContent = message;
  toast.classList.add("visible");
  state.toastTimer = setTimeout(() => toast.classList.remove("visible"), 4500);
}

function formatDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return "—";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function formatNumber(value) {
  return new Intl.NumberFormat().format(value || 0);
}

function messageOf(error) {
  return error instanceof Error ? error.message : "Something went wrong";
}
