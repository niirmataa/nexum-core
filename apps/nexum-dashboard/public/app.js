"use strict";

const $ = (id) => document.getElementById(id);

// --- System: zywy podgląd all-in-one (dane operacyjne, nie escrow). ---

function systemItem(label, value, state) {
  const item = document.createElement("li");
  const name = document.createElement("span");
  name.className = "system-label";
  name.textContent = label;
  const badge = document.createElement("span");
  badge.className = "system-badge";
  badge.dataset.state = state || "unknown";
  badge.textContent = value;
  item.append(name, badge);
  return item;
}

function fillSystemList(id, items) {
  const list = $(id);
  list.replaceChildren(...items);
}

function renderSystem(result) {
  fillSystemList("system-services", (result.services || []).map((service) =>
    systemItem(service.label, service.state, service.state === "active" ? "ok" : "bad")));
  const mailbox = result.mailbox || {};
  const onion = mailbox.onion || {};
  fillSystemList("system-tor", [
    systemItem("mailbox · lokalnie", mailbox.local ? "OK" : "brak", mailbox.local ? "ok" : "bad"),
    systemItem(`mailbox · onion`, onion.ok ? "odpowiada" : "nie odpowiada", onion.ok ? "ok" : "bad"),
  ]);
  const trust = result.trust || {};
  fillSystemList("system-trust", [
    systemItem("epoch", trust.epoch || "nieznany", "info"),
    systemItem("quorum", (trust.signers || []).join(" + ") || "brak", (trust.signatures === 2) ? "ok" : "bad"),
  ]);
  const monero = result.monero || {};
  fillSystemList("system-monero", [
    systemItem("wysokość łańcucha", String(monero.height ?? "?"), monero.synchronized ? "ok" : "info"),
    systemItem("synchronizacja", monero.synchronized ? "tak" : "nie", monero.synchronized ? "ok" : "bad"),
    systemItem("pary wychodzące", String(monero.outgoing ?? 0), (monero.outgoing ?? 0) > 0 ? "ok" : "info"),
    systemItem("sieć", monero.nettype || "?", "info"),
  ]);
  const agents = result.agents || {};
  fillSystemList("system-agents", Object.entries(agents).map(([name, agent]) =>
    systemItem(name,
      agent.started ? `aktywny · retry pull: ${agent.pull_failures}` : "nie wystartował",
      agent.started ? "ok" : "bad")));
}

function pomiaryLink(target) {
  const link = document.createElement("a");
  link.className = "system-label";
  link.href = `http://127.0.0.1:3000/d/nxms-overview?var-lab=${encodeURIComponent(target)}&from=now-3h&to=now`;
  link.target = "_blank";
  link.rel = "noreferrer";
  link.textContent = "pomiary";
  return link;
}

function renderLab(result) {
  const instances = result.instances || [];
  const stateMap = {
    confirmed: "ok", confirming: "info", funded: "info",
    ready: "info", created: "unknown", failed: "bad",
  };
  const items = instances.length
    ? instances.map((inst) => {
        const address = (inst.address || "").slice(0, 10);
        const detail = inst.state === "confirmed"
          ? `potwierdzone · ${inst.confirmations ?? 0} bloków`
          : inst.state === "confirming"
            ? `potwierdzenia: ${inst.confirmations ?? 0}`
            : inst.tx_hash
              ? `${inst.state} · tx ${inst.tx_hash.slice(0, 8)}`
              : `${inst.state || "?"}`;
        const item = systemItem(`${inst.id} · ${address}…`, detail, stateMap[inst.state] || "unknown");
        item.append(pomiaryLink(inst.id));
        return item;
      })
    : [systemItem("instancje", "brak — bash tools/l.sh up", "info")];
  fillSystemList("system-lab", items);
}

function renderTasks(result) {
  const instances = result.instances || [];
  const stateMap = {
    done: "ok", running: "ok", queued: "info",
    degraded: "info", failed: "bad", stopped: "unknown",
  };
  const items = instances.length
    ? instances.flatMap((inst) => {
        const roles = (inst.roles || []).filter((role) => role && typeof role === "object");
        const active = roles.filter((role) => role.state === "active").length;
        const kind = inst.kind === "multisig" ? "ceremonia multisig" : "all-in-one";
        const state = inst.state || "?";
        const step = inst.step ? ` · krok: ${inst.step}` : "";
        const details = roles.filter((role) => role.detail)
          .map((role) => `${role.name || "?"}: ${role.detail}`).join(" · ");
        return [
          (() => {
            const row = systemItem(`${inst.id || "?"} · ${kind}`, `${state}${step}`, stateMap[inst.state] || "unknown");
            row.append(pomiaryLink(inst.container || inst.id || ""));
            return row;
          })(),
          systemItem(`${inst.id || "?"} · role`,
            `${active}/${roles.length} aktywnych${details ? ` · ${details}` : ""}`,
            roles.length > 0 && active === roles.length ? "ok" : "info"),
        ];
      })
    : [systemItem("instancje", "brak — bash tools/nxms-stack.sh up", "info")];
  fillSystemList("system-tasks", items);
}

async function refreshSystem() {
  try {
    const response = await fetch("/api/system/status", { credentials: "same-origin", cache: "no-store" });
    renderSystem(await response.json());
  } catch (_error) {
    /* panel System nie przerywa przeplywu demo */
  }
  try {
    const response = await fetch("/api/lab/status", { credentials: "same-origin", cache: "no-store" });
    renderLab(await response.json());
  } catch (_error) {
    /* panel Lab nie przerywa przeplywu demo */
  }
  try {
    const response = await fetch("/api/tasks/status", { credentials: "same-origin", cache: "no-store" });
    renderTasks(await response.json());
  } catch (_error) {
    /* panel Zadan nie przerywa przeplywu demo */
  }
}

refreshSystem();
setInterval(refreshSystem, 10000);

const state = { csrf: "", phase: "connect", escrows: [], selected: null, challenge: null,
  offline: false, connected: false, busy: false, polling: false, timer: null,
  generation: 0, pendingRefresh: false, backendDown: false };
const steps = ["connect", "select", "challenge", "view"];
let demoPassword = "";

function notice(message, kind = "success") {
  $("notice").textContent = message;
  $("notice").dataset.state = kind;
}

async function api(path, body) {
  const options = { credentials: "same-origin", cache: "no-store", headers: {} };
  if (body !== undefined) {
    options.method = "POST";
    options.headers = { "Content-Type": "application/json", "X-Nexum-CSRF": state.csrf };
    options.body = JSON.stringify(body);
  }
  let response;
  try {
    response = await fetch(path, options);
  } catch (_error) {
    state.backendDown = true;
    controls();
    const error = new Error("Lokalny serwer demonstracyjny jest niedostępny. Ostatnie dane mogą być nieaktualne.");
    error.code = "BACKEND_DOWN";
    throw error;
  }
  state.backendDown = false;
  const result = await response.json();
  if (!response.ok) {
    const error = new Error(result.message || "Nie udało się wykonać operacji demonstracyjnej.");
    error.code = result.error;
    throw error;
  }
  return result;
}

function controls() {
  const challengeReady = Boolean(state.challenge && Date.now() < state.challenge.expires_unix * 1000);
  document.querySelectorAll("button").forEach((button) => { button.disabled = state.busy; });
  $("select-button").disabled = state.busy || !state.selected || state.offline;
  $("confirm-button").disabled = state.busy || state.offline || !challengeReady;
  $("expire-challenge").disabled = state.busy || state.phase !== "challenge" || !state.challenge;
  $("expire-access").disabled = state.busy || state.phase !== "view";
  $("simulate-online").disabled = state.busy || !state.offline;
  $("simulate-offline").disabled = state.busy || state.offline || !state.connected;
  $("vault-password").disabled = state.busy || !challengeReady;
  $("fill-demo-password").disabled = state.busy || !challengeReady;
  document.querySelectorAll("input[name='escrow']").forEach((input) => { input.disabled = state.busy; });
  $("renew-challenge").disabled = state.busy || state.offline;
  $("renew-challenge").hidden = Boolean(state.challenge && Date.now() < state.challenge.expires_unix * 1000);
  $("connection-status").textContent = state.backendDown ? "Serwer lokalny · niedostępny" : !state.connected ? "Tor demo · oczekiwanie" :
    state.offline ? "Tor demo · offline" : "Tor demo · połączono";
  $("connection-status").dataset.state = state.backendDown ? "error" : state.offline ? "offline" : state.connected ? "success" : "pending";
}

function showStep(phase) {
  state.phase = phase;
  clearTimeout(state.timer);
  state.timer = null;
  steps.forEach((step) => { $("step-" + step).hidden = step !== phase; });
  document.querySelectorAll("[data-step]").forEach((item) => {
    const index = steps.indexOf(item.dataset.step);
    item.classList.toggle("active", item.dataset.step === phase);
    item.classList.toggle("complete", index < steps.indexOf(phase));
    if (item.dataset.step === phase) item.setAttribute("aria-current", "step");
    else item.removeAttribute("aria-current");
  });
  controls();
}

async function action(work) {
  if (state.busy) return;
  state.generation += 1;
  clearTimeout(state.timer);
  state.timer = null;
  state.busy = true;
  controls();
  try { await work(); }
  catch (error) {
    if (["TOO_MANY_ATTEMPTS", "CHALLENGE_USED", "CHALLENGE_MISMATCH", "CHALLENGE_EXPIRED"].includes(error.code)) {
      state.challenge = null;
      showStep("challenge");
      renderChallenge();
    }
    notice(error.message || "Lokalny serwer jest niedostępny.", "error");
  }
  finally {
    state.busy = false;
    controls();
    if (state.phase === "view" && !state.polling && !state.timer) state.timer = setTimeout(refreshStatus, 10000);
  }
}

function renderEscrows() {
  const list = $("escrow-list");
  list.replaceChildren();
  state.escrows.forEach((escrow) => {
    const label = document.createElement("label");
    label.className = "escrow-option";
    const input = document.createElement("input");
    input.type = "radio";
    input.name = "escrow";
    input.value = escrow.id;
    input.checked = state.selected === escrow.id;
    const detail = document.createElement("span");
    const title = document.createElement("strong");
    title.textContent = escrow.id;
    const subtitle = document.createElement("span");
    subtitle.textContent = `${escrow.title} · ${escrow.role}`;
    detail.append(title, subtitle);
    const amount = document.createElement("strong");
    amount.textContent = escrow.amount;
    label.append(input, detail, amount);
    input.addEventListener("change", () => { state.selected = escrow.id; controls(); });
    list.append(label);
  });
}

function renderChallenge() {
  const challenge = state.challenge;
  $("challenge-id").textContent = challenge?.id || "Pobierz nowe challenge";
  $("challenge-service").textContent = challenge?.service || "Usługa demonstracyjna";
  $("challenge-escrow").textContent = challenge?.escrow_id || state.selected || "—";
  $("challenge-scope").textContent = "Wyłącznie podgląd escrow";
  $("vault-password").value = "";
  tick();
}

function tick() {
  if (state.challenge) {
    const seconds = Math.max(0, Math.ceil(state.challenge.expires_unix - Date.now() / 1000));
    $("challenge-expires").textContent = seconds ? `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}` : "Wygasło";
    $("challenge-expires").dataset.state = seconds ? "pending" : "error";
  } else $("challenge-expires").textContent = "—";
  controls();
}

async function prepareChallenge() {
  const result = await api("/api/demo/challenge/prepare", {});
  state.challenge = result.challenge;
  showStep("challenge");
  renderChallenge();
  notice("Nowe challenge jest gotowe. Sprawdź jego cel i użyj wyłącznie hasła demonstracyjnego.", "pending");
}

function dateLabel(value) {
  return new Intl.DateTimeFormat("pl-PL", { dateStyle: "short", timeStyle: "medium" }).format(new Date(value));
}

function renderSnapshot(result) {
  const snapshot = result.snapshot;
  state.offline = result.offline;
  $("escrow-id").textContent = snapshot.id;
  $("escrow-amount").textContent = snapshot.amount;
  $("escrow-stage").textContent = snapshot.stage;
  $("escrow-address").textContent = snapshot.address;
  $("escrow-confirmations").textContent = `${snapshot.confirmations} / ${snapshot.required_confirmations}`;
  $("updated-at").textContent = dateLabel(snapshot.observed_at);
  $("updated-at").setAttribute("datetime", snapshot.observed_at);
  $("history").replaceChildren();
  snapshot.history.forEach((event) => {
    const row = document.createElement("li");
    const time = document.createElement("time");
    time.dateTime = event.at;
    time.textContent = dateLabel(event.at);
    const title = document.createElement("strong");
    title.textContent = event.title;
    const description = document.createElement("p");
    description.textContent = event.description;
    row.append(time, title, description);
    $("history").append(row);
  });
  notice(result.fresh ? "Podgląd demonstracyjny aktywny. Nie wykonano prawdziwego podpisu ani transakcji." :
    "Symulacja utraty Tora. Pokazujemy ostatnie dane — nie są aktualizowane.", result.fresh ? "success" : "offline");
  controls();
}

async function refreshStatus() {
  if (state.phase !== "view") return;
  if (state.polling) { state.pendingRefresh = true; return; }
  const generation = state.generation;
  state.polling = true;
  clearTimeout(state.timer);
  state.timer = null;
  try {
    const result = await api("/api/demo/status");
    if (generation === state.generation && state.phase === "view") renderSnapshot(result);
  } catch (error) {
    if (generation !== state.generation || state.phase !== "view") return;
    if (error.code === "ACCESS_EXPIRED") {
      state.challenge = null;
      showStep("challenge");
      renderChallenge();
    }
    notice(error.message || "Serwer lokalny jest niedostępny. Ostatni widok może być nieaktualny.", "error");
  } finally {
    state.polling = false;
    if (state.phase === "view" && state.pendingRefresh) {
      state.pendingRefresh = false;
      state.timer = setTimeout(refreshStatus, 0);
    } else if (state.phase === "view") state.timer = setTimeout(() => {
      if (!state.busy) refreshStatus();
      else state.timer = setTimeout(refreshStatus, 1000);
    }, state.offline ? 30000 : 10000);
  }
}

const renew = document.createElement("button");
renew.id = "renew-challenge";
renew.type = "button";
renew.className = "button secondary";
renew.textContent = "Pobierz nowe challenge";
renew.hidden = true;
$("challenge-form").append(renew);
renew.addEventListener("click", () => action(prepareChallenge));

$("connect-button").addEventListener("click", () => action(async () => {
  await api("/api/demo/connect", {});
  state.connected = true;
  state.offline = false;
  showStep("select");
  notice("Połączenie jest symulowane. Wybierz escrow z danych demonstracyjnych.");
}));

$("select-button").addEventListener("click", () => action(async () => {
  await api("/api/demo/select", { escrow_id: state.selected });
  await prepareChallenge();
  notice("Sprawdź cel wyzwania. Użyj wyłącznie hasła demonstracyjnego.", "pending");
}));

$("fill-demo-password").addEventListener("click", () => {
  $("vault-password").value = demoPassword;
  $("vault-password").focus();
});

$("challenge-form").addEventListener("submit", (event) => {
  event.preventDefault();
  action(async () => {
    const password = $("vault-password").value;
    $("vault-password").value = "";
    await api("/api/demo/challenge/confirm", { challenge_id: state.challenge?.id, password });
    showStep("view");
    await refreshStatus();
  });
});

async function lock() {
  await api("/api/demo/lock", {});
  state.challenge = null;
  $("vault-password").value = "";
  $("history").replaceChildren();
  showStep("select");
  notice("Podgląd zablokowany. Nowy dostęp wymaga ponownego zatwierdzenia challenge.", "pending");
}
$("cancel-button").addEventListener("click", () => action(lock));
$("lock-button").addEventListener("click", () => action(lock));
$("refresh-button").addEventListener("click", () => action(refreshStatus));

const scenarios = { "simulate-offline": "offline", "simulate-online": "online",
  "expire-challenge": "expire_challenge", "expire-access": "expire_access" };
for (const [id, scenario] of Object.entries(scenarios)) {
  $(id).addEventListener("click", () => action(async () => {
    const result = await api("/api/demo/scenario", { scenario });
    state.offline = result.offline;
    if (state.phase === "challenge") {
      state.challenge = result.challenge;
      renderChallenge();
    }
    if (state.phase === "view") {
      notice(state.offline ? "Symulacja utraty Tora. Pokazujemy ostatnie dane — nie są aktualizowane." :
        "Symulowane połączenie przywrócone. Odświeżamy podgląd.", state.offline ? "offline" : "pending");
      await refreshStatus();
    }
    else notice(state.offline ? "Symulacja: Tor offline. Możesz przywrócić połączenie." :
      scenario === "expire_challenge" ? "Symulacja: challenge wygasło. Pobierz nowe." : "Symulowane połączenie przywrócone.",
      state.offline || scenario === "expire_challenge" ? "offline" : "success");
  }));
}

async function start() {
  try {
    const result = await api("/api/demo/bootstrap");
    Object.assign(state, { csrf: result.csrf, connected: result.connected, offline: result.offline,
      escrows: result.escrows, selected: result.selected, challenge: result.challenge });
    demoPassword = result.demo_password;
    renderEscrows();
    showStep(result.phase);
    if (result.phase === "challenge") renderChallenge();
    if (result.phase === "view") await refreshStatus();
    else notice("Tryb demonstracyjny. Nie wpisuj prawdziwego hasła ani danych portfela.", "pending");
    setInterval(tick, 1000);
  } catch (error) {
    notice(error.message || "Nie można połączyć się z lokalnym serwerem demonstracyjnym.", "error");
  }
}
start();
