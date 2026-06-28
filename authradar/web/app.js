/* AuthRadar web console — application logic (no build step, no dependencies). */
"use strict";

const KEY_STORAGE = "authradar_api_key";
const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const SEV_COLOR = {
  critical: "#ff5470", high: "#ff8a4c", medium: "#ffd24c", low: "#4cc2ff", info: "#94a3b8",
};
const ACRONYMS = { jwt: "JWT", otp: "OTP", csrf: "CSRF", mfa: "MFA", oauth: "OAuth" };

const state = {
  apiKey: localStorage.getItem(KEY_STORAGE) || "",
  scanners: [],
  job: null,
  result: null,
  poll: null,
  ticker: null,
  startedAt: 0,
  filters: { severity: "all", q: "" },
};

/* ---------------- DOM helpers (XSS-safe) ---------------- */
function el(tag, attrs, children) {
  const node = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === null || v === undefined || v === false) continue;
      if (k === "class") node.className = v;
      else if (k === "text") node.textContent = v;
      else if (k === "html") node.innerHTML = v; // only ever called with trusted constants
      else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v === true ? "" : String(v));
    }
  }
  for (const child of [].concat(children || [])) {
    if (child === null || child === undefined || child === false) continue;
    node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return node;
}
const $ = (sel) => document.querySelector(sel);
function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
function prettyCat(c) {
  return String(c).split("_").map((w) => ACRONYMS[w] || (w.charAt(0).toUpperCase() + w.slice(1))).join(" ");
}

/* ---------------- Toasts ---------------- */
function toast(message, kind = "info", ms = 4200) {
  const t = el("div", { class: `toast ${kind}`, text: message });
  $("#toasts").appendChild(t);
  setTimeout(() => { t.style.opacity = "0"; setTimeout(() => t.remove(), 250); }, ms);
}

/* ---------------- API client ---------------- */
async function api(path, { method = "GET", body, keyed = false } = {}) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (keyed && state.apiKey) headers["X-API-Key"] = state.apiKey;
  const resp = await fetch(path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
  return resp;
}
async function errMessage(resp) {
  try {
    const d = await resp.json();
    if (typeof d.detail === "string") return d.detail;
    if (Array.isArray(d.detail)) {
      return d.detail.map((e) => `${(e.loc || []).slice(1).join(".")}: ${e.msg}`).join("; ");
    }
    return `${resp.status} ${resp.statusText}`;
  } catch { return `${resp.status} ${resp.statusText}`; }
}

/* ---------------- Health & scanners ---------------- */
async function loadHealth() {
  const pill = $("#health"); const text = $("#healthText");
  try {
    const resp = await api("/health");
    const data = await resp.json();
    pill.className = "pill pill-ok";
    text.textContent = `online · v${data.version}`;
    $("#footVersion").textContent = `v${data.version}`;
  } catch {
    pill.className = "pill pill-bad";
    text.textContent = "offline";
  }
}

async function loadScanners() {
  const list = $("#scannerList");
  try {
    const resp = await api("/scanners");
    state.scanners = await resp.json();
  } catch {
    clear(list); list.appendChild(el("p", { class: "muted", text: "Could not load scanners." }));
    return;
  }
  $("#scannerCount").textContent = `(${state.scanners.length})`;
  clear(list);
  for (const s of state.scanners) {
    const cb = el("input", { type: "checkbox", checked: true, "data-id": s.id });
    list.appendChild(el("label", { class: "scanner-row" }, [
      cb,
      el("span", {}, [
        el("span", { class: "s-name", text: s.name }),
        el("span", { class: "scanner-cat", text: prettyCat(s.category) }),
        el("span", { class: "s-meta", text: s.description || s.id }),
      ]),
    ]));
  }
}

/* ---------------- API key modal ---------------- */
function refreshKeyState() {
  const on = Boolean(state.apiKey);
  $("#keyState").className = `key-state ${on ? "key-state-on" : "key-state-off"}`;
  $("#keyBtn").title = on ? "API key is set" : "No API key set — scanning is disabled";
}
function openKeyModal() { $("#keyInput").value = state.apiKey; $("#keyModal").hidden = false; $("#keyInput").focus(); }
function closeKeyModal() { $("#keyModal").hidden = true; }
function saveKey() {
  state.apiKey = $("#keyInput").value.trim();
  if (state.apiKey) localStorage.setItem(KEY_STORAGE, state.apiKey);
  else localStorage.removeItem(KEY_STORAGE);
  refreshKeyState(); updateSubmitState(); closeKeyModal();
  toast(state.apiKey ? "API key saved." : "API key cleared.", "success");
}
function clearKey() { $("#keyInput").value = ""; state.apiKey = ""; localStorage.removeItem(KEY_STORAGE); refreshKeyState(); updateSubmitState(); }

/* ---------------- Config building ---------------- */
function numOr(id, fallback) {
  const v = parseFloat($(`#${id}`).value);
  return Number.isFinite(v) ? v : fallback;
}
function trimmed(id) { return $(`#${id}`).value.trim(); }

function buildConfig() {
  const target = trimmed("target");
  if (!target) throw new Error("Target URL is required.");

  const config = {
    target,
    max_pages: numOr("max_pages", 50),
    max_depth: numOr("max_depth", 3),
    concurrency: numOr("concurrency", 10),
    timeout_s: numOr("timeout_s", 15),
    probe_attempts: numOr("probe_attempts", 12),
    active_probes: $("#active_probes").checked,
    use_browser: $("#use_browser").checked,
    verify_tls: $("#verify_tls").checked,
  };

  const hosts = trimmed("allowed_hosts").split(/[\s,]+/).filter(Boolean);
  if (hosts.length) config.allowed_hosts = hosts;

  const disabled = [...document.querySelectorAll("#scannerList input[type=checkbox]")]
    .filter((c) => !c.checked).map((c) => c.getAttribute("data-id"));
  if (disabled.length) config.disabled_scanners = disabled;

  const username = trimmed("username");
  if (username) {
    const password = $("#password").value;
    if (!password) throw new Error("A password is required when a username is given.");
    const auth = { valid: { username, password } };
    for (const f of ["login_path", "logout_path", "protected_path", "username_field", "password_field"]) {
      const v = trimmed(f);
      if (v) auth[f] = v;
    }
    config.auth = auth;
  }
  return config;
}

/* ---------------- Scan lifecycle ---------------- */
function updateSubmitState() {
  const ok = $("#authorized").checked && trimmed("target") !== "" && !state.poll;
  $("#submitBtn").disabled = !ok;
}

async function startScan(evt) {
  evt.preventDefault();
  $("#formError").hidden = true;
  if (!state.apiKey) { toast("Set your API key first.", "error"); openKeyModal(); return; }

  let config;
  try { config = buildConfig(); }
  catch (e) { showFormError(e.message); return; }

  let resp;
  try { resp = await api("/scan/jobs", { method: "POST", body: config, keyed: true }); }
  catch { showFormError("Network error — is the server running?"); return; }

  if (resp.status === 401) { showFormError("Invalid API key."); openKeyModal(); return; }
  if (resp.status === 503) { showFormError("Server scanning is disabled (AUTHRADAR_API_KEY not set on the server)."); return; }
  if (!resp.ok) { showFormError(await errMessage(resp)); return; }

  state.job = await resp.json();
  state.result = null;
  state.startedAt = Date.now();
  renderProgress();
  startTicker();
  state.poll = setInterval(pollJob, 1500);
  updateSubmitState();
  toast("Scan started.", "success");
}

function showFormError(msg) { const e = $("#formError"); e.textContent = msg; e.hidden = false; }

async function pollJob() {
  if (!state.job) return;
  let resp;
  try { resp = await api(`/scan/jobs/${state.job.id}`, { keyed: true }); }
  catch { return; }
  if (!resp.ok) { stopScan(); showFormError(await errMessage(resp)); return; }
  const job = await resp.json();
  state.job = job;
  if (job.status === "completed") {
    state.result = job.result;
    stopScan();
    renderResult(job.result);
    toast("Scan complete.", "success");
  } else if (job.status === "failed") {
    stopScan();
    renderError(job.error || "Scan failed.");
    toast("Scan failed.", "error");
  } else {
    renderProgress();
  }
}

function stopScan() {
  if (state.poll) { clearInterval(state.poll); state.poll = null; }
  if (state.ticker) { clearInterval(state.ticker); state.ticker = null; }
  updateSubmitState();
}
function startTicker() {
  state.ticker = setInterval(() => { const e = document.getElementById("elapsed"); if (e) e.textContent = elapsed(); }, 500);
}
function elapsed() { return `${((Date.now() - state.startedAt) / 1000).toFixed(1)}s`; }

/* ---------------- Rendering ---------------- */
function renderProgress() {
  const r = $("#results");
  clear(r);
  const spin = el("img", { src: "logo-mark.svg", class: "scanner-spin", alt: "", width: 48, height: 48 });
  r.appendChild(el("div", { class: "panel progress" }, [
    spin,
    el("div", { class: "p-text" }, [
      el("h3", { text: `Scanning ${state.job.target}` }),
      el("div", { class: "muted", html: `Status: <b>${state.job.status}</b> · <span id="elapsed">${elapsed()}</span> elapsed` }),
      el("div", { class: "bar" }, el("i", {})),
    ]),
  ]));
}

function renderError(message) {
  const r = $("#results");
  clear(r);
  r.appendChild(el("div", { class: "panel scan-head" }, [
    el("div", { class: "target", text: state.job ? state.job.target : "Scan" }),
  ]));
  r.appendChild(el("div", { class: "notes" }, [
    el("h3", { text: "Scan failed" }),
    el("p", { class: "muted", text: message }),
  ]));
}

function summarize(result) {
  const bySev = {}; const byCat = {};
  for (const s of SEVERITIES) bySev[s] = 0;
  for (const f of result.findings) {
    bySev[f.severity] = (bySev[f.severity] || 0) + 1;
    byCat[f.category] = (byCat[f.category] || 0) + 1;
  }
  return { bySev, byCat, total: result.findings.length };
}

function renderResult(result) {
  const r = $("#results");
  clear(r);
  const sum = summarize(result);

  // header
  const started = new Date(result.started_at);
  r.appendChild(el("div", { class: "panel scan-head" }, [
    el("div", { class: "target" }, el("a", { href: result.target, target: "_blank", rel: "noopener noreferrer", text: result.target })),
    el("div", { class: "scan-meta" }, [
      kv("Findings", String(sum.total)),
      kv("Pages crawled", String(result.pages_crawled)),
      kv("Duration", `${Number(result.duration_s).toFixed(2)}s`),
      kv("Scanners", String(result.scanners_run.length)),
      kv("Started", started.toLocaleString()),
    ]),
  ]));

  // summary cards
  const cards = el("div", { class: "cards" });
  cards.appendChild(card("total", "Findings", sum.total, () => setSeverityFilter("all")));
  for (const s of SEVERITIES) cards.appendChild(card(`s-${s}`, s, sum.bySev[s], () => setSeverityFilter(s)));
  r.appendChild(cards);

  // charts
  r.appendChild(el("div", { class: "charts" }, [
    el("div", { class: "panel chart-box" }, [el("h3", { text: "Severity" }), donut(sum)]),
    el("div", { class: "panel chart-box" }, [el("h3", { text: "By category" }), categoryBars(sum.byCat)]),
  ]));

  // findings toolbar
  const sevSelect = el("select", { class: "select", onchange: (e) => { state.filters.severity = e.target.value; renderFindingList(); } },
    [el("option", { value: "all", text: "All severities" })].concat(
      SEVERITIES.map((s) => el("option", { value: s, text: prettyCat(s) }))));
  sevSelect.id = "sevFilter";
  const search = el("input", { class: "input-search", type: "search", placeholder: "Filter findings…",
    oninput: (e) => { state.filters.q = e.target.value.toLowerCase(); renderFindingList(); } });
  r.appendChild(el("div", { class: "findings-head" }, [el("h2", { text: "Findings" }), search, sevSelect]));

  r.appendChild(el("div", { id: "findingList" }));
  renderFindingList();

  // scan notes / errors
  if (result.errors && result.errors.length) {
    r.appendChild(el("div", { class: "panel notes" }, [
      el("h3", { text: `Scan notes (${result.errors.length})` }),
      el("ul", {}, result.errors.map((e) => el("li", { text: e }))),
    ]));
  }
}

function kv(label, value) { return el("span", {}, [el("b", { text: `${value} ` }), document.createTextNode(label)]); }

function card(cls, label, num, onclick) {
  return el("div", { class: `card ${cls}`, role: "button", tabindex: 0, onclick,
    onkeydown: (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onclick(); } } }, [
    el("div", { class: "num", text: String(num) }),
    el("div", { class: "lbl", text: label }),
  ]);
}

function setSeverityFilter(sev) {
  state.filters.severity = sev;
  const sel = document.getElementById("sevFilter");
  if (sel) sel.value = sev;
  renderFindingList();
}

function donut(sum) {
  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", "0 0 140 140"); svg.setAttribute("class", "donut");
  const R = 54, C = 2 * Math.PI * R, cx = 70, cy = 70, sw = 16;
  const track = document.createElementNS(NS, "circle");
  for (const [k, v] of Object.entries({ cx, cy, r: R, fill: "none", stroke: "#173249", "stroke-width": sw })) track.setAttribute(k, v);
  svg.appendChild(track);
  let offset = 0;
  if (sum.total > 0) {
    for (const s of SEVERITIES) {
      const count = sum.bySev[s]; if (!count) continue;
      const len = (count / sum.total) * C;
      const seg = document.createElementNS(NS, "circle");
      const attrs = { cx, cy, r: R, fill: "none", stroke: SEV_COLOR[s], "stroke-width": sw,
        "stroke-dasharray": `${len} ${C - len}`, "stroke-dashoffset": -offset, transform: `rotate(-90 ${cx} ${cy})` };
      for (const [k, val] of Object.entries(attrs)) seg.setAttribute(k, val);
      svg.appendChild(seg);
      offset += len;
    }
  }
  const center = document.createElementNS(NS, "text");
  center.setAttribute("x", cx); center.setAttribute("y", cy + 2);
  center.setAttribute("text-anchor", "middle"); center.setAttribute("dominant-baseline", "middle");
  center.setAttribute("class", "donut-center"); center.textContent = String(sum.total);
  svg.appendChild(center);
  const sub = document.createElementNS(NS, "text");
  sub.setAttribute("x", cx); sub.setAttribute("y", cy + 18);
  sub.setAttribute("text-anchor", "middle"); sub.setAttribute("class", "donut-sub"); sub.textContent = "findings";
  svg.appendChild(sub);

  const legend = el("div", { class: "legend" },
    SEVERITIES.map((s) => el("span", {}, [
      el("i", { style: `background:${SEV_COLOR[s]}` }),
      document.createTextNode(prettyCat(s)),
      el("b", { text: String(sum.bySev[s]) }),
    ])));
  return el("div", { class: "donut-wrap" }, [svg, legend]);
}

function categoryBars(byCat) {
  const entries = Object.entries(byCat).sort((a, b) => b[1] - a[1]);
  if (!entries.length) return el("p", { class: "muted", text: "No findings to categorize." });
  const max = Math.max(...entries.map((e) => e[1]));
  return el("div", { class: "cat-bars" }, entries.map(([cat, n]) =>
    el("div", { class: "cat-row" }, [
      el("div", { class: "cat-name", text: prettyCat(cat) }),
      el("div", { class: "cat-track" }, el("div", { class: "cat-fill", style: `width:${Math.max(6, (n / max) * 100)}%` })),
      el("div", { class: "cat-num", text: String(n) }),
    ])));
}

function filteredFindings() {
  const { severity, q } = state.filters;
  return (state.result.findings || []).filter((f) => {
    if (severity !== "all" && f.severity !== severity) return false;
    if (q) {
      const hay = `${f.title} ${f.id} ${f.description} ${f.category} ${f.location || ""}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
}

function renderFindingList() {
  const host = document.getElementById("findingList");
  if (!host) return;
  clear(host);
  if (!state.result.findings.length) {
    host.appendChild(el("div", { class: "clean" }, [el("span", { class: "big", text: "✓" }), document.createTextNode("No findings. The authentication surface looked clean.")]));
    return;
  }
  const items = filteredFindings();
  if (!items.length) { host.appendChild(el("div", { class: "empty-filter", text: "No findings match the current filter." })); return; }
  for (const f of items) host.appendChild(findingCard(f));
}

function findingCard(f) {
  const body = el("div", { class: "f-body" });

  const meta = el("div", { class: "f-kv" }, [
    metaItem("Confidence", f.confidence),
    metaItem("Category", prettyCat(f.category)),
    metaItem("Scanner", f.scanner),
  ]);
  if (f.location) meta.appendChild(metaItem("Location", f.location, true));
  if (f.cwe && f.cwe.length) meta.appendChild(metaItem("CWE", f.cwe.map((c) => `CWE-${c}`).join(", ")));
  body.appendChild(meta);

  body.appendChild(el("p", { text: f.description }));
  body.appendChild(el("div", { class: "f-section", text: "Remediation" }));
  body.appendChild(el("p", { text: f.remediation }));

  if (f.evidence && f.evidence.length) {
    body.appendChild(el("div", { class: "f-section", text: "Evidence" }));
    body.appendChild(el("div", { class: "evidence", text: f.evidence.join("\n") }));
  }
  if (f.references && f.references.length) {
    body.appendChild(el("div", { class: "f-section", text: "References" }));
    body.appendChild(el("ul", { class: "refs" }, f.references.map((ref) =>
      el("li", {}, el("a", { href: ref, target: "_blank", rel: "noopener noreferrer", text: ref })))));
  }

  const card = el("div", { class: `finding s-${f.severity}` });
  const head = el("div", { class: "f-head" }, [
    el("span", { class: `tag s-${f.severity}`, text: f.severity }),
    el("span", { class: "f-title", text: f.title }),
    el("span", { class: "f-id", text: f.id }),
    el("span", { class: "f-chev", html: "&#9656;" }),
  ]);
  head.addEventListener("click", () => card.classList.toggle("open"));
  card.appendChild(head);
  card.appendChild(body);
  return card;
}

function metaItem(label, value, mono) {
  return el("span", {}, [el("b", { text: `${label}: ` }), mono ? el("code", { text: value }) : document.createTextNode(value)]);
}

/* ---------------- Wiring ---------------- */
function init() {
  loadHealth();
  loadScanners();
  refreshKeyState();

  $("#scanForm").addEventListener("submit", startScan);
  $("#authorized").addEventListener("change", updateSubmitState);
  $("#target").addEventListener("input", updateSubmitState);

  $("#keyBtn").addEventListener("click", openKeyModal);
  $("#keySave").addEventListener("click", saveKey);
  $("#keyClear").addEventListener("click", clearKey);
  $("#keyInput").addEventListener("keydown", (e) => { if (e.key === "Enter") saveKey(); });
  for (const node of document.querySelectorAll("[data-close]")) node.addEventListener("click", closeKeyModal);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeKeyModal(); });

  for (const btn of document.querySelectorAll(".scanner-actions [data-all]")) {
    btn.addEventListener("click", () => {
      const on = btn.getAttribute("data-all") === "true";
      for (const c of document.querySelectorAll("#scannerList input[type=checkbox]")) c.checked = on;
    });
  }
  updateSubmitState();
}

document.addEventListener("DOMContentLoaded", init);
