// ---------------- state ----------------
const state = {
  baseUrl: localStorage.getItem("sg_base_url") || "http://127.0.0.1:5000",
  labelColDefault: localStorage.getItem("sg_label_col") || "",
  apkAnalyses: [],      // { filename, result, ts }
  datasetAnalyses: [],  // { filename, result, ts }
  auditLog: [],
  alerts: [],
  timeline: [],         // { malware, fraud, ioc }
  running: { malware: 0, fraud: 0, ioc: 0 },
  backendOnline: null,
};

function esc(s) { return (s ?? "").toString().replace(/[&<>\"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function api(path) {
  if (!path.startsWith("/")) path = "/" + path;
  return state.baseUrl ? state.baseUrl.replace(/\/+$/, "") + path : path;
}
function nowStr() { return new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }); }

function addAudit(action, detail) {
  state.auditLog.unshift({ time: new Date().toLocaleString(), action, detail });
  renderAuditTable();
}

function addAlert(dotClass, badgeClass, badgeText, title) {
  state.alerts.unshift({ dotClass, badgeClass, badgeText, title, time: nowStr() });
  state.alerts = state.alerts.slice(0, 20);
}

// ---------------- nav ----------------
const PAGES = ["dashboard", "malware", "fraud", "bridge", "intel", "yara", "reports", "audit", "compliance", "settings"];
function switchPage(key) {
  PAGES.forEach(p => document.getElementById(`page-${p}`).classList.toggle("hidden", p !== key));
  document.querySelectorAll(".nav-item").forEach(btn => btn.classList.toggle("active", btn.dataset.page === key));
  if (key === "dashboard") renderDashboard();
  if (key === "intel") renderIntel();
  if (key === "yara") renderYaraPage();
  if (key === "reports") renderReports();
  if (key === "audit") renderAuditTable();
}
document.getElementById("sidebar-nav").addEventListener("click", (e) => {
  const btn = e.target.closest(".nav-item");
  if (btn) switchPage(btn.dataset.page);
});
document.getElementById("sidebar-upload-btn").addEventListener("click", () => {
  switchPage("malware");
  document.getElementById("apk-input").click();
});
document.getElementById("fab-scan").addEventListener("click", () => switchPage("malware"));

// ---------------- backend health ----------------
async function checkHealth() {
  try {
    const r = await fetch(api("/"), { method: "GET" });
    state.backendOnline = r.ok;
  } catch {
    state.backendOnline = false;
  }
  renderDashboard();
}

// ---------------- APK (PS1) ----------------
const apkInput = document.getElementById("apk-input");
const apkBtn = document.getElementById("apk-analyze-btn");
apkInput.addEventListener("change", () => {
  document.getElementById("apk-filename").textContent = apkInput.files[0]?.name || "No file selected";
  apkBtn.disabled = !apkInput.files.length;
});

apkBtn.addEventListener("click", async () => {
  const statusEl = document.getElementById("apk-status");
  const resultsEl = document.getElementById("apk-results");
  statusEl.className = "status";
  statusEl.textContent = "Decompiling APK with Androguard — this can take a few seconds...";
  resultsEl.innerHTML = "";
  apkBtn.disabled = true;

  const fd = new FormData();
  fd.append("apk", apkInput.files[0]);
  try {
    const url = api("/api/analyze_apk");
    console.debug("POST", url);
    const res = await fetch(url, { method: "POST", body: fd });
    let data;
    try { data = await res.json(); } catch (derr) { data = null; }
    if (!res.ok) {
      const text = data && data.error ? data.error : `HTTP ${res.status}`;
      throw new Error(text);
    }
    if (data && data.error) throw new Error(data.error || "Analysis failed");
    statusEl.textContent = `Done in ${data.analysis_seconds}s.`;
    renderApkResults(data);

    state.backendOnline = true;
    state.apkAnalyses.unshift({ filename: apkInput.files[0].name, result: data, ts: Date.now() });
    state.running.malware += (data.severity !== "LOW" ? 1 : 0);
    state.running.ioc += (data.target_banking_apps.length + data.c2_candidates.length);
    state.timeline.push({ ...state.running });
    addAlert(`sev-dot-${data.severity}`, `badge-${data.severity.toLowerCase()}`,
      data.severity === "LOW" ? "Info" : data.severity[0] + data.severity.slice(1).toLowerCase(),
      `${data.family_verdict.split(" (")[0]} detected — ${apkInput.files[0].name}`);
    addAudit("APK analysed", `${apkInput.files[0].name} → ${data.severity} (${data.risk_score}/100)`);
    addAlert("dot-info", "badge-info", "Info", `New YARA rule generated — ${data.yara.rule_name}`);
  } catch (e) {
    console.error("APK analysis error", e);
    statusEl.className = "status error";
    statusEl.textContent = `${e.message || e} ` + (state.backendOnline === false ? "(is the backend running? check Settings for the base URL)" : "");
    statusEl.textContent += ` [url=${api("/api/analyze_apk")}]`;
  } finally {
    apkBtn.disabled = false;
  }
});

function renderApkResults(d) {
  const el = document.getElementById("apk-results");
  const mitreRows = d.mitre.map(m => `<tr><td>${m.id}</td><td>${esc(m.name)}</td><td>${esc(m.detection)}</td></tr>`).join("")
    || `<tr><td colspan="3">No MITRE ATT&CK-Mobile techniques matched.</td></tr>`;
  const perms = d.dangerous_permissions.map(p => `<span class="chip danger">${esc(p.replace('android.permission.',''))}</span>`).join(" ") || "<em>none</em>";
  const targets = d.target_banking_apps.map(t => `<span class="chip">${esc(t)}</span>`).join(" ") || "<em>none referenced</em>";
  const c2 = d.c2_candidates.map(c => `<span class="chip danger">${esc(c)}</span>`).join(" ") || "<em>none found</em>";
  const apis = d.api_iocs.map(a => `<span class="chip">${esc(a)}</span>`).join(" ") || "<em>none</em>";

  el.innerHTML = `
    <div class="result-panel">
    <div class="stat-row">
      <div class="stat-box"><div class="v">${d.risk_score}/100</div><div class="l">RISK SCORE</div></div>
      <div class="stat-box"><div class="v"><span class="severity-badge sev-${d.severity}">${d.severity}</span></div><div class="l">SEVERITY</div></div>
      <div class="stat-box"><div class="v">${d.dangerous_permissions.length}</div><div class="l">RISK PERMISSIONS</div></div>
      <div class="stat-box"><div class="v">${d.yara.validated ? 'YES' : 'NO'}</div><div class="l">YARA VALIDATED</div></div>
    </div>
    <h3 class="subhead">Verdict</h3>
    <p style="font-size:13px;"><strong>${esc(d.family_verdict)}</strong> — package <code>${esc(d.package)}</code></p>
    <h3 class="subhead">Investigation Report</h3>
    <ul class="report-list">${d.report.narrative.map(l => `<li>${esc(l)}</li>`).join("")}</ul>
    <strong style="font-size:13px;">Recommendations:</strong>
    <ul class="report-list">${d.report.recommendations.map(l => `<li>${esc(l)}</li>`).join("")}</ul>
    <h3 class="subhead">Indicators of Compromise</h3>
    <p style="font-size:12px;"><strong>Target banking apps referenced:</strong><br>${targets}</p>
    <p style="font-size:12px;"><strong>Dangerous permissions:</strong><br>${perms}</p>
    <p style="font-size:12px;"><strong>C2-candidate URLs/IPs:</strong><br>${c2}</p>
    <p style="font-size:12px;"><strong>Suspicious API/class names:</strong><br>${apis}</p>
    <p style="font-size:12px;">Certificate SHA-256: <code>${esc(d.cert_sha256 || 'not extracted')}</code></p>
    <h3 class="subhead">MITRE ATT&CK-Mobile Coverage</h3>
    <table class="mini-table"><thead><tr><th>Technique</th><th>Name</th><th>Detection</th></tr></thead><tbody>${mitreRows}</tbody></table>
    <h3 class="subhead">Generated YARA Rule ${d.yara.compiles ? (d.yara.validated ? '✅ compiled + matched source APK' : '⚠️ compiled, no match') : '❌ compile error'}</h3>
    <div class="code-block">${esc(d.yara.yar_text)}</div>
    </div>
  `;
}

// ---------------- CSV (PS2) ----------------
const csvInput = document.getElementById("csv-input");
const csvBtn = document.getElementById("csv-analyze-btn");
csvInput.addEventListener("change", () => {
  document.getElementById("csv-filename").textContent = csvInput.files[0]?.name || "No file selected";
  csvBtn.disabled = !csvInput.files.length;
});
if (state.labelColDefault) document.getElementById("label-col").value = state.labelColDefault;

csvBtn.addEventListener("click", async () => {
  const statusEl = document.getElementById("csv-status");
  const resultsEl = document.getElementById("csv-results");
  statusEl.className = "status";
  statusEl.textContent = "Running data-integrity audit, then training XGBoost + SHAP...";
  resultsEl.innerHTML = "";
  csvBtn.disabled = true;

  const fd = new FormData();
  fd.append("dataset", csvInput.files[0]);
  const labelCol = document.getElementById("label-col").value.trim();
  if (labelCol) fd.append("label_column", labelCol);

  try {
    const url = api("/api/analyze_dataset");
    console.debug("POST", url);
    const res = await fetch(url, { method: "POST", body: fd });
    let data;
    try { data = await res.json(); } catch (derr) { data = null; }
    if (!res.ok) {
      const text = data && data.error ? data.error : `HTTP ${res.status}`;
      throw new Error(text);
    }
    if (data && data.error) throw new Error(data.error || "Pipeline failed");
    statusEl.textContent = "Done.";
    renderCsvResults(data);

    state.backendOnline = true;
    state.datasetAnalyses.unshift({ filename: csvInput.files[0].name, result: data, ts: Date.now() });
    state.running.fraud += (data.tier_counts.T3 + data.tier_counts.T4);
    state.timeline.push({ ...state.running });
    const topTier = data.top_alerts[0]?.tier;
    if (topTier) {
      const badge = { T4: "critical", T3: "high", T2: "medium", T1: "info" }[topTier];
      addAlert(`sev-dot-${topTier}`, `badge-${badge}`, badge[0].toUpperCase() + badge.slice(1),
        `High risk account detected — ${data.top_alerts[0].account_hash} (${topTier})`);
    }
    addAudit("Dataset analysed", `${csvInput.files[0].name} → ${data.audit.n_rows} rows, ${data.tier_counts.T3 + data.tier_counts.T4} high-risk`);
  } catch (e) {
    console.error("Dataset analysis error", e);
    statusEl.className = "status error";
    statusEl.textContent = `${e.message || e}`;
    statusEl.textContent += ` [url=${api("/api/analyze_dataset")}]`;
  } finally {
    csvBtn.disabled = false;
  }
});

function renderCsvResults(d) {
  const el = document.getElementById("csv-results");
  const auditRows = d.audit.findings.map(f => `<tr><td>${esc(f.signal)}</td><td>${esc(f.type)}</td><td>${esc(f.evidence)}</td><td>${esc(f.disposition)}</td></tr>`).join("")
    || `<tr><td colspan="4">No leakage or target-proxy signals detected.</td></tr>`;
  const alertRows = d.top_alerts.map(a => `
    <tr>
      <td>${esc(a.account_hash)}</td>
      <td><span class="tier-badge tier-${a.tier}">${a.tier}</span></td>
      <td>${a.score}</td>
      <td>${a.shap_drivers.map(s => `${esc(s.feature)} (${s.shap > 0 ? '+' : ''}${s.shap})`).join(", ")}</td>
      <td>${a.counterfactual ? `drops to ${a.counterfactual.drops_to} if ${esc(a.counterfactual.condition)}` : '—'}</td>
    </tr>`).join("");

  el.innerHTML = `
    <div class="result-panel">
    <div class="stat-row">
      <div class="stat-box"><div class="v">${d.cv_aucpr_mean !== null ? d.cv_aucpr_mean.toFixed(3) : 'n/a'}</div><div class="l">CV AUCPR (${d.n_cv_folds}-fold)</div></div>
      <div class="stat-box"><div class="v">${d.audit.prevalence_pct}%</div><div class="l">FRAUD PREVALENCE</div></div>
      <div class="stat-box"><div class="v">${d.audit.flagged_columns.length}</div><div class="l">COLUMNS FLAGGED</div></div>
      <div class="stat-box"><div class="v">${d.feature_columns.length}</div><div class="l">FEATURES USED</div></div>
    </div>
    <h3 class="subhead">Data-Integrity Audit</h3>
    <table class="mini-table"><thead><tr><th>Signal</th><th>Type</th><th>Evidence</th><th>Disposition</th></tr></thead><tbody>${auditRows}</tbody></table>
    <h3 class="subhead">Risk Tiers</h3>
    <div class="stat-row">
      <div class="stat-box"><div class="v">${d.tier_counts.T1}</div><div class="l">T1 · no action</div></div>
      <div class="stat-box"><div class="v">${d.tier_counts.T2}</div><div class="l">T2 · monitor</div></div>
      <div class="stat-box"><div class="v">${d.tier_counts.T3}</div><div class="l">T3 · enhanced review</div></div>
      <div class="stat-box"><div class="v">${d.tier_counts.T4}</div><div class="l">T4 · debit freeze</div></div>
    </div>
    <h3 class="subhead">Top Alerts (${d.top_alerts.length} shown)</h3>
    <table class="mini-table"><thead><tr><th>Account hash</th><th>Tier</th><th>Score</th><th>SHAP drivers</th><th>Counterfactual</th></tr></thead><tbody>${alertRows}</tbody></table>
    </div>
  `;
}

// ---------------- Bridge ----------------
document.getElementById("bridge-btn").addEventListener("click", async () => {
  const el = document.getElementById("bridge-results");
  el.innerHTML = `<p class="status">Linking...</p>`;
  try {
    const url = api("/api/bridge");
    console.debug("POST", url);
    const res = await fetch(url, { method: "POST" });
    let d;
    try { d = await res.json(); } catch (derr) { d = null; }
    if (!res.ok) {
      const text = d && d.error ? d.error : `HTTP ${res.status}`;
      throw new Error(text);
    }
    if (d && d.error) throw new Error(d.error);
    el.innerHTML = `
      <div class="code-block">unified_dashboard / case_view

ALERT   account <span class="k">${esc(d.account_hash)}</span>   tier <span class="k">${esc(d.tier)}</span> (${d.score})   status: PENDING REVIEW
  linked_apk     ${esc(d.linked_apk_package)}   family: ${esc(d.family)}   severity: ${esc(d.severity)}
  shared_ioc     ${esc(d.shared_ioc)}
  yara_rule      ${esc(d.yara_rule)}   validated: ${d.yara_validated}
  recommended    ${esc(d.recommended_action)}

// ${esc(d.note)}</div>`;
    addAudit("IOC Bridge linked", `${d.account_hash} ↔ ${d.linked_apk_package}`);
    addAlert("dot-info", "badge-info", "Info", `IOC match found — ${d.account_hash} linked to ${d.linked_apk_package}`);
    renderDashboard();
  } catch (e) {
    console.error("Bridge error", e);
    el.innerHTML = `<p class="status error">${esc(e.message || e)} [url=${api("/api/bridge")} ]</p>`;
  }
});

// ---------------- Settings ----------------
document.getElementById("settings-base-url").value = state.baseUrl;
document.getElementById("settings-label-col").value = state.labelColDefault;
document.getElementById("settings-save-btn").addEventListener("click", () => {
  state.baseUrl = document.getElementById("settings-base-url").value.trim();
  state.labelColDefault = document.getElementById("settings-label-col").value.trim();
  localStorage.setItem("sg_base_url", state.baseUrl);
  localStorage.setItem("sg_label_col", state.labelColDefault);
  document.getElementById("label-col").value = state.labelColDefault;
  document.getElementById("settings-status").textContent = "Saved.";
  addAudit("Settings updated", `base URL = "${state.baseUrl || '(relative)'}"`);
  checkHealth();
});

// ---------------- Dashboard ----------------
let chartInstance = null;

function renderDashboard() {
  renderStatGrid();
  renderChart();
  renderAlerts();
  renderHealth();
  renderMalwareTable();
  renderAccountsTable();
  renderIocTable();
  renderYaraTable();
}

function renderStatGrid() {
  const malwareCount = state.apkAnalyses.length;
  const highRisk = state.datasetAnalyses.reduce((s, a) => s + a.result.tier_counts.T3 + a.result.tier_counts.T4, 0);
  const iocCorrelations = state.apkAnalyses.reduce((s, a) => s + a.result.target_banking_apps.length + a.result.c2_candidates.length, 0);
  const yaraCount = state.apkAnalyses.length;

  const cards = [
    { icon: "shield", cls: "purple", v: malwareCount, l: "Malware Analyzed", d: `${malwareCount} this session` },
    { icon: "alert", cls: "red", v: highRisk, l: "High Risk Accounts", d: `${highRisk} this session` },
    { icon: "link", cls: "blue", v: iocCorrelations, l: "IOC Correlations", d: `${iocCorrelations} this session` },
    { icon: "file", cls: "purple", v: yaraCount, l: "YARA Rules Generated", d: `${yaraCount} this session` },
  ];
  const icons = {
    shield: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2 4 5v6c0 5 3.4 8.7 8 9 4.6-.3 8-4 8-9V5l-8-3Z"/></svg>`,
    alert: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.3 3.9 2.7 17a1.9 1.9 0 0 0 1.6 2.9h15.4a1.9 1.9 0 0 0 1.6-2.9L13.7 3.9a1.9 1.9 0 0 0-3.4 0Z"/><path d="M12 9v4M12 16.5h.01"/></svg>`,
    link: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1.5 1.5"/><path d="M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1.5-1.5"/></svg>`,
    file: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"/><path d="M14 2v6h6"/></svg>`,
  };
  document.getElementById("stat-grid").innerHTML = cards.map(c => `
    <div class="stat-card">
      <span class="stat-icon ${c.cls}">${icons[c.icon]}</span>
      <div class="stat-body"><div class="v">${c.v}</div><div class="l">${c.l}</div><div class="delta">${c.d}</div></div>
    </div>`).join("");
}

function renderChart() {
  const ctx = document.getElementById("threat-chart");
  if (typeof Chart === "undefined") {
    // Chart.js not loaded (CDN blocked or offline) — show placeholder and avoid throwing
    if (chartInstance) {
      try { chartInstance.destroy(); } catch (_) {}
      chartInstance = null;
    }
    ctx.style.display = 'none';
    const parent = ctx.closest('.panel');
    if (parent) {
      let ph = parent.querySelector('.chart-placeholder');
      if (!ph) {
        ph = document.createElement('div');
        ph.className = 'chart-placeholder';
        ph.textContent = 'Chart library unavailable — refresh or check network.';
        ph.style.padding = '24px';
        ph.style.color = '#c0392b';
        parent.appendChild(ph);
      }
    }
    return;
  }
  const labels = state.timeline.length ? state.timeline.map((_, i) => `Run ${i + 1}`) : ["Start"];
  const points = state.timeline.length ? state.timeline : [{ malware: 0, fraud: 0, ioc: 0 }];
  const data = {
    labels,
    datasets: [
      { label: "Malware", data: points.map(p => p.malware), borderColor: "#ef4444", backgroundColor: "#ef4444", tension: 0.35 },
      { label: "Fraud", data: points.map(p => p.fraud), borderColor: "#f59e0b", backgroundColor: "#f59e0b", tension: 0.35 },
      { label: "IOC Matches", data: points.map(p => p.ioc), borderColor: "#3b82f6", backgroundColor: "#3b82f6", tension: 0.35 },
    ]
  };
  if (chartInstance) { chartInstance.data = data; chartInstance.update(); return; }
  try {
    ctx.style.display = '';
    // create Chart instance
    chartInstance = new Chart(ctx, {
    type: "line",
    data,
    options: {
      responsive: true,
      plugins: { legend: { position: "bottom", labels: { boxWidth: 10, font: { size: 11 } } } },
      scales: { y: { beginAtZero: true, ticks: { precision: 0 } } },
      elements: { point: { radius: 3 } },
    }
    });
  } catch (err) {
    console.error('Failed to render chart', err);
    chartInstance = null;
  }
}

function renderAlerts() {
  const el = document.getElementById("recent-alerts");
  if (!state.alerts.length) { el.innerHTML = `<div class="empty-note show">No alerts yet — run an analysis.</div>`; return; }
  el.innerHTML = state.alerts.slice(0, 6).map(a => `
    <div class="alert-row">
      <span class="alert-dot" style="background:${badgeColor(a.badgeClass)}"></span>
      <div class="alert-text"><span class="title">${esc(a.title)}</span><span class="time">${a.time}</span></div>
      <span class="badge ${a.badgeClass}">${esc(a.badgeText)}</span>
    </div>`).join("");
}
function badgeColor(cls) {
  return { "badge-critical": "#ef4444", "badge-high": "#f59e0b", "badge-medium": "#d4a017", "badge-info": "#3b82f6" }[cls] || "#7c8494";
}

function renderHealth() {
  const online = state.backendOnline;
  const rows = [
    { l: "PS1 Engine", on: online === true },
    { l: "PS2 Engine", on: online === true },
    { l: "IOC Bridge", on: online === true },
    { l: "Threat Intel Feed", on: false, note: "not connected" },
    { l: "Database", on: false, note: "session only" },
  ];
  document.getElementById("system-health").innerHTML = rows.map(r => `
    <div class="health-row"><span>${r.l}</span>
      <span class="health-status ${r.on ? 'on' : 'off'}"><i class="dot ${r.on ? 'online' : ''}" style="background:${r.on ? '#22c55e' : '#c9cedb'}"></i>${r.on ? 'Online' : (r.note || (online === false ? 'Offline' : 'Idle'))}</span>
    </div>`).join("");
}

function fillTable(tableId, rows, rowFn) {
  const table = document.getElementById(tableId);
  const note = document.querySelector(`.empty-note[data-for="${tableId}"]`);
  if (!rows.length) { table.classList.add("hidden-table"); note.classList.add("show"); table.querySelector("tbody").innerHTML = ""; return; }
  table.classList.remove("hidden-table"); note.classList.remove("show");
  table.querySelector("tbody").innerHTML = rows.map(rowFn).join("");
}

function renderMalwareTable() {
  const rows = [...state.apkAnalyses].sort((a, b) => b.result.risk_score - a.result.risk_score).slice(0, 6);
  fillTable("table-malware", rows, a => `<tr><td>${esc(a.filename)}</td><td>${esc(a.result.family_verdict.split(" (")[0])}</td><td>${a.result.risk_score}%</td></tr>`);
}
function renderAccountsTable() {
  const all = state.datasetAnalyses.flatMap(d => d.result.top_alerts.filter(a => a.tier === "T3" || a.tier === "T4"));
  const rows = all.sort((a, b) => b.score - a.score).slice(0, 6);
  fillTable("table-accounts", rows, a => `<tr><td>${esc(a.account_hash)}</td><td><span class="tier-badge tier-${a.tier}">${a.tier}</span></td><td>${(a.score * 100).toFixed(1)}%</td></tr>`);
}
function renderIocTable() {
  let domain = 0, cert = 0, perm = 0, api_ = 0;
  state.apkAnalyses.forEach(a => {
    domain += a.result.c2_candidates.length + a.result.target_banking_apps.length;
    cert += a.result.cert_sha256 ? 1 : 0;
    perm += a.result.dangerous_permissions.length;
    api_ += a.result.api_iocs.length;
  });
  const rows = [
    { t: "Domain / IP / Package", c: domain },
    { t: "Certificate Hash", c: cert },
    { t: "Dangerous Permission", c: perm },
    { t: "API / Class IOC", c: api_ },
  ].filter(r => r.c > 0);
  fillTable("table-ioc", rows, r => `<tr><td>${r.t}</td><td>${r.c}</td></tr>`);
}
function renderYaraTable() {
  const rows = state.apkAnalyses.slice(0, 6);
  fillTable("table-yara", rows, a => `<tr><td>${esc(a.result.yara.rule_name)}</td><td>${a.result.yara.validated ? '✅ Yes' : '— No'}</td></tr>`);
}

// ---------------- IOC Intelligence page ----------------
function renderIntel() {
  const el = document.getElementById("intel-results");
  if (!state.apkAnalyses.length) { el.innerHTML = `<div class="empty-state">No IOCs extracted yet — run a Malware Analysis first.</div>`; return; }
  el.innerHTML = state.apkAnalyses.map(a => `
    <h3 class="subhead">${esc(a.filename)} — <span class="severity-badge sev-${a.result.severity}">${a.result.severity}</span></h3>
    <p style="font-size:12px;"><strong>Target banking apps:</strong> ${a.result.target_banking_apps.map(t => `<span class="chip">${esc(t)}</span>`).join(" ") || "none"}</p>
    <p style="font-size:12px;"><strong>C2 candidates:</strong> ${a.result.c2_candidates.map(t => `<span class="chip danger">${esc(t)}</span>`).join(" ") || "none"}</p>
    <p style="font-size:12px;"><strong>API/class IOCs:</strong> ${a.result.api_iocs.map(t => `<span class="chip">${esc(t)}</span>`).join(" ") || "none"}</p>
    <p style="font-size:12px;">Certificate SHA-256: <code>${esc(a.result.cert_sha256 || 'n/a')}</code></p>
  `).join("<hr style='border:none;border-top:1px solid var(--border);margin:18px 0;'>");
}

// ---------------- YARA Rules page ----------------
function renderYaraPage() {
  const el = document.getElementById("yara-results");
  if (!state.apkAnalyses.length) { el.innerHTML = `<div class="empty-state">No rules generated yet — run a Malware Analysis first.</div>`; return; }
  el.innerHTML = state.apkAnalyses.map(a => `
    <h3 class="subhead">${esc(a.result.yara.rule_name)} — ${a.result.yara.validated ? '✅ validated (compiled + matched)' : '⚠️ not validated'}</h3>
    <div class="code-block">${esc(a.result.yara.yar_text)}</div>
  `).join("");
}

// ---------------- Reports page ----------------
function renderReports() {
  const el = document.getElementById("reports-results");
  if (!state.apkAnalyses.length && !state.datasetAnalyses.length) {
    el.innerHTML = `<div class="empty-state">Nothing to report yet — run an analysis first.</div>`; return;
  }
  const critApks = state.apkAnalyses.filter(a => a.result.severity === "CRITICAL" || a.result.severity === "HIGH").length;
  const totalHighRisk = state.datasetAnalyses.reduce((s, a) => s + a.result.tier_counts.T3 + a.result.tier_counts.T4, 0);
  el.innerHTML = `
    <h3 class="subhead">Session Summary</h3>
    <p style="font-size:13px;">${state.apkAnalyses.length} APK(s) analysed, ${critApks} flagged HIGH/CRITICAL.
    ${state.datasetAnalyses.length} dataset(s) analysed, ${totalHighRisk} accounts flagged T3/T4 across all runs.</p>
    <h3 class="subhead">APK Runs</h3>
    <table class="mini-table"><thead><tr><th>File</th><th>Severity</th><th>Risk score</th><th>Time</th></tr></thead>
    <tbody>${state.apkAnalyses.map(a => `<tr><td>${esc(a.filename)}</td><td><span class="severity-badge sev-${a.result.severity}">${a.result.severity}</span></td><td>${a.result.risk_score}</td><td>${new Date(a.ts).toLocaleString()}</td></tr>`).join("") || "<tr><td colspan='4'>none</td></tr>"}</tbody></table>
    <h3 class="subhead">Dataset Runs</h3>
    <table class="mini-table"><thead><tr><th>File</th><th>Rows</th><th>CV AUCPR</th><th>T3/T4</th><th>Time</th></tr></thead>
    <tbody>${state.datasetAnalyses.map(a => `<tr><td>${esc(a.filename)}</td><td>${a.result.audit.n_rows}</td><td>${a.result.cv_aucpr_mean !== null ? a.result.cv_aucpr_mean.toFixed(3) : 'n/a'}</td><td>${a.result.tier_counts.T3 + a.result.tier_counts.T4}</td><td>${new Date(a.ts).toLocaleString()}</td></tr>`).join("") || "<tr><td colspan='5'>none</td></tr>"}</tbody></table>
  `;
}

// ---------------- Audit Trail page ----------------
function renderAuditTable() {
  fillTable("table-audit", state.auditLog, r => `<tr><td>${r.time}</td><td>${esc(r.action)}</td><td>${esc(r.detail)}</td></tr>`);
}

// ---------------- init ----------------
renderDashboard();
checkHealth();
