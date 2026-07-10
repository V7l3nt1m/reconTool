/* ============================================================
   recon-tool — lógica do frontend
   ============================================================ */

const API_BASE = "http://localhost:8000";

let currentJobId = null;
let currentReport = null;
let activeTab = "summary";

/* ------------------------------------------------------------
   efeito ambiente: chuva de caracteres (assinatura visual,
   bem discreta — opacity controlada via CSS)
   ------------------------------------------------------------ */
(function initRain() {
  const canvas = document.getElementById("rainCanvas");
  const ctx = canvas.getContext("2d");
  const glyphs = "01{}[]<>/;:=+-#$_ABCDEFabcdef".split("");
  let columns, drops;

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    columns = Math.floor(canvas.width / 16);
    drops = new Array(columns).fill(0).map(() => Math.random() * -50);
  }
  window.addEventListener("resize", resize);
  resize();

  function draw() {
    ctx.fillStyle = "rgba(5,8,6,0.15)";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.font = "13px 'JetBrains Mono', monospace";
    ctx.fillStyle = "#39ff8c";
    for (let i = 0; i < columns; i++) {
      const text = glyphs[Math.floor(Math.random() * glyphs.length)];
      ctx.fillText(text, i * 16, drops[i] * 16);
      if (drops[i] * 16 > canvas.height && Math.random() > 0.975) drops[i] = 0;
      drops[i]++;
    }
  }
  if (!window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    setInterval(draw, 60);
  }
})();

/* ------------------------------------------------------------
   verificação de saúde da API
   ------------------------------------------------------------ */
async function checkHealth() {
  const el = document.getElementById("apiState");
  try {
    const res = await fetch(`${API_BASE}/api/health`);
    if (res.ok) {
      el.textContent = "online";
      el.style.color = "var(--accent)";
    } else {
      throw new Error("bad status");
    }
  } catch {
    el.textContent = "offline — inicie o backend (uvicorn main:app --port 8000)";
    el.style.color = "var(--danger)";
  }
}
checkHealth();

/* ------------------------------------------------------------
   utilitários
   ------------------------------------------------------------ */
function esc(s) {
  if (s === null || s === undefined) return "";
  return String(s).replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function copyText(text, btn) {
  navigator.clipboard.writeText(text);
  if (btn) {
    const old = btn.textContent;
    btn.textContent = "copiado!";
    setTimeout(() => (btn.textContent = old), 1000);
  }
}

function timestamp() {
  const d = new Date();
  return d.toTimeString().split(" ")[0];
}

function appendBootLine(message, kind = "info") {
  const log = document.getElementById("bootLog");
  const line = document.createElement("div");
  line.className = "boot-log__line";
  const cls = kind === "error" ? "err" : kind === "done" ? "ok" : "";
  line.innerHTML = `<span class="ts">[${timestamp()}]</span> $ ${esc(message)}` +
    (kind === "done" ? ` <span class="ok">[OK]</span>` : "") +
    (kind === "error" ? ` <span class="err">[FAIL]</span>` : "");
  if (cls) line.classList.add(cls);
  log.appendChild(line);
  log.scrollTop = log.scrollHeight;
}

/* ------------------------------------------------------------
   fluxo principal: iniciar análise + SSE
   ------------------------------------------------------------ */
async function startAnalysis() {
  const urlInput = document.getElementById("urlInput");
  const url = urlInput.value.trim();
  if (!url) {
    urlInput.focus();
    return;
  }

  document.getElementById("bootPanel").classList.remove("hidden");
  document.getElementById("resultsPanel").classList.add("hidden");
  document.getElementById("searchPanel").classList.add("hidden");
  document.getElementById("bootLog").innerHTML = "";
  document.getElementById("progressBar").style.width = "0%";
  document.getElementById("progressPct").textContent = "0%";
  document.getElementById("analyzeBtn").disabled = true;

  appendBootLine(`alvo definido: ${url}`);
  appendBootLine("a estabelecer ligação com a API...");

  let res;
  try {
    res = await fetch(`${API_BASE}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
  } catch (e) {
    appendBootLine("não foi possível contactar o backend — confirme que está a correr em " + API_BASE, "error");
    document.getElementById("analyzeBtn").disabled = false;
    return;
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    appendBootLine("erro ao iniciar: " + (err.detail ? JSON.stringify(err.detail) : res.status), "error");
    document.getElementById("analyzeBtn").disabled = false;
    return;
  }

  const data = await res.json();
  currentJobId = data.job_id;
  appendBootLine(`job criado: ${currentJobId}`, "done");

  const evtSource = new EventSource(`${API_BASE}/api/analyze/${currentJobId}/stream`);
  evtSource.onmessage = (ev) => {
    const payload = JSON.parse(ev.data);
    appendBootLine(payload.message, payload.stage === "error" ? "error" : "info");
    document.getElementById("progressPct").textContent = payload.percent + "%";
    document.getElementById("progressBar").style.width = payload.percent + "%";
  };
  evtSource.onerror = () => {
    // ligação encerrada pelo servidor após o evento "end" — comportamento esperado
  };
  evtSource.addEventListener("end", async () => {
    evtSource.close();
    document.getElementById("analyzeBtn").disabled = false;
    appendBootLine("stream encerrado. a carregar relatório...", "done");
    await loadReport();
  });
}

async function loadReport() {
  const res = await fetch(`${API_BASE}/api/analyze/${currentJobId}/report`);
  const data = await res.json();
  if (data.status === "error") {
    appendBootLine("análise terminou com erro: " + data.error_message, "error");
    return;
  }
  currentReport = data.report;
  document.getElementById("resultsPanel").classList.remove("hidden");
  document.getElementById("searchPanel").classList.remove("hidden");
  renderTabs();
  selectTab("summary");
}

/* ------------------------------------------------------------
   abas / relatório
   ------------------------------------------------------------ */
const TABS = [
  { key: "summary", label: "RESUMO", hotkey: "1" },
  { key: "technologies", label: "TECH", hotkey: "2" },
  { key: "http", label: "HEADERS", hotkey: "3" },
  { key: "cookies", label: "COOKIES", hotkey: "4" },
  { key: "js_files", label: "JS", hotkey: "5" },
  { key: "endpoints", label: "ENDPOINTS", hotkey: "6" },
  { key: "api_docs", label: "SWAGGER", hotkey: "7" },
  { key: "env_vars", label: "ENV", hotkey: "8" },
  { key: "secrets", label: "SECRETS", hotkey: "9" },
  { key: "jwts", label: "JWT", hotkey: "10" },
  { key: "storage_usage", label: "STORAGE", hotkey: "11" },
  { key: "pii", label: "PII", hotkey: "12" },
  { key: "external_domains", label: "URLS EXT.", hotkey: "13" },
];

function renderTabs() {
  const tabsEl = document.getElementById("tabs");
  tabsEl.innerHTML = "";
  TABS.forEach(t => {
    const btn = document.createElement("button");
    btn.className = "tab-btn";
    btn.id = "tabbtn-" + t.key;
    btn.innerHTML = `<span class="key">F${t.hotkey}</span>${t.label}`;
    btn.onclick = () => selectTab(t.key);
    tabsEl.appendChild(btn);
  });
}

function selectTab(key) {
  activeTab = key;
  TABS.forEach(t => document.getElementById("tabbtn-" + t.key).classList.remove("is-active"));
  document.getElementById("tabbtn-" + key).classList.add("is-active");
  document.getElementById("tabContent").innerHTML = renderSection(key);
}

function emptyMsg() {
  return `<div class="empty-msg"></div>`;
}

function statsGrid(stats) {
  return `<div class="stats-grid">` +
    Object.entries(stats || {}).map(([k, v]) => `
      <div class="stat-card">
        <div class="stat-card__value">${esc(v)}</div>
        <div class="stat-card__label">${esc(k)}</div>
      </div>`).join("") + `</div>`;
}

function chipList(items, variant = "") {
  if (!items || items.length === 0) return emptyMsg();
  return items.map(i => `<span class="chip ${variant}">${esc(i)}</span>`).join("");
}

function dataTable(items, columns) {
  if (!items || items.length === 0) return emptyMsg();
  return `<div style="overflow-x:auto"><table class="data-table">
    <thead><tr>${columns.map(c => `<th>${esc(c)}</th>`).join("")}</tr></thead>
    <tbody>
      ${items.map(row => `<tr>${columns.map(c => `<td>${esc(row[c])}</td>`).join("")}</tr>`).join("")}
    </tbody>
  </table></div>`;
}

function renderSection(key) {
  const r = currentReport;
  if (!r) return emptyMsg();

  switch (key) {
    case "summary":
      return statsGrid(r.stats) +
        `<div style="margin-top:16px;font-size:12px;" class="dim">
           alvo: <span style="color:var(--text)">${esc(r.target)}</span>
         </div>`;

    case "technologies":
      return chipList(r.technologies, "chip--accent");

    case "http":
      return `<pre class="raw-json">${esc(JSON.stringify(r.http || {}, null, 2))}</pre>`;

    case "cookies":
      return dataTable(r.cookies, ["name", "http_only", "secure", "same_site", "domain", "path"]);

    case "js_files":
      return dataTable(r.js_files, ["url", "size"]);

    case "endpoints":
      return dataTable(
        (r.endpoints || []).map(e => ({ ...e, methods: e.methods.join(", "), sources: e.sources.length })),
        ["path", "methods", "module", "sources"]
      );

    case "api_docs":
      return dataTable(r.api_docs, ["path", "url", "status_code", "title", "endpoints_count"]);

    case "env_vars":
      if (!r.env_vars || r.env_vars.length === 0) return emptyMsg();
      return r.env_vars.map(v => `
        <div class="jwt-card" style="display:flex;justify-content:space-between;align-items:center;padding:8px 12px;">
          <span style="color:var(--cyan)">${esc(v)}</span>
          <button class="copy-btn" onclick="copyText('${esc(v)}', this)">copiar</button>
        </div>`).join("");

    case "secrets":
      if (!r.secrets || r.secrets.length === 0) return emptyMsg();
      return `<div style="overflow-x:auto"><table class="data-table">
        <thead><tr><th>tipo</th><th>preview</th><th>fonte</th></tr></thead>
        <tbody>${r.secrets.map(s => `<tr>
          <td class="type-secret">${esc(s.type)}</td>
          <td>${esc(s.match_preview)}</td>
          <td>${esc(s.source_file)}</td>
        </tr>`).join("")}</tbody>
      </table></div>`;

    case "jwts":
      if (!r.jwts || r.jwts.length === 0) return emptyMsg();
      return r.jwts.map(j => `
        <div class="jwt-card">
          <div class="jwt-card__source">${esc(j.source_file)}</div>
          <div class="jwt-card__preview">${esc(j.token_preview)}</div>
          <pre>${esc(JSON.stringify(j.payload, null, 2))}</pre>
        </div>`).join("");

    case "storage_usage":
      return dataTable(r.storage_usage, ["api", "method", "key", "source_file"]);

    case "pii":
      if (!r.pii || r.pii.length === 0) return emptyMsg();
      return `<div style="overflow-x:auto"><table class="data-table">
        <thead><tr><th>tipo</th><th>valor</th><th>fonte</th></tr></thead>
        <tbody>${r.pii.map(p => `<tr>
          <td class="type-pii">${esc(p.type)}</td>
          <td>${esc(p.value)}</td>
          <td>${esc(p.source_file)}</td>
        </tr>`).join("")}</tbody>
      </table></div>`;

    case "external_domains":
      return chipList(r.external_domains);

    default:
      return emptyMsg();
  }
}

/* ------------------------------------------------------------
   pesquisa global
   ------------------------------------------------------------ */
async function doSearch() {
  const q = document.getElementById("searchInput").value.trim();
  if (!q || !currentJobId) return;
  const res = await fetch(`${API_BASE}/api/analyze/${currentJobId}/search?q=${encodeURIComponent(q)}`);
  const data = await res.json();
  const box = document.getElementById("searchResults");
  box.classList.remove("hidden");
  box.innerHTML = `<div class="dim" style="margin-bottom:8px;">${data.count} resultado(s) para "${esc(q)}"</div>` +
    data.results.map(r => `
      <div class="search-results__item">
        <div class="search-results__section">${esc(r.section)}</div>
        <div class="search-results__blob">${esc(JSON.stringify(r.item))}</div>
      </div>`).join("");
}

/* ------------------------------------------------------------
   exportação
   ------------------------------------------------------------ */
function exportReport(fmt) {
  if (!currentJobId) return;
  window.open(`${API_BASE}/api/analyze/${currentJobId}/export?fmt=${fmt}`, "_blank");
}

/* ------------------------------------------------------------
   atalhos de teclado: Enter no campo de URL executa a análise
   ------------------------------------------------------------ */
document.getElementById("urlInput").addEventListener("keydown", (e) => {
  if (e.key === "Enter") startAnalysis();
});