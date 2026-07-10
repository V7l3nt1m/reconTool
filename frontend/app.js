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

function badge(relevance) {
  if (!relevance) return "";
  return `<span class="badge badge--${esc(relevance)}">${esc(relevance)}</span>`;
}

/* ------------------------------------------------------------
   opções avançadas: toggle + parsing de headers customizados
   ------------------------------------------------------------ */
function toggleOptions() {
  const body = document.getElementById("optionsBody");
  const btn = document.querySelector(".options-panel__toggle");
  const isHidden = body.classList.toggle("hidden");
  btn.textContent = isHidden
    ? "[+] opções avançadas (headers customizados, sondagens)"
    : "[-] opções avançadas (headers customizados, sondagens)";
}

// Converte texto "Nome: valor" (uma linha por header) num objeto.
// Usado tanto no arranque da análise como no painel de execução de endpoints.
function parseHeadersText(text) {
  const headers = {};
  if (!text) return headers;
  text.split("\n").forEach(line => {
    const idx = line.indexOf(":");
    if (idx === -1) return;
    const name = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    if (name && value) headers[name] = value;
  });
  return headers;
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

  const customHeaders = parseHeadersText(document.getElementById("customHeaders").value);
  const options = {
    probe_stack_files: document.getElementById("optStackFiles").checked,
    probe_external_domains: document.getElementById("optExternalDomains").checked,
  };

  appendBootLine(`alvo definido: ${url}`);
  if (Object.keys(customHeaders).length) {
    appendBootLine(`headers customizados: ${Object.keys(customHeaders).join(", ")}`);
  }
  appendBootLine("a estabelecer ligação com a API...");

  let res;
  try {
    res = await fetch(`${API_BASE}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, headers: customHeaders, options }),
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
  { key: "routes", label: "ROTAS", hotkey: "7" },
  { key: "api_docs", label: "SWAGGER", hotkey: "8" },
  { key: "robots", label: "ROBOTS.TXT", hotkey: "9" },
  { key: "env_vars", label: "ENV", hotkey: "10" },
  { key: "secrets", label: "SECRETS", hotkey: "11" },
  { key: "jwts", label: "JWT", hotkey: "12" },
  { key: "storage_usage", label: "STORAGE", hotkey: "13" },
  { key: "pii", label: "PII", hotkey: "14" },
  { key: "external_domains", label: "URLS EXT.", hotkey: "15" },
  { key: "external_domain_recon", label: "RECON EXT.", hotkey: "16" },
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

function redirectChainHtml(chain, finalUrl) {
  if (!chain || chain.length === 0) return "";
  const hops = chain.map(h => `
    <div class="redirect-chain__hop">
      <span class="dim">${esc(h.status_code)}</span>
      <span>${esc(h.from_url)}</span>
      <span class="arrow">→</span>
    </div>`).join("");
  return `<div class="redirect-chain">
    <div class="dim" style="font-size:11px;">cadeia de redirecionamentos:</div>
    ${hops}
    <div class="redirect-chain__hop"><span class="accent">destino final:</span> ${esc(finalUrl)}</div>
  </div>`;
}

function renderSection(key) {
  const r = currentReport;
  if (!r) return emptyMsg();

  switch (key) {
    case "summary":
      return statsGrid(r.stats) +
        `<div style="margin-top:16px;font-size:12px;" class="dim">
           alvo: <span style="color:var(--text)">${esc(r.target)}</span>
         </div>` +
        (r.final_url && r.final_url !== r.target
          ? `<div style="font-size:12px;" class="dim">destino final (após redirects): <span style="color:var(--accent)">${esc(r.final_url)}</span></div>`
          : "");

    case "technologies": {
      const details = r.technologies_detail && r.technologies_detail.length
        ? r.technologies_detail
        : (r.technologies || []).map(n => ({ name: n, evidence: [], confirmed_files: [] }));
      if (details.length === 0) return emptyMsg();
      return details.map(t => `
        <div class="jwt-card">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <span class="chip chip--accent">${esc(t.name)}</span>
            ${t.confirmed_files && t.confirmed_files.length
              ? `<span class="badge badge--high">confirmado</span>` : ""}
          </div>
          ${t.evidence && t.evidence.length
            ? `<div class="dim" style="font-size:11px;margin-top:6px;">evidência: ${t.evidence.map(esc).join("; ")}</div>` : ""}
          ${t.confirmed_files && t.confirmed_files.length
            ? `<div style="margin-top:6px;font-size:11px;">arquivos característicos encontrados:<ul style="margin:4px 0 0 16px;">${
                t.confirmed_files.map(f => `<li><span style="color:var(--cyan)">${esc(f.path)}</span> (status ${esc(f.status_code)})</li>`).join("")
              }</ul></div>` : ""}
        </div>`).join("");
    }

    case "http":
      return redirectChainHtml(r.http && r.http.redirect_chain, r.final_url) +
        `<pre class="raw-json">${esc(JSON.stringify(r.http || {}, null, 2))}</pre>`;

    case "cookies":
      return dataTable(r.cookies, ["name", "http_only", "secure", "same_site", "domain", "path", "source_type"]);

    case "js_files":
      return dataTable(r.js_files, ["url", "size"]);

    case "endpoints":
      return renderEndpoints(r.endpoints || []);

    case "routes":
      return renderRoutes(r.routes || []);

    case "api_docs":
      return renderApiDocs(r.api_docs || []);

    case "robots":
      return renderRobots(r.robots_findings || [], r.sitemap_urls || []);

    case "env_vars":
      if (!r.env_vars || r.env_vars.length === 0) return emptyMsg();
      return r.env_vars.map(v => {
        const name = typeof v === "string" ? v : v.name;
        const sources = typeof v === "string" ? [] : (v.sources || []);
        return `
        <div class="jwt-card" style="padding:8px 12px;">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <span style="color:var(--cyan)">${esc(name)}</span>
            <button class="copy-btn" onclick="copyText('${esc(name)}', this)">copiar</button>
          </div>
          ${sources.length ? `<div class="dim" style="font-size:10.5px;margin-top:4px;">fonte: ${sources.map(esc).join(", ")}</div>` : ""}
        </div>`;
      }).join("");

    case "secrets":
      if (!r.secrets || r.secrets.length === 0) return emptyMsg();
      return `<div style="overflow-x:auto"><table class="data-table">
        <thead><tr><th>relevância</th><th>tipo</th><th>preview</th><th>origem</th><th>fonte</th></tr></thead>
        <tbody>${r.secrets.map(s => `<tr>
          <td>${badge(s.relevance)}</td>
          <td class="type-secret">${esc(s.type)}</td>
          <td>${esc(s.match_preview)}</td>
          <td class="dim">${esc(s.source_type)}</td>
          <td>${esc(s.source_file)}</td>
        </tr>`).join("")}</tbody>
      </table></div>`;

    case "jwts":
      if (!r.jwts || r.jwts.length === 0) return emptyMsg();
      return r.jwts.map(j => `
        <div class="jwt-card">
          <div class="jwt-card__source">${esc(j.source_type || "")} — ${esc(j.source_file)}</div>
          <div class="jwt-card__preview">${esc(j.token_preview)}</div>
          <pre>${esc(JSON.stringify(j.payload, null, 2))}</pre>
        </div>`).join("");

    case "storage_usage":
      if (!r.storage_usage || r.storage_usage.length === 0) return emptyMsg();
      return `<div style="overflow-x:auto"><table class="data-table">
        <thead><tr><th>relevância</th><th>api</th><th>método</th><th>chave</th><th>fonte</th></tr></thead>
        <tbody>${r.storage_usage.map(s => `<tr>
          <td>${badge(s.relevance)}</td>
          <td>${esc(s.api)}</td>
          <td>${esc(s.method)}</td>
          <td style="color:var(--cyan)">${esc(s.key)}</td>
          <td>${esc(s.source_file)}</td>
        </tr>`).join("")}</tbody>
      </table></div>`;

    case "pii":
      if (!r.pii || r.pii.length === 0) return emptyMsg();
      return `<div style="overflow-x:auto"><table class="data-table">
        <thead><tr><th>relevância</th><th>tipo</th><th>valor</th><th>origem</th><th>fonte</th></tr></thead>
        <tbody>${r.pii.map(p => `<tr>
          <td>${badge(p.relevance)}</td>
          <td class="type-pii">${esc(p.type)}</td>
          <td>${esc(p.value)}</td>
          <td class="dim">${esc(p.source_type)}</td>
          <td>${esc(p.source_file)}</td>
        </tr>`).join("")}</tbody>
      </table></div>`;

    case "external_domains":
      return chipList(r.external_domains);

    case "external_domain_recon":
      if (!r.external_domain_recon || r.external_domain_recon.length === 0) {
        return `<div class="empty-msg" style="font-size:12px;">nenhum reconhecimento realizado
          (ative "reconhecimento de domínios externos" nas opções avançadas antes de analisar)</div>`;
      }
      return r.external_domain_recon.map(d => `
        <div class="jwt-card">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <span class="chip">${esc(d.domain)}</span>
            <span class="dim">${d.reachable ? "status " + esc(d.status_code) : "inacessível"}</span>
          </div>
          ${d.error ? `<div class="dim" style="font-size:11px;margin-top:6px;">${esc(d.error)}</div>` : ""}
          ${redirectChainHtml(d.redirect_chain, d.final_url)}
          ${d.findings && d.findings.length ? `
            <div style="margin-top:8px;font-size:11.5px;">achados:
              <ul style="margin:4px 0 0 16px;">
                ${d.findings.map(f => `<li>[${esc(f.kind)}] <span style="color:var(--cyan)">${esc(f.url)}</span> (status ${esc(f.status_code)})</li>`).join("")}
              </ul>
            </div>` : ""}
        </div>`).join("");

    default:
      return emptyMsg();
  }
}

/* ------------------------------------------------------------
   endpoints: execução de requisições diretamente pelo frontend
   ------------------------------------------------------------ */
function endpointBaseUrl(path) {
  // caminhos relativos são resolvidos contra o alvo (ou destino final,
  // caso a análise tenha seguido redirecionamentos)
  if (/^https?:\/\//i.test(path)) return path;
  const base = (currentReport && (currentReport.final_url || currentReport.target)) || "";
  try {
    return new URL(path, base).toString();
  } catch {
    return path;
  }
}

function renderEndpoints(endpoints) {
  if (!endpoints || endpoints.length === 0) return emptyMsg();
  return endpoints.map((e, idx) => {
    const id = `ep-${idx}`;
    const methods = e.methods.join(", ");
    // paths relativos (ex.: "v1/applicants", vistos em clientes tipo
    // s.api.get("v1/applicants")) são ambíguos estaticamente — o backend
    // já gera as combinações mais prováveis em candidate_urls; quando há
    // mais de uma, mostramos um seletor em vez de adivinhar uma só.
    const candidates = (e.candidate_urls && e.candidate_urls.length) ? e.candidate_urls : [endpointBaseUrl(e.path)];
    const url = candidates[0];
    const ambiguous = candidates.length > 1;
    return `
    <div class="endpoint-row">
      <div class="endpoint-row__head">
        <span class="endpoint-row__path">${esc(e.path)}</span>
        <span class="endpoint-row__methods">${esc(methods)}</span>
        <span class="endpoint-row__module">módulo: ${esc(e.module)}</span>
        <button class="btn btn--tiny" onclick="toggleExecPanel('${id}')">executar</button>
        <button class="btn btn--tiny" onclick="inferMethods('${id}', document.getElementById('${id}-url').value)">inferir métodos</button>
      </div>
      <div id="${id}" class="exec-panel">
        ${ambiguous ? `
        <div class="dim" style="font-size:10.5px;margin-bottom:4px;">
          caminho relativo — o prefixo real depende do baseURL configurado em runtime (não visível estaticamente).
          escolha um candidato ou edite a URL manualmente:
          <select onchange="document.getElementById('${id}-url').value=this.value">
            ${candidates.map(c => `<option value="${esc(c)}">${esc(c)}</option>`).join("")}
          </select>
        </div>` : ""}
        <div class="exec-panel__row">
          <select id="${id}-method">
            ${["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].map(m =>
              `<option value="${m}" ${e.methods.includes(m) ? "selected" : ""}>${m}</option>`).join("")}
          </select>
          <input id="${id}-url" type="text" style="flex:1;min-width:220px;" value="${esc(url)}" />
          <button class="btn btn--tiny" onclick="runProbe('${id}')">[ enviar ]</button>
        </div>
        <textarea id="${id}-body" placeholder='corpo (JSON) — usado apenas em POST/PUT/PATCH/DELETE'></textarea>
        <div class="dim" style="font-size:10.5px;">
          os headers customizados definidos nas opções avançadas (Authorization, Cookie, etc.) são
          reutilizados automaticamente nesta requisição. respostas são automaticamente varridas
          por PII/secrets/JWT, mesmo quando não são JSON.
        </div>
        <div id="${id}-methods-result"></div>
        <div id="${id}-result"></div>
      </div>
    </div>`;
  }).join("");
}

function renderRoutes(routes) {
  if (!routes || routes.length === 0) return emptyMsg();
  // reaproveita o mesmo painel de execução dos endpoints (rotas de frontend
  // também podem ser testadas com GET para ver o que respondem)
  return routes.map((r, idx) => {
    const id = `rt-${idx}`;
    return `
    <div class="endpoint-row">
      <div class="endpoint-row__head">
        <span class="endpoint-row__path">${esc(r.path)}</span>
        ${r.has_param ? `<span class="endpoint-row__methods">tem parâmetro (ex.: :id)</span>` : ""}
        <span class="endpoint-row__module">chave(s): ${esc(r.keys.join(", "))}</span>
        <button class="btn btn--tiny" onclick="toggleExecPanel('${id}')">executar</button>
      </div>
      <div id="${id}" class="exec-panel">
        ${r.has_param ? `<div class="dim" style="font-size:10.5px;margin-bottom:4px;">
          esta rota tem um parâmetro na URL — substitua o placeholder pelo valor real antes de enviar.</div>` : ""}
        <div class="exec-panel__row">
          <select id="${id}-method"><option value="GET" selected>GET</option></select>
          <input id="${id}-url" type="text" style="flex:1;min-width:220px;" value="${esc(r.full_url)}" />
          <button class="btn btn--tiny" onclick="runProbe('${id}')">[ enviar ]</button>
        </div>
        <textarea id="${id}-body" placeholder="corpo (JSON) — normalmente não usado em rotas de frontend"></textarea>
        <div id="${id}-methods-result"></div>
        <div id="${id}-result"></div>
      </div>
    </div>`;
  }).join("");
}

function renderApiDocs(docs) {
  if (!docs || docs.length === 0) return emptyMsg();
  return `<div style="overflow-x:auto"><table class="data-table">
    <thead><tr><th>status</th><th>path</th><th>url</th><th>título</th><th># endpoints</th><th>nota</th></tr></thead>
    <tbody>${docs.map(d => `<tr>
      <td>${d.confirmed
        ? `<span class="badge badge--high">confirmado</span>`
        : `<span class="badge badge--medium">não confirmado</span>`}</td>
      <td>${esc(d.path)}</td>
      <td><span style="color:var(--cyan)">${esc(d.url)}</span></td>
      <td>${esc(d.title || "")}</td>
      <td>${d.endpoints_count != null ? esc(d.endpoints_count) : ""}</td>
      <td class="dim" style="font-size:10.5px;">${esc(d.note || "")}</td>
    </tr>`).join("")}</tbody>
  </table></div>`;
}

function renderRobots(findings, sitemapUrls) {
  const hasFindings = findings && findings.length > 0;
  const hasSitemap = sitemapUrls && sitemapUrls.length > 0;
  if (!hasFindings && !hasSitemap) return emptyMsg();
  let html = "";
  if (hasFindings) {
    html += `<div style="font-size:11px;margin-bottom:8px;" class="dim">
      caminhos declarados em robots.txt (Disallow/Allow) — o operador tentou mantê-los fora de
      motores de busca, o que os torna candidatos interessantes para inspeção manual.</div>`;
    html += `<div style="overflow-x:auto"><table class="data-table">
      <thead><tr><th>diretiva</th><th>path</th><th>url</th></tr></thead>
      <tbody>${findings.map(f => `<tr>
        <td>${f.directive === "Disallow" ? badge("high") : badge("low")} ${esc(f.directive)}</td>
        <td>${esc(f.path)}</td>
        <td><span style="color:var(--cyan)">${esc(f.full_url)}</span></td>
      </tr>`).join("")}</tbody>
    </table></div>`;
  }
  if (hasSitemap) {
    html += `<div style="font-size:11px;margin:12px 0 8px;" class="dim">URLs declaradas em sitemap.xml / robots.txt (Sitemap:):</div>`;
    html += chipList(sitemapUrls);
  }
  return html;
}

function toggleExecPanel(id) {
  document.getElementById(id).classList.toggle("is-open");
}

function statusClass(status) {
  if (!status) return "status-err";
  if (status < 300) return "status-ok";
  if (status < 500) return "status-warn";
  return "status-err";
}

async function runProbe(id) {
  const method = document.getElementById(`${id}-method`).value;
  const url = document.getElementById(`${id}-url`).value.trim();
  const body = document.getElementById(`${id}-body`).value.trim();
  const resultEl = document.getElementById(`${id}-result`);
  const customHeaders = parseHeadersText(document.getElementById("customHeaders").value);

  resultEl.innerHTML = `<div class="dim">a executar ${esc(method)} ${esc(url)}...</div>`;

  let res, data;
  try {
    res = await fetch(`${API_BASE}/api/probe`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, method, headers: customHeaders, body: body || null }),
    });
    data = await res.json();
  } catch (e) {
    resultEl.innerHTML = `<div class="exec-panel__result"><span class="status-err">falha ao contactar o backend</span></div>`;
    return;
  }

  if (data.error) {
    resultEl.innerHTML = `<div class="exec-panel__result"><span class="status-err">erro: ${esc(data.error)}</span></div>`;
    return;
  }

  let html = `<div class="exec-panel__result">
    <div class="exec-panel__meta">
      <span class="${statusClass(data.status_code)}">status ${esc(data.status_code)}</span>
      <span>${esc(data.elapsed_ms)} ms</span>
      <span>${data.is_json ? "JSON" : "não-JSON"}</span>
    </div>`;

  if (data.note) {
    html += `<div class="exec-panel__note">${esc(data.note)}</div>`;
  }

  if (data.redirect_chain && data.redirect_chain.length) {
    html += redirectChainHtml(data.redirect_chain, data.final_url);
  }

  if (data.is_json && data.json_analysis) {
    const a = data.json_analysis;
    const total = a.pii.length + a.secrets.length + a.jwts.length;
    if (total > 0) {
      html += `<div style="margin:8px 0;font-size:11.5px;"><span class="accent">análise automática do JSON:</span></div>`;
      if (a.secrets.length) {
        html += a.secrets.map(s => `<div>${badge(s.relevance)} <span class="type-secret">${esc(s.type)}</span>: ${esc(s.match_preview)}</div>`).join("");
      }
      if (a.pii.length) {
        html += a.pii.map(p => `<div>${badge(p.relevance)} <span class="type-pii">${esc(p.type)}</span>: ${esc(p.value)}</div>`).join("");
      }
      if (a.jwts.length) {
        html += a.jwts.map(j => `<div>JWT: ${esc(j.token_preview)}</div>`).join("");
      }
    }
  }

  html += `<div style="margin-top:8px;">
      <button class="copy-btn" onclick="copyText(${JSON.stringify(data.body_preview || "")}, this)">copiar corpo</button>
    </div>
    <pre class="raw-json" style="margin-top:6px;max-height:260px;overflow:auto;">${esc(data.body_preview || "")}</pre>
  </div>`;

  resultEl.innerHTML = html;
}

async function inferMethods(id, url) {
  const resultEl = document.getElementById(`${id}-methods-result`);
  const customHeaders = parseHeadersText(document.getElementById("customHeaders").value);
  resultEl.innerHTML = `<div class="dim">a inferir métodos suportados...</div>`;

  let res, data;
  try {
    res = await fetch(`${API_BASE}/api/probe/methods`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, headers: customHeaders }),
    });
    data = await res.json();
  } catch (e) {
    resultEl.innerHTML = `<div class="status-err">falha ao contactar o backend</div>`;
    return;
  }

  const source = data.via_options ? `via cabeçalho Allow (OPTIONS): ${esc(data.allow_header)}` : "via sondagem direta (OPTIONS indisponível)";
  const rows = Object.entries(data.methods || {}).map(([m, info]) => {
    const cls = info.inference && info.inference.includes("enabled") ? "status-ok" : info.inference === "inconclusive" ? "status-warn" : "status-err";
    return `<div><span style="color:var(--cyan)">${esc(m)}</span> — <span class="${cls}">${esc(info.inference)}</span>${info.status_code ? ` (status ${esc(info.status_code)})` : ""}</div>`;
  }).join("");

  resultEl.innerHTML = `<div class="exec-panel__result">
    <div class="dim" style="font-size:10.5px;margin-bottom:6px;">${source}</div>
    ${rows}
  </div>`;
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