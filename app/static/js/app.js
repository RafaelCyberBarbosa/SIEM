const state = {
  eventsPage: 1,
  alertsPage: 1,
  ws: null,
};

// ---------- Auth / bootstrap ----------

function showApp() {
  document.getElementById("login-screen").classList.add("hidden");
  document.getElementById("app").classList.remove("hidden");
  const user = API.getUser();
  document.getElementById("current-user").textContent = `${user.username} (${user.role})`;
  if (user.role !== "admin") document.getElementById("nav-users").classList.add("hidden");
  window.addEventListener("hashchange", router);
  router();
}

function showLogin() {
  document.getElementById("app").classList.add("hidden");
  document.getElementById("login-screen").classList.remove("hidden");
}

document.getElementById("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = document.getElementById("login-username").value;
  const password = document.getElementById("login-password").value;
  const errEl = document.getElementById("login-error");
  errEl.textContent = "";
  try {
    await API.login(username, password);
    showApp();
  } catch (err) {
    errEl.textContent = err.message;
  }
});

document.getElementById("logout-btn").addEventListener("click", () => {
  API.clearToken();
  if (state.ws) state.ws.close();
  showLogin();
});

// ---------- Router ----------

const ROUTES = {
  dashboard: renderDashboard,
  events: renderEvents,
  alerts: renderAlerts,
  livetail: renderLiveTail,
  rules: renderRules,
  sources: renderSources,
  users: renderUsers,
};

function router() {
  const hash = window.location.hash.replace("#/", "") || "dashboard";
  const route = hash.split("?")[0];
  document.querySelectorAll(".sidebar nav a").forEach((a) => {
    a.classList.toggle("active", a.dataset.route === route);
  });
  const main = document.getElementById("main-content");
  main.innerHTML = "";
  const fn = ROUTES[route] || renderDashboard;
  fn(main);
}

// ---------- Dashboard ----------

async function renderDashboard(main) {
  main.innerHTML = `<h1 class="page-title">Dashboard</h1><div id="dash-body">A carregar...</div>`;
  let stats;
  try {
    stats = await API.get("/api/stats/dashboard");
  } catch (err) {
    document.getElementById("dash-body").innerHTML = `<div class="empty-state">Erro: ${escapeHtml(err.message)}</div>`;
    return;
  }

  const body = document.getElementById("dash-body");
  body.innerHTML = `
    <div class="stat-grid">
      <div class="stat-card"><div class="value">${stats.total_events_24h}</div><div class="label">Eventos (24h)</div></div>
      <div class="stat-card"><div class="value">${stats.total_events_1h}</div><div class="label">Eventos (1h)</div></div>
      <div class="stat-card"><div class="value" style="color:${stats.total_alerts_open ? "#eb5757" : "#37d67a"}">${stats.total_alerts_open}</div><div class="label">Alertas abertos</div></div>
      <div class="stat-card"><div class="value">${stats.sources_online}</div><div class="label">Fontes ativas (15m)</div></div>
    </div>
    <div class="panel-grid">
      <div class="panel">
        <h3>Volume de eventos (últimas 24h)</h3>
        <canvas id="timeline-chart" style="width:100%;height:220px;"></canvas>
      </div>
      <div class="panel">
        <h3>Alertas abertos por severidade</h3>
        <canvas id="severity-donut" style="width:100%;height:180px;"></canvas>
        <div id="severity-legend" style="margin-top:10px;font-size:12px;"></div>
      </div>
    </div>
    <div class="panel-grid">
      <div class="panel">
        <h3>Top IPs de origem (24h)</h3>
        <div class="table-wrap">${renderSimpleTable(stats.top_src_ips, ["src_ip", "count"], ["IP", "Eventos"])}</div>
      </div>
      <div class="panel">
        <h3>Top hosts (24h)</h3>
        <div class="table-wrap">${renderSimpleTable(stats.top_hosts, ["host", "count"], ["Host", "Eventos"])}</div>
      </div>
    </div>
    <div class="panel">
      <h3>Eventos por categoria (24h)</h3>
      <div class="table-wrap">${renderSimpleTable(
        Object.entries(stats.events_by_category).map(([category, count]) => ({ category, count })),
        ["category", "count"], ["Categoria", "Eventos"]
      )}</div>
    </div>
  `;

  drawBarChart(
    document.getElementById("timeline-chart"),
    stats.events_timeline.map((p) => p.hour),
    stats.events_timeline.map((p) => p.count)
  );
  drawDonutChart(document.getElementById("severity-donut"), stats.alerts_by_severity, SEVERITY_COLORS);
  document.getElementById("severity-legend").innerHTML = Object.entries(stats.alerts_by_severity)
    .map(([k, v]) => `<div style="display:flex;justify-content:space-between;padding:2px 0;"><span><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${SEVERITY_COLORS[k]};margin-right:6px;"></span>${k}</span><span>${v}</span></div>`)
    .join("");
}

function renderSimpleTable(rows, keys, headers) {
  if (!rows.length) return `<div class="empty-state">Sem dados</div>`;
  return `<table><thead><tr>${headers.map((h) => `<th>${h}</th>`).join("")}</tr></thead><tbody>
    ${rows.map((r) => `<tr>${keys.map((k) => `<td>${escapeHtml(r[k])}</td>`).join("")}</tr>`).join("")}
  </tbody></table>`;
}

// ---------- Events ----------

async function renderEvents(main) {
  main.innerHTML = `
    <h1 class="page-title">Explorador de Eventos</h1>
    <div class="filter-bar">
      <input id="f-q" placeholder="Pesquisar mensagem/host/IP/utilizador...">
      <select id="f-category"><option value="">Categoria (todas)</option>
        ${["authentication","network","process","file","malware","web","system","account_management","other"].map(c=>`<option value="${c}">${c}</option>`).join("")}
      </select>
      <select id="f-severity"><option value="">Severidade (todas)</option>
        ${["info","low","medium","high","critical"].map(s=>`<option value="${s}">${s}</option>`).join("")}
      </select>
      <select id="f-outcome"><option value="">Resultado (todos)</option>
        <option value="success">success</option><option value="failure">failure</option><option value="unknown">unknown</option>
      </select>
      <button class="btn" id="f-search">Pesquisar</button>
    </div>
    <div id="events-body">A carregar...</div>
  `;
  document.getElementById("f-search").addEventListener("click", () => { state.eventsPage = 1; loadEvents(); });
  document.getElementById("f-q").addEventListener("keydown", (e) => { if (e.key === "Enter") { state.eventsPage = 1; loadEvents(); } });
  await loadEvents();
}

async function loadEvents() {
  const q = document.getElementById("f-q").value;
  const category = document.getElementById("f-category").value;
  const severity = document.getElementById("f-severity").value;
  const outcome = document.getElementById("f-outcome").value;
  const params = new URLSearchParams({ page: state.eventsPage, page_size: 50 });
  if (q) params.set("q", q);
  if (category) params.set("category", category);
  if (severity) params.set("severity", severity);
  if (outcome) params.set("outcome", outcome);

  const body = document.getElementById("events-body");
  try {
    const data = await API.get("/api/events?" + params.toString());
    body.innerHTML = `
      <div class="table-wrap"><table>
        <thead><tr><th>Hora</th><th>Severidade</th><th>Categoria</th><th>Ação</th><th>Host</th><th>Utilizador</th><th>Origem</th><th>Mensagem</th></tr></thead>
        <tbody>${data.items.map(ev => `
          <tr class="clickable" onclick='showEventModal(${JSON.stringify(ev.id)})'>
            <td class="small">${fmtDate(ev.timestamp)}</td>
            <td>${severityBadge(ev.severity)}</td>
            <td>${escapeHtml(ev.category)}</td>
            <td>${escapeHtml(ev.action)}</td>
            <td>${escapeHtml(ev.host)}</td>
            <td>${escapeHtml(ev.user)}</td>
            <td class="mono">${escapeHtml(ev.src_ip)}</td>
            <td>${escapeHtml((ev.message || "").slice(0, 90))}</td>
          </tr>`).join("")}
        </tbody>
      </table></div>
      <div class="pagination">
        <button class="btn secondary" id="prev-page">&laquo; Anterior</button>
        <span>Página ${state.eventsPage} — ${data.total} eventos</span>
        <button class="btn secondary" id="next-page">Seguinte &raquo;</button>
      </div>
    `;
    if (!data.items.length) body.querySelector(".table-wrap").innerHTML = `<div class="empty-state">Sem eventos encontrados</div>`;
    document.getElementById("prev-page").addEventListener("click", () => { if (state.eventsPage > 1) { state.eventsPage--; loadEvents(); } });
    document.getElementById("next-page").addEventListener("click", () => { if ((state.eventsPage) * 50 < data.total) { state.eventsPage++; loadEvents(); } });
    window._eventCache = {};
    data.items.forEach(ev => window._eventCache[ev.id] = ev);
  } catch (err) {
    body.innerHTML = `<div class="empty-state">Erro: ${escapeHtml(err.message)}</div>`;
  }
}

function showEventModal(id) {
  const ev = window._eventCache[id];
  if (!ev) return;
  openModal(`
    <h2>Detalhe do evento</h2>
    <div class="kv-list">
      <div class="k">Hora</div><div>${fmtDate(ev.timestamp)}</div>
      <div class="k">Severidade</div><div>${severityBadge(ev.severity)}</div>
      <div class="k">Categoria</div><div>${escapeHtml(ev.category)}</div>
      <div class="k">Ação</div><div>${escapeHtml(ev.action)}</div>
      <div class="k">Resultado</div><div>${escapeHtml(ev.outcome)}</div>
      <div class="k">Host</div><div>${escapeHtml(ev.host)}</div>
      <div class="k">Utilizador</div><div>${escapeHtml(ev.user)}</div>
      <div class="k">IP origem</div><div class="mono">${escapeHtml(ev.src_ip)}${ev.src_port ? ":" + ev.src_port : ""}</div>
      <div class="k">IP destino</div><div class="mono">${escapeHtml(ev.dst_ip)}${ev.dst_port ? ":" + ev.dst_port : ""}</div>
      <div class="k">Fonte</div><div>${escapeHtml(ev.source_type)}</div>
      <div class="k">Tags</div><div>${(ev.tags||[]).map(t=>`<span class="badge sev-medium">${escapeHtml(t)}</span>`).join(" ")}</div>
    </div>
    <p><b>Mensagem</b></p>
    <pre class="raw-block">${escapeHtml(ev.message)}</pre>
    <p><b>Dados adicionais (JSON)</b></p>
    <pre class="raw-block">${escapeHtml(JSON.stringify(ev.extra, null, 2))}</pre>
    <p><b>Linha bruta (raw)</b></p>
    <pre class="raw-block">${escapeHtml(ev.raw)}</pre>
    <div class="modal-actions">
      <button class="btn secondary" onclick="closeModal()">Fechar</button>
      <button class="btn" onclick='showTimeline("event", ${JSON.stringify(ev.id)})'>Ver cadeia de ataque</button>
    </div>
  `);
}

// ---------- Alerts ----------

async function renderAlerts(main) {
  main.innerHTML = `
    <h1 class="page-title">Alertas</h1>
    <div class="filter-bar">
      <select id="af-status"><option value="">Estado (todos)</option>
        <option value="open">open</option><option value="acknowledged">acknowledged</option>
        <option value="resolved">resolved</option><option value="closed">closed</option>
      </select>
      <select id="af-severity"><option value="">Severidade (todas)</option>
        ${["info","low","medium","high","critical"].map(s=>`<option value="${s}">${s}</option>`).join("")}
      </select>
      <button class="btn" id="af-search">Pesquisar</button>
    </div>
    <div id="alerts-body">A carregar...</div>
  `;
  document.getElementById("af-search").addEventListener("click", () => { state.alertsPage = 1; loadAlerts(); });
  await loadAlerts();
}

async function loadAlerts() {
  const status = document.getElementById("af-status").value;
  const severity = document.getElementById("af-severity").value;
  const params = new URLSearchParams({ page: state.alertsPage, page_size: 50 });
  if (status) params.set("status", status);
  if (severity) params.set("severity", severity);

  const body = document.getElementById("alerts-body");
  try {
    const data = await API.get("/api/alerts?" + params.toString());
    window._alertCache = {};
    data.items.forEach(a => window._alertCache[a.id] = a);
    body.innerHTML = `
      <div class="table-wrap"><table>
        <thead><tr><th>Criado</th><th>Severidade</th><th>Título</th><th>Regra</th><th>MITRE</th><th>Estado</th><th>Eventos</th><th></th></tr></thead>
        <tbody>${data.items.map(a => `
          <tr>
            <td class="small">${fmtDate(a.created_at)}</td>
            <td>${severityBadge(a.severity)}</td>
            <td class="clickable" onclick='showAlertModal(${JSON.stringify(a.id)})'>${escapeHtml(a.title)}</td>
            <td class="mono small">${escapeHtml(a.rule_key)}</td>
            <td class="small">${escapeHtml(a.mitre)}</td>
            <td class="status-${a.status}">${a.status}</td>
            <td>${(a.event_ids||[]).length}</td>
            <td><button class="btn secondary" onclick='showAlertModal(${JSON.stringify(a.id)})'>Ver</button></td>
          </tr>`).join("")}
        </tbody>
      </table></div>
      <div class="pagination">
        <button class="btn secondary" id="a-prev">&laquo; Anterior</button>
        <span>Página ${state.alertsPage} — ${data.total} alertas</span>
        <button class="btn secondary" id="a-next">Seguinte &raquo;</button>
      </div>
    `;
    if (!data.items.length) body.querySelector(".table-wrap").innerHTML = `<div class="empty-state">Sem alertas encontrados</div>`;
    document.getElementById("a-prev").addEventListener("click", () => { if (state.alertsPage > 1) { state.alertsPage--; loadAlerts(); } });
    document.getElementById("a-next").addEventListener("click", () => { if (state.alertsPage * 50 < data.total) { state.alertsPage++; loadAlerts(); } });
  } catch (err) {
    body.innerHTML = `<div class="empty-state">Erro: ${escapeHtml(err.message)}</div>`;
  }
}

async function showAlertModal(id) {
  const a = window._alertCache[id];
  if (!a) return;
  let events = [];
  try { events = await API.get(`/api/alerts/${id}/events`); } catch (e) {}
  openModal(`
    <h2>${escapeHtml(a.title)}</h2>
    <div class="kv-list">
      <div class="k">Severidade</div><div>${severityBadge(a.severity)}</div>
      <div class="k">Regra</div><div class="mono">${escapeHtml(a.rule_key)}</div>
      <div class="k">MITRE ATT&amp;CK</div><div>${escapeHtml(a.mitre)}</div>
      <div class="k">Estado</div><div class="status-${a.status}">${a.status}</div>
      <div class="k">Chave de grupo</div><div class="mono">${escapeHtml(a.group_key)}</div>
      <div class="k">Criado</div><div>${fmtDate(a.created_at)}</div>
      <div class="k">Atualizado</div><div>${fmtDate(a.updated_at)}</div>
    </div>
    <p>${escapeHtml(a.description)}</p>
    <p><b>Contexto</b></p>
    <pre class="raw-block">${escapeHtml(JSON.stringify(a.context, null, 2))}</pre>
    <p><b>Eventos relacionados (${events.length})</b></p>
    <div class="table-wrap"><table><thead><tr><th>Hora</th><th>Host</th><th>IP</th><th>Mensagem</th></tr></thead>
    <tbody>${events.slice(0,20).map(ev => `<tr><td class="small">${fmtDate(ev.timestamp)}</td><td>${escapeHtml(ev.host)}</td><td class="mono">${escapeHtml(ev.src_ip)}</td><td>${escapeHtml((ev.message||"").slice(0,70))}</td></tr>`).join("")}</tbody></table></div>
    <div class="modal-actions">
      <select id="alert-status-select">
        ${["open","acknowledged","resolved","closed"].map(s=>`<option value="${s}" ${s===a.status?"selected":""}>${s}</option>`).join("")}
      </select>
      <button class="btn" onclick='updateAlertStatus(${JSON.stringify(a.id)})'>Atualizar estado</button>
      <button class="btn secondary" onclick="closeModal()">Fechar</button>
      <button class="btn" onclick='showTimeline("alert", ${JSON.stringify(a.id)})'>Ver cadeia de ataque</button>
    </div>
  `);
}

// ---------- Attack chain timeline ----------

async function showTimeline(anchorType, anchorId) {
  let data;
  try {
    data = await API.get(`/api/timeline/${anchorType}/${anchorId}?window_minutes=120`);
  } catch (err) {
    toast(err.message, "error");
    return;
  }

  const entityLabel = { src_ip: "IP de origem", host: "Host", user: "Utilizador", none: "" }[data.entity_type] || data.entity_type;

  openModal(`
    <h2>Cadeia de ataque</h2>
    <p class="small">
      ${data.entity_type !== "none" ? `${entityLabel}: <span class="mono">${escapeHtml(data.entity_value)}</span> — ` : ""}
      janela de ${fmtDate(data.window_start)} a ${fmtDate(data.window_end)}
    </p>
    ${data.mitre_techniques.length ? `<div style="margin-bottom:14px;">${data.mitre_techniques.map(m => `<span class="badge sev-high" style="margin-right:6px;">${escapeHtml(m)}</span>`).join("")}</div>` : ""}
    <div class="timeline">
      ${data.items.map(item => `
        <div class="timeline-item ${item.is_anchor ? "anchor" : ""}">
          <div class="timeline-dot sev-dot-${item.severity}"></div>
          <div class="timeline-content">
            <div class="timeline-head">
              <span class="small mono">${fmtDate(item.timestamp)}</span>
              ${severityBadge(item.severity)}
              <span class="badge" style="background:${item.type === "alert" ? "rgba(255,37,89,.12)" : "rgba(46,230,214,.1)"};color:${item.type === "alert" ? "#ff5c81" : "#2ee6d6"};">${item.type === "alert" ? "ALERTA" : "EVENTO"}</span>
            </div>
            <div class="timeline-title">${escapeHtml(item.title)}${item.detail.mitre ? ` <span class="small">(${escapeHtml(item.detail.mitre)})</span>` : ""}</div>
            <div class="small">${escapeHtml(item.detail.message || item.detail.description || "")}</div>
          </div>
        </div>
      `).join("")}
    </div>
    <div class="modal-actions"><button class="btn secondary" onclick="closeModal()">Fechar</button></div>
  `, "wide");
}

async function updateAlertStatus(id) {
  const status = document.getElementById("alert-status-select").value;
  try {
    await API.patch(`/api/alerts/${id}`, { status });
    toast("Alerta atualizado", "success");
    closeModal();
    loadAlerts();
  } catch (err) {
    toast(err.message, "error");
  }
}

// ---------- Live Tail ----------

function renderLiveTail(main) {
  main.innerHTML = `
    <h1 class="page-title">Live Tail</h1>
    <div class="live-feed" id="live-feed"><div class="small">A ligar...</div></div>
  `;
  connectWebSocket();
}

function connectWebSocket() {
  if (state.ws) state.ws.close();
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${window.location.host}/ws/live?token=${encodeURIComponent(API.getToken())}`);
  state.ws = ws;
  const feed = document.getElementById("live-feed");
  ws.onopen = () => { if (feed) feed.innerHTML = `<div class="small">Ligado. À espera de eventos...</div>`; };
  ws.onmessage = (msg) => {
    const payload = JSON.parse(msg.data);
    if (!document.getElementById("live-feed")) return; // navigated away
    const line = document.createElement("div");
    line.className = "live-line";
    if (payload.type === "event") {
      const ev = payload.data;
      line.innerHTML = `<span class="ts">${fmtDate(ev.timestamp)}</span><span class="host">${escapeHtml(ev.host)}</span><span>${severityBadge(ev.severity)}</span><span>${escapeHtml(ev.category)}/${escapeHtml(ev.action)}</span><span>${escapeHtml((ev.message||"").slice(0,120))}</span>`;
    } else if (payload.type === "alert") {
      const al = payload.data;
      line.innerHTML = `<span class="ts">${fmtDate(al.created_at)}</span><span style="color:#eb5757">🚨 ALERTA</span>${severityBadge(al.severity)}<span>${escapeHtml(al.title)}</span>`;
    }
    document.getElementById("live-feed").prepend(line);
  };
  ws.onclose = () => { if (document.getElementById("live-feed")) document.getElementById("live-feed").insertAdjacentHTML("afterbegin", `<div class="small">Ligação fechada.</div>`); };
}

// ---------- Rules ----------

async function renderRules(main) {
  main.innerHTML = `
    <h1 class="page-title">Regras de Deteção</h1>
    <button class="btn" id="new-rule-btn" style="margin-bottom:14px;">+ Nova regra</button>
    <div id="rules-body">A carregar...</div>
  `;
  document.getElementById("new-rule-btn").addEventListener("click", () => showRuleModal(null));
  await loadRules();
}

async function loadRules() {
  const body = document.getElementById("rules-body");
  try {
    const rules = await API.get("/api/rules");
    window._ruleCache = {};
    rules.forEach(r => window._ruleCache[r.id] = r);
    body.innerHTML = `<div class="table-wrap"><table>
      <thead><tr><th>Nome</th><th>Tipo</th><th>Severidade</th><th>MITRE</th><th>Ativa</th><th></th></tr></thead>
      <tbody>${rules.map(r => `
        <tr>
          <td class="clickable" onclick='showRuleModal(${JSON.stringify(r.id)})'>${escapeHtml(r.name)}${r.is_builtin ? ' <span class="small">(built-in)</span>' : ""}</td>
          <td>${escapeHtml(r.type)}</td>
          <td>${severityBadge(r.severity)}</td>
          <td class="small">${escapeHtml(r.mitre)}</td>
          <td><input type="checkbox" ${r.enabled ? "checked" : ""} onchange='toggleRule(${JSON.stringify(r.id)}, this.checked)'></td>
          <td><button class="btn secondary" onclick='showRuleModal(${JSON.stringify(r.id)})'>Editar</button></td>
        </tr>`).join("")}
      </tbody></table></div>`;
  } catch (err) {
    body.innerHTML = `<div class="empty-state">Erro: ${escapeHtml(err.message)}</div>`;
  }
}

async function toggleRule(id, enabled) {
  try {
    await API.patch(`/api/rules/${id}`, { enabled });
    toast("Regra atualizada", "success");
  } catch (err) {
    toast(err.message, "error");
  }
}

function showRuleModal(id) {
  const r = id ? window._ruleCache[id] : null;
  openModal(`
    <h2>${r ? "Editar regra" : "Nova regra"}</h2>
    <div class="field-row"><label>Chave única (rule_key)</label><input id="rule-key" value="${r ? escapeHtml(r.rule_key) : ""}" ${r ? "disabled" : ""}></div>
    <div class="field-row"><label>Nome</label><input id="rule-name" value="${r ? escapeHtml(r.name) : ""}"></div>
    <div class="field-row"><label>Descrição</label><input id="rule-desc" value="${r ? escapeHtml(r.description) : ""}"></div>
    <div class="field-row"><label>Tipo</label>
      <select id="rule-type" ${r ? "disabled" : ""}>
        <option value="threshold" ${r && r.type === "threshold" ? "selected" : ""}>threshold (contagem numa janela)</option>
        <option value="match" ${r && r.type === "match" ? "selected" : ""}>match (evento único)</option>
        <option value="sequence" ${r && r.type === "sequence" ? "selected" : ""}>sequence (dois passos)</option>
      </select>
    </div>
    <div class="field-row"><label>Severidade</label>
      <select id="rule-severity">${["info","low","medium","high","critical"].map(s=>`<option value="${s}" ${r && r.severity===s?"selected":""}>${s}</option>`).join("")}</select>
    </div>
    <div class="field-row"><label>MITRE ATT&amp;CK</label><input id="rule-mitre" value="${r ? escapeHtml(r.mitre) : ""}"></div>
    <div class="field-row"><label>Definição (JSON) — ex: {"filter":{"category":"authentication","action":"login_failure"},"group_by":"src_ip","threshold":5,"window_seconds":120}</label>
      <textarea id="rule-definition">${r ? escapeHtml(JSON.stringify(r.definition, null, 2)) : '{\n  "filter": {},\n  "group_by": "src_ip",\n  "threshold": 5,\n  "window_seconds": 60\n}'}</textarea>
    </div>
    <div class="modal-actions">
      ${r && !r.is_builtin ? `<button class="btn danger" onclick='deleteRule(${JSON.stringify(r.id)})'>Eliminar</button>` : ""}
      <button class="btn secondary" onclick="closeModal()">Cancelar</button>
      <button class="btn" onclick='saveRule(${JSON.stringify(id)})'>Guardar</button>
    </div>
  `);
}

async function saveRule(id) {
  let definition;
  try {
    definition = JSON.parse(document.getElementById("rule-definition").value);
  } catch (e) {
    toast("JSON de definição inválido", "error");
    return;
  }
  const payload = {
    name: document.getElementById("rule-name").value,
    description: document.getElementById("rule-desc").value,
    severity: document.getElementById("rule-severity").value,
    definition,
  };
  try {
    if (id) {
      await API.patch(`/api/rules/${id}`, payload);
    } else {
      payload.rule_key = document.getElementById("rule-key").value;
      payload.type = document.getElementById("rule-type").value;
      payload.mitre = document.getElementById("rule-mitre").value;
      payload.enabled = true;
      await API.post("/api/rules", payload);
    }
    toast("Regra guardada", "success");
    closeModal();
    loadRules();
  } catch (err) {
    toast(err.message, "error");
  }
}

async function deleteRule(id) {
  if (!confirm("Eliminar esta regra?")) return;
  try {
    await API.del(`/api/rules/${id}`);
    toast("Regra eliminada", "success");
    closeModal();
    loadRules();
  } catch (err) {
    toast(err.message, "error");
  }
}

// ---------- Sources ----------

async function renderSources(main) {
  main.innerHTML = `
    <h1 class="page-title">Fontes de Log</h1>
    <div class="panel" style="margin-bottom:16px;">
      <h3>Registar nova fonte</h3>
      <div class="filter-bar">
        <input id="src-name" placeholder="Nome (ex: web-server-1)">
        <select id="src-type">
          <option value="http">http</option><option value="agent-linux">agent-linux</option>
          <option value="agent-windows">agent-windows</option><option value="file">file</option><option value="syslog">syslog</option>
        </select>
        <input id="src-desc" placeholder="Descrição (opcional)">
        <button class="btn" id="src-create">Criar</button>
      </div>
    </div>
    <div id="sources-body">A carregar...</div>
  `;
  document.getElementById("src-create").addEventListener("click", async () => {
    const name = document.getElementById("src-name").value.trim();
    if (!name) return toast("Indique um nome", "error");
    try {
      await API.post("/api/sources", { name, type: document.getElementById("src-type").value, description: document.getElementById("src-desc").value });
      toast("Fonte criada", "success");
      loadSources();
    } catch (err) { toast(err.message, "error"); }
  });
  await loadSources();
}

async function loadSources() {
  const body = document.getElementById("sources-body");
  try {
    const sources = await API.get("/api/sources");
    body.innerHTML = `<div class="table-wrap"><table>
      <thead><tr><th>Nome</th><th>Tipo</th><th>API Key</th><th>Eventos</th><th>Última atividade</th><th></th></tr></thead>
      <tbody>${sources.map(s => `
        <tr>
          <td>${escapeHtml(s.name)}</td>
          <td>${escapeHtml(s.type)}</td>
          <td class="mono small">${escapeHtml(s.api_key)}</td>
          <td>${s.event_count}</td>
          <td class="small">${s.last_seen_at ? fmtDate(s.last_seen_at) : "nunca"}</td>
          <td><button class="btn secondary" onclick='rotateKey(${JSON.stringify(s.id)})'>Rodar chave</button>
              <button class="btn danger" onclick='deleteSource(${JSON.stringify(s.id)})'>Eliminar</button></td>
        </tr>`).join("")}
      </tbody></table></div>`;
    if (!sources.length) body.innerHTML = `<div class="empty-state">Sem fontes registadas. O listener de syslog cria a sua fonte automaticamente ao receber o primeiro log.</div>`;
  } catch (err) {
    body.innerHTML = `<div class="empty-state">Erro: ${escapeHtml(err.message)}</div>`;
  }
}

async function rotateKey(id) {
  try { await API.post(`/api/sources/${id}/rotate-key`); toast("Chave rodada", "success"); loadSources(); }
  catch (err) { toast(err.message, "error"); }
}
async function deleteSource(id) {
  if (!confirm("Eliminar esta fonte?")) return;
  try { await API.del(`/api/sources/${id}`); toast("Fonte eliminada", "success"); loadSources(); }
  catch (err) { toast(err.message, "error"); }
}

// ---------- Users ----------

async function renderUsers(main) {
  if (API.getUser().role !== "admin") {
    main.innerHTML = `<div class="empty-state">Acesso restrito a administradores.</div>`;
    return;
  }
  main.innerHTML = `
    <h1 class="page-title">Utilizadores</h1>
    <div class="panel" style="margin-bottom:16px;">
      <h3>Criar utilizador</h3>
      <div class="filter-bar">
        <input id="u-username" placeholder="Utilizador">
        <input id="u-email" placeholder="Email">
        <input id="u-password" type="password" placeholder="Palavra-passe">
        <select id="u-role"><option value="analyst">analyst</option><option value="admin">admin</option><option value="viewer">viewer</option></select>
        <button class="btn" id="u-create">Criar</button>
      </div>
    </div>
    <div id="users-body">A carregar...</div>
  `;
  document.getElementById("u-create").addEventListener("click", async () => {
    try {
      await API.post("/api/users", {
        username: document.getElementById("u-username").value,
        email: document.getElementById("u-email").value,
        password: document.getElementById("u-password").value,
        role: document.getElementById("u-role").value,
      });
      toast("Utilizador criado", "success");
      loadUsers();
    } catch (err) { toast(err.message, "error"); }
  });
  await loadUsers();
}

async function loadUsers() {
  const body = document.getElementById("users-body");
  try {
    const users = await API.get("/api/users");
    body.innerHTML = `<div class="table-wrap"><table>
      <thead><tr><th>Utilizador</th><th>Email</th><th>Perfil</th><th>Ativo</th><th>Criado</th><th></th></tr></thead>
      <tbody>${users.map(u => `
        <tr>
          <td>${escapeHtml(u.username)}</td><td>${escapeHtml(u.email)}</td><td>${escapeHtml(u.role)}</td>
          <td>${u.is_active ? "sim" : "não"}</td><td class="small">${fmtDate(u.created_at)}</td>
          <td><button class="btn danger" onclick='deleteUser(${JSON.stringify(u.id)})'>Eliminar</button></td>
        </tr>`).join("")}
      </tbody></table></div>`;
  } catch (err) {
    body.innerHTML = `<div class="empty-state">Erro: ${escapeHtml(err.message)}</div>`;
  }
}

async function deleteUser(id) {
  if (!confirm("Eliminar este utilizador?")) return;
  try { await API.del(`/api/users/${id}`); toast("Utilizador eliminado", "success"); loadUsers(); }
  catch (err) { toast(err.message, "error"); }
}

// ---------- Modal helpers ----------

function openModal(html, variant) {
  closeModal();
  const overlay = document.createElement("div");
  overlay.className = "modal-overlay";
  overlay.id = "modal-overlay";
  overlay.innerHTML = `<div class="modal${variant === "wide" ? " modal-wide" : ""}">${html}</div>`;
  overlay.addEventListener("click", (e) => { if (e.target === overlay) closeModal(); });
  document.body.appendChild(overlay);
}
function closeModal() {
  const el = document.getElementById("modal-overlay");
  if (el) el.remove();
}

// ---------- Bootstrap ----------
// Runs last so it can safely reference ROUTES/router/showApp, all defined above.

if (API.getToken() && API.getUser()) {
  showApp();
} else {
  showLogin();
}
