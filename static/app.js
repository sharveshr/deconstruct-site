// App shell: hash router, sidebar, and the library pages
// (analyze, projects, uptime, history, saved reports, compare).
// Report rendering itself lives in report.js.

const view = $("#view");
let navToken = 0;           // bumps on every navigation so slow fetches don't paint over a newer page
let lastResult = null;      // most recent analysis, so returning to Analyze still shows it
let running = null;         // { url } while an analysis is in flight
let refreshTimer = null;

const SCORE_KEYS = [["performance", "Perf"], ["seo", "SEO"], ["accessibility", "A11y"], ["security", "Sec"]];
const steps = ["Fetching page", "Reading HTML", "Downloading stylesheets", "Measuring resources", "Checking TLS & headers",
  "Checking robots.txt & sitemap", "Rendering in Chromium", "Measuring Core Web Vitals", "Taking screenshots", "Checking color contrast", "Loading the mobile view"];

// ---------------------------------------------------------------- helpers

async function api(path, { method = "GET", body } = {}) {
  const r = await fetch(path, { method, headers: body ? { "Content-Type": "application/json" } : {}, body: body ? JSON.stringify(body) : undefined });
  const j = await r.json().catch(() => ({ ok: false, error: `Server error (HTTP ${r.status})` }));
  if (!j.ok) throw new Error(j.error || "Request failed.");
  return j.data;
}

function toast(msg, ms = 2800) {
  const t = $("#toast"); t.innerHTML = msg; t.classList.add("on");
  clearTimeout(t._h); t._h = setTimeout(() => t.classList.remove("on"), ms);
}

const scoreClass = v => v == null ? "" : v >= 85 ? "g" : v >= 60 ? "w" : "b";
const miniScores = s => s ? `<div class="mini-scores">${SCORE_KEYS.map(([k, l]) =>
  `<span class="ms ${scoreClass(s[k])}" title="${l} score"><small>${l}</small>${s[k] ?? "—"}</span>`).join("")}</div>` : '<span class="muted">Not analyzed yet</span>';
const statusDot = site => !site.monitor_enabled ? `<span class="sdot off" title="Not monitored"></span>`
  : `<span class="sdot ${site.last_status || ""}" title="${site.last_status ? site.last_status.toUpperCase() : "Waiting for first check"}"></span>`;
const pct = v => v == null ? "—" : (v >= 99.995 ? "100" : v.toFixed(2)) + "%";
const secs = ms => ms == null ? "—" : (ms / 1000).toFixed(2) + " s";
const localInputNow = () => new Date(Date.now() - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 16);
const loading = (text = "Loading…") => `<div class="wrap"><div class="status on" style="margin-top:40px"><div class="spinner"></div><span>${esc(text)}</span></div></div>`;
const errorBox = msg => `<div class="wrap"><div class="error" style="display:block;margin-top:30px">${esc(msg)}</div></div>`;
const parseHash = () => {
  const h = location.hash.replace(/^#/, "") || "/";
  const [path, qs] = h.split("?");
  return { parts: path.split("/").filter(Boolean), q: new URLSearchParams(qs || "") };
};

// ---------------------------------------------------------------- sidebar

async function refreshSidebar() {
  try {
    const [projects, sites] = await Promise.all([api("/api/projects"), api("/api/sites")]);
    const { parts } = parseHash();
    $("#side-projects").innerHTML = projects.length ? projects.slice(0, 12).map(p => `
      <a class="side-proj ${parts[0] === "projects" && +parts[1] === p.id ? "active" : ""}" href="#/projects/${p.id}">
        <svg class="ico" viewBox="0 0 24 24"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>
        <span class="nm">${esc(p.name)}</span>${p.sites_down ? `<span class="sdot down" title="${p.sites_down} down"></span>` : `<span class="n">${p.site_count}</span>`}</a>`).join("")
      + (projects.length > 12 ? `<a class="side-proj" href="#/projects"><span class="nm muted">All ${projects.length} projects…</span></a>` : "")
      : '<div class="side-empty">No projects yet</div>';
    const monitored = sites.filter(s => s.monitor_enabled), down = monitored.filter(s => s.last_status === "down");
    const badge = $("#down-badge");
    badge.hidden = !down.length; badge.textContent = down.length;
    $("#side-foot").innerHTML = `${sites.length} site${sites.length === 1 ? "" : "s"} saved<br>${monitored.length} monitored`
      + (down.length ? ` · <span style="color:var(--bad);font-weight:600">${down.length} down</span>` : monitored.length ? " · all up" : "")
      + (running ? `<br><span class="row" style="gap:6px;margin-top:4px"><span class="spinner" style="width:11px;height:11px"></span>Analyzing ${esc(running.url)}</span>` : "");
  } catch { /* sidebar is best-effort */ }
}

function setActiveNav(parts) {
  const route = parts[0] === "analyses" ? "history" : parts[0] || "analyze";
  document.querySelectorAll(".nav a").forEach(a => a.classList.toggle("active", a.dataset.route === route));
  $("#sidebar").classList.remove("open");
  $("#menu-btn").setAttribute("aria-expanded", "false");
}

$("#menu-btn").addEventListener("click", () => {
  const open = $("#sidebar").classList.toggle("open");
  $("#menu-btn").setAttribute("aria-expanded", String(open));
});

// ---------------------------------------------------------------- router

async function route() {
  if (location.search.includes("url=") && !location.hash) {   // old ?url= links
    const u = new URLSearchParams(location.search).get("url");
    history.replaceState(null, "", "/#/?url=" + encodeURIComponent(u));
  }
  const token = ++navToken;
  clearInterval(refreshTimer);
  const { parts, q } = parseHash();
  setActiveNav(parts);
  refreshSidebar();
  const [p0, p1] = parts;
  try {
    if (!p0 || p0 === "analyze") return pageAnalyze(q, token);
    if (p0 === "projects" && p1) return await pageProject(+p1, token);
    if (p0 === "projects") return await pageProjects(q, token);
    if (p0 === "sites" && p1) return await pageSite(+p1, q, token);
    if (p0 === "sites") return await pageSites(token);
    if (p0 === "history") return await pageHistory(q, token);
    if (p0 === "analyses" && p1) return await pageAnalysis(+p1, token);
    if (p0 === "compare") return await pageCompare(q, token);
    if (p0 === "osint") return await pageOsint(q, token);
    view.innerHTML = errorBox("Page not found.");
  } catch (e) {
    if (token === navToken) view.innerHTML = errorBox(e.message);
  }
}
window.addEventListener("hashchange", route);
const fresh = token => token === navToken;

// ---------------------------------------------------------------- analyze

async function pageAnalyze(q, token) {
  const projects = await api("/api/projects").catch(() => []);
  if (!fresh(token)) return;
  const preProject = q.get("project");
  view.innerHTML = `<div class="wrap">
    <section class="hero">
      <h1>See how any website is built.</h1>
      <p>Enter a URL to get its technology stack, design system, performance, SEO, accessibility and security. Every analysis is saved to History so you can come back to it or compare it later.</p>
      <form class="search" id="form">
        <label for="url" style="position:absolute;left:-9999px">Website URL</label>
        <input id="url" name="url" type="text" inputmode="url" autocomplete="url" placeholder="example.com" required>
        <button class="primary" id="go" type="submit">Analyze →</button>
      </form>
      <div class="examples">Try:
        ${["stripe.com", "github.com", "wordpress.org", "vercel.com"].map(u => `<button class="chip" type="button" data-url="${u}">${u}</button>`).join("")}
      </div>
      <div class="row" style="margin-top:12px;gap:18px">
        <label class="toggle" style="margin:0"><input type="checkbox" id="render" checked> Load in a real browser (screenshots, Core Web Vitals, contrast)</label>
        ${projects.length ? `<label class="toggle" style="margin:0">Save to project
          <select class="field" id="proj" style="padding:4px 8px;font-size:13px"><option value="">None</option>
          ${projects.map(p => `<option value="${p.id}" ${String(p.id) === preProject ? "selected" : ""}>${esc(p.name)}</option>`).join("")}</select></label>` : ""}
      </div>
    </section>
    <div class="status" id="status"><div class="spinner"></div><span id="status-text">Analyzing…</span></div>
    <div class="error" id="error" role="alert"></div>
    <div id="report"></div>
  </div>`;
  $("#form").addEventListener("submit", e => { e.preventDefault(); runAnalysis($("#url").value); });
  view.querySelectorAll(".chip").forEach(c => c.addEventListener("click", () => { $("#url").value = c.dataset.url; runAnalysis(c.dataset.url); }));

  const url = q.get("url");
  if (running) showRunning();
  else if (url && (!lastResult || lastResult.requested !== url)) { $("#url").value = url; runAnalysis(url); }
  else if (lastResult) { $("#url").value = lastResult.requested; showResult(lastResult, false); }
}

function showRunning() {
  if (!$("#status")) return;
  $("#url").value = running.url; $("#go").disabled = true;
  $("#status").classList.add("on"); $("#status-text").textContent = running.step + "…";
}

async function runAnalysis(url) {
  url = url.trim(); if (!url || running) return;
  const useBrowser = $("#render")?.checked ?? true;
  const projectId = $("#proj")?.value || null;
  running = { url, step: steps[0] };
  $("#error").style.display = "none"; $("#report").innerHTML = "";
  showRunning(); refreshSidebar();
  history.replaceState(null, "", "#/?url=" + encodeURIComponent(url));
  let i = 0;
  const last = useBrowser ? steps.length - 1 : 5;
  const tick = setInterval(() => {
    i = Math.min(i + 1, last); running.step = steps[i];
    if ($("#status-text")) $("#status-text").textContent = steps[i] + "…";
  }, useBrowser ? 1800 : 1200);
  try {
    const res = await api("/api/analyze", { method: "POST", body: { url, render: useBrowser, project_id: projectId } });
    lastResult = { ...res, requested: url };
    running = null;
    if ($("#report") && parseHash().parts[0] in { undefined: 1, analyze: 1 }) showResult(lastResult, true);
    else toast(`Analysis of <b>${esc(res.site.host)}</b> saved · <a href="#/analyses/${res.analysis_id}" style="color:inherit;text-decoration:underline">Open</a>`, 6000);
  } catch (err) {
    running = null;
    if ($("#error")) { $("#error").textContent = err.message; $("#error").style.display = "block"; }
    else toast(esc(err.message), 5000);
  } finally {
    clearInterval(tick);
    if ($("#status")) { $("#status").classList.remove("on"); $("#go").disabled = false; }
    refreshSidebar();
  }
}

async function showResult(res, scroll) {
  const root = $("#report");
  const projects = await api("/api/projects").catch(() => []);
  const actions = `<a class="ghost" href="#/osint?target=${encodeURIComponent(res.site.host)}">OSINT</a>
    ${res.iteration > 1 ? `<a class="ghost" href="#/compare?a=prev:${res.analysis_id}&b=${res.analysis_id}">Compare with previous</a>` : ""}
    ${projects.length ? `<select class="ghost" data-act="addproj" aria-label="Add to project"><option value="">Add to project…</option>
      ${projects.map(p => `<option value="${p.id}">${esc(p.name)}</option>`).join("")}</select>` : ""}`;
  renderReport(res.report, root, { analysis_id: res.analysis_id, iteration: res.iteration, site_id: res.site.id, created_at: res.created_at, actions });
  root.querySelector('[data-act="addproj"]')?.addEventListener("change", async e => {
    if (!e.target.value) return;
    await api(`/api/projects/${e.target.value}/sites`, { method: "POST", body: { site_id: res.site.id } });
    toast(`Added to <b>${esc(e.target.selectedOptions[0].textContent)}</b>`); e.target.value = ""; refreshSidebar();
  });
  if (scroll) root.scrollIntoView({ behavior: "smooth" });
}

// ---------------------------------------------------------------- saved report

async function pageAnalysis(id, token) {
  view.innerHTML = loading("Loading saved report…");
  const a = await api(`/api/analyses/${id}`);
  if (!fresh(token)) return;
  view.innerHTML = `<div class="wrap"><div class="crumbs" style="padding-top:22px"><a href="#/history">History</a> / <a href="#/sites/${a.site_id}">${esc(a.host)}</a> / Iteration ${a.iteration}</div><div id="report"></div></div>`;
  const actions = `<a class="ghost" href="#/?url=${encodeURIComponent(a.url)}">Analyze again</a>
    <a class="ghost" href="#/osint?target=${encodeURIComponent(a.host)}">OSINT</a>
    ${a.iteration > 1 ? `<a class="ghost" href="#/compare?a=prev:${a.id}&b=${a.id}">Compare with previous</a>` : ""}`;
  renderReport(a.report, $("#report"), { analysis_id: a.id, iteration: a.iteration, site_id: a.site_id, created_at: a.created_at, label: a.label, actions });
}

// ---------------------------------------------------------------- projects

async function pageProjects(q, token) {
  const projects = await api("/api/projects");
  if (!fresh(token)) return;
  view.innerHTML = `<div class="wrap">
    <div class="page-head"><div><h1>Projects</h1><p>Group websites you analyze together: a client's sites, competitors, or everything you're redesigning.</p></div></div>
    <section class="card" style="margin-bottom:16px"><h3>New project</h3>
      <form class="inline-form" id="new-proj">
        <input class="field grow" name="name" placeholder="Project name, e.g. Competitor research" required maxlength="120">
        <input class="field grow" name="description" placeholder="Description (optional)" maxlength="1000">
        <button class="btn dark" type="submit">Create project</button>
      </form></section>
    ${projects.length ? `<div class="proj-grid">${projects.map(p => `
      <a class="proj-card" href="#/projects/${p.id}">
        <h3>${esc(p.name)}</h3>${p.description ? `<p>${esc(p.description)}</p>` : ""}
        <div class="meta"><span>${p.site_count} site${p.site_count === 1 ? "" : "s"}</span>
        ${p.sites_down ? `<span style="color:var(--bad)"><span class="sdot down"></span> ${p.sites_down} down</span>` : ""}
        <span>Created ${esc(fmtTime(p.created_at))}</span></div></a>`).join("")}</div>`
      : `<div class="empty"><h3>No projects yet</h3><p>Create one above, then add websites to it.</p></div>`}
  </div>`;
  const f = $("#new-proj");
  if (q.get("new")) f.name.focus();
  f.addEventListener("submit", async e => {
    e.preventDefault();
    const p = await api("/api/projects", { method: "POST", body: { name: f.name.value, description: f.description.value } });
    location.hash = `#/projects/${p.id}`;
  });
}

async function pageProject(id, token) {
  if (!view.querySelector(".proj-page")) view.innerHTML = loading();
  const p = await api(`/api/projects/${id}`);
  if (!fresh(token)) return;
  const selected = new Set();
  view.innerHTML = `<div class="wrap proj-page">
    <div class="page-head"><div><div class="crumbs"><a href="#/projects">Projects</a></div>
      <h1 id="pname">${esc(p.name)}</h1><p id="pdesc">${esc(p.description || "No description")}</p></div>
      <div class="row"><button class="btn" id="rename">Edit</button>
        <button class="btn" id="analyze-all" ${p.sites.length ? "" : "disabled"}>Re-analyze all</button>
        <button class="btn" id="cmp" disabled title="Tick two sites to compare them">Compare selected</button>
        <button class="btn danger" id="del">Delete</button></div></div>
    <section class="card" style="margin-bottom:16px"><h3>Add a website</h3>
      <form class="inline-form" id="add-site">
        <input class="field grow" name="url" placeholder="example.com" required inputmode="url">
        <label class="toggle" style="margin:0"><input type="checkbox" name="now" checked> Analyze now</label>
        <button class="btn dark" type="submit">Add</button>
      </form>
      <div class="status" id="pstatus" style="margin:12px 0 0"><div class="spinner"></div><span id="pstatus-text"></span></div></section>
    ${p.sites.length ? `<div class="site-cards">${p.sites.map(s => {
      const l = s.latest;
      return `<article class="site-card" data-sid="${s.id}">
        <a class="thumb" href="${l ? `#/analyses/${l.id}` : `#/sites/${s.id}`}">${l?.thumb ? `<img src="${l.thumb}" alt="Screenshot of ${esc(s.host)}" loading="lazy">` : `<div class="ph">${l ? "No screenshot" : "Not analyzed yet"}</div>`}</a>
        <div class="body">
          <div class="host"><label title="Select to compare"><input type="checkbox" class="pick-site" value="${s.id}" ${l ? "" : "disabled"}></label>
            ${statusDot(s)}<a href="#/sites/${s.id}" style="color:inherit">${esc(s.host)}</a></div>
          <div class="title">${esc(l?.title || s.title || s.url)}</div>
          ${miniScores(l?.scores)}
          <div class="foot">${l ? `${s.iterations} iteration${s.iterations === 1 ? "" : "s"} · last ${esc(ago(l.created_at))}` : "No analyses"}
            ${s.monitor_enabled ? ` · ${pct(s.uptime_24h)} up (24h)` : ""}</div>
          <div class="row"><button class="btn sm" data-reanalyze="${esc(s.url)}">Analyze</button>
            <a class="btn sm" href="#/sites/${s.id}">History & uptime</a>
            <button class="btn sm danger" data-remove="${s.id}" title="Remove from project (keeps its history)">Remove</button></div>
        </div></article>`;
    }).join("")}</div>` : `<div class="empty"><h3>No websites in this project</h3><p>Add one above. It's analyzed and saved straight away.</p></div>`}
  </div>`;

  const status = (on, text = "") => { $("#pstatus").classList.toggle("on", on); $("#pstatus-text").textContent = text; };
  const analyzeOne = async (url, label) => {
    status(true, `${label}Analyzing ${url}… (10–20 s)`);
    try { await api("/api/analyze", { method: "POST", body: { url, project_id: id } }); }
    catch (e) { toast(`${esc(url)}: ${esc(e.message)}`, 5000); }
  };
  $("#add-site").addEventListener("submit", async e => {
    e.preventDefault();
    const f = e.target, url = f.url.value.trim();
    f.querySelector("button").disabled = true;
    if (f.now.checked) await analyzeOne(url, "");
    else await api(`/api/projects/${id}/sites`, { method: "POST", body: { url } }).catch(err => toast(esc(err.message)));
    status(false); if (fresh(token)) route();
  });
  $("#analyze-all").addEventListener("click", async e => {
    e.target.disabled = true;
    for (const [i, s] of p.sites.entries()) await analyzeOne(s.url, `${i + 1}/${p.sites.length} · `);
    status(false); toast("All sites re-analyzed"); if (fresh(token)) route();
  });
  view.querySelectorAll("[data-reanalyze]").forEach(b => b.addEventListener("click", async () => {
    b.disabled = true; await analyzeOne(b.dataset.reanalyze, ""); status(false); if (fresh(token)) route();
  }));
  view.querySelectorAll("[data-remove]").forEach(b => b.addEventListener("click", async () => {
    await api(`/api/projects/${id}/sites/${b.dataset.remove}`, { method: "DELETE" }); route();
  }));
  view.querySelectorAll(".pick-site").forEach(cb => cb.addEventListener("change", () => {
    cb.checked ? selected.add(+cb.value) : selected.delete(+cb.value);
    if (selected.size > 2) { const first = [...selected][0]; selected.delete(first); view.querySelector(`.pick-site[value="${first}"]`).checked = false; }
    $("#cmp").disabled = selected.size !== 2;
  }));
  $("#cmp").addEventListener("click", () => {
    const [a, b] = [...selected].map(sid => p.sites.find(s => s.id === sid).latest.id);
    location.hash = `#/compare?a=${a}&b=${b}`;
  });
  $("#rename").addEventListener("click", async () => {
    const name = prompt("Project name", p.name); if (name === null || !name.trim()) return;
    const description = prompt("Description", p.description || ""); if (description === null) return;
    await api(`/api/projects/${id}`, { method: "PATCH", body: { name, description } }); route();
  });
  $("#del").addEventListener("click", async () => {
    if (!confirm(`Delete the project "${p.name}"? Its websites, saved analyses and uptime history are kept.`)) return;
    await api(`/api/projects/${id}`, { method: "DELETE" }); location.hash = "#/projects";
  });
}

// ---------------------------------------------------------------- uptime list

async function pageSites(token) {
  const sites = await api("/api/sites");
  if (!fresh(token)) return;
  view.innerHTML = `<div class="wrap">
    <div class="page-head"><div><h1>Uptime</h1><p>Every website you've analyzed. Turn on monitoring to check it on a schedule and log when it goes down or comes back.</p></div></div>
    ${sites.length ? `<div class="data-table"><table><thead><tr><th>Status</th><th>Site</th><th>Uptime 24h</th><th>Last check</th><th>Checks every</th><th>Monitoring</th><th>Iterations</th></tr></thead><tbody>
      ${sites.map(s => `<tr class="click" data-href="#/sites/${s.id}?tab=uptime">
        <td>${statusDot(s)} <span style="margin-left:4px;font-size:13px">${s.monitor_enabled ? (s.last_status ? s.last_status.toUpperCase() : "Pending") : "Off"}</span></td>
        <td><b>${esc(s.host)}</b><div class="muted" style="font-size:12.5px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(s.title || s.url)}</div></td>
        <td>${s.monitor_enabled ? pct(s.uptime_24h) : '<span class="muted">—</span>'}</td>
        <td>${esc(s.last_checked_at ? ago(s.last_checked_at) : "never")}</td>
        <td>${s.monitor_interval_min} min</td>
        <td><label class="toggle" style="margin:0" onclick="event.stopPropagation()"><input type="checkbox" data-mon="${s.id}" ${s.monitor_enabled ? "checked" : ""}> On</label></td>
        <td>${s.iterations}</td></tr>`).join("")}</tbody></table></div>`
      : `<div class="empty"><h3>No websites yet</h3><p>Analyze a site and it shows up here.</p><a class="btn dark" href="#/">Analyze a website</a></div>`}
  </div>`;
  view.querySelectorAll("tr[data-href]").forEach(tr => tr.addEventListener("click", () => location.hash = tr.dataset.href));
  view.querySelectorAll("[data-mon]").forEach(cb => cb.addEventListener("change", async () => {
    await api(`/api/sites/${cb.dataset.mon}`, { method: "PATCH", body: { monitor_enabled: cb.checked } });
    toast(cb.checked ? "Monitoring on — first check within 15 s" : "Monitoring off"); refreshSidebar();
  }));
  refreshTimer = setInterval(() => fresh(token) && !document.hidden && route(), 30000);
}

// ---------------------------------------------------------------- site detail

async function pageSite(id, q, token) {
  const tab = q.get("tab") || "iterations";
  if (!view.querySelector(".site-page")) view.innerHTML = loading();
  const [s, projects] = await Promise.all([api(`/api/sites/${id}`), api("/api/projects")]);
  const checks = tab === "uptime" ? await api(`/api/sites/${id}/checks?days=${q.get("range") === "30d" ? 30 : 7}`) : [];
  if (!fresh(token)) return;
  const l = s.latest;
  const otherProjects = projects.filter(p => !s.projects.some(sp => sp.id === p.id));
  view.innerHTML = `<div class="wrap site-page">
    <div class="page-head"><div style="min-width:0"><div class="crumbs"><a href="#/sites">Uptime</a> / ${esc(s.host)}</div>
      <h1 class="row" style="gap:12px">${statusDot(s)}${esc(s.title || s.host)}</h1>
      <p>${link(s.url)} ${s.projects.map(p => `<a class="pill" href="#/projects/${p.id}">${esc(p.name)}</a>`).join(" ")}</p></div>
      <div class="row">
        ${otherProjects.length ? `<select class="field" id="addproj" style="padding:6px 8px;font-size:13px"><option value="">Add to project…</option>
          ${otherProjects.map(p => `<option value="${p.id}">${esc(p.name)}</option>`).join("")}</select>` : ""}
        <a class="btn" href="#/osint?target=${encodeURIComponent(s.host)}">OSINT</a>
        <a class="btn dark" href="#/?url=${encodeURIComponent(s.url)}">Analyze again</a>
        <button class="btn danger" id="del-site">Delete site</button></div></div>
    <nav class="subtabs">
      <a href="#/sites/${id}?tab=iterations" class="${tab === "iterations" ? "on" : ""}">Iterations (${s.iterations.length})</a>
      <a href="#/sites/${id}?tab=uptime" class="${tab === "uptime" ? "on" : ""}">Uptime & incidents</a></nav>
    <div id="tab-body">${tab === "uptime" ? renderUptimeTab(s, checks, q.get("range") || "7d") : renderIterationsTab(s)}</div>
  </div>`;

  $("#addproj")?.addEventListener("change", async e => {
    if (!e.target.value) return;
    await api(`/api/projects/${e.target.value}/sites`, { method: "POST", body: { site_id: id } }); route();
  });
  $("#del-site").addEventListener("click", async () => {
    if (!confirm(`Delete ${s.host} with all ${s.iterations.length} saved analyses and its uptime history? This can't be undone.`)) return;
    await api(`/api/sites/${id}`, { method: "DELETE" }); location.hash = "#/sites";
  });
  if (tab === "uptime") wireUptime(s, token); else wireIterations(s);
}

function scoreTrend(its) {
  if (its.length < 2) return "";
  const W = 640, H = 170, P = 26;
  const colors = { performance: "#1f5eff", seo: "#12805c", accessibility: "#b26a00", security: "#9b3dd1" };
  const x = i => P + (W - 2 * P) * i / (its.length - 1), y = v => H - P - (H - 2 * P) * v / 100;
  const grid = [0, 50, 100].map(v => `<line x1="${P}" x2="${W - P}" y1="${y(v)}" y2="${y(v)}" stroke="var(--line)"/><text x="${P - 6}" y="${y(v) + 4}" text-anchor="end" font-size="10" fill="var(--ink-3)">${v}</text>`).join("");
  const lines = SCORE_KEYS.map(([k]) => `<polyline fill="none" stroke="${colors[k]}" stroke-width="2" points="${its.map((it, i) => `${x(i)},${y(it.scores[k])}`).join(" ")}"/>
    ${its.map((it, i) => `<circle cx="${x(i)}" cy="${y(it.scores[k])}" r="3" fill="${colors[k]}"><title>#${it.iteration} ${k}: ${it.scores[k]}</title></circle>`).join("")}`).join("");
  const labels = its.map((it, i) => `<text x="${x(i)}" y="${H - 6}" text-anchor="middle" font-size="10" fill="var(--ink-3)">#${it.iteration}</text>`).join("");
  return card("Score trend", `<div class="chart"><svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Scores across iterations">${grid}${lines}${labels}</svg>
    <div class="legend">${SCORE_KEYS.map(([k, l]) => `<span><i style="background:${colors[k]}"></i>${l}</span>`).join("")}</div></div>`, "wide");
}

function renderIterationsTab(s) {
  const its = s.iterations;
  if (!its.length) return `<div class="empty"><h3>Not analyzed yet</h3><p>Run an analysis to start this site's history.</p><a class="btn dark" href="#/?url=${encodeURIComponent(s.url)}">Analyze now</a></div>`;
  return `<div class="grid" style="margin-bottom:12px">${scoreTrend(its)}</div>
    <div class="row" style="margin-bottom:10px;justify-content:space-between"><span class="muted" style="font-size:13px">Pick two iterations (A and B) to compare them.</span>
      <button class="btn" id="cmp-its" disabled>Compare A → B</button></div>
    <div class="data-table"><table><thead><tr><th>A</th><th>B</th><th>#</th><th>When</th><th>Label</th><th>Scores</th><th>LCP</th><th>Weight</th><th>Issues</th><th></th></tr></thead><tbody>
    ${[...its].reverse().map((it, idx) => `<tr>
      <td><input type="radio" name="ia" value="${it.id}" ${idx === 1 ? "checked" : ""} aria-label="Use #${it.iteration} as A"></td>
      <td><input type="radio" name="ib" value="${it.id}" ${idx === 0 ? "checked" : ""} aria-label="Use #${it.iteration} as B"></td>
      <td><b>${it.iteration}</b></td>
      <td style="white-space:nowrap">${esc(fmtTime(it.created_at))}<div class="muted" style="font-size:12px">${esc(ago(it.created_at))}</div></td>
      <td><button class="btn sm" data-label="${it.id}" data-cur="${esc(it.label)}">${it.label ? esc(it.label) : '<span class="muted">+ label</span>'}</button></td>
      <td>${miniScores(it.scores)}</td>
      <td>${it.vitals ? secs(it.vitals.lcp) : '<span class="muted">—</span>'}</td>
      <td>${bytes(it.page_bytes)}</td><td>${it.issue_count}</td>
      <td style="white-space:nowrap"><a class="btn sm" href="#/analyses/${it.id}">Open</a> <button class="btn sm danger" data-del="${it.id}" aria-label="Delete iteration ${it.iteration}">✕</button></td></tr>`).join("")}
    </tbody></table></div>`;
}

function wireIterations(s) {
  const btn = $("#cmp-its");
  if (!btn) return;
  const sync = () => {
    const a = view.querySelector('input[name="ia"]:checked')?.value, b = view.querySelector('input[name="ib"]:checked')?.value;
    btn.disabled = !a || !b || a === b; return [a, b];
  };
  view.querySelectorAll('input[name="ia"], input[name="ib"]').forEach(r => r.addEventListener("change", sync));
  sync();
  btn.addEventListener("click", () => { const [a, b] = sync(); location.hash = `#/compare?a=${a}&b=${b}`; });
  view.querySelectorAll("[data-label]").forEach(b => b.addEventListener("click", async () => {
    const label = prompt("Label this iteration (e.g. 'after redesign', 'v2 launch')", b.dataset.cur); if (label === null) return;
    await api(`/api/analyses/${b.dataset.label}`, { method: "PATCH", body: { label } }); route();
  }));
  view.querySelectorAll("[data-del]").forEach(b => b.addEventListener("click", async () => {
    if (!confirm("Delete this saved analysis?")) return;
    await api(`/api/analyses/${b.dataset.del}`, { method: "DELETE" }); route();
  }));
}

function uptimeStrip(checks, days) {
  const n = days <= 1 ? 48 : days <= 7 ? 84 : 90;
  const end = Date.now(), start = end - days * 86400000, size = (end - start) / n;
  const asc = [...checks].reverse();
  let state = null, k = 0;
  const cells = [];
  for (let i = 0; i < n; i++) {
    const bEnd = start + (i + 1) * size, seen = new Set();
    while (k < asc.length && new Date(asc[k].checked_at) < bEnd) { seen.add(asc[k].status); state = asc[k].status; k++; }
    const cls = seen.size > 1 ? "mixed" : seen.size ? [...seen][0] : state || "";
    const from = new Date(start + i * size);
    cells.push(`<i class="${cls}" title="${esc(from.toLocaleString(undefined, { dateStyle: "short", timeStyle: "short" }))} — ${cls ? cls.toUpperCase() : "no data"}"></i>`);
  }
  return `<div class="strip">${cells.join("")}</div><div class="strip-axis"><span>${days} day${days > 1 ? "s" : ""} ago</span><span>now</span></div>`;
}

function responseChart(checks) {
  const pts = [...checks].reverse().filter(c => c.response_ms != null && c.source === "auto");
  if (pts.length < 2) return '<span class="muted">Not enough automatic checks yet.</span>';
  const W = 640, H = 120, P = 6, max = Math.max(...pts.map(p => p.response_ms));
  const t0 = new Date(pts[0].checked_at), t1 = new Date(pts.at(-1).checked_at), span = Math.max(1, t1 - t0);
  const xy = pts.map(p => `${P + (W - 2 * P) * (new Date(p.checked_at) - t0) / span},${H - P - (H - 2 * P) * p.response_ms / max}`).join(" ");
  return `<div class="chart"><svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Response time"><polyline fill="none" stroke="var(--accent)" stroke-width="1.6" points="${xy}"/></svg>
    <div class="legend"><span>Peak ${max} ms</span><span>Latest ${pts.at(-1).response_ms} ms</span></div></div>`;
}

function renderUptimeTab(s, checks, range) {
  const u = s.uptime, days = range === "30d" ? 30 : 7;
  const incidents = u[range === "30d" ? "30d" : "7d"].incidents;
  return `
    <div class="grid" style="margin-bottom:12px">
      ${card("Current status", `<div class="big-status">${statusDot(s)}${s.monitor_enabled ? (s.last_status ? s.last_status.toUpperCase() : "Waiting for first check") : "Not monitored"}</div>
        <p class="muted" style="font-size:13px;margin:8px 0 14px">${s.last_change_at ? `Since ${esc(fmtTime(s.last_change_at))} (${esc(ago(s.last_change_at))})` : ""}${s.last_checked_at ? ` · Last check ${esc(ago(s.last_checked_at))}` : ""}</p>
        <div class="inline-form"><label class="toggle" style="margin:0"><input type="checkbox" id="mon" ${s.monitor_enabled ? "checked" : ""}> Monitor automatically</label>
          <select class="field" id="interval" aria-label="Check interval" style="padding:5px 8px;font-size:13px">${[1, 5, 15, 30, 60, 360, 1440].map(m => `<option value="${m}" ${m === s.monitor_interval_min ? "selected" : ""}>every ${m < 60 ? m + " min" : m / 60 + " h"}</option>`).join("")}</select>
          <button class="btn sm" id="check-now">Check now</button></div>`)}
      ${card("Log an event by hand", `<form class="inline-form" id="log-form" style="flex-direction:column;align-items:stretch">
          <div class="inline-form"><select class="field" name="status"><option value="down">Went down</option><option value="up">Came back up</option></select>
          <input class="field grow" type="datetime-local" name="at" value="${localInputNow()}" max="${localInputNow()}" required></div>
          <input class="field" name="note" placeholder="Note, e.g. 'DNS change', 'deploy #482 broke checkout'" maxlength="500">
          <button class="btn dark" type="submit" style="align-self:flex-start">Save event</button></form>`)}
    </div>
    <div class="stat-cards">${Object.entries(u).map(([k, v]) => `<div class="stat"><div class="v">${pct(v.uptime_pct)}</div><div class="k">Uptime ${k} · ${v.checks} checks</div></div>`).join("")}
      <div class="stat"><div class="v">${u["24h"].avg_response_ms != null ? u["24h"].avg_response_ms + " ms" : "—"}</div><div class="k">Avg response (24h)</div></div>
      <div class="stat"><div class="v">${incidents.length}</div><div class="k">Incidents (${days}d)</div></div></div>
    <div class="grid">
      ${card(`Status timeline`, `<div class="row" style="justify-content:flex-end;margin:-30px 0 10px">
        <a class="btn sm ${range !== "30d" ? "dark" : ""}" href="#/sites/${s.id}?tab=uptime&range=7d">7 days</a><a class="btn sm ${range === "30d" ? "dark" : ""}" href="#/sites/${s.id}?tab=uptime&range=30d">30 days</a></div>
        ${checks.length ? uptimeStrip(checks, days) : '<span class="muted">No checks yet. Turn on monitoring, click "Check now", or log an event.</span>'}`, "wide")}
      ${card("Response time", responseChart(checks), "wide")}
      ${card(`Incidents (${days} days)`, incidents.length ? `<div class="table-scroll"><table><thead><tr><th>Went down</th><th>Came back</th><th>Duration</th></tr></thead>
        ${incidents.map(i => `<tr><td>${esc(fmtTime(i.started_at))}</td><td>${i.ended_at ? esc(fmtTime(i.ended_at)) : '<span class="pill bad">Ongoing</span>'}</td><td>${duration(i.duration_s)}</td></tr>`).join("")}</table></div>`
        : '<div class="issue"><span class="dot good"></span><span>No downtime recorded in this period.</span></div>', "wide")}
      ${card(`Event log (${checks.length})`, checks.length ? `<div class="table-scroll" style="max-height:440px"><table><thead><tr><th>Time</th><th>Status</th><th>Source</th><th>HTTP</th><th>Response</th><th>Details</th><th></th></tr></thead>
        ${checks.map(c => `<tr><td style="white-space:nowrap">${esc(fmtTime(c.checked_at))}</td>
          <td><span class="pill ${c.status === "up" ? "good" : "bad"}">${c.status.toUpperCase()}</span></td>
          <td>${c.source === "manual" ? '<span class="pill warn">Manual</span>' : "Auto"}</td><td>${c.http_status ?? "—"}</td>
          <td>${c.response_ms != null ? c.response_ms + " ms" : "—"}</td><td style="overflow-wrap:anywhere">${esc(c.note || c.error || "")}</td>
          <td>${c.source === "manual" ? `<button class="btn sm danger" data-delcheck="${c.id}" aria-label="Delete event">✕</button>` : ""}</td></tr>`).join("")}</table></div>`
        : '<span class="muted">Nothing logged yet.</span>', "wide")}
    </div>`;
}

function wireUptime(s, token) {
  const patch = body => api(`/api/sites/${s.id}`, { method: "PATCH", body });
  $("#mon").addEventListener("change", async e => { await patch({ monitor_enabled: e.target.checked }); toast(e.target.checked ? "Monitoring on" : "Monitoring off"); route(); });
  $("#interval").addEventListener("change", async e => { await patch({ monitor_interval_min: +e.target.value }); toast("Interval saved"); });
  $("#check-now").addEventListener("click", async e => {
    e.target.disabled = true; e.target.textContent = "Checking…";
    const c = await api(`/api/sites/${s.id}/check-now`, { method: "POST" }).catch(err => (toast(esc(err.message)), null));
    if (c) toast(`${c.status.toUpperCase()} · ${c.http_status ?? c.error} · ${c.response_ms ?? "—"} ms`);
    route();
  });
  $("#log-form").addEventListener("submit", async e => {
    e.preventDefault();
    const f = e.target;
    await api(`/api/sites/${s.id}/checks`, { method: "POST", body: { status: f.status.value, at: new Date(f.at.value).toISOString(), note: f.note.value } })
      .then(() => { toast("Event saved"); route(); }).catch(err => toast(esc(err.message), 4000));
  });
  view.querySelectorAll("[data-delcheck]").forEach(b => b.addEventListener("click", async () => {
    if (!confirm("Delete this logged event?")) return;
    await api(`/api/checks/${b.dataset.delcheck}`, { method: "DELETE" }); route();
  }));
  refreshTimer = setInterval(() => fresh(token) && !document.hidden && !view.contains(document.activeElement?.closest("form")) && route(), 30000);
}

// ---------------------------------------------------------------- history

async function pageHistory(q, token) {
  const items = await api("/api/analyses?limit=500");
  if (!fresh(token)) return;
  const filter = (q.get("q") || "").toLowerCase();
  const shown = items.filter(i => !filter || i.host.includes(filter) || (i.title || "").toLowerCase().includes(filter) || (i.label || "").toLowerCase().includes(filter));
  const byDay = {};
  for (const i of shown) (byDay[new Date(i.created_at).toLocaleDateString(undefined, { weekday: "long", year: "numeric", month: "long", day: "numeric" })] ||= []).push(i);
  view.innerHTML = `<div class="wrap">
    <div class="page-head"><div><h1>History</h1><p>Every analysis you've run is saved here automatically: ${items.length} so far across ${new Set(items.map(i => i.site_id)).size} websites.</p></div>
      <form id="hsearch" class="inline-form"><input class="field" name="q" type="search" placeholder="Filter by site, title or label" value="${esc(q.get("q") || "")}" style="min-width:240px"></form></div>
    ${shown.length ? Object.entries(byDay).map(([day, list]) => `<div class="day-label">${esc(day)}</div>
      <div class="data-table"><table><tbody>${list.map(i => `<tr class="click" data-href="#/analyses/${i.id}">
        <td style="width:70px;white-space:nowrap" class="muted">${esc(new Date(i.created_at).toLocaleTimeString(undefined, { timeStyle: "short" }))}</td>
        <td style="min-width:200px"><b>${esc(i.host)}</b> <span class="pill">#${i.iteration}</span> ${i.label ? `<span class="pill warn">${esc(i.label)}</span>` : ""}
          <div class="muted" style="font-size:12.5px;max-width:360px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(i.title || i.final_url)}</div></td>
        <td>${miniScores(i.scores)}</td>
        <td class="muted" style="font-size:12.5px;white-space:nowrap">${i.tech.slice(0, 3).map(esc).join(", ")}${i.tech.length > 3 ? ` +${i.tech.length - 3}` : ""}</td>
        <td style="white-space:nowrap"><a class="btn sm" href="#/?url=${encodeURIComponent(i.url)}" onclick="event.stopPropagation()">Re-analyze</a></td></tr>`).join("")}</tbody></table></div>`).join("")
      : items.length ? `<div class="empty"><h3>No matches</h3><p>Nothing in your history matches "${esc(filter)}".</p></div>`
      : `<div class="empty"><h3>Nothing analyzed yet</h3><p>Analyses are saved here automatically.</p><a class="btn dark" href="#/">Analyze a website</a></div>`}
  </div>`;
  view.querySelectorAll("tr[data-href]").forEach(tr => tr.addEventListener("click", () => location.hash = tr.dataset.href));
  const f = $("#hsearch");
  let t;
  f.q.addEventListener("input", () => { clearTimeout(t); t = setTimeout(() => { history.replaceState(null, "", `#/history?q=${encodeURIComponent(f.q.value)}`); pageHistory(new URLSearchParams(`q=${f.q.value}`), navToken).then(() => { const i = $("#hsearch").q; i.focus(); i.setSelectionRange(i.value.length, i.value.length); }); }, 250); });
  f.addEventListener("submit", e => e.preventDefault());
}

// ---------------------------------------------------------------- compare

// [key, label, getter(diff), higherIsBetter, format]
const COMPARE_METRICS = [
  ["Scores", [
    ["performance", "Performance score", d => d.scores.performance, true, v => v],
    ["seo", "SEO score", d => d.scores.seo, true, v => v],
    ["accessibility", "Accessibility score", d => d.scores.accessibility, true, v => v],
    ["security", "Security score", d => d.scores.security, true, v => v],
  ]],
  ["Core Web Vitals (lab)", [
    ["lcp", "Largest Contentful Paint", d => d.vitals?.lcp, false, secs],
    ["fcp", "First Contentful Paint", d => d.vitals?.fcp, false, secs],
    ["tbt", "Total Blocking Time", d => d.vitals?.tbt, false, v => Math.round(v) + " ms"],
    ["cls", "Cumulative Layout Shift", d => d.vitals?.cls, false, v => v.toFixed(3)],
    ["ttfb", "Time to First Byte", d => d.vitals?.ttfb, false, secs],
  ]],
  ["Weight & speed", [
    ["page_bytes", "Page weight", d => d.metrics.page_bytes, false, bytes],
    ["requests", "Requests", d => d.metrics.requests, false, v => v],
    ["html_bytes", "HTML size", d => d.metrics.html_bytes, false, bytes],
    ["server_ms", "Server response", d => d.metrics.server_ms, false, v => v + " ms"],
  ]],
  ["Quality", [
    ["contrast_failures", "Text failing contrast", d => d.metrics.contrast_failures, false, v => v],
    ["words", "Words on page", d => d.metrics.words, null, v => v.toLocaleString()],
    ["css_variables", "CSS variables", d => d.metrics.css_variables, null, v => v],
  ]],
];

function vitalPair(d, key) {
  const v = d.vitals?.[key];
  return v ? { from: v.from, to: v.to } : { from: null, to: null };
}

async function pageCompare(q, token) {
  let a = q.get("a"), b = q.get("b");
  if (a?.startsWith("prev:")) {        // "compare with previous" links resolve the iteration before b
    const target = await api(`/api/analyses/${a.slice(5)}`);
    const its = await api(`/api/analyses?site_id=${target.site_id}`);
    const idx = its.findIndex(i => i.id === target.id);
    a = its[idx + 1]?.id;
    if (!a) throw new Error("There's no earlier iteration to compare with.");
    history.replaceState(null, "", `#/compare?a=${a}&b=${b}`);
  }
  const all = await api("/api/analyses?limit=500");
  if (!fresh(token)) return;
  const sites = [...new Map(all.map(i => [i.site_id, i.host])).entries()];
  const siteOf = id => all.find(i => i.id === +id)?.site_id;
  const picker = (name, sel) => {
    const sid = siteOf(sel) ?? sites[name === "a" ? 0 : Math.min(1, sites.length - 1)]?.[0];
    return `<label>${name === "a" ? "Website A" : "Website B"}
      <select class="field" data-site="${name}">${sites.map(([id, host]) => `<option value="${id}" ${id === sid ? "selected" : ""}>${esc(host)}</option>`).join("")}</select>
      <select class="field" data-it="${name}">${all.filter(i => i.site_id === sid).map(i => `<option value="${i.id}" ${i.id === +sel ? "selected" : ""}>#${i.iteration} · ${esc(fmtTime(i.created_at))}${i.label ? " · " + esc(i.label) : ""}</option>`).join("")}</select></label>`;
  };
  view.innerHTML = `<div class="wrap">
    <div class="page-head"><div><h1>Compare</h1><p>Put two websites side by side, or two iterations of the same site, on measured numbers: scores, Core Web Vitals, weight, requests and more.</p></div></div>
    ${all.length < 2 ? `<div class="empty"><h3>Analyze at least two websites first</h3><p>Every analysis is saved, so you can compare any two of them here.</p><a class="btn dark" href="#/">Analyze a website</a></div>` : `
    <form class="pick" id="pick">${picker("a", a)}${picker("b", b)}<button class="btn dark" type="submit">Compare</button></form>
    <div id="cmp-out" style="margin-top:16px">${a && b ? loading("Comparing…") : ""}</div>`}
  </div>`;
  if (all.length < 2) return;

  view.querySelectorAll("[data-site]").forEach(s => s.addEventListener("change", () => {
    const its = all.filter(i => i.site_id === +s.value);
    $(`[data-it="${s.dataset.site}"]`).innerHTML = its.map(i => `<option value="${i.id}">#${i.iteration} · ${esc(fmtTime(i.created_at))}${i.label ? " · " + esc(i.label) : ""}</option>`).join("");
  }));
  $("#pick").addEventListener("submit", e => {
    e.preventDefault();
    location.hash = `#/compare?a=${$('[data-it="a"]').value}&b=${$('[data-it="b"]').value}`;
  });
  if (!a || !b) return;
  if (a === b) { $("#cmp-out").innerHTML = '<div class="error" style="display:block">Pick two different analyses.</div>'; return; }
  const c = await api(`/api/compare?a=${a}&b=${b}`);
  if (!fresh(token)) return;
  $("#cmp-out").innerHTML = renderComparison(c);
}

function renderComparison(c) {
  const { diff: d, same_site: same } = c;
  const nameA = same ? `#${c.a.iteration}` : c.a.host, nameB = same ? `#${c.b.iteration}` : c.b.host;
  let winsA = 0, winsB = 0, ties = 0;
  const rows = COMPARE_METRICS.map(([group, metrics]) => {
    const body = metrics.map(([key, label, get, higher, fmt]) => {
      const pair = d.scores[key] || (["lcp", "fcp", "tbt", "cls", "ttfb"].includes(key) ? vitalPair(d, key) : d.metrics[key]);
      if (!pair || (pair.from == null && pair.to == null)) return "";
      const { from, to } = pair;
      let win = null;
      if (higher !== null && from != null && to != null) {
        const tol = key === "cls" ? 0.005 : Math.abs(from) * 0.02 + (key in d.scores ? 0.5 : 0);
        win = Math.abs(to - from) <= tol ? "tie" : (to > from) === higher ? "b" : "a";
        win === "a" ? winsA++ : win === "b" ? winsB++ : ties++;
      }
      const delta = from != null && to != null && to !== from
        ? `<span class="delta ${win === "b" ? "better" : win === "a" ? "worse" : "same"}">${to > from ? "+" : "−"}${fmt(Math.abs(to - from))}</span>` : "";
      return `<tr><td>${esc(label)}</td>
        <td class="${win === "a" ? "win" : ""}">${from == null ? "—" : fmt(from)}${win === "a" ? " ✓" : ""}</td>
        <td class="${win === "b" ? "win" : ""}">${to == null ? "—" : fmt(to)}${win === "b" ? " ✓" : ""}${same ? delta : ""}</td>
        <td class="muted" style="font-size:12.5px">${higher === null ? "info" : win === "tie" ? "tie" : win ? `${win === "a" ? esc(nameA) : esc(nameB)} ${higher ? "higher" : "lower"}` : "—"}</td></tr>`;
    }).join("");
    return body ? `<tr><th colspan="4" style="padding-top:18px">${esc(group)}</th></tr>${body}` : "";
  }).join("");
  const total = winsA + winsB + ties || 1;
  const counted = winsA + winsB + ties;
  const headline = same
    ? `${nameB} vs ${nameA}: better on ${winsB}, worse on ${winsA}, unchanged on ${ties} of ${counted} metrics`
    : winsA === winsB ? `Even: each wins ${winsA} of ${counted} metrics`
    : `${winsB > winsA ? nameB : nameA} wins ${Math.max(winsA, winsB)} of ${counted} metrics`;

  const side = (m, label, shot) => `<div class="side"><div class="lbl">${label}</div>
    <h3><a href="#/analyses/${m.id}" style="color:inherit">${esc(m.host)}</a> <span class="pill">#${m.iteration}</span></h3>
    <div class="muted" style="font-size:13px">${esc(m.title || "")}<br>${esc(fmtTime(m.created_at))}${m.label ? ` · ${esc(m.label)}` : ""}</div>
    ${shot ? `<div class="shot"><img src="${shot}" alt="Screenshot of ${esc(m.host)}"></div>` : ""}</div>`;
  const list = (items, tag, cls) => items.map(x => `<li><span class="${cls}">${tag}</span><span>${esc(x)}</span></li>`).join("");
  const words = same ? { onlyB: "Added", onlyA: "Removed", newI: "New", goneI: "Resolved" }
    : { onlyB: `Only ${nameB}`, onlyA: `Only ${nameA}`, newI: `Only ${nameB}`, goneI: `Only ${nameA}` };
  const t = d.tech, issueCats = Object.entries(d.issues);
  const techBody = `<ul class="diff-list">${list(t.added, words.onlyB, "tag-add")}${list(t.removed, words.onlyA, "tag-rm")}
      ${t.version_changed.map(v => `<li><span class="tag-ch">Version</span><span>${esc(v.name)}: ${esc(v.from)} → ${esc(v.to)}</span></li>`).join("")}</ul>
    ${t.unchanged.length ? `<p class="muted" style="font-size:13px;margin:10px 0 0">${same ? "Unchanged" : "Both use"}: ${t.unchanged.map(esc).join(", ")}</p>` : ""}`;
  const issuesBody = issueCats.map(([cat, v]) => (v.new.length || v.resolved.length || v.changed.length) ? `<div class="section-title" style="margin-top:10px">${esc(cat)}</div><ul class="diff-list">
      ${list(v.new, words.newI, "tag-rm")}${list(v.resolved, words.goneI, "tag-add")}
      ${v.changed.map(x => `<li><span class="tag-ch">Changed</span><span>${esc(x.from)} → ${esc(x.to)}</span></li>`).join("")}</ul>` : "").join("")
    || '<span class="muted">Same issues on both.</span>';
  const swatches = cols => cols.map(c => `<span class="mini" title="${esc(c)}" style="display:inline-block;background:${esc(c)};margin:0 4px 4px 0"></span>`).join("");

  return `
    <div class="vs">${side(c.a, same ? "Before (A)" : "Website A", d.screenshots.from)}${side(c.b, same ? "After (B)" : "Website B", d.screenshots.to)}</div>
    <section class="card" style="margin-top:12px"><h3>Scoreboard</h3>
      <div style="font-size:20px;font-weight:700;letter-spacing:-.02em">${esc(headline)}</div>
      <div class="winner-bar" aria-hidden="true"><i style="width:${winsA / total * 100}%;background:${same ? "var(--bad)" : "var(--accent)"}"></i><i style="width:${ties / total * 100}%;background:var(--line)"></i><i style="width:${winsB / total * 100}%;background:var(--good)"></i></div>
      <div class="muted" style="font-size:12.5px">${esc(nameA)} better on ${winsA} · tied ${ties} · ${esc(nameB)} better on ${winsB}. Differences under 2% count as a tie.</div>
      <div class="table-scroll" style="margin-top:12px"><table><thead><tr><th>Metric</th><th>${esc(nameA)}</th><th>${esc(nameB)}</th><th>Better</th></tr></thead><tbody>${rows}</tbody></table></div>
      <p class="muted" style="font-size:12.5px;margin:10px 0 0">Every number comes from the saved reports, so you can open either one to see where it came from. Vitals are single lab loads, so expect ±10–20% noise between runs.</p>
    </section>
    <div class="grid" style="margin-top:12px">
      ${card("Technology", techBody)}
      ${card(same ? "Issues: new and resolved" : "Issues only one site has", issuesBody)}
      ${card("Security headers", (d.security_headers.added.length || d.security_headers.removed.length) ? `<ul class="diff-list">${list(d.security_headers.added, words.onlyB, "tag-add")}${list(d.security_headers.removed, words.onlyA, "tag-rm")}</ul>` : '<span class="muted">Same security headers.</span>')}
      ${card("Design", kv([
        [`Colors ${same ? "added" : "only in " + nameB}`, swatches(d.design.colors_added) || "—"],
        [`Colors ${same ? "removed" : "only in " + nameA}`, swatches(d.design.colors_removed) || "—"],
        [`Fonts ${same ? "added" : "only in " + nameB}`, d.design.fonts_added.map(esc).join(", ") || "—"],
        [`Fonts ${same ? "removed" : "only in " + nameA}`, d.design.fonts_removed.map(esc).join(", ") || "—"]]))}
      ${Object.keys(d.content).length ? card("Content & server", kv(Object.entries(d.content).map(([k, v]) => [k.replace("_", " "), `${esc(v.from ?? "—")} <span class="muted">→</span> ${esc(v.to ?? "—")}`])), "wide") : ""}
    </div>`;
}

route();
setInterval(() => !document.hidden && refreshSidebar(), 30000);
