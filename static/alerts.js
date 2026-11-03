// Alerts page: the activity feed of detected changes, notification channels,
// and per-site watch schedules. renderEvents() is also used on site pages.

const SEV_LABEL = { critical: "Critical", warning: "Warning", info: "Info" };
const HOURS_LABEL = h => h === 0 ? "Off" : h < 24 ? `Every ${h} h` : h === 24 ? "Daily" : h === 72 ? "Every 3 days" : h === 168 ? "Weekly" : `Every ${h} h`;
const CHANNEL_KINDS = {
  slack: ["Slack", "https://hooks.slack.com/services/…", "Create an Incoming Webhook in Slack (Apps → Incoming Webhooks) and paste its URL."],
  discord: ["Discord", "https://discord.com/api/webhooks/…", "Channel settings → Integrations → Webhooks → New webhook → Copy URL."],
  webhook: ["Webhook", "https://your-endpoint.example/alerts", "Receives a JSON POST for each event: {app, url, event:{kind, severity, title, detail…}}."],
  email: ["Email", "you@example.com, team@example.com", "Uses the SMTP server set in SMTP_HOST / SMTP_PORT / SMTP_USER / SMTP_PASSWORD / SMTP_FROM."],
};

function eventHref(e) {
  const l = e.detail?.links || {};
  if (l.compare) return `#/compare?a=${l.compare[0]}&b=${l.compare[1]}`;
  if (l.analysis) return `#/analyses/${l.analysis}`;
  if (l.uptime) return `#/sites/${l.uptime}?tab=uptime`;
  if (l.osint) return `#/osint?target=${encodeURIComponent(l.osint)}`;
  if (l.site) return `#/sites/${l.site}`;
  return null;
}

function renderEvents(events, { showTarget = true } = {}) {
  if (!events.length) return "";
  return `<div class="events">${events.map(e => {
    const href = eventHref(e), lines = (e.detail?.lines || []).filter(Boolean);
    const sent = e.notified?.length ? e.notified.map(n => `<span class="pill ${n.ok ? "good" : "bad"}" title="${esc(n.ok ? "Delivered" : n.error || "Failed")}">${n.ok ? "✓" : "✕"} ${esc(n.name)}</span>`).join(" ") : "";
    return `<article class="event sev-${e.severity} ${e.read ? "" : "unread"}" data-eid="${e.id}">
      <span class="sev-bar" aria-hidden="true"></span>
      <div class="ev-main">
        <div class="ev-top"><span class="pill sev-pill-${e.severity}">${SEV_LABEL[e.severity]}</span>
          <b class="ev-title">${href ? `<a href="${href}">${esc(e.title)}</a>` : esc(e.title)}</b></div>
        ${lines.length ? `<ul class="ev-lines">${lines.slice(0, 6).map(l => `<li>${esc(l)}</li>`).join("")}${lines.length > 6 ? `<li class="muted">…and ${lines.length - 6} more</li>` : ""}</ul>` : ""}
        <div class="ev-meta"><span title="${esc(fmtTime(e.created_at))}">${esc(ago(e.created_at))}</span>
          ${showTarget && (e.site_host || e.target) ? `· ${e.site_id ? `<a href="#/sites/${e.site_id}">${esc(e.site_host || e.target)}</a>` : `<a href="#/osint?target=${encodeURIComponent(e.target)}">${esc(e.target)}</a>`}` : ""}
          ${sent ? `· ${sent}` : ""}</div>
      </div>
      <button class="btn sm ev-read" data-read="${e.id}" data-state="${e.read ? 1 : 0}" title="${e.read ? "Mark unread" : "Mark read"}" aria-label="${e.read ? "Mark unread" : "Mark read"}">${e.read ? "○" : "●"}</button>
    </article>`;
  }).join("")}</div>`;
}

function wireEvents(root, onChange) {
  root.querySelectorAll("[data-read]").forEach(b => b.addEventListener("click", async () => {
    await api("/api/events/read", { method: "POST", body: { ids: [+b.dataset.read], read: b.dataset.state !== "1" } });
    refreshSidebar(); onChange?.();
  }));
  // Opening an event marks it read.
  root.querySelectorAll(".ev-title a").forEach(a => a.addEventListener("click", () => {
    const id = +a.closest("[data-eid]").dataset.eid;
    api("/api/events/read", { method: "POST", body: { ids: [id] } }).then(refreshSidebar);
  }));
}

// ---------------------------------------------------------------- page

async function pageAlerts(q, token) {
  const tab = q.get("tab") || "activity";
  view.innerHTML = `<div class="wrap">
    <div class="page-head"><div><h1>Alerts</h1>
      <p>Changes detected between runs: downtime, expiring certificates and domains, new subdomains, DNS and email-policy changes, removed security headers, score drops and more.</p></div></div>
    <nav class="subtabs">
      <a href="#/alerts" class="${tab === "activity" ? "on" : ""}">Activity</a>
      <a href="#/alerts?tab=channels" class="${tab === "channels" ? "on" : ""}">Channels</a>
      <a href="#/alerts?tab=watching" class="${tab === "watching" ? "on" : ""}">Watching</a></nav>
    <div id="alerts-body">${loading().replace('class="wrap"', "")}</div></div>`;
  if (tab === "channels") return alertsChannels(token);
  if (tab === "watching") return alertsWatching(token);
  return alertsActivity(q, token);
}

async function alertsActivity(q, token) {
  const severity = q.get("severity") || "info", unread = q.get("unread") === "1", site = q.get("site") || "";
  const [events, sites] = await Promise.all([
    api(`/api/events?severity=${severity}${unread ? "&unread=1" : ""}${site ? `&site_id=${site}` : ""}&limit=100`),
    api("/api/sites")]);
  if (!fresh(token)) return;
  const setQ = (k, v) => { const p = new URLSearchParams(q); v ? p.set(k, v) : p.delete(k); location.hash = `#/alerts?${p}`; };
  $("#alerts-body").innerHTML = `
    <div class="row" style="justify-content:space-between;margin-bottom:12px">
      <div class="row">
        <select class="field" id="f-sev" aria-label="Minimum severity"><option value="info">All severities</option>
          <option value="warning" ${severity === "warning" ? "selected" : ""}>Warning and critical</option>
          <option value="critical" ${severity === "critical" ? "selected" : ""}>Critical only</option></select>
        <select class="field" id="f-site" aria-label="Site"><option value="">All sites</option>
          ${sites.map(s => `<option value="${s.id}" ${String(s.id) === site ? "selected" : ""}>${esc(s.host)}</option>`).join("")}</select>
        <label class="toggle" style="margin:0"><input type="checkbox" id="f-unread" ${unread ? "checked" : ""}> Unread only</label>
      </div>
      <div class="row"><button class="btn" id="read-all">Mark all read</button><button class="btn danger" id="clear-all">Clear all</button></div>
    </div>
    <div id="ev-list">${events.length ? renderEvents(events) : `<div class="empty"><h3>No alerts${unread || severity !== "info" || site ? " match these filters" : " yet"}</h3>
      <p>Alerts appear when a new analysis, OSINT lookup or uptime check differs from the previous one.
      Set up <a href="#/alerts?tab=watching">scheduled watching</a> so that happens automatically, and add a <a href="#/alerts?tab=channels">channel</a> to be notified.</p></div>`}</div>
    ${events.length === 100 ? `<div style="text-align:center;margin-top:12px"><button class="btn" id="more">Load older</button></div>` : ""}`;
  $("#f-sev").addEventListener("change", e => setQ("severity", e.target.value === "info" ? "" : e.target.value));
  $("#f-site").addEventListener("change", e => setQ("site", e.target.value));
  $("#f-unread").addEventListener("change", e => setQ("unread", e.target.checked ? "1" : ""));
  $("#read-all").addEventListener("click", async () => { await api("/api/events/read", { method: "POST", body: { all: true } }); refreshSidebar(); route(); });
  $("#clear-all").addEventListener("click", async () => {
    if (!confirm("Delete every alert in the activity feed? Channels and watch settings are kept.")) return;
    await api("/api/events/delete", { method: "POST", body: { all: true } }); refreshSidebar(); route();
  });
  wireEvents($("#ev-list"), () => route());
  $("#more")?.addEventListener("click", async e => {
    const last = events.at(-1).id;
    const older = await api(`/api/events?severity=${severity}${unread ? "&unread=1" : ""}${site ? `&site_id=${site}` : ""}&before=${last}&limit=100`);
    e.target.remove();
    const holder = document.createElement("div"); holder.innerHTML = renderEvents(older);
    $("#ev-list").append(holder); wireEvents(holder);
  });
  refreshTimer = setInterval(() => fresh(token) && !document.hidden && route(), 60000);
}

async function alertsChannels(token) {
  const { channels, email_configured, app_url } = await api("/api/channels");
  if (!fresh(token)) return;
  const shortTarget = c => c.kind === "email" ? c.target : (() => { try { const u = new URL(c.target); return `${u.host}/…${c.target.slice(-6)}`; } catch { return c.target; } })();
  $("#alerts-body").innerHTML = `
    <section class="card" style="margin-bottom:16px"><h3>Add a channel</h3>
      <form class="inline-form" id="ch-form" style="flex-direction:column;align-items:stretch">
        <div class="inline-form">
          <select class="field" name="kind" aria-label="Channel type">${Object.entries(CHANNEL_KINDS).map(([k, [l]]) => `<option value="${k}">${l}</option>`).join("")}</select>
          <input class="field" name="name" placeholder="Name (optional)" maxlength="80" style="width:180px">
          <input class="field grow" name="target" required>
          <select class="field" name="min_severity" aria-label="Minimum severity">
            <option value="critical">Critical only</option><option value="warning" selected>Warning and critical</option><option value="info">Everything</option></select>
          <button class="btn dark" type="submit">Add channel</button></div>
        <div class="muted" id="ch-help" style="font-size:12.5px"></div>
      </form></section>
    ${!email_configured ? `<div class="issue" style="margin-bottom:12px"><span class="dot"></span><span style="font-size:13.5px">Email channels need an SMTP server. Set <span class="mono">SMTP_HOST</span>, <span class="mono">SMTP_PORT</span>, <span class="mono">SMTP_USER</span>, <span class="mono">SMTP_PASSWORD</span> and <span class="mono">SMTP_FROM</span> before starting the app. Slack, Discord and webhooks work without setup.</span></div>` : ""}
    ${channels.length ? `<div class="data-table"><table><thead><tr><th>Channel</th><th>Sends</th><th>Status</th><th>On</th><th></th></tr></thead><tbody>
      ${channels.map(c => `<tr data-cid="${c.id}">
        <td><b>${esc(c.name)}</b> <span class="pill">${esc(CHANNEL_KINDS[c.kind][0])}</span><div class="muted mono" style="font-size:11.5px">${esc(shortTarget(c))}</div></td>
        <td><select class="field" data-sev style="padding:4px 8px;font-size:13px">${["critical", "warning", "info"].map(s => `<option value="${s}" ${c.min_severity === s ? "selected" : ""}>${s === "critical" ? "Critical only" : s === "warning" ? "Warning +" : "Everything"}</option>`).join("")}</select></td>
        <td style="font-size:12.5px">${c.last_error ? `<span class="pill bad" title="${esc(c.last_error)}">Failed</span> <span class="muted">${esc(c.last_error.slice(0, 70))}</span>` : c.last_sent_at ? `<span class="pill good">Sent</span> <span class="muted">${esc(ago(c.last_sent_at))}</span>` : '<span class="muted">Nothing sent yet</span>'}</td>
        <td><input type="checkbox" data-enabled ${c.enabled ? "checked" : ""} aria-label="Enabled"></td>
        <td style="white-space:nowrap"><button class="btn sm" data-test>Send test</button> <button class="btn sm danger" data-del aria-label="Delete channel">✕</button></td></tr>`).join("")}
      </tbody></table></div>` : `<div class="empty"><h3>No channels yet</h3><p>Add Slack, Discord, a webhook or email above to be notified when something changes.</p></div>`}
    <p class="muted" style="font-size:12.5px;margin-top:12px">Links in notifications point to <span class="mono">${esc(app_url)}</span>. Set the <span class="mono">APP_URL</span> environment variable if the app is reachable at another address.</p>`;
  const f = $("#ch-form");
  const help = () => { const [, ph, h] = CHANNEL_KINDS[f.kind.value]; f.target.placeholder = ph; f.target.type = f.kind.value === "email" ? "text" : "url"; $("#ch-help").textContent = h; };
  f.kind.addEventListener("change", help); help();
  f.addEventListener("submit", async e => {
    e.preventDefault();
    try {
      await api("/api/channels", { method: "POST", body: { kind: f.kind.value, name: f.name.value, target: f.target.value, min_severity: f.min_severity.value } });
      toast("Channel added. Use <b>Send test</b> to check it."); route();
    } catch (err) { toast(esc(err.message), 5000); }
  });
  view.querySelectorAll("tr[data-cid]").forEach(tr => {
    const id = tr.dataset.cid, patch = body => api(`/api/channels/${id}`, { method: "PATCH", body });
    tr.querySelector("[data-sev]").addEventListener("change", e => patch({ min_severity: e.target.value }).then(() => toast("Saved")));
    tr.querySelector("[data-enabled]").addEventListener("change", e => patch({ enabled: e.target.checked }).then(() => toast(e.target.checked ? "Channel on" : "Channel paused")));
    tr.querySelector("[data-test]").addEventListener("click", async e => {
      e.target.disabled = true; e.target.textContent = "Sending…";
      try { await api(`/api/channels/${id}/test`, { method: "POST" }); toast("Test notification sent"); }
      catch (err) { toast(esc(err.message), 6000); }
      route();
    });
    tr.querySelector("[data-del]").addEventListener("click", async () => {
      if (!confirm("Delete this channel?")) return;
      await api(`/api/channels/${id}`, { method: "DELETE" }); route();
    });
  });
}

async function alertsWatching(token) {
  const [{ sites, tools, hours }, projects] = await Promise.all([api("/api/watch"), api("/api/projects")]);
  if (!fresh(token)) return;
  const sel = (name, value, id) => `<select class="field" data-watch="${name}" data-sid="${id}" style="padding:4px 8px;font-size:13px">${hours.map(h => `<option value="${h}" ${h === value ? "selected" : ""}>${HOURS_LABEL(h)}</option>`).join("")}</select>`;
  $("#alerts-body").innerHTML = `
    <div class="grid" style="margin-bottom:16px">
      ${card("How watching works", `<ul class="plain" style="font-size:13.5px">
        <li><b>Re-analyze</b> runs a full analysis (with the browser) and compares it with the previous iteration: scores, status, title, technology, security headers, page weight, LCP, new issues and certificate expiry.</li>
        <li><b>OSINT</b> refreshes ${tools.map(esc).join(", ")} and compares each with its last run: new subdomains, DNS/NS/MX changes, registrar and expiry, SPF/DMARC/DKIM, TLS versions, redirects and robots.txt.</li>
        <li><b>Uptime</b> checks alert when a site goes down (confirmed by a second check) and when it recovers.</li>
        <li>Schedules only run while the app is running.</li></ul>`)}
      ${projects.length ? card("Watch a whole project", `<form class="inline-form" id="proj-watch" style="flex-direction:column;align-items:stretch">
        <select class="field" name="project">${projects.map(p => `<option value="${p.id}">${esc(p.name)} (${p.site_count} sites)</option>`).join("")}</select>
        <select class="field" name="preset">
          <option value="daily">Daily analysis + daily OSINT + uptime every 5 min</option>
          <option value="weekly">Weekly analysis + daily OSINT + uptime every 15 min</option>
          <option value="osint">OSINT daily only</option>
          <option value="off">Turn all watching off</option></select>
        <button class="btn dark" type="submit" style="align-self:flex-start">Apply to every site</button></form>`) : ""}
    </div>
    ${sites.length ? `<div class="data-table"><table><thead><tr><th>Site</th><th>Re-analyze</th><th>OSINT</th><th>Uptime</th><th>Last scheduled run</th></tr></thead><tbody>
      ${sites.map(s => `<tr><td><a href="#/sites/${s.id}"><b>${esc(s.host)}</b></a><div class="muted" style="font-size:12px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(s.title || s.url)}</div></td>
        <td>${sel("watch_analyze_hours", s.watch_analyze_hours, s.id)}</td><td>${sel("watch_osint_hours", s.watch_osint_hours, s.id)}</td>
        <td><label class="toggle" style="margin:0"><input type="checkbox" data-mon="${s.id}" ${s.monitor_enabled ? "checked" : ""}> every ${s.monitor_interval_min} min</label></td>
        <td class="muted" style="font-size:12.5px">${s.last_watch_analysis_at ? `Analysis ${esc(ago(s.last_watch_analysis_at))}` : ""}${s.last_watch_analysis_at && s.last_watch_osint_at ? "<br>" : ""}${s.last_watch_osint_at ? `OSINT ${esc(ago(s.last_watch_osint_at))}` : ""}${!s.last_watch_analysis_at && !s.last_watch_osint_at ? "—" : ""}</td></tr>`).join("")}
      </tbody></table></div>` : `<div class="empty"><h3>No sites yet</h3><p>Analyze a website first, then choose how often to watch it here.</p><a class="btn dark" href="#/">Analyze a website</a></div>`}`;
  view.querySelectorAll("[data-watch]").forEach(s => s.addEventListener("change", async () => {
    await api(`/api/sites/${s.dataset.sid}`, { method: "PATCH", body: { [s.dataset.watch]: +s.value } });
    toast(+s.value ? `Scheduled: ${HOURS_LABEL(+s.value).toLowerCase()}. First run within a minute.` : "Schedule off");
  }));
  view.querySelectorAll("[data-mon]").forEach(cb => cb.addEventListener("change", async () => {
    await api(`/api/sites/${cb.dataset.mon}`, { method: "PATCH", body: { monitor_enabled: cb.checked } });
    toast(cb.checked ? "Uptime monitoring on" : "Uptime monitoring off"); refreshSidebar();
  }));
  $("#proj-watch")?.addEventListener("submit", async e => {
    e.preventDefault();
    const f = e.target;
    const presets = {
      daily: { watch_analyze_hours: 24, watch_osint_hours: 24, monitor_enabled: true, monitor_interval_min: 5 },
      weekly: { watch_analyze_hours: 168, watch_osint_hours: 24, monitor_enabled: true, monitor_interval_min: 15 },
      osint: { watch_osint_hours: 24 },
      off: { watch_analyze_hours: 0, watch_osint_hours: 0, monitor_enabled: false },
    };
    const r = await api(`/api/projects/${f.project.value}/watch`, { method: "POST", body: presets[f.preset.value] });
    toast(`Applied to ${r.sites} site${r.sites === 1 ? "" : "s"}`); route();
  });
}
