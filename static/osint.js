// OSINT page: twelve passive lookups for one domain. Each tool runs as its own
// request so cards fill in as their sources answer. Results are saved server-side.

const OSINT_TOOLS = [
  ["dns", "DNS Lookup", "A, AAAA, MX, NS, TXT, CAA and more", "DNS-over-HTTPS"],
  ["rdap", "WHOIS / RDAP", "Registrar, registration and expiry dates", "RDAP"],
  ["subdomains", "Subdomain Discovery", "Publicly visible subdomains from issued certificates", "Certificate Transparency"],
  ["ssl", "SSL Certificate", "Issuer, validity, expiry and accepted TLS versions", "TLS / crt.sh"],
  ["headers", "HTTP Header Analyzer", "Server headers and security settings", "HTTP"],
  ["tech", "Technology Detection", "CMS, frameworks and web technologies", "Fingerprints"],
  ["ip", "IP / ASN Lookup", "Hosting provider, ASN and network owner", "RDAP / Team Cymru"],
  ["history", "Website History", "Historical snapshots of the site", "Internet Archive"],
  ["robots", "Robots.txt Analyzer", "Crawling rules and AI-crawler policy", "robots.txt"],
  ["sitemap", "Sitemap Analyzer", "Publicly listed URLs", "sitemap.xml"],
  ["email", "Email Security", "SPF, DKIM, DMARC, MTA-STS and BIMI", "DNS"],
  ["redirects", "Redirect Analyzer", "Redirect chains for http/https and www", "HTTP"],
];
const OSINT_ICONS = {
  dns: '<path d="M4 6h16M4 12h16M4 18h16"/><circle cx="8" cy="6" r="1"/><circle cx="8" cy="12" r="1"/><circle cx="8" cy="18" r="1"/>',
  rdap: '<rect x="5" y="3" width="14" height="18" rx="2"/><path d="M9 8h6M9 12h6M9 16h4"/>',
  subdomains: '<circle cx="12" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="12" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><path d="M12 7v10M12 10l-7 7M12 10l7 7"/>',
  ssl: '<rect x="5" y="10" width="14" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
  headers: '<path d="M4 5h16M4 10h10M4 15h16M4 20h8"/>',
  tech: '<path d="m8 8-4 4 4 4M16 8l4 4-4 4M14 5l-4 14"/>',
  ip: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
  history: '<path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5M12 7v5l3 2"/>',
  robots: '<rect x="5" y="8" width="14" height="11" rx="2"/><path d="M12 4v4M9 13h.01M15 13h.01M9 16h6"/>',
  sitemap: '<rect x="9" y="3" width="6" height="5" rx="1"/><rect x="3" y="16" width="6" height="5" rx="1"/><rect x="15" y="16" width="6" height="5" rx="1"/><path d="M12 8v4M6 16v-4h12v4"/>',
  email: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/>',
  redirects: '<path d="M4 12h12M12 6l6 6-6 6"/><path d="M4 6v12"/>',
};

const osintState = { target: null, results: {} };

// ---------------------------------------------------------------- page

async function pageOsint(q, token) {
  const target = (q.get("target") || "").trim().toLowerCase();
  const recent = await api("/api/osint/recent").catch(() => []);
  if (!fresh(token)) return;
  view.innerHTML = `<div class="wrap osint-page">
    <div class="page-head"><div><h1>OSINT</h1>
      <p>Passive lookups on a domain from public sources: DNS, registration, certificates, network owner, archives and the site's own public files. Results are saved so you can come back to them.</p></div></div>
    <form class="search" id="osint-form" style="max-width:none">
      <label for="osint-target" style="position:absolute;left:-9999px">Domain</label>
      <input id="osint-target" name="target" placeholder="example.com" value="${esc(target)}" autocomplete="off" required>
      <button class="primary" type="submit">Run all 12 tools →</button>
    </form>
    <div id="osint-body" style="margin-top:18px"></div>
  </div>`;
  $("#osint-form").addEventListener("submit", e => {
    e.preventDefault();
    const t = $("#osint-target").value.trim();
    if (!t) return;
    osintState.target = null;   // force a fresh run even for the same target
    location.hash = `#/osint?target=${encodeURIComponent(t)}&run=1`;
  });

  if (!target) {
    $("#osint-body").innerHTML = recent.length ? `<div class="section-title" style="margin-top:6px">Recent lookups</div>
      <div class="data-table"><table><thead><tr><th>Domain</th><th>Last run</th><th>Tools</th><th></th></tr></thead><tbody>
      ${recent.map(r => `<tr class="click" data-href="#/osint?target=${encodeURIComponent(r.target)}">
        <td><b>${esc(r.target)}</b></td><td>${esc(fmtTime(r.last_run))} <span class="muted">· ${esc(ago(r.last_run))}</span></td>
        <td>${r.tools}/12${r.failures ? ` <span class="muted">· ${r.failures} failed run${r.failures === 1 ? "" : "s"}</span>` : ""}</td>
        <td><button class="btn sm danger" data-forget="${esc(r.target)}">Forget</button></td></tr>`).join("")}</tbody></table></div>`
      : `<div class="grid">${OSINT_TOOLS.map(([id, name, what, src]) => `<div class="card osint-intro"><div class="row" style="gap:10px;margin-bottom:6px">
          <svg class="ico" viewBox="0 0 24 24">${OSINT_ICONS[id]}</svg><b>${esc(name)}</b></div>
          <div class="muted" style="font-size:13.5px">${esc(what)}</div><span class="pill" style="margin-top:8px">${esc(src)}</span></div>`).join("")}</div>`;
    view.querySelectorAll("tr[data-href]").forEach(tr => tr.addEventListener("click", () => location.hash = tr.dataset.href));
    view.querySelectorAll("[data-forget]").forEach(b => b.addEventListener("click", async e => {
      e.stopPropagation();
      if (!confirm(`Delete all saved OSINT results for ${b.dataset.forget}?`)) return;
      await api(`/api/osint/saved?target=${encodeURIComponent(b.dataset.forget)}`, { method: "DELETE" }); route();
    }));
    return;
  }

  const runNow = q.get("run") === "1";
  if (runNow) history.replaceState(null, "", `#/osint?target=${encodeURIComponent(target)}`);
  const sameTarget = osintState.target === target;
  if (!sameTarget) {
    osintState.target = target;
    osintState.results = {};
    if (!runNow) {
      const saved = await api(`/api/osint/saved?target=${encodeURIComponent(target)}`).catch(() => null);
      if (!fresh(token)) return;
      for (const [tool, r] of Object.entries(saved?.results || {}))
        osintState.results[tool] = r.ok ? { state: "ok", data: r.data, ms: r.ms, ran_at: r.ran_at, saved: true }
          : { state: "error", error: r.error, ms: r.ms, ran_at: r.ran_at, saved: true };
    }
  }
  renderOsintShell(target);
  const missing = OSINT_TOOLS.map(([id]) => id).filter(id => !osintState.results[id]);
  if (runNow || (!sameTarget && missing.length === OSINT_TOOLS.length)) runAllOsint(target);
}

function renderOsintShell(target) {
  const anySaved = Object.values(osintState.results).some(r => r.saved);
  $("#osint-body").innerHTML = `
    <div class="row" style="justify-content:space-between;margin-bottom:12px">
      <div class="row" style="gap:6px" id="osint-chips">${OSINT_TOOLS.map(([id, name]) => `<a class="chip osint-chip" href="#" data-jump="${id}"><span class="sdot" id="chip-${id}"></span>${esc(name.replace(/ (Lookup|Analyzer|Discovery|Detection|Checker)$/, ""))}</a>`).join("")}</div>
    </div>
    <div class="row" style="justify-content:space-between;margin-bottom:14px">
      <div class="muted" id="osint-progress" style="font-size:13.5px"></div>
      <div class="row"><button class="btn" id="osint-rerun">${anySaved ? "Run again" : "Re-run all"}</button>
        <a class="btn" href="#/?url=${encodeURIComponent(target)}">Full site analysis</a>
        <button class="btn" id="osint-dl">Download JSON</button></div>
    </div>
    <div class="osint-grid">${OSINT_TOOLS.map(([id]) => `<section class="card osint-card" id="osint-${id}"></section>`).join("")}</div>`;
  OSINT_TOOLS.forEach(([id]) => updateOsintCard(id));
  view.querySelectorAll("[data-jump]").forEach(a => a.addEventListener("click", e => {
    e.preventDefault(); $(`#osint-${a.dataset.jump}`).scrollIntoView({ behavior: "smooth", block: "start" });
  }));
  $("#osint-rerun").addEventListener("click", () => runAllOsint(target));
  $("#osint-dl").addEventListener("click", () => {
    const out = { target, exported_at: new Date().toISOString(), results: osintState.results };
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([JSON.stringify(out, null, 2)], { type: "application/json" }));
    a.download = `osint-${target}.json`; a.click();
  });
}

function runAllOsint(target) {
  OSINT_TOOLS.forEach(([id]) => runOsintTool(id, target));
}

async function runOsintTool(tool, target) {
  osintState.results[tool] = { state: "loading", started: Date.now() };
  updateOsintCard(tool);
  try {
    const r = await api(`/api/osint/${tool}?target=${encodeURIComponent(target)}`);
    if (osintState.target !== target) return;
    osintState.results[tool] = { state: "ok", data: r.data, ms: r.ms, ran_at: r.ran_at, events: r.events || [] };
  } catch (e) {
    if (osintState.target !== target) return;
    osintState.results[tool] = { state: "error", error: e.message, ran_at: new Date().toISOString() };
  }
  updateOsintCard(tool);
  if (!Object.values(osintState.results).some(r => r.state === "loading")) {
    refreshSidebar();
    const changes = Object.values(osintState.results).flatMap(r => r.events || []);
    if (changes.length) {
      toast(`${changes.length} change${changes.length === 1 ? "" : "s"} since the last lookup · <a href="#/alerts" style="color:inherit;text-decoration:underline">See alerts</a>`, 7000);
      Object.values(osintState.results).forEach(r => { r.events = []; });   // announce each change once
    }
  }
}

function updateOsintCard(tool) {
  const el = document.getElementById(`osint-${tool}`);
  const r = osintState.results[tool];
  const chip = document.getElementById(`chip-${tool}`);
  if (chip) chip.className = `sdot ${!r ? "" : r.state === "ok" ? "up" : r.state === "error" ? "down" : "off"}`;
  const prog = $("#osint-progress");
  if (prog) {
    const all = OSINT_TOOLS.map(([id]) => osintState.results[id]);
    const done = all.filter(x => x && x.state !== "loading").length, failed = all.filter(x => x?.state === "error").length;
    const loadingN = all.filter(x => x?.state === "loading").length;
    const savedAt = all.filter(x => x?.saved).map(x => x.ran_at).sort().at(-1);
    prog.innerHTML = loadingN ? `<span class="row" style="gap:8px"><span class="spinner" style="width:13px;height:13px"></span>${done} of 12 done…</span>`
      : `${done} of 12 tools${failed ? ` · <span style="color:var(--bad)">${failed} failed</span>` : ""}${savedAt ? ` · saved results from ${esc(fmtTime(savedAt))} (${esc(ago(savedAt))})` : ""}`;
  }
  if (!el) return;
  const [, name, what, src] = OSINT_TOOLS.find(t => t[0] === tool);
  const head = `<div class="osint-head">
      <div class="row" style="gap:10px;min-width:0"><svg class="ico" viewBox="0 0 24 24">${OSINT_ICONS[tool]}</svg>
        <div style="min-width:0"><h2>${esc(name)}</h2><div class="muted" style="font-size:12.5px">${esc(what)} · <span class="pill">${esc(src)}</span></div></div></div>
      <div class="row" style="gap:6px;flex:none">${r?.state === "ok" || r?.state === "error" ? `<span class="muted" style="font-size:12px" title="${esc(fmtTime(r.ran_at))}">${r.ms != null ? (r.ms / 1000).toFixed(1) + "s · " : ""}${esc(ago(r.ran_at))}</span>` : ""}
        <button class="btn sm" data-rerun="${tool}" ${r?.state === "loading" ? "disabled" : ""} aria-label="Re-run ${esc(name)}">↻</button></div></div>`;
  let body;
  if (!r) body = '<div class="muted">Not run yet.</div>';
  else if (r.state === "loading") body = `<div class="status on" style="margin:6px 0"><div class="spinner"></div><span>Querying ${esc(src)}…</span></div>`;
  else if (r.state === "error") body = `<div class="error" style="display:block;margin:0">${esc(r.error)}</div>`;
  else {
    try { body = OSINT_RENDER[tool](r.data); }
    catch (e) { body = `<div class="error" style="display:block;margin:0">Couldn't display this result: ${esc(e.message)}</div>`; }
  }
  el.innerHTML = head + `<div class="osint-body">${body}</div>`;
  el.querySelector("[data-rerun]").addEventListener("click", () => runOsintTool(tool, osintState.target));
  el.querySelectorAll("input[data-filter]").forEach(inp => inp.addEventListener("input", () => {
    const needle = inp.value.toLowerCase();
    el.querySelectorAll(`[data-rows="${inp.dataset.filter}"] tr[data-k]`).forEach(tr => tr.hidden = needle && !tr.dataset.k.includes(needle));
  }));
}

// ---------------------------------------------------------------- shared bits

const gradeBadge = g => `<span class="grade grade-${esc(g)}" title="Grade">${esc(g)}</span>`;
const okList = (bad = [], good = []) => (bad.length || good.length)
  ? bad.map(i => `<div class="issue"><span class="dot"></span><span>${esc(i)}</span></div>`).join("")
    + good.map(i => `<div class="issue"><span class="dot good"></span><span>${esc(i)}</span></div>`).join("") : "";
const sub = title => `<div class="section-title" style="margin:16px 0 8px">${esc(title)}</div>`;
const statPills = items => `<div class="stat-cards" style="margin-bottom:8px">${items.map(([v, k]) => `<div class="stat"><div class="v">${v}</div><div class="k">${esc(k)}</div></div>`).join("")}</div>`;
const daysPill = d => d == null ? "" : `<span class="pill ${d < 0 ? "bad" : d < 30 ? "bad" : d < 60 ? "warn" : "good"}">${d < 0 ? `expired ${-d} days ago` : `${d} days left`}</span>`;
const yn = (v, yes = "Yes", no = "No") => v == null ? '<span class="pill">Unknown</span>' : v ? `<span class="pill good">${yes}</span>` : `<span class="pill bad">${no}</span>`;
const filterBox = (id, placeholder) => `<input class="field" data-filter="${id}" placeholder="${esc(placeholder)}" style="width:100%;margin-bottom:8px">`;
const ext = (url, text) => `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(text ?? url)}</a>`;
const httpPill = s => s == null ? '<span class="pill">—</span>' : `<span class="pill ${s < 300 ? "good" : s < 400 ? "warn" : "bad"}">${s}</span>`;

// ---------------------------------------------------------------- renderers

const OSINT_RENDER = {
  dns(d) {
    const order = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA", "HTTPS"];
    const rows = order.flatMap(t => d.records[t].map(r => `<tr><td><span class="pill">${t}</span></td><td class="url">${esc(r.data)}</td><td class="muted">${r.ttl ?? ""}</td></tr>`));
    return `${d.notes.length ? okList(d.notes.filter(n => /no |not |any /i.test(n)), d.notes.filter(n => !/no |not |any /i.test(n))) : ""}
      ${rows.length ? `<div class="table-scroll" style="max-height:420px;margin-top:8px"><table><thead><tr><th>Type</th><th>Value</th><th>TTL</th></tr></thead><tbody>${rows.join("")}</tbody></table></div>` : '<div class="muted">No records.</div>'}
      <p class="muted" style="font-size:12px;margin:8px 0 0">${d.count} records via ${esc(d.resolver)}</p>`;
  },

  rdap(d) {
    return kv([
      ["Domain", `<b>${esc(d.domain)}</b>`],
      ["Registrar", `${esc(d.registrar || "—")}${d.registrar_iana_id ? ` <span class="muted">(IANA ${esc(d.registrar_iana_id)})</span>` : ""}`],
      ["Registered", d.created ? `${esc(fmtTime(d.created))}${d.age_years != null ? ` <span class="muted">· ${d.age_years} years ago</span>` : ""}` : null],
      ["Expires", d.expires ? `${esc(fmtTime(d.expires))} ${daysPill(d.days_until_expiry)}` : null],
      ["Last changed", d.updated ? esc(fmtTime(d.updated)) : null],
      ["Nameservers", d.nameservers.map(n => `<span class="mono">${esc(n)}</span>`).join("<br>") || null],
      ["DNSSEC", yn(d.dnssec, "Signed", "Not signed")],
      ["Status", d.status.map(s => `<span class="pill">${esc(s)}</span>`).join(" ") || null],
      ["Registrant", d.registrant ? esc(Object.values(d.registrant).join(" · ")) : '<span class="muted">Redacted / not public</span>'],
      ["Abuse contact", [d.abuse_email, d.abuse_phone].filter(Boolean).map(esc).join(" · ") || null],
      ["Source", ext(d.source, new URL(d.source).hostname)],
    ]);
  },

  subdomains(d) {
    const rows = d.subdomains.map(s => `<tr data-k="${esc(s.name)}"><td class="url">${ext(`https://${s.name}`, s.name)}${s.wildcard ? ' <span class="pill">wildcard</span>' : ""}</td>
      <td>${s.resolves == null ? '<span class="muted">—</span>' : s.resolves ? '<span class="pill good">live</span>' : '<span class="pill">no DNS</span>'}</td>
      <td class="url">${esc(s.cname ? "→ " + s.cname : (s.ips || []).join(", "))}</td><td>${s.certs}</td><td class="muted" style="white-space:nowrap">${esc(s.first_seen || "")}</td><td class="muted" style="white-space:nowrap">${esc(s.last_seen || "")}</td></tr>`).join("");
    return `${statPills([[d.count.toLocaleString(), "subdomains found"], [`${d.live}/${d.checked}`, "resolve today (checked)"]])}
      ${d.warning ? `<div class="issue"><span class="dot"></span><span>${esc(d.warning)}</span></div>` : ""}
      ${d.notable.length ? `${sub("Worth a look")}<div class="row" style="gap:6px">${d.notable.map(n => `<span class="pill warn mono">${esc(n)}</span>`).join("")}</div>` : ""}
      ${sub(`All names (${d.subdomains.length}${d.count > d.subdomains.length ? ` of ${d.count}` : ""})`)}${filterBox("subs", "Filter subdomains…")}
      <div class="table-scroll" style="max-height:440px"><table><thead><tr><th>Name</th><th>DNS</th><th>Points to</th><th>Certs</th><th>First seen</th><th>Last cert expiry</th></tr></thead><tbody data-rows="subs">${rows}</tbody></table></div>
      <p class="muted" style="font-size:12px;margin:8px 0 0">From ${esc(d.source)}. Only names that appeared on a public certificate are found; DNS checked for the first ${d.checked}.</p>`;
  },

  ssl(d) {
    const ver = Object.entries(d.versions).map(([k, v]) => {
      const bad = /1\.[01]$/.test(k);
      return `<span class="pill ${v == null ? "" : v ? (bad ? "bad" : "good") : bad ? "good" : ""}">${esc(k)}: ${v == null ? "?" : v ? "on" : "off"}</span>`;
    }).join(" ");
    return `<div class="row" style="margin-bottom:10px">${d.valid ? '<span class="pill good">Valid certificate</span>' : '<span class="pill bad">Invalid certificate</span>'} ${daysPill(d.days_left)}</div>
      ${d.issues.length ? okList(d.issues) : ""}
      ${kv([["Subject", `<span class="mono">${esc(d.subject)}</span>`], ["Issuer", `${esc(d.issuer)}${d.issuer_cn && d.issuer_cn !== d.issuer ? ` <span class="muted">(${esc(d.issuer_cn)})</span>` : ""}`],
        ["Valid", `${esc(fmtTime(d.not_before))} → ${esc(fmtTime(d.not_after))} <span class="muted">(${d.lifetime_days} days)</span>`],
        ["Connection", `${esc(d.protocol)} · ${esc(d.cipher)} (${d.cipher_bits} bit)${d.alpn ? ` · ALPN ${esc(d.alpn)}` : ""}`],
        ["TLS versions", ver], ["Covers", `${d.san_count} name${d.san_count === 1 ? "" : "s"}: <span class="mono">${d.sans.slice(0, 12).map(esc).join(", ")}${d.sans.length > 12 ? ", …" : ""}</span>`],
        ["SHA-256", `<span class="mono" style="font-size:11px">${esc(d.sha256)}</span>`], ["Serial", `<span class="mono" style="font-size:11px">${esc(d.serial)}</span>`],
        ["OCSP", d.ocsp.map(u => `<span class="mono">${esc(u)}</span>`).join("<br>") || null]])}
      ${sub(`Recently issued certificates${d.ct_source ? ` (${d.ct_source})` : ""}`)}
      ${d.recent_certificates.length ? `<div class="table-scroll" style="max-height:300px"><table><thead><tr><th>Issued</th><th>Expires</th><th>Issuer</th><th>Names</th></tr></thead>
        ${d.recent_certificates.map(c => `<tr><td style="white-space:nowrap">${c.id ? ext(`https://crt.sh/?id=${c.id}`, c.not_before) : esc(c.not_before)}</td><td style="white-space:nowrap">${esc(c.not_after)}</td><td>${esc(c.issuer)}</td><td class="url">${c.names.map(esc).join(", ")}</td></tr>`).join("")}</table></div>`
        : `<div class="muted">${esc(d.ct_warning || "None found.")}</div>`}`;
  },

  headers(d) {
    return `<div class="row" style="gap:14px;margin-bottom:10px">${gradeBadge(d.grade)}<div><b>${d.score} of ${d.out_of}</b> security headers present
        <div class="muted" style="font-size:12.5px">${ext(d.url)} · HTTP ${d.status} · ${d.response_ms} ms${d.redirects ? ` · ${d.redirects} redirect${d.redirects > 1 ? "s" : ""}` : ""}</div></div></div>
      ${d.checks.map(c => `<div class="issue"><span class="dot ${c.present ? "good" : "bad"}"></span><div style="min-width:0"><b class="mono" style="font-size:13px">${esc(c.name)}</b>
        <div class="muted" style="font-size:12.5px">${esc(c.why)}</div>${c.value ? `<div class="mono muted" style="font-size:11.5px;overflow-wrap:anywhere">${esc(c.value.slice(0, 240))}</div>` : ""}</div></div>`).join("")}
      ${d.hsts ? sub("HSTS") + kv([["max-age", `${d.hsts.max_age?.toLocaleString() ?? "—"} s <span class="muted">(${d.hsts.max_age ? Math.round(d.hsts.max_age / 86400) : 0} days)</span>`], ["includeSubDomains", yn(d.hsts.include_subdomains)], ["preload", yn(d.hsts.preload)]]) : ""}
      ${d.csp ? sub(`Content-Security-Policy${d.csp.report_only ? " (report-only)" : ""}`) + okList(d.csp.warnings)
        + `<div class="table-scroll" style="max-height:240px"><table>${Object.entries(d.csp.directives).map(([k, v]) => `<tr><td class="mono" style="white-space:nowrap">${esc(k)}</td><td class="url">${v.map(esc).join(" ")}</td></tr>`).join("")}</table></div>` : ""}
      ${d.cookies.length ? sub(`Cookies (${d.cookies.length})`) + `<div class="table-scroll"><table><thead><tr><th>Name</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th><th>Expires</th></tr></thead>
        ${d.cookies.map(c => `<tr><td class="url">${esc(c.name)}</td><td>${yn(c.secure)}</td><td>${yn(c.http_only)}</td><td>${esc(c.same_site || "—")}</td><td class="muted" style="font-size:12px">${esc(c.expires)}</td></tr>`).join("")}</table></div>` : ""}
      ${d.info_leaks.length ? sub("Software disclosure") + kv(d.info_leaks.map(l => [l.header, `<span class="mono">${esc(l.value)}</span>`])) : ""}
      ${Object.keys(d.caching).length ? sub("Caching") + kv(Object.entries(d.caching).map(([k, v]) => [k, `<span class="mono">${esc(v)}</span>`])) : ""}
      ${d.issues.length ? sub("Findings") + okList(d.issues) : ""}
      <details style="margin-top:12px"><summary class="muted" style="cursor:pointer">All ${Object.keys(d.headers).length} response headers</summary>
        <div class="table-scroll" style="margin-top:8px"><table>${Object.entries(d.headers).map(([k, v]) => `<tr><td class="url" style="white-space:nowrap">${esc(k)}</td><td class="url">${esc(v)}</td></tr>`).join("")}</table></div></details>`;
  },

  tech(d) {
    const cats = Object.entries(d.by_category);
    return `${cats.length ? cats.map(([c, list]) => `${sub(c)}${list.map(t => `<div class="tech"><div style="min-width:0"><div class="name">${esc(t.name)} ${t.version ? `<span class="pill">${esc(t.version)}</span>` : ""}</div>
        ${t.evidence.map(e => `<div class="ev">${esc(e)}</div>`).join("")}</div></div>`).join("")}`).join("")
      : '<div class="muted">No known technologies detected in the HTML and headers.</div>'}
      ${d.generator ? `<p style="font-size:13px">Generator meta tag: <span class="mono">${esc(d.generator)}</span></p>` : ""}
      <p class="muted" style="font-size:12px;margin:10px 0 0">${esc(d.note)}</p>`;
  },

  ip(d) {
    return `${d.providers.length ? `<p style="margin:0 0 10px">Hosted by <b>${d.providers.map(esc).join("</b>, <b>")}</b></p>` : ""}
      ${d.addresses.map(a => {
        const n = a.network || {}, s = a.asn || {};
        return `<div class="ip-block"><div class="row" style="gap:8px"><b class="mono">${esc(a.ip)}</b><span class="pill">IPv${a.version}</span>${a.ptr ? `<span class="muted mono" style="font-size:12px">${esc(a.ptr)}</span>` : ""}</div>
          ${a.note ? `<div class="muted">${esc(a.note)}</div>` : kv([
            ["ASN", s.asn ? `${ext(`https://bgp.he.net/AS${s.asn}`, `AS${s.asn}`)} ${esc(s.as_name || "")}` : null],
            ["Prefix", s.prefix ? `<span class="mono">${esc(s.prefix)}</span>` : null],
            ["Country", esc(s.country || n.country || "") || null], ["Registry", s.registry ? `${esc(s.registry)}${s.allocated ? ` · allocated ${esc(s.allocated)}` : ""}` : null],
            ["Network", n.name ? `${esc(n.name)}${n.handle ? ` <span class="muted">(${esc(n.handle)})</span>` : ""}` : null],
            ["Range", n.range ? `<span class="mono" style="font-size:12px">${esc(n.cidr?.join(", ") || n.range)}</span>` : null],
            ["Owner", esc(n.org || "") || null], ["Abuse", esc(n.abuse_email || "") || null]])}</div>`;
      }).join("")}`;
  },

  history(d) {
    return `${statPills([[d.months_captured.toLocaleString(), "months with snapshots"], [d.first ? esc(d.first.date) : "—", "first capture"], [d.last ? esc(d.last.date) : "—", "latest capture"]])}
      ${d.by_year.length ? `${sub("Months captured per year")}<div class="year-bars">${d.by_year.map(y => `<div class="yb" title="${y.year}: ${y.months} months"><i style="height:${Math.round(y.months / 12 * 100)}%"></i><span>${String(y.year).slice(2)}</span></div>`).join("")}</div>` : ""}
      ${d.recent.length ? `${sub("Recent snapshots")}<ul class="plain">${d.recent.map(s => `<li>${ext(s.url, s.date)}</li>`).join("")}</ul>` : ""}
      ${d.earliest.length ? `${sub("Earliest snapshots")}<div class="row" style="gap:6px">${d.earliest.map(s => `<a class="pill" href="${esc(s.url)}" target="_blank" rel="noopener noreferrer">${esc(s.date)}</a>`).join("")}</div>` : ""}
      <p style="margin:14px 0 0">${ext(d.calendar_url, "Open the full Wayback Machine calendar ↗")}</p>`;
  },

  robots(d) {
    if (!d.exists) return okList(d.issues) + `<p class="muted" style="font-size:12.5px">Checked ${ext(d.url)} (HTTP ${d.status}).</p>`;
    const ai = d.ai_crawlers.filter(a => a.status !== "not listed");
    return `${statPills([[d.groups.length, "user-agent groups"], [d.rule_count, "rules"], [d.sitemaps.length, "sitemaps listed"]])}
      ${okList(d.issues)}
      ${sub("AI crawlers")}${ai.length ? `<div class="row" style="gap:6px">${ai.map(a => `<span class="pill ${a.status.startsWith("blocked") ? "bad" : a.status === "partially blocked" ? "warn" : "good"}">${esc(a.bot)}: ${esc(a.status)}</span>`).join("")}</div>`
        : '<div class="muted" style="font-size:13.5px">No AI crawlers are named; they follow the * rules.</div>'}
      ${d.interesting_paths.length ? `${sub("Disallowed paths worth noting")}<div class="row" style="gap:6px">${d.interesting_paths.map(p => `<span class="pill warn mono">${esc(p)}</span>`).join("")}</div>` : ""}
      ${sub("Rules by user agent")}<div class="table-scroll" style="max-height:300px"><table><thead><tr><th>User agents</th><th>Disallow</th><th>Allow</th><th>Crawl-delay</th></tr></thead>
        ${d.groups.map(g => `<tr><td class="url">${g.agents.map(esc).join(", ")}</td><td title="${esc(g.disallow.slice(0, 30).join("\n"))}">${g.disallow.length}</td><td>${g.allow.length}</td><td>${esc(g.crawl_delay || "—")}</td></tr>`).join("")}</table></div>
      ${d.sitemaps.length ? `${sub("Sitemaps")}${d.sitemaps.map(s => `<div class="mono" style="font-size:12px;overflow-wrap:anywhere">${ext(s)}</div>`).join("")}` : ""}
      <details style="margin-top:12px"><summary class="muted" style="cursor:pointer">robots.txt (${bytes(d.size)})</summary><pre class="raw" style="margin-top:8px;max-height:360px">${esc(d.raw)}</pre></details>`;
  },

  sitemap(d) {
    const max = Math.max(1, ...d.sections.map(s => s[1]));
    return `${statPills([[d.total_urls.toLocaleString(), "URLs listed"], [d.sitemaps.length, "sitemap files read"], [d.lastmod_range ? `${esc(d.lastmod_range[0].slice(0, 4))}–${esc(d.lastmod_range[1].slice(0, 4))}` : "—", "lastmod range"]])}
      ${d.truncated ? '<div class="issue"><span class="dot"></span><span>Stopped after 20 sitemap files; the site lists more.</span></div>' : ""}
      ${d.errors.length ? okList(d.errors.map(e => `Couldn't read ${e.url}: ${e.error}`)) : ""}
      ${d.extensions.length ? `<p style="font-size:13px;margin:6px 0">Extensions: ${d.extensions.map(x => `<span class="pill">${esc(x)}</span>`).join(" ")}</p>` : ""}
      ${sub("Top sections")}${d.sections.map(([s, n]) => `<div class="bar-row"><span class="k mono" style="width:150px;overflow:hidden;text-overflow:ellipsis">/${esc(s === "/" ? "" : s)}</span><span class="bar" style="width:${Math.round(n / max * 160)}px"></span><span class="n">${n.toLocaleString()}</span></div>`).join("")}
      ${sub("Sitemap files")}<div class="table-scroll" style="max-height:200px"><table>${d.sitemaps.map(s => `<tr><td class="url">${ext(s.url)}</td><td><span class="pill">${s.type}</span></td><td>${s.entries.toLocaleString()}</td></tr>`).join("")}</table></div>
      ${sub(`Sample URLs (${d.sample.length})`)}${filterBox("sm", "Filter URLs…")}
      <div class="table-scroll" style="max-height:320px"><table><tbody data-rows="sm">${d.sample.map(u => `<tr data-k="${esc(u.url.toLowerCase())}"><td class="url">${ext(u.url)}</td><td class="muted" style="white-space:nowrap">${esc(u.lastmod || "")}</td></tr>`).join("")}</tbody></table></div>
      <p class="muted" style="font-size:12px;margin:8px 0 0">Found via ${esc(d.discovered_from)}.</p>`;
  },

  email(d) {
    return `<div class="row" style="gap:14px;margin-bottom:10px">${gradeBadge(d.grade)}<div><b>${esc(d.domain)}</b><div class="muted" style="font-size:12.5px">Spoofing protection and mail transport security</div></div></div>
      ${okList(d.issues, d.passed)}
      ${sub("Records")}${kv([
        ["MX", d.mx.length ? d.mx.map(m => `<span class="mono">${esc(m)}</span>`).join("<br>") : '<span class="pill bad">None</span>'],
        ["SPF", d.spf ? `<span class="mono" style="font-size:12px;overflow-wrap:anywhere">${esc(d.spf.record)}</span><br><span class="pill ${d.spf.all === "-all" ? "good" : d.spf.all === "~all" ? "warn" : "bad"}">${esc(d.spf.policy)}</span> <span class="muted" style="font-size:12.5px">${d.spf.dns_lookups}/10 DNS lookups</span>` : '<span class="pill bad">Missing</span>'],
        ["DMARC", d.dmarc ? `<span class="mono" style="font-size:12px;overflow-wrap:anywhere">${esc(d.dmarc.record)}</span><br><span class="pill ${d.dmarc.policy === "reject" ? "good" : d.dmarc.policy === "quarantine" ? "warn" : "bad"}">p=${esc(d.dmarc.policy)}</span>${d.dmarc.subdomain_policy ? ` <span class="pill">sp=${esc(d.dmarc.subdomain_policy)}</span>` : ""} <span class="muted" style="font-size:12.5px">pct ${d.dmarc.pct} · alignment dkim ${esc(d.dmarc.adkim)} / spf ${esc(d.dmarc.aspf)}</span>` : '<span class="pill bad">Missing</span>'],
        ["DKIM", d.dkim_wildcard ? `<span class="pill">Wildcard record${d.dkim_wildcard.revoked ? " (revoked)" : ""}</span>`
          : d.dkim.length ? d.dkim.map(k => `<span class="pill ${k.revoked ? "" : k.key_bits && k.key_bits < 2048 ? "warn" : "good"}">${esc(k.selector)} · ${esc(k.key_type)}${k.key_bits ? " " + k.key_bits : ""}${k.revoked ? " · revoked" : ""}</span>`).join(" ")
          : `<span class="muted">None on ${d.dkim_selectors_checked} common selectors</span>`],
        ["MTA-STS", d.mta_sts ? `<span class="pill good">${esc(d.mta_sts.mode || "published")}</span>` : '<span class="muted">Not published</span>'],
        ["TLS-RPT", d.tls_rpt ? `<span class="mono" style="font-size:12px">${esc(d.tls_rpt)}</span>` : '<span class="muted">Not published</span>'],
        ["BIMI", d.bimi ? `<span class="mono" style="font-size:12px;overflow-wrap:anywhere">${esc(d.bimi)}</span>` : '<span class="muted">Not published</span>'],
      ])}`;
  },

  redirects(d) {
    return `${d.canonical ? `<p style="margin:0 0 10px">Canonical address: <b>${ext(d.canonical)}</b></p>` : ""}
      ${okList(d.issues, d.passed)}
      ${d.chains.map(c => `<div class="chain"><div class="chain-start"><span class="mono">${esc(c.start)}</span>
          <span class="muted" style="font-size:12px">${c.error ? "" : c.redirects ? `${c.redirects} redirect${c.redirects > 1 ? "s" : ""}` : "no redirect"}</span></div>
        ${c.hops.map(h => `<div class="hop">${httpPill(h.status)} <span class="url mono" style="font-size:12px;overflow-wrap:anywhere">${esc(h.url)}</span>
          <span class="muted" style="font-size:11.5px;white-space:nowrap">${h.ms} ms${h.hsts ? " · HSTS" : ""}${h.meta_refresh ? ` · meta refresh → ${esc(h.meta_refresh)}` : ""}</span></div>`).join("")}
        ${c.error ? `<div class="hop"><span class="pill bad">error</span> <span>${esc(c.error)}</span></div>` : ""}</div>`).join("")}`;
  },
};
