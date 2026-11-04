const $ = (s, el = document) => el.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const bytes = n => n == null ? "—" : n < 1024 ? n + " B" : n < 1048576 ? (n/1024).toFixed(1) + " KB" : (n/1048576).toFixed(2) + " MB";
const yes = (b, good = "Yes", bad = "No") => b == null ? '<span class="pill">Unknown</span>' : b ? `<span class="pill good">${good}</span>` : `<span class="pill bad">${bad}</span>`;
const kv = rows => `<dl class="kv">${rows.filter(r => r).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v ?? '<span class="muted">—</span>'}</dd>`).join("")}</dl>`;
const card = (title, body, cls = "") => `<section class="card ${cls}"><h3>${esc(title)}</h3>${body}</section>`;
const issues = (list, okText) => list.length ? list.map(i => `<div class="issue"><span class="dot"></span><span>${esc(i)}</span></div>`).join("")
  : `<div class="issue"><span class="dot good"></span><span>${esc(okText)}</span></div>`;
const link = u => u ? `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(u)}</a>` : null;
const fmtTime = iso => iso ? new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "—";
const ago = iso => {
  if (!iso) return "never";
  const s = Math.round((Date.now() - new Date(iso)) / 1000);
  if (s < 60) return `${s}s ago`; if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`; return `${Math.round(s / 86400)}d ago`;
};
const duration = sec => sec == null ? "—" : sec < 60 ? `${sec}s` : sec < 3600 ? `${Math.round(sec / 60)}m` : sec < 86400 ? `${(sec / 3600).toFixed(1)}h` : `${(sec / 86400).toFixed(1)}d`;
const scoreColor = v =>v >= 85 ? "var(--good)" : v >= 60 ? "var(--warn)" : "var(--bad)";
const bars = (items, label = i => i.value) => {
  const max = Math.max(1, ...items.map(i => i.count));
  return items.map(i => `<div class="bar-row"><span class="k mono">${esc(label(i))}</span><span class="bar" style="width:${Math.round(i.count / max * 160)}px"></span><span class="n">${i.count}</span></div>`).join("") || '<span class="muted">None found</span>';
};


function renderReport(d, root, meta = {}) {
  const o = d.overview, s = d.scores;
  const tabs = [["overview", "Overview"], ["tech", `Technology (${d.technologies.count})`], ["design", "Design"],
    ...(d.browser?.available ? [["shots", "Screenshots"]] : []), ["perf", "Performance"],
    ["seo", "SEO"], ["a11y", "Accessibility"], ["security", "Security"], ["structure", "Structure"], ["raw", "Raw data"]];
  const scoreCards = [["perf", "Performance", s.performance, `${d.performance.issues.length} issues`],
    ["seo", "SEO", s.seo, `${d.seo.issues.length} issues`], ["a11y", "Accessibility", s.accessibility, `${d.accessibility.issues.length} issues`],
    ["security", "Security", s.security, `${d.security.headers.filter(h => !h.present).length} headers missing`]];

  const saved = meta.analysis_id ? `<div class="sub">Iteration ${meta.iteration} of <a href="#/sites/${meta.site_id}">${esc(o.host)}</a>
    · saved ${esc(fmtTime(meta.created_at))}${meta.label ? ` · <span class="pill">${esc(meta.label)}</span>` : ""}</div>` : "";
  root.innerHTML = `
    <div class="site-head">
      <img class="fav" src="${esc(o.favicon)}" alt="" onerror="this.style.visibility='hidden'">
      <div style="min-width:0"><h2>${esc(o.title || o.host)}</h2>
        <div class="sub">${link(o.final_url)} · HTTP ${o.status} · analyzed in ${(d.analysis_ms/1000).toFixed(1)}s</div>${saved}</div>
      <div class="actions">${meta.actions || ""}<button class="ghost" data-act="dl">Download JSON</button></div>
    </div>
    <div class="scores">${scoreCards.map(([tab, l, v, h]) => `
      <div class="score" data-goto="${tab}" role="button" tabindex="0"><div class="ring" style="--v:${v};--c:${scoreColor(v)}"><span>${v}</span></div>
      <div><div class="lbl">${l}</div><div class="hint">${h}</div></div></div>`).join("")}</div>
    <nav class="tabs" role="tablist">${tabs.map(([id, l], i) => `<button role="tab" data-tab="${id}" aria-selected="${i === 0}">${l}</button>`).join("")}</nav>
    <div class="panel on" data-panel="overview">${renderOverview(d)}</div>
    <div class="panel" data-panel="tech">${renderTech(d)}</div>
    <div class="panel" data-panel="design">${renderDesign(d, meta)}</div>
    ${d.browser?.available ? `<div class="panel" data-panel="shots">${renderShots(d)}</div>` : ""}
    <div class="panel" data-panel="perf">${renderPerf(d)}</div>
    <div class="panel" data-panel="seo">${renderSeo(d)}</div>
    <div class="panel" data-panel="a11y">${renderA11y(d)}</div>
    <div class="panel" data-panel="security">${renderSecurity(d)}</div>
    <div class="panel" data-panel="structure">${renderStructure(d)}</div>
    <div class="panel" data-panel="raw"><pre class="raw">${esc(JSON.stringify(d, (k, v) => typeof v === "string" && v.startsWith("data:image") ? `(image, ${Math.round(v.length / 1024)} KB)` : v, 2))}</pre></div>`;
  const show = id => {
    root.querySelectorAll("nav.tabs button").forEach(b => b.setAttribute("aria-selected", b.dataset.tab === id));
    root.querySelectorAll(".panel").forEach(p => p.classList.toggle("on", p.dataset.panel === id));
  };
  root.querySelectorAll("nav.tabs button").forEach(b => b.addEventListener("click", () => show(b.dataset.tab)));
  root.querySelectorAll("[data-goto]").forEach(b => {
    const go = () => { show(b.dataset.goto); $("nav.tabs", root).scrollIntoView({ behavior: "smooth" }); };
    b.addEventListener("click", go); b.addEventListener("keydown", e => e.key === "Enter" && go());
  });
  root.querySelectorAll(".sw").forEach(b => b.addEventListener("click", () => navigator.clipboard?.writeText(b.dataset.color)));
  wireTokens(root, meta);
  $('[data-act="dl"]', root).onclick = () => {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([JSON.stringify(d, null, 2)], { type: "application/json" }));
    a.download = `deconstruct-site-${o.host}${meta.iteration ? "-v" + meta.iteration : ""}.json`; a.click();
  };
}

function renderOverview(d) {
  const o = d.overview, t = d.technologies.by_category, p = d.performance, sec = d.security;
  const stack = Object.entries(t).map(([c, list]) => `<div class="role-row"><b>${esc(c)}</b>${list.map(x => `<span class="pill">${esc(x.name)}${x.version ? " " + esc(x.version) : ""}</span>`).join("")}</div>`).join("");
  const allIssues = [...p.issues, ...d.seo.issues, ...d.accessibility.issues];
  const b = d.browser, sh = b?.screenshots, rd = d.rendering;
  const shotCard = b?.available ? card("How it looks", `<div class="shots">
      <div><div class="shot"><img src="${sh.above_fold}" alt="Desktop screenshot of ${esc(o.host)}"></div><div class="shot-cap">Desktop · 1366px</div></div>
      ${sh.mobile ? `<div><div class="shot"><img src="${sh.mobile}" alt="Mobile screenshot of ${esc(o.host)}"></div><div class="shot-cap">Mobile · 390px</div></div>` : ""}
    </div>`, "wide")
    : card("Browser rendering", `<span class="muted">${esc(b?.error || "Not run.")}</span>`, "wide");
  return `<div class="grid">
    ${shotCard}
    ${rd ? card("Rendering", kv([["Type", rd.client_side_rendered ? '<span class="pill warn">Client-side rendered</span>' : '<span class="pill good">Server-rendered HTML</span>'],
      ["Words in HTML", rd.raw_word_count.toLocaleString()], ["Words after JS", rd.rendered_word_count.toLocaleString()],
      ["Elements in HTML → after JS", `${rd.raw_elements.toLocaleString()} → ${rd.rendered_elements.toLocaleString()}`]])) : ""}
    ${card("Site", kv([["URL", link(o.final_url)], ["Title", esc(o.title)], ["Description", esc(o.description)], ["Language", esc(o.language)],
      ["Redirects", o.redirects.length ? o.redirects.map(r => `${r.status} ${esc(r.url)}`).join("<br>") : "None"]]))}
    ${card("Infrastructure", kv([["Host", esc(o.host)], ["IP addresses", o.ip_addresses.map(esc).join("<br>")], ["Server", esc(o.server)],
      ["Protocol", esc(o.http_version)], ["TLS", sec.tls?.valid ? `${esc(sec.tls.protocol)} · ${esc(sec.tls.issuer)}` : sec.tls?.valid === null ? '<span class="pill">Couldn\'t check</span>' : sec.tls ? '<span class="pill bad">Invalid</span>' : "No HTTPS"],
      ["Response time", `${o.response_ms} ms`], ["HTML size", bytes(o.html_size)]]))}
    ${card("Built with", stack || '<span class="muted">Nothing detected</span>', "wide")}
    ${card("At a glance", kv([["Requests", p.request_count], ["Page weight", bytes(p.total_known_bytes)], ["Words", d.structure.word_count.toLocaleString()],
      ["Colors in CSS", d.design.colors.length], ["Fonts", d.design.fonts.slice(0, 3).map(f => esc(f.value)).join(", ") || "—"],
      ["CSS variables", d.design.css_variable_count]]))}
    ${card("Top issues", issues(allIssues.slice(0, 8), "No major issues found."))}
    ${o.og_image ? card("Social preview image", `<img src="${esc(o.og_image)}" alt="Open Graph image" style="max-width:100%;border-radius:8px">`) : ""}
  </div>`;
}

function renderTech(d) {
  const cats = Object.entries(d.technologies.by_category);
  if (!cats.length) return card("Technology", '<span class="muted">No known technologies detected. The site may be custom-built or hide its fingerprints.</span>');
  return `<div class="grid">${cats.map(([c, list]) => card(c, list.map(t => `
    <div class="tech"><div style="min-width:0"><div class="name">${esc(t.name)} ${t.version ? `<span class="pill">${esc(t.version)}</span>` : ""}</div>
    ${t.evidence.map(e => `<div class="ev">${esc(e)}</div>`).join("")}</div></div>`).join(""))).join("")}</div>`;
}

const TOKEN_FORMATS = [["css", "CSS variables"], ["tailwind", "Tailwind v3"], ["tailwind4", "Tailwind v4"], ["json", "Figma / Style Dictionary"], ["scss", "SCSS"]];

function renderTokens(meta) {
  if (!meta.analysis_id) return "";
  return card("Export design tokens", `<div class="seg" role="tablist" aria-label="Token format">${TOKEN_FORMATS.map(([f, l], i) =>
      `<button type="button" role="tab" data-fmt="${f}" aria-selected="${i === 0}">${l}</button>`).join("")}</div>
    <p class="muted tok-note" style="font-size:12.5px;margin:10px 0">Colors, fonts, type scale, weights, line heights, spacing, radii, shadows, breakpoints and durations, named the way each format expects.</p>
    <pre class="raw tok-out" style="max-height:340px" tabindex="0">Loading…</pre>
    <div class="row" style="gap:8px;margin-top:10px"><button class="ghost" data-tok="copy">Copy</button><button class="ghost" data-tok="dl">Download</button></div>`, "wide tokens-card");
}

function wireTokens(root, meta) {
  const box = $(".tokens-card", root);
  if (!box) return;
  let current = null;
  const load = async fmt => {
    box.querySelectorAll("[data-fmt]").forEach(b => b.setAttribute("aria-selected", b.dataset.fmt === fmt));
    $(".tok-out", box).textContent = "Loading…";
    try {
      const r = await fetch(`/api/analyses/${meta.analysis_id}/tokens?format=${fmt}`).then(r => r.json());
      if (!r.ok) throw new Error(r.error);
      current = r.data;
      $(".tok-out", box).textContent = current.content;
      const n = Object.values(current.counts).reduce((a, b) => a + b, 0);
      $(".tok-note", box).textContent = `${n} tokens in ${Object.keys(current.counts).length} groups.` + (current.rendered
        ? " Color roles (background, text, primary) come from what the browser painted."
        : " This was a quick analysis, so colors are a palette without roles; run it with the browser for background, text and primary colors.");
    } catch (e) { $(".tok-out", box).textContent = "Couldn't build tokens: " + e.message; }
  };
  box.querySelectorAll("[data-fmt]").forEach(b => b.addEventListener("click", () => load(b.dataset.fmt)));
  $('[data-tok="copy"]', box).onclick = () => current && navigator.clipboard?.writeText(current.content).then(() => typeof toast === "function" && toast("Copied"));
  $('[data-tok="dl"]', box).onclick = () => {
    if (!current) return;
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([current.content], { type: "text/plain" }));
    a.download = current.filename; a.click();
  };
  load("css");
}

function renderDesign(d, meta = {}) {
  const ds = d.design;
  const translucent = c => /^#[0-9a-f]{8}$/.test(c.value) || /^(rgba|hsla)|\/\s*[\d.]+%?\s*\)$/.test(c.value);
  const swatch = list => list.map(c => `<button class="sw" data-color="${esc(c.value)}" title="Copy ${esc(c.value)}"><div class="c"><i style="background:${esc(c.value)}"></i></div>
    <div class="t">${esc(c.value)}<div class="n">${c.count}×</div></div></button>`).join("");
  const solid = ds.colors.filter(c => !translucent(c)), tints = ds.colors.filter(translucent);
  const sw = (solid.length ? `<div class="swatches">${swatch(solid)}</div>` : "")
    + (tints.length ? `<h3 style="margin:18px 0 10px">Transparent tints (${tints.length})</h3><div class="swatches">${swatch(tints)}</div>` : "");
  const roles = Object.entries(ds.color_roles).filter(([, l]) => l.length).map(([r, l]) =>
    `<div class="role-row"><b>${esc(r)}</b>${l.map(c => `<span class="mini" title="${esc(c.value)} (${c.count}×)" style="background:${esc(c.value)}"></span>`).join("")}</div>`).join("");
  const typeScale = ds.type_scale.filter(t => /^[\d.]+(px|rem|em)$/.test(t.value)).map(t =>
    `<div class="scale-row"><span class="v">${esc(t.value)} · ${t.count}</span><span style="font-size:${esc(t.value)};font-family:${esc(ds.fonts[0]?.value || "inherit")}">Aa Quick brown fox</span></div>`).join("");
  const radii = ds.radii.map(r => `<div style="display:inline-flex;flex-direction:column;align-items:center;margin:0 10px 10px 0;font-size:11px" class="mono">
    <div style="width:52px;height:52px;border:2px solid var(--ink);border-radius:${esc(r.value)}"></div>${esc(r.value)}</div>`).join("");
  const vars = Object.entries(ds.css_variables);
  const cp = ds.computed;
  const minis = list => list.map(c => `<button class="sw" data-color="${esc(c.value)}" title="Copy ${esc(c.value)}" style="width:auto"><div class="c" style="height:36px"><i style="background:${esc(c.value)}"></i></div><div class="t">${esc(c.value)}</div></button>`).join("");
  const computedCards = cp ? `
    ${card("Page colors by area (rendered)", `<div class="swatches">${minis(cp.background_by_area.slice(0, 10))}</div>
      <h3 style="margin:18px 0 10px">Text colors by amount of text</h3><div class="swatches">${minis(cp.text_colors.slice(0, 10))}</div>
      <p class="muted" style="font-size:12.5px;margin:10px 0 0">Measured from what the browser actually painted, so these are the colors you really see.</p>`, "wide")}
    ${card("Fonts in use (rendered)", bars(cp.fonts_by_text) + `<p class="muted" style="font-size:12.5px">Weighted by characters of text. Body: <span class="mono">${esc(cp.body["font-family"])}</span> ${esc(cp.body["font-size"])} / ${esc(cp.body["line-height"])}</p>`)}
    ${card("Buttons", cp.buttons.length ? cp.buttons.map(bt => `<span class="btn-demo" title="${esc(`${bt["background-color"]} · ${bt.color} · radius ${bt["border-radius"]} · padding ${bt.padding}`)}"
      style="background:${esc(bt["background-color"])};color:${esc(bt.color)};border-radius:${esc(bt["border-radius"])};padding:${esc(bt.padding)};font-size:${esc(bt["font-size"])};font-weight:${esc(bt["font-weight"])};font-family:${esc(bt["font-family"])};border:${esc(bt.border)};box-shadow:${esc(bt["box-shadow"])};text-transform:${esc(bt["text-transform"])}">${esc(bt.label)}</span>`).join("")
      + `<p class="muted" style="font-size:12.5px;margin:4px 0 0">Recreated from computed styles. Hover for values.</p>` : '<span class="muted">No buttons found</span>')}
    ${card("Typography (rendered)", `<div class="table-scroll"><table><thead><tr><th>Tag</th><th>Font</th><th>Size</th><th>Weight</th><th>Line height</th><th>Spacing</th><th>Color</th><th>Sample</th></tr></thead>
      ${cp.typography.map(t => `<tr><td><span class="pill">${esc(t.tag)}</span></td><td class="url">${esc(t["font-family"].split(",")[0])}</td><td class="mono">${esc(t["font-size"])}</td><td class="mono">${esc(t["font-weight"])}</td>
      <td class="mono">${esc(t["line-height"])}</td><td class="mono">${esc(t["letter-spacing"])}</td><td><span class="mini" style="display:inline-block;width:14px;height:14px;vertical-align:middle;background:${esc(t.color)}"></span></td>
      <td style="font-family:${esc(t["font-family"])};font-weight:${esc(t["font-weight"])};white-space:nowrap;max-width:260px;overflow:hidden;text-overflow:ellipsis">${esc(t.sample)}</td></tr>`).join("")}</table></div>`, "wide")}` : "";
  return `<div class="grid">
    ${renderTokens(meta)}
    ${computedCards}
    ${card(`Color palette from CSS (${ds.colors.length})`, (sw || '<span class="muted">No colors found</span>') + `<p class="muted" style="font-size:12.5px;margin:10px 0 0">Click a swatch to copy it.${ds.theme_color ? ` Theme color: <span class="mono">${esc(ds.theme_color)}</span>` : ""}</p>`, "wide")}
    ${card("Colors by role", roles || '<span class="muted">—</span>')}
    ${card("Typefaces", bars(ds.fonts) + (ds.font_faces.length ? `<p class="muted" style="font-size:13px">Self-hosted @font-face: ${ds.font_faces.map(esc).join(", ")}</p>` : "")
      + (ds.google_fonts.length ? `<p class="muted" style="font-size:13px">Loads Google Fonts</p>` : ""))}
    ${card("Type scale", typeScale || '<span class="muted">—</span>', "wide")}
    ${card("Font weights", bars(ds.font_weights))}
    ${card("Line heights", bars(ds.line_heights))}
    ${card("Spacing scale", bars(ds.spacing_scale))}
    ${card("Border radius", radii || '<span class="muted">—</span>')}
    ${card("Breakpoints", bars(ds.breakpoints))}
    ${card("Motion", kv([["Durations", ds.motion.durations.map(x => `<span class="pill">${esc(x.value)} ×${x.count}</span>`).join(" ") || "—"],
      ["Keyframes", ds.motion.keyframes.map(esc).join(", ") || "—"], ["Max z-index", ds.max_z_index]]))}
    ${card("Shadows", ds.shadows.map(s => `<div style="display:flex;gap:12px;align-items:center;margin-bottom:12px"><div style="width:44px;height:30px;border-radius:6px;background:var(--panel);box-shadow:${esc(s.value)};flex:none"></div><span class="mono" style="font-size:11px;overflow-wrap:anywhere">${esc(s.value)}</span></div>`).join("") || '<span class="muted">—</span>')}
    ${card(`CSS variables (${ds.css_variable_count})`, vars.length ? `<div class="table-scroll" style="max-height:360px"><table>${vars.map(([k, v]) => `<tr><td class="url">${esc(k)}</td><td class="url">${/^#|rgb|hsl/.test(v) ? `<span class="mini" style="display:inline-block;vertical-align:middle;width:14px;height:14px;background:${esc(v)}"></span> ` : ""}${esc(v)}</td></tr>`).join("")}</table></div>` : '<span class="muted">None</span>', "wide")}
    <p class="muted card wide" style="font-size:13px;margin:0">Analyzed ${bytes(ds.css_bytes_analyzed)} of CSS. Values are counted from stylesheet declarations, so frequency shows how often a value is written, not how much of the page it covers.</p>
  </div>`;
}

function renderShots(d) {
  const sh = d.browser.screenshots, comps = d.browser.components;
  const names = { header: "Header", footer: "Footer", form: "First form" };
  return `<div class="grid">
    ${card(`Full page${sh.page_height > sh.full_page_height ? ` (first ${sh.full_page_height}px of ${sh.page_height}px)` : ""}`,
      `<div class="shot fullpage"><img src="${sh.full_page}" alt="Full-page screenshot"></div>`, "wide")}
    ${Object.entries(comps).map(([k, c]) => card(`${names[k] || k} · ${c.width}×${c.height}`,
      `<div class="shot"><img src="${c.image}" alt="${esc(names[k] || k)} component"></div><div class="shot-cap mono">${esc(c.selector)}</div>`, "wide")).join("")}
  </div>`;
}

const VITAL_FMT = { ttfb: x => (x / 1000).toFixed(2) + " s", fcp: x => (x / 1000).toFixed(2) + " s", lcp: x => (x / 1000).toFixed(2) + " s",
  tbt: x => Math.round(x) + " ms", cls: x => x.toFixed(3), inp: x => Math.round(x) + " ms", load: x => (x / 1000).toFixed(2) + " s" };
const VITAL_LIMITS = { lcp: [2500, 4000], fcp: [1800, 3000], tbt: [200, 600], cls: [0.1, 0.25], ttfb: [800, 1800], inp: [200, 500] };
const rateVital = (k, x) => x == null || !VITAL_LIMITS[k] ? "" : x <= VITAL_LIMITS[k][0] ? "good" : x > VITAL_LIMITS[k][1] ? "poor" : "needs-improvement";

// p is the report's performance section (older saved reports only have p.vitals from one desktop load).
function renderVitals(p) {
  const v = p.vitals, mobile = p.vitals_method === "mobile-throttled", t = p.throttle;
  const names = { lcp: "Largest Contentful Paint", fcp: "First Contentful Paint", tbt: "Total Blocking Time", cls: "Cumulative Layout Shift", ttfb: "Server response (TTFB)" };
  const range = k => v[`${k}_range`] && v[`${k}_range`][0] !== v[`${k}_range`][1]
    ? `<div class="vr">${VITAL_FMT[k](v[`${k}_range`][0])} – ${VITAL_FMT[k](v[`${k}_range`][1])}</div>` : "";
  const how = mobile
    ? `Median of ${v.runs} cold load${v.runs === 1 ? "" : "s"} as a mid-range phone on 4G: ${esc(t?.name || "throttled")} (${Math.round(t.down_bps * 8 / 1024 / 1024)} Mbps, ${t.latency_ms} ms latency, ${t.viewport.width}×${t.viewport.height}).
       Ranges show the spread across runs. TTFB is the server's own response time; throttling adds its latency afterwards.`
    : "One unthrottled desktop load on this machine. Re-analyze to get throttled mobile measurements.";
  const d = p.vitals_desktop;
  const runs = (p.vitals_runs || []);
  return `<div class="vitals">${Object.entries(names).map(([k, n]) => `<div class="vital ${v.ratings[k] || ""}">
    <div class="v">${v[k] == null ? "—" : VITAL_FMT[k](v[k])}</div>${range(k)}<div class="k">${n}</div><div class="r">${esc((v.ratings[k] || "n/a").replace("-", " "))}</div></div>`).join("")}</div>
    ${v.lcp_element ? `<p class="muted" style="font-size:12.5px;margin:12px 0 0">LCP element: <span class="mono">${esc(v.lcp_element.slice(0, 160))}</span></p>` : ""}
    <p class="muted" style="font-size:12.5px;margin:6px 0 0">${how}</p>
    ${mobile && d ? `<p style="font-size:12.5px;margin:6px 0 0"><b>Unthrottled desktop load for comparison:</b> LCP ${d.lcp != null ? VITAL_FMT.lcp(d.lcp) : "—"} · FCP ${d.fcp != null ? VITAL_FMT.fcp(d.fcp) : "—"} · TBT ${d.tbt != null ? VITAL_FMT.tbt(d.tbt) : "—"} · CLS ${d.cls != null ? VITAL_FMT.cls(d.cls) : "—"}</p>` : ""}
    ${runs.length > 1 || runs.some(r => r.error) ? `<details style="margin-top:8px"><summary class="muted" style="cursor:pointer;font-size:12.5px">Individual runs</summary>
      <div class="table-scroll"><table><thead><tr><th>Run</th><th>FCP</th><th>LCP</th><th>TBT</th><th>CLS</th><th>Load</th></tr></thead>
      ${runs.map((r, i) => `<tr><td>${i + 1}</td>${r.error ? `<td colspan="5" class="muted">${esc(r.error)}</td>` : ["fcp", "lcp", "tbt", "cls", "load"].map(k => `<td class="mono">${r[k] != null ? VITAL_FMT[k](r[k]) : "—"}</td>`).join("")}</tr>`).join("")}</table></div></details>` : ""}
    <p class="muted" style="font-size:12.5px;margin:6px 0 0">Load event ${v.load ? (v.load / 1000).toFixed(2) + " s" : "—"} · ${bytes(v.transfer_bytes)} transferred · ${(v.dom_nodes || 0).toLocaleString()} DOM nodes · ${v.long_tasks ?? "—"} long tasks</p>`;
}

function renderField(f) {
  if (!f) return "";
  if (!f.available) {
    const msg = {
      no_key: `Set a free Chrome UX Report API key in <span class="mono">CRUX_API_KEY</span> to see what real Chrome users experienced on this site over the last 28 days.
        <a href="https://developer.chrome.com/docs/crux/api" target="_blank" rel="noopener noreferrer">Get a key</a>.`,
      not_enough_traffic: "Google has no real-user data for this page or site: it doesn't get enough Chrome traffic to be in the Chrome UX Report.",
      error: `Couldn't read the Chrome UX Report: ${esc(f.error || "unknown error")}.`,
    }[f.reason] || "No field data.";
    return card("Real-user data (Chrome UX Report)", `<p class="muted" style="font-size:13.5px;margin:0">${msg}</p>`, "wide");
  }
  const order = ["lcp", "inp", "cls", "fcp", "ttfb"].filter(k => f.metrics[k]);
  return card(`Real-user data · ${f.scope === "page" ? "this page" : "whole site"} · phones`, `<div class="vitals">${order.map(k => {
      const m = f.metrics[k], r = rateVital(k, m.p75), [g, ni, poor] = m.distribution.concat([0, 0, 0]);
      return `<div class="vital ${r}"><div class="v">${m.p75 == null ? "—" : VITAL_FMT[k](m.p75)}</div><div class="k">${esc(m.label)}</div><div class="r">${esc(r.replace("-", " ") || "n/a")} · p75</div>
        <div class="dist" title="${g}% good · ${ni}% needs improvement · ${poor}% poor"><i class="g" style="width:${g}%"></i><i class="n" style="width:${ni}%"></i><i class="p" style="width:${poor}%"></i></div></div>`;
    }).join("")}</div>
    <p class="muted" style="font-size:12.5px;margin:10px 0 0">75th percentile of real Chrome visitors on phones, ${esc(f.period?.[0] || "")} to ${esc(f.period?.[1] || "")}. Bars show the share of visits rated good / needs improvement / poor. This is what Google uses for Core Web Vitals in search.</p>`, "wide");
}

function renderPerf(d) {
  const p = d.performance, b = d.browser;
  const types = Object.entries(p.browser_requests_by_type || p.requests_by_type).map(([k, n]) => ({ value: k, count: n }));
  const errs = b?.available ? [...b.page_errors.map(e => ["bad", `Uncaught: ${e}`]), ...b.console.map(c => [c.type === "error" ? "bad" : "", `${c.type}: ${c.text}`]),
    ...b.failed_requests.map(f => ["bad", `Failed ${f.type}: ${f.url} (${f.error})`]), ...b.http_errors.map(h => ["bad", `HTTP ${h.status} ${h.type}: ${h.url}`])] : [];
  return `<div class="grid">
    ${p.vitals ? card(p.vitals_method === "mobile-throttled" ? "Core Web Vitals · lab · mobile on 4G" : "Core Web Vitals · lab · desktop", renderVitals(p), "wide") : ""}
    ${renderField(p.field)}
    ${b?.available ? card(`Console & network errors (${errs.length})`, errs.length ? `<div style="max-height:320px;overflow:auto">${errs.map(([lvl, e]) => `<div class="issue"><span class="dot ${lvl}"></span><span class="mono" style="font-size:12px;overflow-wrap:anywhere">${esc(e)}</span></div>`).join("")}</div>`
      : '<div class="issue"><span class="dot good"></span><span>No console errors or failed requests.</span></div>', "wide") : ""}
    ${card("Summary", kv([["Server response", `${p.server_response_ms} ms`], ["HTML", `${bytes(p.html_size)} ${p.html_compression ? `<span class="pill good">${esc(p.html_compression)}</span>` : '<span class="pill bad">uncompressed</span>'}`],
      ["Requests", p.request_count], ["Known page weight", bytes(p.total_known_bytes)], ["Inline JS", bytes(p.inline_script_bytes)],
      ["Render-blocking", p.render_blocking.length], ["HTML cache", `<span class="mono">${esc(p.html_cache_control || "—")}</span>`]]))}
    ${card("Issues & fixes", issues(p.issues, "No performance issues detected."))}
    ${card(`Requests by type${p.browser_request_count ? ` (${p.browser_request_count} in browser)` : ""}`, bars(types))}
    ${card("Bytes by type", Object.entries(p.bytes_by_type).map(([k, v]) => `<div class="bar-row"><span class="k">${esc(k)}</span><span class="n">${bytes(v)}</span></div>`).join("") || "—")}
    ${card("Third-party hosts", p.third_party_hosts.length ? `<ul class="plain">${p.third_party_hosts.map(([h, n]) => `<li><span class="mono">${esc(h)}</span> <span class="muted">· ${n}</span></li>`).join("")}</ul>` : '<span class="muted">None — all resources are first-party.</span>')}
    ${card(`All resources (${p.resources.length})`, `<div class="table-scroll"><table><thead><tr><th>Type</th><th>URL</th><th>Size</th><th>Time</th><th>Enc.</th><th>Cache</th></tr></thead><tbody>
      ${p.resources.map(r => `<tr><td>${esc(r.type)}${r.render_blocking ? ' <span class="pill warn">blocking</span>' : ""}</td><td class="url">${esc(r.url)}</td>
      <td>${bytes(r.size)}</td><td>${r.ms != null ? r.ms + " ms" : "—"}</td><td>${esc(r.encoding || "")}</td><td class="url">${esc(r.cache || "")}</td></tr>`).join("")}</tbody></table></div>`, "wide")}
  </div>`;
}

function renderSeo(d) {
  const s = d.seo;
  const ogRows = Object.entries(s.open_graph).concat(Object.entries(s.twitter));
  return `<div class="grid">
    ${card("Search listing", kv([["Title", `${esc(s.title)} <span class="muted">(${s.title_length} chars)</span>`],
      ["Description", s.description ? `${esc(s.description)} <span class="muted">(${s.description_length} chars)</span>` : null],
      ["Canonical", link(s.canonical)], ["H1", s.h1.map(esc).join("<br>") || null], ["Robots meta", esc(s.robots_meta)], ["Hreflang", s.hreflang.map(esc).join(", ") || null]]))}
    ${card("Issues", issues(s.issues, "No SEO issues found."))}
    ${card("Crawling", kv([["robots.txt", yes(s.robots_txt.exists, "Found", "Missing")], ["Sitemaps in robots", s.robots_txt.sitemaps.map(link).join("<br>") || null],
      ["sitemap.xml", s.sitemap_xml.exists ? `<span class="pill good">Found</span> ${s.sitemap_xml.url_count} URLs` : '<span class="pill bad">Missing</span>'],
      ["Unknown URLs return 404", yes(s.soft_404 == null ? null : !s.soft_404)], ["Structured data", s.structured_data.map(t => `<span class="pill">${esc(t)}</span>`).join(" ") || null]]))}
    ${card("Social tags (Open Graph / Twitter)", ogRows.length ? `<div class="table-scroll"><table>${ogRows.map(([k, v]) => `<tr><td class="url">${esc(k)}</td><td style="overflow-wrap:anywhere">${esc(v)}</td></tr>`).join("")}</table></div>` : '<span class="muted">None</span>')}
    ${s.robots_txt.preview ? card("robots.txt", `<pre class="raw" style="max-height:260px">${esc(s.robots_txt.preview)}</pre>`, "wide") : ""}
  </div>`;
}

function renderAxe(axe) {
  const impacts = ["critical", "serious", "moderate", "minor"];
  const counts = Object.fromEntries(impacts.map(i => [i, axe.violations.filter(v => v.impact === i).length]));
  const cls = { critical: "bad", serious: "bad", moderate: "warn", minor: "" };
  const tag = t => t === "best-practice" ? "Best practice"
    // wcag2a → WCAG 2.0 A, wcag21aa → WCAG 2.1 AA, wcag143 → SC 1.4.3, wcag1412 → SC 1.4.12
    : /^wcag\d\d?a+$/.test(t) ? t.replace(/^wcag(\d)(\d?)(a+)$/, (m, a, b, l) => `WCAG ${a}.${b || 0} ${l.toUpperCase()}`)
    : t.replace(/^wcag(\d)(\d)(\d+)$/, (m, a, b, c) => `SC ${a}.${b}.${c}`);
  const list = [...axe.violations].sort((a, b) => impacts.indexOf(a.impact) - impacts.indexOf(b.impact) || b.count - a.count);
  return `<div class="row" style="gap:8px;margin-bottom:12px">
      ${impacts.map(i => `<span class="pill ${counts[i] ? cls[i] : ""}">${counts[i]} ${i}</span>`).join("")}
      <span class="pill good">${axe.passes} rules passed</span>${axe.incomplete ? `<span class="pill" title="Rules axe couldn't decide automatically">${axe.incomplete} need manual review</span>` : ""}</div>
    ${list.length ? list.map(v => `<details class="axe-rule"><summary>
        <span class="pill ${cls[v.impact] || ""}">${esc(v.impact || "unknown")}</span> <b>${esc(v.help)}</b>
        <span class="muted">· ${v.count} element${v.count === 1 ? "" : "s"}</span>
        <span class="axe-tags">${v.tags.map(t => `<span class="pill">${esc(tag(t))}</span>`).join("")}</span></summary>
      <p style="font-size:13.5px;margin:8px 0">${esc(v.description)} <a href="${esc(v.help_url)}" target="_blank" rel="noopener noreferrer">How to fix ↗</a></p>
      ${v.nodes.map(n => `<div class="axe-node"><div class="mono" style="font-size:11.5px;color:var(--ink-3)">${esc(n.target)}</div>
        <code>${esc(n.html)}</code>${n.summary ? `<div style="font-size:12.5px;color:var(--ink-2);white-space:pre-line">${esc(n.summary)}</div>` : ""}</div>`).join("")}
      ${v.count > v.nodes.length ? `<div class="muted" style="font-size:12.5px">…and ${v.count - v.nodes.length} more elements</div>` : ""}
    </details>`).join("")
      : '<div class="issue"><span class="dot good"></span><span>No WCAG A/AA or best-practice violations found by axe-core.</span></div>'}`;
}

function renderA11y(d) {
  const a = d.accessibility;
  if (a.axe) {
    return `<div class="grid">
      ${card(`axe-core ${esc(a.axe.version)} · WCAG 2.2 A/AA and best practices`, renderAxe(a.axe), "wide")}
      ${a.mobile && !a.mobile.error ? card(`Mobile (${a.mobile.viewport_width}px)`, kv([["Sideways scrolling", yes(!a.mobile.horizontal_overflow, "None", `Yes — ${a.mobile.page_width}px wide`)],
        ["Small tap targets (<24px)", a.mobile.small_tap_targets], ["Body text size", `${a.mobile.body_font_px}px`]])) : ""}
      ${card("Page basics", kv([["Page language", a.lang ? `<span class="pill good">${esc(a.lang)}</span>` : '<span class="pill bad">Missing</span>'],
        ["Skip-to-content link", yes(a.skip_link)], ["Images", a.images], ["ARIA attributes", a.aria_attributes]]))}
      <p class="muted card wide" style="font-size:13px;margin:0">Checked by axe-core on the rendered page. Automated tools can't judge everything: keyboard navigation, focus order, screen-reader announcements and whether alt text is meaningful still need a manual test.</p>
    </div>`;
  }
  return `<div class="grid">
    ${a.axe_error ? `<div class="issue card wide" style="margin:0"><span class="dot"></span><span>${esc(a.axe_error)} Showing the basic HTML checks instead.</span></div>` : ""}
    ${card("Checks", kv([["Page language", a.lang ? `<span class="pill good">${esc(a.lang)}</span>` : '<span class="pill bad">Missing</span>'],
      ["Images missing alt", `${a.images_missing_alt} of ${a.images}`], ["Unlabeled form fields", a.unlabeled_fields],
      ["Buttons without a name", a.nameless_buttons], ["Links without a name", a.nameless_links], ["Heading level skips", a.heading_skips],
      ["Skip-to-content link", yes(a.skip_link)], ["ARIA attributes", a.aria_attributes]]))}
    ${card("Issues", issues(a.issues, "No accessibility problems found."))}
    ${a.contrast ? card(`Color contrast · ${a.contrast.failing_elements} of ${a.contrast.checked} text elements fail`, (a.contrast.failures.length
      ? `<div class="table-scroll"><table><thead><tr><th>Sample</th><th>Ratio</th><th>Needs</th><th>Size</th><th>Colors</th><th>Count</th></tr></thead>
        ${a.contrast.failures.map(f => `<tr><td><span class="contrast-sample" style="color:${esc(f.fg)};background:${esc(f.bg)}">${esc(f.text)}</span></td>
        <td><span class="pill bad">${f.ratio}:1</span></td><td>${f.required}:1</td><td class="mono">${esc(f.font_size)} ${esc(f.tag)}</td>
        <td class="mono">${esc(f.fg)} on ${esc(f.bg)}</td><td>${f.count}</td></tr>`).join("")}</table></div>`
      : '<div class="issue"><span class="dot good"></span><span>All checked text meets WCAG AA contrast.</span></div>')
      + (a.contrast.uncertain ? `<p class="muted" style="font-size:12.5px">${a.contrast.uncertain} elements couldn't be checked (text over images or gradients, or hidden text).</p>` : ""), "wide") : ""}
    ${a.mobile && !a.mobile.error ? card("Mobile (390px)", kv([["Sideways scrolling", yes(!a.mobile.horizontal_overflow, "None", `Yes — ${a.mobile.page_width}px wide`)],
      ["Small tap targets (<24px)", a.mobile.small_tap_targets], ["Body text size", `${a.mobile.body_font_px}px`]])) : ""}
    <p class="muted card wide" style="font-size:13px;margin:0">${a.contrast ? "Contrast and mobile checks come from the rendered page; the rest from the DOM." : "These checks read the HTML only. Turn on browser rendering for contrast and mobile checks."} Focus styles and keyboard behavior still need a manual test.</p>
  </div>`;
}

function renderVulnLibs(vl) {
  if (!vl) return "";
  if (!vl.available) return card("Vulnerable JavaScript libraries", `<span class="muted">${esc(vl.error)}</span>`, "wide");
  const sevClass = s => s === "critical" || s === "high" ? "bad" : s === "medium" ? "warn" : "";
  const body = vl.findings.length ? vl.findings.map(f => `<div class="vuln">
      <div class="row" style="gap:8px;flex-wrap:wrap"><b>${esc(f.component)} ${esc(f.version)}</b><span class="pill ${sevClass(f.severity)}">${esc(f.severity)}</span>
        <span class="muted" style="font-size:12.5px">${f.vulnerabilities.length} known issue${f.vulnerabilities.length === 1 ? "" : "s"} · found by ${esc(f.detected_by.join(", "))}</span></div>
      <div style="font-size:13px;margin:4px 0">${f.upgrade_to ? `Upgrade to <b class="mono">${esc(f.upgrade_to)}</b> or later.` : "No fixed release in this version line (end of life): move to a supported version."}</div>
      <details><summary class="muted" style="font-size:13px;cursor:pointer">Vulnerabilities</summary>${f.vulnerabilities.map(v => `<div class="issue"><span class="dot ${v.severity === "low" ? "" : "bad"}"></span><div style="min-width:0">
        ${esc(v.summary)} <span class="pill ${sevClass(v.severity)}">${esc(v.severity)}</span>${v.below ? ` <span class="muted" style="font-size:12px">fixed in ${esc(v.below)}</span>` : ""}
        <div style="font-size:12px">${[...v.cve, ...(v.ghsa ? [v.ghsa] : [])].map(id => `<span class="mono">${esc(id)}</span>`).join(" · ")}${v.info[0] ? ` · <a href="${esc(v.info[0])}" target="_blank" rel="noopener noreferrer">details</a>` : ""}</div></div></div>`).join("")}</details>
      ${f.sources.length ? `<div class="mono muted" style="font-size:11.5px;overflow-wrap:anywhere">${f.sources.map(esc).join("<br>")}</div>` : ""}</div>`).join("")
    : `<div class="issue"><span class="dot good"></span><span>No libraries with known vulnerabilities found.</span></div>`;
  return card(`Vulnerable JavaScript libraries${vl.findings.length ? ` (${vl.findings.length})` : ""}`, body
    + (vl.findings.length ? `<p class="muted" style="font-size:12.5px;margin:10px 0 0">Matched by version number. Some issues only apply to certain setups (for example a self-hosted server or a particular feature), so read the details before treating each one as exploitable here.</p>` : "")
    + `<p class="muted" style="font-size:12.5px;margin:10px 0 0">Checked ${vl.scripts_checked} scripts (${vl.scripts_downloaded} downloaded) against the ${esc(vl.database)} database of ${vl.database_components} libraries.
      ${vl.libraries_seen.length ? `Versions seen: ${vl.libraries_seen.map(esc).join(", ")}.` : "No library versions could be identified."}</p>`, "wide");
}

function renderSecurity(d) {
  const s = d.security, t = s.tls;
  return `<div class="grid">
    ${renderVulnLibs(s.vulnerable_libraries)}
    ${card("Connection", kv([["HTTPS", yes(s.https)], ["HTTP → HTTPS redirect", yes(s.http_redirects_to_https)],
      ["Protocol", esc(s.alpn === "h2" ? "HTTP/2" : s.alpn || "—")],
      t && ["Certificate", t.valid ? `<span class="pill good">Valid</span> ${esc(t.protocol)}` : t.valid === null ? `<span class="pill">Couldn't check</span> <span class="muted">${esc(t.error)}</span>` : `<span class="pill bad">Invalid</span> ${esc(t.error)}`],
      t?.valid && ["Issuer", esc(t.issuer)], t?.valid && ["Expires", `${esc(t.expires)} <span class="pill ${t.days_left < 14 ? "bad" : t.days_left < 30 ? "warn" : ""}">${t.days_left} days</span>`],
      t?.valid && ["Covers", `${t.san_count} names: <span class="mono">${t.san_sample.map(esc).join(", ")}</span>`],
      ["CORS", s.cors ? `<span class="mono">${esc(s.cors)}</span>` : "Not set"]]))}
    ${card("Security headers", s.headers.map(h => `<div class="issue"><span class="dot ${h.present ? "good" : "bad"}"></span><div style="min-width:0"><b class="mono" style="font-size:13px">${esc(h.name)}</b>
      <div class="muted" style="font-size:13px">${esc(h.why)}</div>${h.value ? `<div class="mono muted" style="font-size:11.5px;overflow-wrap:anywhere">${esc(h.value.slice(0, 220))}</div>` : ""}</div></div>`).join(""))}
    ${card(`Cookies (${s.cookies.length})`, s.cookies.length ? `<div class="table-scroll"><table><thead><tr><th>Name</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th></tr></thead>
      ${s.cookies.map(c => `<tr><td class="url">${esc(c.name)}</td><td>${yes(c.secure)}</td><td>${yes(c.http_only)}</td><td>${esc(c.same_site || "—")}</td></tr>`).join("")}</table></div>` : '<span class="muted">No cookies set on the first response.</span>')}
    ${card("Other findings", issues([
      ...s.version_leaks.map(v => `Server reveals software version: ${v.header}: ${v.value}`),
      ...(s.mixed_content.length ? [`${s.mixed_content.length} resources load over insecure http:// (mixed content).`] : []),
      ...(s.third_party_scripts_without_sri.length ? [`${s.third_party_scripts_without_sri.length} third-party scripts have no integrity (SRI) hash.`] : []),
      ...(s.cors === "*" ? ["Any website can read this page's responses (Access-Control-Allow-Origin: *)."] : []),
    ], "Nothing else of note."))}
    ${card("All response headers", `<div class="table-scroll"><table>${Object.entries(d.response_headers).map(([k, v]) => `<tr><td class="url">${esc(k)}</td><td class="url">${esc(v)}</td></tr>`).join("")}</table></div>`, "wide")}
  </div>`;
}

function renderStructure(d) {
  const s = d.structure;
  return `<div class="grid">
    ${card("Page outline", s.outline.length ? `<ul style="margin:0;padding:0" class="outline">${s.outline.map(h => `<li style="padding-left:${(h.level - 1) * 16}px"><span class="pill">h${h.level}</span> ${esc(h.text)}</li>`).join("")}</ul>` : '<span class="muted">No headings</span>', "wide")}
    ${card("Landmarks", kv(Object.entries(s.landmarks).map(([k, v]) => [`<${k}>`, v ? v : '<span class="muted">0</span>'])))}
    ${card("Content", kv([["Words", s.word_count.toLocaleString()], ["Reading time", `${s.reading_time_min} min`], ["Elements", s.element_count.toLocaleString()],
      ["Most used tags", s.top_elements.slice(0, 8).map(([t, n]) => `<span class="pill">${esc(t)} ${n}</span>`).join(" ")],
      ["Internal links", s.internal_links], ["External links", s.external_links]]))}
    ${card("Navigation", s.navigation.length ? `<ul class="plain">${s.navigation.map(n => `<li>${esc(n.text || "(no text)")} <span class="muted mono" style="font-size:11.5px">${esc(n.href)}</span></li>`).join("")}</ul>` : '<span class="muted">No &lt;nav&gt; found</span>')}
    ${card("Linked domains", s.external_domains.length ? `<ul class="plain">${s.external_domains.map(([h, n]) => `<li><span class="mono">${esc(h)}</span> <span class="muted">· ${n}</span></li>`).join("")}</ul>` : '<span class="muted">None</span>')}
    ${card("Social & contact", (s.social_profiles.concat(s.contact)).map(u => `<div>${link(u)}</div>`).join("") || '<span class="muted">None found</span>')}
    ${card(`Forms (${s.forms.length})`, s.forms.map(f => `<div style="margin-bottom:10px"><span class="pill">${esc(f.method)}</span> <span class="mono" style="font-size:12px;overflow-wrap:anywhere">${esc(f.action)}</span>
      <div class="muted" style="font-size:13px">${f.fields.map(x => esc(`${x.name || "?"} (${x.type})`)).join(", ") || "no fields"}</div></div>`).join("") || '<span class="muted">No forms</span>')}
    ${s.iframes.length ? card("Embedded iframes", s.iframes.map(u => `<div class="mono" style="font-size:12px;overflow-wrap:anywhere">${esc(u)}</div>`).join("")) : ""}
  </div>`;
}

