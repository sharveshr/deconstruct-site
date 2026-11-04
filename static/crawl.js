// Crawl pages: start a multi-page crawl, watch it run, and read the site-wide results.

let crawlTimer = null;
const CRAWL_LIVE = ["queued", "crawling", "checking", "stopping"];
const sevDot = s => s === "critical" ? "bad" : s === "warning" ? "" : "info";

function crawlStatusPill(c) {
  const p = c.progress || {};
  if (c.status === "queued") return '<span class="pill">Starting</span>';
  if (c.status === "crawling") return `<span class="pill warn">Crawling ${p.pages_done ?? c.pages_done}/${c.max_pages}</span>`;
  if (c.status === "checking") return '<span class="pill warn">Checking links</span>';
  if (c.status === "stopping") return '<span class="pill">Stopping</span>';
  if (c.status === "error") return '<span class="pill bad">Failed</span>';
  if (c.status === "stopped") return '<span class="pill">Stopped</span>';
  return '<span class="pill good">Done</span>';
}

async function pageCrawls(q, token) {
  const data = await api("/api/crawls");
  if (!fresh(token)) return;
  const list = data.crawls;
  view.innerHTML = `<div class="wrap">
    <div class="page-head"><div><h1>Crawl</h1>
      <p>Follow a site's links and sitemap to check every page: broken pages and links, redirects, duplicate or missing titles and descriptions, thin or slow pages, orphans, and technology missing from some templates.</p></div></div>
    <form class="search" id="crawl-form" style="max-width:none">
      <label for="crawl-url" style="position:absolute;left:-9999px">Website to crawl</label>
      <input id="crawl-url" placeholder="example.com" value="${esc(q.get("url") || "")}" autocomplete="url" required>
      <label class="toggle" style="margin:0 6px;white-space:nowrap">Up to
        <select class="field" id="crawl-pages" style="padding:4px 8px;font-size:13px">${data.limits.map(n => `<option value="${n}" ${n === 100 ? "selected" : ""}>${n} pages</option>`).join("")}</select></label>
      <button class="primary" type="submit">Start crawl →</button>
    </form>
    <p class="muted" style="font-size:12.5px;margin:8px 2px 0">Follows robots.txt, stays on the same site, and checks up to 300 outgoing links.
      ${data.background ? "Crawls keep running if you leave this page." : "On this server a crawl only advances while this page is open."}</p>
    <div id="crawl-error" class="error" role="alert"></div>
    ${list.length ? `<div class="section-title">Your crawls</div><div class="data-table"><table><thead><tr><th>Site</th><th>Started</th><th>Status</th><th>Pages</th><th>Health</th><th>Broken</th><th></th></tr></thead><tbody>
      ${list.map(c => `<tr class="click" data-href="#/crawls/${c.id}"><td><b>${esc(c.host)}</b><div class="muted" style="font-size:12px">${esc(c.root_url)}</div></td>
        <td>${esc(fmtTime(c.created_at))}<div class="muted" style="font-size:12px">${esc(ago(c.created_at))}</div></td>
        <td>${crawlStatusPill(c)}</td><td>${c.pages_done}<span class="muted"> / ${c.max_pages}</span></td>
        <td>${c.health == null ? "—" : `<span class="ms ${scoreClass(c.health)}" style="display:inline-flex">${c.health}</span>`}</td>
        <td>${c.broken == null ? "—" : c.broken ? `<span style="color:var(--bad);font-weight:600">${c.broken}</span>` : "0"}</td>
        <td><button class="btn sm danger" data-del="${c.id}" aria-label="Delete crawl of ${esc(c.host)}">Delete</button></td></tr>`).join("")}</tbody></table></div>`
      : `<div class="grid" style="margin-top:22px">${[
        ["Broken pages & links", "Pages returning 4xx/5xx, links to them, and outgoing links that are dead."],
        ["Titles & descriptions", "Missing, duplicate and over-long titles and meta descriptions, missing H1s."],
        ["Redirects", "Internal links that redirect, and chains of more than one hop."],
        ["Orphans & sitemap", "Sitemap pages nothing links to, and pages missing from the sitemap."],
        ["Speed", "Slowest and heaviest pages, median and 90th-percentile response time."],
        ["Consistency", "Analytics, tag managers or frameworks missing from some templates."],
      ].map(([t, d]) => `<div class="card"><b>${t}</b><div class="muted" style="font-size:13.5px;margin-top:4px">${d}</div></div>`).join("")}</div>`}
  </div>`;
  $("#crawl-form").addEventListener("submit", async e => {
    e.preventDefault();
    const btn = e.submitter; btn.disabled = true;
    try {
      const c = await api("/api/crawls", { method: "POST", body: { url: $("#crawl-url").value.trim(), max_pages: +$("#crawl-pages").value } });
      location.hash = `#/crawls/${c.id}`;
    } catch (err) { const box = $("#crawl-error"); box.textContent = err.message; box.style.display = "block"; btn.disabled = false; }
  });
  view.querySelectorAll("tr[data-href]").forEach(tr => tr.addEventListener("click", () => location.hash = tr.dataset.href));
  view.querySelectorAll("[data-del]").forEach(b => b.addEventListener("click", async e => {
    e.stopPropagation();
    if (!confirm("Delete this crawl and its results?")) return;
    await api(`/api/crawls/${b.dataset.del}`, { method: "DELETE" }); route();
  }));
}

async function pageCrawl(id, q, token) {
  const c = await api(`/api/crawls/${id}`);
  if (!fresh(token)) return;
  const live = CRAWL_LIVE.includes(c.status);
  const s = c.summary;
  view.innerHTML = `<div class="wrap">
    <div class="page-head"><div><div class="crumbs"><a href="#/crawls">Crawls</a> / ${esc(c.host)}</div>
      <h1>${esc(c.host)}</h1>
      <p>${link(c.root_url)} · started ${esc(fmtTime(c.created_at))} · up to ${c.max_pages} pages${s?.duration_s != null ? ` · took ${duration(s.duration_s)}` : ""}</p></div>
      <div class="row">${live ? '<button class="btn" id="crawl-stop">Stop</button>' : `
        <button class="btn" id="crawl-again">Crawl again</button>
        ${s ? `<a class="btn" href="/api/crawls/${c.id}/pages.csv" download>Download CSV</a>` : ""}`}
        ${c.site_id ? `<a class="btn" href="#/sites/${c.site_id}">Site</a>` : ""}
        <button class="btn danger" id="crawl-del">Delete</button></div></div>
    <div id="crawl-body">${live ? crawlProgress(c) : c.status === "error" ? `<div class="error" style="display:block">This crawl failed: ${esc(c.error)}</div>` : crawlResults(c)}</div>
  </div>`;
  $("#crawl-del").onclick = async () => { if (confirm("Delete this crawl?")) { await api(`/api/crawls/${id}`, { method: "DELETE" }); location.hash = "#/crawls"; } };
  $("#crawl-stop")?.addEventListener("click", async e => { e.target.disabled = true; await api(`/api/crawls/${id}/stop`, { method: "POST" }); route(); });
  $("#crawl-again")?.addEventListener("click", async () => {
    const n = await api("/api/crawls", { method: "POST", body: { url: c.root_url, max_pages: c.max_pages, max_depth: c.max_depth } });
    location.hash = `#/crawls/${n.id}`;
  });
  if (live) {
    crawlTimer = setTimeout(() => { if (fresh(token)) route(); }, 1500);
    return;
  }
  if (s) wireCrawlPages(c, q);
}

function crawlProgress(c) {
  const p = c.progress;
  const stage = c.status === "queued" ? "Reading robots.txt and the sitemap…"
    : c.status === "crawling" ? `Crawling pages: ${p.pages_done} of up to ${c.max_pages} · ${p.queued.toLocaleString()} more URLs queued`
    : c.status === "checking" ? `Checking outgoing links: ${p.links_checked} of ${p.links_total ?? "…"}`
    : "Stopping and summarizing…";
  const frac = c.status === "crawling" ? p.pages_done / c.max_pages : c.status === "checking" && p.links_total ? 0.9 + 0.1 * p.links_checked / p.links_total : c.status === "queued" ? 0.02 : 0.98;
  return `<div class="card" style="margin-top:6px">
    <div class="row" style="gap:10px"><div class="spinner"></div><b>${esc(stage)}</b></div>
    <div class="progress" style="margin-top:14px"><span style="width:${Math.max(2, Math.min(100, frac * 100)).toFixed(1)}%"></span></div>
    <p class="muted" style="font-size:12.5px;margin:10px 0 0">${p.skipped ? `${p.skipped} URLs skipped because robots.txt disallows them. ` : ""}Results appear here when the crawl finishes.</p></div>`;
}

const pageLink = u => `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer" class="mono" style="font-size:12.5px;overflow-wrap:anywhere">${esc(u.replace(/^https?:\/\//, ""))}</a>`;
const fromList = urls => urls?.length ? `<div class="muted" style="font-size:12px">Linked from ${urls.slice(0, 3).map(u => esc(u.replace(/^https?:\/\/[^/]+/, "") || "/")).join(", ")}${urls.length > 3 ? "…" : ""}</div>` : "";

function crawlResults(c) {
  const s = c.summary;
  const tableOf = (rows, cols) => rows.length ? `<div class="table-scroll" style="max-height:340px"><table><tbody>${rows.map(cols).join("")}</tbody></table></div>` : "";
  const stat = (v, k, cls = "") => `<div class="stat"><div class="v ${cls}">${v}</div><div class="k">${esc(k)}</div></div>`;
  const notes = [
    s.stopped && "You stopped this crawl early, so results cover only the pages crawled so far.",
    s.hit_limit && `Stopped at the ${c.max_pages}-page limit with ${s.queued_left.toLocaleString()} more URLs queued. Crawl again with a higher limit to cover the whole site.`,
    s.skipped_robots && `${s.skipped_robots} URLs were skipped because robots.txt disallows them.`,
    !s.sitemap_urls && "No sitemap was found, so only pages reachable by links were crawled.",
  ].filter(Boolean);
  const dupBlock = (title, list, withValue) => list.length ? `${sub(title)}${list.slice(0, 15).map(d => `<div class="dup">
      ${withValue ? `<div><b>${esc(d.value.slice(0, 140))}</b> <span class="pill">${d.count} pages</span></div>` : `<div><span class="pill">${d.count} pages with the same text</span></div>`}
      <div class="muted mono" style="font-size:12px;overflow-wrap:anywhere">${d.urls.slice(0, 6).map(u => esc(u.replace(/^https?:\/\/[^/]+/, "") || "/")).join(" · ")}${d.urls.length > 6 ? " …" : ""}</div></div>`).join("")}` : "";
  return `
    <div class="crawl-top">
      <div class="score crawl-health"><div class="ring" style="--v:${s.health ?? 0};--c:${scoreColor(s.health ?? 0)}"><span>${s.health ?? "—"}</span></div>
        <div><div class="lbl">Site health</div><div class="hint">${s.pages_crawled - s.issue_pages} of ${s.pages_crawled} pages without serious issues</div></div></div>
      <div class="stat-cards">${stat(s.pages_crawled, "pages crawled")}${stat(s.counts.broken_pages, "broken pages", s.counts.broken_pages ? "bad" : "")}
        ${stat(s.counts.broken_links, "broken links", s.counts.broken_links ? "bad" : "")}${stat(s.counts.redirects, "redirecting URLs")}
        ${stat(s.response_ms.median != null ? s.response_ms.median + " ms" : "—", "median response")}${stat(s.counts.links_checked, "outgoing links checked")}</div>
    </div>
    ${notes.length ? `<div class="card" style="margin-top:12px">${notes.map(n => `<div class="issue"><span class="dot info"></span><span>${esc(n)}</span></div>`).join("")}</div>` : ""}
    <div class="grid" style="margin-top:12px">
      ${card("Issues", s.issues.length ? s.issues.map(i => `<button class="issue-row" data-issue="${i.key}"><span class="dot ${sevDot(i.severity)}"></span>
          <span style="flex:1;text-align:left">${esc(i.label)}</span><span class="pill">${i.pages} page${i.pages === 1 ? "" : "s"}</span></button>`).join("")
        + `<p class="muted" style="font-size:12px;margin:8px 0 0">Click an issue to list its pages below.</p>`
        : `<div class="issue"><span class="dot good"></span><span>No issues found on the crawled pages.</span></div>`)}
      ${card(`Broken pages (${s.counts.broken_pages})`, s.broken_pages.length ? tableOf(s.broken_pages, b => `<tr><td>${httpPill(b.status) || ""}${b.error ? ` <span class="muted" style="font-size:12px">${esc(b.error)}</span>` : ""}</td>
          <td>${pageLink(b.url)}${fromList(b.linked_from)}</td><td class="muted" style="white-space:nowrap">${b.inlinks} links</td></tr>`)
        : `<div class="issue"><span class="dot good"></span><span>Every crawled page loaded.</span></div>`)}
      ${card(`Broken outgoing links (${s.counts.broken_links})`, (s.broken_links.length ? tableOf(s.broken_links, b => `<tr><td>${b.status ? httpPill(b.status) : `<span class="pill bad">${esc(b.error)}</span>`}</td>
          <td>${pageLink(b.url)}${fromList(b.linked_from)}</td></tr>`) : `<div class="issue"><span class="dot good"></span><span>No broken links among the ${s.counts.links_checked} checked.</span></div>`)
        + (s.unverified_links.length ? `<details style="margin-top:8px"><summary class="muted" style="font-size:13px;cursor:pointer">${s.counts.unverified_links} links couldn't be verified (the server blocks automated requests)</summary>
            ${tableOf(s.unverified_links, b => `<tr><td>${httpPill(b.status)}</td><td>${pageLink(b.url)}</td></tr>`)}</details>` : ""))}
      ${card(`Redirects (${s.counts.redirects})`, s.redirects.length ? tableOf(s.redirects, r => `<tr><td><span class="pill ${r.hops > 1 ? "warn" : ""}">${r.hops} hop${r.hops > 1 ? "s" : ""}</span></td>
          <td>${pageLink(r.url)}<div class="muted" style="font-size:12px">→ ${esc(r.final_url)}</div></td><td class="muted" style="white-space:nowrap">${r.inlinks} links</td></tr>`)
          + `<p class="muted" style="font-size:12px;margin:8px 0 0">Update internal links to point at the final URL to save a round trip.</p>`
        : `<div class="issue"><span class="dot good"></span><span>No internal links redirect.</span></div>`)}
      ${card("Duplicates", (dupBlock("Titles", s.duplicate_titles, true) + dupBlock("Meta descriptions", s.duplicate_descriptions, true) + dupBlock("Page text", s.duplicate_content, false))
        || `<div class="issue"><span class="dot good"></span><span>Every page has its own title, description and text.</span></div>`, "wide")}
      ${card("Sitemap coverage", kv([["URLs in sitemap", s.sitemap_urls.toLocaleString()],
          ["Orphan pages", s.orphans.length ? `${s.orphans.length}${s.orphans_reliable ? "" : ' <span class="muted">(may be incomplete: the crawl didn\'t reach every page)</span>'}` : "None"],
          ["Crawled pages not in the sitemap", s.sitemap_urls ? s.not_in_sitemap.length : "—"]])
        + (s.orphans.length ? `${sub("Orphans")}${tableOf(s.orphans.slice(0, 50), u => `<tr><td>${pageLink(u)}</td></tr>`)}` : "")
        + (s.not_in_sitemap.length ? `${sub("Not in the sitemap")}${tableOf(s.not_in_sitemap.slice(0, 50), u => `<tr><td>${pageLink(u)}</td></tr>`)}` : ""))}
      ${card("Speed", `${kv([["Median response", s.response_ms.median != null ? s.response_ms.median + " ms" : "—"], ["90th percentile", s.response_ms.p90 != null ? s.response_ms.p90 + " ms" : "—"]])}
        ${sub("Slowest pages")}${tableOf(s.slowest, p => `<tr><td>${pageLink(p.url)}</td><td class="mono" style="white-space:nowrap">${p.ms} ms</td></tr>`)}
        ${sub("Heaviest HTML")}${tableOf(s.largest, p => `<tr><td>${pageLink(p.url)}</td><td class="mono" style="white-space:nowrap">${bytes(p.bytes)}</td></tr>`)}`)}
      ${card("Consistency across pages", (s.consistency.length ? s.consistency.map(t => `<div class="issue"><span class="dot info"></span><div style="min-width:0">
          <b>${esc(t.tech)}</b> is on ${t.pages_with} pages but missing from ${t.pages_without}
          <div class="muted mono" style="font-size:12px;overflow-wrap:anywhere">${t.missing_on.slice(0, 5).map(u => esc(u.replace(/^https?:\/\/[^/]+/, "") || "/")).join(" · ")}${t.missing_on.length > 5 ? " …" : ""}</div></div></div>`).join("")
          : `<div class="issue"><span class="dot good"></span><span>The same technology loads on every page.</span></div>`)
        + `${sub("Languages")}${s.languages.map(([l, n]) => `<span class="pill">${esc(l)} · ${n}</span>`).join(" ")}
        ${sub("Status codes")}${Object.entries(s.status).map(([k, n]) => `<span class="pill ${k === "2xx" ? "good" : k === "3xx" ? "" : "bad"}">${esc(k)} · ${n}</span>`).join(" ")}
        ${sub("Pages by click depth")}${s.depths.map(([d, n]) => `<div class="bar-row"><span class="k mono">depth ${d}</span><span class="bar" style="width:${Math.round(n / Math.max(...s.depths.map(x => x[1])) * 160)}px"></span><span class="n">${n}</span></div>`).join("")}`)}
    </div>
    <div class="section-title" id="pages-title">Pages</div>
    <div class="inline-form" style="margin-bottom:10px">
      <input class="field grow" id="pg-q" placeholder="Filter by URL or title…" value="">
      <select class="field" id="pg-issue"><option value="">All pages</option>${s.issues.map(i => `<option value="${i.key}">${esc(i.label)} (${i.pages})</option>`).join("")}
        ${s.skipped_robots ? '<option value="skipped">Skipped by robots.txt</option>' : ""}</select>
    </div>
    <div id="pg-table"><div class="status on"><div class="spinner"></div><span>Loading pages…</span></div></div>`;
}

function wireCrawlPages(c, q) {
  const state = { issue: q.get("issue") || "", q: "", sort: "url", dir: "asc" };
  let timer = null;
  const load = async () => {
    const params = new URLSearchParams({ sort: state.sort, dir: state.dir, ...(state.issue ? { issue: state.issue } : {}), ...(state.q ? { q: state.q } : {}) });
    const d = await api(`/api/crawls/${c.id}/pages?${params}`);
    const head = [["url", "Page"], ["status", "Status"], ["depth", "Depth"], ["words", "Words"], ["ms", "Time"], ["inlinks", "Links in"], ["issues", "Issues"]];
    $("#pg-table").innerHTML = d.pages.length ? `<div class="data-table"><table><thead><tr>${head.map(([k, l]) =>
        `<th><button class="th-sort" data-sort="${k}">${l}${state.sort === k ? (state.dir === "asc" ? " ↑" : " ↓") : ""}</button></th>`).join("")}</tr></thead><tbody>
      ${d.pages.map(p => `<tr><td style="max-width:420px">${pageLink(p.url)}<div class="muted" style="font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(p.title || p.error || "")}</div></td>
        <td>${p.state === "skipped" ? '<span class="pill">skipped</span>' : p.status ? httpPill(p.status) : '<span class="pill bad">error</span>'}</td>
        <td>${p.depth ?? "—"}</td><td>${p.words ?? "—"}</td><td class="mono" style="white-space:nowrap">${p.ms != null ? p.ms + " ms" : "—"}</td><td>${p.inlinks}</td>
        <td>${p.issues.map(k => `<span class="pill" title="${esc(d.issue_labels[k])}">${esc(d.issue_labels[k])}</span>`).join(" ")}</td></tr>`).join("")}</tbody></table></div>
      ${d.total > d.pages.length ? `<p class="muted" style="font-size:12.5px">Showing ${d.pages.length} of ${d.total}. Download the CSV for all of them.</p>` : ""}`
      : '<div class="muted">No pages match.</div>';
    $("#pg-table").querySelectorAll("[data-sort]").forEach(b => b.addEventListener("click", () => {
      state.dir = state.sort === b.dataset.sort && state.dir === "asc" ? "desc" : "asc";
      state.sort = b.dataset.sort; load();
    }));
  };
  $("#pg-issue").value = state.issue;
  $("#pg-issue").addEventListener("change", e => { state.issue = e.target.value; load(); });
  $("#pg-q").addEventListener("input", e => { clearTimeout(timer); timer = setTimeout(() => { state.q = e.target.value.trim(); load(); }, 250); });
  view.querySelectorAll("[data-issue]").forEach(b => b.addEventListener("click", async () => {
    state.issue = b.dataset.issue; $("#pg-issue").value = state.issue;
    await load();   // scroll once the shorter table is in place, or the page can land past its end
    $("#pages-title").scrollIntoView({ behavior: "smooth", block: "start" });
  }));
  load();
}
