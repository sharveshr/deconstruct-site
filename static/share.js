// Public, read-only view of a shared analysis or crawl (/s/<token>), with the sharer's agency branding.

function toast(msg, ms = 2800) {
  const t = $("#toast"); t.innerHTML = msg; t.classList.add("on");
  clearTimeout(t._h); t._h = setTimeout(() => t.classList.remove("on"), ms);
}

(async () => {
  const token = location.pathname.split("/").filter(Boolean).pop();
  const root = $("#share");
  const r = await fetch(`/api/public/${encodeURIComponent(token)}`).then(x => x.json()).catch(() => null);
  if (!r?.ok) {
    document.title = "Report unavailable";
    root.innerHTML = `<div class="empty" style="margin-top:40px"><h3>This report isn't available</h3><p>${esc(r?.error || "The link may have expired or been turned off.")}</p></div>`;
    return;
  }
  const { kind, data, branding: b, pdf } = r.data;
  const host = data.host;
  document.title = `${kind === "analysis" ? "Website report" : "Site crawl"}: ${host}${b.name ? ` · ${b.name}` : ""}`;
  if (/^#[0-9a-f]{6}$/i.test(b.color || "")) document.documentElement.style.setProperty("--brand", b.color);
  const base = `/api/public/${encodeURIComponent(token)}`;
  const safeUrl = /^https?:\/\//.test(b.url || "") ? b.url : null;
  $("#share-top").innerHTML = `<div class="wrap share-bar">
      <div class="share-brand">${b.logo ? `<img src="${esc(b.logo)}" alt="${esc(b.name || "")}">` : '<span class="logo" aria-hidden="true"></span>'}
        <div><b>${esc(b.name || "Deconstruct Site")}</b>${b.contact ? `<div class="muted" style="font-size:12.5px">${esc(b.contact)}</div>` : ""}</div></div>
      <div class="row">${safeUrl ? `<a class="btn sm" href="${esc(safeUrl)}" target="_blank" rel="noopener noreferrer">Website</a>` : ""}
        <a class="btn sm" href="${base}/report.${pdf ? "pdf" : "print"}" ${pdf ? "download" : 'target="_blank" rel="noopener"'}>PDF</a>
        <a class="btn sm" href="${base}/report.md" download>Markdown</a></div></div>`;
  $("#share-foot").innerHTML = b.hide_credit ? "" : 'Made with <a href="/" target="_blank" rel="noopener">Deconstruct Site</a>';

  const intro = `<div class="share-intro"><div class="kicker">${kind === "analysis" ? "Website report" : "Site crawl"}</div>
    <p class="muted">Shared ${esc(fmtTime(r.data.shared_at))}${r.data.expires_at ? ` · available until ${esc(fmtTime(r.data.expires_at))}` : ""}</p></div>`;
  if (kind === "analysis") {
    const ai = data.ai || {};
    root.innerHTML = intro + (ai.summary || ai.fixes ? `<div class="grid" style="margin-bottom:6px">
        ${ai.summary ? card("Summary", `<div class="md">${md(ai.summary.text)}</div>`, "wide") : ""}
        ${ai.fixes ? card("Prioritized fixes", renderFixes(ai.fixes.fixes), "wide") : ""}</div>` : "") + '<div id="report"></div>';
    renderReport(data.report, $("#report"), {});
    wireCopy(root);
  } else if (data.summary) {
    root.innerHTML = intro + `<div class="page-head" style="padding-top:6px"><div><h1>${esc(host)}</h1>
      <p>${link(data.root_url)} · up to ${data.max_pages} pages${data.summary.duration_s != null ? ` · took ${duration(data.summary.duration_s)}` : ""}</p></div></div>` + crawlResults(data);
    // The per-page table needs the owner's account; the summary above is what's shared.
    ["#pages-title", "#pg-table"].forEach(s => $(s, root)?.remove());
    root.querySelector(".inline-form")?.remove();
    root.querySelectorAll("[data-issue]").forEach(btn => btn.disabled = true);
    root.querySelectorAll(".issue-row + p.muted").forEach(p => p.remove());
  } else {
    root.innerHTML = intro + '<div class="empty"><h3>This crawl hasn\'t finished yet</h3></div>';
  }
})();
