// "Share & export" dialog for a saved analysis or crawl: PDF / Markdown downloads and read-only links.

const SHARE_EXPIRY = [[7, "7 days"], [30, "30 days"], [90, "90 days"], [1, "1 day"], [0, "Never"]];
const shareUrl = token => `${location.origin}/s/${token}`;

document.addEventListener("click", e => {
  const b = e.target.closest("[data-share]");
  if (b) { e.preventDefault(); openShare(b.dataset.share, +b.dataset.id); }
});

async function downloadExport(base, fmt) {
  const r = await fetch(`${base}/report.${fmt}`);
  const type = r.headers.get("content-type") || "";
  if (fmt === "pdf" && !type.includes("pdf")) {
    const j = await r.json().catch(() => ({}));
    // No headless browser on this server (Vercel): open the printable page and use "Save as PDF".
    if (j.print) { window.open(`${base}/report.print`, "_blank", "noopener"); return; }
    throw new Error(j.error || "Couldn't make the PDF.");
  }
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || "Export failed.");
  const name = (r.headers.get("content-disposition") || "").match(/filename="([^"]+)"/)?.[1] || `report.${fmt}`;
  const a = document.createElement("a");
  a.href = URL.createObjectURL(await r.blob()); a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
}

async function openShare(kind, id) {
  let dlg = $("#share-dlg");
  if (!dlg) { dlg = document.createElement("dialog"); dlg.id = "share-dlg"; dlg.className = "dlg"; document.body.append(dlg); }
  const base = `/api/${kind === "analysis" ? "analyses" : "crawls"}/${id}`;
  const render = async () => {
    const links = await api(`/api/shares?kind=${kind}&ref_id=${id}`).catch(() => []);
    dlg.innerHTML = `<form method="dialog" class="dlg-head"><h2>Share & export</h2><button class="btn sm" aria-label="Close">✕</button></form>
      <div class="section-title" style="margin-top:4px">Download</div>
      <div class="row"><button class="btn" data-exp="pdf">PDF</button><button class="btn" data-exp="md">Markdown</button>
        <button class="btn" data-exp="print">Print view</button></div>
      <p class="muted" style="font-size:12.5px;margin:8px 0 0">Includes your agency branding when it's turned on in <a href="#/settings" data-close>Settings</a>${kind === "analysis" ? ", and the AI summary and fixes if you've generated them" : ""}.</p>
      <div class="section-title">Read-only link</div>
      <p class="muted" style="font-size:13px;margin:0 0 10px">Anyone with the link can view this ${kind === "analysis" ? "report" : "crawl"} without an account. They can't see anything else in your library.</p>
      <div class="inline-form"><label class="toggle" style="margin:0">Expires
        <select class="field" id="sh-exp">${SHARE_EXPIRY.map(([d, l]) => `<option value="${d}" ${d === 30 ? "selected" : ""}>${l}</option>`).join("")}</select></label>
        ${kind === "analysis" ? '<label class="toggle" style="margin:0"><input type="checkbox" id="sh-ai" checked> Include AI summary and fixes</label>' : ""}
        <button class="btn dark" id="sh-create">Create link</button></div>
      <div id="sh-error" class="error" role="alert"></div>
      ${links.length ? `<div class="share-links">${links.map(l => `<div class="share-link">
          <input class="field mono" readonly value="${esc(shareUrl(l.token))}" aria-label="Share link" onclick="this.select()">
          <button class="btn sm" data-copylink="${esc(shareUrl(l.token))}">Copy</button>
          <a class="btn sm" href="${esc(shareUrl(l.token))}" target="_blank" rel="noopener">Open</a>
          <button class="btn sm danger" data-revoke="${l.id}">Turn off</button>
          <div class="muted" style="font-size:12px;flex-basis:100%">Created ${esc(fmtTime(l.created_at))} · ${l.expires_at ? `expires ${esc(fmtTime(l.expires_at))}` : "never expires"} · ${l.views} view${l.views === 1 ? "" : "s"}${kind === "analysis" ? (l.include_ai ? " · includes AI" : " · without AI") : ""}</div></div>`).join("")}</div>` : ""}`;
    dlg.querySelectorAll("[data-exp]").forEach(b => b.onclick = async () => {
      b.disabled = true;
      try { await downloadExport(base, b.dataset.exp === "print" ? "print" : b.dataset.exp); }
      catch (err) { toast(esc(err.message), 4000); }
      b.disabled = false;
    });
    dlg.querySelector('[data-exp="print"]').onclick = () => window.open(`${base}/report.print`, "_blank", "noopener");
    $("#sh-create", dlg).onclick = async e => {
      e.preventDefault(); e.target.disabled = true;
      try {
        const l = await api("/api/shares", { method: "POST", body: { kind, id, expires_days: +$("#sh-exp", dlg).value, include_ai: $("#sh-ai", dlg)?.checked ?? false } });
        await navigator.clipboard?.writeText(shareUrl(l.token)).catch(() => {});
        toast("Link created and copied");
        render();
      } catch (err) { const box = $("#sh-error", dlg); box.textContent = err.message; box.style.display = "block"; e.target.disabled = false; }
    };
    dlg.querySelectorAll("[data-copylink]").forEach(b => b.onclick = () => navigator.clipboard?.writeText(b.dataset.copylink).then(() => toast("Copied")));
    dlg.querySelectorAll("[data-revoke]").forEach(b => b.onclick = async () => {
      if (!confirm("Turn off this link? Anyone who has it will no longer be able to open the report.")) return;
      await api(`/api/shares/${b.dataset.revoke}`, { method: "DELETE" }); render();
    });
    dlg.querySelector("[data-close]").onclick = () => dlg.close();
  };
  await render();
  if (!dlg.open) dlg.showModal();
}
