// Settings: the user's own Anthropic API key, agency branding, API tokens for the browser extension,
// and every share link.

async function pageSettings(q, token) {
  const [models, branding, tokensList, shares] = await Promise.all([
    api("/api/ai/models"), api("/api/settings/branding"), api("/api/tokens"), api("/api/shares")]);
  if (!fresh(token)) return;
  const key = aiKey();
  const remembered = (() => { try { return !!localStorage.getItem(AI_KEY); } catch { return false; } })();
  const b = branding || {};
  view.innerHTML = `<div class="wrap settings">
    <div class="page-head"><div><h1>Settings</h1><p>${esc(currentUser.email)}</p></div></div>

    <section class="card" id="set-ai"><h3>AI: your Anthropic API key</h3>
      <p class="muted" style="margin:0 0 12px;font-size:14px">AI features (summaries, fix lists, questions, component-to-code) run on <b>your own</b> key, so usage is billed to your Anthropic account.
        The key stays in this browser and is sent only with AI requests. This server uses it for that request and never stores or logs it.
        <a href="https://console.anthropic.com/settings/keys" target="_blank" rel="noopener noreferrer">Create a key in the Claude Console</a>.</p>
      <label class="lbl" for="ai-key">API key</label>
      <div class="inline-form"><input class="field grow mono" id="ai-key" type="password" autocomplete="off" spellcheck="false" placeholder="sk-ant-…" value="${esc(key)}">
        <button class="btn sm" type="button" id="ai-show">Show</button></div>
      <div class="inline-form" style="margin-top:10px">
        <label class="toggle" style="margin:0"><input type="checkbox" id="ai-remember" ${remembered || !key ? "checked" : ""}> Remember on this device</label>
        <label class="toggle" style="margin:0">Model <select class="field" id="ai-model">${models.models.map(m => `<option value="${m.id}" ${m.id === aiModel() ? "selected" : ""}>${esc(m.name)}</option>`).join("")}</select></label></div>
      <p class="muted" style="font-size:12.5px;margin:8px 0 0">Claude Opus 5.5 gives the best results; Sonnet 5.5 and Haiku 5.5 cost less per request. Without "Remember", the key is forgotten when you close this tab.</p>
      <div class="row" style="margin-top:12px"><button class="btn dark" id="ai-save">Save</button><button class="btn" id="ai-test">Save and test</button>
        ${key ? '<button class="btn danger" id="ai-remove">Remove key</button>' : ""}<span id="ai-status" class="muted" style="font-size:13px"></span></div>
    </section>

    <section class="card" id="set-brand"><h3>Agency branding</h3>
      <p class="muted" style="margin:0 0 12px;font-size:14px">Put your own name, logo and color on shared report links, PDFs and Markdown exports for clients.</p>
      <label class="toggle" style="margin:0 0 12px"><input type="checkbox" id="br-on" ${b.enabled ? "checked" : ""}> Use my branding on shared and exported reports</label>
      <div class="form-grid">
        <div><label class="lbl" for="br-name">Agency or company name</label><input class="field" id="br-name" maxlength="80" value="${esc(b.name || "")}"></div>
        <div><label class="lbl" for="br-url">Website</label><input class="field" id="br-url" maxlength="200" placeholder="https://" value="${esc(b.url || "")}"></div>
        <div><label class="lbl" for="br-contact">Contact line</label><input class="field" id="br-contact" maxlength="200" placeholder="hello@agency.com · +44 20 …" value="${esc(b.contact || "")}"></div>
        <div><label class="lbl" for="br-color">Brand color</label><div class="inline-form"><input type="color" id="br-color" value="${esc(b.color || "#141414")}"><span class="mono" id="br-color-v">${esc(b.color || "#141414")}</span></div></div>
        <div><label class="lbl" for="br-logo">Logo (PNG, JPEG or WebP, under 300 KB)</label>
          <div class="inline-form"><input type="file" id="br-logo" accept="image/png,image/jpeg,image/webp"><button class="btn sm" id="br-logo-clear" type="button" ${b.logo ? "" : "hidden"}>Remove logo</button></div></div>
        <div><label class="toggle" style="margin:22px 0 0"><input type="checkbox" id="br-credit" ${b.hide_credit ? "checked" : ""}> Hide "Made with Deconstruct Site"</label></div>
      </div>
      <div class="lbl" style="margin-top:14px">Preview</div>
      <div class="brand-preview" id="br-preview"></div>
      <div class="row" style="margin-top:12px"><button class="btn dark" id="br-save">Save branding</button><span id="br-status" class="muted" style="font-size:13px"></span></div>
    </section>

    <section class="card" id="set-ext"><h3>Browser extension and API tokens</h3>
      <p class="muted" style="margin:0 0 12px;font-size:14px">The Chrome / Edge extension adds "Deconstruct this tab": one click analyzes the page you're on and saves it to your library.</p>
      <ol class="steps-list">
        <li><a class="btn sm" href="/api/extension.zip" download>Download the extension</a> and unzip it.</li>
        <li>Open <span class="mono">chrome://extensions</span> (or <span class="mono">edge://extensions</span>), turn on <b>Developer mode</b>, click <b>Load unpacked</b> and pick the unzipped folder.</li>
        <li>Create a token below, then open the extension's options and paste this server's address (<span class="mono">${esc(location.origin)}</span>) and the token.</li>
      </ol>
      <div class="inline-form" style="margin-top:12px"><input class="field grow" id="tok-name" placeholder="Token name, e.g. Work laptop" maxlength="60"><button class="btn dark" id="tok-create">Create token</button></div>
      <div id="tok-new"></div>
      ${tokensList.length ? `<div class="data-table" style="margin-top:12px"><table><thead><tr><th>Name</th><th>Token</th><th>Created</th><th>Last used</th><th></th></tr></thead><tbody>
        ${tokensList.map(t => `<tr><td>${esc(t.name)}</td><td class="mono">${esc(t.prefix)}…</td><td>${esc(fmtTime(t.created_at))}</td><td>${t.last_used_at ? esc(ago(t.last_used_at)) : "never"}</td>
          <td><button class="btn sm danger" data-deltok="${t.id}">Revoke</button></td></tr>`).join("")}</tbody></table></div>` : ""}
      <p class="muted" style="font-size:12.5px;margin:10px 0 0">A token can do anything you can in the app. Revoke it if a device is lost.</p>
    </section>

    <section class="card" id="set-shares"><h3>Shared links (${shares.length})</h3>
      ${shares.length ? `<div class="data-table"><table><thead><tr><th>What</th><th>Created</th><th>Expires</th><th>Views</th><th></th></tr></thead><tbody>
        ${shares.map(s => `<tr><td><a href="#/${s.kind === "analysis" ? "analyses" : "crawls"}/${s.ref_id}">${s.kind === "analysis" ? "Analysis" : "Crawl"} #${s.ref_id}</a></td>
          <td>${esc(fmtTime(s.created_at))}</td><td>${s.expires_at ? esc(fmtTime(s.expires_at)) : "Never"}</td><td>${s.views}</td>
          <td class="row" style="flex-wrap:nowrap"><button class="btn sm" data-copylink="${esc(shareUrl(s.token))}">Copy link</button><button class="btn sm danger" data-revoke="${s.id}">Turn off</button></td></tr>`).join("")}</tbody></table></div>`
        : '<p class="muted" style="margin:0">Nothing shared yet. Use <b>Share & export</b> on a report or crawl.</p>'}
    </section>
  </div>`;

  // ---- AI key
  $("#ai-show").onclick = e => { const i = $("#ai-key"); i.type = i.type === "password" ? "text" : "password"; e.target.textContent = i.type === "password" ? "Show" : "Hide"; };
  const saveKey = () => {
    const k = $("#ai-key").value.trim();
    if (k && !/^sk-ant-[A-Za-z0-9_-]{20,}$/.test(k)) { $("#ai-status").textContent = "That doesn't look like an Anthropic API key (they start with sk-ant-)."; return false; }
    setAiKey(k, $("#ai-remember").checked);
    try { localStorage.setItem(AI_MODEL, $("#ai-model").value); } catch { /* storage blocked */ }
    return true;
  };
  $("#ai-save").onclick = () => { if (saveKey()) { toast($("#ai-key").value.trim() ? "Key saved in this browser" : "Key removed"); route(); } };
  $("#ai-test").onclick = async e => {
    if (!saveKey() || !aiKey()) { if (!aiKey()) $("#ai-status").textContent = "Enter a key first."; return; }
    e.target.disabled = true; $("#ai-status").textContent = "Checking with Anthropic…";
    try { const r = await aiJson("/api/ai/check"); $("#ai-status").innerHTML = `<span style="color:var(--good)">✓ Works with ${esc(r.name)}</span>`; }
    catch (err) { $("#ai-status").innerHTML = `<span style="color:var(--bad)">${esc(err.message)}</span>`; }
    e.target.disabled = false;
  };
  $("#ai-remove")?.addEventListener("click", () => { setAiKey("", false); toast("Key removed from this browser"); route(); });

  // ---- branding
  let logo = b.logo || "";
  const preview = () => {
    const color = $("#br-color").value;
    $("#br-color-v").textContent = color;
    $("#br-preview").innerHTML = `<div class="share-bar" style="--brand:${esc(color)}"><div class="share-brand">${logo ? `<img src="${esc(logo)}" alt="">` : '<span class="logo" aria-hidden="true"></span>'}
      <div><b>${esc($("#br-name").value || "Your agency")}</b>${$("#br-contact").value ? `<div class="muted" style="font-size:12.5px">${esc($("#br-contact").value)}</div>` : ""}</div></div></div>`;
  };
  ["#br-name", "#br-contact", "#br-color"].forEach(s => $(s).addEventListener("input", preview));
  $("#br-logo").onchange = e => {
    const f = e.target.files[0];
    if (!f) return;
    if (!/^image\/(png|jpeg|webp)$/.test(f.type)) { $("#br-status").textContent = "Use a PNG, JPEG or WebP image."; return; }
    if (f.size > 300 * 1024) { $("#br-status").textContent = "That image is over 300 KB."; return; }
    const rd = new FileReader();
    rd.onload = () => { logo = rd.result; $("#br-logo-clear").hidden = false; preview(); };
    rd.readAsDataURL(f);
  };
  $("#br-logo-clear").onclick = () => { logo = ""; $("#br-logo").value = ""; $("#br-logo-clear").hidden = true; preview(); };
  preview();
  $("#br-save").onclick = async e => {
    e.target.disabled = true;
    try {
      await api("/api/settings/branding", { method: "PUT", body: { enabled: $("#br-on").checked, name: $("#br-name").value, url: $("#br-url").value,
        contact: $("#br-contact").value, color: $("#br-color").value, logo, hide_credit: $("#br-credit").checked } });
      $("#br-status").innerHTML = '<span style="color:var(--good)">Saved</span>';
    } catch (err) { $("#br-status").innerHTML = `<span style="color:var(--bad)">${esc(err.message)}</span>`; }
    e.target.disabled = false;
  };

  // ---- tokens
  $("#tok-create").onclick = async e => {
    e.target.disabled = true;
    try {
      const t = await api("/api/tokens", { method: "POST", body: { name: $("#tok-name").value.trim() || "Browser extension" } });
      $("#tok-new").innerHTML = `<div class="token-once"><b>Copy this token now. It won't be shown again.</b>
        <div class="inline-form" style="margin-top:8px"><input class="field grow mono" readonly value="${esc(t.token)}" onclick="this.select()" aria-label="New token">
        <button class="btn sm" id="tok-copy">Copy</button></div></div>`;
      $("#tok-copy").onclick = () => navigator.clipboard?.writeText(t.token).then(() => toast("Token copied"));
    } catch (err) { toast(esc(err.message), 4000); }
    e.target.disabled = false;
  };
  view.querySelectorAll("[data-deltok]").forEach(btn => btn.onclick = async () => {
    if (!confirm("Revoke this token? Anything using it stops working.")) return;
    await api(`/api/tokens/${btn.dataset.deltok}`, { method: "DELETE" }); route();
  });

  // ---- share links
  view.querySelectorAll("#set-shares [data-copylink]").forEach(btn => btn.onclick = () => navigator.clipboard?.writeText(btn.dataset.copylink).then(() => toast("Copied")));
  view.querySelectorAll("#set-shares [data-revoke]").forEach(btn => btn.onclick = async () => {
    if (!confirm("Turn off this link?")) return;
    await api(`/api/shares/${btn.dataset.revoke}`, { method: "DELETE" }); route();
  });
}
