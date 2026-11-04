// AI tab on a saved report: summary, prioritized fixes, questions, and component-to-code.
// Calls run on the user's own Anthropic API key, kept in this browser and sent only with AI requests.

const AI_KEY = "ds.ai.key", AI_MODEL = "ds.ai.model";
const aiKey = () => { try { return localStorage.getItem(AI_KEY) || sessionStorage.getItem(AI_KEY) || ""; } catch { return ""; } };
const aiModel = () => { try { return localStorage.getItem(AI_MODEL) || "claude-opus-5-5"; } catch { return "claude-opus-5-5"; } };
const AI_MODEL_NAMES = { "claude-opus-5-5": "Claude Opus 5.5", "claude-sonnet-5-5": "Claude Sonnet 5.5", "claude-haiku-5-5": "Claude Haiku 5.5" };
const aiChats = {};   // analysis id -> [{role, content}], for the current page session

function setAiKey(key, remember) {
  try {
    localStorage.removeItem(AI_KEY); sessionStorage.removeItem(AI_KEY);
    if (key) (remember ? localStorage : sessionStorage).setItem(AI_KEY, key);
  } catch { /* storage blocked: the key can't be kept */ }
}

function aiHeaders() {
  return { "X-Requested-With": "fetch", "Content-Type": "application/json", "X-Anthropic-Key": aiKey(), "X-Anthropic-Model": aiModel() };
}

async function aiJson(path, body) {
  const r = await fetch(path, { method: "POST", headers: aiHeaders(), body: JSON.stringify(body || {}) });
  const j = await r.json().catch(() => ({ ok: false, error: `Server error (HTTP ${r.status})` }));
  if (!j.ok) throw new Error(j.error || "AI request failed.");
  return j.data;
}

// POSTs and reads the server-sent events: {type: "text"} chunks, then {type: "done"} or {type: "error"}.
async function aiStream(path, body, onText) {
  const r = await fetch(path, { method: "POST", headers: aiHeaders(), body: JSON.stringify(body || {}) });
  if (!r.ok || !(r.headers.get("content-type") || "").includes("event-stream")) {
    const j = await r.json().catch(() => ({ error: `Server error (HTTP ${r.status})` }));
    throw new Error(j.error || "AI request failed.");
  }
  const reader = r.body.getReader(), dec = new TextDecoder();
  let buf = "", text = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let i;
    while ((i = buf.indexOf("\n\n")) >= 0) {
      const line = buf.slice(0, i); buf = buf.slice(i + 2);
      if (!line.startsWith("data: ")) continue;
      const ev = JSON.parse(line.slice(6));
      if (ev.type === "text") { text += ev.text; onText?.(text); }
      else if (ev.type === "error") throw new Error(ev.error);
      else if (ev.type === "done") return ev;
    }
  }
  throw new Error("The connection closed before Claude finished.");
}

// Small Markdown renderer for Claude's answers. Everything is escaped first; only these constructs become HTML.
function md(src) {
  const blocks = [];
  let s = String(src || "").replace(/```(\w*)\n?([\s\S]*?)(```|$)/g, (_, lang, code) => {
    blocks.push(codeBlock(code.replace(/\n$/, ""), lang)); return `\u0000${blocks.length - 1}\u0000`;
  });
  s = esc(s);
  const inline = t => t.replace(/`([^`]+)`/g, "<code>$1</code>").replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>")
    .replace(/(^|[^*])\*([^*\s][^*]*)\*/g, "$1<i>$2</i>")
    .replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
  const out = [];
  let list = null;
  const closeList = () => { if (list) { out.push(`</${list}>`); list = null; } };
  for (const raw of s.split("\n")) {
    const line = raw.trimEnd();
    let m;
    if (/^\u0000\d+\u0000$/.test(line.trim())) { closeList(); out.push(line.trim()); }
    else if ((m = line.match(/^(#{1,4})\s+(.*)/))) { closeList(); out.push(`<h4 class="md-h">${inline(m[2])}</h4>`); }
    else if ((m = line.match(/^\s*[-*]\s+(.*)/))) { if (list !== "ul") { closeList(); out.push("<ul>"); list = "ul"; } out.push(`<li>${inline(m[1])}</li>`); }
    else if ((m = line.match(/^\s*\d+[.)]\s+(.*)/))) { if (list !== "ol") { closeList(); out.push("<ol>"); list = "ol"; } out.push(`<li>${inline(m[1])}</li>`); }
    else if (!line.trim()) closeList();
    else { closeList(); out.push(`<p>${inline(line)}</p>`); }
  }
  closeList();
  return out.join("").replace(/\u0000(\d+)\u0000/g, (_, n) => blocks[+n]);
}

function codeBlock(code, lang = "") {
  return `<div class="code-wrap"><div class="code-bar"><span>${esc(lang || "code")}</span><button class="btn sm" data-copy>Copy</button></div><pre class="raw code"><code>${esc(code)}</code></pre></div>`;
}

function wireCopy(root) {
  root.querySelectorAll("[data-copy]").forEach(b => b.onclick = () => {
    navigator.clipboard?.writeText(b.closest(".code-wrap").querySelector("code").textContent).then(() => toast("Copied"));
  });
}

const aiMeta = r => r ? `<p class="muted ai-meta">${esc(AI_MODEL_NAMES[r.model?.replace(/-\d{8}$/, "")] || r.model || "")}${r.created_at ? ` · ${esc(fmtTime(r.created_at))}` : ""} · uses your Anthropic API key</p>` : "";

function renderAiTab(d, meta) {
  if (!meta.analysis_id) return "";
  const saved = meta.ai || {};
  const comps = Object.keys(d.browser?.components || {});
  const noKey = !aiKey();
  return `<div class="grid ai-grid">
    ${noKey ? `<section class="card wide ai-nokey"><h3>Add your Anthropic API key</h3>
      <p>AI features run on <b>your own</b> Anthropic API key, so usage is billed to your Anthropic account. The key stays in this browser and is sent only with AI requests; this server never stores it.</p>
      <a class="btn dark" href="#/settings">Open Settings</a> <a class="btn" href="https://console.anthropic.com/settings/keys" target="_blank" rel="noopener noreferrer">Get a key</a></section>` : ""}
    <section class="card wide" id="ai-summary"><div class="ai-head"><h3>Summary</h3>
      <button class="btn sm" data-ai="summary" ${noKey ? "disabled" : ""}>${saved.summary ? "Regenerate" : "Generate"}</button></div>
      <div class="ai-out md">${saved.summary ? md(saved.summary.text) : '<p class="muted">A plain-English read of this report for the site owner: how it\'s doing, what to fix first, and what works.</p>'}</div>
      <div class="ai-foot">${aiMeta(saved.summary)}</div></section>
    <section class="card wide" id="ai-fixes"><div class="ai-head"><h3>Prioritized fixes</h3>
      <button class="btn sm" data-ai="fixes" ${noKey ? "disabled" : ""}>${saved.fixes ? "Regenerate" : "Generate"}</button></div>
      <div class="ai-out">${saved.fixes ? renderFixes(saved.fixes.fixes) : '<p class="muted">Highest impact for the least effort first, each with the evidence from this report, why it matters, how to do it and code.</p>'}</div>
      <div class="ai-foot">${aiMeta(saved.fixes)}</div></section>
    <section class="card wide" id="ai-ask"><h3>Ask about this report</h3>
      <div class="chat" id="ai-chat">${(aiChats[meta.analysis_id] || []).map(chatBubble).join("")}</div>
      <div class="chips" id="ai-suggest">${["What should I fix before launch?", "Why is the performance score what it is?", "How do I fix the accessibility issues?", "Is anything here a security risk?"]
        .map(q => `<button class="chip" type="button" ${noKey ? "disabled" : ""}>${esc(q)}</button>`).join("")}</div>
      <form class="search ai-form" id="ai-ask-form"><label for="ai-q" style="position:absolute;left:-9999px">Question</label>
        <input id="ai-q" placeholder="${noKey ? "Add your API key in Settings first" : "Ask anything about this site…"}" ${noKey ? "disabled" : ""} autocomplete="off">
        <button class="primary" type="submit" ${noKey ? "disabled" : ""}>Ask</button></form></section>
    <section class="card wide" id="ai-code"><div class="ai-head"><h3>Component to code</h3></div>
      ${comps.length ? `<div class="row" style="gap:10px;margin-bottom:12px">
          <label class="toggle" style="margin:0">Component <select class="field" id="ai-comp">${comps.map(c => `<option value="${c}">${esc(c)}</option>`).join("")}</select></label>
          <div class="seg" role="tablist" aria-label="Output">${[["tailwind", "Tailwind"], ["html", "HTML + CSS"], ["react", "React"]].map(([f, l], i) =>
            `<button type="button" role="tab" data-fw="${f}" aria-selected="${i === 0}">${l}</button>`).join("")}</div>
          <button class="btn dark sm" data-ai="component" ${noKey ? "disabled" : ""}>Generate code</button></div>
        <div class="comp-shot"><img id="ai-comp-img" alt="Captured component" src="${esc(d.browser.components[comps[0]].image)}"></div>
        <div class="ai-out md" id="ai-code-out"></div>`
        : '<p class="muted">No components were captured. Run the analysis with the browser turned on to capture the header, footer and forms.</p>'}</section>
  </div>`;
}

function renderFixes(list) {
  const pill = (v, kind) => `<span class="pill ${kind === "impact" ? (v === "high" ? "bad" : v === "medium" ? "warn" : "") : (v === "low" ? "good" : v === "high" ? "warn" : "")}">${esc(v)} ${kind}</span>`;
  return `<ol class="fixes">${list.map(f => `<li class="fix">
      <div class="row" style="gap:6px"><b>${esc(f.title)}</b> ${pill(f.impact, "impact")} ${pill(f.effort, "effort")} <span class="pill">${esc(f.category)}</span></div>
      <div class="muted" style="font-size:13px;margin:4px 0">${esc(f.evidence)}</div>
      <div style="font-size:14px">${esc(f.why)}</div>
      <div class="md" style="font-size:14px;margin-top:6px">${md(f.how)}</div>
      ${f.code ? codeBlock(f.code, f.code_language) : ""}</li>`).join("")}</ol>`;
}

const chatBubble = m => `<div class="bubble ${m.role}">${m.role === "user" ? esc(m.content) : md(m.content)}</div>`;

function wireAiTab(root, d, meta) {
  const tab = $(".ai-grid", root);
  if (!tab) return;
  wireCopy(tab);
  const id = meta.analysis_id, base = `/api/analyses/${id}/ai`;
  meta.ai = meta.ai || {};
  const busy = (btn, on, label) => { btn.disabled = on; if (label) btn.textContent = label; };
  const fail = (box, e) => { box.insertAdjacentHTML("afterbegin", `<div class="error" style="display:block;margin:0 0 10px">${esc(e.message)}</div>`); };

  $('[data-ai="summary"]', tab)?.addEventListener("click", async e => {
    const btn = e.target, out = $("#ai-summary .ai-out", tab);
    busy(btn, true, "Writing…"); out.innerHTML = '<div class="status on"><div class="spinner"></div><span>Claude is reading the report…</span></div>';
    try {
      const done = await aiStream(`${base}/summary`, {}, text => { out.innerHTML = md(text); });
      meta.ai.summary = { text: done.text, model: done.model, created_at: new Date().toISOString() };
      out.innerHTML = md(done.text); wireCopy(out);
      $("#ai-summary .ai-foot", tab).innerHTML = aiMeta(meta.ai.summary) + usageNote(done.usage);
    } catch (err) { out.innerHTML = meta.ai.summary ? md(meta.ai.summary.text) : ""; fail(out, err); }
    busy(btn, false, meta.ai.summary ? "Regenerate" : "Generate");
  });

  $('[data-ai="fixes"]', tab)?.addEventListener("click", async e => {
    const btn = e.target, out = $("#ai-fixes .ai-out", tab);
    busy(btn, true, "Working…");
    out.innerHTML = '<div class="status on"><div class="spinner"></div><span>Claude is ranking fixes and writing code. This can take a minute.</span></div>';
    try {
      const r = await aiJson(`${base}/fixes`);
      meta.ai.fixes = { fixes: r.fixes, model: r.model, created_at: new Date().toISOString() };
      out.innerHTML = renderFixes(r.fixes); wireCopy(out);
      $("#ai-fixes .ai-foot", tab).innerHTML = aiMeta(meta.ai.fixes) + usageNote(r.usage);
    } catch (err) { out.innerHTML = meta.ai.fixes ? renderFixes(meta.ai.fixes.fixes) : ""; fail(out, err); }
    busy(btn, false, meta.ai.fixes ? "Regenerate" : "Generate");
  });

  const chat = $("#ai-chat", tab), form = $("#ai-ask-form", tab);
  const ask = async q => {
    if (!q.trim() || !aiKey()) return;
    const hist = aiChats[id] = aiChats[id] || [];
    const prior = hist.slice();
    hist.push({ role: "user", content: q });
    chat.insertAdjacentHTML("beforeend", chatBubble({ role: "user", content: q }) + '<div class="bubble assistant pending"><div class="spinner"></div></div>');
    const live = chat.lastElementChild;
    chat.scrollTop = chat.scrollHeight;
    $("#ai-q", tab).value = ""; form.querySelector("button").disabled = true;
    try {
      const done = await aiStream(`${base}/ask`, { question: q, history: prior }, text => { live.classList.remove("pending"); live.innerHTML = md(text); chat.scrollTop = chat.scrollHeight; });
      hist.push({ role: "assistant", content: done.text });
      live.classList.remove("pending"); live.innerHTML = md(done.text); wireCopy(live);
    } catch (err) {
      hist.pop(); live.classList.remove("pending"); live.classList.add("err"); live.textContent = err.message;
    }
    form.querySelector("button").disabled = false;
  };
  form?.addEventListener("submit", e => { e.preventDefault(); ask($("#ai-q", tab).value); });
  tab.querySelectorAll("#ai-suggest .chip").forEach(c => c.addEventListener("click", () => ask(c.textContent)));

  let fw = "tailwind";
  tab.querySelectorAll("[data-fw]").forEach(b => b.addEventListener("click", () => {
    fw = b.dataset.fw; tab.querySelectorAll("[data-fw]").forEach(x => x.setAttribute("aria-selected", x === b)); showSavedCode();
  }));
  const compSel = $("#ai-comp", tab);
  const showSavedCode = () => {
    const out = $("#ai-code-out", tab);
    if (!out) return;
    const saved = (meta.ai.components || {})[`${compSel.value}:${fw}`];
    out.innerHTML = saved ? codeResult(saved.text, fw) : "";
    wireCode(out);
  };
  compSel?.addEventListener("change", () => { $("#ai-comp-img", tab).src = d.browser.components[compSel.value].image; showSavedCode(); });
  showSavedCode();
  $('[data-ai="component"]', tab)?.addEventListener("click", async e => {
    const btn = e.target, out = $("#ai-code-out", tab), comp = compSel.value, f = fw;
    busy(btn, true, "Generating…");
    out.innerHTML = '<div class="status on"><div class="spinner"></div><span>Claude is rebuilding the component…</span></div>';
    try {
      const done = await aiStream(`${base}/component`, { component: comp, framework: f }, text => { out.innerHTML = md(text); });
      meta.ai.components = { ...(meta.ai.components || {}), [`${comp}:${f}`]: { text: done.text, model: done.model } };
      out.innerHTML = codeResult(done.text, f); wireCode(out);
    } catch (err) { out.innerHTML = ""; fail(out, err); }
    busy(btn, false, "Generate code");
  });
}

const usageNote = u => u ? `<p class="muted ai-meta">${(u.input_tokens + u.cache_read_input_tokens + u.cache_creation_input_tokens).toLocaleString()} input tokens${u.cache_read_input_tokens ? ` (${u.cache_read_input_tokens.toLocaleString()} from cache)` : ""} · ${u.output_tokens.toLocaleString()} output</p>` : "";

function codeResult(text, fw) {
  const m = String(text).match(/```(\w*)\n([\s\S]*?)```/);
  const preview = m && fw !== "react";
  return md(text) + (preview ? `<div class="row" style="margin-top:10px"><button class="btn sm" data-preview>Preview</button></div>
    <div class="preview-box" hidden><iframe sandbox="allow-scripts" title="Preview of the generated component"></iframe></div>` : "");
}

function wireCode(out) {
  wireCopy(out);
  const btn = $("[data-preview]", out);
  if (!btn) return;
  btn.onclick = () => {
    const box = $(".preview-box", out), code = out.querySelector(".code-wrap code").textContent;
    box.hidden = !box.hidden;
    btn.textContent = box.hidden ? "Preview" : "Hide preview";
    // Sandboxed without allow-same-origin, so the generated markup can't reach this app or its cookies.
    $("iframe", box).srcdoc = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
      <script src="https://cdn.tailwindcss.com/3.4.17"><\/script></head><body style="margin:0">${code}</body></html>`;
  };
}
