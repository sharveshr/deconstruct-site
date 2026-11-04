// Popup: "Deconstruct this tab", plus shortcuts to crawl the site or run OSINT on it in the app.

const $ = s => document.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const SCORES = [["performance", "Perf"], ["seo", "SEO"], ["accessibility", "A11y"], ["security", "Sec"]];
const cls = v => v >= 85 ? "g" : v >= 60 ? "w" : "b";

$("#opts").onclick = () => chrome.runtime.openOptionsPage();

async function currentUrl() {
  // ?url= lets the popup page be opened directly (tests, or pinning it in a tab).
  const fromQuery = new URLSearchParams(location.search).get("url");
  if (fromQuery) return fromQuery;
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.url || "";
}

async function render() {
  const { server = "", token = "", jobs = {} } = await chrome.storage.local.get(["server", "token", "jobs"]);
  const base = server.replace(/\/+$/, "");
  const url = await currentUrl();
  const main = $("#main");
  if (!base || !token) {
    main.innerHTML = `<p>Connect the extension to your Deconstruct Site server first.</p><button class="primary" id="setup">Set up</button>`;
    $("#setup").onclick = () => chrome.runtime.openOptionsPage();
    return;
  }
  if (!/^https?:\/\//.test(url)) {
    main.innerHTML = `<p class="muted">This page can't be analyzed. Open a website (http or https) and try again.</p>`;
    return;
  }
  const host = new URL(url).hostname;
  const job = jobs[url];
  const recent = Object.values(jobs).filter(j => j.url !== url && j.status === "done").sort((a, b) => b.finished - a.finished).slice(0, 4);
  main.innerHTML = `<div class="target"><b>${esc(host)}</b><div class="muted url">${esc(url)}</div></div>
    ${job?.status === "running" ? `<div class="status"><span class="spinner"></span>Analyzing… you can close this popup; you'll get a notification.</div>`
      : job?.status === "done" ? `<div class="result"><div class="muted" style="margin-bottom:6px">${esc(job.title || host)}</div>
          <div class="scores">${SCORES.map(([k, l]) => `<span class="ms ${cls(job.scores[k])}"><small>${l}</small>${job.scores[k]}</span>`).join("")}</div>
          <a class="primary block" target="_blank" href="${esc(base)}/#/analyses/${job.analysis_id}">Open the full report</a></div>`
      : job?.status === "error" ? `<div class="error">${esc(job.error)}</div>` : ""}
    ${job?.status === "running" ? "" : `<button class="primary block" id="go">${job?.status === "done" ? "Analyze again" : "Deconstruct this tab"}</button>
      <label class="check"><input type="checkbox" id="quick"> Quick analysis (no browser: faster, no screenshots or vitals)</label>`}
    <div class="row"><button class="ghost" id="crawl">Crawl site</button><a class="ghost" target="_blank" href="${esc(base)}/#/osint?target=${encodeURIComponent(host)}&run=1">OSINT</a>
      <a class="ghost" target="_blank" href="${esc(base)}/#/history">Library</a></div>
    ${recent.length ? `<div class="recent"><div class="muted label">Recent</div>${recent.map(j => `<a target="_blank" href="${esc(base)}/#/analyses/${j.analysis_id}">${esc(j.host || j.url)}</a>`).join("")}</div>` : ""}`;
  $("#go")?.addEventListener("click", () => chrome.runtime.sendMessage({ type: "analyze", url, render: !$("#quick").checked }, render));
  $("#crawl").onclick = async e => {
    e.target.disabled = true; e.target.textContent = "Starting…";
    try {
      const r = await fetch(`${base}/api/crawls`, { method: "POST", headers: { "Authorization": `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ url: new URL(url).origin + "/", max_pages: 100 }) });
      const j = await r.json();
      if (!j.ok) throw new Error(j.error);
      chrome.tabs.create({ url: `${base}/#/crawls/${j.data.id}` });
    } catch (err) {
      e.target.textContent = "Crawl site"; e.target.disabled = false;
      main.insertAdjacentHTML("afterbegin", `<div class="error">${esc(err.message || "Couldn't start the crawl.")}</div>`);
    }
  };
}

chrome.storage.onChanged.addListener((changes, area) => { if (area === "local" && changes.jobs) render(); });
render();
