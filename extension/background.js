// Runs analyses for the popup and the right-click menu. Analyses take 15-45 s, longer than a popup stays
// open, so they run here and the result is kept in storage and announced with a notification.

const SCORE_NAMES = { performance: "Perf", seo: "SEO", accessibility: "A11y", security: "Sec" };

async function settings() {
  const { server = "", token = "" } = await chrome.storage.local.get(["server", "token"]);
  return { server: server.replace(/\/+$/, ""), token };
}

async function setJob(url, job) {
  const { jobs = {} } = await chrome.storage.local.get("jobs");
  jobs[url] = { ...(jobs[url] || {}), ...job, url };
  // Keep the 20 most recent.
  const recent = Object.values(jobs).sort((a, b) => (b.started || 0) - (a.started || 0)).slice(0, 20);
  await chrome.storage.local.set({ jobs: Object.fromEntries(recent.map(j => [j.url, j])) });
}

async function analyze(url, render) {
  const { server, token } = await settings();
  if (!server || !token) {
    chrome.runtime.openOptionsPage();
    return;
  }
  await setJob(url, { status: "running", started: Date.now(), render, error: null });
  // A fetch alone doesn't keep a service worker alive past 30 s of idle time; a cheap extension API call does.
  const keepAlive = setInterval(() => chrome.runtime.getPlatformInfo(() => {}), 20000);
  try {
    const r = await fetch(`${server}/api/analyze`, {
      method: "POST",
      headers: { "Authorization": `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ url, render, perf_runs: 1, label: "extension" }),
    });
    const j = await r.json().catch(() => ({ ok: false, error: `The server answered HTTP ${r.status}.` }));
    if (!j.ok) throw new Error(j.error || "The analysis failed.");
    const d = j.data;
    await setJob(url, { status: "done", analysis_id: d.analysis_id, title: d.report.overview.title, host: d.site.host,
                        scores: d.report.scores, finished: Date.now() });
    const s = d.report.scores;
    notify(`done:${d.analysis_id}`, `Saved: ${d.site.host}`, Object.entries(SCORE_NAMES).map(([k, n]) => `${n} ${s[k]}`).join(" · "));
  } catch (e) {
    const msg = e instanceof TypeError ? "Couldn't reach the server. Check its address in the extension's options." : e.message;
    await setJob(url, { status: "error", error: msg, finished: Date.now() });
    notify(`error:${Date.now()}`, "Analysis failed", msg);
  } finally {
    clearInterval(keepAlive);
  }
}

function notify(id, title, message) {
  chrome.notifications.create(id, { type: "basic", iconUrl: "icons/128.png", title, message });
}

chrome.notifications.onClicked.addListener(async id => {
  const m = id.match(/^done:(\d+)$/);
  if (!m) return;
  const { server } = await settings();
  chrome.tabs.create({ url: `${server}/#/analyses/${m[1]}` });
  chrome.notifications.clear(id);
});

chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
  if (msg?.type === "analyze" && /^https?:\/\//.test(msg.url)) {
    analyze(msg.url, msg.render !== false);
    reply({ started: true });
  }
});

chrome.runtime.onInstalled.addListener(details => {
  chrome.contextMenus.create({ id: "page", title: "Deconstruct this page", contexts: ["page"], documentUrlPatterns: ["http://*/*", "https://*/*"] });
  chrome.contextMenus.create({ id: "link", title: "Deconstruct this link", contexts: ["link"], targetUrlPatterns: ["http://*/*", "https://*/*"] });
  // A tab rather than openOptionsPage(), which does nothing when no browser window has focus yet.
  if (details.reason === "install") chrome.tabs.create({ url: chrome.runtime.getURL("options.html") });
});

chrome.contextMenus.onClicked.addListener(info => {
  const url = info.menuItemId === "link" ? info.linkUrl : info.pageUrl;
  if (/^https?:\/\//.test(url || "")) analyze(url, true);
});
