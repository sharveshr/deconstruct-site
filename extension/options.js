const $ = s => document.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

chrome.storage.local.get(["server", "token"]).then(({ server = "", token = "" }) => {
  $("#server").value = server; $("#token").value = token;
});

$("#form").addEventListener("submit", async e => {
  e.preventDefault();
  const status = $("#status");
  let origin;
  try { origin = new URL($("#server").value.trim()).origin; } catch { status.innerHTML = '<p class="error">Enter the full address, like https://deconstruct.example.com</p>'; return; }
  const token = $("#token").value.trim();
  if (!token.startsWith("dst_")) { status.innerHTML = '<p class="error">API tokens start with dst_.</p>'; return; }
  // localhost is allowed up front; any other server needs the user's OK to send requests to it.
  if (!/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) {
    const granted = await chrome.permissions.request({ origins: [`${origin}/*`] });
    if (!granted) { status.innerHTML = '<p class="error">The extension needs permission to talk to that server.</p>'; return; }
  }
  await chrome.storage.local.set({ server: origin, token });
  status.innerHTML = '<p class="muted">Testing…</p>';
  try {
    const r = await fetch(`${origin}/api/whoami`, { headers: { "Authorization": `Bearer ${token}` } });
    const j = await r.json();
    if (!j.ok) throw new Error(j.error);
    status.innerHTML = `<p class="ok">✓ Connected as ${esc(j.data.email)}. Click the extension's icon on any page to deconstruct it.</p>`;
  } catch (err) {
    status.innerHTML = `<p class="error">${esc(err instanceof TypeError ? "Couldn't reach that server." : err.message)}</p>`;
  }
});
