// Home page (what the app does, with screenshots) and the sign-in / sign-up pages.

const FEATURES = [
  { img: "report", route: "/analyze", title: "One-click teardown", text: "Tech stack with versions, server and hosting, rendering mode, SEO and structure for any URL, saved as an iteration you can compare later." },
  { img: "design", route: "/analyze", title: "Design system & tokens", text: "Colors by painted area, fonts, type scale, spacing, radii and buttons. Export them as CSS variables, Tailwind or Figma tokens." },
  { img: "performance", route: "/analyze", title: "Performance you can trust", text: "The median of throttled mobile loads for Core Web Vitals, every resource with its size and caching, plus real-user data from Chrome." },
  { img: "accessibility", route: "/analyze", title: "Accessibility with axe-core", text: "WCAG 2.2 checks on the rendered page with the failing elements, their impact and how to fix them." },
  { img: "crawl", route: "/crawls", title: "Whole-site crawl", text: "Up to 500 pages: broken pages and links, redirects, duplicate titles, thin and slow pages, orphans and missing tracking." },
  { img: "security", route: "/analyze", title: "Security & vulnerable libraries", text: "TLS, security headers and cookies, plus JavaScript libraries with known CVEs from the retire.js database." },
  { img: "osint", route: "/osint", title: "15 OSINT lookups", text: "DNS, WHOIS, subdomains, certificates, email security, lookalike domains, subdomain takeover and blocklists." },
  { img: "uptime", route: "/sites", title: "Uptime monitoring", text: "Checks every minute to every day, response-time charts, incidents, and a log for outages you noted yourself." },
  { img: "alerts", route: "/alerts", title: "Change alerts", text: "Score drops, new subdomains, expiring certificates, broken pages and more, sent to Slack, Discord, email or a webhook." },
  { img: "compare", route: "/compare", title: "Side-by-side compare", text: "Two sites or two iterations of one, scored metric by metric with the winner of each." },
];

const featHref = route => currentUser ? `#${route}` : `#/signup?next=${encodeURIComponent(route)}`;

function pageHome() {
  window.scrollTo(0, 0);
  view.innerHTML = `<div class="home">
    <section class="wrap home-hero">
      <div class="home-copy">
        <div class="eyebrow">Website teardown · crawl · OSINT · monitoring</div>
        <h1>See how any website is built. Then keep an eye on it.</h1>
        <p>Paste a URL for its tech stack, design system, real performance, accessibility and security in one report. Crawl whole sites, look up 15 kinds of public records, and get an alert when something changes.</p>
        <form class="search" id="home-form">
          <label for="home-url" style="position:absolute;left:-9999px">Website URL</label>
          <input id="home-url" type="text" inputmode="url" autocomplete="url" placeholder="example.com" required>
          <button class="primary" type="submit">${currentUser ? "Analyze →" : "Analyze free →"}</button>
        </form>
        <div class="home-proof">${["axe-core accessibility", "Throttled mobile Web Vitals", "retire.js CVE checks", "500-page crawls", "Figma & Tailwind tokens"]
          .map(t => `<span><svg viewBox="0 0 24 24" class="ico" aria-hidden="true"><path d="m5 12 5 5 9-10"/></svg>${t}</span>`).join("")}</div>
      </div>
      <a class="hero-shot" data-tilt href="${featHref("/analyze")}" aria-label="Open Analyze">
        <img src="/static/img/features/report.jpg" alt="A Deconstruct Site report for stripe.com with scores, screenshots and technology" width="1280" height="800" fetchpriority="high"
          onerror="this.closest('.hero-shot').classList.add('noimg')">
      </a>
    </section>

    <section class="wrap home-section" id="features">
      <div class="kicker">Everything in one place</div>
      <h2>Ten tools that usually take ten tabs</h2>
      <div class="feat-grid">${FEATURES.map(f => `
        <a class="feat" data-tilt href="${featHref(f.route)}">
          <div class="thumb"><img src="/static/img/features/${f.img}.jpg" alt="" loading="lazy" width="1280" height="800" onerror="this.parentElement.classList.add('noimg')"></div>
          <div class="feat-body"><h3>${esc(f.title)}</h3><p>${esc(f.text)}</p></div>
        </a>`).join("")}</div>
    </section>

    <section class="wrap home-section">
      <div class="kicker">How it works</div>
      <h2>From a URL to a watched site in three steps</h2>
      <ol class="steps">
        <li><b>Paste a URL</b><span>A fast pass reads the HTML, CSS and headers while a real Chromium loads the page, runs axe-core and measures throttled mobile loads.</span></li>
        <li><b>Read the report</b><span>Scores, issues with fixes, the design system and every resource. Export tokens or JSON, or crawl the whole site.</span></li>
        <li><b>Keep watching</b><span>Schedule re-analyses, OSINT refreshes and uptime checks. Changes arrive in Alerts and your channels.</span></li>
      </ol>
    </section>

    <section class="wrap home-section">
      <div class="home-cta">
        <div><h2>${currentUser ? "Pick up where you left off" : "Start deconstructing"}</h2>
          <p>${currentUser ? "Your history, projects and alerts are in the sidebar." : "Free, private to your account, and nothing to install."}</p></div>
        <a class="btn" href="${currentUser ? "#/analyze" : "#/signup"}">${currentUser ? "Analyze a website" : "Create an account"}</a>
      </div>
    </section>
    <footer class="wrap home-foot">Deconstruct Site · Lookups are passive and use public sources only.</footer>
  </div>`;
  $("#home-form").addEventListener("submit", e => {
    e.preventDefault();
    const u = $("#home-url").value.trim();
    if (!u) return;
    location.hash = currentUser ? `#/analyze?url=${encodeURIComponent(u)}` : `#/signup?next=${encodeURIComponent("/analyze?url=" + encodeURIComponent(u))}`;
  });
  wireTilt(view);
}

// Cards and screenshots lean slightly toward the pointer; nothing moves for people who prefer reduced motion.
function wireTilt(root) {
  if (matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  root.querySelectorAll("[data-tilt]").forEach(el => {
    el.addEventListener("pointermove", e => {
      const r = el.getBoundingClientRect();
      el.style.setProperty("--mx", ((e.clientX - r.left) / r.width - 0.5).toFixed(3));
      el.style.setProperty("--my", ((e.clientY - r.top) / r.height - 0.5).toFixed(3));
    });
    el.addEventListener("pointerleave", () => { el.style.setProperty("--mx", 0); el.style.setProperty("--my", 0); });
  });
}

function safeNext(q) {
  const n = q.get("next") || "";
  return n.startsWith("/") && !n.startsWith("//") ? n : "/analyze";
}

function pageAuth(kind, q) {
  const next = safeNext(q);
  if (currentUser) { location.replace("#" + next); return; }
  const up = kind === "signup";
  const closed = up && !authInfo.signup_open;
  view.innerHTML = `<div class="auth-wrap"><div class="auth-card">
    <h1>${up ? "Create your account" : "Welcome back"}</h1>
    <p>${up ? "Save analyses, crawls and lookups, and get alerts when sites change." : "Sign in to your analyses, crawls and alerts."}</p>
    ${closed ? `<div class="error" style="display:block">Sign-up is closed on this server. Ask its owner for an account.</div>
      <p class="switch"><a href="#/signin?next=${encodeURIComponent(next)}">Sign in instead</a></p>` : `
    <form id="auth-form" novalidate>
      ${up ? `<label for="au-name">Name <span class="muted" style="font-weight:400">(optional)</span></label>
        <input class="field" id="au-name" autocomplete="name" maxlength="80">` : ""}
      <label for="au-email">Email</label>
      <input class="field" id="au-email" type="email" autocomplete="${up ? "email" : "username"}" required>
      <label for="au-pw">Password</label>
      <div class="pw"><input class="field" id="au-pw" type="password" autocomplete="${up ? "new-password" : "current-password"}" minlength="8" required>
        <button type="button" id="au-show" aria-controls="au-pw" aria-pressed="false">Show</button></div>
      ${up ? '<div class="hint">At least 8 characters.</div>' : ""}
      ${up && !authInfo.has_users ? '<div class="note">This is the first account on this server, so anything already saved here becomes yours.</div>' : ""}
      <div class="error" id="auth-error" role="alert"></div>
      <button class="primary" type="submit">${up ? "Create account" : "Sign in"}</button>
    </form>
    <p class="switch">${up ? `Already have an account? <a href="#/signin?next=${encodeURIComponent(next)}">Sign in</a>`
      : authInfo.signup_open ? `New here? <a href="#/signup?next=${encodeURIComponent(next)}">Create an account</a>` : ""}</p>`}
  </div></div>`;
  if (closed) return;
  $(up ? "#au-name" : "#au-email").focus();
  $("#au-show").addEventListener("click", e => {
    const pw = $("#au-pw"), show = pw.type === "password";
    pw.type = show ? "text" : "password";
    e.target.textContent = show ? "Hide" : "Show";
    e.target.setAttribute("aria-pressed", String(show));
  });
  $("#auth-form").addEventListener("submit", async e => {
    e.preventDefault();
    const err = $("#auth-error"), btn = e.target.querySelector("button[type=submit]");
    err.style.display = "none";
    const email = $("#au-email").value.trim(), password = $("#au-pw").value;
    const problem = !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) ? "Enter a valid email address."
      : up && password.length < 8 ? "Use a password of at least 8 characters." : !password ? "Enter your password." : null;
    if (problem) { err.textContent = problem; err.style.display = "block"; return; }
    btn.disabled = true;
    try {
      const r = await api(`/api/auth/${kind}`, { method: "POST", body: { email, password, ...(up ? { name: $("#au-name").value.trim() } : {}) } });
      authInfo.has_users = true;
      setUser(r.user);
      const claimed = Object.values(r.claimed || {}).reduce((a, b) => a + b, 0);
      toast(up ? (claimed ? "Account created. Everything saved on this server is now yours." : "Account created") : `Welcome back${r.user.name ? ", " + esc(r.user.name) : ""}`);
      location.hash = "#" + next;
    } catch (ex) {
      err.textContent = ex.message; err.style.display = "block"; btn.disabled = false;
    }
  });
}
