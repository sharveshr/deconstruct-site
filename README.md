# Deconstruct Site

Paste a website URL and get a full report on how it's built.

## Run it

```
py -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m playwright install chromium
.venv\Scripts\python app.py
```

Then open http://localhost:5173 (or `http://localhost:5173/#/?url=stripe.com` to analyze straight away).
Set the `PORT` environment variable to use a different port.

## The sidebar

| Page | What it does |
|---|---|
| Analyze | Run an analysis. Every run is saved automatically as a new **iteration** of that site, optionally straight into a project. |
| Projects | Group sites together (a client's sites, competitors…). Add sites by URL, re-analyze them all at once, tick two to compare. |
| Uptime | Every saved site, with optional scheduled monitoring (every 1 min to 24 h). Per site: current status, uptime % for 24h/7d/30d, status timeline, response-time chart, incidents, and a log where you can record outages by hand with a note. |
| History | Every analysis you've ever run, grouped by day and searchable, so nothing gets lost. |
| Compare | Two different sites, or two iterations of one site, side by side: a scoreboard of measured metrics (scores, Core Web Vitals, page weight, requests, contrast failures…) with the winner of each, plus tech, issues, security headers, colors and fonts that differ. |

Data lives in `data/deconstruct.db` (SQLite, git-ignored). Set `DECONSTRUCT_DB` to store it elsewhere.
A site counts as **up** when it answers with HTTP status below 400 within 15 seconds.

## What it reports

Two passes run in parallel: a fast one over the raw HTML/CSS/headers, and a headless Chromium
load of the page (can be switched off with the checkbox, or `"render": false` in the API).

| Section | Contents |
|---|---|
| Overview | Desktop + mobile screenshots, final URL, redirects, IPs, server, HTTP version, server- vs client-side rendering |
| Technology | ~110 HTML/header fingerprints plus ~55 runtime checks (`window.next.version`, React fibers, `jQuery.fn.jquery`…) with evidence |
| Design | Colors by painted area, fonts by amount of text, typography per tag, rebuilt buttons, plus CSS palette, type/spacing scales, radii, shadows, breakpoints, motion, variables |
| Screenshots | Full page (up to 5000px) and header/footer/form component shots |
| Performance | Lab Core Web Vitals (LCP, FCP, TBT, CLS, TTFB) with LCP element, console and network errors, every resource with size/time/compression/caching |
| SEO | Title/description, canonical, Open Graph/Twitter, JSON-LD, robots.txt, sitemap, soft-404, JS-only content warning |
| Accessibility | WCAG AA contrast on rendered text, mobile overflow and tap targets, lang, alt text, labels, nameless controls, heading order |
| Security | TLS certificate, HTTPS redirect, security headers, cookies, mixed content, SRI, version leaks |
| Structure | Heading outline, nav, links, social/contact, forms, iframes, word count (from the rendered DOM) |

## API

All responses are `{"ok": true, "data": …}` or `{"ok": false, "error": "…"}`.

| Method & path | Purpose |
|---|---|
| `POST /api/analyze` `{url, render?, project_id?, label?}` | Analyze and save; returns the report plus `analysis_id`, `iteration`, `site` |
| `GET /api/analyses[?site_id=]` · `GET/PATCH/DELETE /api/analyses/<id>` | History and saved reports (PATCH sets `label`) |
| `GET /api/compare?a=<id>&b=<id>` | Diff of two saved analyses |
| `GET/POST /api/projects` · `GET/PATCH/DELETE /api/projects/<id>` | Projects |
| `POST /api/projects/<id>/sites` `{url \| site_id}` · `DELETE /api/projects/<id>/sites/<site_id>` | Project membership |
| `GET /api/sites` · `GET/PATCH/DELETE /api/sites/<id>` | Sites; PATCH sets `monitor_enabled`, `monitor_interval_min` |
| `GET /api/sites/<id>/checks?days=` · `POST /api/sites/<id>/checks` `{status, at?, note?}` | Uptime log; POST records a manual up/down event |
| `POST /api/sites/<id>/check-now` · `DELETE /api/checks/<id>` | Run a check immediately; delete a logged event |

## Files

- `app.py` — Flask server and API routes
- `analyzer.py` — fetching, every report section, scoring, and merging in browser results
- `browser.py` — headless Chromium pass (vitals, screenshots, computed styles, contrast, JS globals)
- `signatures.py` — HTML/header technology fingerprints; add a line to detect something new
- `store.py` — SQLite storage for projects, sites, iterations and uptime checks
- `monitor.py` — background thread that checks monitored sites on their interval
- `compare.py` — diff between two saved reports
- `static/index.html`, `app.js`, `app.css` — app shell, sidebar and library pages
- `static/report.js`, `styles.css` — the report view

## Notes

- Vitals are a single unthrottled lab load from this machine; real users on slower devices see higher numbers.
- Every request the browser makes is checked, and requests to private/loopback addresses are aborted,
  so a page can't use the server's browser to probe its local network.
- Sites behind bot challenges (e.g. Cloudflare "checking your browser") may show the challenge page.
