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
| Alerts | What changed between runs, with notification channels and per-site watch schedules (see below). |
| OSINT | Twelve passive lookups for a domain, run in parallel; each result card fills in as its source answers, and results are saved (see below). |
| Compare | Two different sites, or two iterations of one site, side by side: a scoreboard of measured metrics (scores, Core Web Vitals, page weight, requests, contrast failures…) with the winner of each, plus tech, issues, security headers, colors and fonts that differ. |

### Change detection and alerts

Every new result is compared with the previous one of the same kind, and differences become events
(info / warning / critical) shown under **Alerts** and sent to your channels.

| Source | Alerts on |
|---|---|
| Analysis (vs. the previous run made the same way, with or without the browser) | Score drops ≥10 (critical ≥25), HTTP status, landing URL, title, technology added/removed/version, security headers removed, page weight +50%, LCP turning poor, 3+ new issues, certificate expiry |
| OSINT | New subdomains (warning for dev/staging/admin names), NS/MX/A/TXT/CAA changes (load-balancer IP rotation ignored), registrar/nameserver changes, domain expiry (30/7 days) and hold status, certificate expiry (14/3 days), issuer change, TLS 1.0/1.1 re-enabled, DMARC weakened, SPF changed/removed, email grade drop, canonical URL change, HTTP→HTTPS redirect lost, robots.txt blocking everything |
| Uptime | Site down (confirmed by a second check) and recovered, with downtime |

Repeating alerts (expiry thresholds, header removals) are de-duplicated. **Watching** schedules a full re-analysis and/or
an OSINT refresh per site (hourly to weekly), or for a whole project at once; schedules only run while the app is running.

**Channels:** Slack (Incoming Webhook URL), Discord (channel webhook URL), generic webhook (JSON POST), or email.
Email reads its SMTP settings from environment variables so no password is stored in the database:

```
SMTP_HOST=smtp.example.com SMTP_PORT=587 SMTP_USER=me@example.com SMTP_PASSWORD=… SMTP_FROM=alerts@example.com
```

Set `APP_URL` to the address the app is reachable at so links in notifications work (default `http://localhost:$PORT`).

### OSINT tools

All lookups are passive and use public sources only; nothing is scanned or brute-forced.

| Tool | What it finds | Source |
|---|---|---|
| DNS Lookup | A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, HTTPS records | DNS-over-HTTPS (Cloudflare, Google fallback) |
| WHOIS / RDAP | Registrar, created/expiry dates, status, nameservers, DNSSEC, abuse contact | RDAP via rdap.org |
| Subdomain Discovery | Names seen on public certificates, which still resolve, notable ones (dev, staging, admin…) | crt.sh, Cert Spotter fallback |
| SSL Certificate | Issuer, validity, days left, SANs, fingerprint, cipher, TLS 1.0–1.3 support, recent certificates | TLS handshake + CT logs |
| HTTP Header Analyzer | Security-header grade, HSTS, CSP breakdown, cookie flags, software disclosure, caching, CORS | HTTPS request |
| Technology Detection | CMS, frameworks, hosting, analytics with evidence | Fingerprints (`signatures.py`) |
| IP / ASN Lookup | IPs, reverse DNS, ASN and AS name, prefix, network owner and abuse contact | Team Cymru DNS + RDAP |
| Website History | First/last capture, months captured per year, snapshot links | Internet Archive CDX API |
| Robots.txt Analyzer | Rules per user agent, AI-crawler policy, notable disallowed paths, sitemaps | robots.txt |
| Sitemap Analyzer | URL count, sections, lastmod range, sample URLs (follows sitemap indexes, gzip) | sitemap.xml |
| Email Security | SPF (incl. 10-lookup limit), DMARC, DKIM on ~45 common selectors, MTA-STS, TLS-RPT, BIMI, grade | DNS |
| Redirect Analyzer | Hop-by-hop chains for http/https × bare/www, canonical URL, downgrades, meta refresh | HTTP |

`GET /api/osint/<tool>?target=example.com` runs one tool; `GET /api/osint/saved?target=` returns the latest saved result per tool;
`GET /api/osint/recent` lists looked-up domains.

Alerts API: `GET /api/events?severity=&site_id=&unread=1&before=`, `GET /api/events/unread`,
`POST /api/events/read {ids|all, read}`, `POST /api/events/delete {ids|all}`; channels at `GET/POST /api/channels`,
`PATCH/DELETE /api/channels/<id>`, `POST /api/channels/<id>/test`; schedules via `PATCH /api/sites/<id>`
`{watch_analyze_hours, watch_osint_hours}` (0, 1, 6, 12, 24, 72 or 168) or `POST /api/projects/<id>/watch` for every site in a project.

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
- `osint.py` — the twelve OSINT tools
- `watch.py` — change-detection rules and the scheduled watcher
- `notify.py` — Slack, Discord, webhook and email delivery
- `static/alerts.js` — the Alerts page
- `static/osint.js` — the OSINT page
- `static/index.html`, `app.js`, `app.css` — app shell, sidebar and library pages
- `static/report.js`, `styles.css` — the report view

## Notes

- Vitals are a single unthrottled lab load from this machine; real users on slower devices see higher numbers.
- Every request the browser makes is checked, and requests to private/loopback addresses are aborted,
  so a page can't use the server's browser to probe its local network.
- Sites behind bot challenges (e.g. Cloudflare "checking your browser") may show the challenge page.
