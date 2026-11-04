# Deconstruct Site

Paste a website URL and get a full report on how it's built. Crawl whole sites, run passive OSINT and security
lookups, watch sites for changes, and export a site's design system as tokens. Each account has its own private library.

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/sharveshr/deconstruct-site)

## Run it in GitHub Codespaces

Click the badge above (or **Code → Codespaces → Create codespace on main** on GitHub). The first start takes a few
minutes while it installs the Python packages and Chromium; after that the server starts in a terminal on its own
and the app opens in a new browser tab at `https://<codespace-name>-5173.app.github.dev`.

- The forwarded URL is private to your GitHub account by default. To show it to someone else, open the **Ports** tab,
  right-click port 5173 and set **Port Visibility** to Public. Anyone with the link can then create an account and
  use it; set `ALLOW_SIGNUP=0` once your own account exists to stop that.
- The database lives in `data/` inside the codespace. It survives stopping and restarting the codespace but is lost
  when the codespace is deleted.
- Codespaces stop after 30 minutes without activity (configurable in your GitHub settings), and uptime monitoring and
  scheduled watching only run while the codespace is running.
- If the server isn't running (for example after you closed its terminal), start it with `python app.py`.
- Notification links point at the codespace's forwarded URL automatically.
- Free GitHub accounts include 120 core-hours (60 hours on the default 2-core machine) per month.

## Run it locally

```
py -m venv .venv
.venv\Scripts\python -m pip install -r requirements-browser.txt
.venv\Scripts\python -m playwright install chromium
.venv\Scripts\python app.py
```

Then open http://localhost:5173 and create an account (or go to `http://localhost:5173/#/analyze?url=stripe.com` to analyze straight away).
Set the `PORT` environment variable to use a different port. `requirements.txt` alone installs everything except the
headless browser; the app then runs the quick analysis only.

## Deploy to Vercel

Vercel runs the app as a serverless Python function (`api/index.py`, configured in `vercel.json`), which changes
what it can do:

| Works | Doesn't work on Vercel |
|---|---|
| Quick analysis (technology, design from CSS, SEO, security, vulnerable libraries from script URLs and files, HTML accessibility checks, resource sizes) and token export | The browser pass: screenshots, Core Web Vitals, axe-core, computed styles. Playwright's Chromium is too large for a Vercel function, so only `requirements.txt` is installed |
| OSINT tools, Compare, History, Projects, manual uptime entries, "Check now" | Uptime monitoring and scheduled watching, which need a process that keeps running |
| Crawls, advanced a few seconds at a time while the crawl page is open (each status poll runs the next step) | Crawls continuing after you close the page |
| Alerts raised by analyses, crawls and OSINT lookups, sent while the request runs | Keeping data, **including accounts**: the database lives in `/tmp` and is lost whenever Vercel recycles the function, and each instance has its own copy. Accounts on Vercel need a hosted database first |

To deploy:

1. On [vercel.com/new](https://vercel.com/new), import the `deconstruct-site` repository (allow Vercel's GitHub app
   to access it). Keep the defaults; `vercel.json` sets the build.
2. Under **Environment Variables**, add `SECRET_KEY` (any long random string; it signs sign-in cookies, and without it
   each instance signs people out). Add `ALLOW_SIGNUP=0` to stop strangers creating accounts, or `APP_PASSWORD` to put
   the whole site behind one password (the browser asks for it, any username). Optionally add `CRUX_API_KEY` for
   real-user vitals and `APP_URL` for notification links.
3. Deploy. Every push to `main` redeploys; other branches get preview URLs.

For the full app (browser pass, monitoring, data that persists) use a host that runs a long-lived server with a disk,
such as Fly.io, Railway or a small VPS.

## Accounts

Everything except the home page needs an account. Sign up with an email and a password (at least 8 characters,
hashed with scrypt); each account only sees its own sites, analyses, projects, crawls, OSINT results, alerts and
notification channels, and background monitoring and watching run as the site's owner.

- **Existing data:** the first account created on a server takes over everything saved before accounts existed.
- **Sessions:** a signed cookie that lasts 30 days. Set `SECRET_KEY` to keep sign-ins valid across restarts on hosts
  without a persistent disk; otherwise a key is generated and kept in `data/secret_key`.
- **Closing sign-up:** set `ALLOW_SIGNUP=0`, and only the first account can be created.
- **Abuse protection:** repeated failed sign-ins for an address are slowed down (8 per 15 minutes). Every API call
  that changes something must send `X-Requested-With: fetch`, which a cross-site form can't, and the cookie is
  `SameSite=Lax`.
- **Not built yet:** password reset by email and team sharing.

## The sidebar

| Page | What it does |
|---|---|
| Home | What the app does, with screenshots of each feature. The only page open to signed-out visitors. |
| Analyze | Run an analysis. Every run is saved automatically as a new **iteration** of that site, optionally straight into a project. |
| Projects | Group sites together (a client's sites, competitors…). Add sites by URL, re-analyze them all at once, tick two to compare. |
| Uptime | Every saved site, with optional scheduled monitoring (every 1 min to 24 h). Per site: current status, uptime % for 24h/7d/30d, status timeline, response-time chart, incidents, and a log where you can record outages by hand with a note. |
| Crawl | Crawl a whole site (see below). |
| History | Every analysis you've ever run, grouped by day and searchable, so nothing gets lost. |
| Alerts | What changed between runs, with notification channels and per-site watch schedules (see below). |
| OSINT | Fifteen passive lookups for a domain, run in parallel; each result card fills in as its source answers, and results are saved (see below). |
| Compare | Two different sites, or two iterations of one site, side by side: a scoreboard of measured metrics (scores, Core Web Vitals, page weight, requests, contrast failures…) with the winner of each, plus tech, issues, security headers, colors and fonts that differ. |

### Crawl

A crawl starts at a URL, reads robots.txt and the sitemap, and follows links on the same site (breadth-first, up to
10 clicks deep) for 25, 100, 250 or 500 pages. It then checks up to 300 outgoing links and files on the site (PDFs and
the like) with HEAD requests. robots.txt is respected for every page, including `Crawl-delay` (capped at 5 s).

| Finds | Details |
|---|---|
| Broken pages and links | Pages returning 4xx/5xx or not loading, with the pages that link to them; dead outgoing links. Links that answer 401/403/429/999 are listed separately as "couldn't verify", since many servers block bots |
| Redirects | Internal links that redirect, and chains of more than one hop |
| Titles, descriptions, headings | Missing, duplicated or over-long titles and meta descriptions; missing or multiple H1s |
| Content | Thin pages (under 200 words), pages with the same text, `noindex` (meta or header), canonicals pointing elsewhere, images without alt, missing `lang` |
| Sitemap coverage | Orphans (in the sitemap but not linked from any crawled page, only reliable when the crawl covered the whole site) and crawled pages missing from the sitemap |
| Speed | Median and 90th-percentile response time, slowest pages, heaviest HTML |
| Consistency | Technology on most pages but missing from some (analytics or a consent banner missing from one template) |

**Site health** is the share of pages without a serious issue (errors, broken links, missing or duplicate titles,
descriptions or H1s, duplicate content, slow responses). The pages table filters by issue and sorts by any column;
**Download CSV** exports every page. A crawl runs in short steps with its queue in the database, so it survives a
restart; locally a background worker drives it, and on Vercel the open crawl page does.

### Design tokens

The Design tab exports the site's design as tokens: colors (with background, surface, text and primary roles taken
from what the browser painted, plus the site's own named color variables), font families, type scale, weights, line
heights, spacing, radii, shadows, breakpoints and durations. Formats: CSS variables, SCSS, a Tailwind v3 config, a
Tailwind v4 `@theme` block, and W3C Design Tokens JSON, which Figma Tokens Studio and Style Dictionary read.
`GET /api/analyses/<id>/tokens?format=css|scss|tailwind|tailwind4|json`. A quick analysis (no browser) exports a plain
palette, since CSS-text counts can't tell a dark theme's background from its text.

### Change detection and alerts

Every new result is compared with the previous one of the same kind, and differences become events
(info / warning / critical) shown under **Alerts** and sent to your channels.

| Source | Alerts on |
|---|---|
| Analysis (vs. the previous run made the same way, with or without the browser) | Score drops ≥10 (critical ≥25), HTTP status, landing URL, title, technology added/removed/version, security headers removed, page weight +50%, LCP turning poor, 3+ new issues, certificate expiry, a JavaScript library with known vulnerabilities (once per version; critical for high/critical severity) |
| Crawl (vs. the site's previous crawl) | Pages that started returning errors (critical if the start page or 5+ pages), site health down ≥10, pages that became `noindex`, 3+ more broken outgoing links; a first crawl that finds broken pages |
| OSINT | New subdomains (warning for dev/staging/admin names), NS/MX/A/TXT/CAA changes (load-balancer IP rotation ignored), registrar/nameserver changes, domain expiry (30/7 days) and hold status, certificate expiry (14/3 days), issuer change, TLS 1.0/1.1 re-enabled, DMARC weakened, SPF changed/removed, email grade drop, canonical URL change, HTTP→HTTPS redirect lost, robots.txt blocking everything, subdomain takeover candidates (critical), newly registered lookalike domains, the domain appearing on a blocklist (critical) |
| Uptime | Site down (confirmed by a second check) and recovered, with downtime |

Repeating alerts (expiry thresholds, header removals) are de-duplicated. **Watching** schedules a full re-analysis and/or
an OSINT refresh per site (hourly to weekly), or for a whole project at once; schedules only run while the app is running.

**Channels:** Slack (Incoming Webhook URL), Discord (channel webhook URL), generic webhook (JSON POST), or email.
Email reads its SMTP settings from environment variables so no password is stored in the database:

```
SMTP_HOST=smtp.example.com SMTP_PORT=587 SMTP_USER=me@example.com SMTP_PASSWORD=… SMTP_FROM=alerts@example.com
```

Set `APP_URL` to the address the app is reachable at so links in notifications work (default `http://localhost:$PORT`,
or the forwarded URL in a codespace). Webhooks must point to public internet addresses and aren't sent on through
redirects; set `ALLOW_PRIVATE_WEBHOOKS=1` to send alerts to a tool on your own network (n8n, Home Assistant) when
the app isn't reachable by others.

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
| Subdomain Takeover | Subdomains whose CNAME points at a service where the resource is gone (GitHub Pages, Heroku, S3, Azure, Shopify, Fastly and ~15 more), from NXDOMAIN targets or the service's "nothing here" page | CT logs + DNS + one HTTP request per candidate |
| Lookalike Domains | Up to 500 typo, homoglyph, keyboard, bit-flip, hyphen, affix and other-TLD variations, which are registered, which receive mail, and which share your nameservers (probably yours) | DNS only; no lookalike site is visited |
| Blocklist Reputation | The domain on the Spamhaus DBL and its web server addresses on Spamhaus ZEN; Google Safe Browsing with `SAFE_BROWSING_API_KEY`; abuse.ch URLhaus with `URLHAUS_AUTH_KEY` | Spamhaus is queried at its own nameservers, since it refuses public resolvers |

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
| Performance | Lab Core Web Vitals (LCP, FCP, TBT, CLS, TTFB) as the median of 1–5 cold mobile loads on 4G (9 Mbps, 60 ms, 4× CPU slowdown) with the spread across runs and an unthrottled desktop load for comparison; optional real-user p75 vitals from the Chrome UX Report; LCP element, console and network errors, every resource with size/time/compression/caching |
| SEO | Title/description, canonical, Open Graph/Twitter, JSON-LD, robots.txt, sitemap, soft-404, JS-only content warning |
| Accessibility | axe-core (WCAG 2.0–2.2 A/AA and best practices) on the rendered page, with impact, affected elements and fix links; mobile overflow and tap targets. Falls back to basic HTML checks without the browser |
| Security | TLS certificate, HTTPS redirect, security headers, cookies, mixed content, SRI, version leaks, and JavaScript libraries with known vulnerabilities (the [retire.js](https://github.com/RetireJS/retire.js) database, downloaded and cached for a day): versions come from script URLs and file names, the start of up to 10 script files, version expressions evaluated in the rendered page (`jQuery.fn.jquery`…), and technology detection. Each finding lists its CVEs and the version that fixes them, or says the line is end of life |
| Structure | Heading outline, nav, links, social/contact, forms, iframes, word count (from the rendered DOM) |

## API

All responses are `{"ok": true, "data": …}` or `{"ok": false, "error": "…"}`.

| Method & path | Purpose |
|---|---|
| `GET /api/auth/me` · `POST /api/auth/signup` `{email, password, name?}` · `POST /api/auth/signin` `{email, password}` · `POST /api/auth/signout` | Accounts; everything else needs a signed-in session |
| `POST /api/analyze` `{url, render?, project_id?, label?}` | Analyze and save; returns the report plus `analysis_id`, `iteration`, `site` |
| `GET /api/analyses[?site_id=]` · `GET/PATCH/DELETE /api/analyses/<id>` | History and saved reports (PATCH sets `label`) |
| `GET /api/compare?a=<id>&b=<id>` | Diff of two saved analyses |
| `GET/POST /api/projects` · `GET/PATCH/DELETE /api/projects/<id>` | Projects |
| `POST /api/projects/<id>/sites` `{url \| site_id}` · `DELETE /api/projects/<id>/sites/<site_id>` | Project membership |
| `GET /api/sites` · `GET/PATCH/DELETE /api/sites/<id>` | Sites; PATCH sets `monitor_enabled`, `monitor_interval_min` |
| `GET /api/sites/<id>/checks?days=` · `POST /api/sites/<id>/checks` `{status, at?, note?}` | Uptime log; POST records a manual up/down event |
| `POST /api/sites/<id>/check-now` · `DELETE /api/checks/<id>` | Run a check immediately; delete a logged event |
| `GET /api/analyses/<id>/tokens?format=` | Design tokens (see above) |
| `GET/POST /api/crawls` `{url, max_pages, max_depth?}` · `GET/DELETE /api/crawls/<id>` · `POST /api/crawls/<id>/stop` | Crawls; GET returns progress and, when done, the summary |
| `GET /api/crawls/<id>/pages?issue=&q=&sort=&dir=` · `GET /api/crawls/<id>/pages.csv` | Crawled pages with their issues |

## Files

- `app.py` — Flask server and API routes
- `api/index.py`, `vercel.json`, `.vercelignore` — Vercel deployment (see above)
- `.devcontainer/` — GitHub Codespaces setup
- `analyzer.py` — fetching, every report section, scoring, and merging in browser results
- `browser.py` — headless Chromium pass (vitals, screenshots, computed styles, contrast, JS globals)
- `signatures.py` — HTML/header technology fingerprints; add a line to detect something new
- `store.py` — SQLite storage for accounts, projects, sites, iterations, uptime checks, crawls and alerts, scoped to the signed-in account
- `crawl.py` — the multi-page crawler and its summary
- `tokens.py` — design-token export
- `vulns.py` — vulnerable JavaScript libraries (retire.js)
- `monitor.py` — background thread that checks monitored sites on their interval
- `compare.py` — diff between two saved reports
- `osint.py` — the fifteen OSINT tools
- `watch.py` — change-detection rules and the scheduled watcher
- `notify.py` — Slack, Discord, webhook and email delivery
- `static/alerts.js` — the Alerts page
- `static/osint.js` — the OSINT page
- `static/crawl.js` — the Crawl pages
- `static/home.js`, `static/img/features/` — the home page and its screenshots, and the sign-in / sign-up pages
- `scripts/make_thumbnails.py` — retakes the home page screenshots from a running copy of the app
- `static/index.html`, `app.js`, `app.css` — app shell, sidebar and library pages
- `static/report.js`, `styles.css` — the report view

## Notes

- Lab vitals emulate a mid-range phone on 4G with Chrome DevTools throttling. They're more realistic than an
  unthrottled load but are not the same as PageSpeed Insights' simulated scores. TTFB is the server's own response
  time (Chrome applies emulated latency after it). For what real visitors experience, set `CRUX_API_KEY` to a free
  [Chrome UX Report API key](https://developer.chrome.com/docs/crux/api); sites without enough Chrome traffic have no field data.
- `POST /api/analyze` accepts `perf_runs` (1–5, default 3). Alerts only compare runs measured the same way, so the
  first throttled run of a site never raises false score or vitals alerts against older desktop-measured runs.
- Page weight in comparisons and alerts uses the bytes the browser actually transferred, which is stable between runs.
- Every request the browser makes is checked, and requests to private/loopback addresses are aborted,
  so a page can't use the server's browser to probe its local network.
- Sites behind bot challenges (e.g. Cloudflare "checking your browser") may show the challenge page.
