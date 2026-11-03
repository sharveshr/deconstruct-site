# Deconstruct Site

Paste a website URL and get a full report on how it's built.

## Run it

```
py -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m playwright install chromium
.venv\Scripts\python app.py
```

Then open http://localhost:5173 (or `http://localhost:5173/?url=stripe.com` to analyze straight away).

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

`POST /api/analyze` with `{"url": "example.com", "render": true}` returns the whole report as JSON.

## Files

- `app.py` — Flask server
- `analyzer.py` — fetching, every report section, scoring, and merging in browser results
- `browser.py` — headless Chromium pass (vitals, screenshots, computed styles, contrast, JS globals)
- `signatures.py` — HTML/header technology fingerprints; add a line to detect something new
- `static/index.html` — the UI

## Notes

- Vitals are a single unthrottled lab load from this machine; real users on slower devices see higher numbers.
- Every request the browser makes is checked, and requests to private/loopback addresses are aborted,
  so a page can't use the server's browser to probe its local network.
- Sites behind bot challenges (e.g. Cloudflare "checking your browser") may show the challenge page.
