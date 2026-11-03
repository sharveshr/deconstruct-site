"""Loads the page in headless Chromium to see what only a real browser can:
lab Core Web Vitals, screenshots, computed styles, color contrast, JavaScript
globals, console errors and the fully rendered DOM.

Uses Playwright's sync API; each call owns its own browser, so it is safe to
run from a worker thread.
"""
from __future__ import annotations

import base64
import os
import statistics
import time
from urllib.parse import urlparse

try:
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import TimeoutError as PlaywrightTimeout
    from playwright.sync_api import sync_playwright
    AVAILABLE = True
except ImportError:
    AVAILABLE = False

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0 Safari/537.36 DeconstructSite/1.0"
)
MOBILE_UA = (
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0 Mobile Safari/537.36 DeconstructSite/1.0"
)
NAV_TIMEOUT_MS = 25_000
THROTTLED_NAV_TIMEOUT_MS = 45_000
MAX_FULLPAGE_HEIGHT = 5000
DEFAULT_PERF_RUNS = 3

# A mid-range phone on a typical 4G connection (Chrome DevTools' "Fast 4G" preset with a 4x CPU slowdown),
# so lab vitals reflect a realistic visitor rather than this machine's fast desktop connection.
# Lighthouse's harsher "Slow 4G" (1.6 Mbps, 562 ms per request) made heavy pages take 25+ s per load here,
# because DevTools adds the latency to every request; its own scores use simulation instead.
THROTTLE = {"name": "Fast 4G, 4× CPU slowdown", "latency_ms": 60, "down_bps": 9 * 1024 * 1024 / 8,
            "up_bps": 1.5 * 1024 * 1024 / 8, "cpu": 4}
PERF_VIEWPORT = {"width": 412, "height": 823}

try:
    import axe_playwright_python as _axe_pkg
    AXE_JS = os.path.join(os.path.dirname(_axe_pkg.__file__), "axe.min.js")
    if not os.path.exists(AXE_JS):
        AXE_JS = None
except ImportError:
    AXE_JS = None

_axe_source = None
AXE_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"]
RUN_AXE = """
async (tags) => {
  // preload:false stops axe re-fetching cross-origin stylesheets, which caused CORS errors
  // that would show up as if the site had them.
  const r = await axe.run(document, { runOnly: { type: 'tag', values: tags }, resultTypes: ['violations'], preload: false });
  const trim = s => s && s.length > 240 ? s.slice(0, 240) + '…' : s;
  return {
    version: axe.version,
    violations: r.violations.map(v => ({
      id: v.id, impact: v.impact, help: v.help, description: v.description, help_url: v.helpUrl,
      tags: v.tags.filter(t => /^wcag\\d|best-practice/.test(t)), count: v.nodes.length,
      nodes: v.nodes.slice(0, 8).map(n => ({ target: [].concat(n.target).join(' '), html: trim(n.html), summary: trim(n.failureSummary) })),
    })),
    passes: r.passes.length, incomplete: r.incomplete.length, inapplicable: r.inapplicable.length,
  };
}
"""

# Installed before any page script runs, so buffered entries are never missed.
VITALS_INIT = """
(() => {
  const s = window.__ss = { lcp: null, lcpEl: null, cls: 0, longtasks: [] };
  const obs = (type, fn) => { try { new PerformanceObserver(l => l.getEntries().forEach(fn)).observe({ type, buffered: true }); } catch (e) {} };
  obs('largest-contentful-paint', e => {
    s.lcp = e.startTime;
    s.lcpAt = performance.now();
    const el = e.element;
    s.lcpEl = el ? (el.tagName.toLowerCase() + (el.id ? '#' + el.id : '') + (el.className && typeof el.className === 'string' ? '.' + el.className.trim().split(/\\s+/).slice(0, 2).join('.') : '')) + (e.url ? ' ' + e.url : '') : null;
  });
  obs('layout-shift', e => { if (!e.hadRecentInput) s.cls += e.value; });
  obs('longtask', e => s.longtasks.push([e.startTime, e.duration]));
})();
"""

COLLECT_VITALS = """
() => {
  const s = window.__ss || {};
  const nav = performance.getEntriesByType('navigation')[0] || {};
  const fcp = (performance.getEntriesByName('first-contentful-paint')[0] || {}).startTime ?? null;
  const tbt = (s.longtasks || []).filter(([st]) => fcp == null || st >= fcp).reduce((a, [, d]) => a + Math.max(0, d - 50), 0);
  const res = performance.getEntriesByType('resource');
  return {
    ttfb: nav.responseStart ?? null, fcp, lcp: s.lcp, lcp_element: s.lcpEl, cls: s.cls ?? 0, tbt,
    long_tasks: (s.longtasks || []).length,
    dom_content_loaded: nav.domContentLoadedEventEnd ?? null, load: nav.loadEventEnd ?? null,
    transfer_bytes: res.reduce((a, r) => a + (r.transferSize || 0), 0) + (nav.transferSize || 0),
    dom_nodes: document.getElementsByTagName('*').length,
    js_heap: performance.memory ? performance.memory.usedJSHeapSize : null,
  };
}
"""

# Reads computed styles from visible elements. Colors and fonts are weighted
# by how much of the page they actually cover, unlike the CSS-text counts.
COLLECT_STYLES = """
() => {
  const vis = el => { const r = el.getBoundingClientRect(); const cs = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && cs.visibility !== 'hidden' && cs.display !== 'none' && parseFloat(cs.opacity) > 0.05; };
  const toHex = c => { const m = c.match(/rgba?\\(([\\d.]+),\\s*([\\d.]+),\\s*([\\d.]+)(?:,\\s*([\\d.]+))?/); if (!m) return null;
    const a = m[4] === undefined ? 1 : +m[4]; if (a === 0) return null;
    const h = '#' + [m[1], m[2], m[3]].map(v => (+v | 0).toString(16).padStart(2, '0')).join('');
    return a < 1 ? h + Math.round(a * 255).toString(16).padStart(2, '0') : h; };
  const area = {}, text = {}, fonts = {}, sizes = {}, radii = {};
  const els = [...document.body.querySelectorAll('*')].slice(0, 5000);
  for (const el of els) {
    if (!vis(el)) continue;
    const cs = getComputedStyle(el), r = el.getBoundingClientRect();
    const bg = toHex(cs.backgroundColor);
    if (bg) area[bg] = (area[bg] || 0) + Math.min(r.width * r.height, 4e6);
    const own = [...el.childNodes].filter(n => n.nodeType === 3).map(n => n.textContent.trim()).join(' ');
    if (own.length) {
      const fg = toHex(cs.color); if (fg) text[fg] = (text[fg] || 0) + own.length;
      const fam = cs.fontFamily.split(',')[0].replace(/["']/g, '').trim();
      fonts[fam] = (fonts[fam] || 0) + own.length;
      sizes[cs.fontSize] = (sizes[cs.fontSize] || 0) + 1;
    }
    if (cs.borderRadius !== '0px' && (bg || cs.borderStyle !== 'none')) radii[cs.borderRadius] = (radii[cs.borderRadius] || 0) + 1;
  }
  const top = (o, n) => Object.entries(o).sort((a, b) => b[1] - a[1]).slice(0, n).map(([value, count]) => ({ value, count: Math.round(count) }));
  const pick = (el, props) => { const cs = getComputedStyle(el); return Object.fromEntries(props.map(p => [p, cs.getPropertyValue(p)])); };
  const typeProps = ['font-family', 'font-size', 'font-weight', 'line-height', 'letter-spacing', 'color', 'text-transform'];
  const headings = ['h1', 'h2', 'h3', 'h4', 'p', 'a'].map(t => { const el = [...document.querySelectorAll(t)].find(vis);
    return el ? { tag: t, sample: el.textContent.trim().slice(0, 60), ...pick(el, typeProps) } : null; }).filter(Boolean);
  const btnCandidates = [...document.querySelectorAll('button, a[class*="btn"], a[class*="button"], [role="button"], input[type="submit"]')].filter(vis);
  const seen = new Set(), buttons = [];
  for (const el of btnCandidates) {
    const st = pick(el, ['background-color', 'color', 'border-radius', 'padding', 'font-size', 'font-weight', 'font-family', 'border', 'box-shadow', 'text-transform']);
    const key = st['background-color'] + st.color + st['border-radius'] + st.padding;
    const looksLikeButton = toHex(st['background-color']) || (parseFloat(getComputedStyle(el).borderTopWidth) > 0 && getComputedStyle(el).borderTopStyle !== 'none');
    if (!looksLikeButton || seen.has(key) || !(el.innerText || el.value || '').trim()) continue;
    seen.add(key); buttons.push({ label: (el.innerText || el.value).trim().slice(0, 30), ...st });
    if (buttons.length >= 8) break;
  }
  const body = pick(document.body, ['font-family', 'font-size', 'line-height', 'color', 'background-color']);
  const vars = {}; const rs = getComputedStyle(document.documentElement);
  for (let i = 0; i < rs.length && Object.keys(vars).length < 150; i++) { const p = rs[i]; if (p.startsWith('--')) vars[p] = rs.getPropertyValue(p).trim().slice(0, 80); }
  return { background_by_area: top(area, 14), text_colors: top(text, 12), fonts_by_text: top(fonts, 8), font_sizes: top(sizes, 14),
           radii: top(radii, 10), typography: headings, buttons, body, root_variables: vars, root_variable_count: Object.keys(vars).length };
}
"""

COLLECT_CONTRAST = """
() => {
  const parse = c => { const m = c.match(/rgba?\\(([\\d.]+),\\s*([\\d.]+),\\s*([\\d.]+)(?:,\\s*([\\d.]+))?/); return m ? [+m[1], +m[2], +m[3], m[4] === undefined ? 1 : +m[4]] : null; };
  const blend = (top, bot) => [0, 1, 2].map(i => top[i] * top[3] + bot[i] * (1 - top[3])).concat(1);
  const lum = c => { const [r, g, b] = c.slice(0, 3).map(v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }); return 0.2126 * r + 0.7152 * g + 0.0722 * b; };
  const ratio = (a, b) => { const [l1, l2] = [lum(a), lum(b)].sort((x, y) => y - x); return (l1 + 0.05) / (l2 + 0.05); };
  const hex = c => '#' + c.slice(0, 3).map(v => Math.round(v).toString(16).padStart(2, '0')).join('');
  const bgOf = el => { const layers = []; let imageBehind = false;
    for (let n = el; n && n.nodeType === 1; n = n.parentElement) { const cs = getComputedStyle(n);
      if (cs.backgroundImage !== 'none') { imageBehind = true; break; }
      const c = parse(cs.backgroundColor); if (c && c[3] > 0) { layers.push(c); if (c[3] >= 1) break; } }
    let out = [255, 255, 255, 1]; for (let i = layers.length - 1; i >= 0; i--) out = blend(layers[i], out);
    return { color: out, imageBehind }; };
  const fails = [], keys = new Set(); let checked = 0, uncertain = 0;
  for (const el of [...document.body.querySelectorAll('*')].slice(0, 5000)) {
    const own = [...el.childNodes].filter(n => n.nodeType === 3).map(n => n.textContent.trim()).join(' ').trim();
    if (!own) continue;
    const r = el.getBoundingClientRect(), cs = getComputedStyle(el);
    if (!r.width || !r.height || cs.visibility === 'hidden' || cs.display === 'none' || parseFloat(cs.opacity) < 0.1) continue;
    if (el.closest('[aria-hidden="true"], [hidden]')) continue;
    if (r.right < 0 || r.left > innerWidth) continue;
    // screen-reader-only text (.sr-only, .screen-reader-text) is 1px and clipped
    if (r.width < 3 || r.height < 3 || /rect\\(0/.test(cs.clip) || /inset\\(50%/.test(cs.clipPath)) continue;
    // opacity isn't inherited in computed style, so walk up for faded-out containers (carousels, reveal animations)
    let op = 1, clipText = false;
    for (let n = el; n && n.nodeType === 1; n = n.parentElement) {
      const ncs = getComputedStyle(n); op *= parseFloat(ncs.opacity);
      if (ncs.webkitTextFillColor && /transparent|rgba\\(.*,\\s*0\\)/.test(ncs.webkitTextFillColor) || ncs.webkitBackgroundClip === 'text' || ncs.backgroundClip === 'text') clipText = true;
    }
    if (op < 0.1) continue;
    checked++;
    const { color: bg, imageBehind } = bgOf(el);
    if (imageBehind || clipText) { uncertain++; continue; }
    const fgRaw = parse(cs.color); if (!fgRaw) continue;
    const fg = blend(fgRaw, bg), cr = ratio(fg, bg);
    if (cr < 1.05) { uncertain++; continue; }  // same color as background: hidden/animated text, not a real failure
    const size = parseFloat(cs.fontSize), bold = parseInt(cs.fontWeight) >= 700;
    const large = size >= 24 || (bold && size >= 18.66);
    const need = large ? 3 : 4.5;
    if (cr < need) {
      const key = hex(fg) + hex(bg) + large;
      if (keys.has(key)) { fails.find(f => f.key === key).count++; continue; }
      keys.add(key);
      fails.push({ key, text: own.slice(0, 60), fg: hex(fg), bg: hex(bg), ratio: Math.round(cr * 100) / 100, required: need,
                   font_size: cs.fontSize, tag: el.tagName.toLowerCase(), count: 1 });
    }
  }
  fails.sort((a, b) => a.ratio - b.ratio);
  return { checked, uncertain, failing_groups: fails.length, failing_elements: fails.reduce((a, f) => a + f.count, 0), failures: fails.slice(0, 30) };
}
"""

# Libraries that expose themselves on window or on DOM nodes at runtime.
COLLECT_GLOBALS = """
() => {
  const out = [], w = window;
  const add = (name, category, version, evidence) => out.push({ name, category, version: version ? String(version) : null, evidence: ['js: ' + evidence] });
  const anyEl = (test) => { for (const el of document.querySelectorAll('body *')) { if (test(el)) return true; } return false; };
  try {
    if (w.React || anyEl(el => Object.keys(el).some(k => k.startsWith('__reactFiber') || k.startsWith('__reactContainer'))) || document.getElementById('__next'))
      add('React', 'JavaScript library', w.React && w.React.version, w.React ? 'window.React' : 'React fiber on DOM nodes');
    if (w.next) add('Next.js', 'JavaScript framework', w.next.version, 'window.next');
    if (w.__NUXT__ || w.$nuxt || w.useNuxtApp) add('Nuxt', 'JavaScript framework', w.$nuxt && w.$nuxt.$root && w.$nuxt.$root.constructor && w.$nuxt.$root.constructor.version, 'window.__NUXT__');
    const vueApp = document.querySelector('[data-v-app]') || anyEl(el => el.__vue_app__ || el.__vue__);
    if (w.Vue || vueApp) add('Vue.js', 'JavaScript library', w.Vue && w.Vue.version, w.Vue ? 'window.Vue' : 'Vue instance on DOM');
    if (w.getAllAngularRootElements || w.ng) { const v = document.querySelector('[ng-version]'); add('Angular', 'JavaScript framework', v && v.getAttribute('ng-version'), 'Angular runtime'); }
    if (w.angular) add('AngularJS', 'JavaScript framework', w.angular.version && w.angular.version.full, 'window.angular');
    if (w.__svelte || anyEl(el => el.__svelte_meta)) add('Svelte', 'JavaScript library', null, 'Svelte runtime');
    if (w.jQuery) add('jQuery', 'JavaScript library', w.jQuery.fn && w.jQuery.fn.jquery, 'window.jQuery');
    if (w.Alpine) add('Alpine.js', 'JavaScript library', w.Alpine.version, 'window.Alpine');
    if (w.htmx) add('htmx', 'JavaScript library', w.htmx.version, 'window.htmx');
    if (w.Ember) add('Ember.js', 'JavaScript framework', w.Ember.VERSION, 'window.Ember');
    if (w.Backbone) add('Backbone.js', 'JavaScript library', w.Backbone.VERSION, 'window.Backbone');
    if (w.Stimulus) add('Stimulus', 'JavaScript library', null, 'window.Stimulus');
    if (w.Turbo) add('Turbo', 'JavaScript library', null, 'window.Turbo');
    if (w.preact) add('Preact', 'JavaScript library', null, 'window.preact');
    if (w.gsap) add('GSAP', 'Animation', w.gsap.version, 'window.gsap');
    if (w.THREE) add('Three.js', '3D / WebGL', w.THREE.REVISION, 'window.THREE');
    if (w.lottie || w.bodymovin) add('Lottie', 'Animation', null, 'window.lottie');
    if (w.Swiper) add('Swiper', 'UI library', null, 'window.Swiper');
    if (w._ && w._.VERSION) add('Lodash', 'JavaScript library', w._.VERSION, 'window._');
    if (w.moment) add('Moment.js', 'JavaScript library', w.moment.version, 'window.moment');
    if (w.Shopify) add('Shopify', 'Ecommerce', null, 'window.Shopify');
    if (w.wp) add('WordPress', 'CMS', null, 'window.wp');
    if (w.Webflow) add('Webflow', 'Website builder', null, 'window.Webflow');
    if (w.dataLayer) add('Google Tag Manager', 'Tag manager', null, 'window.dataLayer');
    if (w.gtag || w.ga) add('Google Analytics', 'Analytics', null, w.gtag ? 'window.gtag' : 'window.ga');
    if (w.fbq) add('Meta Pixel', 'Analytics', null, 'window.fbq');
    if (w.hj) add('Hotjar', 'Analytics', null, 'window.hj');
    if (w.clarity) add('Microsoft Clarity', 'Analytics', null, 'window.clarity');
    if (w.posthog) add('PostHog', 'Analytics', null, 'window.posthog');
    if (w.mixpanel) add('Mixpanel', 'Analytics', null, 'window.mixpanel');
    if (w.amplitude) add('Amplitude', 'Analytics', null, 'window.amplitude');
    if (w.analytics && w.analytics.track) add('Segment', 'Analytics', w.analytics.VERSION, 'window.analytics');
    if (w.plausible) add('Plausible', 'Analytics', null, 'window.plausible');
    if (w.__SENTRY__ || w.Sentry) add('Sentry', 'Error tracking', w.Sentry && w.Sentry.SDK_VERSION, 'window.__SENTRY__');
    if (w.DD_RUM) add('Datadog RUM', 'Monitoring', null, 'window.DD_RUM');
    if (w.newrelic || w.NREUM) add('New Relic', 'Monitoring', null, 'window.NREUM');
    if (w.Stripe) add('Stripe', 'Payments', null, 'window.Stripe');
    if (w.paypal) add('PayPal', 'Payments', null, 'window.paypal');
    if (w.Intercom) add('Intercom', 'Live chat', null, 'window.Intercom');
    if (w.$crisp) add('Crisp', 'Live chat', null, 'window.$crisp');
    if (w.zE) add('Zendesk', 'Live chat', null, 'window.zE');
    if (w.HubSpotConversations || w._hsq) add('HubSpot', 'Marketing', null, 'window._hsq');
    if (w.grecaptcha) add('Google reCAPTCHA', 'Security', null, 'window.grecaptcha');
    if (w.turnstile) add('Cloudflare Turnstile', 'Security', null, 'window.turnstile');
    if (w.OneTrust || w.Optanon) add('OneTrust', 'Cookie consent', null, 'window.OneTrust');
    if (w.Cookiebot) add('Cookiebot', 'Cookie consent', null, 'window.Cookiebot');
    if (w.algoliasearch || w.docsearch) add('Algolia', 'Search', null, 'window.algoliasearch');
    if (w.mapboxgl) add('Mapbox', 'Maps', w.mapboxgl.version, 'window.mapboxgl');
    if (w.google && w.google.maps) add('Google Maps', 'Maps', w.google.maps.version, 'window.google.maps');
    if (w.workbox || (navigator.serviceWorker && navigator.serviceWorker.controller)) add('Service worker', 'Platform', null, 'active service worker');
  } catch (e) {}
  return out;
}
"""

MOBILE_CHECKS = """
() => {
  const small = [...document.querySelectorAll('a, button, input, select, [role="button"]')].filter(el => {
    const r = el.getBoundingClientRect(); return r.width > 0 && r.height > 0 && (r.width < 24 || r.height < 24) && r.top < innerHeight * 3;
  }).length;
  const bodyFont = parseFloat(getComputedStyle(document.body).fontSize);
  return { horizontal_overflow: document.documentElement.scrollWidth > innerWidth + 1, page_width: document.documentElement.scrollWidth,
           viewport_width: innerWidth, small_tap_targets: small, body_font_px: bodyFont };
}
"""


def _is_browser_noise(text: str) -> bool:
    """Messages caused by headless Chromium itself rather than the site."""
    return any(s in text for s in ("GL Driver Message", "GPU stall", "WebGL", "Automatic fallback to software WebGL"))


def _jpeg(data: bytes) -> str:
    return "data:image/jpeg;base64," + base64.b64encode(data).decode()


def _rate(value, good, poor):
    if value is None:
        return None
    return "good" if value <= good else "poor" if value > poor else "needs-improvement"


def _guard_routes(context, is_public):
    """Aborts any request (including ones made by page scripts) to a private
    address, so a hostile page can't make the server's browser probe its network."""
    def handle(route):
        u = urlparse(route.request.url)
        if u.scheme in ("http", "https") and not is_public(u.hostname or ""):
            return route.abort("blockedbyclient")
        return route.continue_()
    context.route("**/*", handle)


def _settle(page):
    try:
        page.wait_for_load_state("networkidle", timeout=6000)
    except PlaywrightTimeout:
        pass


def _await_lcp(page, timeout_ms=12000):
    """Waits until Largest Contentful Paint has stopped changing for 2 s. Animated or late-loading
    hero content can be painted well after the load event, and reading earlier misses it."""
    try:
        page.wait_for_function("() => window.__ss && window.__ss.lcp !== null && performance.now() - window.__ss.lcpAt > 2000",
                               timeout=timeout_ms, polling=250)
    except PlaywrightTimeout:
        pass


def _element_shot(page, selectors):
    for sel in selectors:
        loc = page.locator(sel).first
        try:
            if loc.count() == 0 or not loc.is_visible():
                continue
            box = loc.bounding_box()
            if not box or box["height"] < 20 or box["height"] > 1600 or box["width"] < 200:
                continue
            return {"selector": sel, "width": round(box["width"]), "height": round(box["height"]),
                    "image": _jpeg(loc.screenshot(type="jpeg", quality=70, timeout=4000))}
        except PlaywrightError:
            continue
    return None


def _run_axe(page) -> dict:
    """Runs axe-core's WCAG 2.x A/AA and best-practice rules on the loaded page."""
    global _axe_source
    if not AXE_JS:
        return {"error": "axe-core isn't installed (pip install axe-playwright-python)."}
    try:
        if _axe_source is None:
            with open(AXE_JS, encoding="utf-8") as f:
                _axe_source = f.read() + "\n;true"
        # Evaluated through DevTools rather than injected as a <script>, so the page's
        # Content-Security-Policy doesn't block it and the page itself runs unmodified.
        page.evaluate(_axe_source)
        return page.evaluate(RUN_AXE, AXE_TAGS)
    except PlaywrightError as e:
        return {"error": f"axe-core couldn't run on this page: {str(e).splitlines()[0][:160]}"}


def _rate_all(v: dict) -> dict:
    return {
        "fcp": _rate(v.get("fcp"), 1800, 3000),
        "lcp": _rate(v.get("lcp"), 2500, 4000),
        "cls": _rate(v.get("cls"), 0.1, 0.25),
        "tbt": _rate(v.get("tbt"), 200, 600),
        "ttfb": _rate(v.get("ttfb"), 800, 1800),
    }


def _perf_run(browser, url, is_public, capture_mobile: bool) -> dict:
    """One cold, throttled mobile load. Returns its vitals (and, if asked, the mobile
    screenshot and layout checks, which don't depend on throttling)."""
    ctx = browser.new_context(viewport=PERF_VIEWPORT, user_agent=MOBILE_UA, is_mobile=True, has_touch=True,
                              device_scale_factor=1.75, service_workers="block")
    try:
        _guard_routes(ctx, is_public)
        ctx.add_init_script(VITALS_INIT)
        page = ctx.new_page()
        cdp = ctx.new_cdp_session(page)
        cdp.send("Network.enable")
        cdp.send("Network.setCacheDisabled", {"cacheDisabled": True})
        cdp.send("Network.emulateNetworkConditions", {"offline": False, "latency": THROTTLE["latency_ms"],
                                                      "downloadThroughput": THROTTLE["down_bps"], "uploadThroughput": THROTTLE["up_bps"]})
        cdp.send("Emulation.setCPUThrottlingRate", {"rate": THROTTLE["cpu"]})
        t0 = time.perf_counter()
        page.goto(url, wait_until="load", timeout=THROTTLED_NAV_TIMEOUT_MS)
        try:
            page.wait_for_load_state("networkidle", timeout=8000)
        except PlaywrightTimeout:
            pass
        _await_lcp(page)
        out = {"vitals": page.evaluate(COLLECT_VITALS), "wall_ms": round((time.perf_counter() - t0) * 1000)}
        if capture_mobile:
            cdp.send("Emulation.setCPUThrottlingRate", {"rate": 1})
            try:
                out["mobile"] = page.evaluate(MOBILE_CHECKS)
                out["mobile"]["screenshot"] = _jpeg(page.screenshot(type="jpeg", quality=72))
            except PlaywrightError as e:
                out["mobile"] = {"error": str(e).splitlines()[0][:200]}
        return out
    except PlaywrightTimeout:
        return {"error": f"Didn't finish loading within {THROTTLED_NAV_TIMEOUT_MS // 1000} s on a throttled connection."}
    except PlaywrightError as e:
        return {"error": str(e).splitlines()[0][:200]}
    finally:
        ctx.close()


METRICS = ("ttfb", "fcp", "lcp", "cls", "tbt", "load", "dom_content_loaded")


def _median_vitals(runs: list[dict]) -> dict | None:
    ok = [r["vitals"] for r in runs if "vitals" in r]
    if not ok:
        return None
    out = {}
    for k in METRICS:
        vals = [v[k] for v in ok if v.get(k) is not None]
        out[k] = statistics.median(vals) if vals else None
        out[f"{k}_range"] = [min(vals), max(vals)] if len(vals) > 1 else None
    # Report the LCP element and counts from the run closest to the median LCP.
    closest = min(ok, key=lambda v: abs((v.get("lcp") or 0) - (out["lcp"] or 0)))
    out |= {k: closest.get(k) for k in ("lcp_element", "long_tasks", "transfer_bytes", "dom_nodes", "js_heap")}
    out["runs"] = len(ok)
    out["ratings"] = _rate_all(out)
    return out


def analyze_rendered(url: str, is_public, perf_runs: int = DEFAULT_PERF_RUNS) -> dict:
    if not AVAILABLE:
        return {"available": False, "error": "Playwright is not installed."}
    t0 = time.perf_counter()
    console, page_errors, failed, requests_seen = [], [], [], []
    perf = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--disable-dev-shm-usage"])
            try:
                ctx = browser.new_context(viewport={"width": 1366, "height": 860}, user_agent=USER_AGENT,
                                          ignore_https_errors=False, service_workers="block")
                _guard_routes(ctx, is_public)
                ctx.add_init_script(VITALS_INIT)
                page = ctx.new_page()
                page.on("console", lambda m: m.type in ("error", "warning") and len(console) < 40
                        and not _is_browser_noise(m.text) and console.append({"type": m.type, "text": m.text[:300]}))
                page.on("pageerror", lambda e: len(page_errors) < 20 and page_errors.append(str(e)[:300]))
                # ERR_ABORTED is a request the page itself cancelled (beacons, prefetches), not a failure.
                page.on("requestfailed", lambda r: len(failed) < 40 and "ERR_ABORTED" not in (r.failure or "")
                        and failed.append({"url": r.url[:200], "error": (r.failure or "")[:80], "type": r.resource_type}))
                page.on("response", lambda r: requests_seen.append(
                    {"url": r.url, "status": r.status, "type": r.request.resource_type}))

                resp = page.goto(url, wait_until="load", timeout=NAV_TIMEOUT_MS)
                _settle(page)
                _await_lcp(page, timeout_ms=8000)

                vitals = page.evaluate(COLLECT_VITALS)
                above_fold = _jpeg(page.screenshot(type="jpeg", quality=72))
                globals_found = page.evaluate(COLLECT_GLOBALS)
                styles = page.evaluate(COLLECT_STYLES)
                contrast = page.evaluate(COLLECT_CONTRAST)
                components = {
                    "header": _element_shot(page, ["header", "[role=banner]", "nav"]),
                    "footer": _element_shot(page, ["footer", "[role=contentinfo]"]),
                    "form": _element_shot(page, ["form"]),
                }
                axe = _run_axe(page)
                # Scroll through once so lazy images load before the full-page capture.
                height = page.evaluate("document.documentElement.scrollHeight")
                for y in range(0, min(height, MAX_FULLPAGE_HEIGHT), 700):
                    page.evaluate(f"window.scrollTo(0, {y})")
                    page.wait_for_timeout(120)
                page.evaluate("window.scrollTo(0, 0)")
                page.wait_for_timeout(300)
                full_h = min(page.evaluate("document.documentElement.scrollHeight"), MAX_FULLPAGE_HEIGHT)
                full_page = _jpeg(page.screenshot(type="jpeg", quality=55, full_page=True,
                                                  clip={"x": 0, "y": 0, "width": 1366, "height": full_h}))
                rendered_html = page.content()
                final_url = page.url
                status = resp.status if resp else None
                ctx.close()

                # Throttled mobile runs, one after another so they don't compete for CPU.
                for i in range(max(1, perf_runs)):
                    perf.append(_perf_run(browser, final_url, is_public, capture_mobile=(i == 0)))
                    if i == 0 and "error" in perf[0] and "Didn't finish" in perf[0]["error"]:
                        break   # a page that can't load once won't load on the next tries either
                mobile = perf[0].pop("mobile", None) or {"error": perf[0].get("error", "Mobile view not captured.")}
            finally:
                browser.close()
    except PlaywrightTimeout:
        return {"available": False, "error": "The page took too long to load in the browser."}
    except PlaywrightError as e:
        msg = str(e).splitlines()[0][:240]
        if "Executable doesn't exist" in msg:
            msg = "Chromium isn't installed. Run: python -m playwright install chromium"
        return {"available": False, "error": msg}

    by_type = {}
    for r in requests_seen:
        by_type[r["type"]] = by_type.get(r["type"], 0) + 1
    vitals["ratings"] = _rate_all(vitals)
    mobile_vitals = _median_vitals(perf)
    return {
        "available": True,
        "final_url": final_url,
        "status": status,
        # Throttled mobile median when it worked; otherwise the single unthrottled desktop load.
        "vitals": mobile_vitals or vitals,
        "vitals_method": "mobile-throttled" if mobile_vitals else "desktop-unthrottled",
        "vitals_desktop": vitals,
        "vitals_runs": [{"wall_ms": r.get("wall_ms"), "error": r.get("error"),
                         **({k: r["vitals"].get(k) for k in METRICS} if "vitals" in r else {})} for r in perf],
        "throttle": THROTTLE | {"viewport": PERF_VIEWPORT},
        "axe": axe,
        "screenshots": {"above_fold": above_fold, "full_page": full_page, "full_page_height": full_h,
                        "page_height": height, "mobile": mobile.pop("screenshot", None)},
        "mobile": mobile,
        "components": {k: v for k, v in components.items() if v},
        "computed_styles": styles,
        "contrast": contrast,
        "js_technologies": globals_found,
        "console": console,
        "page_errors": page_errors,
        "failed_requests": [f for f in failed if "blockedbyclient" not in f["error"].lower()],
        "blocked_private_requests": sum(1 for f in failed if "blockedbyclient" in f["error"].lower()),
        "requests_by_type": by_type,
        "request_count": len(requests_seen),
        "http_errors": [r for r in requests_seen if r["status"] >= 400][:30],
        "rendered_html": rendered_html,
        "browser_ms": round((time.perf_counter() - t0) * 1000),
    }
