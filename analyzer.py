"""Fetches a public web page and reports how it is built.

Everything here works from the raw HTTP responses (HTML, headers, CSS, TLS),
so it needs no headless browser. Each section of the report is produced by
its own function and the results are assembled in `analyze()`.
"""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import ssl
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import os
from urllib.parse import urljoin, urlparse

import certifi
import requests
from bs4 import BeautifulSoup

import browser
import vulns
from signatures import SIGNATURES

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0 Safari/537.36 DeconstructSite/1.0"
)
TIMEOUT = 12
MAX_HTML_BYTES = 6 * 1024 * 1024
MAX_CSS_BYTES = 2 * 1024 * 1024
MAX_STYLESHEETS = 10
MAX_RESOURCE_PROBES = 60
MAX_REDIRECTS = 6


class AnalysisError(Exception):
    pass


# ---------------------------------------------------------------- fetching

_host_ok_cache: dict[str, bool | None] = {}


def _host_is_public(host: str) -> bool | None:
    """Refuses hosts that resolve to private, loopback or link-local addresses,
    so the analyzer can't be used to probe the server's own network.
    Returns None when the name doesn't resolve at all."""
    if host in _host_ok_cache:
        return _host_ok_cache[host]
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return None
    ok = bool(infos)
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if not ip.is_global:
            ok = False
    _host_ok_cache[host] = ok
    return ok


def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    p = urlparse(raw)
    if not p.hostname or "." not in p.hostname:
        raise AnalysisError("That doesn't look like a valid website address.")
    return raw


def safe_get(session: requests.Session, url: str, *, method="GET", max_bytes=MAX_HTML_BYTES,
             timeout=TIMEOUT):
    """GET with manual redirect handling so every hop is checked against
    `_host_is_public`. Returns (response, body_bytes, redirect_chain)."""
    chain = []
    for _ in range(MAX_REDIRECTS + 1):
        host = urlparse(url).hostname or ""
        public = _host_is_public(host)
        if public is None:
            raise AnalysisError(f"Couldn't find {host}. Check the spelling.")
        if not public:
            raise AnalysisError(f"{host} is not a public address.")
        resp = session.request(method, url, allow_redirects=False, stream=True, timeout=timeout)
        if resp.is_redirect or resp.is_permanent_redirect:
            nxt = urljoin(url, resp.headers.get("location", ""))
            chain.append({"url": url, "status": resp.status_code})
            resp.close()
            url = nxt
            continue
        body = b""
        if method == "GET":
            for chunk in resp.iter_content(64 * 1024):
                body += chunk
                if len(body) > max_bytes:
                    break
        resp.close()
        return resp, body, chain
    raise AnalysisError("Too many redirects.")


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
    })
    return s


# ---------------------------------------------------------------- helpers

def _text(el) -> str:
    return re.sub(r"\s+", " ", el.get_text(" ", strip=True)) if el else ""


def _meta(soup, *, name=None, prop=None):
    el = soup.find("meta", attrs={"name": name}) if name else soup.find("meta", attrs={"property": prop})
    return el.get("content", "").strip() if el else None


def _abs(base, href):
    return urljoin(base, href) if href else None


def _set_cookie_headers(resp) -> list[str]:
    try:
        return resp.raw.headers.getlist("Set-Cookie")
    except Exception:
        val = resp.headers.get("set-cookie")
        return [val] if val else []


def _human_bytes(n):
    if n is None:
        return None
    for unit in ("B", "KB", "MB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


# ---------------------------------------------------------------- sections

def overview(url, final_url, resp, html_bytes, chain, elapsed_ms, soup):
    host = urlparse(final_url).hostname
    try:
        ips = sorted({i[4][0] for i in socket.getaddrinfo(host, 443)})
    except socket.gaierror:
        ips = []
    icon = soup.find("link", rel=lambda v: v and "icon" in v)
    return {
        "requested_url": url,
        "final_url": final_url,
        "status": resp.status_code,
        "redirects": chain,
        "host": host,
        "ip_addresses": ips,
        "server": resp.headers.get("server"),
        "http_version": {10: "HTTP/1.0", 11: "HTTP/1.1"}.get(getattr(resp.raw, "version", 0), "unknown"),
        "content_type": resp.headers.get("content-type"),
        "title": _text(soup.title),
        "description": _meta(soup, name="description"),
        "language": (soup.html.get("lang") if soup.html else None),
        "favicon": _abs(final_url, icon.get("href")) if icon else urljoin(final_url, "/favicon.ico"),
        "og_image": _abs(final_url, _meta(soup, prop="og:image")),
        "response_ms": elapsed_ms,
        "html_size": len(html_bytes),
    }


def detect_technologies(resp, html: str, soup, cookies: list[str]):
    headers = "\n".join(f"{k.lower()}: {v}" for k, v in resp.headers.items())
    scripts = "\n".join(s.get("src", "") for s in soup.find_all("script") if s.get("src"))
    links = "\n".join(l.get("href", "") for l in soup.find_all("link") if l.get("href"))
    generator = _meta(soup, name="generator") or ""
    cookie_names = "\n".join(c.split("=", 1)[0].strip() for c in cookies)
    sources = {"header": headers, "html": html, "script": scripts, "link": links,
               "generator": generator, "cookie": cookie_names}

    found = {}
    for sig in SIGNATURES:
        evidence = []
        for source, pattern in sig["match"]:
            m = re.search(pattern, sources[source], re.I | re.M)
            if m:
                snippet = m.group(0)
                evidence.append(f"{source}: {snippet[:90]}")
        if evidence:
            version = None
            if sig.get("version"):
                source, pattern = sig["version"]
                vm = re.search(pattern, sources[source], re.I)
                version = vm.group(1) if vm else None
            found[sig["name"]] = {"name": sig["name"], "category": sig["category"],
                                  "version": version, "evidence": evidence[:3]}

    # Tailwind leaves no file signature; it shows up as utility class names.
    classes = Counter()
    for el in soup.find_all(class_=True):
        classes.update(el.get("class", []))
    tw = sum(n for c, n in classes.items() if re.fullmatch(
        r"(?:[a-z]+:)*-?(?:p|m|px|py|mx|my|pt|pb|pl|pr|mt|mb|ml|mr|gap|w|h|text|bg|rounded|"
        r"border|flex|grid|items|justify|font|leading|tracking|space-[xy]|shadow|max-w|min-h)"
        r"(?:-[\w./\[\]#%]+)?", c))
    if tw > 40 and "Tailwind CSS" not in found:
        found["Tailwind CSS"] = {"name": "Tailwind CSS", "category": "CSS framework", "version": None,
                                 "evidence": [f"html: {tw} utility-class usages"]}

    by_cat: dict[str, list] = {}
    for t in found.values():
        by_cat.setdefault(t["category"], []).append(t)
    return {"count": len(found), "by_category": by_cat}


_COLOR_RE = re.compile(
    r"#(?:[0-9a-fA-F]{8}|[0-9a-fA-F]{6}|[0-9a-fA-F]{3,4})\b"
    r"|rgba?\([^)]*\)|hsla?\([^)]*\)|oklch\([^)]*\)", re.I)
_DECL_RE = re.compile(r"([\w-]+)\s*:\s*([^;{}]+)")


def _norm_color(c: str) -> str | None:
    c = c.strip().lower()
    if c.startswith("#"):
        h = c[1:]
        if len(h) in (3, 4):
            h = "".join(ch * 2 for ch in h)
        if len(h) == 8 and h.endswith("ff"):
            h = h[:6]
        return "#" + h
    m = re.match(r"rgba?\(\s*(\d{1,3})[\s,]+(\d{1,3})[\s,]+(\d{1,3})(?:\s*[,/]\s*([\d.]+)(%?))?\s*\)", c)
    if m:
        r, g, b = (min(255, int(x)) for x in m.group(1, 2, 3))
        hexv = f"#{r:02x}{g:02x}{b:02x}"
        if m.group(4) is not None:
            a = float(m.group(4)) / (100 if m.group(5) else 1)
            if a < 1:
                return hexv + f"{round(a * 255):02x}"
        return hexv
    if "var(" in c:
        return None
    return re.sub(r"\s+", " ", c)


def design_system(css_text: str, soup):
    by_role = {"text": Counter(), "background": Counter(), "border": Counter(), "other": Counter()}
    all_colors = Counter()
    fonts, sizes, weights, radii, spacing, shadows, durations, line_heights = (
        Counter(), Counter(), Counter(), Counter(), Counter(), Counter(), Counter(), Counter())
    variables = {}
    raw_fonts = []
    z_max = 0

    for prop, value in _DECL_RE.findall(css_text):
        prop = prop.lower()
        value = value.strip().replace("!important", "").strip()
        if prop.startswith("--"):
            variables.setdefault(prop, value[:200])
        for c in _COLOR_RE.findall(value):
            nc = _norm_color(c)
            if not nc:
                continue
            all_colors[nc] += 1
            if prop == "color":
                by_role["text"][nc] += 1
            elif prop.startswith("background"):
                by_role["background"][nc] += 1
            elif prop.startswith("border") or prop.startswith("outline"):
                by_role["border"][nc] += 1
            else:
                by_role["other"][nc] += 1
        if prop in ("font-family", "font") or (prop.startswith("--") and re.search(r"font-?family|fontstack", prop)):
            raw_fonts.append(value)
        elif prop == "font-size":
            sizes[value] += 1
        elif prop == "font-weight":
            weights[value] += 1
        elif prop == "line-height":
            line_heights[value] += 1
        elif prop == "border-radius":
            radii[value] += 1
        elif prop in ("margin", "padding", "gap", "row-gap", "column-gap") or prop.startswith(("margin-", "padding-")):
            for part in value.split():
                if re.fullmatch(r"-?[\d.]+(px|rem|em)", part):
                    spacing[part.lstrip("-")] += 1
        elif prop == "box-shadow" and value != "none":
            shadows[value[:100]] += 1
        elif prop in ("transition", "transition-duration", "animation", "animation-duration"):
            for d in re.findall(r"\b\d*\.?\d+m?s\b", value):
                durations[d] += 1
        elif prop == "z-index" and re.fullmatch(r"-?\d+", value):
            z_max = max(z_max, int(value))

    def resolve(v, depth=0):
        if depth > 5:
            return v
        return re.sub(r"var\(\s*(--[\w-]+)\s*(?:,\s*([^()]*))?\)",
                      lambda m: resolve(variables.get(m.group(1), m.group(2) or ""), depth + 1), v)

    generic = {"inherit", "initial", "unset", "revert", "sans-serif", "serif", "monospace", "system-ui",
               "cursive", "fantasy", "ui-sans-serif", "ui-serif", "ui-monospace", "-apple-system",
               "blinkmacsystemfont", "emoji", "math", "var"}
    for v in raw_fonts:
        v = resolve(v)
        # `font` shorthand: family list follows the size, e.g. "600 14px/1.4 Inter, sans-serif"
        v = re.sub(r"^.*?\d(?:px|rem|em|%)(?:/[\d.]+\w*)?\s+", "", v)
        first = next((f.strip().strip("'\"") for f in v.split(",")
                      if f.strip().strip("'\"") and f.strip().strip("'\"").lower() not in generic), None)
        if first and not re.search(r"[(){}]|^\d", first):
            fonts[first] += 1

    font_faces = sorted(set(m.strip("'\" ") for m in re.findall(
        r"@font-face\s*{[^}]*?font-family\s*:\s*([^;}]+)", css_text, re.I)))
    breakpoints = Counter(f"{n}{u}" for n, u in re.findall(
        r"@media[^{]*?(?:min|max)-width\s*:\s*([\d.]+)(px|em|rem)", css_text, re.I))
    keyframes = sorted(set(re.findall(r"@keyframes\s+([\w-]+)", css_text)))
    google_fonts = [l.get("href") for l in soup.find_all("link", href=True) if "fonts.googleapis.com" in l["href"]]

    def top(counter, n):
        return [{"value": k, "count": v} for k, v in counter.most_common(n)]

    def px_sort(items):
        def key(i):
            m = re.match(r"([\d.]+)(px|rem|em)?", i["value"])
            if not m:
                return 1e9
            n = float(m.group(1))
            return n * 16 if m.group(2) in ("rem", "em") else n
        return sorted(items, key=key)

    return {
        "colors": top(all_colors, 32),
        "color_roles": {role: top(c, 10) for role, c in by_role.items()},
        "theme_color": _meta(soup, name="theme-color"),
        "fonts": top(fonts, 12),
        "font_faces": font_faces[:30],
        "google_fonts": google_fonts,
        "type_scale": px_sort(top(sizes, 18)),
        "font_weights": top(weights, 10),
        "line_heights": top(line_heights, 8),
        "spacing_scale": px_sort(top(spacing, 18)),
        "radii": top(radii, 10),
        "shadows": top(shadows, 6),
        "breakpoints": px_sort(top(breakpoints, 12)),
        "motion": {"durations": top(durations, 8), "keyframes": keyframes[:30]},
        "max_z_index": z_max,
        "css_variables": dict(list(variables.items())[:120]),
        "css_variable_count": len(variables),
        "css_bytes_analyzed": len(css_text),
    }


def structure(soup, final_url):
    host = urlparse(final_url).hostname
    outline = [{"level": int(h.name[1]), "text": _text(h)[:120]}
               for h in soup.find_all(re.compile(r"^h[1-6]$"))][:60]
    internal, external = [], []
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        absu = urljoin(final_url, href)
        (internal if urlparse(absu).hostname == host else external).append(
            {"text": _text(a)[:60], "href": absu})
    social_hosts = ("twitter.com", "x.com", "github.com", "linkedin.com", "instagram.com",
                    "facebook.com", "youtube.com", "tiktok.com", "discord.gg", "discord.com", "threads.net")
    social = sorted({l["href"] for l in external if any(
        urlparse(l["href"]).hostname and urlparse(l["href"]).hostname.endswith(h) for h in social_hosts)})
    forms = []
    for f in soup.find_all("form")[:10]:
        fields = [{"type": i.get("type", i.name), "name": i.get("name")}
                  for i in f.find_all(["input", "select", "textarea"]) if i.get("type") != "hidden"]
        forms.append({"action": _abs(final_url, f.get("action")) or final_url,
                      "method": (f.get("method") or "get").upper(), "fields": fields})
    nav = soup.find("nav")
    tags = Counter(el.name for el in soup.find_all(True))
    body_text = _text(soup.body) if soup.body else ""
    words = len(body_text.split())
    return {
        "outline": outline,
        "landmarks": {tag: tags.get(tag, 0) for tag in ("header", "nav", "main", "section", "article", "aside", "footer")},
        "navigation": [{"text": _text(a)[:40], "href": urljoin(final_url, a["href"])}
                       for a in (nav.find_all("a", href=True) if nav else [])][:30],
        "internal_links": len(internal),
        "external_links": len(external),
        "external_domains": Counter(urlparse(l["href"]).hostname for l in external).most_common(15),
        "social_profiles": social,
        "contact": sorted({a["href"] for a in soup.find_all("a", href=True)
                           if a["href"].startswith(("mailto:", "tel:"))})[:10],
        "forms": forms,
        "iframes": [_abs(final_url, i.get("src")) for i in soup.find_all("iframe") if i.get("src")][:10],
        "element_count": sum(tags.values()),
        "top_elements": tags.most_common(12),
        "word_count": words,
        "reading_time_min": max(1, round(words / 230)) if words else 0,
    }


def collect_resources(soup, final_url):
    res = []
    head = soup.head
    for s in soup.find_all("script", src=True):
        blocking = bool(head and s in head.find_all("script")) and not (
            s.has_attr("async") or s.has_attr("defer") or s.get("type") == "module")
        res.append({"type": "script", "url": urljoin(final_url, s["src"]), "render_blocking": blocking,
                    "attrs": [a for a in ("async", "defer") if s.has_attr(a)] + (["module"] if s.get("type") == "module" else [])})
    for l in soup.find_all("link", href=True):
        rel = " ".join(l.get("rel", [])).lower()
        if "stylesheet" in rel:
            res.append({"type": "stylesheet", "url": urljoin(final_url, l["href"]),
                        "render_blocking": l.get("media") in (None, "all", "screen")})
        elif "preload" in rel or "modulepreload" in rel:
            res.append({"type": f"preload:{l.get('as', 'module' if 'modulepreload' in rel else '?')}",
                        "url": urljoin(final_url, l["href"]), "render_blocking": False})
    for img in soup.find_all("img"):
        src = img.get("src") or img.get("data-src")
        if src and not src.startswith("data:"):
            res.append({"type": "image", "url": urljoin(final_url, src), "render_blocking": False,
                        "lazy": img.get("loading") == "lazy",
                        "has_dimensions": bool(img.get("width") and img.get("height"))})
    for v in soup.find_all(["video", "source", "audio"], src=True):
        res.append({"type": "media", "url": urljoin(final_url, v["src"]), "render_blocking": False})
    seen, out = set(), []
    for r in res:
        if r["url"] not in seen and r["url"].startswith("http"):
            seen.add(r["url"])
            out.append(r)
    return out


def probe_resources(session, resources):
    """Fetches headers for each resource to learn its size, type and caching."""
    def probe(r):
        try:
            host = urlparse(r["url"]).hostname or ""
            if not _host_is_public(host):
                return r
            t0 = time.perf_counter()
            resp = session.head(r["url"], allow_redirects=True, timeout=5)
            if resp.status_code >= 400 or "content-length" not in resp.headers:
                resp = session.get(r["url"], stream=True, timeout=5)
                size = int(resp.headers["content-length"]) if "content-length" in resp.headers else None
                resp.close()
            else:
                size = int(resp.headers["content-length"])
            r.update({
                "status": resp.status_code,
                "size": size,
                "ms": round((time.perf_counter() - t0) * 1000),
                "mime": (resp.headers.get("content-type") or "").split(";")[0],
                "encoding": resp.headers.get("content-encoding"),
                "cache": resp.headers.get("cache-control"),
            })
        except requests.RequestException:
            r["status"] = "error"
        return r

    with ThreadPoolExecutor(max_workers=16) as pool:
        return list(pool.map(probe, resources[:MAX_RESOURCE_PROBES])) + resources[MAX_RESOURCE_PROBES:]


def fetch_css(session, soup, final_url):
    parts = [s.get_text() for s in soup.find_all("style")]
    parts += [el["style"] for el in soup.find_all(style=True)][:2000]
    hrefs = [urljoin(final_url, l["href"]) for l in soup.find_all("link", href=True)
             if "stylesheet" in [r.lower() for r in l.get("rel", [])]][:MAX_STYLESHEETS]

    def get(u):
        try:
            _, body, _ = safe_get(session, u, max_bytes=MAX_CSS_BYTES, timeout=10)
            return body.decode("utf-8", "replace")
        except (requests.RequestException, AnalysisError):
            return ""

    with ThreadPoolExecutor(max_workers=6) as pool:
        parts += list(pool.map(get, hrefs))
    return "\n".join(parts)


def performance(resp, html_bytes, elapsed_ms, resources, soup):
    sized = [r for r in resources if isinstance(r.get("size"), int)]
    by_type = Counter()
    bytes_by_type = Counter()
    for r in resources:
        t = r["type"].split(":")[0]
        by_type[t] += 1
        if isinstance(r.get("size"), int):
            bytes_by_type[t] += r["size"]
    total = len(html_bytes) + sum(r["size"] for r in sized)
    blocking = [r["url"] for r in resources if r.get("render_blocking")]
    imgs = [r for r in resources if r["type"] == "image"]
    third_party_hosts = Counter(urlparse(r["url"]).hostname for r in resources
                                if urlparse(r["url"]).hostname != urlparse(resp.url).hostname)
    inline_js = sum(len(s.get_text()) for s in soup.find_all("script") if not s.get("src"))

    issues = []
    if elapsed_ms > 800:
        issues.append(f"Slow server response ({elapsed_ms} ms). Aim for under 600 ms.")
    if not resp.headers.get("content-encoding"):
        issues.append("HTML is sent uncompressed. Enable gzip or Brotli.")
    if len(blocking) > 3:
        issues.append(f"{len(blocking)} render-blocking scripts/stylesheets in <head>.")
    if len(html_bytes) > 200_000:
        issues.append(f"Large HTML document ({_human_bytes(len(html_bytes))}).")
    big = [r for r in sized if r["size"] > 300_000]
    for r in big[:5]:
        issues.append(f"Heavy {r['type']} ({_human_bytes(r['size'])}): {r['url'][:90]}")
    no_lazy = [r for r in imgs if not r.get("lazy")]
    if len(imgs) > 6 and len(no_lazy) > len(imgs) * 0.7:
        issues.append(f"{len(no_lazy)} of {len(imgs)} images don't use loading=\"lazy\".")
    no_dim = [r for r in imgs if not r.get("has_dimensions")]
    if no_dim:
        issues.append(f"{len(no_dim)} images have no width/height (risk of layout shift).")
    uncompressed = [r for r in sized if r["type"] in ("script", "stylesheet") and not r.get("encoding") and r["size"] > 20_000]
    if uncompressed:
        issues.append(f"{len(uncompressed)} scripts/stylesheets are served without compression.")
    if inline_js > 100_000:
        issues.append(f"{_human_bytes(inline_js)} of inline JavaScript in the HTML.")

    return {
        "server_response_ms": elapsed_ms,
        "html_size": len(html_bytes),
        "html_compression": resp.headers.get("content-encoding"),
        "html_cache_control": resp.headers.get("cache-control"),
        "request_count": len(resources) + 1,
        "total_known_bytes": total,
        "requests_by_type": dict(by_type),
        "bytes_by_type": dict(bytes_by_type),
        "render_blocking": blocking,
        "third_party_hosts": third_party_hosts.most_common(20),
        "inline_script_bytes": inline_js,
        "issues": issues,
        "resources": sorted(resources, key=lambda r: -(r.get("size") or 0)),
    }


SECURITY_HEADERS = {
    "strict-transport-security": "Forces browsers to always use HTTPS.",
    "content-security-policy": "Restricts where scripts, styles and other content can load from (blocks XSS).",
    "x-content-type-options": "Stops browsers guessing file types (should be 'nosniff').",
    "x-frame-options": "Prevents the page being embedded in other sites (clickjacking).",
    "referrer-policy": "Controls how much of the URL is sent to other sites.",
    "permissions-policy": "Limits access to camera, microphone, location and other features.",
    "cross-origin-opener-policy": "Isolates the page from cross-origin windows.",
}


def _handshake(host):
    ctx = ssl.create_default_context(cafile=certifi.where())
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    with socket.create_connection((host, 443), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as s:
            return s.getpeercert(), s.version(), s.selected_alpn_protocol()


def tls_info(host):
    """Certificate and protocol details. `valid` is None when the check
    couldn't complete (timeout), False when the certificate is rejected."""
    try:
        try:
            cert, proto, alpn = _handshake(host)
        except (TimeoutError, socket.timeout):
            cert, proto, alpn = _handshake(host)
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        subject = dict(x[0] for x in cert.get("subject", ()))
        sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
        return {
            "valid": True,
            "protocol": proto,
            "alpn": alpn,
            "issuer": issuer.get("organizationName") or issuer.get("commonName"),
            "subject": subject.get("commonName"),
            "expires": not_after.date().isoformat(),
            "days_left": (not_after - datetime.now(timezone.utc)).days,
            "san_count": len(sans),
            "san_sample": sans[:8],
        }
    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "error": e.verify_message or str(e)[:160]}
    except (OSError, ssl.SSLError, ValueError, KeyError) as e:
        return {"valid": None, "error": str(e)[:160]}


def security(session, resp, final_url, cookies, soup):
    h = {k.lower(): v for k, v in resp.headers.items()}
    headers = [{"name": n, "present": n in h, "value": h.get(n), "why": why}
               for n, why in SECURITY_HEADERS.items()]
    if "x-frame-options" not in h and "frame-ancestors" in h.get("content-security-policy", ""):
        headers[3]["present"] = True
        headers[3]["value"] = "(covered by CSP frame-ancestors)"

    cookie_report = []
    for c in cookies:
        name = c.split("=", 1)[0].strip()
        low = c.lower()
        cookie_report.append({
            "name": name,
            "secure": "secure" in low,
            "http_only": "httponly" in low,
            "same_site": (re.search(r"samesite=(\w+)", low) or [None, None])[1],
        })

    host = urlparse(final_url).hostname
    https_redirect = None
    if final_url.startswith("https://"):
        try:
            r, _, _ = safe_get(session, f"http://{host}/", max_bytes=1, timeout=6)
            https_redirect = r.url.startswith("https://")
        except (requests.RequestException, AnalysisError):
            https_redirect = None

    mixed = []
    if final_url.startswith("https://"):
        for tag, attr in (("script", "src"), ("img", "src"), ("link", "href"), ("iframe", "src")):
            for el in soup.find_all(tag):
                v = el.get(attr, "")
                if v.startswith("http://"):
                    mixed.append(v)

    leaks = [k for k in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator") if k in h]
    sri_missing = [s["src"] for s in soup.find_all("script", src=True)
                   if urlparse(urljoin(final_url, s["src"])).hostname != host and not s.get("integrity")]

    tls = tls_info(host) if final_url.startswith("https://") else None
    return {
        "https": final_url.startswith("https://"),
        "http_redirects_to_https": https_redirect,
        "tls": tls,
        "alpn": tls.get("alpn") if tls else None,
        "headers": headers,
        "cors": h.get("access-control-allow-origin"),
        "cookies": cookie_report,
        "mixed_content": mixed[:20],
        "version_leaks": [{"header": k, "value": h[k]} for k in leaks],
        "third_party_scripts_without_sri": sri_missing[:20],
    }


def seo(session, soup, final_url, resp):
    origin = f"{urlparse(final_url).scheme}://{urlparse(final_url).netloc}"
    title = _text(soup.title)
    desc = _meta(soup, name="description")
    canonical = soup.find("link", rel="canonical")
    og = {m["property"]: m.get("content", "") for m in soup.find_all("meta", property=re.compile(r"^og:"))}
    tw = {m["name"]: m.get("content", "") for m in soup.find_all("meta", attrs={"name": re.compile(r"^twitter:")})}
    jsonld_types = []
    for s in soup.find_all("script", type="application/ld+json"):
        try:
            data = json.loads(s.get_text())
            items = data if isinstance(data, list) else data.get("@graph", [data])
            jsonld_types += [str(i.get("@type")) for i in items if isinstance(i, dict) and i.get("@type")]
        except (ValueError, AttributeError):
            jsonld_types.append("(invalid JSON-LD)")

    def check_file(path, expect):
        try:
            r, body, _ = safe_get(session, origin + path, max_bytes=200_000, timeout=5)
            ctype = r.headers.get("content-type", "")
            ok = r.status_code == 200 and expect in ctype
            return {"exists": ok, "status": r.status_code, "content_type": ctype,
                    "body": body.decode("utf-8", "replace") if ok else ""}
        except (requests.RequestException, AnalysisError):
            return {"exists": False, "status": None, "content_type": None, "body": ""}

    robots = check_file("/robots.txt", "text/plain")
    sitemaps = re.findall(r"(?im)^sitemap:\s*(\S+)", robots["body"])
    sitemap = check_file("/sitemap.xml", "xml")
    sitemap_urls = len(re.findall(r"<loc>", sitemap["body"]))

    h1s = [_text(h) for h in soup.find_all("h1")]
    imgs = soup.find_all("img")
    missing_alt = [i.get("src", "")[:100] for i in imgs if i.get("alt") is None]

    soft404 = None
    try:
        r404, _, _ = safe_get(session, origin + "/__deconstruct_site_missing_page_check__", max_bytes=1, timeout=6)
        soft404 = r404.status_code == 200
    except (requests.RequestException, AnalysisError):
        pass

    issues = []
    if not title:
        issues.append("Missing <title>.")
    elif not 15 <= len(title) <= 65:
        issues.append(f"Title is {len(title)} characters (aim for 15–65).")
    if not desc:
        issues.append("Missing meta description.")
    elif not 50 <= len(desc) <= 165:
        issues.append(f"Meta description is {len(desc)} characters (aim for 50–165).")
    if len(h1s) != 1:
        issues.append(f"Page has {len(h1s)} <h1> headings (should have exactly 1).")
    if not canonical:
        issues.append("No canonical URL.")
    if not og:
        issues.append("No Open Graph tags — shared links won't show a preview card.")
    if not soup.find("meta", attrs={"name": "viewport"}):
        issues.append("No viewport meta tag (page won't scale on mobile).")
    if not robots["exists"]:
        issues.append(f"robots.txt missing or wrong type ({robots['content_type'] or 'no response'}).")
    if not sitemap["exists"] and not sitemaps:
        issues.append("No sitemap.xml found.")
    if soft404:
        issues.append("Unknown URLs return 200 instead of 404 (soft 404).")
    if missing_alt:
        issues.append(f"{len(missing_alt)} images are missing alt text.")
    noindex = _meta(soup, name="robots") or ""
    if "noindex" in noindex.lower() or "noindex" in resp.headers.get("x-robots-tag", "").lower():
        issues.append("Page is set to noindex — search engines won't list it.")

    return {
        "title": title, "title_length": len(title),
        "description": desc, "description_length": len(desc or ""),
        "canonical": canonical.get("href") if canonical else None,
        "robots_meta": _meta(soup, name="robots"),
        "x_robots_tag": resp.headers.get("x-robots-tag"),
        "h1": h1s,
        "open_graph": og,
        "twitter": tw,
        "structured_data": jsonld_types,
        "hreflang": [l.get("hreflang") for l in soup.find_all("link", hreflang=True)],
        "robots_txt": {"exists": robots["exists"], "status": robots["status"], "sitemaps": sitemaps,
                       "preview": robots["body"][:1500]},
        "sitemap_xml": {"exists": sitemap["exists"], "url_count": sitemap_urls},
        "soft_404": soft404,
        "images_missing_alt": len(missing_alt),
        "issues": issues,
    }


def accessibility(soup):
    issues = []
    lang = soup.html.get("lang") if soup.html else None
    if not lang:
        issues.append("<html> has no lang attribute.")
    imgs = soup.find_all("img")
    no_alt = [i for i in imgs if i.get("alt") is None and i.get("aria-hidden") != "true"]
    if no_alt:
        issues.append(f"{len(no_alt)} images have no alt attribute.")

    unlabeled = 0
    for inp in soup.find_all(["input", "select", "textarea"]):
        if inp.get("type") in ("hidden", "submit", "button", "reset", "image"):
            continue
        has_label = (inp.get("id") and soup.find("label", attrs={"for": inp["id"]})) or inp.find_parent("label") \
            or inp.get("aria-label") or inp.get("aria-labelledby") or inp.get("title")
        if not has_label:
            unlabeled += 1
    if unlabeled:
        issues.append(f"{unlabeled} form fields have no label.")

    def nameless(el):
        return not (_text(el) or el.get("aria-label") or el.get("aria-labelledby") or el.get("title")
                    or el.find("img", alt=lambda a: a) or el.find("svg", attrs={"aria-label": True}))
    nameless_buttons = sum(1 for b in soup.find_all("button") if nameless(b))
    nameless_links = sum(1 for a in soup.find_all("a", href=True) if nameless(a))
    if nameless_buttons:
        issues.append(f"{nameless_buttons} buttons have no accessible name.")
    if nameless_links:
        issues.append(f"{nameless_links} links have no accessible name.")

    levels = [int(h.name[1]) for h in soup.find_all(re.compile(r"^h[1-6]$"))]
    skips = sum(1 for a, b in zip(levels, levels[1:]) if b > a + 1)
    if skips:
        issues.append(f"Heading levels skip {skips} time(s) (e.g. h2 → h4).")
    if not soup.find("main") and not soup.find(attrs={"role": "main"}):
        issues.append("No <main> landmark.")
    skip_link = any(a["href"].startswith("#") and re.search(r"skip", _text(a), re.I)
                    for a in soup.find_all("a", href=True))
    pos_tabindex = sum(1 for el in soup.find_all(attrs={"tabindex": True})
                       if el["tabindex"].lstrip("-").isdigit() and int(el["tabindex"]) > 0)
    if pos_tabindex:
        issues.append(f"{pos_tabindex} elements use a positive tabindex (breaks keyboard order).")
    vp = soup.find("meta", attrs={"name": "viewport"})
    if vp and re.search(r"user-scalable\s*=\s*no|maximum-scale\s*=\s*1(\.0)?\b", vp.get("content", "")):
        issues.append("Viewport disables zoom.")

    return {
        "lang": lang,
        "images": len(imgs), "images_missing_alt": len(no_alt),
        "unlabeled_fields": unlabeled,
        "nameless_buttons": nameless_buttons, "nameless_links": nameless_links,
        "heading_skips": skips,
        "skip_link": skip_link,
        "aria_attributes": sum(1 for el in soup.find_all(True) for a in el.attrs if a.startswith("aria-")),
        "issues": issues,
    }


VITAL_LIMITS = {"fcp": (1800, 3000), "lcp": (2500, 4000), "tbt": (200, 600), "cls": (0.1, 0.25)}
VITAL_WEIGHTS = {"fcp": 0.15, "lcp": 0.3, "tbt": 0.3, "cls": 0.25}


def vitals_score(v):
    """100 at the 'good' limit, 50 at the 'poor' limit, 0 at twice the poor limit."""
    total = 0.0
    for k, w in VITAL_WEIGHTS.items():
        good, poor = VITAL_LIMITS[k]
        x = v.get(k)
        if x is None:
            s = 50
        elif x <= good:
            s = 100
        elif x <= poor:
            s = 100 - 50 * (x - good) / (poor - good)
        else:
            s = max(0, 50 - 50 * (x - poor) / poor)
        total += w * s
    return round(total)


def merge_browser(report, b, resp, raw_html, raw_soup, cookies):
    """Folds what the headless browser saw into the static report."""
    rendered_html = b.pop("rendered_html", "")
    rsoup = BeautifulSoup(rendered_html, "html.parser")

    tech = detect_technologies(resp, raw_html + "\n" + rendered_html, rsoup, cookies)
    flat = {t["name"]: t for ts in tech["by_category"].values() for t in ts}
    for t in b["js_technologies"]:
        if t["name"] in flat:
            flat[t["name"]]["evidence"] = (t["evidence"] + flat[t["name"]]["evidence"])[:3]
            flat[t["name"]]["version"] = flat[t["name"]]["version"] or t["version"]
        else:
            flat[t["name"]] = t
            tech["by_category"].setdefault(t["category"], []).append(t)
    tech["count"] = len(flat)
    report["technologies"] = tech

    raw_words = report["structure"]["word_count"]
    report["structure"] = structure(rsoup, b["final_url"])
    report["structure"]["raw_word_count"] = raw_words
    rendered_words = report["structure"]["word_count"]
    csr = rendered_words > 80 and raw_words < rendered_words * 0.3
    report["rendering"] = {
        "client_side_rendered": csr,
        "raw_word_count": raw_words,
        "rendered_word_count": rendered_words,
        "raw_elements": len(raw_soup.find_all(True)),
        "rendered_elements": len(rsoup.find_all(True)),
    }
    if csr:
        report["seo"]["issues"].append(
            f"Most content is rendered by JavaScript ({raw_words} words in the HTML vs {rendered_words} after rendering). "
            "Some crawlers and link previews won't see it.")

    a11y = accessibility(rsoup)
    c = b["contrast"]
    a11y["contrast"] = c
    axe = b.get("axe") or {}
    if "violations" in axe:
        # axe-core covers everything the HTML checks do (alt text, labels, names, headings, lang,
        # contrast, zoom…) with WCAG mapping, so its findings replace them as the issue list.
        a11y["axe"] = axe
        a11y["source"] = "axe-core"
        order = {"critical": 0, "serious": 1, "moderate": 2, "minor": 3}
        a11y["issues"] = [f"{v['help']} ({v['count']} element{'s' if v['count'] != 1 else ''}, {v['impact']})"
                          for v in sorted(axe["violations"], key=lambda v: (order.get(v["impact"], 4), -v["count"]))]
    else:
        a11y["axe_error"] = axe.get("error")
        if c["failing_elements"]:
            a11y["issues"].append(f"{c['failing_elements']} text elements fail WCAG AA color contrast "
                                  f"({c['failing_groups']} color combinations).")
    m = b["mobile"]
    a11y["mobile"] = m
    if m.get("horizontal_overflow"):
        a11y["issues"].append(f"Page scrolls sideways on phones (content is {m['page_width']}px wide in a {m['viewport_width']}px screen).")
    if m.get("small_tap_targets", 0) > 3:
        a11y["issues"].append(f"{m['small_tap_targets']} tap targets are smaller than 24×24px on mobile.")
    report["accessibility"] = a11y

    v = b["vitals"]
    perf = report["performance"]
    perf["vitals"] = v
    perf["vitals_method"] = b.get("vitals_method", "desktop-unthrottled")
    perf["vitals_desktop"] = b.get("vitals_desktop")
    perf["vitals_runs"] = b.get("vitals_runs", [])
    perf["throttle"] = b.get("throttle")
    where = "on a throttled mobile load" if perf["vitals_method"] == "mobile-throttled" else "on an unthrottled desktop load"
    labels = {"fcp": "First Contentful Paint", "lcp": "Largest Contentful Paint", "tbt": "Total Blocking Time", "cls": "Cumulative Layout Shift"}
    for k, label in labels.items():
        rating = v["ratings"].get(k)
        if rating in ("poor", "needs-improvement"):
            val = f"{v[k]:.3f}" if k == "cls" else f"{v[k] / 1000:.2f} s" if k != "tbt" else f"{round(v[k])} ms"
            perf["issues"].insert(0, f"{label} is {val} {where} ({rating.replace('-', ' ')}).")
    failed_runs = [r for r in perf["vitals_runs"] if r.get("error")]
    if failed_runs and len(failed_runs) == len(perf["vitals_runs"]):
        perf["issues"].append(f"The page didn't finish loading on a throttled mobile connection: {failed_runs[0]['error']}")
    if b["page_errors"]:
        perf["issues"].append(f"{len(b['page_errors'])} uncaught JavaScript errors during load.")
    if b["failed_requests"] or b["http_errors"]:
        perf["issues"].append(f"{len(b['failed_requests']) + len(b['http_errors'])} requests failed or returned errors.")
    perf["browser_request_count"] = b["request_count"]
    perf["browser_requests_by_type"] = b["requests_by_type"]

    report["design"]["computed"] = b["computed_styles"]
    report["browser"] = {k: b[k] for k in ("available", "screenshots", "components", "console", "page_errors",
                                            "failed_requests", "http_errors", "blocked_private_requests", "browser_ms")}


def score(seo_r, a11y_r, sec_r, perf_r):
    def clamp(n):
        return max(0, min(100, round(n)))
    sec_points = 100
    sec_points -= 12 * sum(1 for h in sec_r["headers"] if not h["present"])
    if not sec_r["https"]:
        sec_points -= 40
    if sec_r["http_redirects_to_https"] is False:
        sec_points -= 10
    if sec_r["mixed_content"]:
        sec_points -= 15
    sec_points -= 5 * len(sec_r["version_leaks"])
    # Each vulnerable library costs by its worst known issue, capped so one old bundle can't zero the score.
    vl = sec_r.get("vulnerable_libraries") or {}
    cost = {"critical": 20, "high": 15, "medium": 8, "low": 3}
    sec_points -= min(40, sum(cost.get(f["severity"], 8) for f in vl.get("findings", [])))
    if perf_r.get("vitals"):
        static_issues = [i for i in perf_r["issues"] if "Contentful Paint" not in i
                         and "Blocking Time" not in i and "Layout Shift" not in i]
        perf_points = 0.65 * vitals_score(perf_r["vitals"]) + 0.35 * (100 - 9 * len(static_issues))
    else:
        perf_points = 100 - 9 * len(perf_r["issues"])
    if perf_r["total_known_bytes"] > 3_000_000:
        perf_points -= 15
    if a11y_r.get("axe"):
        # Like Lighthouse: each failed rule costs by impact, however many elements it hits.
        weight = {"critical": 10, "serious": 7, "moderate": 3, "minor": 1}
        a11y_points = 100 - sum(weight.get(v["impact"], 3) for v in a11y_r["axe"]["violations"])
        m = a11y_r.get("mobile") or {}
        a11y_points -= 5 * bool(m.get("horizontal_overflow")) + 3 * (m.get("small_tap_targets", 0) > 3)
    else:
        a11y_points = 100 - 10 * len(a11y_r["issues"])
    return {
        "seo": clamp(100 - 8 * len(seo_r["issues"])),
        "accessibility": clamp(a11y_points),
        "security": clamp(sec_points),
        "performance": clamp(perf_points),
    }


CRUX_METRICS = {
    "largest_contentful_paint": ("lcp", "Largest Contentful Paint", "ms"),
    "interaction_to_next_paint": ("inp", "Interaction to Next Paint", "ms"),
    "cumulative_layout_shift": ("cls", "Cumulative Layout Shift", ""),
    "first_contentful_paint": ("fcp", "First Contentful Paint", "ms"),
    "experimental_time_to_first_byte": ("ttfb", "Time to First Byte", "ms"),
}


def field_data(url: str) -> dict:
    """Real-visitor Core Web Vitals (75th percentile, last 28 days) from the Chrome UX Report.
    Needs a free API key in CRUX_API_KEY; tries the exact page first, then the whole origin."""
    key = os.environ.get("CRUX_API_KEY")
    if not key:
        return {"available": False, "reason": "no_key"}
    origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    for scope, query in (("page", {"url": url}), ("origin", {"origin": origin})):
        try:
            r = requests.post(f"https://chromeuxreport.googleapis.com/v1/records:queryRecord?key={key}",
                              json=query | {"formFactor": "PHONE"}, timeout=10)
        except requests.RequestException as e:
            return {"available": False, "reason": "error", "error": type(e).__name__}
        if r.status_code == 404:
            continue
        if r.status_code >= 400:
            msg = (r.json().get("error") or {}).get("message", f"HTTP {r.status_code}") if r.headers.get("content-type", "").startswith("application/json") else f"HTTP {r.status_code}"
            return {"available": False, "reason": "error", "error": msg[:200]}
        rec = r.json().get("record", {})
        metrics = {}
        for name, (short, label, unit) in CRUX_METRICS.items():
            m = rec.get("metrics", {}).get(name)
            if not m:
                continue
            p75 = m.get("percentiles", {}).get("p75")
            p75 = float(p75) if p75 is not None else None
            dist = [round(h.get("density", 0) * 100, 1) for h in m.get("histogram", [])]
            metrics[short] = {"label": label, "p75": p75, "unit": unit, "distribution": dist}
        cp = r.json().get("record", {}).get("collectionPeriod", {})
        fmt = lambda d: f"{d.get('year')}-{d.get('month'):02d}-{d.get('day'):02d}" if d else None
        return {"available": True, "scope": scope, "form_factor": "phone", "metrics": metrics,
                "period": [fmt(cp.get("firstDate")), fmt(cp.get("lastDate"))]}
    return {"available": False, "reason": "not_enough_traffic"}


# ---------------------------------------------------------------- entry

def _script_head(session, url: str) -> str | None:
    """The start of a script, for version banners; None if it can't be fetched safely."""
    try:
        resp, body, _ = safe_get(session, url, max_bytes=vulns.SCRIPT_BYTES, timeout=10)
    except (AnalysisError, requests.RequestException):
        return None
    return body.decode("utf-8", "replace") if resp.status_code == 200 else None


def analyze(raw_url: str, render: bool = True, perf_runs: int = browser.DEFAULT_PERF_RUNS) -> dict:
    url = normalize_url(raw_url)
    session = _session()
    t0 = time.perf_counter()
    try:
        resp, html_bytes, chain = safe_get(session, url)
    except requests.exceptions.SSLError:
        raise AnalysisError("The site's HTTPS certificate could not be verified.")
    except requests.exceptions.ConnectionError:
        raise AnalysisError("Couldn't connect to that site. Check the address.")
    except requests.exceptions.Timeout:
        raise AnalysisError("The site took too long to respond.")
    elapsed_ms = round(resp.elapsed.total_seconds() * 1000)
    final_url = resp.url
    ctype = resp.headers.get("content-type", "")
    if "html" not in ctype and not html_bytes.lstrip()[:15].lower().startswith((b"<!doctype", b"<html")):
        raise AnalysisError(f"That URL returned {ctype or 'unknown content'}, not a web page.")

    html = html_bytes.decode(resp.encoding or "utf-8", "replace")
    soup = BeautifulSoup(html, "html.parser")
    cookies = _set_cookie_headers(resp)

    checks = vulns.func_checks() if render and browser.AVAILABLE else {}
    with ThreadPoolExecutor(max_workers=6) as pool:
        browser_f = pool.submit(browser.analyze_rendered, final_url, _host_is_public, perf_runs, checks) if render else None
        field_f = pool.submit(field_data, final_url)
        css_f = pool.submit(fetch_css, session, soup, final_url)
        res_f = pool.submit(probe_resources, session, collect_resources(soup, final_url))
        sec_f = pool.submit(security, session, resp, final_url, cookies, soup)
        seo_f = pool.submit(seo, session, soup, final_url, resp)
        css_text, resources, sec_r, seo_r = css_f.result(), res_f.result(), sec_f.result(), seo_f.result()
        browser_r = browser_f.result() if browser_f else {"available": False, "error": "Browser rendering was turned off."}

    perf_r = performance(resp, html_bytes, elapsed_ms, resources, soup)
    a11y_r = accessibility(soup)
    report = {
        "overview": overview(url, final_url, resp, html_bytes, chain, elapsed_ms, soup),
        "technologies": detect_technologies(resp, html, soup, cookies),
        "design": design_system(css_text, soup),
        "structure": structure(soup, final_url),
        "performance": perf_r,
        "seo": seo_r,
        "accessibility": a11y_r,
        "security": sec_r,
        "response_headers": dict(resp.headers),
        "analyzed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    runtime_versions = browser_r.get("runtime_versions") or {}
    script_urls = [r["url"] for r in resources if r["type"] == "script"] + (browser_r.get("script_urls") or [])
    if browser_r["available"]:
        merge_browser(report, browser_r, resp, html, soup, cookies)
    else:
        report["browser"] = browser_r
    tech_versions = {t["name"]: t.get("version") for ts in report["technologies"]["by_category"].values() for t in ts if t.get("version")}
    report["security"]["vulnerable_libraries"] = vulns.scan(script_urls, fetch=lambda u: _script_head(session, u),
                                                            tech=tech_versions, runtime=runtime_versions)
    report["performance"]["field"] = field_f.result()
    report["analysis_ms"] = round((time.perf_counter() - t0) * 1000)
    report["scores"] = score(report["seo"], report["accessibility"], sec_r, report["performance"])
    report["overview"]["http_version"] = "HTTP/2" if sec_r.get("alpn") == "h2" else report["overview"]["http_version"]
    return report
