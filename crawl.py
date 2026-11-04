"""Multi-page crawl: follows a site's internal links (and its sitemap) to check every page, not just
the homepage. It finds broken pages and links, redirects, duplicate or missing titles and descriptions,
thin or slow pages, pages nothing links to, and technology that's missing on some pages.

A crawl runs in short steps that pick up where the last one stopped, with its queue kept in SQLite.
Locally a background thread drives the steps; on Vercel, where nothing runs between requests, each
status poll from the browser advances the crawl a few seconds at a time. robots.txt is respected.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import statistics
import threading
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qsl, urldefrag, urlencode, urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup

import osint
import store
from analyzer import AnalysisError, _set_cookie_headers, detect_technologies, normalize_url, safe_get

log = logging.getLogger("crawl")
UA = "Mozilla/5.0 (compatible; DeconstructSite-Crawler/1.0; +https://github.com/sharveshr/deconstruct-site)"
PAGE_LIMITS = (25, 100, 250, 500)
MAX_DEPTH = 10
PAGE_BYTES = 3_000_000
PAGE_TIMEOUT = 12
WORKERS = 4
MAX_LINK_CHECKS = 300
MAX_SITEMAP_URLS = 10_000
MAX_KNOWN_URLS = 20_000        # stops calendars and faceted search from growing the queue forever
SLOW_MS = 1500
THIN_WORDS = 200
SERVERLESS = bool(os.environ.get("VERCEL"))
SKIP_EXT = re.compile(r"\.(pdf|jpe?g|png|gif|webp|avif|svg|ico|bmp|tiff?|mp4|webm|mov|avi|mp3|wav|ogg|zip|gz|tgz|rar|7z|exe|dmg|msi|"
                      r"apk|docx?|xlsx?|pptx?|csv|xml|json|txt|rss|atom|woff2?|ttf|eot|css|js|map)$", re.I)
TRACKING = re.compile(r"^(utm_\w+|fbclid|gclid|dclid|msclkid|mc_cid|mc_eid|_hsenc|_hsmi|ref_src)$", re.I)
# Statuses that usually mean "this server blocks bots", not "this link is broken".
UNVERIFIABLE = {401, 403, 405, 406, 429, 999}

ISSUES = {
    # key: (label, severity, counts against page health)
    "error": ("Page returns an error", "critical", True),
    "broken_links": ("Links to a broken page or URL", "warning", True),
    "redirected": ("Reached through a redirect", "info", False),
    "missing_title": ("Missing title", "warning", True),
    "duplicate_title": ("Title shared with other pages", "warning", True),
    "long_title": ("Title over 60 characters", "info", False),
    "missing_description": ("Missing meta description", "warning", True),
    "duplicate_description": ("Description shared with other pages", "info", False),
    "long_description": ("Description over 160 characters", "info", False),
    "missing_h1": ("No H1 heading", "warning", True),
    "multiple_h1": ("More than one H1", "info", False),
    "thin": (f"Thin content (under {THIN_WORDS} words)", "info", False),
    "duplicate_content": ("Same text as another page", "warning", True),
    "noindex": ("Blocked from search engines (noindex)", "info", False),
    "canonical_elsewhere": ("Canonical points to another URL", "info", False),
    "slow": (f"Slow response (over {SLOW_MS / 1000:g} s)", "warning", True),
    "images_no_alt": ("Images without alt text", "info", False),
    "missing_lang": ("No lang attribute", "info", False),
    "orphan": ("In the sitemap but not linked from any crawled page", "info", False),
}


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": UA, "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5",
                      "Accept-Language": "en-US,en;q=0.9", "Accept-Encoding": "gzip, deflate"})
    return s


def norm_url(url: str) -> str:
    """One spelling per page: no fragment, lowercase host, no default port, no tracking parameters."""
    url, _ = urldefrag(url.strip())
    p = urlparse(url)
    host = (p.hostname or "").lower()
    port = p.port
    netloc = host + (f":{port}" if port and not (p.scheme == "http" and port == 80 or p.scheme == "https" and port == 443) else "")
    query = urlencode([(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if not TRACKING.match(k)])
    return urlunparse((p.scheme.lower(), netloc, p.path or "/", "", query, ""))


def _site_host(host: str) -> str:
    return host.lower().removeprefix("www.")


def _same_site(url: str, root_host: str) -> bool:
    return _site_host(urlparse(url).hostname or "") == _site_host(root_host)


# ---------------------------------------------------------------- robots.txt

def _robots(session, root: str) -> dict:
    p = urlparse(root)
    try:
        resp, body, _ = safe_get(session, f"{p.scheme}://{p.netloc}/robots.txt", max_bytes=500_000, timeout=10)
    except (AnalysisError, requests.RequestException):
        return {"found": False, "rules": [], "crawl_delay": None, "sitemaps": []}
    text = body.decode("utf-8", "replace")
    if resp.status_code >= 400 or text.lstrip()[:15].lower().startswith(("<!doctype", "<html")):
        return {"found": False, "rules": [], "crawl_delay": None, "sitemaps": []}
    groups, sitemaps = osint._parse_robots(text)
    ours = [g for g in groups if any("deconstructsite" in a.lower() for a in g["agents"])]
    group = (ours or [g for g in groups if "*" in g["agents"]] or [None])[0]
    rules = ([[True, a] for a in group["allow"] if a] + [[False, d] for d in group["disallow"] if d]) if group else []
    try:
        delay = min(5.0, float(group["crawl_delay"])) if group and group["crawl_delay"] else None
    except ValueError:
        delay = None
    return {"found": True, "rules": rules, "crawl_delay": delay, "sitemaps": sitemaps,
            "group": ", ".join(group["agents"]) if group else None}


def _rule_re(pattern: str):
    anchored = pattern.endswith("$")
    body = re.escape(pattern.rstrip("$")).replace(r"\*", ".*")
    return re.compile(body + ("$" if anchored else ""))


def allowed(url: str, rules: list) -> bool:
    """Google's robots.txt semantics: the longest matching rule wins, and Allow wins a tie."""
    p = urlparse(url)
    path = (p.path or "/") + (f"?{p.query}" if p.query else "")
    best = None
    for allow, pattern in rules:
        if _rule_re(pattern).match(path):
            key = (len(pattern), allow)
            if best is None or key > best:
                best = key
    return best is None or best[1]


# ---------------------------------------------------------------- sitemap

def _sitemap_urls(sources: list[str], root: str) -> list[str]:
    p = urlparse(root)
    queue = list(sources) or [f"{p.scheme}://{p.netloc}{path}" for path in ("/sitemap.xml", "/sitemap_index.xml", "/wp-sitemap.xml")]
    guessing = not sources
    seen, urls = set(), []
    while queue and len(seen) < 25 and len(urls) < MAX_SITEMAP_URLS:
        u = queue.pop(0)
        if u in seen:
            continue
        seen.add(u)
        try:
            resp, text = osint._get_sitemap(u)
        except (requests.RequestException, AnalysisError):
            continue
        if resp.status_code >= 400 or "<" not in text[:500] or text.lstrip()[:15].lower().startswith(("<!doctype", "<html")):
            continue
        locs = re.findall(r"<loc>\s*(?:<!\[CDATA\[)?\s*([^<\]\s]+)", text, re.I)
        if re.search(r"<sitemapindex", text[:3000], re.I):
            queue.extend(l for l in locs if l not in seen)
        else:
            urls.extend(locs)
        if guessing:
            queue = [q for q in queue if q not in (f"{p.scheme}://{p.netloc}/sitemap_index.xml", f"{p.scheme}://{p.netloc}/wp-sitemap.xml")]
    return urls[:MAX_SITEMAP_URLS]


# ---------------------------------------------------------------- one page

def _fetch_page(session, url: str, root_host: str) -> tuple[int | None, dict]:
    t0 = time.perf_counter()
    try:
        resp, body, chain = safe_get(session, url, max_bytes=PAGE_BYTES, timeout=PAGE_TIMEOUT)
    except AnalysisError as e:
        return None, {"error": str(e), "ms": round((time.perf_counter() - t0) * 1000)}
    except requests.exceptions.SSLError:
        return None, {"error": "TLS certificate error", "ms": round((time.perf_counter() - t0) * 1000)}
    except requests.exceptions.Timeout:
        return None, {"error": f"Timed out after {PAGE_TIMEOUT} s", "ms": round((time.perf_counter() - t0) * 1000)}
    except requests.exceptions.ConnectionError:
        return None, {"error": "Couldn't connect", "ms": round((time.perf_counter() - t0) * 1000)}
    except requests.RequestException as e:
        return None, {"error": type(e).__name__, "ms": round((time.perf_counter() - t0) * 1000)}
    ms = round((time.perf_counter() - t0) * 1000)
    ctype = resp.headers.get("content-type", "").split(";")[0].strip().lower()
    data = {"final_url": norm_url(resp.url), "ms": ms, "bytes": len(body), "content_type": ctype,
            "redirects": [{"url": c["url"], "status": c["status"]} for c in chain],
            "x_robots": resp.headers.get("x-robots-tag")}
    if "html" not in ctype or not _same_site(resp.url, root_host):
        if not _same_site(resp.url, root_host):
            data["offsite"] = True
        return resp.status_code, data

    html = body.decode(resp.encoding or "utf-8", "replace")
    soup = BeautifulSoup(html, "html.parser")
    meta = lambda n: (soup.find("meta", attrs={"name": re.compile(f"^{n}$", re.I)}) or {}).get("content")
    canonical = soup.find("link", rel=lambda r: r and "canonical" in [x.lower() for x in (r if isinstance(r, list) else [r])], href=True)
    h1s = [h.get_text(" ", strip=True)[:120] for h in soup.find_all("h1")]
    tech = sorted({t["name"] for ts in detect_technologies(resp, html, soup, _set_cookie_headers(resp))["by_category"].values() for t in ts})
    for t in soup(["script", "style", "noscript", "template", "svg"]):
        t.decompose()
    text = re.sub(r"\s+", " ", soup.get_text(" ")).strip()
    words = len(text.split())
    internal, external, resources = [], [], []
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:", "data:", "sms:")):
            continue
        u = norm_url(urljoin(resp.url, href))
        if not u.startswith(("http://", "https://")):
            continue
        if _same_site(u, root_host):
            (resources if SKIP_EXT.search(urlparse(u).path) else internal).append(u)
        else:
            external.append(u)
    imgs = soup.find_all("img")
    data |= {
        "title": (soup.title.get_text(" ", strip=True) if soup.title else "")[:300],
        "description": (meta("description") or "").strip()[:500],
        "robots": meta("robots"),
        "canonical": norm_url(urljoin(resp.url, canonical["href"])) if canonical else None,
        "h1": h1s[:3], "h1_count": len(h1s),
        "lang": (soup.html.get("lang") if soup.html else None),
        "words": words,
        "content_hash": hashlib.md5(text.lower().encode()).hexdigest() if words >= 50 else None,
        "images": len(imgs), "images_no_alt": sum(1 for i in imgs if not i.has_attr("alt")),
        "links": list(dict.fromkeys(internal))[:500],
        "external": list(dict.fromkeys(external))[:200],
        "resources": list(dict.fromkeys(resources))[:100],
        "tech": tech,
    }
    return resp.status_code, data


def _check_link(session, url: str) -> tuple[int | None, str | None]:
    try:
        resp, _, _ = safe_get(session, url, method="HEAD", timeout=10)
        if resp.status_code in (403, 404, 405, 501) or resp.status_code >= 500:
            # Plenty of servers answer HEAD differently from GET; confirm with a small GET.
            resp, _, _ = safe_get(session, url, max_bytes=16_384, timeout=10)
        return resp.status_code, None
    except AnalysisError as e:
        return None, str(e)
    except requests.exceptions.Timeout:
        return None, "Timed out"
    except requests.exceptions.SSLError:
        return None, "TLS certificate error"
    except requests.exceptions.ConnectionError:
        return None, "Couldn't connect"
    except requests.RequestException as e:
        return None, type(e).__name__


# ---------------------------------------------------------------- steps

def create(url: str, max_pages: int, max_depth: int = MAX_DEPTH) -> dict:
    root = norm_url(normalize_url(url))
    host = urlparse(root).hostname
    if max_pages not in PAGE_LIMITS:
        raise ValueError(f"max_pages must be one of {', '.join(map(str, PAGE_LIMITS))}")
    site = store.get_or_create_site(root)
    return store.create_crawl(root, host, max_pages, max(1, min(MAX_DEPTH, int(max_depth))), site["id"])


def _start(crawl: dict, session):
    robots = _robots(session, crawl["root_url"])
    sm = [norm_url(u) for u in _sitemap_urls(robots["sitemaps"], crawl["root_url"])]
    sm = [u for u in dict.fromkeys(sm) if _same_site(u, crawl["host"]) and not SKIP_EXT.search(urlparse(u).path)]
    store.add_crawl_pages(crawl["id"], [(crawl["root_url"], 0, "seed")] + [(u, None, "sitemap") for u in sm])
    store.update_crawl(crawl["id"], status="crawling", started_at=store.now_iso(), sitemap_urls=len(sm),
                       robots={k: robots[k] for k in ("found", "rules", "crawl_delay", "group") if k in robots})


def _crawl_batch(crawl: dict, session, deadline: float):
    done = crawl["pages_done"]
    remaining = crawl["max_pages"] - done
    delay = crawl["robots"].get("crawl_delay")
    size = 1 if delay else (3 if SERVERLESS else 8)
    batch = store.next_crawl_pages(crawl["id"], min(size, remaining)) if remaining > 0 else []
    if not batch:
        _begin_link_checks(crawl)
        return
    rules = crawl["robots"].get("rules", [])
    todo = []
    for page in batch:
        if not allowed(page["url"], rules):
            store.save_crawl_page(page["id"], "skipped", None, {"skipped": "Disallowed by robots.txt"})
        else:
            todo.append(page)
    with ThreadPoolExecutor(1 if delay else WORKERS) as pool:
        results = list(pool.map(lambda p: (p, *_fetch_page(session, p["url"], crawl["host"])), todo))
    known = sum(store.crawl_page_counts(crawl["id"]).values())
    for page, status, data in results:
        store.save_crawl_page(page["id"], "done", status, data)
        depth = page["depth"] if page["depth"] is not None else 1
        if data.get("links") and depth + 1 <= crawl["max_depth"] and known < MAX_KNOWN_URLS:
            known += store.add_crawl_pages(crawl["id"], [(u, depth + 1, "link") for u in data["links"]
                                                         if not SKIP_EXT.search(urlparse(u).path)])
        if delay and time.time() + delay < deadline:
            time.sleep(delay)
    store.update_crawl(crawl["id"], pages_done=done + len(results))


def _begin_link_checks(crawl: dict):
    pages = store.crawl_pages(crawl["id"])
    crawled = {p["url"] for p in pages if p["state"] == "done"}
    links = []
    for p in pages:
        d = p["data"] or {}
        links += [(u, "external") for u in d.get("external", [])]
        links += [(u, "resource") for u in d.get("resources", [])]
    uniq = list(dict.fromkeys(u for u in links if u[0] not in crawled))
    # Resources (PDFs and other files on the site) first: they're the site's own and few.
    uniq.sort(key=lambda l: l[1] != "resource")
    store.add_crawl_links(crawl["id"], uniq[:MAX_LINK_CHECKS])
    store.update_crawl(crawl["id"], status="checking")


def _check_batch(crawl: dict, session):
    batch = store.next_crawl_links(crawl["id"], 12 if SERVERLESS else 24)
    if not batch:
        finish(crawl)
        return
    with ThreadPoolExecutor(12) as pool:
        results = list(pool.map(lambda l: (l, *_check_link(session, l["url"])), batch))
    for link, status, err in results:
        store.save_crawl_link(link["id"], status, err)
    store.update_crawl(crawl["id"], links_checked=crawl["links_checked"] + len(results))


def finish(crawl: dict, stopped: bool = False):
    pages = store.crawl_pages(crawl["id"])
    links = store.crawl_links(crawl["id"])
    summary = summarize(crawl, pages, links, stopped=stopped)
    store.update_crawl(crawl["id"], status="stopped" if stopped else "done", finished_at=store.now_iso(), summary=summary)
    try:
        import watch
        watch.detect_crawl(store.crawl_owner_row(crawl["id"]), summary)
    except Exception:
        log.exception("change detection failed for crawl %s", crawl["id"])


def step(crawl_id: int, budget: float = 20.0) -> bool:
    """Advances a crawl for up to `budget` seconds. Returns False if another worker holds it."""
    if not store.lock_crawl(crawl_id, budget + 60):
        return False
    try:
        crawl = store.crawl_owner_row(crawl_id)
        if not crawl:
            return False
        session = _session()
        deadline = time.time() + budget
        with store.as_user(crawl["user_id"]):
            while crawl and time.time() < deadline:
                if crawl["status"] == "queued":
                    _start(crawl, session)
                elif crawl["status"] == "crawling":
                    _crawl_batch(crawl, session, deadline)
                elif crawl["status"] == "checking":
                    _check_batch(crawl, session)
                elif crawl["status"] == "stopping":
                    finish(crawl, stopped=True)
                else:
                    break
                crawl = store.crawl_owner_row(crawl_id)
    except Exception as e:
        log.exception("crawl %s failed", crawl_id)
        store.update_crawl(crawl_id, status="error", error=f"{type(e).__name__}: {str(e)[:200]}", finished_at=store.now_iso())
    finally:
        store.unlock_crawl(crawl_id)
    return True


# ---------------------------------------------------------------- results

def summarize(crawl: dict, pages: list[dict], links: list[dict], stopped: bool = False) -> dict:
    done = [p for p in pages if p["state"] == "done"]
    skipped = [p for p in pages if p["state"] == "skipped"]
    queued_left = sum(1 for p in pages if p["state"] == "queued")
    html = [p for p in done if p["status"] and p["status"] < 300 and (p["data"] or {}).get("title") is not None
            and not p["data"].get("offsite")]
    by_url = {p["url"]: p for p in done}
    html_ids = {p["id"] for p in html}

    inlinks, linked_from = Counter(), defaultdict(list)
    ext_from = defaultdict(list)
    for p in done:
        d = p["data"] or {}
        for u in set(d.get("links", [])) | set(d.get("resources", [])):
            if u != p["url"]:
                inlinks[u] += 1
                if len(linked_from[u]) < 5:
                    linked_from[u].append(p["url"])
        for u in d.get("external", []):
            if len(ext_from[u]) < 5:
                ext_from[u].append(p["url"])

    def is_error(p):
        return p["status"] is None or p["status"] >= 400

    broken_pages = [{"url": p["url"], "status": p["status"], "error": (p["data"] or {}).get("error"),
                     "inlinks": inlinks[p["url"]], "linked_from": linked_from[p["url"]]}
                    for p in done if is_error(p)]
    broken_links, unverified = [], []
    for l in links:
        if l["state"] != "done":
            continue
        row = {"url": l["url"], "kind": l["kind"], "status": l["status"], "error": l["error"],
               "linked_from": ext_from.get(l["url"]) or linked_from.get(l["url"], [])}
        if l["status"] in UNVERIFIABLE:
            unverified.append(row)
        elif l["error"] or (l["status"] or 0) >= 400:
            broken_links.append(row)
    broken_targets = {b["url"] for b in broken_pages} | {b["url"] for b in broken_links}

    redirects = [{"url": p["url"], "final_url": p["data"]["final_url"], "hops": len(p["data"]["redirects"]),
                  "statuses": [r["status"] for r in p["data"]["redirects"]], "inlinks": inlinks[p["url"]],
                  "linked_from": linked_from[p["url"]]}
                 for p in done if (p["data"] or {}).get("redirects")]

    def groups(key):
        g = defaultdict(list)
        for p in html:
            v = (p["data"].get(key) or "").strip()
            if v:
                g[v].append(p["url"])
        return {v: urls for v, urls in g.items() if len(urls) > 1}

    dup_titles, dup_desc, dup_content = groups("title"), groups("description"), groups("content_hash")
    sitemap_set = {p["url"] for p in pages if p["source"] == "sitemap"}
    hit_limit = queued_left > 0 and not stopped

    page_issues: dict[str, list[str]] = {}
    for p in done:
        d, keys = p["data"] or {}, []
        if is_error(p):
            keys.append("error")
        if d.get("redirects"):
            keys.append("redirected")
        if any(u in broken_targets for u in d.get("links", []) + d.get("external", []) + d.get("resources", [])):
            keys.append("broken_links")
        if (d.get("ms") or 0) > SLOW_MS:
            keys.append("slow")
        if p["id"] in html_ids:
            t, desc = d.get("title", ""), d.get("description", "")
            if not t:
                keys.append("missing_title")
            elif t in dup_titles:
                keys.append("duplicate_title")
            if len(t) > 60:
                keys.append("long_title")
            if not desc:
                keys.append("missing_description")
            elif desc in dup_desc:
                keys.append("duplicate_description")
            if len(desc) > 160:
                keys.append("long_description")
            if d.get("h1_count", 0) == 0:
                keys.append("missing_h1")
            elif d["h1_count"] > 1:
                keys.append("multiple_h1")
            if d.get("words", 0) < THIN_WORDS:
                keys.append("thin")
            if d.get("content_hash") in dup_content:
                keys.append("duplicate_content")
            if "noindex" in f"{d.get('robots') or ''} {d.get('x_robots') or ''}".lower():
                keys.append("noindex")
            if d.get("canonical") and d["canonical"] not in (p["url"], d.get("final_url")):
                keys.append("canonical_elsewhere")
            if d.get("images_no_alt"):
                keys.append("images_no_alt")
            if not d.get("lang"):
                keys.append("missing_lang")
            if p["url"] in sitemap_set and inlinks[p["url"]] == 0 and p["url"] != crawl["root_url"]:
                keys.append("orphan")
        if keys:
            page_issues[p["url"]] = keys

    counts = Counter(k for keys in page_issues.values() for k in keys)
    healthy = sum(1 for p in done if not any(ISSUES[k][2] for k in page_issues.get(p["url"], [])))
    timed = sorted((p for p in done if (p["data"] or {}).get("ms") is not None and not is_error(p)), key=lambda p: -p["data"]["ms"])
    ms_values = [p["data"]["ms"] for p in timed]

    # Technology on most pages but not all, e.g. analytics or a consent banner missing from some templates.
    tech_counts = Counter(t for p in html for t in p["data"].get("tech", []))
    consistency = []
    for t, n in tech_counts.most_common():
        if len(html) >= 4 and len(html) / 2 <= n < len(html):
            missing = [p["url"] for p in html if t not in p["data"].get("tech", [])]
            consistency.append({"tech": t, "pages_with": n, "pages_without": len(missing), "missing_on": missing[:10]})

    status_buckets = Counter("error" if p["status"] is None else f"{p['status'] // 100}xx" for p in done)
    issue_list = [{"key": k, "label": ISSUES[k][0], "severity": ISSUES[k][1], "pages": counts[k]} for k in ISSUES if counts[k]]
    sev = {"critical": 0, "warning": 1, "info": 2}
    issue_list.sort(key=lambda i: (sev[i["severity"]], -i["pages"]))

    started = store.parse_iso(crawl["started_at"]) if crawl.get("started_at") else None
    return {
        "pages_crawled": len(done), "html_pages": len(html), "skipped_robots": len(skipped), "queued_left": queued_left,
        "hit_limit": hit_limit, "stopped": stopped, "sitemap_urls": crawl.get("sitemap_urls", 0),
        "duration_s": round((store.parse_iso(store.now_iso()) - started).total_seconds()) if started else None,
        "health": round(100 * healthy / len(done)) if done else None,
        "issue_pages": len([u for u, keys in page_issues.items() if any(ISSUES[k][2] for k in keys)]),
        "status": dict(status_buckets),
        "counts": {"broken_pages": len(broken_pages), "broken_links": len(broken_links), "unverified_links": len(unverified),
                   "redirects": len(redirects), "links_checked": sum(1 for l in links if l["state"] == "done")},
        "issues": issue_list,
        "broken_pages": sorted(broken_pages, key=lambda b: -b["inlinks"])[:200],
        "broken_links": broken_links[:200],
        "unverified_links": unverified[:100],
        "redirects": sorted(redirects, key=lambda r: (-r["hops"], -r["inlinks"]))[:200],
        "duplicate_titles": [{"value": v, "urls": u[:20], "count": len(u)} for v, u in sorted(dup_titles.items(), key=lambda kv: -len(kv[1]))][:50],
        "duplicate_descriptions": [{"value": v, "urls": u[:20], "count": len(u)} for v, u in sorted(dup_desc.items(), key=lambda kv: -len(kv[1]))][:50],
        "duplicate_content": [{"urls": u[:20], "count": len(u)} for u in sorted(dup_content.values(), key=len, reverse=True)][:50],
        "orphans": [u for u, keys in page_issues.items() if "orphan" in keys][:200],
        # Only a crawl that reached every linked page can say nothing links to a page.
        "orphans_reliable": not hit_limit and not stopped,
        "not_in_sitemap": [p["url"] for p in html if sitemap_set and p["url"] not in sitemap_set][:200] if sitemap_set else [],
        "slowest": [{"url": p["url"], "ms": p["data"]["ms"]} for p in timed[:10]],
        "largest": [{"url": p["url"], "bytes": p["data"]["bytes"]} for p in sorted(done, key=lambda p: -((p["data"] or {}).get("bytes") or 0))[:10]],
        "response_ms": {"median": round(statistics.median(ms_values)) if ms_values else None,
                        "p90": round(sorted(ms_values)[int(len(ms_values) * 0.9)]) if ms_values else None},
        "depths": sorted(Counter(p["depth"] for p in done if p["depth"] is not None).items()),
        "consistency": consistency[:20],
        "languages": Counter(p["data"].get("lang") or "(none)" for p in html).most_common(),
        "page_issues": page_issues,
        "inlinks": {u: n for u, n in inlinks.items() if u in by_url},
    }


def page_rows(crawl: dict) -> list[dict]:
    """One row per crawled page for the pages table and CSV export."""
    s = crawl.get("summary") or {}
    issues, inl = s.get("page_issues", {}), s.get("inlinks", {})
    rows = []
    for p in store.crawl_pages(crawl["id"]):
        if p["state"] == "queued":
            continue
        d = p["data"] or {}
        rows.append({"url": p["url"], "state": p["state"], "status": p["status"], "error": d.get("error") or d.get("skipped"),
                     "depth": p["depth"], "source": p["source"], "title": d.get("title"), "words": d.get("words"),
                     "ms": d.get("ms"), "bytes": d.get("bytes"), "final_url": d.get("final_url"),
                     "inlinks": inl.get(p["url"], 0), "outlinks": len(d.get("links", [])),
                     "issues": issues.get(p["url"], [])})
    return rows


# ---------------------------------------------------------------- background worker

_worker_started = False


def worker_running() -> bool:
    return _worker_started


def _loop():
    while True:
        try:
            for c in store.crawls_in_progress():
                step(c["id"], budget=20)
        except Exception:
            log.exception("crawl worker tick failed")
        time.sleep(2)


def start_worker():
    global _worker_started
    if _worker_started:
        return
    _worker_started = True
    threading.Thread(target=_loop, name="crawler", daemon=True).start()
