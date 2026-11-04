"""Exports a saved analysis or crawl as Markdown, printable HTML or PDF, with the owner's agency branding.

Both documents are built from one outline of sections, so the Markdown and the PDF always say the same
thing. The PDF is printed by headless Chromium when Playwright is installed; without it (Vercel) the
printable HTML is served instead and the browser's "Save as PDF" does the rest.
"""
from __future__ import annotations

import html
import re
from datetime import datetime

import browser

SCORE_NAMES = (("performance", "Performance"), ("seo", "SEO"), ("accessibility", "Accessibility"), ("security", "Security"))


def _date(iso: str | None) -> str:
    if not iso:
        return ""
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).strftime("%d %b %Y")
    except ValueError:
        return iso[:10]


def _ms(v):
    return "—" if v is None else f"{v / 1000:.2f} s" if v >= 1000 else f"{round(v)} ms"


def _kb(n):
    return "—" if n is None else f"{n / 1048576:.2f} MB" if n >= 1048576 else f"{n / 1024:.0f} KB"


# A section is (heading, [blocks]); a block is ("p", text) | ("md", markdown) | ("list", [items]) |
# ("table", [headers], [rows]) | ("code", lang, text) | ("img", data_url, alt).

def analysis_sections(a: dict, ai: dict | None) -> tuple[str, str, list]:
    r = a["report"]
    o, s = r["overview"], r["scores"]
    title = o.get("title") or o["host"]
    secs = []
    secs.append(("Scores", [("table", ["Area", "Score", "Issues"], [
        [name, f"{s[key]}/100", str(n)] for (key, name), n in zip(SCORE_NAMES, (
            len(r["performance"]["issues"]), len(r["seo"]["issues"]), len(r["accessibility"]["issues"]),
            sum(1 for h in r["security"]["headers"] if not h["present"])))])]))
    shot = ((r.get("browser") or {}).get("screenshots") or {}).get("above_fold")
    if shot and str(shot).startswith("data:image/"):
        secs.append(("How it looks", [("img", shot, f"Screenshot of {o['host']}")]))
    if ai and ai.get("summary"):
        secs.append(("Summary", [("md", ai["summary"]["text"])]))
    if ai and ai.get("fixes"):
        blocks = []
        for i, f in enumerate(ai["fixes"]["fixes"], 1):
            blocks.append(("p", f"**{i}. {f['title']}** · {f['impact']} impact, {f['effort']} effort · {f['category']}"))
            blocks.append(("p", f"{f['evidence']} {f['why']}"))
            blocks.append(("md", f["how"]))
            if f.get("code"):
                blocks.append(("code", f.get("code_language") or "", f["code"]))
        secs.append(("Prioritized fixes", blocks))
    else:
        issues = [*(f"Performance: {i}" for i in r["performance"]["issues"]), *(f"SEO: {i}" for i in r["seo"]["issues"]),
                  *(f"Accessibility: {i}" for i in r["accessibility"]["issues"])]
        secs.append(("Issues found", [("list", issues or ["No issues found."])]))
    tech = [[cat, ", ".join(f"{t['name']}{' ' + t['version'] if t.get('version') else ''}" for t in ts)]
            for cat, ts in r["technologies"]["by_category"].items() if ts]
    if tech:
        secs.append(("Technology", [("table", ["Category", "Detected"], tech)]))
    p = r["performance"]
    v = p.get("vitals") or {}
    perf = [("p", f"Page weight {_kb(v.get('transfer_bytes') or p.get('total_known_bytes'))}, "
                  f"{p.get('browser_request_count') or p.get('request_count')} requests, server response {_ms(p.get('server_response_ms'))}.")]
    if v:
        method = "median of throttled mobile loads on 4G" if p.get("vitals_method") == "mobile-throttled" else "one desktop load"
        perf.append(("table", ["Metric", "Value"], [["Largest Contentful Paint", _ms(v.get("lcp"))], ["First Contentful Paint", _ms(v.get("fcp"))],
                                                   ["Total Blocking Time", _ms(v.get("tbt"))], ["Cumulative Layout Shift", f"{v['cls']:.3f}" if v.get("cls") is not None else "—"],
                                                   ["Time to First Byte", _ms(v.get("ttfb"))]]))
        perf.append(("p", f"Lab measurements: {method}."))
    secs.append(("Performance", perf))
    axe = (r["accessibility"].get("axe") or {}).get("violations") or []
    if axe:
        secs.append(("Accessibility (axe-core)", [("table", ["Rule", "Impact", "Elements"],
                                                   [[x.get("help") or x["id"], x.get("impact") or "", str(x.get("count") or len(x.get("nodes", [])))] for x in axe[:20]])]))
    sec = r["security"]
    sec_blocks = [("list", [f"HTTPS: {'yes' if sec.get('https') else 'no'}",
                            *(f"Missing header: {h['name']}" for h in sec["headers"] if not h["present"]),
                            *(f"Version disclosed: {x['header']}: {x['value']}" for x in sec.get("version_leaks", []))])]
    vl = (sec.get("vulnerable_libraries") or {}).get("findings") or []
    if vl:
        sec_blocks.append(("table", ["Library", "Severity", "Known issues", "Fix"],
                           [[f"{f['component']} {f['version']}", f["severity"], str(len(f["vulnerabilities"])),
                             f"Upgrade to {f['upgrade_to']}" if f.get("upgrade_to") else "End of life"] for f in vl]))
    secs.append(("Security", sec_blocks))
    ds = r["design"]
    cp = ds.get("computed") or {}
    colors = [c["value"] for c in (cp.get("background_by_area") or ds["colors"])[:8]]
    fonts = [f["value"] for f in (cp.get("fonts_by_text") or ds["fonts"])[:5]]
    secs.append(("Design", [("p", f"Main colors: {', '.join(colors) or '—'}. Fonts: {', '.join(fonts) or '—'}.")]))
    subtitle = f"{o['final_url']} · analyzed {_date(a.get('created_at'))}"
    return f"{title}", subtitle, secs


def crawl_sections(c: dict) -> tuple[str, str, list]:
    s = c["summary"]
    rel = lambda u: re.sub(r"^https?://[^/]+", "", u) or "/"
    secs = [("Overview", [("table", ["Measure", "Value"], [
        ["Site health", f"{s['health']}/100" if s.get("health") is not None else "—"], ["Pages crawled", str(s["pages_crawled"])],
        ["Broken pages", str(s["counts"]["broken_pages"])], ["Broken outgoing links", str(s["counts"]["broken_links"])],
        ["Redirecting URLs", str(s["counts"]["redirects"])], ["Median response", _ms(s["response_ms"]["median"])]])] +
        ([("p", f"Stopped at the {c['max_pages']}-page limit with {s['queued_left']} more URLs queued.")] if s.get("hit_limit") else []))]
    if s["issues"]:
        secs.append(("Issues", [("table", ["Issue", "Severity", "Pages"], [[i["label"], i["severity"], str(i["pages"])] for i in s["issues"]])]))
    if s["broken_pages"]:
        secs.append(("Broken pages", [("table", ["Page", "Status", "Linked from"],
                                       [[rel(b["url"]), str(b["status"] or b["error"]), ", ".join(rel(u) for u in b["linked_from"][:3])] for b in s["broken_pages"][:50]])]))
    if s["broken_links"]:
        secs.append(("Broken outgoing links", [("table", ["Link", "Status"], [[b["url"], str(b["status"] or b["error"])] for b in s["broken_links"][:50]])]))
    if s["redirects"]:
        secs.append(("Redirects", [("table", ["From", "To", "Hops"], [[rel(r["url"]), rel(r["final_url"]), str(r["hops"])] for r in s["redirects"][:50]])]))
    dups = [*(f"Title “{d['value'][:80]}” on {d['count']} pages" for d in s["duplicate_titles"][:15]),
            *(f"Description “{d['value'][:80]}” on {d['count']} pages" for d in s["duplicate_descriptions"][:10])]
    if dups:
        secs.append(("Duplicates", [("list", dups)]))
    if s["orphans"]:
        secs.append(("Orphan pages", [("list", [rel(u) for u in s["orphans"][:50]])]))
    if s["slowest"]:
        secs.append(("Slowest pages", [("table", ["Page", "Response"], [[rel(p["url"]), _ms(p["ms"])] for p in s["slowest"]])]))
    return f"Site crawl: {c['host']}", f"{c['root_url']} · crawled {_date(c.get('finished_at') or c.get('created_at'))}", secs


# ---------------------------------------------------------------- Markdown

def _md_cell(t: str) -> str:
    return str(t).replace("|", "\\|").replace("\n", " ")


def to_markdown(title: str, subtitle: str, secs: list, branding: dict) -> str:
    out = []
    brand = branding if branding.get("enabled") else {}
    if brand.get("name"):
        out.append(f"*Prepared by {brand['name']}{' · ' + brand['contact'] if brand.get('contact') else ''}*\n")
    out += [f"# {title}", "", subtitle, ""]
    for heading, blocks in secs:
        if all(b[0] == "img" for b in blocks):
            continue
        out += [f"## {heading}", ""]
        for b in blocks:
            if b[0] == "p":
                out += [b[1], ""]
            elif b[0] == "md":
                out += [b[1].strip(), ""]
            elif b[0] == "list":
                out += [f"- {i}" for i in b[1]] + [""]
            elif b[0] == "table":
                out += ["| " + " | ".join(_md_cell(h) for h in b[1]) + " |", "|" + "---|" * len(b[1])]
                out += ["| " + " | ".join(_md_cell(c) for c in row) + " |" for row in b[2]] + [""]
            elif b[0] == "code":
                out += [f"```{b[1]}", b[2].rstrip(), "```", ""]
            # images are left out of Markdown: they'd be megabytes of base64
    if not brand.get("hide_credit"):
        out += ["---", "Generated with Deconstruct Site."]
    return "\n".join(out).strip() + "\n"


# ---------------------------------------------------------------- HTML / PDF

def _inline(t: str) -> str:
    t = html.escape(t)
    t = re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
    t = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", t)
    return re.sub(r"(^|[^*])\*([^*\s][^*]*)\*", r"\1<i>\2</i>", t)


def md_to_html(src: str) -> str:
    """The same small Markdown subset the app renders: headings, bold/italic/code, lists, code fences."""
    out, lst = [], None
    parts = re.split(r"```(\w*)\n?([\s\S]*?)(?:```|$)", src or "")
    for i in range(0, len(parts), 3):
        for line in parts[i].split("\n"):
            line = line.rstrip()
            m = re.match(r"^(#{1,4})\s+(.*)", line) or None
            li = re.match(r"^\s*(?:[-*]|\d+[.)])\s+(.*)", line)
            if m:
                if lst: out.append("</ul>"); lst = None
                out.append(f"<h4>{_inline(m.group(2))}</h4>")
            elif li:
                if not lst: out.append("<ul>"); lst = "ul"
                out.append(f"<li>{_inline(li.group(1))}</li>")
            elif not line.strip():
                if lst: out.append("</ul>"); lst = None
            else:
                if lst: out.append("</ul>"); lst = None
                out.append(f"<p>{_inline(line)}</p>")
        if lst: out.append("</ul>"); lst = None
        if i + 2 < len(parts):
            out.append(f"<pre><code>{html.escape(parts[i + 2].rstrip())}</code></pre>")
    return "".join(out)


def to_html(title: str, subtitle: str, secs: list, branding: dict, *, auto_print: bool = False) -> str:
    brand = branding if branding.get("enabled") else {}
    color = brand.get("color") if re.fullmatch(r"#[0-9a-fA-F]{6}", brand.get("color") or "") else "#141414"
    logo = brand.get("logo") if str(brand.get("logo", "")).startswith("data:image/") else None
    body = []
    for heading, blocks in secs:
        body.append(f"<section><h2>{html.escape(heading)}</h2>")
        for b in blocks:
            if b[0] == "p":
                body.append(f"<p>{_inline(b[1])}</p>")
            elif b[0] == "md":
                body.append(f'<div class="md">{md_to_html(b[1])}</div>')
            elif b[0] == "list":
                body.append("<ul>" + "".join(f"<li>{_inline(i)}</li>" for i in b[1]) + "</ul>")
            elif b[0] == "table":
                body.append("<table><thead><tr>" + "".join(f"<th>{html.escape(h)}</th>" for h in b[1]) + "</tr></thead><tbody>"
                            + "".join("<tr>" + "".join(f"<td>{html.escape(str(c))}</td>" for c in row) + "</tr>" for row in b[2]) + "</tbody></table>")
            elif b[0] == "code":
                body.append(f"<pre><code>{html.escape(b[2])}</code></pre>")
            elif b[0] == "img":
                body.append(f'<img class="shot" src="{html.escape(b[1])}" alt="{html.escape(b[2])}">')
        body.append("</section>")
    head = ""
    if brand.get("name") or logo:
        logo_tag = f'<img src="{html.escape(logo)}" alt="">' if logo else ""
        contact = f"<br><span>{html.escape(brand['contact'][:200])}</span>" if brand.get("contact") else ""
        head = f'<div class="brand">{logo_tag}<div><b>{html.escape(brand.get("name", ""))}</b>{contact}</div></div>'
    credit = "" if brand.get("hide_credit") else '<footer>Generated with Deconstruct Site</footer>'
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="robots" content="noindex">
<title>{html.escape(title)}</title><style>
@page {{ size: A4; margin: 16mm 14mm; }}
* {{ box-sizing: border-box; }}
body {{ font: 10.5pt/1.5 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #1b1b1b; margin: 0; }}
.wrap {{ max-width: 780px; margin: 0 auto; padding: 24px; }}
.brand {{ display: flex; align-items: center; gap: 12px; padding-bottom: 12px; margin-bottom: 18px; border-bottom: 3px solid {color}; font-size: 10pt; color: #555; }}
.brand img {{ max-height: 44px; max-width: 160px; }}
.brand b {{ color: #111; font-size: 12pt; }}
h1 {{ font-size: 21pt; letter-spacing: -.02em; margin: 0 0 4px; color: {color}; }}
.sub {{ color: #666; margin: 0 0 18px; overflow-wrap: anywhere; }}
h2 {{ font-size: 13pt; margin: 22px 0 8px; padding-bottom: 4px; border-bottom: 1px solid #ddd; }}
h4 {{ font-size: 11pt; margin: 12px 0 4px; }}
section {{ break-inside: auto; }}
table {{ width: 100%; border-collapse: collapse; margin: 6px 0 10px; font-size: 9.5pt; }}
th, td {{ text-align: left; padding: 5px 7px; border-bottom: 1px solid #e5e5e5; vertical-align: top; overflow-wrap: anywhere; }}
th {{ background: #f4f4f2; }}
tr {{ break-inside: avoid; }}
pre {{ background: #f4f4f2; border-radius: 6px; padding: 9px 11px; font-size: 8.5pt; white-space: pre-wrap; overflow-wrap: anywhere; break-inside: avoid; }}
code {{ font-family: Consolas, "SF Mono", monospace; }}
.shot {{ width: 100%; border: 1px solid #ddd; border-radius: 6px; }}
footer {{ margin-top: 28px; padding-top: 8px; border-top: 1px solid #ddd; color: #888; font-size: 8.5pt; }}
@media print {{ .wrap {{ padding: 0; }} }}
</style></head><body><div class="wrap">{head}<h1>{html.escape(title)}</h1><p class="sub">{html.escape(subtitle)}</p>
{"".join(body)}{credit}</div>{"<script>window.addEventListener('load', () => setTimeout(() => print(), 300))</script>" if auto_print else ""}</body></html>"""


def to_pdf(html_doc: str) -> bytes | None:
    """Prints the HTML with headless Chromium; None when Playwright isn't installed. Every network request
    is blocked: the document is self-contained, and nothing in it should reach out."""
    if not browser.AVAILABLE:
        return None
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        b = p.chromium.launch()
        try:
            page = b.new_page()
            page.route("**/*", lambda route: route.abort())
            page.set_content(html_doc, wait_until="load")
            return page.pdf(format="A4", print_background=True, margin={"top": "14mm", "bottom": "14mm", "left": "12mm", "right": "12mm"})
        finally:
            b.close()
