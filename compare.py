"""Diffs two saved analyses of a site (or of two different sites)."""
from __future__ import annotations

import re


def _techs(r):
    return {t["name"]: t.get("version") for ts in r["technologies"]["by_category"].values() for t in ts}


def _issues(r):
    return {"performance": r["performance"]["issues"], "seo": r["seo"]["issues"], "accessibility": r["accessibility"]["issues"]}


def _shape(text):
    # "12 images are missing alt" and "9 images are missing alt" are the same issue with a new count
    return re.sub(r"[\d.,]+", "#", text)


def _solid_colors(r, n=16):
    return [c["value"] for c in r["design"]["colors"] if len(c["value"]) == 7][:n]


def _fonts(r):
    computed = (r["design"].get("computed") or {}).get("fonts_by_text")
    return [f["value"] for f in (computed or r["design"]["fonts"])][:8]


def page_bytes(r):
    """Bytes the browser actually transferred when available. The HTTP-probe total depends on
    which files happen to report a Content-Length, so it can double between identical runs."""
    v = r["performance"].get("vitals") or {}
    return v.get("transfer_bytes") or r["performance"]["total_known_bytes"]


def _delta(a, b):
    if a is None or b is None:
        return None
    return b - a


def compare(a: dict, b: dict) -> dict:
    """`a` is the older/baseline report, `b` the newer one."""
    ta, tb = _techs(a), _techs(b)
    tech = {
        "added": sorted(set(tb) - set(ta)),
        "removed": sorted(set(ta) - set(tb)),
        "version_changed": sorted([{"name": n, "from": ta[n], "to": tb[n]} for n in set(ta) & set(tb)
                                   if ta[n] and tb[n] and ta[n] != tb[n]], key=lambda x: x["name"]),
        "unchanged": sorted(set(ta) & set(tb)),
    }

    issues = {}
    ia, ib = _issues(a), _issues(b)
    for cat in ia:
        sa = {_shape(i): i for i in ia[cat]}
        sb = {_shape(i): i for i in ib[cat]}
        issues[cat] = {
            "new": [sb[k] for k in sb if k not in sa],
            "resolved": [sa[k] for k in sa if k not in sb],
            "changed": [{"from": sa[k], "to": sb[k]} for k in sb if k in sa and sa[k] != sb[k]],
        }

    va = a["performance"].get("vitals") or {}
    vb = b["performance"].get("vitals") or {}
    vitals = {k: {"from": va.get(k), "to": vb.get(k), "delta": _delta(va.get(k), vb.get(k))}
              for k in ("lcp", "fcp", "tbt", "cls", "ttfb")} if (va or vb) else None

    def metric(path_a, path_b=None):
        x, y = path_a(a), (path_b or path_a)(b)
        return {"from": x, "to": y, "delta": _delta(x, y)}

    ha = {h["name"]: h["present"] for h in a["security"]["headers"]}
    hb = {h["name"]: h["present"] for h in b["security"]["headers"]}
    ca, cb = _solid_colors(a), _solid_colors(b)
    fa, fb = _fonts(a), _fonts(b)

    content = {}
    for key, get in (("title", lambda r: r["overview"]["title"]), ("description", lambda r: r["overview"]["description"]),
                     ("final_url", lambda r: r["overview"]["final_url"]), ("status", lambda r: r["overview"]["status"]),
                     ("server", lambda r: r["overview"]["server"])):
        if get(a) != get(b):
            content[key] = {"from": get(a), "to": get(b)}

    return {
        "scores": {k: {"from": a["scores"][k], "to": b["scores"][k], "delta": b["scores"][k] - a["scores"][k]} for k in b["scores"]},
        "vitals": vitals,
        "metrics": {
            "page_bytes": metric(page_bytes),
            "requests": metric(lambda r: r["performance"].get("browser_request_count") or r["performance"]["request_count"]),
            "html_bytes": metric(lambda r: r["performance"]["html_size"]),
            "server_ms": metric(lambda r: r["performance"]["server_response_ms"]),
            "words": metric(lambda r: r["structure"]["word_count"]),
            "css_variables": metric(lambda r: r["design"]["css_variable_count"]),
            "contrast_failures": metric(lambda r: (r["accessibility"].get("contrast") or {}).get("failing_elements")),
        },
        "tech": tech,
        "issues": issues,
        "security_headers": {
            "added": sorted(k for k in hb if hb[k] and not ha.get(k)),
            "removed": sorted(k for k in ha if ha[k] and not hb.get(k)),
        },
        "design": {
            "colors_added": [c for c in cb if c not in ca],
            "colors_removed": [c for c in ca if c not in cb],
            "fonts_added": [f for f in fb if f not in fa],
            "fonts_removed": [f for f in fa if f not in fb],
        },
        "content": content,
        "screenshots": {
            "from": ((a.get("browser") or {}).get("screenshots") or {}).get("above_fold"),
            "to": ((b.get("browser") or {}).get("screenshots") or {}).get("above_fold"),
        },
    }
