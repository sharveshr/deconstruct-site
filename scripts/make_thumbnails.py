"""Regenerates the feature screenshots on the home page (static/img/features/*.jpg).

Run it against a running copy of the app, signed in as an account that already has an
analysis (with the browser pass), a second analysis to compare, a finished crawl, an
OSINT lookup and a monitored site:

    THUMB_EMAIL=you@example.com THUMB_PASSWORD=… python scripts/make_thumbnails.py --base http://localhost:5173

The script picks the newest analysis, crawl and OSINT target it finds.
"""
from __future__ import annotations

import argparse
import os

from playwright.sync_api import sync_playwright

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "img", "features")
SIZE = {"width": 1280, "height": 800}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://localhost:5173")
    args = ap.parse_args()
    base = args.base.rstrip("/")
    email, password = os.environ["THUMB_EMAIL"], os.environ["THUMB_PASSWORD"]
    os.makedirs(OUT, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context(viewport=SIZE, device_scale_factor=1, color_scheme="light", reduced_motion="reduce")
        api = ctx.request
        headers = {"X-Requested-With": "fetch"}
        r = api.post(f"{base}/api/auth/signin", data={"email": email, "password": password}, headers=headers)
        assert r.ok, f"Sign-in failed: {r.status} {r.text()[:200]}"
        get = lambda path: api.get(f"{base}{path}", headers=headers).json()["data"]
        analyses = [a for a in get("/api/analyses") if a.get("rendered")]
        main_a = next((a for a in analyses if a["host"] == "stripe.com"), analyses[0])
        other = next(a for a in analyses if a["site_id"] != main_a["site_id"])
        crawl = next(c for c in get("/api/crawls")["crawls"] if c["status"] == "done")
        target = get("/api/osint/recent")[0]["target"]
        site = next(s for s in get("/api/sites") if s["monitor_enabled"])
        page = ctx.new_page()

        def shot(name, hash_, before=None, wait=1500):
            page.goto(f"{base}/#{hash_}")
            page.wait_for_timeout(wait)
            if before:
                page.evaluate(before)
                page.wait_for_timeout(900)
            page.screenshot(path=os.path.join(OUT, f"{name}.jpg"), type="jpeg", quality=74)
            print("saved", name)

        tab = lambda t: (f"document.querySelector('nav.tabs button[data-tab=\"{t}\"]').click();"
                         "window.scrollTo(0, document.querySelector('nav.tabs').getBoundingClientRect().top + scrollY - 8)")
        a = f"/analyses/{main_a['id']}"
        shot("report", a, wait=2500)
        shot("design", a, tab("design"))
        shot("performance", a, tab("perf"))
        shot("accessibility", a, tab("a11y"))
        shot("security", a, tab("security"))
        shot("crawl", f"/crawls/{crawl['id']}", wait=2500)
        shot("osint", f"/osint?target={target}", "document.getElementById('osint-lookalikes').scrollIntoView({block: 'start'}); window.scrollBy(0, -12)", wait=2500)
        shot("uptime", f"/sites/{site['id']}?tab=uptime", wait=2000)
        shot("alerts", "/alerts", wait=2000)
        shot("compare", f"/compare?a={other['id']}&b={main_a['id']}", wait=2500)
        browser.close()


if __name__ == "__main__":
    main()
