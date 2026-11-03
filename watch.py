"""Change detection and scheduled watching.

Every saved analysis is compared with the site's previous one, and every
saved OSINT result with the previous run of the same tool. Differences that
matter become events (info / warning / critical), which are stored and sent
to the notification channels. A background thread re-runs analyses and OSINT
lookups for sites that have a watch schedule.

The same functions save results for the API and for the scheduler, so a
change is detected no matter how the new result came in.
"""
from __future__ import annotations

import logging
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import notify
import osint
import store
from analyzer import AnalysisError, analyze
from compare import compare

log = logging.getLogger("watch")

# OSINT tools refreshed on a schedule: the ones whose changes are worth an alert.
WATCH_TOOLS = ["dns", "rdap", "ssl", "subdomains", "headers", "email", "redirects", "robots", "tech"]
SCORE_LABELS = {"performance": "Performance", "seo": "SEO", "accessibility": "Accessibility", "security": "Security"}
DMARC_STRENGTH = {None: 0, "none": 1, "quarantine": 2, "reject": 3}
NOTABLE_SUB = re.compile(r"(^|[.-])(dev|staging|stage|test|qa|uat|admin|internal|vpn|jenkins|git|grafana|kibana|old|beta)([.-]|$)")


def _today():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class _Collector:
    """Builds the events for one result, then stores and dispatches them together."""

    def __init__(self, site_id=None, target=None, links=None):
        self.site_id, self.target, self.links = site_id, target, links or {}
        self.events = []

    def add(self, kind, severity, title, lines=None, *, dedup_key=None, dedup_days=None, **extra):
        ev = store.add_event(kind, severity, title, site_id=self.site_id, target=self.target,
                             detail={"lines": lines or [], "links": self.links, **extra},
                             dedup_key=dedup_key, dedup_days=dedup_days)
        if ev:
            self.events.append(ev)

    def flush(self):
        if self.events:
            notify.dispatch(self.events)
        return self.events


# ---------------------------------------------------------------- shared rules

def _cert_expiry(ev: _Collector, host: str, days_left, not_after, source: str):
    if days_left is None:
        return
    stamp = (not_after or "")[:10]
    if days_left < 0:
        ev.add("cert_expired", "critical", f"TLS certificate for {host} has expired",
               [f"Expired {-days_left} days ago ({stamp})."], dedup_key=f"cert:{host}:{stamp}:expired", source=source)
    elif days_left <= 3:
        ev.add("cert_expiring", "critical", f"TLS certificate for {host} expires in {days_left} days",
               [f"Expires {stamp}."], dedup_key=f"cert:{host}:{stamp}:3", source=source)
    elif days_left <= 14:
        ev.add("cert_expiring", "warning", f"TLS certificate for {host} expires in {days_left} days",
               [f"Expires {stamp}. Check that automatic renewal is working."], dedup_key=f"cert:{host}:{stamp}:14", source=source)


def _header_changes(ev: _Collector, host: str, removed, added):
    for h in removed:
        ev.add("header_removed", "warning", f"{host} stopped sending {h}",
               [f"The {h} security header was present before and is missing now."],
               dedup_key=f"header-removed:{host}:{h}:{_today()}", dedup_days=1)
    if added:
        ev.add("header_added", "info", f"{host} added security header{'s' if len(added) > 1 else ''}: {', '.join(added)}",
               dedup_key=f"header-added:{host}:{','.join(sorted(added))}:{_today()}", dedup_days=1)


def _tech_changes(ev: _Collector, host: str, added, removed, versions):
    if added:
        ev.add("tech_added", "info", f"New technology on {host}: {', '.join(added[:6])}{'…' if len(added) > 6 else ''}",
               [f"Detected for the first time: {', '.join(added)}."],
               dedup_key=f"tech-added:{host}:{','.join(sorted(added))}:{_today()}", dedup_days=1)
    if removed:
        ev.add("tech_removed", "info", f"Technology no longer detected on {host}: {', '.join(removed[:6])}",
               dedup_key=f"tech-removed:{host}:{','.join(sorted(removed))}:{_today()}", dedup_days=1)
    for v in versions:
        ev.add("tech_version", "info", f"{v['name']} on {host} changed version: {v['from']} → {v['to']}",
               dedup_key=f"tech-ver:{host}:{v['name']}:{v['to']}", dedup_days=None)


# ---------------------------------------------------------------- analyses

def detect_analysis(site: dict, analysis_id: int, report: dict) -> list[dict]:
    host = site["host"]
    prev = store.previous_analysis(site["id"], analysis_id, mode=store.analysis_mode(report))
    ev = _Collector(site_id=site["id"], target=host,
                    links={"analysis": analysis_id, **({"compare": [prev["id"], analysis_id]} if prev else {})})
    tls = (report.get("security") or {}).get("tls") or {}
    if tls.get("valid"):
        _cert_expiry(ev, host, tls.get("days_left"), tls.get("expires"), "analysis")
    elif tls.get("valid") is False:
        ev.add("cert_invalid", "critical", f"TLS certificate for {host} doesn't validate", [tls.get("error") or ""],
               dedup_key=f"cert-invalid:{host}:{_today()}", dedup_days=1)
    if not prev:
        return ev.flush()

    d = compare(prev["report"], report)
    for key, s in d["scores"].items():
        if s["delta"] <= -10:
            ev.add("score_drop", "critical" if s["delta"] <= -25 else "warning",
                   f"{SCORE_LABELS[key]} score for {host} dropped {s['from']} → {s['to']}",
                   [f"Down {-s['delta']} points since iteration {prev['iteration']}."], metric=key)
        elif s["delta"] >= 10:
            ev.add("score_rise", "info", f"{SCORE_LABELS[key]} score for {host} improved {s['from']} → {s['to']}", metric=key)

    c = d["content"]
    if "status" in c:
        bad = (c["status"]["to"] or 0) >= 400
        ev.add("status_changed", "critical" if bad else "info",
               f"{host} now returns HTTP {c['status']['to']} (was {c['status']['from']})")
    if "final_url" in c:
        ev.add("redirect_changed", "warning", f"{host} now lands on a different URL",
               [f"{c['final_url']['from']} → {c['final_url']['to']}"])
    if "title" in c:
        ev.add("title_changed", "info", f"Page title on {host} changed", [f"“{c['title']['from']}” → “{c['title']['to']}”"])

    _tech_changes(ev, host, d["tech"]["added"], d["tech"]["removed"], d["tech"]["version_changed"])
    _header_changes(ev, host, d["security_headers"]["removed"], d["security_headers"]["added"])

    w = d["metrics"]["page_bytes"]
    if w["from"] and w["to"] and w["to"] - w["from"] > 500_000 and w["to"] > w["from"] * 1.5:
        ev.add("weight_jump", "warning", f"Page weight on {host} grew {w['from'] // 1024} KB → {w['to'] // 1024} KB")
    lcp = (d["vitals"] or {}).get("lcp") or {}
    if lcp.get("from") and lcp.get("to") and lcp["from"] <= 4000 < lcp["to"]:
        ev.add("vitals_poor", "warning", f"Largest Contentful Paint on {host} is now poor ({lcp['to'] / 1000:.1f} s)",
               [f"Was {lcp['from'] / 1000:.1f} s. Lab vitals vary between runs, so check whether it persists."])
    new_issues = sum(len(v["new"]) for v in d["issues"].values())
    if new_issues >= 3:
        ev.add("issues_new", "info", f"{new_issues} new issues found on {host}",
               [i for v in d["issues"].values() for i in v["new"]][:8])
    return ev.flush()


def save_analysis(url: str, report: dict, *, label: str = "", project_id=None) -> dict:
    """Saves an analysis as a new iteration and runs change detection on it."""
    site = store.get_or_create_site(url, report["overview"]["title"] or None)
    saved = store.save_analysis(site["id"], report, label)
    if project_id:
        store.add_site_to_project(int(project_id), site["id"])
    try:
        events = detect_analysis(site, saved["id"], report)
    except Exception:  # detection must never lose the analysis itself
        log.exception("change detection failed for analysis %s", saved["id"])
        events = []
    return saved | {"site": store.get_site(site["id"]), "events": events}


# ---------------------------------------------------------------- OSINT

def _set(records):
    return {r["data"] for r in records}


def detect_osint(target: str, tool: str, run_id: int, data: dict) -> list[dict]:
    site = store.site_for_host(target)
    ev = _Collector(site_id=site["id"] if site else None, target=target, links={"osint": target})
    prev_run = store.previous_osint(target, tool, run_id)
    prev = prev_run.get("data") if prev_run else None

    if tool == "ssl":
        _cert_expiry(ev, target, data.get("days_left"), data.get("not_after"), "osint")
        if not data.get("valid"):
            ev.add("cert_invalid", "critical", f"TLS certificate for {target} doesn't validate", [data.get("verify_error") or ""],
                   dedup_key=f"cert-invalid:{target}:{_today()}", dedup_days=1)
        if prev:
            if prev.get("issuer") and data.get("issuer") and prev["issuer"] != data["issuer"]:
                ev.add("cert_issuer", "info", f"{target} switched certificate authority: {prev['issuer']} → {data['issuer']}")
            for v in ("TLS 1.0", "TLS 1.1"):
                if data["versions"].get(v) and not prev["versions"].get(v):
                    ev.add("tls_downgrade", "warning", f"{target} now accepts deprecated {v}")

    elif tool == "rdap":
        days = data.get("days_until_expiry")
        if days is not None:
            stamp = (data.get("expires") or "")[:10]
            if days <= 7:
                ev.add("domain_expiring", "critical", f"Domain {data['domain']} expires in {days} days", [f"Expiry: {stamp}."],
                       dedup_key=f"domain:{data['domain']}:{stamp}:7")
            elif days <= 30:
                ev.add("domain_expiring", "warning", f"Domain {data['domain']} expires in {days} days",
                       [f"Expiry: {stamp}. Renew it or confirm auto-renew is on."], dedup_key=f"domain:{data['domain']}:{stamp}:30")
        if prev:
            if prev.get("registrar") != data.get("registrar"):
                ev.add("registrar_changed", "warning", f"Registrar for {data['domain']} changed",
                       [f"{prev.get('registrar')} → {data.get('registrar')}"])
            if set(prev.get("nameservers", [])) != set(data.get("nameservers", [])):
                ev.add("nameservers_changed", "warning", f"Nameservers for {data['domain']} changed",
                       [f"Was: {', '.join(prev.get('nameservers', []))}", f"Now: {', '.join(data.get('nameservers', []))}"])
            danger = [s for s in set(data.get("status", [])) - set(prev.get("status", []))
                      if re.search(r"hold|redemption|pending ?delete", s, re.I)]
            if danger:
                ev.add("domain_status", "critical", f"Domain {data['domain']} entered status {', '.join(danger)}")
            if prev.get("dnssec") != data.get("dnssec") and data.get("dnssec") is not None:
                ev.add("dnssec_changed", "info" if data["dnssec"] else "warning",
                       f"DNSSEC {'enabled' if data['dnssec'] else 'disabled'} for {data['domain']}")

    elif tool == "subdomains" and prev:
        if prev.get("source") == data.get("source") and prev.get("count", 0) <= 1000 and data.get("count", 0) <= 1000:
            before = {s["name"] for s in prev.get("subdomains", [])}
            new = sorted({s["name"] for s in data.get("subdomains", [])} - before)
            if new:
                notable = [n for n in new if NOTABLE_SUB.search(n.removesuffix(data["domain"]))]
                ev.add("new_subdomains", "warning" if notable else "info",
                       f"{len(new)} new subdomain{'s' if len(new) > 1 else ''} on certificates for {data['domain']}",
                       new[:25] + ([f"…and {len(new) - 25} more"] if len(new) > 25 else []), names=new[:200])

    elif tool == "dns" and prev:
        for rtype, severity in (("NS", "warning"), ("MX", "warning"), ("A", "info"), ("AAAA", "info"), ("CNAME", "info"), ("CAA", "info"), ("TXT", "info")):
            a, b = _set(prev["records"].get(rtype, [])), _set(data["records"].get(rtype, []))
            if a == b:
                continue
            # Load balancers rotate addresses; only report A/AAAA when the whole set changed.
            if rtype in ("A", "AAAA") and a & b:
                continue
            added, removed = sorted(b - a), sorted(a - b)
            ev.add("dns_changed", severity, f"{rtype} records for {target} changed",
                   [f"+ {x}" for x in added][:10] + [f"− {x}" for x in removed][:10], rtype=rtype)

    elif tool == "email" and prev:
        pd, nd = (prev.get("dmarc") or {}).get("policy"), (data.get("dmarc") or {}).get("policy")
        if pd != nd:
            weaker = DMARC_STRENGTH.get(nd, 0) < DMARC_STRENGTH.get(pd, 0)
            ev.add("dmarc_changed", "warning" if weaker else "info",
                   f"DMARC policy for {data['domain']} changed: {pd or 'none published'} → {nd or 'removed'}")
        ps, ns = (prev.get("spf") or {}).get("record"), (data.get("spf") or {}).get("record")
        if ps != ns:
            ev.add("spf_changed", "warning" if not ns else "info",
                   f"SPF record for {data['domain']} {'was removed' if not ns else 'changed'}",
                   [f"Was: {ps or '—'}", f"Now: {ns or '—'}"])
        if "ABCDF".index(data["grade"]) > "ABCDF".index(prev["grade"]):
            ev.add("email_grade", "warning", f"Email security grade for {data['domain']} dropped {prev['grade']} → {data['grade']}",
                   data.get("issues", [])[:6])

    elif tool == "headers" and prev:
        removed = [c["name"] for c in data["checks"] if not c["present"]
                   and any(p["name"] == c["name"] and p["present"] for p in prev["checks"])]
        added = [c["name"] for c in data["checks"] if c["present"]
                 and any(p["name"] == c["name"] and not p["present"] for p in prev["checks"])]
        _header_changes(ev, target, removed, added)

    elif tool == "redirects" and prev:
        if prev.get("canonical") and data.get("canonical") and prev["canonical"] != data["canonical"]:
            ev.add("redirect_changed", "warning", f"Canonical address for {target} changed",
                   [f"{prev['canonical']} → {data['canonical']}"])
        http_ok = lambda r: all(c["final_url"] is None or c["final_url"].startswith("https://") for c in r["chains"])
        if http_ok(prev) and not http_ok(data):
            ev.add("https_redirect_lost", "warning", f"{target} no longer redirects plain HTTP to HTTPS")

    elif tool == "robots" and prev:
        blocks_all = lambda r: any("Disallow: /" in i or "blocked from the whole site" in i for i in r.get("issues", []))
        if blocks_all(data) and not blocks_all(prev):
            ev.add("robots_block_all", "critical", f"robots.txt on {target} now blocks all crawlers",
                   ["Search engines will drop the site if this stays. Often caused by deploying a staging robots.txt."])
        if prev.get("exists") and not data.get("exists"):
            ev.add("robots_missing", "warning", f"robots.txt on {target} disappeared", data.get("issues", []))

    elif tool == "tech" and prev:
        names = lambda r: {t["name"]: t.get("version") for ts in r["by_category"].values() for t in ts}
        a, b = names(prev), names(data)
        versions = [{"name": n, "from": a[n], "to": b[n]} for n in set(a) & set(b) if a[n] and b[n] and a[n] != b[n]]
        _tech_changes(ev, target, sorted(set(b) - set(a)), sorted(set(a) - set(b)), versions)

    return ev.flush()


def run_osint(tool: str, target: str) -> tuple[bool, dict]:
    """Runs one OSINT tool, saves the result and runs change detection.
    Returns (ok, result-or-error) where result is osint.run()'s dict plus 'events'."""
    t0 = time.perf_counter()
    try:
        result = osint.run(tool, target)
    except osint.OsintError as e:
        store.save_osint(target, tool, False, {"error": str(e)}, round((time.perf_counter() - t0) * 1000))
        return False, {"error": str(e), "status": 422}
    except Exception as e:  # one failing source shouldn't look like a server crash
        log.exception("osint %s failed", tool)
        msg = f"{tool} lookup failed: {type(e).__name__}: {str(e)[:200]}"
        store.save_osint(target, tool, False, {"error": msg}, round((time.perf_counter() - t0) * 1000))
        return False, {"error": msg, "status": 502}
    run_id = store.save_osint(target, tool, True, {"data": result["data"]}, result["ms"])
    try:
        events = detect_osint(target, tool, run_id, result["data"])
    except Exception:
        log.exception("change detection failed for osint %s/%s", target, tool)
        events = []
    return True, result | {"events": events}


# ---------------------------------------------------------------- uptime

def on_status_change(site: dict, previous: str | None, check: dict):
    """Called by the monitor after a check whose status differs from the last one."""
    host = site["host"]
    ev = _Collector(site_id=site["id"], target=host, links={"uptime": site["id"]})
    if check["status"] == "down":
        ev.add("site_down", "critical", f"{host} is DOWN",
               [check.get("error") or f"HTTP {check.get('http_status')}", f"Checked {site['url']}"],
               dedup_key=f"down:{site['id']}:{check['checked_at']}")
    elif previous == "down":
        since = site.get("last_change_at")
        mins = None
        if since:
            mins = round((datetime.now(timezone.utc) - store.parse_iso(since)).total_seconds() / 60)
        ev.add("site_up", "info", f"{host} is back UP", [f"Down for about {mins} minutes." if mins is not None else "Recovered."],
               dedup_key=f"up:{site['id']}:{check['checked_at']}")
    return ev.flush()


# ---------------------------------------------------------------- scheduler

def _scheduled_analysis(site):
    store.mark_watch_run(site["id"], "analyze")
    try:
        report = analyze(site["url"], render=True)
    except AnalysisError as e:
        _Collector(site_id=site["id"], target=site["host"], links={"site": site["id"]}).add(
            "watch_failed", "warning", f"Scheduled analysis of {site['host']} failed", [str(e)],
            dedup_key=f"watch-failed:{site['id']}:{_today()}", dedup_days=1)
        return
    save_analysis(site["url"], report, label="scheduled")


def _scheduled_osint(site):
    store.mark_watch_run(site["id"], "osint")
    with ThreadPoolExecutor(4) as pool:
        list(pool.map(lambda t: run_osint(t, site["host"]), WATCH_TOOLS))


def _loop():
    last_prune = 0.0
    while True:
        try:
            for site in store.sites_due_for_watch("osint"):
                _scheduled_osint(site)
            # Browser analyses are heavy, so they run one at a time.
            for site in store.sites_due_for_watch("analyze"):
                _scheduled_analysis(site)
            if time.time() - last_prune > 6 * 3600:
                store.prune_events()
                last_prune = time.time()
        except Exception:
            log.exception("watch tick failed")
        time.sleep(60)


_started = False


def start():
    global _started
    if _started:
        return
    _started = True
    threading.Thread(target=_loop, name="watcher", daemon=True).start()
