"""Deconstruct Site: paste a URL, get a full breakdown of how the site is built.

Also keeps a library of analyzed sites: projects that group them, every
analysis saved as an iteration, an uptime log per site, and change alerts
raised when a newer result differs from the previous one.
"""
import hmac
import os
from datetime import datetime, timezone

from flask import Flask, Response, abort, jsonify, request, send_from_directory

import browser
import monitor
import notify
import osint
import store
import watch
from analyzer import AnalysisError, analyze
from compare import compare

app = Flask(__name__, static_folder="static")
APP_PASSWORD = os.environ.get("APP_PASSWORD")
# Vercel runs each request in a short-lived function: no background threads, no Chromium
SERVERLESS = bool(os.environ.get("VERCEL"))


@app.before_request
def require_password():
    """With APP_PASSWORD set, every page and API call needs it (any username) via HTTP Basic auth."""
    if not APP_PASSWORD:
        return None
    auth = request.authorization
    if auth and hmac.compare_digest((auth.password or "").encode(), APP_PASSWORD.encode()):
        return None
    return Response("Password required.", 401, {"WWW-Authenticate": 'Basic realm="Deconstruct Site"'})


def ok(data=None, status=200):
    return jsonify(ok=True, data=data), status


def fail(error, status=400):
    return jsonify(ok=False, error=error), status


def body() -> dict:
    return request.get_json(silent=True) or {}


def need(value, what="Not found"):
    if value is None:
        abort(404, what)
    return value


@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return fail(getattr(e, "description", "Not found"), 404)
    return send_from_directory(app.static_folder, "index.html")


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


# ---------------------------------------------------------------- analysis

@app.post("/api/analyze")
def api_analyze():
    b = body()
    url = str(b.get("url", "")).strip()
    if not url:
        return fail("Enter a URL.")
    try:
        runs = max(1, min(5, int(b.get("perf_runs", 3))))
    except (TypeError, ValueError):
        return fail("perf_runs must be a number from 1 to 5.")
    try:
        report = analyze(url, render=browser.AVAILABLE and b.get("render", True) is not False, perf_runs=runs)
    except AnalysisError as e:
        return fail(str(e), 422)
    saved = watch.save_analysis(url, report, label=str(b.get("label", "")), project_id=b.get("project_id"))
    return ok({"report": report, "analysis_id": saved["id"], "iteration": saved["iteration"],
               "site": saved["site"], "created_at": saved["created_at"], "events": saved["events"]})


@app.get("/api/analyses")
def api_analyses():
    site_id = request.args.get("site_id", type=int)
    return ok(store.list_analyses(site_id, limit=request.args.get("limit", 200, type=int)))


@app.get("/api/analyses/<int:aid>")
def api_analysis(aid):
    return ok(need(store.get_analysis(aid), "That analysis doesn't exist."))


@app.patch("/api/analyses/<int:aid>")
def api_analysis_update(aid):
    need(store.get_analysis(aid))
    store.update_analysis_label(aid, str(body().get("label", "")))
    return ok()


@app.delete("/api/analyses/<int:aid>")
def api_analysis_delete(aid):
    store.delete_analysis(aid)
    return ok()


@app.get("/api/compare")
def api_compare():
    a = need(store.get_analysis(request.args.get("a", type=int)), "First analysis not found.")
    b = need(store.get_analysis(request.args.get("b", type=int)), "Second analysis not found.")
    same_site = a["site_id"] == b["site_id"]
    # Two runs of one site read as before → after; two different sites keep the order the user picked.
    if same_site and (a["created_at"], a["id"]) > (b["created_at"], b["id"]):
        a, b = b, a
    meta = lambda x: {k: x[k] for k in ("id", "site_id", "url", "host", "created_at", "label", "iteration")} | {
        "title": x["report"]["overview"]["title"], "favicon": x["report"]["overview"]["favicon"]}
    return ok({"a": meta(a), "b": meta(b), "same_site": same_site, "diff": compare(a["report"], b["report"])})


# ---------------------------------------------------------------- projects

@app.get("/api/projects")
def api_projects():
    return ok(store.list_projects())


@app.post("/api/projects")
def api_project_create():
    name = str(body().get("name", "")).strip()
    if not name:
        return fail("Give the project a name.")
    return ok(store.create_project(name, str(body().get("description", ""))), 201)


@app.get("/api/projects/<int:pid>")
def api_project(pid):
    return ok(need(store.get_project(pid), "That project doesn't exist."))


@app.patch("/api/projects/<int:pid>")
def api_project_update(pid):
    need(store.get_project(pid))
    b = body()
    store.update_project(pid, b.get("name"), b.get("description"))
    return ok()


@app.delete("/api/projects/<int:pid>")
def api_project_delete(pid):
    store.delete_project(pid)
    return ok()


@app.post("/api/projects/<int:pid>/sites")
def api_project_add_site(pid):
    need(store.get_project(pid))
    b = body()
    if b.get("site_id"):
        site = need(store.get_site(int(b["site_id"])))
    elif b.get("url"):
        site = store.get_or_create_site(str(b["url"]).strip())
    else:
        return fail("Give a site_id or url.")
    store.add_site_to_project(pid, site["id"])
    return ok(site, 201)


@app.post("/api/projects/<int:pid>/watch")
def api_project_watch(pid):
    """Applies one watch schedule to every site in a project."""
    p = need(store.get_project(pid), "That project doesn't exist.")
    b = body()
    try:
        for s in p["sites"]:
            store.update_site(s["id"], watch_analyze_hours=b.get("watch_analyze_hours"), watch_osint_hours=b.get("watch_osint_hours"),
                              monitor_enabled=b.get("monitor_enabled"), monitor_interval_min=b.get("monitor_interval_min"))
    except (ValueError, TypeError) as e:
        return fail(str(e))
    return ok({"sites": len(p["sites"])})


@app.delete("/api/projects/<int:pid>/sites/<int:sid>")
def api_project_remove_site(pid, sid):
    store.remove_site_from_project(pid, sid)
    return ok()


# ---------------------------------------------------------------- sites & uptime

@app.get("/api/sites")
def api_sites():
    sites = store.list_sites()
    for s in sites:
        s["uptime_24h"] = store.uptime_stats(s["id"], 1)["uptime_pct"]
        s["latest"] = store.latest_summary(s["id"], with_thumb=False)
    return ok(sites)


@app.get("/api/sites/<int:sid>")
def api_site(sid):
    site = need(store.get_site(sid), "That site doesn't exist.")
    site["projects"] = store.projects_for_site(sid)
    site["iterations"] = list(reversed(store.list_analyses(sid)))
    site["latest"] = store.latest_summary(sid)
    site["uptime"] = {label: store.uptime_stats(sid, days) for label, days in (("24h", 1), ("7d", 7), ("30d", 30))}
    return ok(site)


@app.patch("/api/sites/<int:sid>")
def api_site_update(sid):
    need(store.get_site(sid))
    b = body()
    try:
        store.update_site(sid, monitor_enabled=b.get("monitor_enabled"), monitor_interval_min=b.get("monitor_interval_min"),
                          title=b.get("title"), watch_analyze_hours=b.get("watch_analyze_hours"),
                          watch_osint_hours=b.get("watch_osint_hours"))
    except (ValueError, TypeError) as e:
        return fail(str(e))
    return ok(store.get_site(sid))


@app.delete("/api/sites/<int:sid>")
def api_site_delete(sid):
    store.delete_site(sid)
    return ok()


@app.get("/api/sites/<int:sid>/checks")
def api_checks(sid):
    need(store.get_site(sid))
    return ok(store.list_checks(sid, days=request.args.get("days", 7, type=float)))


@app.post("/api/sites/<int:sid>/checks")
def api_check_log(sid):
    """Log an up/down event by hand, e.g. an outage noticed before monitoring was on."""
    need(store.get_site(sid))
    b = body()
    status = b.get("status")
    if status not in ("up", "down"):
        return fail("Status must be 'up' or 'down'.")
    at = b.get("at")
    if at:
        try:
            dt = datetime.fromisoformat(str(at).replace("Z", "+00:00"))
        except ValueError:
            return fail("Couldn't read that date and time.")
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        if dt > datetime.now(timezone.utc):
            return fail("That time is in the future.")
        at = dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return ok(store.record_check(sid, status, source="manual", note=str(b.get("note", "")), checked_at=at), 201)


@app.post("/api/sites/<int:sid>/check-now")
def api_check_now(sid):
    site = need(store.get_site(sid))
    return ok(monitor.check_site(site, source="auto"))


@app.delete("/api/checks/<int:cid>")
def api_check_delete(cid):
    store.delete_check(cid)
    return ok()


# ---------------------------------------------------------------- OSINT

@app.get("/api/osint/tools")
def api_osint_tools():
    return ok(list(osint.TOOLS))


@app.get("/api/osint/recent")
def api_osint_recent():
    return ok(store.recent_osint_targets())


@app.get("/api/osint/saved")
def api_osint_saved():
    try:
        target = osint.normalize_target(request.args.get("target", ""))
    except osint.OsintError as e:
        return fail(str(e))
    return ok({"target": target, "results": store.latest_osint(target)})


@app.delete("/api/osint/saved")
def api_osint_forget():
    store.delete_osint_target(request.args.get("target", ""))
    return ok()


@app.get("/api/osint/<tool>")
def api_osint(tool):
    if tool not in osint.TOOLS:
        return fail(f"Unknown tool: {tool}", 404)
    try:
        target = osint.normalize_target(request.args.get("target", ""))
    except osint.OsintError as e:
        return fail(str(e))
    success, result = watch.run_osint(tool, target)
    return ok(result) if success else fail(result["error"], result["status"])


# ---------------------------------------------------------------- alerts

@app.get("/api/events")
def api_events():
    a = request.args
    severity = a.get("severity", "info")
    if severity not in store.SEVERITY_RANK:
        return fail("severity must be info, warning or critical.")
    return ok(store.list_events(site_id=a.get("site_id", type=int), target=a.get("target"), min_severity=severity,
                                unread_only=a.get("unread") == "1", kind=a.get("kind"), before_id=a.get("before", type=int),
                                limit=min(500, a.get("limit", 100, type=int))))


@app.get("/api/events/unread")
def api_events_unread():
    return ok(store.unread_counts())


@app.post("/api/events/read")
def api_events_read():
    """Body: {"ids": [..]} or {"all": true}; "read": false marks them unread."""
    b = body()
    ids = None if b.get("all") else [int(i) for i in b.get("ids", [])]
    store.mark_events_read(ids, read=b.get("read", True) is not False)
    return ok(store.unread_counts())


@app.post("/api/events/delete")
def api_events_delete():
    b = body()
    store.delete_events(None if b.get("all") else [int(i) for i in b.get("ids", [])])
    return ok()


@app.get("/api/channels")
def api_channels():
    return ok({"channels": store.list_channels(), "email_configured": bool(os.environ.get("SMTP_HOST")), "app_url": notify.APP_URL})


@app.post("/api/channels")
def api_channel_create():
    b = body()
    kind, target = str(b.get("kind", "")), str(b.get("target", "")).strip()
    severity = b.get("min_severity", "warning")
    if severity not in store.SEVERITY_RANK:
        return fail("min_severity must be info, warning or critical.")
    err = notify.validate(kind, target)
    if err:
        return fail(err)
    name = str(b.get("name") or "").strip() or {"webhook": "Webhook", "slack": "Slack", "discord": "Discord", "email": target}[kind]
    return ok(store.create_channel(kind, name, target, severity), 201)


@app.patch("/api/channels/<int:cid>")
def api_channel_update(cid):
    ch = need(store.get_channel(cid), "That channel doesn't exist.")
    b = body()
    if b.get("min_severity") is not None and b["min_severity"] not in store.SEVERITY_RANK:
        return fail("min_severity must be info, warning or critical.")
    if b.get("target") is not None:
        err = notify.validate(ch["kind"], b["target"])
        if err:
            return fail(err)
    store.update_channel(cid, name=b.get("name"), target=b.get("target"), min_severity=b.get("min_severity"), enabled=b.get("enabled"))
    return ok(store.get_channel(cid))


@app.delete("/api/channels/<int:cid>")
def api_channel_delete(cid):
    store.delete_channel(cid)
    return ok()


@app.post("/api/channels/<int:cid>/test")
def api_channel_test(cid):
    ch = need(store.get_channel(cid), "That channel doesn't exist.")
    err = notify.send_one(ch, notify.test_event())
    return fail(f"Sending failed: {err}", 502) if err else ok({"sent": True})


@app.get("/api/watch")
def api_watch():
    """Every site with its watch schedule, for the alerts settings page."""
    return ok({"sites": store.list_sites(), "tools": watch.WATCH_TOOLS, "hours": store.WATCH_HOURS})


@app.get("/api/health")
def health():
    return ok({"browser": browser.AVAILABLE, "background": not SERVERLESS})


store.init()

if __name__ == "__main__":
    monitor.start()
    watch.start()
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5173)), debug=False, threaded=True)
