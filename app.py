"""Deconstruct Site: paste a URL, get a full breakdown of how the site is built.

Also keeps a library of analyzed sites: projects that group them, every
analysis saved as an iteration, and an uptime log per site.
"""
import os
from datetime import datetime, timezone

from flask import Flask, abort, jsonify, request, send_from_directory

import monitor
import store
from analyzer import AnalysisError, analyze
from compare import compare

app = Flask(__name__, static_folder="static")


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
        report = analyze(url, render=b.get("render", True) is not False)
    except AnalysisError as e:
        return fail(str(e), 422)
    site = store.get_or_create_site(url, report["overview"]["title"] or None)
    saved = store.save_analysis(site["id"], report, str(b.get("label", "")))
    if b.get("project_id"):
        store.add_site_to_project(int(b["project_id"]), site["id"])
    return ok({"report": report, "analysis_id": saved["id"], "iteration": saved["iteration"],
               "site": store.get_site(site["id"]), "created_at": saved["created_at"]})


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
    store.update_site(sid, monitor_enabled=b.get("monitor_enabled"), monitor_interval_min=b.get("monitor_interval_min"),
                      title=b.get("title"))
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


@app.get("/api/health")
def health():
    return ok()


store.init()

if __name__ == "__main__":
    monitor.start()
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5173)), debug=False, threaded=True)
