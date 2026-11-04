"""Deconstruct Site: paste a URL, get a full breakdown of how the site is built.

Also keeps a library of analyzed sites: projects that group them, every
analysis saved as an iteration, an uptime log per site, and change alerts
raised when a newer result differs from the previous one.
"""
import csv
import hmac
import io
import logging
import os
import re
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone

from flask import Flask, Response, abort, g, jsonify, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash

import browser
import crawl
import monitor
import notify
import osint
import store
import tokens
import watch
from analyzer import AnalysisError, analyze
from compare import compare

app = Flask(__name__, static_folder="static")
log = logging.getLogger("app")
APP_PASSWORD = os.environ.get("APP_PASSWORD")
# Vercel runs each request in a short-lived function: no background threads, no Chromium
SERVERLESS = bool(os.environ.get("VERCEL"))
# ALLOW_SIGNUP=0 closes registration once the first account exists.
ALLOW_SIGNUP = os.environ.get("ALLOW_SIGNUP", "1") not in ("0", "false", "no")


def _secret_key() -> str:
    """SECRET_KEY signs session cookies. Without it, a random key is kept next to the database so
    sign-ins survive restarts; on Vercel, where that file doesn't last, set SECRET_KEY instead."""
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    path = os.path.join(os.path.dirname(store.DB_PATH), "secret_key")
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        key = secrets.token_hex(32)
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(key)
        except OSError:
            log.warning("SECRET_KEY isn't set and couldn't be saved; sign-ins end when the server restarts.")
        return key


app.config.update(
    SECRET_KEY=_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=SERVERLESS or bool(os.environ.get("CODESPACE_NAME")) or os.environ.get("SESSION_COOKIE_SECURE") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
    # Only sign-in and sign-out write the cookie. Refreshing it on every response let a request that was
    # still in flight during sign-out put the old session back.
    SESSION_REFRESH_EACH_REQUEST=False,
)
PUBLIC_API = {"/api/health", "/api/auth/me", "/api/auth/signin", "/api/auth/signup", "/api/auth/signout"}


@app.before_request
def require_password():
    """With APP_PASSWORD set, every page and API call needs it (any username) via HTTP Basic auth."""
    if not APP_PASSWORD:
        return None
    auth = request.authorization
    if auth and hmac.compare_digest((auth.password or "").encode(), APP_PASSWORD.encode()):
        return None
    return Response("Password required.", 401, {"WWW-Authenticate": 'Basic realm="Deconstruct Site"'})


@app.before_request
def require_account():
    """API calls need a signed-in account, and every store call in the request only sees that account's data.
    Changes must come from the app's own fetch() (a custom header a cross-site form can't send)."""
    if not request.path.startswith("/api/"):
        return None
    if request.method not in ("GET", "HEAD", "OPTIONS") and request.headers.get("X-Requested-With") != "fetch":
        return fail("Missing the X-Requested-With: fetch header.", 403)
    if request.path in PUBLIC_API:
        return None
    user = store.get_user(session["uid"]) if session.get("uid") else None
    if not user:
        return jsonify(ok=False, error="Sign in to continue.", auth="required"), 401
    g.user = user
    g.user_token = store.set_user(user["id"])
    return None


@app.teardown_request
def _clear_user(exc):
    token = g.pop("user_token", None)
    if token is not None:
        store.reset_user(token)


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


# ---------------------------------------------------------------- accounts

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DUMMY_HASH = generate_password_hash(secrets.token_hex(16))
_failures: dict[str, list[float]] = {}
_failures_lock = threading.Lock()
MAX_FAILURES, FAILURE_WINDOW = 8, 15 * 60


def _throttled(key: str) -> bool:
    """True after too many failed sign-ins for this address from this client recently."""
    now = time.time()
    with _failures_lock:
        recent = [t for t in _failures.get(key, []) if now - t < FAILURE_WINDOW]
        _failures[key] = recent
        return len(recent) >= MAX_FAILURES


def _note_failure(key: str):
    with _failures_lock:
        _failures.setdefault(key, []).append(time.time())


def _start_session(user: dict):
    session.clear()          # a fresh session on sign-in, so an old cookie can't be carried over
    session["uid"] = user["id"]
    session.permanent = True
    store.touch_login(user["id"])


def _signup_open() -> bool:
    return ALLOW_SIGNUP or store.user_count() == 0


@app.get("/api/auth/me")
def api_me():
    user = store.get_user(session["uid"]) if session.get("uid") else None
    return ok({"user": user, "signup_open": _signup_open(), "has_users": store.user_count() > 0})


@app.post("/api/auth/signup")
def api_signup():
    if not _signup_open():
        return fail("Sign-up is closed on this server. Ask its owner for an account.", 403)
    b = body()
    email = str(b.get("email", "")).strip().lower()
    password = str(b.get("password", ""))
    name = str(b.get("name", "")).strip()
    if not EMAIL_RE.match(email) or len(email) > 254:
        return fail("Enter a valid email address.")
    if len(password) < 8:
        return fail("Use a password of at least 8 characters.")
    if len(password) > 200:
        return fail("That password is too long.")
    if password.lower() == email or password.lower() in ("password", "12345678", "password1", "qwertyui"):
        return fail("Choose a less guessable password.")
    if store.user_for_login(email):
        return fail("An account with that email already exists. Sign in instead.", 409)
    first = store.user_count() == 0
    user = store.create_user(email, name, generate_password_hash(password))
    claimed = store.claim_unowned(user["id"]) if first else {}
    _start_session(user)
    return ok({"user": user, "claimed": {k: v for k, v in claimed.items() if v}}, 201)


@app.post("/api/auth/signin")
def api_signin():
    b = body()
    email = str(b.get("email", "")).strip().lower()
    password = str(b.get("password", ""))
    key = f"{request.remote_addr}|{email}"
    if _throttled(key):
        return fail("Too many failed attempts. Wait 15 minutes and try again.", 429)
    found = store.user_for_login(email) if email else None
    # Check a hash even for unknown addresses so response time doesn't reveal which emails have accounts.
    valid = check_password_hash(found[1] if found else _DUMMY_HASH, password)
    if not found or not valid:
        _note_failure(key)
        return fail("Wrong email or password.", 401)
    _start_session(found[0])
    return ok({"user": found[0]})


@app.post("/api/auth/signout")
def api_signout():
    session.clear()
    return ok()


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


@app.get("/api/analyses/<int:aid>/tokens")
def api_analysis_tokens(aid):
    """Design tokens as ?format=css|scss|tailwind|tailwind4|json."""
    a = need(store.get_analysis(aid), "That analysis doesn't exist.")
    try:
        return ok(tokens.export(a["report"], request.args.get("format", "css")))
    except ValueError as e:
        return fail(str(e))


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


# ---------------------------------------------------------------- crawls

IN_PROGRESS = ("queued", "crawling", "checking", "stopping")


def _crawl_view(c: dict) -> dict:
    """A crawl with its progress; the per-page maps stay out (the pages endpoint serves them)."""
    out = dict(c)
    if out.get("summary"):
        out["summary"] = {k: v for k, v in out["summary"].items() if k not in ("page_issues", "inlinks")}
    counts = store.crawl_page_counts(c["id"])
    out["progress"] = {"pages_done": c["pages_done"], "queued": counts["queued"], "skipped": counts["skipped"],
                       "links_checked": c["links_checked"], "links_total": len(store.crawl_links(c["id"])) if c["status"] in ("checking", "done") else None}
    return out


@app.get("/api/crawls")
def api_crawls():
    return ok({"crawls": store.list_crawls(request.args.get("site_id", type=int)), "limits": crawl.PAGE_LIMITS,
               "background": crawl.worker_running()})


@app.post("/api/crawls")
def api_crawl_create():
    b = body()
    url = str(b.get("url", "")).strip()
    if not url:
        return fail("Enter a URL to crawl.")
    try:
        c = crawl.create(url, int(b.get("max_pages", 100)), int(b.get("max_depth", crawl.MAX_DEPTH)))
    except (ValueError, TypeError) as e:
        return fail(str(e))
    except AnalysisError as e:
        return fail(str(e), 422)
    return ok(_crawl_view(c), 201)


@app.get("/api/crawls/<int:cid>")
def api_crawl(cid):
    c = need(store.get_crawl(cid), "That crawl doesn't exist.")
    if c["status"] in IN_PROGRESS and not crawl.worker_running():
        # No background worker (Vercel, or tests): each poll advances the crawl a little.
        crawl.step(cid, budget=6 if SERVERLESS else 15)
        c = store.get_crawl(cid)
    return ok(_crawl_view(c))


@app.get("/api/crawls/<int:cid>/pages")
def api_crawl_pages(cid):
    c = need(store.get_crawl(cid), "That crawl doesn't exist.")
    rows = crawl.page_rows(c)
    a = request.args
    if a.get("issue"):
        rows = [r for r in rows if a["issue"] in r["issues"] or (a["issue"] == "skipped" and r["state"] == "skipped")]
    if a.get("q"):
        q = a["q"].lower()
        rows = [r for r in rows if q in r["url"].lower() or q in (r["title"] or "").lower()]
    key = a.get("sort", "url")
    if key in ("url", "status", "depth", "ms", "bytes", "words", "inlinks", "outlinks", "issues"):
        val = (lambda r: len(r["issues"])) if key == "issues" else (lambda r: (r[key] is None, r[key] if r[key] is not None else 0))
        rows.sort(key=val, reverse=a.get("dir") == "desc")
    return ok({"total": len(rows), "pages": rows[:min(1000, a.get("limit", 500, type=int))], "issue_labels": {k: v[0] for k, v in crawl.ISSUES.items()}})


@app.get("/api/crawls/<int:cid>/pages.csv")
def api_crawl_csv(cid):
    c = need(store.get_crawl(cid), "That crawl doesn't exist.")
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["url", "status", "error", "depth", "title", "words", "response_ms", "bytes", "inlinks", "outlinks", "final_url", "issues"])
    for r in crawl.page_rows(c):
        w.writerow([r["url"], r["status"] or "", r["error"] or "", r["depth"] if r["depth"] is not None else "", r["title"] or "",
                    r["words"] or "", r["ms"] or "", r["bytes"] or "", r["inlinks"], r["outlinks"], r["final_url"] or "",
                    "; ".join(crawl.ISSUES[k][0] for k in r["issues"])])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="crawl-{c["host"]}-{c["id"]}.csv"'})


@app.post("/api/crawls/<int:cid>/stop")
def api_crawl_stop(cid):
    c = need(store.get_crawl(cid), "That crawl doesn't exist.")
    if c["status"] in ("queued", "crawling", "checking"):
        store.update_crawl(cid, status="stopping")
        if not crawl.worker_running():
            crawl.step(cid, budget=5)
    return ok(_crawl_view(store.get_crawl(cid)))


@app.delete("/api/crawls/<int:cid>")
def api_crawl_delete(cid):
    store.delete_crawl(cid)
    return ok()


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
    return ok({"browser": browser.AVAILABLE, "background": not SERVERLESS,
               "sessions_persist": bool(os.environ.get("SECRET_KEY")) or not SERVERLESS})


store.init()

if __name__ == "__main__":
    monitor.start()
    watch.start()
    crawl.start_worker()
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5173)), debug=False, threaded=True)
