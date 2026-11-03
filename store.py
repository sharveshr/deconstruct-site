"""SQLite persistence: projects, sites, saved analyses (iterations) and uptime checks.

Every analysis is saved against a site, so re-analyzing a URL builds up a
history of iterations that can be compared. Sites can belong to any number
of projects. Uptime checks come from the background monitor or are logged
by hand.
"""
from __future__ import annotations

import gzip
import json
import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

DB_PATH = os.environ.get("DECONSTRUCT_DB", os.path.join(os.path.dirname(__file__), "data", "deconstruct.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sites (
  id INTEGER PRIMARY KEY,
  url TEXT NOT NULL UNIQUE,
  host TEXT NOT NULL,
  title TEXT,
  created_at TEXT NOT NULL,
  monitor_enabled INTEGER NOT NULL DEFAULT 0,
  monitor_interval_min INTEGER NOT NULL DEFAULT 5,
  last_status TEXT,
  last_checked_at TEXT,
  last_change_at TEXT
);
CREATE TABLE IF NOT EXISTS project_sites (
  project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  added_at TEXT NOT NULL,
  PRIMARY KEY (project_id, site_id)
);
CREATE TABLE IF NOT EXISTS analyses (
  id INTEGER PRIMARY KEY,
  site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  label TEXT NOT NULL DEFAULT '',
  summary TEXT NOT NULL,
  thumb TEXT,
  report BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS analyses_site ON analyses(site_id, created_at);
CREATE TABLE IF NOT EXISTS checks (
  id INTEGER PRIMARY KEY,
  site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  checked_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('up', 'down')),
  http_status INTEGER,
  response_ms INTEGER,
  error TEXT,
  source TEXT NOT NULL DEFAULT 'auto' CHECK (source IN ('auto', 'manual')),
  note TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS checks_site ON checks(site_id, checked_at);
CREATE TABLE IF NOT EXISTS osint_results (
  id INTEGER PRIMARY KEY,
  target TEXT NOT NULL,
  tool TEXT NOT NULL,
  ran_at TEXT NOT NULL,
  ok INTEGER NOT NULL,
  ms INTEGER,
  result BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS osint_target ON osint_results(target, tool, ran_at);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY,
  created_at TEXT NOT NULL,
  site_id INTEGER REFERENCES sites(id) ON DELETE CASCADE,
  target TEXT,
  kind TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
  title TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '{}',
  dedup_key TEXT,
  read INTEGER NOT NULL DEFAULT 0,
  notified TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS events_created ON events(created_at);
CREATE INDEX IF NOT EXISTS events_dedup ON events(dedup_key);
CREATE TABLE IF NOT EXISTS channels (
  id INTEGER PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('webhook', 'slack', 'discord', 'email')),
  name TEXT NOT NULL,
  target TEXT NOT NULL,
  min_severity TEXT NOT NULL DEFAULT 'warning' CHECK (min_severity IN ('info', 'warning', 'critical')),
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  last_sent_at TEXT,
  last_error TEXT
);
"""

# Columns added after the first release; init() adds any that an older database is missing.
SITE_COLUMNS = {
    "watch_analyze_hours": "INTEGER NOT NULL DEFAULT 0",
    "watch_osint_hours": "INTEGER NOT NULL DEFAULT 0",
    "last_watch_analysis_at": "TEXT",
    "last_watch_osint_at": "TEXT",
}
SEVERITY_RANK = {"info": 0, "warning": 1, "critical": 2}


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with db() as c:
        c.execute("PRAGMA journal_mode = WAL")
        c.executescript(SCHEMA)
        have = {r["name"] for r in c.execute("PRAGMA table_info(sites)")}
        for col, decl in SITE_COLUMNS.items():
            if col not in have:
                c.execute(f"ALTER TABLE sites ADD COLUMN {col} {decl}")


def site_key(url: str) -> str:
    """One site per scheme + host + path, so re-analyzing the same URL adds an iteration."""
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    p = urlparse(url)
    path = p.path.rstrip("/") or "/"
    return f"{p.scheme.lower()}://{(p.hostname or '').lower()}{'' if not p.port else ':' + str(p.port)}{path}"


# ---------------------------------------------------------------- sites

def _site_row(r) -> dict:
    return dict(r) | {"monitor_enabled": bool(r["monitor_enabled"])}


def get_or_create_site(url: str, title: str | None = None) -> dict:
    key = site_key(url)
    with db() as c:
        row = c.execute("SELECT * FROM sites WHERE url = ?", (key,)).fetchone()
        if row:
            if title and title != row["title"]:
                c.execute("UPDATE sites SET title = ? WHERE id = ?", (title, row["id"]))
            return _site_row(row) | ({"title": title} if title else {})
        cur = c.execute("INSERT INTO sites (url, host, title, created_at) VALUES (?, ?, ?, ?)",
                        (key, urlparse(key).hostname, title, now_iso()))
        return _site_row(c.execute("SELECT * FROM sites WHERE id = ?", (cur.lastrowid,)).fetchone())


def get_site(site_id: int) -> dict | None:
    with db() as c:
        r = c.execute("SELECT * FROM sites WHERE id = ?", (site_id,)).fetchone()
        return _site_row(r) if r else None


def list_sites() -> list[dict]:
    with db() as c:
        rows = c.execute("""
          SELECT s.*, (SELECT COUNT(*) FROM analyses a WHERE a.site_id = s.id) AS iterations,
                 (SELECT MAX(created_at) FROM analyses a WHERE a.site_id = s.id) AS last_analyzed_at
          FROM sites s ORDER BY COALESCE(last_analyzed_at, s.created_at) DESC""").fetchall()
        return [_site_row(r) for r in rows]


WATCH_HOURS = (0, 1, 6, 12, 24, 72, 168)


def update_site(site_id: int, *, monitor_enabled=None, monitor_interval_min=None, title=None,
                watch_analyze_hours=None, watch_osint_hours=None):
    sets, args = [], []
    for col, val in (("watch_analyze_hours", watch_analyze_hours), ("watch_osint_hours", watch_osint_hours)):
        if val is not None:
            val = int(val)
            if val not in WATCH_HOURS:
                raise ValueError(f"{col} must be one of {WATCH_HOURS}")
            sets.append(f"{col} = ?"); args.append(val)
    if monitor_enabled is not None:
        sets.append("monitor_enabled = ?"); args.append(1 if monitor_enabled else 0)
    if monitor_interval_min is not None:
        sets.append("monitor_interval_min = ?"); args.append(max(1, min(1440, int(monitor_interval_min))))
    if title is not None:
        sets.append("title = ?"); args.append(title)
    if not sets:
        return
    with db() as c:
        c.execute(f"UPDATE sites SET {', '.join(sets)} WHERE id = ?", (*args, site_id))


def delete_site(site_id: int):
    with db() as c:
        c.execute("DELETE FROM sites WHERE id = ?", (site_id,))


def monitored_sites_due() -> list[dict]:
    now = datetime.now(timezone.utc)
    with db() as c:
        rows = c.execute("SELECT * FROM sites WHERE monitor_enabled = 1").fetchall()
    return [_site_row(r) for r in rows if not r["last_checked_at"]
            or now - parse_iso(r["last_checked_at"]) >= timedelta(minutes=r["monitor_interval_min"])]


# ---------------------------------------------------------------- projects

def list_projects() -> list[dict]:
    with db() as c:
        rows = c.execute("""
          SELECT p.*, COUNT(ps.site_id) AS site_count,
                 SUM(CASE WHEN s.last_status = 'down' AND s.monitor_enabled = 1 THEN 1 ELSE 0 END) AS sites_down
          FROM projects p LEFT JOIN project_sites ps ON ps.project_id = p.id LEFT JOIN sites s ON s.id = ps.site_id
          GROUP BY p.id ORDER BY p.created_at DESC""").fetchall()
        return [dict(r) | {"sites_down": r["sites_down"] or 0} for r in rows]


def create_project(name: str, description: str = "") -> dict:
    with db() as c:
        cur = c.execute("INSERT INTO projects (name, description, created_at) VALUES (?, ?, ?)",
                        (name.strip()[:120], description.strip()[:1000], now_iso()))
        return dict(c.execute("SELECT * FROM projects WHERE id = ?", (cur.lastrowid,)).fetchone())


def get_project(project_id: int) -> dict | None:
    with db() as c:
        p = c.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
        if not p:
            return None
        sites = c.execute("""
          SELECT s.*, ps.added_at FROM project_sites ps JOIN sites s ON s.id = ps.site_id
          WHERE ps.project_id = ? ORDER BY ps.added_at""", (project_id,)).fetchall()
    out = dict(p)
    out["sites"] = [_site_row(s) | {"added_at": s["added_at"], "latest": latest_summary(s["id"]),
                                    "iterations": count_analyses(s["id"]), "uptime_24h": uptime_stats(s["id"], 1)["uptime_pct"]}
                    for s in sites]
    return out


def update_project(project_id: int, name=None, description=None):
    with db() as c:
        if name is not None:
            c.execute("UPDATE projects SET name = ? WHERE id = ?", (name.strip()[:120], project_id))
        if description is not None:
            c.execute("UPDATE projects SET description = ? WHERE id = ?", (description.strip()[:1000], project_id))


def delete_project(project_id: int):
    """Removes the project only; its sites, iterations and uptime history stay."""
    with db() as c:
        c.execute("DELETE FROM projects WHERE id = ?", (project_id,))


def add_site_to_project(project_id: int, site_id: int):
    with db() as c:
        c.execute("INSERT OR IGNORE INTO project_sites (project_id, site_id, added_at) VALUES (?, ?, ?)",
                  (project_id, site_id, now_iso()))


def remove_site_from_project(project_id: int, site_id: int):
    with db() as c:
        c.execute("DELETE FROM project_sites WHERE project_id = ? AND site_id = ?", (project_id, site_id))


def projects_for_site(site_id: int) -> list[dict]:
    with db() as c:
        return [dict(r) for r in c.execute("""
          SELECT p.id, p.name FROM project_sites ps JOIN projects p ON p.id = ps.project_id
          WHERE ps.site_id = ? ORDER BY p.name""", (site_id,)).fetchall()]


# ---------------------------------------------------------------- analyses (iterations)

def summarize(report: dict) -> dict:
    """The small slice of a report that lists and comparisons need without loading the whole thing."""
    perf = report["performance"]
    v = perf.get("vitals") or {}
    return {
        "title": report["overview"]["title"],
        "final_url": report["overview"]["final_url"],
        "status": report["overview"]["status"],
        "favicon": report["overview"]["favicon"],
        "scores": report["scores"],
        "tech": sorted(t["name"] for ts in report["technologies"]["by_category"].values() for t in ts),
        "vitals": {k: v.get(k) for k in ("lcp", "fcp", "cls", "tbt", "ttfb")} if v else None,
        "page_bytes": (perf.get("vitals") or {}).get("transfer_bytes") or perf["total_known_bytes"],
        "requests": perf.get("browser_request_count") or perf["request_count"],
        "issue_count": len(perf["issues"]) + len(report["seo"]["issues"]) + len(report["accessibility"]["issues"]),
        "analysis_ms": report["analysis_ms"],
        "rendered": bool(report.get("browser", {}).get("available")),
        "mode": analysis_mode(report),
    }


def save_analysis(site_id: int, report: dict, label: str = "") -> dict:
    summary = summarize(report)
    thumb = (report.get("browser") or {}).get("screenshots", {}).get("above_fold") if report.get("browser", {}).get("available") else None
    created = now_iso()
    with db() as c:
        cur = c.execute("INSERT INTO analyses (site_id, created_at, label, summary, thumb, report) VALUES (?, ?, ?, ?, ?, ?)",
                        (site_id, created, label[:120], json.dumps(summary), thumb,
                         gzip.compress(json.dumps(report).encode(), compresslevel=6)))
        n = c.execute("SELECT COUNT(*) FROM analyses WHERE site_id = ?", (site_id,)).fetchone()[0]
    return {"id": cur.lastrowid, "created_at": created, "iteration": n, "summary": summary}


def count_analyses(site_id: int) -> int:
    with db() as c:
        return c.execute("SELECT COUNT(*) FROM analyses WHERE site_id = ?", (site_id,)).fetchone()[0]


def latest_summary(site_id: int, with_thumb=True) -> dict | None:
    with db() as c:
        r = c.execute(f"SELECT id, created_at, summary{', thumb' if with_thumb else ''} FROM analyses "
                      "WHERE site_id = ? ORDER BY created_at DESC, id DESC LIMIT 1", (site_id,)).fetchone()
    if not r:
        return None
    return {"id": r["id"], "created_at": r["created_at"], **json.loads(r["summary"]),
            **({"thumb": r["thumb"]} if with_thumb else {})}


def list_analyses(site_id: int | None = None, limit: int = 200) -> list[dict]:
    q = """SELECT a.id, a.site_id, a.created_at, a.label, a.summary, s.url, s.host,
                  ROW_NUMBER() OVER (PARTITION BY a.site_id ORDER BY a.created_at, a.id) AS iteration
           FROM analyses a JOIN sites s ON s.id = a.site_id"""
    args: tuple = ()
    if site_id is not None:
        q += " WHERE a.site_id = ?"
        args = (site_id,)
    q = f"SELECT * FROM ({q}) ORDER BY created_at DESC, id DESC LIMIT ?"
    with db() as c:
        rows = c.execute(q, (*args, limit)).fetchall()
    return [{k: r[k] for k in ("id", "site_id", "created_at", "label", "url", "host", "iteration")}
            | json.loads(r["summary"]) for r in rows]


def get_analysis(analysis_id: int) -> dict | None:
    with db() as c:
        r = c.execute("""SELECT a.*, s.url, s.host FROM analyses a JOIN sites s ON s.id = a.site_id WHERE a.id = ?""",
                      (analysis_id,)).fetchone()
        if not r:
            return None
        iteration = c.execute("SELECT COUNT(*) FROM analyses WHERE site_id = ? AND (created_at < ? OR (created_at = ? AND id <= ?))",
                              (r["site_id"], r["created_at"], r["created_at"], r["id"])).fetchone()[0]
    return {"id": r["id"], "site_id": r["site_id"], "url": r["url"], "host": r["host"], "created_at": r["created_at"],
            "label": r["label"], "iteration": iteration, "report": json.loads(gzip.decompress(r["report"]))}


def update_analysis_label(analysis_id: int, label: str):
    with db() as c:
        c.execute("UPDATE analyses SET label = ? WHERE id = ?", (label.strip()[:120], analysis_id))


def delete_analysis(analysis_id: int):
    with db() as c:
        c.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,))


# ---------------------------------------------------------------- uptime

def record_check(site_id: int, status: str, *, http_status=None, response_ms=None, error=None,
                 source="auto", note="", checked_at: str | None = None) -> dict:
    checked_at = checked_at or now_iso()
    with db() as c:
        cur = c.execute("""INSERT INTO checks (site_id, checked_at, status, http_status, response_ms, error, source, note)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                        (site_id, checked_at, status, http_status, response_ms, error, source, note[:500]))
        # Keep the site's current state in sync with its most recent check (a back-dated manual entry may not be it).
        latest = c.execute("SELECT status, checked_at FROM checks WHERE site_id = ? ORDER BY checked_at DESC, id DESC LIMIT 1",
                           (site_id,)).fetchone()
        prev = c.execute("SELECT last_status FROM sites WHERE id = ?", (site_id,)).fetchone()["last_status"]
        changed = prev != latest["status"]
        c.execute(f"""UPDATE sites SET last_status = ?, last_checked_at = ?{', last_change_at = ?' if changed else ''}
                      WHERE id = ?""", (latest["status"], latest["checked_at"], *([latest["checked_at"]] if changed else []), site_id))
        return dict(c.execute("SELECT * FROM checks WHERE id = ?", (cur.lastrowid,)).fetchone())


def delete_check(check_id: int):
    with db() as c:
        c.execute("DELETE FROM checks WHERE id = ?", (check_id,))


def list_checks(site_id: int, days: float = 7, limit: int = 2000) -> list[dict]:
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with db() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM checks WHERE site_id = ? AND checked_at >= ? ORDER BY checked_at DESC, id DESC LIMIT ?",
            (site_id, since, limit)).fetchall()]


def uptime_stats(site_id: int, days: float) -> dict:
    """Time-weighted uptime: each check's state lasts until the next check (or now)."""
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days)
    with db() as c:
        before = c.execute("SELECT status, checked_at FROM checks WHERE site_id = ? AND checked_at < ? "
                           "ORDER BY checked_at DESC LIMIT 1", (site_id, start.strftime("%Y-%m-%dT%H:%M:%SZ"))).fetchone()
        rows = c.execute("SELECT status, checked_at, response_ms FROM checks WHERE site_id = ? AND checked_at >= ? "
                         "ORDER BY checked_at, id", (site_id, start.strftime("%Y-%m-%dT%H:%M:%SZ"))).fetchall()
    points = ([(start, before["status"])] if before else []) + [(parse_iso(r["checked_at"]), r["status"]) for r in rows]
    if not points:
        return {"days": days, "uptime_pct": None, "checks": 0, "avg_response_ms": None, "incidents": []}
    up = down = 0.0
    incidents, open_inc = [], None
    for i, (t, st) in enumerate(points):
        end = points[i + 1][0] if i + 1 < len(points) else now
        span = (end - t).total_seconds()
        if st == "up":
            up += span
            if open_inc:
                open_inc["ended_at"] = t.strftime("%Y-%m-%dT%H:%M:%SZ")
                open_inc["duration_s"] = round((t - parse_iso(open_inc["started_at"])).total_seconds())
                incidents.append(open_inc)
                open_inc = None
        else:
            down += span
            if not open_inc:
                open_inc = {"started_at": t.strftime("%Y-%m-%dT%H:%M:%SZ"), "ended_at": None}
    if open_inc:
        open_inc["duration_s"] = round((now - parse_iso(open_inc["started_at"])).total_seconds())
        incidents.append(open_inc)
    times = [r["response_ms"] for r in rows if r["response_ms"] is not None]
    total = up + down
    return {
        "days": days,
        "uptime_pct": round(100 * up / total, 3) if total else None,
        "checks": len(rows),
        "avg_response_ms": round(sum(times) / len(times)) if times else None,
        "incidents": list(reversed(incidents)),
    }


def prune_checks(keep_days: int = 90):
    cutoff = (datetime.now(timezone.utc) - timedelta(days=keep_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with db() as c:
        c.execute("DELETE FROM checks WHERE source = 'auto' AND checked_at < ?", (cutoff,))


# ---------------------------------------------------------------- OSINT results

def save_osint(target: str, tool: str, ok: bool, payload: dict, ms: int | None) -> int:
    with db() as c:
        cur = c.execute("INSERT INTO osint_results (target, tool, ran_at, ok, ms, result) VALUES (?, ?, ?, ?, ?, ?)",
                        (target, tool, now_iso(), 1 if ok else 0, ms, gzip.compress(json.dumps(payload).encode())))
        return cur.lastrowid


def previous_osint(target: str, tool: str, before_id: int) -> dict | None:
    """The last successful result of a tool before a given run, for change detection."""
    with db() as c:
        r = c.execute("SELECT * FROM osint_results WHERE target = ? AND tool = ? AND ok = 1 AND id < ? ORDER BY id DESC LIMIT 1",
                      (target, tool, before_id)).fetchone()
    return {"id": r["id"], "ran_at": r["ran_at"], **json.loads(gzip.decompress(r["result"]))} if r else None


def latest_osint(target: str) -> dict:
    """Most recent result of each tool for a target."""
    with db() as c:
        rows = c.execute("""SELECT o.* FROM osint_results o JOIN (
                              SELECT tool, MAX(id) AS id FROM osint_results WHERE target = ? GROUP BY tool) m ON m.id = o.id""",
                         (target,)).fetchall()
    return {r["tool"]: {"ok": bool(r["ok"]), "ran_at": r["ran_at"], "ms": r["ms"], **json.loads(gzip.decompress(r["result"]))}
            for r in rows}


def recent_osint_targets(limit: int = 30) -> list[dict]:
    with db() as c:
        return [dict(r) for r in c.execute("""
          SELECT target, MAX(ran_at) AS last_run, COUNT(DISTINCT tool) AS tools, COUNT(*) AS runs,
                 SUM(CASE WHEN ok = 0 THEN 1 ELSE 0 END) AS failures
          FROM osint_results GROUP BY target ORDER BY last_run DESC LIMIT ?""", (limit,)).fetchall()]


def delete_osint_target(target: str):
    with db() as c:
        c.execute("DELETE FROM osint_results WHERE target = ?", (target,))


def analysis_mode(report: dict) -> str:
    """How an analysis was measured. Runs are only compared with runs of the same mode, since a
    browser-free run detects less technology and throttled mobile vitals score lower than desktop ones."""
    if not (report.get("browser") or {}).get("available"):
        return "quick"
    return "browser-mobile" if report["performance"].get("vitals_method") == "mobile-throttled" else "browser"


# Older saved summaries have no "mode"; derive it the way analysis_mode() did before throttled runs existed.
_MODE_SQL = ("COALESCE(json_extract(summary, '$.mode'), "
             "CASE WHEN COALESCE(json_extract(summary, '$.rendered'), 0) THEN 'browser' ELSE 'quick' END)")


def previous_analysis(site_id: int, before_id: int, mode: str | None = None) -> dict | None:
    """The iteration before `before_id`; with `mode`, the last one measured the same way."""
    q, args = "SELECT id FROM analyses WHERE site_id = ? AND id < ?", [site_id, before_id]
    if mode is not None:
        q += f" AND {_MODE_SQL} = ?"
        args.append(mode)
    with db() as c:
        r = c.execute(q + " ORDER BY id DESC LIMIT 1", args).fetchone()
    return get_analysis(r["id"]) if r else None


# ---------------------------------------------------------------- watch schedules

def sites_due_for_watch(kind: str) -> list[dict]:
    """Sites whose scheduled re-analysis ('analyze') or OSINT refresh ('osint') is due."""
    hours_col, last_col = ("watch_analyze_hours", "last_watch_analysis_at") if kind == "analyze" else ("watch_osint_hours", "last_watch_osint_at")
    now = datetime.now(timezone.utc)
    with db() as c:
        rows = c.execute(f"SELECT * FROM sites WHERE {hours_col} > 0").fetchall()
    return [_site_row(r) for r in rows if not r[last_col] or now - parse_iso(r[last_col]) >= timedelta(hours=r[hours_col])]


def mark_watch_run(site_id: int, kind: str):
    col = "last_watch_analysis_at" if kind == "analyze" else "last_watch_osint_at"
    with db() as c:
        c.execute(f"UPDATE sites SET {col} = ? WHERE id = ?", (now_iso(), site_id))


def site_for_host(host: str) -> dict | None:
    with db() as c:
        r = c.execute("SELECT * FROM sites WHERE host = ? ORDER BY id LIMIT 1", (host,)).fetchone()
    return _site_row(r) if r else None


# ---------------------------------------------------------------- events

def _event_row(r) -> dict:
    return dict(r) | {"read": bool(r["read"]), "detail": json.loads(r["detail"]), "notified": json.loads(r["notified"])}


def add_event(kind: str, severity: str, title: str, *, site_id=None, target=None, detail=None,
              dedup_key: str | None = None, dedup_days: float | None = None) -> dict | None:
    """Records an event; returns None when an event with the same dedup_key already exists
    (within dedup_days, or ever when dedup_days is None)."""
    with db() as c:
        if dedup_key:
            q, args = "SELECT 1 FROM events WHERE dedup_key = ?", [dedup_key]
            if dedup_days is not None:
                q += " AND created_at >= ?"
                args.append((datetime.now(timezone.utc) - timedelta(days=dedup_days)).strftime("%Y-%m-%dT%H:%M:%SZ"))
            if c.execute(q, args).fetchone():
                return None
        cur = c.execute("""INSERT INTO events (created_at, site_id, target, kind, severity, title, detail, dedup_key)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                        (now_iso(), site_id, target, kind, severity, title[:300], json.dumps(detail or {}), dedup_key))
        return _event_row(c.execute("SELECT * FROM events WHERE id = ?", (cur.lastrowid,)).fetchone())


def list_events(*, site_id=None, target=None, min_severity="info", unread_only=False, kind=None,
                before_id=None, limit=100) -> list[dict]:
    allowed = [s for s, rank in SEVERITY_RANK.items() if rank >= SEVERITY_RANK.get(min_severity, 0)]
    where, args = [f"e.severity IN ({','.join('?' * len(allowed))})"], list(allowed)
    if site_id is not None:
        where.append("(e.site_id = ? OR e.target = (SELECT host FROM sites WHERE id = ?))"); args += [site_id, site_id]
    if target:
        where.append("e.target = ?"); args.append(target)
    if unread_only:
        where.append("e.read = 0")
    if kind:
        where.append("e.kind = ?"); args.append(kind)
    if before_id:
        where.append("e.id < ?"); args.append(before_id)
    with db() as c:
        rows = c.execute(f"""SELECT e.*, s.host AS site_host FROM events e LEFT JOIN sites s ON s.id = e.site_id
                             WHERE {' AND '.join(where)} ORDER BY e.id DESC LIMIT ?""", (*args, limit)).fetchall()
    return [_event_row(r) for r in rows]


def unread_counts() -> dict:
    with db() as c:
        rows = c.execute("SELECT severity, COUNT(*) AS n FROM events WHERE read = 0 GROUP BY severity").fetchall()
    out = {"info": 0, "warning": 0, "critical": 0} | {r["severity"]: r["n"] for r in rows}
    return out | {"total": sum(out.values())}


def mark_events_read(ids: list[int] | None = None, read: bool = True):
    with db() as c:
        if ids is None:
            c.execute("UPDATE events SET read = ?", (1 if read else 0,))
        elif ids:
            c.execute(f"UPDATE events SET read = ? WHERE id IN ({','.join('?' * len(ids))})", (1 if read else 0, *ids))


def set_event_notified(event_id: int, results: list[dict]):
    with db() as c:
        c.execute("UPDATE events SET notified = ? WHERE id = ?", (json.dumps(results), event_id))


def delete_events(ids: list[int] | None = None):
    with db() as c:
        if ids is None:
            c.execute("DELETE FROM events")
        elif ids:
            c.execute(f"DELETE FROM events WHERE id IN ({','.join('?' * len(ids))})", ids)


def prune_events(keep_days: int = 180):
    cutoff = (datetime.now(timezone.utc) - timedelta(days=keep_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with db() as c:
        c.execute("DELETE FROM events WHERE created_at < ?", (cutoff,))


# ---------------------------------------------------------------- notification channels

def _channel_row(r) -> dict:
    return dict(r) | {"enabled": bool(r["enabled"])}


def list_channels() -> list[dict]:
    with db() as c:
        return [_channel_row(r) for r in c.execute("SELECT * FROM channels ORDER BY id").fetchall()]


def get_channel(channel_id: int) -> dict | None:
    with db() as c:
        r = c.execute("SELECT * FROM channels WHERE id = ?", (channel_id,)).fetchone()
    return _channel_row(r) if r else None


def create_channel(kind: str, name: str, target: str, min_severity: str = "warning") -> dict:
    with db() as c:
        cur = c.execute("INSERT INTO channels (kind, name, target, min_severity, created_at) VALUES (?, ?, ?, ?, ?)",
                        (kind, name.strip()[:80], target.strip()[:500], min_severity, now_iso()))
        return _channel_row(c.execute("SELECT * FROM channels WHERE id = ?", (cur.lastrowid,)).fetchone())


def update_channel(channel_id: int, **fields):
    allowed = {"name", "target", "min_severity", "enabled"}
    sets = [(k, (1 if v else 0) if k == "enabled" else v) for k, v in fields.items() if k in allowed and v is not None]
    if not sets:
        return
    with db() as c:
        c.execute(f"UPDATE channels SET {', '.join(f'{k} = ?' for k, _ in sets)} WHERE id = ?", (*[v for _, v in sets], channel_id))


def record_channel_result(channel_id: int, error: str | None):
    with db() as c:
        if error:
            c.execute("UPDATE channels SET last_error = ? WHERE id = ?", (error[:300], channel_id))
        else:
            c.execute("UPDATE channels SET last_sent_at = ?, last_error = NULL WHERE id = ?", (now_iso(), channel_id))


def delete_channel(channel_id: int):
    with db() as c:
        c.execute("DELETE FROM channels WHERE id = ?", (channel_id,))
