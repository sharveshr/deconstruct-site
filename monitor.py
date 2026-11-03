"""Background uptime monitor.

A daemon thread wakes every few seconds, checks every monitored site whose
interval has elapsed, and records up/down in the store. A site counts as up
when it answers with a status below 400 within the timeout.
"""
from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import requests

import store
from analyzer import AnalysisError, _session, safe_get

TICK_SECONDS = 15
CHECK_TIMEOUT = 15
log = logging.getLogger("monitor")


def check_url(url: str) -> dict:
    t0 = time.perf_counter()
    try:
        resp, _, _ = safe_get(_session(), url, max_bytes=1, timeout=CHECK_TIMEOUT)
        ms = round((time.perf_counter() - t0) * 1000)
        up = resp.status_code < 400
        return {"status": "up" if up else "down", "http_status": resp.status_code, "response_ms": ms,
                "error": None if up else f"HTTP {resp.status_code}"}
    except requests.exceptions.Timeout:
        return {"status": "down", "http_status": None, "response_ms": None, "error": f"No response within {CHECK_TIMEOUT}s"}
    except requests.exceptions.SSLError:
        return {"status": "down", "http_status": None, "response_ms": None, "error": "TLS/certificate error"}
    except requests.exceptions.ConnectionError:
        return {"status": "down", "http_status": None, "response_ms": None, "error": "Connection failed"}
    except (requests.RequestException, AnalysisError) as e:
        return {"status": "down", "http_status": None, "response_ms": None, "error": str(e)[:200]}


def check_site(site: dict, source="auto") -> dict:
    result = check_url(site["url"])
    if result["status"] == "down":
        # Confirm before recording an outage, so one dropped request doesn't page anyone.
        time.sleep(5)
        retry = check_url(site["url"])
        if retry["status"] == "up":
            result = retry
    previous = store.get_site(site["id"])["last_status"]
    check = store.record_check(site["id"], result["status"], http_status=result["http_status"],
                               response_ms=result["response_ms"], error=result["error"], source=source)
    if previous != check["status"] and (previous is not None or check["status"] == "down"):
        import watch  # imported here: watch imports analyzer/osint, which monitor doesn't otherwise need
        watch.on_status_change(store.get_site(site["id"]) | {"last_change_at": site.get("last_change_at")}, previous, check)
    return check


def _loop():
    last_prune = 0.0
    with ThreadPoolExecutor(max_workers=6) as pool:
        while True:
            try:
                due = store.monitored_sites_due()
                if due:
                    list(pool.map(check_site, due))
                if time.time() - last_prune > 6 * 3600:
                    store.prune_checks()
                    last_prune = time.time()
            except Exception:
                log.exception("monitor tick failed")
            time.sleep(TICK_SECONDS)


_started = False


def start():
    global _started
    if _started:
        return
    _started = True
    threading.Thread(target=_loop, name="uptime-monitor", daemon=True).start()
