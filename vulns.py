"""Known-vulnerable JavaScript libraries, using the retire.js vulnerability database.

Versions are found the ways retire.js finds them: from script URLs and file names,
from the first part of each script's contents, from expressions evaluated in the
rendered page (e.g. jQuery.fn.jquery), and from versions technology detection
already found. The database is downloaded from GitHub and cached for a day.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import requests

import store

log = logging.getLogger("vulns")
REPO_URL = "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v4.json"
CACHE_FILE = os.path.join(os.path.dirname(store.DB_PATH), "retire-jsrepository.json")
VERSION_RE = r"[0-9][0-9.a-z_\-]+"
SEVERITY_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
MAX_SCRIPTS = 10            # script bodies downloaded per analysis
SCRIPT_BYTES = 300_000      # banners and version strings sit near the top of a file

_lock = threading.Lock()
_repo = {"data": None, "loaded_at": 0.0, "compiled": None, "error": None}


def _load_repo() -> dict | None:
    """The retire.js database: memory → cache file (< 1 day old) → GitHub → stale cache file."""
    with _lock:
        if _repo["data"] and time.time() - _repo["loaded_at"] < 86400:
            return _repo["data"]
        data = None
        try:
            if os.path.exists(CACHE_FILE) and time.time() - os.path.getmtime(CACHE_FILE) < 86400:
                with open(CACHE_FILE, encoding="utf-8") as f:
                    data = json.load(f)
        except (OSError, ValueError):
            data = None
        if data is None:
            try:
                r = requests.get(REPO_URL, timeout=15)
                r.raise_for_status()
                data = r.json()
                try:
                    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
                    with open(CACHE_FILE, "w", encoding="utf-8") as f:
                        json.dump(data, f)
                except OSError:
                    pass
            except (requests.RequestException, ValueError) as e:
                _repo["error"] = f"Couldn't download the retire.js database ({type(e).__name__})."
                if os.path.exists(CACHE_FILE):
                    with open(CACHE_FILE, encoding="utf-8") as f:
                        data = json.load(f)
        if data:
            data.pop("retire-example", None)
            _repo.update(data=data, loaded_at=time.time(), compiled=_compile(data), error=None)
        return data


def _compile(repo: dict) -> dict:
    """Pre-compiles every extractor; patterns Python's regex engine can't read are skipped."""
    out = {}
    for comp, entry in repo.items():
        ex = entry.get("extractors", {})
        c = {}
        for kind in ("uri", "filename", "filecontent"):
            pats = []
            for p in ex.get(kind, []):
                p = p.replace("§§version§§", VERSION_RE)
                if kind == "filecontent":
                    p = p.replace(".*", ".{0,800}")   # bound JS-style greedy gaps so a minified file can't stall the scan
                try:
                    pats.append(re.compile(p))
                except re.error:
                    pass
            c[kind] = pats
        c["func"] = ex.get("func", [])
        out[comp] = c
    return out


def func_checks() -> dict[str, list[str]]:
    """Expressions that reveal a library's version at runtime, for the browser pass."""
    repo = _load_repo()
    if not repo:
        return {}
    return {comp: c["func"] for comp, c in _repo["compiled"].items() if c["func"]}


# ---------------------------------------------------------------- versions

def _vparts(v: str):
    return [int(t) if t.isdigit() else t for t in re.findall(r"\d+|[a-z]+", v.lower())]


def vcmp(a: str, b: str) -> int:
    """Compares versions the way retire.js does: 1.9.0b1 < 1.9.0 < 1.9.0.1."""
    pa, pb = _vparts(a), _vparts(b)
    for i in range(max(len(pa), len(pb))):
        x = pa[i] if i < len(pa) else None
        y = pb[i] if i < len(pb) else None
        if x == y:
            continue
        if x is None:     # "1.9.0" vs "1.9.0b1": a trailing word is a pre-release, a trailing number a later version
            return 1 if isinstance(y, str) else -1
        if y is None:
            return -1 if isinstance(x, str) else 1
        if isinstance(x, int) and isinstance(y, int):
            return -1 if x < y else 1
        if isinstance(x, str) and isinstance(y, str):
            return -1 if x < y else 1
        return -1 if isinstance(x, str) else 1   # words (beta, rc) sort before numbers
    return 0


def _affected(version: str, vuln: dict) -> bool:
    if vuln.get("atOrAbove") and vcmp(version, vuln["atOrAbove"]) < 0:
        return False
    if vuln.get("above") and vcmp(version, vuln["above"]) <= 0:
        return False
    if vuln.get("below") and vcmp(version, vuln["below"]) >= 0:
        return False
    return bool(vuln.get("below") or vuln.get("atOrAbove") or vuln.get("above"))


# ---------------------------------------------------------------- detection

def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower().removesuffix(".js").removesuffix("js"))


def _name_index(repo: dict) -> dict:
    idx = {}
    for comp, entry in repo.items():
        for n in [comp, entry.get("npmname") or "", *entry.get("bowername", [])]:
            if n:
                idx.setdefault(_norm(n), comp)
    return idx


def scan(script_urls: list[str], *, fetch=None, tech: dict | None = None, runtime: dict | None = None) -> dict:
    """Finds libraries with known vulnerabilities. `fetch(url)` returns the first SCRIPT_BYTES of a
    script (or None) and must apply the caller's address checks; `tech` is {name: version} from
    technology detection; `runtime` is {component: version} from the browser's func checks."""
    repo = _load_repo()
    if not repo:
        return {"available": False, "error": _repo["error"] or "The retire.js database isn't available."}
    compiled = _repo["compiled"]
    found: dict[tuple, dict] = {}     # (component, version) → finding

    def add(comp, version, how, where=None):
        version = re.sub(r"([._-](min|slim|js|prod|production|bundle|umd|esm))+$", "", version.strip().rstrip("."), flags=re.I)
        if not re.match(r"^\d", version):
            return
        f = found.setdefault((comp, version), {"component": comp, "version": version, "detected_by": [], "sources": []})
        if how not in f["detected_by"]:
            f["detected_by"].append(how)
        if where and where not in f["sources"] and len(f["sources"]) < 5:
            f["sources"].append(where)

    urls = list(dict.fromkeys(u for u in script_urls if u.startswith("http")))[:300]
    for u in urls:
        path = urlparse(u).path
        fname = path.rsplit("/", 1)[-1]
        for comp, c in compiled.items():
            for p in c["uri"]:
                m = p.search(u)
                if m and m.groups():
                    add(comp, m.group(1), "URL", u)
            for p in c["filename"]:
                m = p.search(fname)
                if m and m.groups():
                    add(comp, m.group(1), "file name", u)

    # File contents: first-party scripts and scripts whose URL didn't already reveal a version.
    with_version = {s for f in found.values() for s in f["sources"]}
    candidates = [u for u in urls if u not in with_version]
    candidates.sort(key=lambda u: 0 if "jquery" in u.lower() or "/vendor" in u.lower() else 1)
    fetched = 0
    if fetch and candidates:
        with ThreadPoolExecutor(6) as pool:
            bodies = list(pool.map(lambda u: (u, fetch(u)), candidates[:MAX_SCRIPTS]))
        for u, body in bodies:
            if not body:
                continue
            fetched += 1
            for comp, c in compiled.items():
                for p in c["filecontent"]:
                    m = p.search(body)
                    if m and m.groups():
                        add(comp, m.group(1), "file contents", u)
                        break

    for comp, version in (runtime or {}).items():
        if comp in compiled and isinstance(version, str):
            add(comp, version, "runtime")
    idx = _name_index(repo)
    for name, version in (tech or {}).items():
        comp = idx.get(_norm(name))
        if comp and version:
            add(comp, str(version), "technology detection")

    findings = []
    for (comp, version), f in found.items():
        vulns = [v for v in repo[comp].get("vulnerabilities", []) if _affected(version, v)]
        if not vulns:
            continue
        items = []
        for v in vulns:
            ids = v.get("identifiers", {})
            items.append({"severity": v.get("severity", "medium"), "summary": ids.get("summary") or ", ".join(ids.get("CVE", [])) or "Known vulnerability",
                          "cve": ids.get("CVE", []), "ghsa": ids.get("githubID"), "below": v.get("below"),
                          "info": v.get("info", [])[:3]})
        items.sort(key=lambda i: -SEVERITY_RANK.get(i["severity"], 2))
        fixed = max((i["below"] for i in items if i["below"]), key=lambda b: _vparts(b), default=None)
        # retire.js marks "no fixed release in this line" with placeholders like 1.999 or 3.999.999
        eol = bool(fixed and any(isinstance(p, int) and p >= 99 for p in _vparts(fixed)))
        findings.append(f | {"severity": items[0]["severity"], "vulnerabilities": items,
                             "upgrade_to": None if eol else fixed, "end_of_life": eol})
    # "3.4" from technology detection and "3.4.1" from a file are the same copy; a page can still load two real versions.
    findings = [f for f in findings if not any(g is not f and g["component"] == f["component"]
                                               and g["version"].startswith(f["version"] + ".") for g in findings)]
    findings.sort(key=lambda f: (-SEVERITY_RANK.get(f["severity"], 2), f["component"], f["version"]))
    return {"available": True, "findings": findings, "scripts_checked": len(urls), "scripts_downloaded": fetched,
            "libraries_seen": sorted({f"{c} {v}" for c, v in found}),
            "database": "retire.js", "database_components": len(repo)}
