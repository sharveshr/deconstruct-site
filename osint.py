"""OSINT tools: passive lookups against public sources for a single domain.

Each tool is a function `tool(host) -> dict` registered in TOOLS. They only
read public data: DNS over HTTPS, RDAP, Certificate Transparency logs, the
Internet Archive, Team Cymru's IP-to-ASN DNS service, and the site's own
public HTTP responses. HTTP requests to the target go through the analyzer's
safe_get, which refuses private and loopback addresses.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import ipaddress
import os
import re
import socket
import ssl
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import quote, urljoin, urlparse

import certifi
import requests
from bs4 import BeautifulSoup

from analyzer import SECURITY_HEADERS, AnalysisError, _host_is_public, _session, _set_cookie_headers, detect_technologies, safe_get

UA = "DeconstructSite-OSINT/1.0 (+https://github.com/sharveshr/deconstruct-site)"
_api = requests.Session()
_api.headers.update({"User-Agent": UA})

# Two-label public suffixes common enough to matter when finding the registrable domain.
_SECOND_LEVEL = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "govt.nz", "ac.nz",
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "edu.in", "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "com.br", "net.br", "org.br", "gov.br", "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "co.za", "org.za", "gov.za", "com.mx", "org.mx", "gob.mx", "com.sg", "edu.sg", "gov.sg",
    "com.tr", "org.tr", "gov.tr", "co.kr", "or.kr", "go.kr", "com.hk", "org.hk", "com.tw", "org.tw",
    "com.ar", "com.co", "com.pe", "com.ph", "com.my", "com.pk", "com.ng", "co.id", "or.id", "go.id",
    "com.sa", "com.eg", "co.il", "org.il", "ac.il", "co.th", "in.th", "com.vn", "com.ua", "co.ke",
}


class OsintError(Exception):
    pass


def normalize_target(raw: str) -> str:
    raw = (raw or "").strip()
    if re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I):
        raw = urlparse(raw).hostname or ""
    host = raw.split("/")[0].split(":")[0].strip().rstrip(".").lower()
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise OsintError("That domain name isn't valid.")
    if not re.fullmatch(r"(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]", host):
        raise OsintError("Enter a domain name like example.com.")
    return host


def org_domain(host: str) -> str:
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _now():
    return datetime.now(timezone.utc)


def _days_until(iso):
    try:
        return (datetime.fromisoformat(iso.replace("Z", "+00:00")) - _now()).days
    except (ValueError, AttributeError):
        return None


# ---------------------------------------------------------------- small TTL cache

_cache: dict = {}
_cache_lock = threading.Lock()


def cached(ttl):
    def deco(fn):
        def wrapper(*args):
            key = (fn.__name__, args)
            with _cache_lock:
                hit = _cache.get(key)
                if hit and hit[0] > time.time():
                    return hit[1]
            value = fn(*args)
            with _cache_lock:
                _cache[key] = (time.time() + ttl, value)
            return value
        return wrapper
    return deco


# ---------------------------------------------------------------- DNS over HTTPS

RTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 257: "CAA", 65: "HTTPS"}
DOH_SERVERS = ["https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"]


def _txt(data: str) -> str:
    # DoH JSON returns TXT as quoted chunks: "\"v=spf1 ...\" \"-all\""
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', data)
    return "".join(p.replace('\\"', '"') for p in parts) if parts else data


@cached(120)
def doh(name: str, rtype: str) -> dict:
    last_err = None
    for server in DOH_SERVERS:
        try:
            r = _api.get(server, params={"name": name, "type": rtype}, headers={"Accept": "application/dns-json"}, timeout=8)
            r.raise_for_status()
            j = r.json()
            answers = [{"name": a["name"].rstrip("."), "type": RTYPES.get(a["type"], str(a["type"])), "ttl": a.get("TTL"),
                        "data": _txt(a["data"]) if a["type"] == 16 else a["data"].rstrip(".") if a["type"] in (2, 5, 12) else a["data"]}
                       for a in j.get("Answer", [])]
            return {"status": j.get("Status"), "answers": answers, "resolver": urlparse(server).hostname}
        except (requests.RequestException, ValueError) as e:
            last_err = e
    raise OsintError(f"DNS lookup failed: {last_err}")


def records(name: str, rtype: str) -> list[str]:
    """Answers of exactly that type (DoH also returns the CNAME chain)."""
    return [a["data"] for a in doh(name, rtype)["answers"] if a["type"] == rtype]


def dns_lookup(host: str) -> dict:
    types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "HTTPS"]
    with ThreadPoolExecutor(len(types)) as pool:
        results = dict(zip(types, pool.map(lambda t: doh(host, t), types)))
    out = {t: [a for a in r["answers"] if a["type"] == t] for t, r in results.items()}
    if out["MX"]:
        out["MX"] = sorted(out["MX"], key=lambda a: int(a["data"].split()[0]) if a["data"].split()[0].isdigit() else 0)
    nx = results["A"]["status"] == 3
    zone = org_domain(host)
    if not out["NS"] and zone != host:
        out["NS"] = [a for a in doh(zone, "NS")["answers"] if a["type"] == "NS"]
    notes = []
    if nx:
        notes.append("The domain does not exist (NXDOMAIN).")
    if not out["A"] and not out["AAAA"] and not out["CNAME"] and not nx:
        notes.append("No A/AAAA records: the name doesn't point at a server.")
    if out["AAAA"]:
        notes.append("IPv6 is enabled (AAAA records present).")
    if not out["CAA"]:
        notes.append("No CAA records: any certificate authority may issue certificates for this domain.")
    if results["A"]["status"] == 0 and out["HTTPS"]:
        notes.append("HTTPS/SVCB records published (used for HTTP/3 and ECH hints).")
    return {"domain": host, "records": out, "resolver": results["A"]["resolver"],
            "count": sum(len(v) for v in out.values()), "notes": notes, "nxdomain": nx}


# ---------------------------------------------------------------- RDAP / WHOIS

def _vcard(entity) -> dict:
    out = {}
    for item in (entity.get("vcardArray") or [None, []])[1]:
        key, _, _, value = item[:4]
        if key in ("fn", "org", "email", "tel", "adr", "kind"):
            out.setdefault(key, value if not isinstance(value, list) else ", ".join(str(v) for v in value if v))
    return out


def _entities(obj, role):
    found = []
    for e in obj.get("entities", []) or []:
        if role in (e.get("roles") or []):
            found.append(e)
        found += _entities(e, role)
    return found


@cached(900)
def _rdap(kind: str, value: str):
    r = _api.get(f"https://rdap.org/{kind}/{quote(value)}", headers={"Accept": "application/rdap+json"}, timeout=15)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json() | {"_source": r.url}


def rdap_lookup(host: str) -> dict:
    candidates = [org_domain(host)]
    if host != candidates[0]:
        candidates.append(host)
    data = None
    for name in candidates:
        try:
            data = _rdap("domain", name)
        except requests.RequestException as e:
            raise OsintError(f"RDAP request failed: {e}")
        if data:
            break
    if not data:
        raise OsintError("No RDAP record found. The TLD may not publish RDAP, or the domain isn't registered.")
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
    registrar = next(iter(_entities(data, "registrar")), {})
    abuse = next(iter(_entities(registrar, "abuse")), {}) if registrar else {}
    registrant = next(iter(_entities(data, "registrant")), {})
    expires = events.get("expiration")
    created = events.get("registration")
    age_days = -_days_until(created) if created else None
    iana_id = next((p.get("identifier") for p in registrar.get("publicIds", []) or [] if "IANA" in (p.get("type") or "")), None)
    rd = _vcard(registrant)
    return {
        "domain": data.get("ldhName", candidates[0]).lower(),
        "handle": data.get("handle"),
        "registrar": _vcard(registrar).get("fn"),
        "registrar_iana_id": iana_id,
        "registrar_url": next((l.get("href") for l in registrar.get("links", []) or [] if l.get("rel") == "about"), None),
        "abuse_email": _vcard(abuse).get("email"),
        "abuse_phone": _vcard(abuse).get("tel"),
        "registrant": {k: v for k, v in rd.items() if k in ("fn", "org", "adr") and v and "redacted" not in str(v).lower()} or None,
        "created": created,
        "updated": events.get("last changed"),
        "expires": expires,
        "days_until_expiry": _days_until(expires) if expires else None,
        "age_years": round(age_days / 365.25, 1) if age_days is not None else None,
        "status": data.get("status", []),
        "nameservers": sorted(ns.get("ldhName", "").lower() for ns in data.get("nameservers", []) or []),
        "dnssec": (data.get("secureDNS") or {}).get("delegationSigned"),
        "source": data["_source"],
    }


# ---------------------------------------------------------------- Certificate Transparency

@cached(900)
def _crtsh(query: str, exclude_expired: bool = False, timeout: int = 45):
    params = {"q": query, "output": "json"}
    if exclude_expired:
        params["exclude"] = "expired"
    r = _api.get("https://crt.sh/", params=params, timeout=timeout)
    r.raise_for_status()
    return r.json()


@cached(900)
def _certspotter(domain: str):
    r = _api.get("https://api.certspotter.com/v1/issuances",
                 params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"}, timeout=25)
    r.raise_for_status()
    return r.json()


@cached(600)   # the takeover check reuses it, and crt.sh is slow
def subdomain_discovery(host: str) -> dict:
    domain = org_domain(host)
    names: dict[str, dict] = {}
    source, error = None, None

    def add(name, first=None, last=None):
        name = name.strip().lower().rstrip(".")
        wildcard = name.startswith("*.")
        name = name.removeprefix("*.")
        if not name or not (name == domain or name.endswith("." + domain)) or " " in name or "@" in name:
            return
        n = names.setdefault(name, {"name": name, "certs": 0, "first_seen": None, "last_seen": None, "wildcard": False})
        n["wildcard"] |= wildcard
        n["certs"] += 1
        if first and (not n["first_seen"] or first < n["first_seen"]):
            n["first_seen"] = first
        if last and (not n["last_seen"] or last > n["last_seen"]):
            n["last_seen"] = last

    try:
        for c in _crtsh(f"%.{domain}"):
            for nv in (c.get("name_value") or "").split("\n"):
                add(nv, (c.get("not_before") or "")[:10], (c.get("not_after") or "")[:10])
        source = "crt.sh"
    except (requests.RequestException, ValueError) as e:
        error = f"crt.sh unavailable ({type(e).__name__})"
        try:
            for c in _certspotter(domain):
                for nv in c.get("dns_names", []):
                    add(nv, (c.get("not_before") or "")[:10], (c.get("not_after") or "")[:10])
            source = "Cert Spotter (crt.sh unavailable)"
        except (requests.RequestException, ValueError) as e2:
            raise OsintError(f"Certificate Transparency sources are unavailable right now (crt.sh: {type(e).__name__}, "
                             f"Cert Spotter: {type(e2).__name__}). Try again in a minute.")

    found = sorted(names.values(), key=lambda n: (n["name"].count("."), n["name"]))

    # Check which names still resolve (bounded, so huge domains stay quick).
    to_check = found[:150]

    def resolve(n):
        try:
            ans = doh(n["name"], "A")["answers"]
            ips = [a["data"] for a in ans if a["type"] == "A"]
            n["resolves"] = bool(ans)
            n["ips"] = ips[:3]
            n["cname"] = next((a["data"] for a in ans if a["type"] == "CNAME"), None)
        except OsintError:
            n["resolves"] = None
        return n

    with ThreadPoolExecutor(16) as pool:
        list(pool.map(resolve, to_check))
    live = sum(1 for n in to_check if n.get("resolves"))
    keywords = re.compile(r"(^|[.-])(dev|staging|stage|test|qa|uat|admin|internal|vpn|jenkins|git|grafana|kibana|old|beta|api|mail|sso|auth)([.-]|$)")
    return {
        "domain": domain, "source": source, "warning": error, "count": len(found),
        "checked": len(to_check), "live": live,
        "notable": [n["name"] for n in found if keywords.search(n["name"].removesuffix(domain))][:40],
        "subdomains": found[:1000],
    }


# ---------------------------------------------------------------- SSL / TLS

def _tls_connect(host, *, version=None, verify=True):
    ctx = ssl.create_default_context(cafile=certifi.where())
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if version:
        ctx.minimum_version = ctx.maximum_version = version
        if version < ssl.TLSVersion.TLSv1_2:
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    sock = socket.create_connection((host, 443), timeout=8)
    return ctx.wrap_socket(sock, server_hostname=host)


def _name(rdn) -> dict:
    return {k: v for part in rdn for (k, v) in part}


def ssl_check(host: str) -> dict:
    if not _host_is_public(host):
        raise OsintError(f"{host} doesn't resolve to a public address.")
    verify_error = None
    try:
        s = _tls_connect(host)
    except ssl.SSLCertVerificationError as e:
        verify_error = e.verify_message or str(e)
        s = _tls_connect(host, verify=False)
    except (OSError, ssl.SSLError) as e:
        raise OsintError(f"Couldn't open a TLS connection to {host}:443 ({e}).")
    with s:
        cert = s.getpeercert() or {}
        der = s.getpeercert(binary_form=True)
        proto, cipher, alpn = s.version(), s.cipher(), s.selected_alpn_protocol()

    def parse_time(t):
        return datetime.strptime(t, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc) if t else None

    nb, na = parse_time(cert.get("notBefore")), parse_time(cert.get("notAfter"))
    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]

    # Which protocol versions does the server accept?
    versions = {}
    for label, v in (("TLS 1.3", ssl.TLSVersion.TLSv1_3), ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
                     ("TLS 1.1", ssl.TLSVersion.TLSv1_1), ("TLS 1.0", ssl.TLSVersion.TLSv1)):
        try:
            with _tls_connect(host, version=v, verify=False):
                versions[label] = True
        except ssl.SSLError as e:
            versions[label] = None if "UNSUPPORTED_PROTOCOL" in str(e) and v < ssl.TLSVersion.TLSv1_2 and "alert" not in str(e).lower() else False
        except (OSError, ValueError):
            versions[label] = None

    recent = []
    ct_error, ct_source = None, "crt.sh"
    try:
        # Supplementary data, so don't let a busy crt.sh hold up the certificate check.
        for c in sorted(_crtsh(host, True, 15), key=lambda c: c.get("not_before") or "", reverse=True)[:12]:
            recent.append({"id": c.get("id"), "issuer": _issuer_cn(c.get("issuer_name")), "not_before": (c.get("not_before") or "")[:10],
                           "not_after": (c.get("not_after") or "")[:10], "names": (c.get("name_value") or "").split("\n")[:6]})
    except (requests.RequestException, ValueError) as e:
        try:
            r = _api.get("https://api.certspotter.com/v1/issuances",
                         params={"domain": host, "expand": ["dns_names", "issuer"]}, timeout=12)
            r.raise_for_status()
            for c in sorted(r.json(), key=lambda c: c.get("not_before") or "", reverse=True)[:12]:
                recent.append({"id": None, "issuer": (c.get("issuer") or {}).get("friendly_name") or _issuer_cn((c.get("issuer") or {}).get("name")),
                               "not_before": (c.get("not_before") or "")[:10], "not_after": (c.get("not_after") or "")[:10],
                               "names": c.get("dns_names", [])[:6]})
            ct_source = "Cert Spotter"
        except (requests.RequestException, ValueError):
            ct_error = f"Certificate Transparency logs unavailable (crt.sh: {type(e).__name__})"

    issues = []
    days_left = (na - _now()).days if na else None
    if verify_error:
        issues.append(f"Certificate doesn't validate: {verify_error}.")
    if days_left is not None and days_left < 14:
        issues.append(f"Certificate expires in {days_left} days.")
    if versions.get("TLS 1.0") or versions.get("TLS 1.1"):
        issues.append("Server still accepts TLS 1.0/1.1, which are deprecated.")
    if not versions.get("TLS 1.3"):
        issues.append("TLS 1.3 is not supported.")
    return {
        "host": host,
        "valid": verify_error is None,
        "verify_error": verify_error,
        "subject": _name(cert.get("subject", ())).get("commonName"),
        "issuer": _name(cert.get("issuer", ())).get("organizationName") or _name(cert.get("issuer", ())).get("commonName"),
        "issuer_cn": _name(cert.get("issuer", ())).get("commonName"),
        "not_before": nb.isoformat() if nb else None,
        "not_after": na.isoformat() if na else None,
        "days_left": days_left,
        "lifetime_days": (na - nb).days if na and nb else None,
        "serial": cert.get("serialNumber"),
        "sha256": ":".join(f"{b:02X}" for b in hashlib.sha256(der).digest()) if der else None,
        "sans": sans, "san_count": len(sans),
        "ocsp": list(cert.get("OCSP", ())), "ca_issuers": list(cert.get("caIssuers", ())),
        "crl": list(cert.get("crlDistributionPoints", ())),
        "protocol": proto, "cipher": cipher[0] if cipher else None, "cipher_bits": cipher[2] if cipher else None, "alpn": alpn,
        "versions": versions,
        "recent_certificates": recent, "ct_warning": ct_error, "ct_source": ct_source,
        "issues": issues,
    }


def _issuer_cn(dn):
    m = re.search(r"O=([^,]+)", dn or "") or re.search(r"CN=([^,]+)", dn or "")
    return m.group(1).strip('"') if m else dn


# ---------------------------------------------------------------- HTTP headers

def _fetch(host, path="/", max_bytes=2_000_000, timeout=12):
    try:
        return safe_get(_session(), f"https://{host}{path}", max_bytes=max_bytes, timeout=timeout)
    except requests.exceptions.SSLError:
        return safe_get(_session(), f"http://{host}{path}", max_bytes=max_bytes, timeout=timeout)
    except AnalysisError as e:
        raise OsintError(str(e))
    except requests.RequestException as e:
        raise OsintError(f"Couldn't fetch https://{host}{path} ({type(e).__name__}).")


def _parse_csp(value):
    directives = {}
    for part in value.split(";"):
        bits = part.strip().split()
        if bits:
            directives[bits[0].lower()] = bits[1:]
    warnings = []
    script = directives.get("script-src", directives.get("default-src", []))
    if "'unsafe-inline'" in script and not any(s.startswith(("'nonce-", "'sha")) for s in script):
        warnings.append("script-src allows 'unsafe-inline' without nonces or hashes.")
    if "'unsafe-eval'" in script:
        warnings.append("script-src allows 'unsafe-eval'.")
    if "*" in script or any(s in ("http:", "https:") for s in script):
        warnings.append("script-src allows scripts from any host.")
    for d in ("default-src", "object-src", "base-uri", "frame-ancestors"):
        if d not in directives and not (d == "object-src" and "default-src" in directives):
            warnings.append(f"No {d} directive.")
    return directives, warnings


def header_analysis(host: str) -> dict:
    t0 = time.perf_counter()
    resp, _, chain = _fetch(host, max_bytes=1)
    ms = round((time.perf_counter() - t0) * 1000)
    h = {k.lower(): v for k, v in resp.headers.items()}
    checks = []
    for name, why in SECURITY_HEADERS.items():
        present = name in h
        if name == "x-frame-options" and not present and "frame-ancestors" in h.get("content-security-policy", ""):
            present, h_val = True, "(covered by CSP frame-ancestors)"
        else:
            h_val = h.get(name)
        checks.append({"name": name, "present": present, "value": h_val, "why": why})
    score = sum(c["present"] for c in checks)
    grade = "A" if score >= 6 else "B" if score >= 5 else "C" if score >= 4 else "D" if score >= 2 else "F"

    hsts = None
    if "strict-transport-security" in h:
        v = h["strict-transport-security"]
        m = re.search(r"max-age=(\d+)", v)
        hsts = {"max_age": int(m.group(1)) if m else None, "include_subdomains": "includesubdomains" in v.lower(),
                "preload": "preload" in v.lower()}
    csp = None
    csp_value = h.get("content-security-policy") or h.get("content-security-policy-report-only")
    if csp_value:
        directives, warnings = _parse_csp(csp_value)
        csp = {"report_only": "content-security-policy" not in h, "directives": directives, "warnings": warnings}

    cookies = []
    for c in _set_cookie_headers(resp):
        attrs = dict((a.split("=", 1) + [""])[:2] for a in (p.strip() for p in c.split(";")[1:]) if a)
        attrs = {k.lower(): v for k, v in attrs.items()}
        cookies.append({"name": c.split("=", 1)[0].strip(), "secure": "secure" in attrs, "http_only": "httponly" in attrs,
                        "same_site": attrs.get("samesite"), "domain": attrs.get("domain"), "path": attrs.get("path"),
                        "expires": attrs.get("expires") or (f"max-age {attrs['max-age']}" if "max-age" in attrs else "session")})
    leaks = [{"header": k, "value": h[k]} for k in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                                                     "x-generator", "x-drupal-cache", "x-runtime", "via") if k in h]
    issues = [f"Missing {c['name']}." for c in checks if not c["present"]]
    if hsts and (hsts["max_age"] or 0) < 15552000:
        issues.append("HSTS max-age is under 180 days.")
    if csp:
        issues += [f"CSP: {w}" for w in csp["warnings"]]
        if csp["report_only"]:
            issues.append("CSP is report-only, so it isn't enforced.")
    for c in cookies:
        if not c["secure"] or not c["http_only"]:
            issues.append(f"Cookie {c['name']} is missing {'Secure' if not c['secure'] else ''}{' and ' if not c['secure'] and not c['http_only'] else ''}{'HttpOnly' if not c['http_only'] else ''}.")
    if h.get("access-control-allow-origin") == "*" and h.get("access-control-allow-credentials") == "true":
        issues.append("CORS allows any origin with credentials.")
    for l in leaks:
        if re.search(r"\d", l["value"]) and l["header"] in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
            issues.append(f"{l['header']} reveals a software version ({l['value']}).")
    return {
        "url": resp.url, "status": resp.status_code, "response_ms": ms, "redirects": len(chain),
        "grade": grade, "score": score, "out_of": len(checks), "checks": checks, "hsts": hsts, "csp": csp,
        "cookies": cookies, "info_leaks": leaks,
        "caching": {k: h[k] for k in ("cache-control", "expires", "etag", "last-modified", "age", "vary", "cdn-cache-control") if k in h},
        "cors": {k: h[k] for k in h if k.startswith("access-control-")},
        "issues": issues,
        "headers": dict(sorted(resp.headers.items(), key=lambda kv: kv[0].lower())),
    }


# ---------------------------------------------------------------- Technology detection

def tech_detection(host: str) -> dict:
    resp, body, _ = _fetch(host, max_bytes=4_000_000)
    html = body.decode(resp.encoding or "utf-8", "replace")
    soup = BeautifulSoup(html, "html.parser")
    tech = detect_technologies(resp, html, soup, _set_cookie_headers(resp))
    gen = soup.find("meta", attrs={"name": "generator"})
    return {"url": resp.url, "status": resp.status_code, "count": tech["count"], "by_category": tech["by_category"],
            "generator": gen.get("content") if gen else None,
            "note": "Detected from HTML, headers and cookies. A full analysis also loads the page in a browser to catch runtime libraries."}


# ---------------------------------------------------------------- IP / ASN

def _cymru(ip: ipaddress._BaseAddress):
    if ip.version == 4:
        q = ".".join(reversed(str(ip).split("."))) + ".origin.asn.cymru.com"
    else:
        q = ip.reverse_pointer.removesuffix(".ip6.arpa") + ".origin6.asn.cymru.com"
    txt = records(q, "TXT")
    if not txt:
        return None
    asn, prefix, cc, registry, allocated = [p.strip() for p in txt[0].split("|")][:5]
    asn = asn.split()[0]
    name = records(f"AS{asn}.asn.cymru.com", "TXT")
    as_name = name[0].split("|")[-1].strip() if name else None
    return {"asn": int(asn), "prefix": prefix, "country": cc, "registry": registry.upper(), "allocated": allocated, "as_name": as_name}


def ip_asn_lookup(host: str) -> dict:
    ips = records(host, "A")[:4] + records(host, "AAAA")[:2]
    if not ips:
        raise OsintError(f"{host} has no A or AAAA records.")

    def one(ip_s):
        ip = ipaddress.ip_address(ip_s)
        out = {"ip": ip_s, "version": ip.version, "public": ip.is_global}
        if not ip.is_global:
            return out | {"note": "Private or reserved address."}
        try:
            out["ptr"] = (records(ip.reverse_pointer, "PTR") or [None])[0]
        except OsintError:
            out["ptr"] = None
        try:
            out["asn"] = _cymru(ip)
        except (OsintError, ValueError):
            out["asn"] = None
        try:
            r = _rdap("ip", ip_s)
            if r:
                org = next(iter(_entities(r, "registrant")), None) or next(iter(_entities(r, "administrative")), None)
                abuse = next(iter(_entities(r, "abuse")), None)
                cidrs = [f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}" for c in r.get("cidr0_cidrs", [])]
                out["network"] = {"name": r.get("name"), "handle": r.get("handle"), "range": f"{r.get('startAddress')} – {r.get('endAddress')}",
                                  "cidr": cidrs, "country": r.get("country"), "type": r.get("type"),
                                  "org": _vcard(org).get("fn") if org else None, "abuse_email": _vcard(abuse).get("email") if abuse else None,
                                  "source": r["_source"]}
        except requests.RequestException:
            out["network"] = None
        return out

    with ThreadPoolExecutor(6) as pool:
        result = list(pool.map(one, ips))
    providers = Counter((r.get("asn") or {}).get("as_name") for r in result if r.get("asn"))
    return {"host": host, "addresses": result, "providers": [p for p, _ in providers.most_common() if p]}


# ---------------------------------------------------------------- Website history (Internet Archive)

def website_history(host: str) -> dict:
    try:
        avail = _api.get("https://archive.org/wayback/available", params={"url": host}, timeout=15).json()
        closest = (avail.get("archived_snapshots") or {}).get("closest")
    except (requests.RequestException, ValueError):
        closest = None
    try:
        r = _api.get("https://web.archive.org/cdx/search/cdx",
                     params={"url": host, "output": "json", "fl": "timestamp,statuscode,original", "collapse": "timestamp:6",
                             "filter": "statuscode:200"}, timeout=35)
        r.raise_for_status()
        rows = r.json()[1:] if r.text.strip() else []
    except (requests.RequestException, ValueError) as e:
        if not closest:
            raise OsintError(f"The Internet Archive didn't respond ({type(e).__name__}). It's often slow; try again.")
        rows = []

    def snap(ts, original=None):
        return {"timestamp": ts, "date": f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}",
                "url": f"https://web.archive.org/web/{ts}/{original or host}"}

    by_year = Counter(row[0][:4] for row in rows)
    return {
        "host": host,
        "months_captured": len(rows),
        "first": snap(rows[0][0], rows[0][2]) if rows else None,
        "last": snap(rows[-1][0], rows[-1][2]) if rows else None,
        "closest": snap(closest["timestamp"], closest.get("url")) if closest else None,
        "by_year": [{"year": y, "months": by_year[y]} for y in sorted(by_year)],
        "recent": [snap(r[0], r[2]) for r in rows[-12:]][::-1],
        "earliest": [snap(r[0], r[2]) for r in rows[:5]],
        "calendar_url": f"https://web.archive.org/web/*/{host}",
    }


# ---------------------------------------------------------------- robots.txt

AI_BOTS = ["GPTBot", "ChatGPT-User", "OAI-SearchBot", "ClaudeBot", "anthropic-ai", "Claude-Web", "CCBot", "Google-Extended",
           "PerplexityBot", "Bytespider", "Applebot-Extended", "meta-externalagent", "Amazonbot", "cohere-ai"]
SENSITIVE = re.compile(r"admin|login|signin|wp-admin|backup|\.git|\.env|config|private|internal|staging|dev\b|test|api|cgi-bin|phpmyadmin|dashboard|account|checkout|cart|search|tmp|old", re.I)


def _robots_raw(host):
    resp, body, _ = _fetch(host, "/robots.txt", max_bytes=600_000)
    text = body.decode("utf-8", "replace")
    looks_html = text.lstrip()[:15].lower().startswith(("<!doctype", "<html"))
    return resp, text, looks_html


def _parse_robots(text):
    groups, current, sitemaps, last_was_agent = [], None, [], False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        key, value = [p.strip() for p in line.split(":", 1)]
        key = key.lower()
        if key == "user-agent":
            if not last_was_agent or current is None:
                current = {"agents": [], "allow": [], "disallow": [], "crawl_delay": None}
                groups.append(current)
            current["agents"].append(value)
            last_was_agent = True
            continue
        last_was_agent = False
        if key == "sitemap":
            sitemaps.append(value)
        elif current is not None and key in ("allow", "disallow"):
            if value or key == "allow":
                current[key].append(value)
        elif current is not None and key == "crawl-delay":
            current["crawl_delay"] = value
    return groups, sitemaps


def robots_analysis(host: str) -> dict:
    resp, text, looks_html = _robots_raw(host)
    if resp.status_code >= 400:
        return {"exists": False, "status": resp.status_code, "url": resp.url, "issues": [f"No robots.txt (HTTP {resp.status_code}): crawlers may fetch everything."]}
    if looks_html:
        return {"exists": False, "status": resp.status_code, "url": resp.url,
                "issues": ["/robots.txt returns an HTML page (probably the site's catch-all route), not a robots file."]}
    groups, sitemaps = _parse_robots(text)

    def blocks_all(g):
        return "/" in g["disallow"] and "/" not in g["allow"]

    star = next((g for g in groups if "*" in g["agents"]), None)
    ai = []
    for bot in AI_BOTS:
        g = next((g for g in groups if any(a.lower() == bot.lower() for a in g["agents"])), None)
        ai.append({"bot": bot, "status": "blocked" if g and blocks_all(g) else "partially blocked" if g and g["disallow"]
                   else "allowed" if g else ("blocked (via *)" if star and blocks_all(star) else "not listed")})
    disallowed = sorted({p for g in groups for p in g["disallow"]})
    issues = []
    if star and blocks_all(star):
        issues.append("All crawlers are blocked from the whole site (User-agent: * / Disallow: /).")
    if not sitemaps:
        issues.append("No Sitemap: line.")
    if len(text) > 500_000:
        issues.append("robots.txt is over 500 KB; Google ignores content past that.")
    return {
        "exists": True, "status": resp.status_code, "url": resp.url, "content_type": resp.headers.get("content-type"),
        "size": len(text), "groups": groups, "sitemaps": sitemaps,
        "rule_count": sum(len(g["allow"]) + len(g["disallow"]) for g in groups),
        "user_agents": [a for g in groups for a in g["agents"]],
        "interesting_paths": [p for p in disallowed if SENSITIVE.search(p)][:40],
        "ai_crawlers": ai,
        "issues": issues,
        "raw": text[:20000],
    }


# ---------------------------------------------------------------- sitemap

def _get_sitemap(url):
    resp, body, _ = safe_get(_session(), url, max_bytes=12_000_000, timeout=20)
    if body[:2] == b"\x1f\x8b":
        try:
            body = gzip.decompress(body)[:30_000_000]
        except OSError:
            pass
    return resp, body.decode("utf-8", "replace")


def sitemap_analysis(host: str) -> dict:
    sources = []
    try:
        resp, text, looks_html = _robots_raw(host)
        if resp.status_code < 400 and not looks_html:
            sources = _parse_robots(text)[1]
    except OsintError:
        pass
    discovered_from = "robots.txt" if sources else "common locations"
    if not sources:
        sources = [f"https://{host}{p}" for p in ("/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml", "/wp-sitemap.xml")]

    queue, seen, fetched, urls, errors = list(sources), set(), [], [], []
    extensions = Counter()
    while queue and len(fetched) < 20:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        try:
            resp, text = _get_sitemap(url)
        except (requests.RequestException, AnalysisError) as e:
            errors.append({"url": url, "error": type(e).__name__ if isinstance(e, requests.RequestException) else str(e)})
            continue
        if resp.status_code >= 400 or "<" not in text[:500]:
            if discovered_from == "robots.txt":
                errors.append({"url": url, "error": f"HTTP {resp.status_code}"})
            continue
        if text.lstrip()[:15].lower().startswith(("<!doctype", "<html")):
            continue
        is_index = re.search(r"<sitemapindex", text[:3000], re.I) is not None
        locs = re.findall(r"<loc>\s*(?:<!\[CDATA\[)?\s*([^<\]\s]+)", text, re.I)
        for ns in ("image", "video", "news", "xhtml"):
            if f"xmlns:{ns}" in text[:3000]:
                extensions[ns] += 1
        fetched.append({"url": url, "type": "index" if is_index else "urlset", "entries": len(locs)})
        if is_index:
            queue.extend(l for l in locs if l not in seen)
        else:
            for block in re.findall(r"<url>(.*?)</url>", text, re.I | re.S)[:60000]:
                loc = re.search(r"<loc>\s*(?:<!\[CDATA\[)?\s*([^<\]\s]+)", block, re.I)
                if loc:
                    lm = re.search(r"<lastmod>\s*([^<\s]+)", block, re.I)
                    urls.append((loc.group(1), lm.group(1)[:10] if lm else None))
        if not discovered_from == "robots.txt" and fetched:
            queue = [q for q in queue if q not in sources]   # found one at a common path; skip the other guesses
    if not fetched:
        if errors:
            listed = "; ".join(f"{e['url']} ({e['error']})" for e in errors[:3])
            raise OsintError(f"robots.txt lists sitemaps, but none could be read: {listed}. "
                             "The server may block automated clients.")
        raise OsintError("No sitemap found (checked robots.txt and the usual /sitemap.xml locations).")

    sections = Counter((urlparse(u).path.strip("/").split("/") or [""])[0] or "/" for u, _ in urls)
    hosts = Counter(urlparse(u).hostname for u, _ in urls)
    lastmods = sorted(l for _, l in urls if l)
    years = Counter(l[:4] for l in lastmods)
    return {
        "discovered_from": discovered_from, "sitemaps": fetched, "errors": errors[:10],
        "total_urls": len(urls), "unique_urls": len({u for u, _ in urls}),
        "hosts": hosts.most_common(5),
        "sections": sections.most_common(20),
        "lastmod_range": [lastmods[0], lastmods[-1]] if lastmods else None,
        "with_lastmod": len(lastmods),
        "lastmod_by_year": sorted(years.items()),
        "extensions": sorted(extensions),
        "sample": [{"url": u, "lastmod": l} for u, l in urls[:400]],
        "truncated": len(fetched) >= 20 and bool(queue),
    }


# ---------------------------------------------------------------- email security

DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "k2", "k3", "s1", "s2", "mail", "dkim", "email", "smtp",
                  "mandrill", "mxvault", "zoho", "zmail", "protonmail", "protonmail2", "protonmail3", "pm", "everlytickey1",
                  "sendgrid", "smtpapi", "mailjet", "ses", "amazonses", "cm", "fm1", "fm2", "fm3", "mailo", "key1", "key2",
                  "sig1", "dk", "mx", "hs1", "hs2", "hubspot", "intercom", "postmark", "pf2014", "spop1024", "turbo-smtp", "200608"]


def _spf_lookups(domain, depth=0, seen=None):
    """Counts DNS-querying mechanisms (RFC 7208 caps them at 10), following include/redirect."""
    seen = seen or set()
    if depth > 4 or domain in seen:
        return 0, []
    seen.add(domain)
    spf = [t for t in records(domain, "TXT") if t.lower().startswith("v=spf1")]
    if not spf:
        return 0, [domain]
    count, missing = 0, []
    for term in spf[0].split()[1:]:
        t = term.lstrip("+-~?").lower()
        if t.startswith(("include:", "redirect=")):
            count += 1
            sub = term.split(":", 1)[1] if ":" in term else term.split("=", 1)[1]
            c, m = _spf_lookups(sub, depth + 1, seen)
            count += c
            missing += m
        elif t.startswith(("a", "mx", "ptr", "exists:")) and not t.startswith("all"):
            count += 1
    return count, missing


def _tags(record):
    return {k.strip().lower(): v.strip() for k, v in (p.split("=", 1) for p in record.split(";") if "=" in p)}


def email_security(host: str) -> dict:
    domain = org_domain(host) if host.startswith("www.") or host.count(".") > org_domain(host).count(".") else host
    mx = records(domain, "MX")
    null_mx = any(m.split()[-1] in (".", "") for m in mx)
    txt = records(domain, "TXT")
    spf_records = [t for t in txt if t.lower().startswith("v=spf1")]
    spf = None
    if spf_records:
        rec = spf_records[0]
        allq = next((t for t in rec.split() if t.lstrip("+-~?").lower() == "all"), None)
        lookups, broken = _spf_lookups(domain)
        spf = {"record": rec, "count": len(spf_records), "all": allq,
               "policy": {"-all": "fail (strict)", "~all": "softfail", "?all": "neutral", "+all": "pass (anyone may send!)", "all": "pass (anyone may send!)"}.get(allq or "", "no 'all' mechanism"),
               "dns_lookups": lookups, "broken_includes": [b for b in broken if b != domain],
               "mechanisms": rec.split()[1:]}
    dmarc_domain = f"_dmarc.{domain}"
    dmarc_rec = [t for t in records(dmarc_domain, "TXT") if t.lower().startswith("v=dmarc1")]
    if not dmarc_rec and domain != org_domain(domain):
        dmarc_domain = f"_dmarc.{org_domain(domain)}"
        dmarc_rec = [t for t in records(dmarc_domain, "TXT") if t.lower().startswith("v=dmarc1")]
    dmarc = None
    if dmarc_rec:
        tags = _tags(dmarc_rec[0])
        dmarc = {"record": dmarc_rec[0], "found_at": dmarc_domain, "policy": tags.get("p"), "subdomain_policy": tags.get("sp"),
                 "pct": int(tags["pct"]) if tags.get("pct", "").isdigit() else 100,
                 "rua": tags.get("rua"), "ruf": tags.get("ruf"), "adkim": tags.get("adkim", "r"), "aspf": tags.get("aspf", "r")}

    def probe(sel):
        try:
            ans = doh(f"{sel}._domainkey.{domain}", "TXT")["answers"]
        except OsintError:
            return None
        recs = [a["data"] for a in ans if a["type"] == "TXT" and ("p=" in a["data"] or "v=dkim1" in a["data"].lower())]
        if not recs:
            return None
        tags = _tags(recs[0])
        p = re.sub(r"\s", "", tags.get("p", ""))
        bits = None
        if p and tags.get("k", "rsa").lower() == "rsa":
            n = len(base64.b64decode(p + "==", validate=False)) if re.fullmatch(r"[A-Za-z0-9+/=]+", p) else 0
            bits = min((1024, 2048, 3072, 4096), key=lambda b: abs(b - (n - 38) * 8)) if n > 60 else None
        cname = next((a["data"] for a in ans if a["type"] == "CNAME"), None)
        return {"selector": sel, "key_type": tags.get("k", "rsa"), "key_bits": bits, "revoked": not p, "via_cname": cname}

    # A domain that sends no mail often publishes "*._domainkey TXT v=DKIM1; p=" (a revoked wildcard),
    # which would make every selector look present. Probe a selector nobody uses first.
    dkim_wildcard = probe(f"zz-nonexistent-{int(time.time()) % 100000}")
    if dkim_wildcard:
        dkim = []
    else:
        with ThreadPoolExecutor(16) as pool:
            dkim = [d for d in pool.map(probe, DKIM_SELECTORS) if d]

    mta_sts = [t for t in records(f"_mta-sts.{domain}", "TXT") if t.lower().startswith("v=stsv1")]
    mta_mode = None
    if mta_sts:
        try:
            r, body, _ = safe_get(_session(), f"https://mta-sts.{domain}/.well-known/mta-sts.txt", max_bytes=20_000, timeout=8)
            m = re.search(r"mode:\s*(\w+)", body.decode("utf-8", "replace"))
            mta_mode = m.group(1) if m and r.status_code == 200 else None
        except (requests.RequestException, AnalysisError):
            pass
    tls_rpt = [t for t in records(f"_smtp._tls.{domain}", "TXT") if t.lower().startswith("v=tlsrptv1")]
    bimi = [t for t in records(f"default._bimi.{domain}", "TXT") if t.lower().startswith("v=bimi1")]

    issues, passed = [], []
    if not mx:
        issues.append("No MX records: the domain can't receive email.")
    elif null_mx:
        passed.append("Null MX published: the domain explicitly accepts no email.")
    if not spf:
        issues.append("No SPF record: anyone can claim to send mail from this domain.")
    else:
        if spf["count"] > 1:
            issues.append("More than one SPF record (that's a permanent error for receivers).")
        if spf["all"] in ("+all", "all"):
            issues.append("SPF ends in +all, which authorizes every server on the internet.")
        elif spf["all"] == "?all" or not spf["all"]:
            issues.append("SPF doesn't end in -all or ~all, so it doesn't reject spoofed mail.")
        else:
            passed.append(f"SPF ends in {spf['all']}.")
        if spf["dns_lookups"] > 10:
            issues.append(f"SPF needs {spf['dns_lookups']} DNS lookups (limit is 10), so receivers will treat it as an error.")
        if spf["broken_includes"]:
            issues.append(f"SPF includes domains with no SPF record: {', '.join(spf['broken_includes'][:5])}.")
    if not dmarc:
        issues.append("No DMARC record: spoofed mail isn't rejected and you get no reports.")
    else:
        if dmarc["policy"] == "none":
            issues.append("DMARC policy is p=none (monitoring only; spoofed mail is still delivered).")
        elif dmarc["policy"] in ("quarantine", "reject"):
            passed.append(f"DMARC enforces p={dmarc['policy']}.")
        if dmarc["pct"] < 100:
            issues.append(f"DMARC applies to only {dmarc['pct']}% of mail.")
        if not dmarc["rua"]:
            issues.append("DMARC has no rua= address, so no aggregate reports are sent.")
    if dkim_wildcard:
        if dkim_wildcard["revoked"]:
            passed.append("Wildcard DKIM record with an empty (revoked) key: the domain declares it signs no mail.")
        else:
            issues.append("A wildcard DKIM record answers for every selector, so individual keys can't be checked.")
    elif dkim:
        live = [d for d in dkim if not d["revoked"]]
        passed.append(f"DKIM keys found for selector{'s' if len(live) != 1 else ''}: {', '.join(d['selector'] for d in live)}.")
        weak = [d["selector"] for d in live if d["key_bits"] and d["key_bits"] < 2048]
        if weak:
            issues.append(f"DKIM key under 2048 bits: {', '.join(weak)}.")
    elif mx and not null_mx:
        issues.append(f"No DKIM key found on {len(DKIM_SELECTORS)} common selectors (it may use a custom selector).")
    if mta_sts:
        passed.append(f"MTA-STS published{f' (mode: {mta_mode})' if mta_mode else ''}.")
    if tls_rpt:
        passed.append("TLS-RPT reporting enabled.")
    if bimi:
        passed.append("BIMI logo record published.")

    points = sum([bool(spf and spf["all"] in ("-all", "~all")), bool(dmarc and dmarc["policy"] in ("quarantine", "reject")),
                  bool(dmarc), bool(dkim), bool(mta_sts), bool(tls_rpt)])
    grade = "A" if points >= 5 else "B" if points == 4 else "C" if points == 3 else "D" if points >= 1 else "F"
    # A domain that sends no mail and says so everywhere is as protected as it gets.
    if null_mx and spf and spf["all"] == "-all" and dmarc and dmarc["policy"] == "reject":
        grade = "A"
        passed.append("Locked down as a no-mail domain (null MX, SPF -all, DMARC reject).")
    return {
        "domain": domain, "grade": grade,
        "mx": mx, "null_mx": null_mx, "spf": spf, "dmarc": dmarc, "dkim": dkim, "dkim_selectors_checked": len(DKIM_SELECTORS),
        "dkim_wildcard": dkim_wildcard,
        "mta_sts": {"record": mta_sts[0], "mode": mta_mode} if mta_sts else None,
        "tls_rpt": tls_rpt[0] if tls_rpt else None, "bimi": bimi[0] if bimi else None,
        "issues": issues, "passed": passed,
    }


# ---------------------------------------------------------------- redirects

def _follow(url, max_hops=10):
    s = _session()
    hops, seen = [], set()
    for _ in range(max_hops + 1):
        host = urlparse(url).hostname or ""
        public = _host_is_public(host)
        if public is None:
            return hops, f"{host} doesn't resolve."
        if not public:
            return hops, f"{host} is not a public address."
        if url in seen:
            return hops, "Redirect loop."
        seen.add(url)
        t0 = time.perf_counter()
        try:
            r = s.get(url, allow_redirects=False, stream=True, timeout=10)
        except requests.exceptions.SSLError:
            return hops, "TLS/certificate error."
        except requests.RequestException as e:
            return hops, f"{type(e).__name__}"
        hop = {"url": url, "status": r.status_code, "ms": round((time.perf_counter() - t0) * 1000),
               "location": r.headers.get("location"), "server": r.headers.get("server"),
               "hsts": "strict-transport-security" in {k.lower() for k in r.headers}}
        if r.is_redirect or r.is_permanent_redirect:
            nxt = urljoin(url, r.headers.get("location", ""))
            hop["location"] = nxt
            r.close()
            hops.append(hop)
            url = nxt
            continue
        body = b""
        for chunk in r.iter_content(16384):
            body += chunk
            if len(body) > 65536:
                break
        r.close()
        m = re.search(rb'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']?\s*\d+\s*;\s*url=([^"\'>\s]+)', body, re.I)
        if m:
            hop["meta_refresh"] = urljoin(url, m.group(1).decode("utf-8", "replace"))
        hops.append(hop)
        return hops, None
    return hops, f"More than {max_hops} redirects."


def redirect_analysis(host: str) -> dict:
    bare = host.removeprefix("www.")
    variants = [f"http://{bare}/", f"https://{bare}/", f"http://www.{bare}/", f"https://www.{bare}/"]
    with ThreadPoolExecutor(4) as pool:
        results = list(pool.map(_follow, variants))
    chains = []
    for start, (hops, error) in zip(variants, results):
        final = hops[-1]["url"] if hops and not error else None
        chains.append({"start": start, "hops": hops, "error": error, "final_url": final,
                       "final_status": hops[-1]["status"] if hops and not error else None, "redirects": max(0, len(hops) - 1)})
    finals = {c["final_url"] for c in chains if c["final_url"]}
    issues, good = [], []
    for c in chains:
        if c["start"].startswith("http://") and c["final_url"] and c["final_url"].startswith("http://"):
            issues.append(f"{c['start']} is served over plain HTTP without redirecting to HTTPS.")
        if any(h["url"].startswith("https://") and (h["location"] or "").startswith("http://") for h in c["hops"]):
            issues.append(f"{c['start']} downgrades from HTTPS to HTTP during redirects.")
        if c["redirects"] > 2:
            issues.append(f"{c['start']} takes {c['redirects']} redirects to settle (each adds latency).")
        if c["hops"] and c["hops"][-1].get("meta_refresh"):
            issues.append(f"{c['final_url']} uses a <meta refresh> redirect.")
    if len(finals) > 1:
        issues.append(f"The variants end on {len(finals)} different URLs, so there is no single canonical address.")
    elif finals:
        good.append(f"All working variants end on {next(iter(finals))}.")
    if all(c["final_url"] is None or c["final_url"].startswith("https://") for c in chains):
        good.append("Plain-HTTP requests end on HTTPS.")
    temp = [c["start"] for c in chains if any(h["status"] in (302, 307) for h in c["hops"][:-1])]
    if temp:
        issues.append(f"Temporary (302/307) redirects used for {', '.join(temp)}; permanent (301/308) is better for canonical moves.")
    return {"host": bare, "chains": chains, "canonical": next(iter(finals)) if len(finals) == 1 else None,
            "final_urls": sorted(finals), "issues": issues, "passed": good}


# ---------------------------------------------------------------- registry

# ---------------------------------------------------------------- subdomain takeover

# (service, CNAME pattern, body fingerprint of an unclaimed resource or None, takeover possible when the CNAME target is NXDOMAIN)
# Services whose takeovers are documented in the community "can-i-take-over-xyz" list.
TAKEOVER_SERVICES = [
    ("GitHub Pages", r"\.github\.io$", r"There isn't a GitHub Pages site here", False),
    ("Heroku", r"\.(herokuapp|herokudns|herokussl)\.com$", r"No such app|herokucdn\.com/error-pages/no-such-app", True),
    ("Amazon S3", r"\.s3[.-]([a-z0-9-]+\.)?amazonaws\.com$|\.s3-website[.-]", r"NoSuchBucket|The specified bucket does not exist", False),
    ("Google Cloud Storage", r"c\.storage\.googleapis\.com$", r"NoSuchBucket", False),
    ("Azure", r"\.(azurewebsites\.net|cloudapp\.net|cloudapp\.azure\.com|trafficmanager\.net|blob\.core\.windows\.net|azureedge\.net"
              r"|azure-api\.net|azurecontainer\.io|azurefd\.net|azurestaticapps\.net|azurehdinsight\.net|servicebus\.windows\.net)$", None, True),
    ("AWS Elastic Beanstalk", r"\.elasticbeanstalk\.com$", None, True),
    ("Shopify", r"\.myshopify\.com$", r"Sorry, this shop is currently unavailable", False),
    ("Fastly", r"\.fastly\.net$", r"Fastly error: unknown domain", False),
    ("Ghost", r"\.ghost\.io$", r"The thing you were looking for is no longer here|Domain error", False),
    ("Pantheon", r"\.pantheonsite\.io$", r"404 error unknown site", False),
    ("Surge.sh", r"\.surge\.sh$", r"project not found", False),
    ("Bitbucket", r"\.bitbucket\.io$", r"Repository not found", False),
    ("Zendesk", r"\.zendesk\.com$", r"Help Center Closed", False),
    ("Tumblr", r"domains\.tumblr\.com$", r"Whatever you were looking for doesn't currently exist at this address", False),
    ("WordPress.com", r"\.wordpress\.com$", r"Do you want to register", False),
    ("ReadMe", r"\.readme\.io$", r"Project doesnt exist\.\.\. yet!", False),
    ("Help Scout", r"\.helpscoutdocs\.com$", r"No settings were found for this company", False),
    ("Webflow", r"proxy(-ssl)?\.webflow\.com$", r"The page you are looking for doesn't exist or has been moved", False),
    ("Unbounce", r"unbouncepages\.com$", r"The requested URL was not found on this server", False),
    ("Agile CRM", r"agilecrm\.com$", r"Sorry, this page is no longer available", False),
    ("Strikingly", r"s\.strikinglydns\.com$", r"But if you're looking to build your own website", False),
    ("Ngrok", r"\.ngrok\.io$", r"Tunnel .{1,80} not found", False),
]


def _cname_chain(name: str) -> tuple[list[str], int | None]:
    """CNAME targets for a name and the DNS status of the lookup (3 = the final target doesn't exist)."""
    r = doh(name, "A")
    return [a["data"] for a in r["answers"] if a["type"] == "CNAME"], r["status"]


def takeover_check(host: str) -> dict:
    """Subdomains whose CNAME points at a service where the resource is gone, so anyone could claim it.
    Reads Certificate Transparency names, resolves them, and fetches the page only when the CNAME
    points at a known service, to look for that service's 'nothing here' message."""
    subs = subdomain_discovery(host)
    domain = subs["domain"]
    names = [n["name"] for n in subs["subdomains"][:250] if not n.get("wildcard")]

    def check(name):
        try:
            chain, status = _cname_chain(name)
        except OsintError:
            return None
        if not chain:
            return None
        target = chain[-1]
        svc = next((s for s in TAKEOVER_SERVICES if any(re.search(s[1], c, re.I) for c in chain)), None)
        row = {"name": name, "cname": chain, "service": svc[0] if svc else None, "nxdomain": status == 3}
        if status == 3:
            return row | {"verdict": "vulnerable" if svc and svc[3] else "dangling",
                          "evidence": f"{target} doesn't exist (NXDOMAIN)."}
        if svc and svc[2]:
            try:
                resp, body, _ = _fetch(name, max_bytes=300_000, timeout=8)
                m = re.search(svc[2], body.decode("utf-8", "replace"), re.I)
                if m:
                    return row | {"verdict": "vulnerable",
                                  "evidence": f"HTTP {resp.status_code} with {svc[0]}'s unclaimed-resource message: “{m.group(0)[:80]}”"}
            except OsintError as e:
                row["fetch_error"] = str(e)[:120]
        return row | {"verdict": "ok"}

    with ThreadPoolExecutor(16) as pool:
        rows = [r for r in pool.map(check, names) if r]
    findings = sorted((r for r in rows if r["verdict"] != "ok"), key=lambda r: (r["verdict"] != "vulnerable", r["name"]))
    services = Counter(r["service"] for r in rows if r["service"])
    return {"domain": domain, "source": subs["source"], "subdomains_known": subs["count"], "checked": len(names),
            "with_cname": len(rows), "findings": findings, "services": services.most_common(),
            "note": "Candidates need confirming by hand, and claim nothing you don't own. Fix one by deleting the DNS record or re-creating the resource."}


# ---------------------------------------------------------------- lookalike domains

_QWERTY = {
    "1": "2q", "2": "3wq1", "3": "4ew2", "4": "5re3", "5": "6tr4", "6": "7yt5", "7": "8uy6", "8": "9iu7", "9": "0oi8", "0": "po9",
    "q": "12wa", "w": "3esaq2", "e": "4rdsw3", "r": "5tfde4", "t": "6ygfr5", "y": "7uhgt6", "u": "8ijhy7", "i": "9okju8",
    "o": "0plki9", "p": "lo0", "a": "qwsz", "s": "edxzaw", "d": "rfcxse", "f": "tgvcdr", "g": "yhbvft", "h": "ujnbgy",
    "j": "ikmnhu", "k": "olmji", "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk",
}
_GLYPHS = {"a": ["4"], "b": ["d", "lb"], "c": ["e"], "d": ["b", "cl"], "e": ["c", "3"], "g": ["q", "9"], "h": ["lh"],
           "i": ["1", "l"], "k": ["lk", "ik"], "l": ["1", "i"], "m": ["n", "nn", "rn"], "n": ["m", "r"], "o": ["0"],
           "q": ["g"], "s": ["5"], "u": ["v"], "v": ["u"], "w": ["vv"], "z": ["2"]}
_GLYPH_PAIRS = {"rn": "m", "vv": "w", "cl": "d", "nn": "m"}
_ALT_TLDS = ["com", "net", "org", "co", "io", "info", "biz", "app", "dev", "xyz", "online", "site", "shop", "store",
             "us", "co.uk", "de", "in", "ai", "me", "cc", "top", "live", "support"]
_AFFIXES = ["login", "secure", "account", "my", "support", "app", "mail", "online", "verify", "official", "help", "auth"]
_LABEL_OK = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
MAX_LOOKALIKES = 500


def _permutations(label: str, suffix: str) -> list[tuple[str, str]]:
    """(fuzzer, domain) pairs in the spirit of dnstwist, most likely-to-matter fuzzers first."""
    out: dict[str, str] = {}

    def add(fuzzer, lab, suf=suffix):
        lab = lab.strip("-")
        if lab and _LABEL_OK.match(lab) and (lab, suf) != (label, suffix):
            out.setdefault(f"{lab}.{suf}", fuzzer)

    n = len(label)
    for i, ch in enumerate(label):
        for g in _GLYPHS.get(ch, []):
            add("homoglyph", label[:i] + g + label[i + 1:])
    for pair, g in _GLYPH_PAIRS.items():
        for m in re.finditer(pair, label):
            add("homoglyph", label[:m.start()] + g + label[m.end():])
    for i in range(n):
        add("omission", label[:i] + label[i + 1:])
    for i in range(n - 1):
        add("transposition", label[:i] + label[i + 1] + label[i] + label[i + 2:])
    for i, ch in enumerate(label):
        for k in _QWERTY.get(ch, ""):
            add("replacement", label[:i] + k + label[i + 1:])
    for t in _ALT_TLDS:
        add("tld-swap", label, t)
    for i, ch in enumerate(label):
        add("repetition", label[:i] + ch + label[i:])
    for i in range(1, n):
        add("hyphenation", label[:i] + "-" + label[i:])
    for i, ch in enumerate(label):
        if ch in "aeiou":
            for v in "aeiou":
                add("vowel-swap", label[:i] + v + label[i + 1:])
    for i, ch in enumerate(label):
        for k in _QWERTY.get(ch, ""):
            add("insertion", label[:i] + k + label[i:])
            add("insertion", label[:i + 1] + k + label[i + 1:])
    for a in _AFFIXES:
        add("dictionary", f"{label}-{a}")
        add("dictionary", f"{a}-{label}")
        add("dictionary", f"{label}{a}")
    for c in "abcdefghijklmnopqrstuvwxyz":
        add("addition", label + c)
    for i, ch in enumerate(label):
        for bit in range(8):
            flipped = chr(ord(ch) ^ (1 << bit))
            if re.fullmatch(r"[a-z0-9-]", flipped):
                add("bitsquatting", label[:i] + flipped + label[i + 1:])
    add("www", "www" + label)
    return [(f, d) for d, f in out.items()]


def lookalike_domains(host: str) -> dict:
    """Registered domains that look like this one (typos, homoglyphs, other TLDs), found with DNS only.
    No lookalike site is visited."""
    domain = org_domain(host)
    label, _, suffix = domain.partition(".")
    perms = _permutations(label, suffix)
    checked = perms[:MAX_LOOKALIKES]
    try:
        own_ns = {x.lower() for x in records(domain, "NS")}
    except OsintError:
        own_ns = set()

    def probe(item):
        fuzzer, name = item
        try:
            r = doh(name, "NS")
        except OsintError:
            return None
        ns = [a["data"].lower() for a in r["answers"] if a["type"] == "NS"]
        if r["status"] != 0 or not ns:     # NXDOMAIN or no delegation: not registered (or not in use)
            return None
        try:
            a, mx = records(name, "A"), records(name, "MX")
        except OsintError:
            a, mx = [], []
        # "0 ." is a null MX (RFC 7505): the domain explicitly accepts no mail.
        mx = [h for h in (m.split()[-1].rstrip(".") for m in mx) if h]
        same_owner = bool(own_ns) and set(ns) == own_ns
        risk = "low" if same_owner else "high" if mx else "medium" if a else "low"
        return {"domain": name, "fuzzer": fuzzer, "ns": ns[:4], "a": a[:3], "mx": mx[:3],
                "same_nameservers": same_owner, "risk": risk}

    with ThreadPoolExecutor(24) as pool:
        found = [r for r in pool.map(probe, checked) if r]
    order = {"high": 0, "medium": 1, "low": 2}
    found.sort(key=lambda r: (order[r["risk"]], r["domain"]))
    return {"domain": domain, "generated": len(perms), "checked": len(checked), "registered": found,
            "registered_count": len(found), "with_mail": sum(1 for r in found if r["mx"]),
            "probably_yours": sum(1 for r in found if r["same_nameservers"]),
            "fuzzers": Counter(f for f, _ in checked).most_common(),
            "note": "Registered means the name has nameservers. A lookalike that receives mail (MX) can be used for phishing. "
                    "Ones on your own nameservers are probably defensive registrations."}


# ---------------------------------------------------------------- reputation / blocklists

DBL_CODES = {"127.0.1.2": "spam domain", "127.0.1.4": "phishing domain", "127.0.1.5": "malware domain",
             "127.0.1.6": "botnet command-and-control domain", "127.0.1.102": "abused legitimate spam domain",
             "127.0.1.103": "abused legitimate redirector", "127.0.1.104": "abused legitimate phishing domain",
             "127.0.1.105": "abused legitimate malware domain", "127.0.1.106": "abused legitimate botnet C&C domain"}
ZEN_CODES = {"127.0.0.2": "SBL (spam source)", "127.0.0.3": "SBL CSS (snowshoe spam)", "127.0.0.4": "XBL (exploited or infected host)",
             "127.0.0.5": "XBL (exploited or infected host)", "127.0.0.6": "XBL (exploited or infected host)",
             "127.0.0.7": "XBL (exploited or infected host)", "127.0.0.9": "DROP (hijacked network)",
             "127.0.0.10": "PBL (address not meant to send mail directly)", "127.0.0.11": "PBL (address not meant to send mail directly)"}
SPAMHAUS_ERRORS = {"127.255.255.252": "the query was malformed",
                   "127.255.255.254": "this server uses a public DNS resolver, which Spamhaus refuses",
                   "127.255.255.255": "this server's DNS resolver has sent too many queries"}


def _dns_udp(name: str, server: str, timeout=3.0) -> tuple[int, list[str]]:
    """One A query sent straight to an authoritative server: (rcode, IPv4 answers). rcode 3 is NXDOMAIN."""
    qid = int.from_bytes(os.urandom(2), "big")
    # Recursion-desired must be set: Spamhaus's servers refuse queries without it, though they answer from their own zone.
    q = qid.to_bytes(2, "big") + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    q += b"".join(bytes([len(p)]) + p.encode() for p in name.rstrip(".").split(".")) + b"\x00\x00\x01\x00\x01"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(q, (server, 53))
        while True:
            data, _ = sock.recvfrom(1500)
            if data[:2] == qid.to_bytes(2, "big"):
                break
    rcode, ancount = data[3] & 0x0F, int.from_bytes(data[6:8], "big")
    i = 12
    while data[i]:                       # skip the question name
        i += data[i] + 1
    i += 5
    ips = []
    for _ in range(ancount):
        if data[i] & 0xC0 == 0xC0:
            i += 2
        else:
            while data[i]:
                i += data[i] + 1
            i += 1
        rtype, rdlen = int.from_bytes(data[i:i + 2], "big"), int.from_bytes(data[i + 8:i + 10], "big")
        i += 10
        if rtype == 1 and rdlen == 4:
            ips.append(".".join(str(b) for b in data[i:i + 4]))
        i += rdlen
    return rcode, ips


@cached(3600)
def _zone_servers(zone: str) -> list[str]:
    ips = []
    for ns in records(zone, "NS")[:4]:
        try:
            ips += records(ns, "A")[:1]
        except OsintError:
            pass
    if not ips:
        raise OsintError(f"Couldn't find the nameservers for {zone}.")
    return ips


def _blocklist_lookup(name: str, zone: str) -> list[str] | None:
    """Answers for `name` from the blocklist zone's own nameservers; None when not listed. Spamhaus refuses
    queries that arrive through big public resolvers, so they don't go through DNS-over-HTTPS."""
    last = None
    for server in _zone_servers(zone):
        try:
            rcode, ips = _dns_udp(name, server)
        except (OSError, IndexError) as e:
            last = e
            continue
        if rcode == 3:
            return None
        if rcode == 0:
            return ips or None
        last = f"DNS error code {rcode}"
    raise OsintError(f"No answer from {zone}'s nameservers ({type(last).__name__ if isinstance(last, Exception) else last}).")


def _spamhaus(domain: str, ips: list[str]) -> dict:
    out = {"source": "Spamhaus", "listings": [], "status": "clean"}
    try:
        for code in _blocklist_lookup(f"{domain}.dbl.spamhaus.org", "dbl.spamhaus.org") or []:
            if code in SPAMHAUS_ERRORS:
                return out | {"status": "error", "detail": f"Spamhaus didn't answer: {SPAMHAUS_ERRORS[code]}."}
            out["listings"].append({"list": "DBL", "item": domain, "meaning": DBL_CODES.get(code, code)})
        for ip in ips[:4]:
            if ":" in ip:
                continue
            for code in _blocklist_lookup(".".join(reversed(ip.split("."))) + ".zen.spamhaus.org", "zen.spamhaus.org") or []:
                if code in SPAMHAUS_ERRORS:
                    return out | {"status": "error", "detail": f"Spamhaus didn't answer: {SPAMHAUS_ERRORS[code]}."}
                out["listings"].append({"list": "ZEN", "item": ip, "meaning": ZEN_CODES.get(code, code),
                                        "policy_only": code in ("127.0.0.10", "127.0.0.11")})
    except OsintError as e:
        return out | {"status": "error", "detail": str(e)}
    if any(not l.get("policy_only") for l in out["listings"]):
        out["status"] = "listed"
    return out | {"detail": "The domain against the Domain Block List, and its web server addresses against ZEN."}


def _safe_browsing(host: str) -> dict:
    key = os.environ.get("SAFE_BROWSING_API_KEY")
    src = "Google Safe Browsing"
    if not key:
        return {"source": src, "status": "not_configured",
                "detail": "Set SAFE_BROWSING_API_KEY (a free Google Cloud API key) to check Google's malware and phishing lists."}
    body = {"client": {"clientId": "deconstruct-site", "clientVersion": "1.0"},
            "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                           "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                           "threatEntries": [{"url": f"{s}://{host}/"} for s in ("http", "https")]}}
    try:
        r = _api.post("https://safebrowsing.googleapis.com/v4/threatMatches:find", params={"key": key}, json=body, timeout=10)
    except requests.RequestException as e:
        return {"source": src, "status": "error", "detail": f"Request failed ({type(e).__name__})."}
    if r.status_code != 200:
        return {"source": src, "status": "error", "detail": f"HTTP {r.status_code}: {r.text[:120]}"}
    matches = r.json().get("matches", [])
    return {"source": src, "status": "listed" if matches else "clean",
            "listings": [{"list": m["threatType"].replace("_", " ").lower(), "item": m["threat"]["url"], "meaning": m["platformType"]} for m in matches],
            "detail": "Google's lists of malware, phishing and unwanted-software sites."}


def _urlhaus(host: str) -> dict:
    key = os.environ.get("URLHAUS_AUTH_KEY")
    src = "URLhaus (abuse.ch)"
    if not key:
        return {"source": src, "status": "not_configured",
                "detail": "Set URLHAUS_AUTH_KEY (free from auth.abuse.ch) to check abuse.ch's list of malware download sites."}
    try:
        j = _api.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": host}, headers={"Auth-Key": key}, timeout=10).json()
    except (requests.RequestException, ValueError) as e:
        return {"source": src, "status": "error", "detail": f"Request failed ({type(e).__name__})."}
    if j.get("query_status") == "no_results":
        return {"source": src, "status": "clean", "detail": "No malware URLs reported on this host."}
    if j.get("query_status") != "ok":
        return {"source": src, "status": "error", "detail": str(j.get("query_status"))[:120]}
    online = [u for u in j.get("urls", []) if u.get("url_status") == "online"]
    return {"source": src, "status": "listed" if online else "history",
            "listings": [{"list": "URLhaus", "item": u["url"], "meaning": f"{u.get('threat')} · {u.get('url_status')}"} for u in j.get("urls", [])[:15]],
            "detail": f"{j.get('url_count', 0)} malware URLs reported, {len(online)} still online." if online
                      else f"{j.get('url_count', 0)} malware URLs reported in the past, none online now."}


def reputation(host: str) -> dict:
    """Whether the domain or its web server addresses are on public blocklists."""
    domain = org_domain(host)
    try:
        ips = records(host, "A")
    except OsintError:
        ips = []
    with ThreadPoolExecutor(3) as pool:
        checks = list(pool.map(lambda f: f(), [lambda: _spamhaus(domain, ips), lambda: _safe_browsing(host), lambda: _urlhaus(host)]))
    listed = [c["source"] for c in checks if c["status"] == "listed"]
    return {"domain": domain, "host": host, "ips": ips, "checks": checks, "listed": bool(listed), "listed_on": listed,
            "summary": f"Listed on {', '.join(listed)}." if listed else "Not listed on any blocklist that answered."}


TOOLS = {
    "dns": dns_lookup,
    "rdap": rdap_lookup,
    "subdomains": subdomain_discovery,
    "ssl": ssl_check,
    "headers": header_analysis,
    "tech": tech_detection,
    "ip": ip_asn_lookup,
    "history": website_history,
    "robots": robots_analysis,
    "sitemap": sitemap_analysis,
    "email": email_security,
    "redirects": redirect_analysis,
    "takeover": takeover_check,
    "lookalikes": lookalike_domains,
    "reputation": reputation,
}


def run(tool: str, target: str) -> dict:
    if tool not in TOOLS:
        raise OsintError(f"Unknown tool: {tool}")
    host = normalize_target(target)
    t0 = time.perf_counter()
    data = TOOLS[tool](host)
    return {"tool": tool, "target": host, "ms": round((time.perf_counter() - t0) * 1000),
            "ran_at": _now().strftime("%Y-%m-%dT%H:%M:%SZ"), "data": data}
