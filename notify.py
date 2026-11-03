"""Sends events to notification channels: generic webhook, Slack, Discord or email.

Delivery runs on a background thread so detection never waits on a slow
endpoint. Email uses SMTP settings from environment variables (SMTP_HOST,
SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM) so no password is stored in
the database. APP_URL sets the base of links in messages. Webhooks must point to
public addresses unless ALLOW_PRIVATE_WEBHOOKS is set.
"""
from __future__ import annotations

import logging
import os
import re
import smtplib
import threading
from email.message import EmailMessage
from urllib.parse import urlparse

import requests

import store
from analyzer import _host_is_public

log = logging.getLogger("notify")


def _default_app_url():
    port = os.environ.get("PORT", 5173)
    if os.environ.get("CODESPACE_NAME"):
        # GitHub Codespaces forwards ports to https://<codespace>-<port>.app.github.dev
        domain = os.environ.get("GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN", "app.github.dev")
        return f"https://{os.environ['CODESPACE_NAME']}-{port}.{domain}"
    return f"http://localhost:{port}"


APP_URL = os.environ.get("APP_URL", _default_app_url()).rstrip("/")
ICON = {"info": "ℹ️", "warning": "⚠️", "critical": "🚨"}
COLOR = {"info": 0x1F5EFF, "warning": 0xB26A00, "critical": 0xC62E2E}
_session = requests.Session()
_session.headers["User-Agent"] = "DeconstructSite-Notifier/1.0"


def validate(kind: str, target: str) -> str | None:
    """Returns an error message for a bad channel target, or None."""
    target = (target or "").strip()
    if kind in ("webhook", "slack", "discord"):
        if not re.match(r"^https?://[^\s/]+", target):
            return "Enter the full webhook URL, starting with https://."
        if kind == "slack" and "hooks.slack.com" not in target:
            return "Slack needs an Incoming Webhook URL (https://hooks.slack.com/services/…)."
        if kind == "discord" and not re.search(r"discord(app)?\.com/api/webhooks/", target):
            return "Discord needs a channel webhook URL (https://discord.com/api/webhooks/…)."
        # ALLOW_PRIVATE_WEBHOOKS=1 permits local tools (n8n, Home Assistant) on a machine only you can reach
        if not os.environ.get("ALLOW_PRIVATE_WEBHOOKS") and not _host_is_public(urlparse(target).hostname or ""):
            return "Webhooks must point to a public internet address, not a private or local one."
    elif kind == "email":
        addrs = [a.strip() for a in target.split(",") if a.strip()]
        if not addrs or not all(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", a) for a in addrs):
            return "Enter one or more email addresses, separated by commas."
    else:
        return "Unknown channel type."
    return None


def link_for(event: dict) -> str:
    links = (event.get("detail") or {}).get("links") or {}
    if links.get("compare"):
        a, b = links["compare"]
        return f"{APP_URL}/#/compare?a={a}&b={b}"
    if links.get("analysis"):
        return f"{APP_URL}/#/analyses/{links['analysis']}"
    if links.get("uptime"):
        return f"{APP_URL}/#/sites/{links['uptime']}?tab=uptime"
    if links.get("osint"):
        return f"{APP_URL}/#/osint?target={links['osint']}"
    return f"{APP_URL}/#/alerts"


def _lines(event):
    return [l for l in (event.get("detail") or {}).get("lines", []) if l]


def _send(channel: dict, event: dict, timeout=10):
    kind, target, url = channel["kind"], channel["target"], link_for(event)
    lines = _lines(event)
    if kind == "webhook":
        payload = {"app": "Deconstruct Site", "url": url, "event": {k: event.get(k) for k in
                   ("id", "created_at", "kind", "severity", "title", "target", "site_id", "detail")}}
        r = _session.post(target, json=payload, timeout=timeout, allow_redirects=False)
    elif kind == "slack":
        text = f"{ICON[event['severity']]} *{event['title']}*" + "".join(f"\n• {l}" for l in lines[:8]) + f"\n<{url}|Open in Deconstruct Site>"
        r = _session.post(target, json={"text": text}, timeout=timeout, allow_redirects=False)
    elif kind == "discord":
        embed = {"title": event["title"][:256], "description": "\n".join(f"• {l}" for l in lines[:10])[:3500] or None,
                 "color": COLOR[event["severity"]], "timestamp": event["created_at"].replace("Z", "+00:00"),
                 "footer": {"text": f"Deconstruct Site · {event['severity']}"}}
        if url.startswith("https://"):
            embed["url"] = url
        r = _session.post(target, json={"embeds": [embed]}, timeout=timeout, allow_redirects=False)
    elif kind == "email":
        host = os.environ.get("SMTP_HOST")
        if not host:
            raise RuntimeError("Email isn't configured: set SMTP_HOST (and SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM) before starting the app.")
        msg = EmailMessage()
        msg["Subject"] = f"[{event['severity'].upper()}] {event['title']}"
        msg["From"] = os.environ.get("SMTP_FROM") or os.environ.get("SMTP_USER") or "deconstruct-site@localhost"
        msg["To"] = target
        msg.set_content("\n".join([event["title"], "", *lines, "", url]))
        port = int(os.environ.get("SMTP_PORT", 587))
        smtp_cls = smtplib.SMTP_SSL if port == 465 else smtplib.SMTP
        with smtp_cls(host, port, timeout=timeout) as s:
            if port != 465:
                s.starttls()
            if os.environ.get("SMTP_USER"):
                s.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASSWORD", ""))
            s.send_message(msg)
        return
    else:
        raise RuntimeError(f"Unknown channel type {kind}")
    if 300 <= r.status_code < 400:
        # Not followed: a redirect could send the alert on to a private address
        raise RuntimeError(f"HTTP {r.status_code}: the webhook redirected to {r.headers.get('location', 'another URL')}")
    if r.status_code >= 400:
        raise RuntimeError(f"HTTP {r.status_code}: {r.text[:150]}")


def send_one(channel: dict, event: dict) -> str | None:
    """Sends one event; records and returns the error, or None on success."""
    try:
        _send(channel, event)
        store.record_channel_result(channel["id"], None)
        return None
    except (requests.RequestException, OSError, RuntimeError, smtplib.SMTPException) as e:
        host = re.sub(r"^https?://([^/]+).*", r"\1", channel.get("target", ""))
        if isinstance(e, requests.exceptions.Timeout):
            msg = f"{host} didn't respond within 10 seconds."
        elif isinstance(e, requests.exceptions.ConnectionError):
            msg = f"Couldn't connect to {host}."
        elif isinstance(e, smtplib.SMTPAuthenticationError):
            msg = "The SMTP server rejected the username or password."
        else:
            msg = str(e)[:300] or type(e).__name__
        store.record_channel_result(channel["id"], msg)
        return msg


def _deliver(events: list[dict]):
    channels = [c for c in store.list_channels() if c["enabled"]]
    for ev in events:
        results = []
        for ch in channels:
            if store.SEVERITY_RANK[ev["severity"]] < store.SEVERITY_RANK[ch["min_severity"]]:
                continue
            err = send_one(ch, ev)
            results.append({"channel_id": ch["id"], "name": ch["name"], "ok": err is None, "error": err})
        if results:
            store.set_event_notified(ev["id"], results)


def dispatch(events: list[dict]):
    if not events:
        return
    if os.environ.get("VERCEL"):
        # A serverless function is frozen once it responds, so a background thread might never finish
        _deliver(events)
    else:
        threading.Thread(target=_deliver, args=(events,), name="notify", daemon=True).start()


def test_event() -> dict:
    return {"id": 0, "created_at": store.now_iso(), "kind": "test", "severity": "info",
            "title": "Test notification from Deconstruct Site", "target": None, "site_id": None,
            "detail": {"lines": ["If you can read this, the channel works."], "links": {}}}
