"""AI features on top of a saved report: a plain-English summary, a prioritized fix list with code,
questions about the report, and code generated from a captured component (header, footer, form).

Every call runs on the signed-in user's own Anthropic API key, which the browser sends with the
request (X-Anthropic-Key). The key is used for that one call and is never stored or logged, so all
AI usage is billed to the user's own Anthropic account.
"""
from __future__ import annotations

import copy
import json
import re

import anthropic

MODELS = {
    "claude-opus-5-5": "Claude Opus 5.5",
    "claude-sonnet-5-5": "Claude Sonnet 5.5",
    "claude-haiku-5-5": "Claude Haiku 5.5",
}
DEFAULT_MODEL = "claude-opus-5-5"
# Server-side fallback re-runs a request a model's safety classifiers decline; Haiku 5.5 has none.
FALLBACK_MODELS = {"claude-opus-5-5", "claude-sonnet-5-5"}
FRAMEWORKS = {"html": "plain HTML and CSS", "tailwind": "HTML with Tailwind CSS utility classes", "react": "a React function component styled with Tailwind CSS"}
KEY_RE = re.compile(r"^sk-ant-[A-Za-z0-9_\-]{20,}$")


class AIError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def client_for(api_key: str | None) -> anthropic.Anthropic:
    key = (api_key or "").strip()
    if not key:
        raise AIError("Add your Anthropic API key in Settings to use AI features.", 400)
    if not KEY_RE.match(key):
        raise AIError("That doesn't look like an Anthropic API key (they start with sk-ant-).", 400)
    return anthropic.Anthropic(api_key=key, max_retries=2, timeout=300)


def friendly(e: Exception) -> AIError:
    """Turns SDK errors into messages a user can act on, most specific first."""
    if isinstance(e, AIError):
        return e
    if isinstance(e, anthropic.AuthenticationError):
        return AIError("Anthropic rejected this API key. Check it in Settings.", 400)
    if isinstance(e, anthropic.PermissionDeniedError):
        return AIError("Your API key doesn't have access to this model. Pick another model in Settings.", 400)
    if isinstance(e, anthropic.NotFoundError):
        return AIError("That model isn't available to your API key. Pick another model in Settings.", 400)
    if isinstance(e, anthropic.RateLimitError):
        return AIError("Your Anthropic account hit a rate or spend limit. Wait a minute, or check your limits in the Claude Console.", 429)
    if isinstance(e, anthropic.BadRequestError):
        msg = getattr(e, "message", "") or str(e)
        if "credit balance" in msg.lower():
            return AIError("Your Anthropic account is out of credits. Add credits in the Claude Console.", 402)
        return AIError(f"Anthropic couldn't process this request: {msg[:200]}", 400)
    if isinstance(e, anthropic.APITimeoutError):
        return AIError("Claude took too long to answer. Try again.", 504)
    if isinstance(e, anthropic.APIStatusError):
        return AIError(f"Anthropic's API returned an error ({e.status_code}). Try again shortly.", 502)
    if isinstance(e, anthropic.APIConnectionError):
        return AIError("Couldn't reach Anthropic's API from this server.", 502)
    return AIError(f"AI request failed: {type(e).__name__}", 500)


def check_key(api_key: str, model: str) -> dict:
    """Validates a key (and that it can use the model) without spending tokens."""
    try:
        m = client_for(api_key).models.retrieve(model)
    except Exception as e:  # noqa: BLE001 - mapped to a readable message
        raise friendly(e)
    return {"ok": True, "model": m.id, "name": getattr(m, "display_name", m.id)}


def _model(model: str | None) -> str:
    return model if model in MODELS else DEFAULT_MODEL


# ---------------------------------------------------------------- report context

def compact_report(report: dict) -> dict:
    """The report without screenshots, rendered HTML and long lists, so it fits comfortably in a prompt."""
    r = copy.deepcopy(report)
    b = r.get("browser") or {}
    b.pop("screenshots", None)
    b.pop("components", None)
    r.get("design", {}).pop("css_variables", None)
    comp = r.get("design", {}).get("computed") or {}
    comp.pop("root_variables", None)
    perf = r.get("performance", {})
    if isinstance(perf.get("resources"), list):
        perf["resources"] = sorted(perf["resources"], key=lambda x: -(x.get("size") or 0))[:25]
    axe = (r.get("accessibility") or {}).get("axe") or {}
    for v in axe.get("violations", []):
        v["nodes"] = v.get("nodes", [])[:3]
    axe.pop("passes", None)
    r.pop("response_headers", None)
    for k in ("links", "images"):
        if isinstance(r.get("structure", {}).get(k), list):
            r["structure"][k] = r["structure"][k][:20]

    def strip(o):
        if isinstance(o, dict):
            return {k: strip(v) for k, v in o.items() if not (isinstance(v, str) and v.startswith("data:"))}
        if isinstance(o, list):
            return [strip(v) for v in o[:60]]
        return o
    return strip(r)


SYSTEM = """You are a senior web engineer reviewing an automated analysis of a website made by Deconstruct Site.
The report below is JSON from that tool: technology detection, design system, performance (lab Core Web Vitals
measured as the median of throttled mobile loads, and resources), SEO, accessibility (axe-core results),
security (headers, TLS, cookies, vulnerable JavaScript libraries) and page structure, with 0-100 scores.

Ground every statement in the report. When something isn't in the data, say it wasn't measured rather than guessing.
Lab vitals come from emulated mobile loads, so they are indicative, not what every visitor experiences.
Write for the site's owner and their developers: plain language first, technical detail where it helps."""


def _system(report: dict) -> list[dict]:
    # The report is the large, stable part: cache it so follow-up questions and other actions on the
    # same report are cheaper. sort_keys keeps the serialization byte-identical between calls.
    data = json.dumps(compact_report(report), sort_keys=True, separators=(",", ":"), default=str)
    return [{"type": "text", "text": SYSTEM},
            {"type": "text", "text": f"<report>\n{data}\n</report>", "cache_control": {"type": "ephemeral"}}]


def _stream(client: anthropic.Anthropic, model: str, **kw):
    """A streaming request, with server-side refusal fallback on models that support it."""
    if model in FALLBACK_MODELS:
        return client.beta.messages.stream(model=model, betas=["server-side-fallback-2026-07-01"], fallbacks="default", **kw)
    return client.messages.stream(model=model, **kw)


def _check_stop(msg):
    if msg.stop_reason == "refusal":
        raise AIError("Claude declined this request. Try rephrasing it.", 422)


def _usage(msg) -> dict:
    u = msg.usage
    return {"input_tokens": u.input_tokens, "output_tokens": u.output_tokens,
            "cache_read_input_tokens": getattr(u, "cache_read_input_tokens", None) or 0,
            "cache_creation_input_tokens": getattr(u, "cache_creation_input_tokens", None) or 0}


def stream_text(api_key: str, model: str | None, report: dict, messages: list[dict], *, max_tokens=16000, effort=None,
                extra_content=None):
    """Yields ("text", chunk) events, then ("done", {text, model, usage}). Errors raise AIError."""
    model = _model(model)
    client = client_for(api_key)
    kw = {"max_tokens": max_tokens, "system": _system(report), "messages": messages}
    if effort:
        kw["output_config"] = {"effort": effort}
    parts = []
    try:
        with _stream(client, model, **kw) as stream:
            for text in stream.text_stream:
                parts.append(text)
                yield "text", text
            final = stream.get_final_message()
    except Exception as e:  # noqa: BLE001
        raise friendly(e)
    _check_stop(final)
    yield "done", {"text": "".join(parts), "model": final.model, "usage": _usage(final),
                   "truncated": final.stop_reason == "max_tokens"}


# ---------------------------------------------------------------- the four features

SUMMARY_PROMPT = """Write a plain-English summary of this website for its owner, in Markdown, under 300 words:

1. One or two sentences on what the site is and what it's built with.
2. **How it's doing**: one short line each for performance, SEO, accessibility and security, citing the score and the main reason.
3. **Fix first**: the three changes that would help most, each with why it matters.
4. **What's working well**: one or two genuine strengths.

Use the headings in bold as shown. No preamble."""


def summary(api_key, model, report):
    return stream_text(api_key, model, report, [{"role": "user", "content": SUMMARY_PROMPT}], max_tokens=4000)


FIX_SCHEMA = {
    "type": "object",
    "properties": {
        "fixes": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "category": {"type": "string", "enum": ["performance", "seo", "accessibility", "security", "design", "other"]},
                    "impact": {"type": "string", "enum": ["high", "medium", "low"]},
                    "effort": {"type": "string", "enum": ["low", "medium", "high"]},
                    "evidence": {"type": "string"},
                    "why": {"type": "string"},
                    "how": {"type": "string"},
                    "code_language": {"type": "string"},
                    "code": {"type": "string"},
                },
                "required": ["title", "category", "impact", "effort", "evidence", "why", "how", "code_language", "code"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["fixes"],
    "additionalProperties": False,
}

FIXES_PROMPT = """List the fixes for this site in priority order: highest impact for the least effort first. Give 5 to 10.

For each fix:
- title: a short imperative ("Add a Content-Security-Policy header").
- evidence: the specific finding in the report it addresses, with numbers or element selectors where the report has them.
- why: what the owner gains, in one or two sentences.
- how: the concrete steps.
- code: a snippet that implements it (HTML, CSS, a server header config, JavaScript...), or an empty string when code wouldn't help.
- code_language: the snippet's language for syntax highlighting (html, css, nginx, apache, js, json, text), or an empty string.

Only include fixes the report's data supports."""


def fixes(api_key, model, report) -> dict:
    """The prioritized fix list as validated JSON."""
    model = _model(model)
    client = client_for(api_key)
    try:
        with _stream(client, model, max_tokens=32000, system=_system(report),
                     output_config={"effort": "high", "format": {"type": "json_schema", "schema": FIX_SCHEMA}},
                     messages=[{"role": "user", "content": FIXES_PROMPT}]) as stream:
            final = stream.get_final_message()
    except Exception as e:  # noqa: BLE001
        raise friendly(e)
    _check_stop(final)
    if final.stop_reason == "max_tokens":
        raise AIError("The fix list was cut off before it finished. Try again.", 502)
    text = next((b.text for b in final.content if b.type == "text"), "")
    try:
        data = json.loads(text)
    except ValueError:
        raise AIError("Claude's answer wasn't valid JSON. Try again.", 502)
    return {"fixes": data["fixes"], "model": final.model, "usage": _usage(final)}


ASK_PROMPT = """Answer questions about this website using the report. Be direct and specific, quote the report's numbers,
and include code when it helps. If the report doesn't contain the answer, say what would need to be measured."""


def ask(api_key, model, report, history: list[dict], question: str):
    """history is earlier turns as [{"role": "user"|"assistant", "content": str}], oldest first."""
    msgs = [{"role": "user", "content": ASK_PROMPT}, {"role": "assistant", "content": "Understood. What would you like to know?"}]
    for h in history[-20:]:
        if h.get("role") in ("user", "assistant") and isinstance(h.get("content"), str) and h["content"].strip():
            msgs.append({"role": h["role"], "content": h["content"][:20000]})
    msgs.append({"role": "user", "content": question[:4000]})
    return stream_text(api_key, model, report, msgs, max_tokens=8000)


def component_code(api_key, model, report, component: str, framework: str):
    shots = ((report.get("browser") or {}).get("components") or {})
    comp = shots.get(component)
    if not comp or not str(comp.get("image", "")).startswith("data:image/"):
        raise AIError(f"This report has no captured {component}. Run the analysis with the browser turned on.", 400)
    if framework not in FRAMEWORKS:
        raise AIError("Choose HTML, Tailwind or React.", 400)
    media, b64 = comp["image"].split(",", 1)
    media_type = media.split(":", 1)[1].split(";", 1)[0]
    design = (report.get("design") or {}).get("computed") or {}
    hints = {"selector": comp.get("selector"), "size_px": [comp.get("width"), comp.get("height")],
             "body": design.get("body"), "typography": design.get("typography"), "buttons": design.get("buttons"),
             "colors_by_area": design.get("background_by_area", [])[:8], "text_colors": design.get("text_colors", [])[:6]}
    prompt = (f"The image is a screenshot of this site's {component} (CSS selector {comp.get('selector')!r}), "
              f"{comp.get('width')}×{comp.get('height')} px. Rebuild it as {FRAMEWORKS[framework]}.\n\n"
              f"Measured styles from the live page, to match exactly:\n{json.dumps(hints, default=str)}\n\n"
              "Match the layout, spacing, colors, fonts and text as closely as the screenshot and styles allow. "
              "Make it responsive and accessible (semantic elements, alt text, labelled buttons and links). "
              "Use placeholder `#` links and describe images with a placeholder box rather than hotlinking the site's files. "
              "Reply with one fenced code block containing the complete component, then at most three short notes on anything you approximated.")
    content = [{"type": "image", "source": {"type": "base64", "media_type": media_type, "data": b64}},
               {"type": "text", "text": prompt}]
    return stream_text(api_key, model, report, [{"role": "user", "content": content}], max_tokens=16000)
