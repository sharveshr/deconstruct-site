"""Turns a report's design data into design tokens and exports them as CSS variables,
SCSS, a Tailwind config (v3 JS or v4 @theme CSS) or W3C Design Tokens JSON, which
Figma Tokens Studio and Style Dictionary read.

Rendered (computed) values are preferred when the browser pass ran, because they
are what the page actually paints; the CSS-text counts fill in the rest.
"""
from __future__ import annotations

import json
import re

FORMATS = {
    "css": ("CSS variables", "tokens.css"),
    "scss": ("SCSS variables", "_tokens.scss"),
    "tailwind": ("Tailwind v3 config", "tailwind.config.js"),
    "tailwind4": ("Tailwind v4 @theme", "theme.css"),
    "json": ("W3C Design Tokens (Figma Tokens Studio, Style Dictionary)", "tokens.json"),
}

_HEX = re.compile(r"^#[0-9a-f]{6}([0-9a-f]{2})?$", re.I)
_LEN = re.compile(r"^(-?[\d.]+)(px|rem|em)$")
WEIGHT_NAMES = {100: "thin", 200: "extralight", 300: "light", 400: "normal", 500: "medium", 600: "semibold",
                700: "bold", 800: "extrabold", 900: "black"}


def _px(value: str) -> float | None:
    m = _LEN.match(value.strip())
    if not m:
        return None
    n = float(m.group(1))
    return n * 16 if m.group(2) in ("rem", "em") else n


def _fmt_px(n: float) -> str:
    return f"{n:g}px"


def _rgb(hex_: str):
    h = hex_.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def _close(a: str, b: str, tol=12) -> bool:
    return max(abs(x - y) for x, y in zip(_rgb(a), _rgb(b))) <= tol


def _slug(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return s or "token"


def _dedupe_colors(values):
    out = []
    for v in values:
        v = v.lower()
        if _HEX.match(v) and len(v) == 7 and not any(_close(v, o) for o in out):
            out.append(v)
    return out


def _sized_names(values, base=None):
    """Names a sorted list of sizes like Tailwind: base for the body size, sm/xs below, lg/xl/2xl… above."""
    if not values:
        return {}
    base_i = min(range(len(values)), key=lambda i: abs(values[i] - (base or 16)))
    names = {}
    below = ["sm", "xs", "2xs", "3xs"]
    for k, i in enumerate(range(base_i - 1, -1, -1)):
        if k < len(below):
            names[below[k]] = values[i]
    names["base"] = values[base_i]
    above = ["lg", "xl"] + [f"{n}xl" for n in range(2, 10)]
    for k, i in enumerate(range(base_i + 1, len(values))):
        if k < len(above):
            names[above[k]] = values[i]
    return dict(sorted(names.items(), key=lambda kv: kv[1]))


def build(report: dict) -> dict:
    """The token set: {group: {name: value}} with px/hex strings, plus where each group came from."""
    ds = report["design"]
    cp = ds.get("computed") or {}
    tokens: dict[str, dict] = {}

    # Colors: semantic roles from what was painted, then the rest of the palette.
    colors = {}
    # Roles only come from what the browser painted: CSS-text counts can't tell a dark theme's
    # background from its text, so a quick analysis exports a plain palette instead.
    bg = _dedupe_colors(c["value"] for c in cp.get("background_by_area", []))
    text = _dedupe_colors(c["value"] for c in cp.get("text_colors", []))
    if bg:
        colors["background"] = bg[0]
    if len(bg) > 1:
        colors["surface"] = bg[1]
    if text:
        colors["text"] = text[0]
    if len(text) > 1:
        colors["text-muted"] = text[1]
    taken = list(colors.values())
    buttons = [b.get("background-color") for b in cp.get("buttons", [])]
    btn_hex = _dedupe_colors(_css_rgb_to_hex(b) for b in buttons if b)
    for i, c in enumerate(c for c in btn_hex if not any(_close(c, t) for t in taken)):
        colors["primary" if i == 0 else f"accent-{i}"] = c
        taken.append(c)
    # Colors the site already named in custom properties keep their names.
    named = {}
    for k, v in {**ds.get("css_variables", {}), **cp.get("root_variables", {})}.items():
        v = v.strip().lower()
        if _HEX.match(v) and len(v) == 7 and len(named) < 24:
            named[_slug(k.lstrip("-"))] = v
    palette = _dedupe_colors(c["value"] for c in ds.get("colors", []))
    n = 1
    for c in palette:
        if any(_close(c, t) for t in taken) or c in named.values():
            continue
        colors[f"palette-{n}"] = c
        taken.append(c)
        n += 1
        if n > 12:
            break
    tokens["color"] = colors | {k: v for k, v in named.items() if k not in colors}

    # Typography
    fonts = {}
    body = (cp.get("body") or {}).get("font-family")
    heading = next((t["font-family"] for t in cp.get("typography", []) if t.get("tag") == "h1"), None)
    css_fonts = [f["value"] for f in ds.get("fonts", [])]
    if body:
        fonts["body"] = body
    elif css_fonts:
        fonts["body"] = f"{css_fonts[0]}, sans-serif"
    if heading and heading != body:
        fonts["heading"] = heading
    mono = next((f for f in css_fonts if re.search(r"mono|code|courier|consolas", f, re.I)), None)
    if mono:
        fonts["mono"] = f"{mono}, monospace"
    tokens["font-family"] = fonts

    body_px = _px((cp.get("body") or {}).get("font-size", "16px")) or 16
    size_src = [s["value"] for s in cp.get("font_sizes", [])] or [s["value"] for s in ds.get("type_scale", [])]
    sizes = sorted({round(p, 2) for p in (_px(v) for v in size_src) if p and 8 <= p <= 120})
    tokens["font-size"] = {k: _fmt_px(v) for k, v in _sized_names(sizes, body_px).items()}

    weights = sorted({int(w["value"]) for w in ds.get("font_weights", []) if re.fullmatch(r"[1-9]00", w["value"])}
                     | {int(t["font-weight"]) for t in cp.get("typography", []) if re.fullmatch(r"[1-9]00", str(t.get("font-weight", "")))})
    tokens["font-weight"] = {WEIGHT_NAMES[w]: str(w) for w in weights}

    lh = [l["value"] for l in ds.get("line_heights", []) if re.fullmatch(r"[\d.]+", l["value"])]
    lh_vals = sorted({float(v) for v in lh if 0.8 <= float(v) <= 2.5})[:5]
    lh_names = ["tight", "snug", "normal", "relaxed", "loose"]
    if len(lh_vals) < len(lh_names):
        lh_names = lh_names[:len(lh_vals)] if len(lh_vals) != 1 else ["normal"]
    tokens["line-height"] = {n: f"{v:g}" for n, v in zip(lh_names, lh_vals)}

    # Spacing: Tailwind-style names from multiples of 4px (6px → 1.5)
    space = sorted({round(p, 2) for p in (_px(s["value"]) for s in ds.get("spacing_scale", [])) if p and 0 < p <= 256})
    tokens["spacing"] = {f"{p / 4:g}": _fmt_px(p) for p in space}

    radius_vals = []
    for r in (cp.get("radii") or []) + ds.get("radii", []):
        v = r["value"].split()[0]
        p = _px(v)
        if p is not None:
            radius_vals.append(p)
        elif v in ("50%", "100%"):
            radius_vals.append(9999.0)
    rv = sorted(set(round(p, 1) for p in radius_vals))
    small = [p for p in rv if 0 < p < 999][:7]
    rnames = {1: ["md"], 2: ["sm", "lg"], 3: ["sm", "md", "lg"]}.get(len(small), ["xs", "sm", "md", "lg", "xl", "2xl", "3xl"])
    radii = {name: _fmt_px(p) for name, p in zip(rnames, small)}
    if any(p >= 9999 or p >= 999 for p in rv):
        radii["full"] = "9999px"
    tokens["radius"] = radii

    shadows = [s["value"] for s in ds.get("shadows", []) if s["value"] not in ("none", "") and "var(" not in s["value"]]
    tokens["shadow"] = {n: v for n, v in zip(["sm", "md", "lg", "xl", "2xl", "3xl"], shadows)}

    bps = sorted({p for p in (_px(b["value"]) for b in ds.get("breakpoints", [])) if p and 300 <= p <= 2400})
    bp_names = ["sm", "md", "lg", "xl", "2xl", "3xl"]
    if len(bps) > len(bp_names):   # keep a spread rather than the smallest few
        step = len(bps) / len(bp_names)
        bps = [bps[int(i * step)] for i in range(len(bp_names))]
    tokens["breakpoint"] = {n: _fmt_px(p) for n, p in zip(bp_names, bps)}

    durs = []
    for d in ds.get("motion", {}).get("durations", []):
        m = re.fullmatch(r"(\d*\.?\d+)(m?s)", d["value"])
        if m:
            ms = float(m.group(1)) * (1 if m.group(2) == "ms" else 1000)
            if 0 < ms <= 2000:
                durs.append(ms)
    durs = sorted(set(durs))[:4]
    dnames = {1: ["normal"], 2: ["fast", "normal"], 3: ["fast", "normal", "slow"], 4: ["fastest", "fast", "normal", "slow"]}.get(len(durs), [])
    tokens["duration"] = {n: f"{d:g}ms" for n, d in zip(dnames, durs)}

    return {k: v for k, v in tokens.items() if v}


def _css_rgb_to_hex(v: str) -> str:
    m = re.match(r"rgba?\(\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)(?:[,\s/]+([\d.]+))?", v or "")
    if not m:
        return v
    if m.group(4) is not None and float(m.group(4)) == 0:
        return ""
    return "#" + "".join(f"{int(float(x)):02x}" for x in m.groups()[:3])


# ---------------------------------------------------------------- formats

_GROUP_PREFIX = {"color": "color", "font-family": "font", "font-size": "text", "font-weight": "font-weight",
                 "line-height": "leading", "spacing": "space", "radius": "radius", "shadow": "shadow",
                 "breakpoint": "breakpoint", "duration": "duration"}


def _var(group, name):
    return f"{_GROUP_PREFIX[group]}-{name.replace('.', '_')}"


def to_css(tokens: dict, host: str) -> str:
    lines = [f"/* Design tokens extracted from {host} by Deconstruct Site */", ":root {"]
    for group, items in tokens.items():
        lines.append(f"  /* {group} */")
        lines += [f"  --{_var(group, n)}: {v};" for n, v in items.items()]
    return "\n".join(lines + ["}", ""])


def to_scss(tokens: dict, host: str) -> str:
    lines = [f"// Design tokens extracted from {host} by Deconstruct Site"]
    for group, items in tokens.items():
        lines.append(f"\n// {group}")
        lines += [f"${_var(group, n)}: {v};" for n, v in items.items()]
        lines.append(f"${_GROUP_PREFIX[group]}s: ({', '.join(f'{json.dumps(n)}: {v}' for n, v in items.items())});"
                     if group not in ("font-family", "shadow") else "")
    return "\n".join(l for l in lines if l != "") + "\n"


_TW3_KEYS = {"color": "colors", "font-family": "fontFamily", "font-size": "fontSize", "font-weight": "fontWeight",
             "line-height": "lineHeight", "spacing": "spacing", "radius": "borderRadius", "shadow": "boxShadow",
             "breakpoint": "screens", "duration": "transitionDuration"}


def to_tailwind(tokens: dict, host: str) -> str:
    theme = {}
    for group, items in tokens.items():
        if group == "font-family":
            items = {n: [f.strip().strip("'\"") for f in v.split(",")] for n, v in items.items()}
        theme[_TW3_KEYS[group]] = items
    body = json.dumps(theme, indent=2).replace("\n", "\n    ")
    return (f"// Design tokens extracted from {host} by Deconstruct Site\n"
            "/** @type {import('tailwindcss').Config} */\n"
            "module.exports = {\n  theme: {\n    extend: " + body + "\n  }\n};\n")


_TW4_NS = {"color": "color", "font-family": "font", "font-size": "text", "font-weight": "font-weight",
           "line-height": "leading", "spacing": "spacing", "radius": "radius", "shadow": "shadow",
           "breakpoint": "breakpoint", "duration": "duration"}


def to_tailwind4(tokens: dict, host: str) -> str:
    lines = [f"/* Design tokens extracted from {host} by Deconstruct Site */", '@import "tailwindcss";', "", "@theme {"]
    for group, items in tokens.items():
        lines.append(f"  /* {group} */")
        lines += [f"  --{_TW4_NS[group]}-{n.replace('.', '_')}: {v};" for n, v in items.items()]
    return "\n".join(lines + ["}", ""])


_DTCG_TYPE = {"color": "color", "font-family": "fontFamily", "font-size": "dimension", "font-weight": "fontWeight",
              "line-height": "number", "spacing": "dimension", "radius": "dimension", "shadow": "shadow",
              "breakpoint": "dimension", "duration": "duration"}


def _dtcg_shadow(v: str):
    """CSS box-shadow → DTCG shadow value(s); falls back to the raw string when it can't be split."""
    out = []
    for part in re.split(r",(?![^(]*\))", v):
        p = part.strip()
        inset = p.startswith("inset")
        p = p.removeprefix("inset").strip()
        color = re.search(r"(rgba?\([^)]*\)|hsla?\([^)]*\)|#[0-9a-f]{3,8}\b|\b[a-z]+$)", p, re.I)
        lens = re.findall(r"-?[\d.]+(?:px|rem|em)?(?=\s|$)", re.sub(r"(rgba?|hsla?)\([^)]*\)", "", p))
        if not color or len(lens) < 2:
            return v
        lens = [l if re.search(r"[a-z]", l) else f"{l}px" for l in lens] + ["0px", "0px"]
        out.append({"color": color.group(1), "offsetX": lens[0], "offsetY": lens[1], "blur": lens[2], "spread": lens[3],
                    **({"inset": True} if inset else {})})
    return out[0] if len(out) == 1 else out


def to_json(tokens: dict, host: str) -> str:
    doc = {"$description": f"Design tokens extracted from {host} by Deconstruct Site"}
    for group, items in tokens.items():
        g = {}
        for n, v in items.items():
            if group == "font-family":
                val = [f.strip().strip("'\"") for f in v.split(",")]
            elif group == "font-weight":
                val = int(v)
            elif group == "line-height":
                val = float(v)
            elif group == "shadow":
                val = _dtcg_shadow(v)
            else:
                val = v
            g[n] = {"$type": _DTCG_TYPE[group] if not (group == "shadow" and isinstance(val, str)) else "string", "$value": val}
        doc[group] = g
    return json.dumps(doc, indent=2) + "\n"


EXPORTERS = {"css": to_css, "scss": to_scss, "tailwind": to_tailwind, "tailwind4": to_tailwind4, "json": to_json}


def export(report: dict, fmt: str) -> dict:
    if fmt not in EXPORTERS:
        raise ValueError(f"format must be one of {', '.join(EXPORTERS)}")
    host = report["overview"]["host"]
    tokens = build(report)
    label, filename = FORMATS[fmt]
    return {"format": fmt, "label": label, "filename": f"{_slug(host)}-{filename}",
            "content": EXPORTERS[fmt](tokens, host), "tokens": tokens,
            "counts": {k: len(v) for k, v in tokens.items()},
            "rendered": bool(report["design"].get("computed"))}
