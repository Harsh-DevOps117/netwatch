"""Re-typeset every <text> of an SVG with MathJax (Computer Modern glyph paths), keeping position, size, colour, anchor.

Usage, from the repo root (once: `cd docs/diagrams/src && npm install`):
    for f in docs/diagrams/src/sources/*.svg; do uv run python docs/diagrams/src/latexify.py "$f" docs/diagrams/$(basename "$f"); done
Edit a figure in sources/ (plain SVG text), then re-run.
A label whose LaTeX form is wider than the original is shrunk to the original width (never below 78%).
"""
import json, re, subprocess, sys
import xml.etree.ElementTree as ET
from pathlib import Path
from PIL import ImageFont

HERE = Path(__file__).parent
NS, XL = "http://www.w3.org/2000/svg", "http://www.w3.org/1999/xlink"
ET.register_namespace("", NS)
ET.register_namespace("xlink", XL)
FONTS = "/mnt/c/Windows/Fonts/"
INHERIT = ("font-size", "fill", "text-anchor", "font-weight", "font-family", "fill-opacity")

SYM = {"→": r"\rightarrow", "←": r"\leftarrow", "≤": r"\le", "≥": r"\ge", "·": r"\cdot", "×": r"\times",
       "Φ": r"\Phi", "Δ": r"\Delta", "π": r"\pi", "μ": r"\mu", "σ": r"\sigma", "τ": r"\tau", "≈": r"\approx",
       "−": "-", "…": r"\ldots", "●": r"\bullet", "‖": r"\|", "ℝ": r"\mathbb{R}", "∈": r"\in", "ŝ": r"\hat{s}",
       "\x00": r"\tilde{s}", "~": r"\sim"}
SUP = dict(zip("⁰¹²³⁴⁵⁶⁷⁸⁹⁻", "0123456789-"))
CIRC = "①②③④⑤⑥⑦⑧⑨⑩⑪⑫⑬⑭⑮⑯⑰⑱⑲⑳"
TOKEN = re.compile(
    r"(?P<code>[\w.<>*-]*/[\w/.<>{},*-]*\.\w+|[\w.<>*-]*/[\w/.<>{},*-]*/|[\w<>-]+\.(?:py|csv|pt|parquet|json|sh)\b|\b[a-z]{2,}(?:_[a-z0-9]+)+\b)"
    r"|(?P<sub>\b(?:dt|[A-Za-z])_[A-Za-z0-9]+\b)"
    r"|(?P<pow>\d+[⁰¹²³⁴⁵⁶⁷⁸⁹⁻]+)"
    r"|(?P<sup>[⁰¹²³⁴⁵⁶⁷⁸⁹⁻]+)"
    r"|(?P<circ>[" + CIRC + r"])"
    r"|(?P<sym>[" + re.escape("".join(SYM)) + r"])")


def esc(s):
    return re.sub(r"([&%$#_{}])", r"\\\1", s)


def to_tex(s, bold, mono):
    s = s.replace("s̃", "\x00")
    wrap = r"\texttt" if mono else (r"\textbf" if bold else r"\text")
    out, pos = [], 0

    def text(run):
        if not run:
            return
        lead, core, trail = run[:len(run) - len(run.lstrip())], run.strip(), run[len(run.rstrip()):]
        out.append((r"\ " if lead else "") + (f"{wrap}{{{esc(core)}}}" if core else "") + (r"\ " if trail and core else ""))

    def math(m):
        out.append(r"{\boldsymbol{" + m + "}}" if bold else "{" + m + "}")

    for m in TOKEN.finditer(s):
        text(s[pos:m.start()])
        pos = m.end()
        kind, tok = m.lastgroup, m.group()
        if kind == "code":
            out.append(r"\texttt{" + esc(tok) + "}")
        elif kind == "sub":
            base, sub = tok.split("_", 1)
            base = r"\mathrm{dt}" if base == "dt" else base
            sub = sub if len(sub) <= 2 else r"\mathrm{" + sub + "}"
            math(f"{base}_{{{sub}}}")
        elif kind == "pow":
            digits = re.match(r"\d+", tok).group()
            math(digits + "^{" + "".join(SUP[c] for c in tok[len(digits):]) + "}")
        elif kind == "sup":
            math("{}^{" + "".join(SUP[c] for c in tok) + "}")
        elif kind == "circ":
            out.append(r"\enclose{circle}{\kern.1em\scriptsize " + str(CIRC.index(tok) + 1) + r"\kern.1em}\,")
        else:
            math(SYM[tok])
    text(s[pos:])
    return "".join(out)


def width(s, size, bold, mono):
    name = ("consolab.ttf" if bold else "consola.ttf") if mono else ("segoeuib.ttf" if bold else "segoeui.ttf")
    return ImageFont.truetype(FONTS + name, max(1, round(size))).getlength(s) * size / max(1, round(size))


def main(src, dst):
    tree = ET.parse(src)
    root = tree.getroot()
    items = []

    def walk(node, inherited):
        here = {**inherited, **{k: node.get(k) for k in INHERIT if node.get(k) is not None}}
        for i, child in enumerate(list(node)):
            if child.tag == f"{{{NS}}}text":
                attrs = {**here, **{k: child.get(k) for k in INHERIT if child.get(k) is not None}}
                items.append((child, attrs))
                node.remove(child)
                node.insert(i, ET.Element(f"{{{NS}}}g", {"id": f"__tex{len(items) - 1}"}))
            else:
                walk(child, here)

    walk(root, {"font-size": root.get("font-size", "12"), "fill": "#e6edf3", "text-anchor": "start"})
    specs = []
    for el, a in items:
        raw = "".join(el.itertext())
        bold = a.get("font-weight") in ("600", "700", "800", "bold")
        mono = "mono" in (a.get("font-family") or "").lower() or "consolas" in (a.get("font-family") or "").lower()
        specs.append(dict(raw=raw, tex=to_tex(raw, bold, mono), size=float(a["font-size"]), fill=a["fill"],
                          anchor=a["text-anchor"], x=float(el.get("x", 0)), y=float(el.get("y", 0)),
                          op=a.get("fill-opacity"), orig=width(raw, float(a["font-size"]), bold, mono)))
    res = json.loads(subprocess.run(["node", str(HERE / "tex.js")], input=json.dumps([s["tex"] for s in specs]),
                                    capture_output=True, text=True, check=True).stdout)
    svg = ET.tostring(root, encoding="unicode")
    bad = []
    for n, (s, it) in enumerate(zip(specs, res["items"])):
        if "merror" in it["inner"]:
            bad.append(s["tex"])
        size = s["size"]
        w = it["w"] / 1000 * size
        if s["raw"].strip() and w > s["orig"] * 1.02:
            size *= max(s["orig"] * 1.02 / w, 0.78)
        w, h = it["w"] / 1000 * size, it["h"] / 1000 * size
        x0 = s["x"] - (w / 2 if s["anchor"] == "middle" else w if s["anchor"] == "end" else 0)
        y0 = s["y"] + it["y"] / 1000 * size
        op = f' fill-opacity="{s["op"]}"' if s["op"] else ""
        nested = (f'<svg x="{x0:.1f}" y="{y0:.1f}" width="{w:.1f}" height="{h:.1f}" viewBox="{it["x"]} {it["y"]} '
                  f'{it["w"]} {it["h"]}" color="{s["fill"]}"{op} overflow="visible">{it["inner"]}</svg>')
        svg = re.sub(rf'<g id="__tex{n}"\s*/>', lambda _: nested, svg, count=1)
    if "xmlns:xlink" not in svg[:500]:
        svg = svg.replace("<svg ", f'<svg xmlns:xlink="{XL}" ', 1)
    svg = svg.replace("</defs>", res["defs"] + "</defs>", 1)
    Path(dst).write_text(svg)
    print(f"{dst}: {len(specs)} labels, {len(svg):,} bytes" + (f", ERRORS: {bad}" if bad else ""))


if __name__ == "__main__":
    main(*sys.argv[1:3])
