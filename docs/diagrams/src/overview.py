"""Build docs/diagrams/overview.svg: two lanes of glowing module cards, layer stacks inside, tensors drawn as vectors.

Usage, from the repo root (once: `cd docs/diagrams/src && npm install`):
    python3 docs/diagrams/src/overview.py docs/diagrams/overview.svg
"""
import json, subprocess, sys
from pathlib import Path

HERE = Path(__file__).parent
OUT = Path(sys.argv[1])
LIGHT, MUTED, INK = "#e6edf3", "#9aa3b0", "#1f2328"
KIND = {"input": ("#F9D4D4", "#E07A7A"), "conv": ("#CDEFF2", "#2FB6C2"), "add": ("#FFF2CC", "#E0B83A"),
        "ff": ("#DAE8FC", "#5B8FD6"), "attn": ("#FFE3C4", "#F0883E"), "gru": ("#F9CCD9", "#E0578A"),
        "mem": ("#E6DAF5", "#A77BE0"), "op": ("#ECEFF3", "#98A2B3"), "soft": ("#D6F5DD", "#3FB950")}
C = {"b7": "#58a6ff", "b8": "#bc8cff", "det": "#e3b341", "b9": "#39c5bb", "b10": "#3fb950", "f": "#7ee787",
     "g": "#8b949e", "rec": "#f778ba"}
parts, tex = [], []


def raw(s):
    parts.append(s)


def t(x, y, src, size=12, color=LIGHT, anchor="middle", fit=None):
    parts.append(("T", len(tex)))
    tex.append((x, y, src, size, color, anchor, fit))


def module(x, y, w, h, color, badge, title, layers, note, memory=False, loop=None):
    """A card: accent bar + title, a bottom-to-top stack of layer pills, a one-line note; `badge` only names its ids."""
    raw(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="16" fill="#0b0e14" stroke="{color}" stroke-width="1.6" '
        f'stroke-opacity="0.85" filter="url(#halo_{badge})"/>')
    raw(f'<defs><filter id="halo_{badge}" x="-20%" y="-20%" width="140%" height="140%"><feDropShadow dx="0" dy="0" '
        f'stdDeviation="7" flood-color="{color}" flood-opacity="0.35"/></filter></defs>')
    raw(f'<rect x="{x + 16}" y="{y + 14}" width="4" height="18" rx="2" fill="{color}"/>')     # accent bar
    t(x + 28, y + 28, r"\textbf{" + title + "}", 13.5, LIGHT, "start", fit=w - 40)
    ph, gap = 24, 7
    top = y + 46
    stack = len(layers) * ph + (len(layers) - 1) * gap
    base = top + (h - 46 - 30 - stack) / 2
    raw(f'<path d="M{x + 13},{base + stack} L{x + 13},{base + 2}" stroke="{color}" stroke-opacity="0.6" stroke-width="1.5" '
        f'marker-end="url(#tip_{badge})"/>')
    raw(f'<defs><marker id="tip_{badge}" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto">'
        f'<path d="M0,0 L10,5 L0,10 z" fill="{color}"/></marker></defs>')
    pw = w - 34 - (18 if loop else 0)
    for i, (kind, label) in enumerate(reversed(layers)):
        py = base + i * (ph + gap)
        fill, stroke = KIND[kind] if kind != "ghost" else ("#c9d1d9", "#8b949e")
        dash = ' stroke-dasharray="4 3"' if kind == "ghost" else ""
        raw(f'<rect x="{x + 22}" y="{py}" width="{pw}" height="{ph}" rx="12" fill="none" '
            f'stroke="{stroke}" stroke-width="1.4"{dash}/>')
        shift = 0
        if "memory" in label:  # store icon on the layer that keeps state between events
            cx, cy = x + 36, py + 7
            raw(f'<path d="M{cx - 6},{cy} v9 a6,2 0 0 0 12,0 v-9" fill="none" stroke="{stroke}"/>'
                f'<ellipse cx="{cx}" cy="{cy}" rx="6" ry="2" fill="none" stroke="{stroke}"/>')
            shift = 8
        t(x + 22 + pw / 2 + shift, py + ph / 2 + 4, label, 11, fill, fit=pw - 14 - 2 * shift)
    if loop:  # top layer's output fed back into the bottom layer: the rollout
        top, bottom, xr, lx = base + ph / 2, base + (len(layers) - 1) * (ph + gap) + ph / 2, x + 22 + pw, x + w - 16
        lane(f"M{xr},{top} L{lx},{top} L{lx},{bottom} L{xr + 1},{bottom}", C["f"], dash="5 3", width=1.8, dur=2.4)
        raw(f'<g transform="rotate(-90 {x + w + 10} {top + 12})">')          # label beside the loop, clear of the output arrow
        t(x + w + 10, top + 12 + 4, loop, 11, C["f"])
        raw('</g>')
    t(x + w / 2, y + h - 12, note, 10.5, MUTED, fit=w - 20)


def vector(x, cy, color, label, cells=6, below=True):
    """A tensor drawn as a column of cells, with its name and size."""
    size, hgt = 11, cells * 11
    top = cy - hgt / 2
    for i in range(cells):
        op = 0.35 + 0.65 * ((i * 37) % 10) / 10
        raw(f'<rect x="{x - size / 2}" y="{top + i * size}" width="{size}" height="{size - 1.5}" rx="2" fill="{color}" '
            f'fill-opacity="{op:.2f}"><animate attributeName="fill-opacity" values="{op:.2f};1;{op:.2f}" dur="2.4s" '
            f'begin="{i * 0.2:.1f}s" repeatCount="indefinite"/></rect>')
    t(x, (top + hgt + 16) if below else (top - 7), label, 12, color)


def lane(d, color, dash=None, width=2, flow=True, dur=2.5):
    extra = f' stroke-dasharray="{dash}"' if dash else ""
    raw(f'<path d="{d}" fill="none" stroke="{color}" stroke-width="{width}" stroke-opacity="0.9"{extra} '
        f'marker-end="url(#ah_{color[1:]})"/>')
    if flow:
        raw(f'<circle r="3.5" fill="#ffffff"><animateMotion dur="{dur}s" repeatCount="indefinite" path="{d}"/>'
            f'<animate attributeName="opacity" values="0;1;1;0" keyTimes="0;0.1;0.85;1" dur="{dur}s" repeatCount="indefinite"/></circle>')


W, H = 1200, 756
defs = []
for kind, (fill, stroke) in KIND.items():
    defs.append(f'<linearGradient id="g_{kind}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ffffff"/>'
                f'<stop offset="0.12" stop-color="{fill}"/><stop offset="1" stop-color="{stroke}" stop-opacity="0.7"/></linearGradient>')
for color in set(C.values()):
    defs.append(f'<marker id="ah_{color[1:]}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" '
                f'orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="{color}"/></marker>')

raw(f'''<svg viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" role="img" aria-labelledby="t d">
  <title id="t">NetWatch architecture</title>
  <desc id="d">Ingest turns packet captures into an event stream. The flow encoder turns each flow (packet graph, two graph-convolution layers, pooling, MLP) into h, 32 numbers. h feeds two lanes. Detect: the detection encoder, a context encoder (link memory with a GRU, a linear query, multi-head attention over neighbour events, an MLP) gives s, 100 numbers; the detector (concatenate h and s, Linear, ReLU, Linear, Softmax) gives class probabilities p, and an alert is raised when p passes a threshold. Forecast: the forecasting encoder, the same design trained separately and also reading flow records through a frozen record encoder, gives s'; the compressor (LayerNorm, Linear, ReLU, Linear) compresses it to z, 32 numbers; the world model (message MLP, GRU host memory, neighbourhood attention, global attention with two learned queries, surprise and next-target heads) rolls the state forward six steps into the forecast. The compressor and world model are trained twice: on s' (serving tag lag) and on the detection encoder's s (serving tag live). Layers with a store icon keep memory between events.</desc>
  <defs>
    <pattern id="grid" width="32" height="32" patternUnits="userSpaceOnUse"><path d="M 32 0 L 0 0 0 32" fill="none" stroke="#ffffff" stroke-opacity="0.06"/></pattern>
    <radialGradient id="glow" cx="24%" cy="10%" r="55%"><stop offset="0%" stop-color="#e54d5e" stop-opacity="0.12"/><stop offset="55%" stop-color="#8b5cf6" stop-opacity="0.06"/><stop offset="100%" stop-color="#6366f1" stop-opacity="0"/></radialGradient>
    <linearGradient id="card" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#1b2332"/><stop offset="1" stop-color="#0f141c"/></linearGradient>
    <linearGradient id="lanedet" x1="0" x2="1"><stop offset="0" stop-color="#e3b341" stop-opacity="0"/><stop offset="0.15" stop-color="#e3b341" stop-opacity="0.10"/><stop offset="1" stop-color="#e3b341" stop-opacity="0.02"/></linearGradient>
    <linearGradient id="lanefc" x1="0" x2="1"><stop offset="0" stop-color="#3fb950" stop-opacity="0"/><stop offset="0.15" stop-color="#3fb950" stop-opacity="0.10"/><stop offset="1" stop-color="#3fb950" stop-opacity="0.02"/></linearGradient>
    {"".join(defs)}
    @@DEFS@@
  </defs>
  <rect width="{W}" height="{H}" fill="#0b0e14"/>
  <rect width="{W}" height="{H}" fill="url(#grid)"/>
  <rect width="{W}" height="{H}" fill="url(#glow)"/>
  <text x="40" y="44" font-family="Consolas, 'Courier New', monospace" font-size="13" letter-spacing="2.5" fill="#a78bfa">NETWATCH · ARCHITECTURE</text>
  <line x1="284" y1="39" x2="1160" y2="39" stroke="#232b38" stroke-width="1.5"/>''')
t(40, 80, r"\text{One event stream, two lanes: }\textcolor{#E3B341}{\textbf{detect}}\text{ each event now, }"
          r"\textcolor{#7EE787}{\textbf{forecast}}\text{ the links that come next}", 21, LIGHT, "start")

# lane ribbons behind the two rows
t(1168, 124, r"\textsf{DETECT}", 11, "#e3b341", "end")
t(1168, 408, r"\textsf{FORECAST}", 11, "#7ee787", "end")

# ================= Ingest + flow encoder =================
raw('<rect x="24" y="262" width="140" height="220" rx="16" fill="#0b0e14" stroke="#8b949e" stroke-opacity="0.7"/>')
t(94, 290, r"\textbf{Ingest}", 13.5)
for i, (label, kind) in enumerate(((r"\text{pcap}", "op"), (r"\text{packets, flows}", "op"), (r"\text{event stream}", "input"))):
    py = 306 + i * 40
    raw(f'<rect x="38" y="{py}" width="112" height="26" rx="13" fill="none" '
        f'stroke="{KIND[kind][1]}" stroke-width="1.4"/>')
    t(94, py + 17, label, 11, KIND[kind][0], fit=100)
    if i < 2:
        raw(f'<path d="M94,{py + 27} L94,{py + 38}" stroke="#8b949e" stroke-width="1.3" marker-end="url(#ah_8b949e)"/>')
t(94, 440, r"\text{ordered by } t_{\mathrm{obs}}", 10.5, MUTED)
t(94, 468, r"\text{+ flow records}", 10.5, "#f778ba")

module(204, 262, 162, 220, C["b7"], "7", "Flow encoder",
       [("input", r"\text{Packet graph}"), ("conv", r"\text{Graph Conv} \times 2"), ("op", r"\text{Mean}\,\|\,\text{Max pool}"),
        ("ff", r"\text{MLP}")], r"\text{one flow, first 10 ms}")
lane("M164,372 L203,372", C["g"], width=1.8, flow=False)

vector(404, 372, C["b7"], r"h \in \mathbb{R}^{32}")
lane("M366,372 L397,372", C["b7"], flow=False)
# h into both lanes and the detector
lane("M414,356 C432,356 426,226 440,226 L453,226", C["b7"], dur=2.2)
lane("M414,388 C432,388 426,512 440,512 L453,512", C["b7"], dur=2.2)
lane("M404,336 L404,98 L760,98 L760,115", C["b7"], width=1.4, dur=3.2)
t(582, 112, r"h", 12, C["b7"])

# ================= detect lane =================
module(454, 116, 166, 222, C["b8"], "8a", "Detection encoder",
       [("mem", r"\text{Link memory} \cdot \text{GRU}"), ("ff", r"\text{Linear} \rightarrow Q"),
        ("attn", r"\text{Multi-Head Attention}"), ("ff", r"\text{MLP}")], r"\text{event and summary messages}", memory=True)
vector(656, 226, C["b8"], r"s \in \mathbb{R}^{100}", cells=7)
lane("M620,226 L649,226", C["b8"], flow=False)
lane("M666,226 L691,226", C["b8"], dur=1.4)
module(692, 116, 150, 222, C["det"], "D", "Detector",
       [("op", r"\text{Concat } [h, s]"), ("ff", r"\text{Linear} \cdot \text{ReLU}"), ("ff", r"\text{Linear}"),
        ("soft", r"\text{Softmax}")], r"\text{one head per day}")
vector(878, 226, C["det"], r"p", cells=4)
lane("M842,226 L871,226", C["det"], flow=False)
# the live tag: the detection encoder's s also trains and feeds a second compressor and world model
lane("M656,282 L656,372 L767,372 L767,400", C["b8"], dash="5 3", width=1.5, dur=3.0)
t(676, 366, r"s \rightarrow \text{compressor and world model, tag live}", 10.5, C["b8"], "start")
lane("M888,226 L915,226", C["det"], dur=1.4)
raw('<rect x="916" y="192" width="104" height="68" rx="14" fill="#0b0e14" stroke="#e3b341" stroke-width="1.6" filter="url(#halo_D)"/>')
t(968, 220, r"\textbf{Alert}", 14, "#e3b341")
t(968, 242, r"\text{if } p \ge \tau", 12)

# legend
raw('<rect x="1036" y="140" width="150" height="190" rx="12" fill="#0b0e14" fill-opacity="0.6" stroke="#30363d"/>')
t(1052, 160, r"\textbf{Legend}", 11.5, MUTED, "start")
raw('<rect x="1052" y="170" width="40" height="14" rx="7" fill="none" stroke="#5B8FD6" stroke-width="1.4"/>')
t(1100, 181, r"\text{layer}", 10.5, LIGHT, "start")
for i in range(4):
    raw(f'<rect x="{1066}" y="{194 + i * 8}" width="8" height="7" rx="1.5" fill="#bc8cff" fill-opacity="{0.4 + 0.2 * i:.1f}"/>')
t(1100, 214, r"\text{tensor, } \mathbb{R}^{n}", 10.5, LIGHT, "start", fit=78)
raw('<path d="M1061,236 v11 a9,3 0 0 0 18,0 v-11" fill="none" stroke="#bc8cff"/>'
    '<ellipse cx="1070" cy="236" rx="9" ry="3" fill="none" stroke="#bc8cff"/>')
t(1100, 246, r"\text{keeps memory}", 10.5, LIGHT, "start", fit=78)
raw('<rect x="1052" y="260" width="40" height="14" rx="7" fill="none" stroke="#8b949e" stroke-dasharray="4 3"/>')
t(1100, 271, r"\text{frozen / training}", 10.5, LIGHT, "start", fit=78)
raw('<path d="M1054,290 L1090,290" stroke="#f778ba" stroke-width="1.6" stroke-dasharray="5 3"/>')
t(1100, 294, r"\text{flow records}", 10.5, LIGHT, "start", fit=78)
raw('<path d="M1054,314 L1090,314" stroke="#58a6ff" stroke-width="2"/><circle cx="1072" cy="314" r="3" fill="#fff"/>')
t(1100, 318, r"\text{data flow}", 10.5, LIGHT, "start", fit=78)

# ================= forecast lane =================
module(454, 402, 166, 222, C["b8"], "8b", "Forecasting encoder",
       [("ghost", r"\text{Record encoder}"), ("mem", r"\text{Link memory} \cdot \text{GRU}"),
        ("attn", r"\text{Multi-Head Attention}"), ("ff", r"\text{MLP}")], r"\text{same design, own weights}", memory=True)
lane("M94,482 L94,662 L537,662 L537,625", C["rec"], dash="5 3", width=1.6, dur=3.5)
t(300, 656, r"\text{flow records, when each flow closes}", 11, "#f778ba")
vector(656, 512, C["b8"], r"s' \in \mathbb{R}^{100}", cells=7)
lane("M620,512 L649,512", C["b8"], flow=False)
lane("M666,512 L691,512", C["b8"], dur=1.4)
module(692, 402, 150, 222, C["b9"], "9", "Compressor",
       [("add", r"\text{LayerNorm}"), ("ff", r"\text{Linear} \cdot \text{ReLU}"), ("ff", r"\text{Linear}"),
        ("ghost", r"\text{Decoder}")], r"\text{autoencoder, benign only}")
vector(878, 512, C["b9"], r"z \in \mathbb{R}^{32}")
lane("M842,512 L871,512", C["b9"], flow=False)
lane("M888,512 L911,512", C["b9"], dur=1.4)
module(912, 402, 180, 222, C["b10"], "10", "World model",
       [("ff", r"\text{Message MLP}"), ("gru", r"\text{GRU} \rightarrow \text{host memory}"),
        ("attn", r"\text{Neighbourhood Attn.}\ \oplus"), ("attn", r"\text{Global Attn. } (q_1, q_2)"),
        ("soft", r"\text{surprise} \cdot \text{next target}")], r"\text{memory per host}", memory=True,
       loop=r"\text{rollout} \times 6")
# rollout loop over the world model
# forecast output
raw('<rect x="1116" y="440" width="72" height="146" rx="14" fill="#0b0e14" stroke="#7ee787" stroke-width="1.6" filter="url(#halo_10)"/>')
lane("M1093,512 L1115,512", C["f"], flow=False)
t(1152, 468, r"\textbf{Forecast}", 11.5, "#7ee787")
t(1152, 498, r"S[t{+}1]", 11)
raw("".join(f'<circle cx="1152" cy="{y}" r="1.3" fill="#e6edf3"/>' for y in (508, 514, 520)))
t(1152, 536, r"S[t{+}6]", 11)
t(1152, 566, r"\text{+ surprise}", 9.5, MUTED)

t(600, 712, r"\textbf{Figure 1.}\ \text{Each card is one trained component; data flows bottom to top inside a card; "
            r"the two context encoders share one design but not their weights; only the forecasting one reads flow records.}", 12, MUTED)
t(600, 732, r"\text{The compressor and world model are trained twice: on } s' \text{ (tag lag, about 150 s behind the traffic) "
            r"and on the detection encoder's } s \text{ (tag live, seconds behind).}", 12, MUTED)
raw("</svg>")

res = json.loads(subprocess.run(["node", str(HERE / "tex.js")], input=json.dumps([s[2] for s in tex]),
                                capture_output=True, text=True, check=True).stdout)
bad = [tex[i][2] for i, it in enumerate(res["items"]) if "merror" in it["inner"]]
out = []
for p in parts:
    if isinstance(p, str):
        out.append(p)
        continue
    x, y, src, size, color, anchor, fit = tex[p[1]]
    it = res["items"][p[1]]
    if fit and it["w"] / 1000 * size > fit:
        shrunk = fit / (it["w"] / 1000)
        if shrunk < size * 0.8:
            print(f"  too long even at 80%: {src}")
        size = max(shrunk, size * 0.8)
    w, h = it["w"] / 1000 * size, it["h"] / 1000 * size
    x0 = x - w / 2 if anchor == "middle" else (x - w if anchor == "end" else x)
    y0 = y + it["y"] / 1000 * size
    out.append(f'<svg x="{x0:.1f}" y="{y0:.1f}" width="{w:.1f}" height="{h:.1f}" viewBox="{it["x"]} {it["y"]} {it["w"]} {it["h"]}" '
               f'color="{color}" overflow="visible">{it["inner"]}</svg>')
svg = "\n".join(out).replace("@@DEFS@@", res["defs"])
OUT.write_text(svg)
print(f"{OUT}: {len(svg):,} bytes, {len(tex)} labels" + (f", ERRORS {bad}" if bad else ""))
