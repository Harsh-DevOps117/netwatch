"""Write the plain source SVGs of the guide figures (ingest, splits, joins, detector, serving, training, publishing).

Usage, from the repo root:
    python3 docs/diagrams/src/guides.py
    for f in ingest splits joins detector serving-live serving-tags serving-detect training publishing; do
        uv run python docs/diagrams/src/latexify.py docs/diagrams/src/sources/$f.svg docs/diagrams/$f.svg; done
"""
from html import escape
from pathlib import Path

SRC = Path(__file__).parent / "sources"
C = {"blue": "#58a6ff", "amber": "#e3b341", "red": "#ff7b72", "purple": "#bc8cff", "green": "#3fb950",
     "teal": "#39c5bb", "grey": "#8b949e", "pink": "#f778ba", "light": "#e6edf3", "muted": "#8b949e"}


class Fig:
    def __init__(self, w, h, title, sub, desc):
        self.w, self.h, self.parts = w, h, []
        marks = "".join(f'<marker id="ah_{v[1:]}" viewBox="0 0 10 10" refX="7.2" refY="5" markerWidth="7" markerHeight="7" '
                        f'orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="{v}"/></marker>' for v in set(C.values()))
        self.parts.append(
            f'<svg viewBox="0 0 {w} {h}" xmlns="http://www.w3.org/2000/svg" role="img" aria-labelledby="t d" '
            f'font-family="-apple-system, BlinkMacSystemFont, \'Segoe UI\', Helvetica, Arial, sans-serif" font-size="12">\n'
            f'  <title id="t">{escape(title)}</title>\n  <desc id="d">{escape(desc)}</desc>\n  <defs>\n'
            '    <pattern id="grid" width="32" height="32" patternUnits="userSpaceOnUse"><path d="M 32 0 L 0 0 0 32" fill="none" stroke="#ffffff" stroke-opacity="0.06"/></pattern>\n'
            '    <radialGradient id="glow" cx="24%" cy="10%" r="55%"><stop offset="0%" stop-color="#e54d5e" stop-opacity="0.10"/><stop offset="55%" stop-color="#8b5cf6" stop-opacity="0.05"/><stop offset="100%" stop-color="#6366f1" stop-opacity="0"/></radialGradient>\n'
            '    <pattern id="hatch" width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)"><line x1="0" y1="0" x2="0" y2="6" stroke="#8b949e" stroke-opacity="0.6" stroke-width="2"/></pattern>\n'
            f'    {marks}\n  </defs>\n'
            f'  <rect width="{w}" height="{h}" fill="#0b0e14"/>\n  <rect width="{w}" height="{h}" fill="url(#grid)"/>\n'
            f'  <rect width="{w}" height="{h}" fill="url(#glow)"/>\n')
        self.text(28, 40, title, 20, C["light"], weight=700)
        self.text(28, 62, sub, 13, C["muted"])

    def text(self, x, y, s, size=12, fill=C["light"], anchor="start", weight=None, mono=False):
        w = f' font-weight="{weight}"' if weight else ""
        m = ' font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"' if mono else ""
        self.parts.append(f'  <text x="{x}" y="{y}" fill="{fill}" font-size="{size}" text-anchor="{anchor}"{w}{m}>{escape(s)}</text>\n')

    def rect(self, x, y, w, h, stroke, fill="#0b0e14", rx=8, dash=False, width=1.4, opacity=None):
        d = ' stroke-dasharray="5 4"' if dash else ""
        o = f' fill-opacity="{opacity}"' if opacity is not None else ""
        self.parts.append(f'  <rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}"{o} stroke="{stroke}" stroke-width="{width}"{d}/>\n')

    def panel(self, x, y, w, h, title, color):
        self.rect(x, y, w, h, "#30363d", "#161b22", rx=12, width=1)
        self.text(x + 14, y + 22, title, 13, color, weight=700)

    def box(self, x, y, w, h, color, head, lines=(), dash=False, mono_head=False, anchor="middle"):
        """Outline box: a coloured first line, then light / muted lines, centred vertically."""
        self.rect(x, y, w, h, color, dash=dash)
        rows = [(head, 12, color, 700, mono_head)] + [(l, 11, C["light"] if i == 0 else C["muted"], None, False)
                                                     for i, l in enumerate(lines)]
        step = 15
        top = y + h / 2 - (len(rows) - 1) * step / 2 + 4
        tx = x + w / 2 if anchor == "middle" else x + 12
        for i, (s, size, fill, weight, mono) in enumerate(rows):
            self.text(tx, top + i * step, s, size, fill, anchor, weight, mono)

    def arrow(self, d, color=C["grey"], dash=False, width=1.5):
        dd = ' stroke-dasharray="5 4"' if dash else ""
        self.parts.append(f'  <path d="{d}" fill="none" stroke="{color}" stroke-width="{width}"{dd} marker-end="url(#ah_{color[1:]})"/>\n')

    def pulse(self, d, color, dur=3):
        self.parts.append(f'  <circle r="3.5" fill="{color}"><animateMotion dur="{dur}s" repeatCount="indefinite" path="{d}"/></circle>\n')

    def raw(self, s):
        self.parts.append("  " + s + "\n")

    def save(self, name):
        (SRC / f"{name}.svg").write_text("".join(self.parts) + "</svg>\n")


# =====================================================================================================================
def ingest():
    f = Fig(1200, 540, "Ingest: from packet captures to an event stream",
            "plain data processing, no learning · each capture becomes tables, then each day becomes one event stream",
            "A day's captures are selected by their pcap header and first packet. tshark writes packets, CICFlowMeter writes "
            "two-way flows, and the published attack schedule labels both. An interval join maps each packet to its flow, and "
            "each flow is also written as an edge. The event stream builder turns a day's flows, packets and map into one event "
            "per flow in six steps. Two more per-event tables, side features and flow records, are built for the context encoder.")
    f.box(28, 196, 170, 110, C["grey"], "Captures", ["a day's folder of files", "kept: pcap/pcapng header,", "first packet on that day"])
    f.box(248, 96, 230, 64, C["blue"], "packets.parquet", ["tshark · one row per packet", "29 columns incl. first 128 payload bytes"], mono_head=True)
    f.box(248, 196, 230, 64, C["amber"], "flows.parquet", ["CICFlowMeter · two-way flows, 76 statistics", "a flow ends at a FIN or 120 s after its start"], mono_head=True)
    f.box(248, 296, 230, 64, C["red"], "5 label columns", ["the published attack schedule:", "attacker / victim IPs, windows, ports"], dash=True)
    f.text(363, 378, "labels are for evaluation only", 10.5, C["muted"], "middle")
    f.arrow("M198,236 C216,236 218,128 232,128 L246,128")
    f.arrow("M198,251 L246,228")
    f.arrow("M363,296 L363,262", C["red"], dash=True)
    f.box(528, 96, 240, 64, C["purple"], "flow_packet_map.parquet", ["interval join: same 5-tuple AND", "inside the flow's time span"], mono_head=True)
    f.box(528, 296, 240, 64, C["grey"], "edges.parquet", ["each flow as a timestamped edge", "between two hosts"], mono_head=True)
    f.arrow("M478,128 L526,128")
    f.arrow("M478,216 C496,216 496,146 512,146 L526,146")
    f.arrow("M478,248 C498,252 498,328 512,328 L526,328")
    # event stream builder
    f.panel(818, 84, 354, 318, "EVENT STREAM · one event per flow", C["green"])
    steps = [("1", "start time from the first packet", "microseconds, not CICFlowMeter's 1 s"),
             ("2", "20 aggregates over the first 20 packets", "size, TTL, window, gaps, flags, payload"),
             ("3", "drop the empty twin", "of a forward / reverse duplicate"),
             ("4", "node ids per day", "by first appearance; never across days"),
             ("5", "per-host history, earlier events only", "dt_src, dt_dst, port_delta, dst_port_new"),
             ("6", "orientation: reversed", "a bare SYN, else the higher port; no label")]
    for i, (n, a, b) in enumerate(steps):
        y = 112 + i * 46
        f.raw(f'<circle cx="848" cy="{y + 12}" r="11" fill="none" stroke="#3fb950" stroke-width="1.4"/>')
        f.text(848, y + 16, n, 11, C["green"], "middle", 700)
        f.text(870, y + 10, a, 12, C["light"])
        f.text(870, y + 25, b, 11, C["muted"])
    f.arrow("M768,128 C786,128 786,200 802,200 L816,200")
    f.arrow("M478,228 L816,228", C["amber"])
    f.text(648, 220, "flows", 10.5, C["amber"], "middle")
    f.arrow("M478,106 C620,62 790,62 806,118 L814,134", C["blue"], dash=True)
    f.text(648, 90, "packets for the aggregates", 10.5, C["blue"], "middle")
    # outputs
    f.box(818, 424, 170, 58, C["green"], "events.parquet", ["one row per event, by t"], mono_head=True)
    f.box(1002, 424, 170, 58, C["green"], "node_index.parquet", ["node id ↔ IP, per day"], mono_head=True)
    f.arrow("M903,402 L903,422", C["green"])
    f.arrow("M1087,402 L1087,422", C["green"])
    f.box(248, 424, 250, 58, C["teal"], "side_features.parquet", ["sender, receiver, request / response", "counts, reply latency, as of t_obs"], mono_head=True)
    f.box(528, 424, 240, 58, C["teal"], "flow_records.parquet", ["69 record columns + record_time", "(the flow's last packet)"], mono_head=True)
    f.arrow("M816,453 L770,453", C["teal"])
    f.arrow("M794,453 L794,504 L373,504 L373,484", C["teal"])
    f.text(560, 526, "built for the context encoder from the same day's packets and flows, one row per event", 11, C["teal"], "middle")
    f.pulse("M198,236 C216,236 218,128 232,128 L246,128 M478,128 L526,128 M768,128 C786,128 786,200 802,200 L816,200", C["blue"], 3.5)
    f.pulse("M478,228 L816,228", C["amber"], 2.5)
    f.save("ingest")


# =====================================================================================================================
def splits():
    f = Fig(1200, 400, "How a day is split",
            "every attack window and every benign stretch is split by its own time: 60% train · 10% validation · 30% test, "
            "120 s unused at each boundary",
            "Each segment of a day, an attack window or a benign stretch, is split by time into 60 percent train, 10 percent "
            "validation and 30 percent test, with a 120 second gap at every boundary so no flow straddles two splits. Every "
            "split therefore contains every attack family. Measured over five days the events fall 69.4 percent train, 6.0 "
            "percent validation, 20.2 percent test and 4.3 percent in gaps.")
    cols = {"train": C["blue"], "val": C["amber"], "test": C["green"]}

    def segment(x, w, label, color, dash=False):
        gap = 9
        inner = w - 3 * gap
        parts = [("train", 0.6), ("val", 0.1), ("test", 0.3)]
        f.rect(x, 128, w, 44, color, fill="none", rx=6, dash=dash, width=1.2)
        f.text(x + w / 2, 118, label, 12, color, "middle", 700)
        cx = x
        for name, frac in parts:
            ww = inner * frac
            f.rect(cx + 2, 134, ww - 2, 32, cols[name], rx=4, width=1.4)
            if ww > 46:
                f.text(cx + ww / 2 + 1, 155, name, 11.5, cols[name], "middle", 700)
            cx += ww
            f.raw(f'<rect x="{cx + 1}" y="134" width="{gap - 2}" height="32" fill="url(#hatch)"/>')
            cx += gap
    segment(40, 470, "benign stretch", C["grey"])
    segment(530, 260, "attack window", C["red"], dash=True)
    segment(810, 350, "benign stretch", C["grey"])
    f.raw('<path d="M40,190 L1160,190" stroke="#6e7681" stroke-width="1.3" marker-end="url(#ah_8b949e)"/>')
    f.text(1160, 208, "time in the day", 11, C["muted"], "end")
    f.raw('<rect x="40" y="222" width="18" height="12" fill="url(#hatch)" stroke="#8b949e" stroke-width="0.8"/>')
    f.text(66, 232, "120 s gap: unused, so no flow crosses a boundary (a flow ends within 120 s)", 11.5, C["light"])
    f.text(620, 232, "why per segment: every split then holds every attack family", 11.5, C["light"])
    # measured
    f.text(40, 282, "Measured share of events, five days", 13, C["muted"], weight=700)
    x = 40
    for name, pct, col in (("train", 69.4, C["blue"]), ("validation", 6.0, C["amber"]), ("test", 20.2, C["green"]), ("gaps", 4.3, C["grey"])):
        w = 1120 * pct / 100
        if name == "gaps":
            f.raw(f'<rect x="{x}" y="296" width="{w}" height="30" rx="4" fill="url(#hatch)" stroke="#8b949e"/>')
        else:
            f.rect(x, 296, w - 3, 30, col, rx=4)
        label = f"{name} {pct}%"
        f.text(x + (w - 3) / 2, 316, label if w > 90 else f"{pct}%", 11.5, col, "middle", 700)
        if w <= 90:
            f.text(x + (w - 3) / 2, 344, name, 11, col, "middle")
        x += w
    f.text(40, 380, "Event shares differ from 60/10/30 because traffic is uneven across a day and short attack windows lose much of "
                    "their validation band to the gaps.", 11.5, C["muted"])
    f.save("splits")


# =====================================================================================================================
def joins():
    f = Fig(1200, 470, "How the tables join",
            "per capture, packets reach flows only through the map · per day, every event table joins on event_id",
            "Packets join the map on frame_no and the map joins flows on flow_uid. Joining packets to flows on flow_key is "
            "wrong, because CICFlowMeter reuses one 5-tuple key for many flows. Per day, events carry flow_uid back to flows, "
            "node ids map to IPs through that day's node index, and every other event table joins on event_id. Links are keyed "
            "on the first packet's sender, not on CICFlowMeter's source.")

    def table(x, y, w, name, keys, color, note=None):
        h = 44 + 17 * len(keys) + (16 if note else 0)
        f.rect(x, y, w, h, color)
        f.text(x + 12, y + 22, name, 12.5, color, weight=700, mono=True)
        f.raw(f'<line x1="{x + 1}" y1="{y + 32}" x2="{x + w - 1}" y2="{y + 32}" stroke="{color}" stroke-opacity="0.4"/>')
        for i, (k, strong) in enumerate(keys):
            f.text(x + 12, y + 50 + i * 17, k, 11.5, C["light"] if strong else C["muted"], weight=700 if strong else None, mono=True)
        if note:
            f.text(x + 12, y + h - 8, note, 10.5, C["muted"])
        return h
    f.panel(20, 84, 560, 366, "PER CAPTURE", C["grey"])
    table(40, 124, 160, "packets", [("frame_no", True), ("flow_key", False), ("timestamp, …", False)], C["blue"])
    table(230, 124, 170, "flow_packet_map", [("frame_no", True), ("flow_uid", True), ("flow_key", False)], C["purple"])
    table(420, 124, 140, "flows", [("flow_uid", True), ("flow_key", False), ("76 statistics", False)], C["amber"])
    f.arrow("M200,183 L228,183", C["purple"])
    f.text(214, 174, "frame_no", 10, C["purple"], "middle", mono=True)
    f.arrow("M400,200 L418,200", C["amber"])
    f.text(410, 222, "flow_uid", 10, C["amber"], "middle", mono=True)
    # the wrong join
    f.raw('<path d="M120,210 C120,300 490,300 490,210" fill="none" stroke="#ff7b72" stroke-width="1.6" stroke-dasharray="6 4"/>')
    f.raw('<g stroke="#ff7b72" stroke-width="2.4"><line x1="296" y1="276" x2="316" y2="296"/><line x1="316" y1="276" x2="296" y2="296"/></g>')
    f.text(306, 322, "never join packets to flows on flow_key:", 12, C["red"], "middle", 700)
    f.text(306, 338, "CICFlowMeter closes and reopens a 5-tuple, so one key", 11, C["light"], "middle")
    f.text(306, 353, "names many flows and rows multiply", 11, C["light"], "middle")
    f.text(40, 392, "packets.merge(flow_packet_map, on=\"frame_no\")", 11.5, C["light"], mono=True)
    f.text(40, 410, "       .merge(flows, on=\"flow_uid\")", 11.5, C["light"], mono=True)
    f.text(40, 432, "the map comes from an interval join, so a packet's label always equals its flow's", 10.5, C["muted"])
    # per day
    f.panel(600, 84, 580, 366, "PER DAY", C["green"])
    table(620, 124, 170, "events", [("event_id", True), ("flow_uid", False), ("src/dst_node_id", False)], C["green"], "sorted by t")
    table(620, 302, 170, "node_index", [("node_id", True), ("ip", False)], C["grey"], "ids are per day")
    others = [("side_features", "sender_node_id", C["teal"]), ("flow_records", "record_time", C["teal"]),
              ("flow_embeddings", "h (32)", C["blue"]), ("event_latents", "z (32), t_obs order", C["purple"])]
    for i, (n, extra, col) in enumerate(others):
        y = 110 + i * 82
        table(980, y, 184, n, [("event_id", True), (extra, False)], col)
        f.arrow(f"M790,150 C872,150 866,{y + 42} 960,{y + 42} L978,{y + 42}", col)
    f.text(820, 140, "event_id", 10.5, C["green"], mono=True)
    f.arrow("M705,240 L705,300", C["grey"])
    f.text(713, 274, "node ids", 10.5, C["grey"], mono=True)
    f.text(620, 410, "links are keyed on the first packet's sender", 11.5, C["light"], weight=700)
    f.text(620, 425, "(sender_node_id), never on src/dst_node_id: CICFlowMeter's", 11, C["muted"])
    f.text(620, 439, "Src disagrees with it on 11–30% of events", 11, C["muted"])
    f.save("joins")


# =====================================================================================================================
def detector():
    f = Fig(1200, 470, "Detector",
            "names the attack family behind an event, with a probability, at a false-alarm budget the operator chooses",
            "The detector reads h, 32 numbers from the flow encoder, and s, 100 numbers from the detection encoder. One head "
            "per day maps the 132 numbers through a hidden layer of 64 to one output per class. Thresholds are quantiles of "
            "benign scores on calibration rows at the chosen false-alarm budget; test labels are never used. An event alerts "
            "for a family when that family's probability reaches its threshold; a host alerts after three such events in a row, and alerts with "
            "no quiet gap longer than 60 seconds form one incident.")
    # inputs as tensors
    for i, (name, n, col, src) in enumerate((("h", 32, C["blue"], "flow encoder"), ("s", 100, C["purple"], "detection encoder"))):
        x = 44 + i * 70
        for k in range(6 if n == 32 else 9):
            f.raw(f'<rect x="{x}" y="{150 + k * 12}" width="12" height="10" rx="2" fill="none" stroke="{col}" stroke-width="1.3"/>')
        f.text(x + 6, 140, f"{name} · {n}", 12, col, "middle", 700)
        f.text(x + 6, 276 + 16 * i, src, 10, C["muted"], "middle")
    f.arrow("M136,205 L178,205")
    # head
    f.panel(180, 84, 250, 290, "ONE HEAD PER DAY", C["amber"])
    for i, (label, col) in enumerate((("concat [h, s] · 132", C["grey"]), ("Linear 132 → 64", C["blue"]), ("ReLU", C["grey"]),
                                      ("Linear 64 → classes", C["blue"]), ("softmax → p(class)", C["green"]))):
        y = 290 - i * 44
        f.rect(204, y, 202, 28, col, rx=14)
        f.text(305, y + 18, label, 11.5, col, "middle", 700)
        if i:
            f.arrow(f"M305,{y + 42} L305,{y + 30}")
    f.text(305, 350, "class 0 benign, then each family", 10.5, C["muted"], "middle")
    f.text(305, 364, "trained on labelled training events", 10.5, C["muted"], "middle")
    f.arrow("M430,150 L470,150")
    # thresholds
    f.panel(472, 84, 330, 290, "THRESHOLD PER FAMILY", C["amber"])
    f.raw('<path d="M496,300 C530,300 540,160 580,150 C620,142 640,250 690,280 C720,292 760,296 780,298" fill="none" stroke="#3fb950" stroke-width="1.6"/>')
    f.raw('<line x1="496" y1="300" x2="784" y2="300" stroke="#6e7681"/>')
    f.raw('<line x1="742" y1="130" x2="742" y2="300" stroke="#e3b341" stroke-width="1.6" stroke-dasharray="5 3"/>')
    f.text(746, 126, "τ", 13, C["amber"], weight=700)
    f.raw('<path d="M742,296 L742,300 L784,300 L784,298 C770,297 755,296 742,295 Z" fill="#ff7b72" fill-opacity="0.5"/>')
    f.text(640, 150, "benign scores on", 11, C["green"], "middle")
    f.text(640, 164, "calibration rows", 11, C["green"], "middle")
    f.text(496, 318, "score of the family →", 10.5, C["muted"])
    f.text(490, 340, "τ per family = its benign quantile at the budget: 0.01%", 11, C["light"])
    f.text(490, 355, "(served), 0.1%, 1%, 5% · calibration = validation + 20% of", 11, C["light"])
    f.text(490, 370, "training kept back · test labels are never used", 11, C["light"])
    # alerts
    f.panel(822, 84, 358, 290, "FROM SCORES TO INCIDENTS", C["red"])
    f.text(836, 118, "one host, events over time; filled = above τ", 11, C["muted"])
    ticks = [0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0]
    for i, hit in enumerate(ticks):
        x = 846 + i * 24
        col = C["red"] if hit else C["grey"]
        fill = col if hit else "none"
        f.raw(f'<circle cx="{x}" cy="150" r="6" fill="{fill}" fill-opacity="0.7" stroke="{col}"/>')
    f.raw('<path d="M918,164 L918,184" stroke="#ff7b72" stroke-width="1.4" marker-end="url(#ah_ff7b72)"/>')
    f.text(926, 180, "3rd in a row → the host alerts", 11, C["light"])
    f.rect(846, 206, 150, 22, C["red"], rx=11)
    f.text(921, 221, "incident 1", 11, C["red"], "middle", 700)
    f.rect(1062, 206, 90, 22, C["red"], rx=11)
    f.text(1107, 221, "incident 2", 11, C["red"], "middle", 700)
    f.text(1029, 256, "quiet > 60 s", 10.5, C["muted"], "middle")
    f.raw('<path d="M1000,238 L1058,238" stroke="#8b949e" stroke-dasharray="3 3"/>')
    f.text(836, 290, "persistence: 3 consecutive events above τ", 11.5, C["light"])
    f.text(836, 308, "incident: alerts on one host with no quiet", 11.5, C["light"])
    f.text(836, 324, "gap longer than 60 s", 11.5, C["light"])
    f.text(836, 352, "models/serving/emitter.py", 10.5, C["muted"], mono=True)
    f.text(28, 420, "Decision, per family: an alert when its probability reaches its own threshold at the served 0.01% budget, "
                    "committed into the head as serve_threshold by the training script.", 12, C["light"])
    f.text(28, 442, "The checkpoint stores the weights, the input scaler, the family names, thresholds per budget and the committed "
                    "operating point.", 11.5, C["muted"])
    f.save("detector")


# =====================================================================================================================
def serving_live():
    f = Fig(1200, 480, "Lag forecast service (tag lag)",
            "each finished capture file starts one cycle over the latest 16 files; only flows that are certainly complete are used",
            "A capture writes a file every 30 seconds. Each cycle merges the latest 16 files, eight minutes, into one capture "
            "and ingests it with the training code. Flows that start in the first or last 120 seconds are dropped, because "
            "they may have begun before the window or may still be open; the rest are final, the same flows a whole-day ingest "
            "produces. The encoders, compressor and world model then run and answer GET /forecast. The state describes the "
            "network as of the newest packet minus 120 seconds, about 121 to 152 seconds ago, refreshed every 30 seconds.")
    x0, fw = 80, 64
    for i in range(16):
        x = x0 + i * fw
        edge = i < 4 or i >= 12
        col = C["grey"] if edge else C["green"]
        f.rect(x + 2, 150, fw - 4, 34, col, rx=5, dash=edge)
        f.text(x + fw / 2, 172, "30 s", 10.5, col, "middle")
    f.raw(f'<rect x="{x0 + 15 * fw + 2}" y="150" width="{fw - 4}" height="34" rx="5" fill="none" stroke="#e6edf3" stroke-width="2">'
          '<animate attributeName="stroke-opacity" values="0.2;1;0.2" dur="2s" repeatCount="indefinite"/></rect>')
    f.text(x0 + 15.5 * fw, 140, "newest file", 10.5, C["light"], "middle")
    f.raw(f'<path d="M{x0},122 L{x0},116 L{x0 + 16 * fw},116 L{x0 + 16 * fw},122" fill="none" stroke="#8b949e"/>')
    f.text(x0 + 8 * fw, 108, "window: the latest 16 files (8 min); every packet is parsed once, and one CICFlowMeter reads all files as one stream",
           11.5, C["light"], "middle")
    for a, b, lab in ((x0, x0 + 4 * fw, "first 120 s: a flow may have begun before the window"),
                      (x0 + 12 * fw, x0 + 16 * fw, "last 120 s: a flow may still be open")):
        f.raw(f'<path d="M{a},196 L{a},202 L{b},202 L{b},196" fill="none" stroke="#8b949e"/>')
        f.text((a + b) / 2, 218, lab, 10.5, C["muted"], "middle")
    f.raw(f'<path d="M{x0 + 4 * fw},196 L{x0 + 4 * fw},202 L{x0 + 12 * fw},202 L{x0 + 12 * fw},196" fill="none" stroke="#3fb950"/>')
    f.text(x0 + 8 * fw, 218, "complete flows: final, identical to a whole-day ingest", 11, C["green"], "middle", 700)
    # age marker
    nx = x0 + 16 * fw
    f.raw(f'<line x1="{nx}" y1="240" x2="{nx}" y2="268" stroke="#e6edf3"/>')
    f.text(nx, 284, "newest packet", 10.5, C["light"], "middle")
    sx = x0 + 12 * fw
    f.raw(f'<line x1="{sx}" y1="240" x2="{sx}" y2="268" stroke="#7ee787" stroke-width="2"/>')
    f.text(sx, 284, "state_as_of = newest − 120 s", 11, "#7ee787", "middle", 700)
    f.arrow(f"M{nx - 4},254 L{sx + 6},254", "#7ee787")
    f.text((sx + nx) / 2 + 150, 256, "", 1)
    f.text(28, 316, "How old the answer is: the newest packet is up to one file (30 s) old when that file closes, the hold is 120 s, "
                    "and a cycle takes some seconds,", 11.5, C["light"])
    f.text(28, 333, "so the forecast shows the network about 121–152 s ago, refreshed every 30 s. The payload says so: "
                    "source.state_as_of, source.lag_seconds.", 11.5, C["light"])
    # cycle
    steps = [("parse the new file", "tshark, once per file", C["grey"]), ("flow stream", "one CICFlowMeter, continuous", C["grey"]),
             ("complete flows", "started ≥ 120 s ago", C["green"]), ("encoders", "flow · context · compressor", C["purple"]),
             ("world model", "state + rollout", C["green"]), ("GET /forecast", "port 8901", "#7ee787")]
    for i, (a, b, col) in enumerate(steps):
        x = 28 + i * 192
        f.rect(x, 372, 170, 52, col)
        f.text(x + 85, 394, a, 12.5, col, "middle", 700)
        f.text(x + 85, 411, b, 10.5, C["muted"], "middle")
        if i:
            f.arrow(f"M{x - 20},398 L{x - 2},398", col)
    f.text(28, 452, "one cycle per finished capture file · capture with dumpcap -b duration:30 · the service itself needs no root",
           11, C["muted"])
    f.pulse(" ".join(f"M{28 + i * 192 - 20},398 L{28 + i * 192 - 2},398" for i in range(1, 6)), "#7ee787", 5)   # arrows only
    f.save("serving-live")


# =====================================================================================================================
def serving_tags():
    f = Fig(1200, 460, "Serving tags",
            "two inputs for the world model, served side by side; a forecast is useful only while its predictions are still ahead",
            "The lag tag reads capture files and uses only complete flows, so its state is about 150 s behind the wire. The "
            "live tag reads the detection stream, every flow 10 ms after its first packet, with a compressor and world model "
            "trained on the detection encoder's output, and is a few seconds behind. serving.json names each tag's models; "
            "resolve refuses a tag whose models are not trained. The table gives, for each attack, how often its next new "
            "target is still ahead when each tag serves.")
    f.box(28, 110, 220, 70, C["green"], "capture files", ["complete flows (120 s timeout)"])
    f.box(28, 250, 220, 70, C["blue"], "packet stream", ["every flow at first packet + 10 ms"])
    f.box(300, 110, 170, 70, C["green"], "tag: lag", ["forecasting encoder", "state ≈ 150 s behind"])
    f.box(300, 250, 170, 70, C["blue"], "tag: live", ["detection encoder", "state ≈ 1–4 s behind"])
    f.arrow("M248,145 L298,145", C["green"])
    f.arrow("M248,285 L298,285", C["blue"])
    f.panel(520, 84, 250, 270, "serving.json", C["light"])
    f.text(536, 124, "written by every training run", 11, C["muted"])
    f.text(536, 154, "lag  → its 4 models", 12, C["green"], mono=True)
    f.text(536, 176, "live → its 4 models", 12, C["blue"], mono=True)
    f.text(536, 214, "resolve(tag):", 12, C["light"], weight=700)
    f.text(536, 234, "models not trained", 11.5, C["light"])
    f.text(536, 250, "→ refused", 11.5, C["red"], weight=700)
    f.text(536, 272, "otherwise → the tag's models", 11.5, C["green"], weight=700)
    f.text(536, 312, "lag: GET :8901/forecast", 11, C["muted"], mono=True)
    f.text(536, 328, "live: GET :8902/forecast", 11, C["muted"], mono=True)
    f.arrow("M470,145 L518,170", C["green"])
    f.arrow("M470,285 L518,250", C["blue"])
    f.panel(790, 84, 390, 350, "IS THE NEXT TARGET STILL AHEAD?", C["purple"])
    f.text(806, 126, "per attack event: wait until its host first reaches", 11, C["muted"])
    f.text(806, 141, "a new target, against each tag's lag (event stream only)", 11, C["muted"])
    f.text(1030, 170, "live", 11, C["blue"], "end", 700)
    f.text(1152, 170, "lag", 11, C["green"], "end", 700)
    rows = [("Infiltration", "98.5%", "33.5%"), ("Bot", "100%", "98.3%"), ("DoS-GoldenEye", "100%", "96.6%"),
            ("DoS floods, web attacks", "stay on one target", "")]
    for i, (a, b, c) in enumerate(rows):
        y = 180 + i * 30
        f.rect(806, y, 358, 24, C["purple"], rx=5, width=1.1)
        f.text(818, y + 16, a, 11.5, C["light"])
        if c:
            f.text(1030, y + 16, b, 11.5, C["blue"], "end", 700)
            f.text(1152, y + 16, c, 11.5, C["green"], "end", 700)
        else:
            f.text(1152, y + 16, b, 11, C["muted"], "end")
    f.text(806, 322, "floods need no forecast: the detector flags them", 11, C["light"])
    f.text(806, 338, "within ~31 ms of each flow's first packet", 11, C["light"])
    f.text(806, 378, "inputs checked against training:", 11, C["muted"])
    f.text(806, 396, "lag  models.serving.parity", 11, C["muted"], mono=True)
    f.text(806, 412, "live tools/live/detect_check.py", 11, C["muted"], mono=True)
    f.text(28, 400, "measured for a trained world model: python -m tools.measure.forecast_lead --latents <day> --checkpoint <pt>",
           11, C["light"], mono=True)
    f.text(28, 420, "the lag tag was called delay; that name still resolves", 11, C["muted"])
    f.save("serving-tags")


# =====================================================================================================================
def publishing():
    f = Fig(1200, 470, "Publishing to Hugging Face",
            "one training run is staged as safetensors for the model repository and per-day tables for the dataset repository",
            "From one training run, each trained stage is converted to safetensors with a config file, checked bit-identical "
            "to the original checkpoint, and staged under artifacts/huggingface/model, every detector head included; epoch and resume files are skipped. The event "
            "tables and the model's per-event outputs are staged under artifacts/huggingface/dataset with one split per day. Both are "
            "uploaded with huggingface-cli; the dataset repository stays private and gated until its terms are checked.")
    f.panel(20, 84, 300, 360, "ONE RUN · artifacts/current or --bundle", C["light"])
    runs = [("b7/<stem>.pt", "flow encoder"), ("b8det/best.pt", "detection encoder"), ("b8/best.pt", "forecasting encoder"),
            ("record_encoder.pt", "record encoder"), ("b9/best.pt", "compressor"), ("b10/best.pt", "world model"),
            ("b9live/, b10live/", "live pair, if trained"), ("detector/head_<day>.pt", "every head")]
    for i, (a, b) in enumerate(runs):
        y = 124 + i * 24
        f.text(36, y, a, 11.5, C["light"], mono=True)
        f.text(304, y, b, 11, C["muted"], "end")
    f.text(36, 340, "events, node_index, flow_records,", 11.5, C["light"], mono=True)
    f.text(36, 358, "side_features, flow_embeddings,", 11.5, C["light"], mono=True)
    f.text(36, 376, "latents", 11.5, C["light"], mono=True)
    f.text(36, 400, "tables for the same days and run", 11, C["muted"])
    f.raw('<line x1="36" y1="318" x2="304" y2="318" stroke="#30363d"/>')
    f.box(370, 110, 260, 124, C["purple"], "convert each checkpoint",
          [".pt → <role>.safetensors", "+ <role>.config.json (names, widths,", "thresholds, scalers)",
           "every tensor checked bit-identical"])
    f.text(500, 256, "why: loading a .pt unpickles it and can run code", 10.5, C["muted"], "middle")
    f.box(370, 300, 260, 100, C["teal"], "stage the tables", ["one Hugging Face split per day", "card inventory regenerated",
                                                              "--include / --days for a part"])
    f.arrow("M320,200 L368,172", C["purple"])
    f.arrow("M320,360 L368,350", C["teal"])
    f.box(690, 96, 250, 170, C["amber"], "artifacts/huggingface/model", ["flow_encoder · context_encoder", "world_model_context_encoder",
                                                                "record_encoder · compressor · world_model", "detector (--detector-day) · detector_<day>",
                                                                "live_compressor · live_world_model",
                                                                "each: .safetensors + .config.json", "card, handler.py, inference.py"],
          mono_head=True)
    f.box(690, 290, 250, 120, C["teal"], "artifacts/huggingface/dataset", ["processed: events, node_index,", "flow_records, side_features",
                                                                  "model: flow_embeddings, latents", "gated · private first"],
          mono_head=True)
    f.arrow("M630,172 L688,176", C["amber"])
    f.arrow("M630,350 L688,350", C["teal"])
    f.rect(1000, 180, 176, 150, C["light"], rx=14)
    f.text(1088, 214, "Hugging Face Hub", 13, C["light"], "middle", 700)
    f.text(1088, 240, "huggingface-cli upload", 11, C["light"], "middle", mono=True)
    f.text(1088, 262, "model repository", 11, C["amber"], "middle")
    f.text(1088, 280, "dataset repository", 11, C["teal"], "middle")
    f.text(1088, 304, "check the licence first", 10.5, C["red"], "middle")
    f.arrow("M940,176 C962,176 962,230 984,230 L998,230", C["amber"])
    f.arrow("M940,350 C962,350 962,290 984,290 L998,290", C["teal"])
    f.text(28, 460, "back to .pt, bit-exact:  uv run python tools/publish/to_safetensors.py world_model.pt --to-pt world_model",
           11, C["muted"], mono=True)
    f.save("publishing")


# =====================================================================================================================
def training():
    f = Fig(1200, 520, "Training order",
            "stages run one at a time in the order numbered; each reads the frozen outputs before it · a finished stage is skipped on resume",
            "tools/train_all.sh trains the flow encoder and exports an embedding for every event; exports flow records and "
            "trains the record encoder; trains the detection encoder and the detector heads; trains the forecasting encoder, "
            "then the lag tag's compressor, latents, world model and calibration; then the live tag's compressor, latents, "
            "world model and calibration on the detection encoder; writes serving.json and the tolerance reports; records the "
            "run and promotes it to artifacts/current.")
    W, H = 140, 66
    col = [28, 200, 370, 540, 710, 880]
    f.box(col[0], 210, W, H, C["blue"], "① Flow encoder", ["fit 320k events/day", "10 epochs"])
    f.box(col[0], 360, W, H, C["green"], "② Flow records", ["and record encoder", "1,000 steps"])
    f.box(col[1], 100, W, H, C["purple"], "③ Detection encoder", ["event + summary", "5 epochs"])
    f.box(col[2], 100, W, H, C["amber"], "④ Detector heads", ["one head per day", "300 steps each"])
    f.box(col[1], 360, W, H, C["purple"], "⑤ Forecasting enc.", ["+ flow records", "5 epochs"])
    lag = [("⑥ Compressor", ["s → z (32)", "5 epochs"], C["teal"]), ("⑦ Latents", ["z for every event", "latents/"], C["teal"]),
           ("⑧ World model", ["on the latents", "5 epochs"], C["green"]), ("⑨ Calibration", ["served threshold", "budget 10⁻⁴"], C["amber"])]
    live = [("⑩ Compressor", ["on the detection", "encoder · 5 epochs"], C["teal"]),
            ("⑪ Latents", ["z for every event", "latents-live/"], C["teal"]),
            ("⑫ World model", ["on those latents", "5 epochs"], C["green"]), ("⑬ Calibration", ["served threshold", "budget 10⁻⁴"], C["amber"])]
    for i, (head, lines, color) in enumerate(lag):
        f.box(col[2 + i], 360, W, H, color, head, lines)
    for i, (head, lines, color) in enumerate(live):
        f.box(col[2 + i], 220, W, H, color, head, lines, dash=True)
    f.text(col[2], 208, "tag live: the world model on the detection encoder", 11, C["muted"])
    f.text(col[2], 348, "tag lag: the world model on the forecasting encoder", 11, C["muted"])
    f.box(1062, 150, 122, 90, C["light"], "⑭ Serving", ["serving.json", "lag and live", "tolerance reports"])
    f.box(1062, 300, 122, 90, C["light"], "⑮ Record", ["manifest.json", "promote to", "artifacts/current"])
    # Right-angle arrows that end in a straight run into the middle of a side: a steep curve in a 30 px gap reached the
    # box almost vertically and some viewers drew its head on the corner.
    f.arrow("M168,243 L174,243 Q180,243 180,237 L180,139 Q180,133 186,133 L198,133", C["blue"])
    f.arrow("M168,243 L174,243 Q180,243 180,249 L180,374 Q180,380 186,380 L198,380", C["blue"])
    f.arrow("M168,405 L198,405", C["green"])
    f.arrow("M340,133 L368,133", C["purple"])
    f.arrow("M270,166 L270,253 L368,253", C["purple"], dash=True)
    for i in range(3):
        x = col[2 + i] + W
        f.arrow(f"M{x},253 L{x + 28},253", C["grey"], dash=True)
        f.arrow(f"M{x},393 L{x + 28},393", C["grey"])
    f.arrow("M340,393 L368,393", C["purple"])
    f.arrow("M1020,253 L1026,253 Q1032,253 1032,247 L1032,206 Q1032,200 1038,200 L1060,200", C["grey"])
    f.arrow("M1020,393 L1036,393 Q1042,393 1042,387 L1042,231 Q1042,225 1048,225 L1060,225", C["grey"])
    f.arrow("M1123,240 L1123,298", C["grey"])
    f.text(28, 480, "each stage keeps best.pt, every epoch's model, resume.pt, history.csv and best_metrics.csv "
                    "(train / validation / test) in ~/netwatch-data/runs/<stamp>/", 11, C["muted"])
    f.text(28, 500, "RUN_DIR=<run> tools/train_all.sh resumes a run, or adds stages it does not have yet (⑩–⑬ on an older run)",
           11, C["muted"], mono=False)
    f.save("training")


# =====================================================================================================================
def serving_detect():
    f = Fig(1200, 560, "Fast live detection",
            "every flow scored 10 ms after its first packet, with the trained models unchanged",
            "Packets from an interface or dumpcap's stream go through tshark with ingest's field list, then a flow tracker "
            "with CICFlowMeter's rules. At first packet plus 10 ms each flow becomes an event: its packets so far, its host "
            "history and its sender. The flow encoder gives h, the detection encoder, streamed in training's 512-event "
            "batches with link memory and neighbours, gives s, and every detector head scores [h, s]; the alert rules turn "
            "scores into incidents, served at GET /detections. With --forecast the same stream feeds the live world model, "
            "served at GET /forecast. A verdict comes about 31 ms after a flow's first packet.")
    W, H, xs = 250, 80, [28, 313, 598, 883]
    f.box(xs[0], 96, W, H, C["blue"], "packets", ["an interface, or dumpcap's pcap stream", "IPv4 TCP and UDP"])
    f.box(xs[1], 96, W, H, C["blue"], "tshark", ["ingest's field list and options", "state reset every 250,000 packets"])
    f.box(xs[2], 96, W, H, C["green"], "flow tracker", ["CICFlowMeter's rules: a 5-tuple both ways,", "ends at a FIN or 120 s after its start"])
    f.box(xs[3], 96, W, H, C["green"], "the event, at t_obs", ["first packet + 10 ms (earlier at a FIN):", "packets seen, host history, sender"])
    f.box(xs[3], 226, W, H, C["blue"], "flow encoder", ["prepare → normalise → embed", "h = 32 numbers"])
    f.box(xs[2], 226, W, H, C["purple"], "detection encoder", ["512-event batches, link memory,", "neighbours, 20-packet summaries → s"])
    f.box(xs[1], 226, W, H, C["amber"], "detector heads", ["[h, s] = 132 numbers, one head per day", "threshold at the served budget"])
    f.box(xs[0], 226, W, H, C["red"], "GET :8902/detections", ["3 in a row per host → alert", "60 s quiet closes an incident"], mono_head=True)
    f.box(xs[2], 356, W, 70, C["green"], "live world model (--forecast)", ["compressor + world model over a window", "rebuilt every 5 s · 1–4 s behind"], dash=True)
    f.box(xs[1], 356, W, 70, C["green"], "GET :8902/forecast", ["tag live · the lag tag's payload"], dash=True, mono_head=True)
    for a, b in ((278, 311), (563, 596), (848, 881)):
        f.arrow(f"M{a},136 L{b},136", C["grey"])
    f.arrow("M1008,176 L1008,224", C["grey"])
    for a, b in ((883, 850), (598, 565), (313, 280)):
        f.arrow(f"M{a},266 L{b},266", C["grey"])
    f.arrow("M723,306 L723,354", C["green"], dash=True)
    f.arrow("M598,391 L565,391", C["green"], dash=True)
    # latency axis: 15 px per millisecond
    x0, y = 40, 486
    f.raw(f'<line x1="{x0}" y1="{y}" x2="{x0 + 15 * 50}" y2="{y}" stroke="#8b949e" stroke-width="1.2"/>')
    for ms, label, color in ((0, "first packet", C["light"]), (10, "t_obs: features cut", C["green"]),
                             (31, "verdict, median", C["amber"]), (47, "p99", C["amber"])):
        x = x0 + 15 * ms
        f.raw(f'<line x1="{x}" y1="{y - 6}" x2="{x}" y2="{y + 6}" stroke="{color}" stroke-width="2"/>')
        f.text(x, y - 12, label, 11, color, "middle" if ms else "start")
        f.text(x, y + 22, f"{ms} ms", 11, C["muted"], "middle" if ms else "start", mono=True)
    f.text(x0, 450, "LATENCY, measured on a capture paced in real time", 11, C["muted"], weight=700)
    f.text(840, 470, "throughput ~12,500 packets/s, ~2,400 flows/s,", 11, C["light"])
    f.text(840, 486, "on one CPU core", 11, C["light"])
    f.text(840, 510, "agreement with training:", 11, C["muted"])
    f.text(840, 526, "tools/live/detect_check.py", 11, C["muted"], mono=True)
    f.save("serving-detect")


if __name__ == "__main__":
    for make in (ingest, splits, joins, detector, serving_live, serving_tags, serving_detect, training, publishing):
        make()
    print("sources written:", ", ".join(p.stem for p in sorted(SRC.glob("*.svg"))))
