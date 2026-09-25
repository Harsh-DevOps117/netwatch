# Data Reference

Every column in the four Parquet artefacts, how to join them, and which parts of
XG-NID (Farrukh et al., 2024) are worth reusing.

Companion docs: [design.md](design.md) for how the pipeline works,
[LABELING_VERIFICATION.md](LABELING_VERIFICATION.md) for the validation record.

---

## The four files

Written per capture into `data/processed/<day>/<capture>/`.

| File | Grain | Rows (Friday-16-02) | Primary key |
|---|---|---:|---|
| `packets.parquet` | one packet | 98,369,227 | `frame_no` |
| `flows.parquet` | one flow | 10,144,299 | `flow_uid` |
| `edges.parquet` | one flow | 10,144,299 | (`flow_key`, `timestamp`) |
| `flow_packet_map.parquet` | one packet | 98,369,227 | `frame_no` |

Every timestamp is **UTC**. The attack schedule is UTC−4; only `LabelMatcher`
converts. See design.md §2.

---

## 1. `packets.parquet`

**Purpose.** Per-packet detail that flow aggregation destroys: exact timing,
per-packet flags, TTL, window size, and payload bytes. This is the only place
ICMP/IGMP traffic exists at all — CICFlowMeter emits no flows for it, so an ICMP
ping sweep is invisible at flow level.

| Column | Type | Meaning |
|---|---|---|
| `frame_no` | int64 | 1-based index in the **original** capture. Unique; join key to the map. |
| `timestamp` | double | UTC epoch seconds, microsecond precision |
| `src_ip`, `dst_ip` | string | endpoints (IPv4 or IPv6) |
| `src_port`, `dst_port` | int32 | 0 for non-TCP/UDP |
| `protocol` | int32 | 6 TCP, 17 UDP, 1 ICMP, 2 IGMP |
| `is_ipv6` | int8 | 1 if IPv6 |
| `length` | int32 | frame length in bytes |
| `ttl` | int32 | IPv4 TTL / IPv6 hop limit — spoofing and OS-fingerprint signal |
| `tcp_window` | int32 | TCP receive window, 0 for non-TCP |
| `tcp_flag_syn` | int8 | SYN set |
| `tcp_flag_ack` | int8 | ACK set |
| `tcp_flag_fin` | int8 | FIN set |
| `tcp_flag_rst` | int8 | RST set |
| `tcp_flag_psh` | int8 | PSH set |
| `tcp_flag_urg` | int8 | URG set |
| `payload_len` | int32 | **true** payload length before truncation |
| `payload` | binary | first `PAYLOAD_BYTES` (128) of transport payload |
| `flow_key` | string | canonical bidirectional 5-tuple |
| `Label` | string | attack name or `Benign` |
| `attack_name` | string | same as `Label` for attacks, `""` for benign |
| `label_source` | string | `attack_timeline` or `default` |
| `label_confidence` | string | `time_endpoint` or `none` |
| `label_direction` | string | `forward`, `reverse`, or `""` |

**Using it.** Per-packet features for the L1 encoder below. For payload as a
numeric vector:

```python
from ingest.sources.packets import payload_vector
import numpy as np
X = np.stack([payload_vector(bytes(p)) for p in df.payload])   # (n, 128) uint8
```

> Output written before payload existed has 23 columns instead of 25 and lacks
> `payload`/`payload_len`. Check the schema before assuming.

---

## 2. `flows.parquet`

**Purpose.** CICFlowMeter's 76 statistical features per flow, plus identity and
labels. This is the aggregate view — volume, rates, flag counts, IAT statistics.

### Identity and metadata (11)

| Column | Type | Meaning |
|---|---|---|
| `day` | string | dataset day, e.g. `Friday-16-02-2018` |
| `capture` | string | capture name |
| `flow_uid` | string | `<capture>#<row>` — **unique per flow** |
| `flow_key` | string | canonical 5-tuple — **not unique**, see §5 |
| `Flow ID` | string | CICFlowMeter's own directional id (unused) |
| `Src IP`, `Dst IP` | string | endpoints |
| `Src Port`, `Dst Port` | double | ports |
| `Protocol` | double | IP protocol number |
| `Timestamp` | string | `dd/MM/yyyy hh:mm:ss a`, **UTC**, one-second resolution |

### CICFlowMeter features (76, all `double`)

| Family | Columns |
|---|---|
| Volume | `Flow Duration`, `Tot Fwd Pkts`, `Tot Bwd Pkts`, `TotLen Fwd Pkts`, `TotLen Bwd Pkts` |
| Packet length | `Fwd Pkt Len Max`, `Fwd Pkt Len Min`, `Fwd Pkt Len Mean`, `Fwd Pkt Len Std`, `Bwd Pkt Len Max`, `Bwd Pkt Len Min`, `Bwd Pkt Len Mean`, `Bwd Pkt Len Std`, `Pkt Len Min`, `Pkt Len Max`, `Pkt Len Mean`, `Pkt Len Std`, `Pkt Len Var`, `Pkt Size Avg` |
| Rates | `Flow Byts/s`, `Flow Pkts/s`, `Fwd Pkts/s`, `Bwd Pkts/s` |
| Inter-arrival | `Flow IAT Mean`, `Flow IAT Std`, `Flow IAT Max`, `Flow IAT Min`, `Fwd IAT Tot`, `Fwd IAT Mean`, `Fwd IAT Std`, `Fwd IAT Max`, `Fwd IAT Min`, `Bwd IAT Tot`, `Bwd IAT Mean`, `Bwd IAT Std`, `Bwd IAT Max`, `Bwd IAT Min` |
| Flag counts | `FIN Flag Cnt`, `SYN Flag Cnt`, `RST Flag Cnt`, `PSH Flag Cnt`, `ACK Flag Cnt`, `URG Flag Cnt`, `CWE Flag Count`, `ECE Flag Cnt`, `Fwd PSH Flags`, `Bwd PSH Flags`, `Fwd URG Flags`, `Bwd URG Flags` |
| Header / segment | `Fwd Header Len`, `Bwd Header Len`, `Fwd Seg Size Avg`, `Bwd Seg Size Avg`, `Fwd Seg Size Min` |
| Bulk | `Fwd Byts/b Avg`, `Fwd Pkts/b Avg`, `Fwd Blk Rate Avg`, `Bwd Byts/b Avg`, `Bwd Pkts/b Avg`, `Bwd Blk Rate Avg` |
| Subflow | `Subflow Fwd Pkts`, `Subflow Fwd Byts`, `Subflow Bwd Pkts`, `Subflow Bwd Byts` |
| Window / activity | `Init Fwd Win Byts`, `Init Bwd Win Byts`, `Fwd Act Data Pkts` |
| Active / idle | `Active Mean`, `Active Std`, `Active Max`, `Active Min`, `Idle Mean`, `Idle Std`, `Idle Max`, `Idle Min` — **not model features**: Idle holds the flow's absolute epoch time on about half of flows and Active is always 0 (design.md, *What must never become a feature → Clock*) |
| Ratio | `Down/Up Ratio` |

### Labels (5)

`Label`, `attack_name`, `label_source`, `label_confidence`, `label_direction` —
same semantics as packets.

**Using it.** The flow-node feature vector for L1. Drop identity columns before
training (see §6 warnings). CIC CSVs contain literal `Infinity`/`NaN` in rate
columns; they survive as float `inf`/`nan` and must be clipped or imputed.

---

## 3. `edges.parquet`

**Purpose.** `flows.parquet` reduced to graph shape, with the timestamp already
converted to epoch seconds so it shares a clock with `packets.timestamp`. One row
per flow = one edge per conversation segment. This is the input to the host-graph
layer.

| Column | Type | Meaning |
|---|---|---|
| `timestamp` | double | UTC epoch seconds (flow start) |
| `flow_key` | string | canonical 5-tuple |
| `src_ip`, `dst_ip` | string | edge endpoints |
| `src_port`, `dst_port` | int32 | ports |
| `protocol` | int16 | protocol number |
| `duration` | double | flow duration in **microseconds** |
| `fwd_packets`, `bwd_packets` | double | packet counts per direction |
| `label`, `attack_name`, `label_source`, `label_confidence`, `label_direction` | string | labels (note: lowercase `label` here) |

**Using it.** Build the per-window host graph: nodes are IPs, edges are the rows
whose `[timestamp, timestamp + duration/1e6]` overlaps the window.

It carries no `flow_uid`, so join back to `flows` on `flow_key` + `timestamp`
when you need the full feature vector.

---

## 4. `flow_packet_map.parquet`

**Purpose.** The bridge between the two granularities. Exactly one row per
packet.

| Column | Type | Meaning |
|---|---|---|
| `frame_no` | int64 | joins to `packets.frame_no` |
| `flow_uid` | string | joins to `flows.flow_uid`; **null** when no flow contains the packet |
| `flow_key` | string | the shared 5-tuple |

**Using it.** This is the only correct way to attach packets to flows — see §5.

```python
from ingest.build.join import load_joined
df = load_joined(Path("data/processed/<day>/<capture>"))
# packet columns + flow columns, suffixed _pkt / _flow on collisions
```

Roughly 97–99% of packets map. The unmapped remainder is ICMP/IGMP (no flow
exists) and capture-edge fragments; they keep a null `flow_uid` rather than being
dropped.

---

## 5. Joining — and the one trap

**`flow_key` is not unique.** CICFlowMeter closes a flow on FIN or timeout and
reopens the same 5-tuple, so one key routinely names several flows — 14,039 of
14,040 keys in one measured capture.

```python
# WRONG: many-to-many, inflates rows, attributes packets to the wrong flow
packets.merge(flows, on="flow_key")

# RIGHT: the map already resolved it with an interval join
packets.merge(flow_packet_map, on="frame_no").merge(flows, on="flow_uid")
```

Measured on the map: one row per packet, `frame_no` unique, every `flow_uid`
resolves, **100.00% label agreement** between a packet and its mapped flow.

### Direction is ambiguous, labels are not

Same-key flows overlap in time because CICFlowMeter emits a forward *and* a
reverse biflow per conversation. Consequences, measured:

| | Result |
|---|---|
| Same-key flows sharing one `Label` | **100%** — a packet cannot be mislabelled |
| Same-key flows sharing one `label_direction` | 49.6% on attack traffic |

So: **labels through the join are exact**; `label_direction` and per-flow
*features* are ambiguous for about half of attack conversations. Take direction
from the packet's own `src_ip`/`dst_ip`, and treat joined flow statistics as
conversation-level rather than direction-level.

### Identifying the reverse record

Four questions with four different answers, all measured on real Friday captures:

| Question | Rule | Measured |
|---|---|---|
| Which way did *this packet* go? | packet `(src_ip, src_port)` equals record `(Src IP, Src Port)` → forward, else backward | exact, by definition |
| Is *this record* client → server? | its first packet is a bare SYN (`syn=1, ack=0`); the SYN sender is the client | ground truth for 72.7% of TCP flows; 4.0% of records holding the SYN are oriented server → client |
| Same, when there is no SYN | ephemeral → service port (`Src Port > Dst Port`) | agrees with the SYN 95.9% where both exist; unverifiable on the other 27.3% |
| Which record is the *twin*? | same `flow_key`, endpoints swapped | 40.0% of same-key pairs are twins, the rest later same-direction segments; the reverse twin holds ≤ 2 packets in 79.9% of pairs |

For attack flows `label_direction` already says `forward` (attacker → victim on
the service port) or `reverse` (the victim's reply record). It is set only where
a labelling rule matched, so it is the label under another name: use it to
filter or analyse, never as a model input. On Friday, Hulk is 1,750,476 forward
and 1,765,956 reverse; SlowHTTPTest is forward only. Hulk reuses about 14,000 source ports, opening a new connection on each roughly
every 5 s, so its 3,516,432 records sit on only 14,116 keys (about 249 each), and
every one of those keys holds both directions.

The SYN rule needs `tcp_flag_syn`. Output written before change-log entry 5m has
every TCP flag at 0 and cannot use it.

`events.parquet` carries both rules as `reversed`: 1 server → client, 0 client →
server, −1 when neither applies (no SYN and equal ports, e.g. ICMP). It is built
from packets and ports only, so unlike `label_direction` it is safe as a model input.
On a 10 s DoS-Hulk slice, `reversed == 1` matched `label_direction == "reverse"`
on 100.00% of 26,970 attack events. For Hulk the attacker opens every connection,
so reversed is victim → attacker; for Bot, where the victim dials out to its C2
server, the two differ by design.

For the L1 encoder, group on **`flow_uid`**. `flow_packet_map` holds exactly one
row per packet, so `flow_uid` partitions the packets: none lost, none duplicated.
Do **not** group on `flow_key` — it is not unique, so it merges time-separated
segments (41.4% of keys name more than one flow, spans up to 722 s), and
disambiguating with a time bucket would reintroduce fixed windows on the
event-based path. The forward/reverse ambiguity above affects direction and
feature attribution, not packet completeness.

---

## 5b. How many features does each file actually give you?

Column count is not feature count. Identity columns are joins, endpoint columns
are graph *structure*, and ports leak the label on this dataset.

| File | Cols | ID/join | Structure | Leaky | Label | **Usable features** |
|---|---:|---:|---:|---:|---:|---:|
| `packets.parquet` | 25 | 3 | 2 | 2 | 5 | **13** (or 11 + 128 payload) |
| `flows.parquet` | 92 | 6 | 2 | 2 | 5 | **77** |
| `edges.parquet` | 15 | 2 | 2 | 2 | 5 | **4** |
| `flow_packet_map.parquet` | 3 | 3 | 0 | 0 | 0 | **0** — pure join table |

**packets (13):** `protocol`, `length`, `ttl`, `is_ipv6`, `tcp_window`, the six
`tcp_flag_*`, `payload_len`, and `payload`. Expanding `payload` through
`payload_vector()` turns the last one into 128 `uint8` columns, giving **11 + 128**
if you want the byte-level view, or keep `payload_len` alone as a scalar summary.

**edges (4):** `protocol`, `duration`, `fwd_packets`, `bwd_packets`. This is
deliberately thin — `edges.parquet` carries graph *structure* and timing, not
rich features. Attach those from `flows` via `flow_key` + `timestamp`.

**flows (77):** the 76 CICFlowMeter features plus `Protocol`.

- *Structure* = `src_ip` / `dst_ip`: graph topology, never a model input.
- *Leaky* = ports: on Friday every attack is on port 21 or 80, so a model given
  raw `Dst Port` learns the port, not the behaviour. Bucket them
  (well-known / registered / ephemeral) or drop them.

---

## 6. Reusing XG-NID

XG-NID does **graph-level classification** on CIC-IoT2023 and contains no
forecasting, no state transitions, and no MITRE mapping. Its dual-modality result
was never demonstrated on a CIC-IDS dataset — on CIC-IDS2017 the authors fell
back to flow-only, because those PCAPs are unlabelled.

So it is not a replacement. But its **packet→flow encoder is directly reusable**,
and it is the piece you would otherwise have to invent.

### Take: the heterogeneous per-flow subgraph (L1)

Their structure, mapped onto our columns:

| Their element | Build it from |
|---|---|
| flow node `h_vf` | the 76 CICFlowMeter feature columns |
| packet nodes `h_vp` | up to K packets via `flow_packet_map` |
| packet features | `length`, `ttl`, `tcp_window`, 6 `tcp_flag_*`, `payload_len`, `payload_vector(payload)` |
| `contain` edge (flow → packet) | direction, layer size |
| `link` edge (packet_i → packet_{i+1}) | Δt between consecutive `timestamp` |

Order packets by `frame_no`. Set **K = 20** — our data independently confirms
their choice:

```
packets per flow:  p50=8  p75=13  p90=19  p95=29  p99=58
91.9% of flows have <= 20 packets;  96.4% have <= 32
```

Output: one embedding `h_f` per flow.

### Take: the sliding-window temporal features

Their "explainable feature extractor" tracks rolling statistics per destination
host across *previous* flows (they tune the window to 350–400). This captures
repeated scanning from one source — reconnaissance — which no single flow shows.
Cheap to compute from `edges.parquet` and directly useful.

### Take: the explainability stack

GNNExplainer + Integrated Gradients + SHAP, then a language model to render it.
Your PS requires interpretable output; this is a sound template, and the
attribution runs over the same flow/packet features you already have.

### Change: four things

| Their choice | Ours | Why |
|---|---|---|
| Payload → ℝ¹⁵⁰⁰ | `payload_vector(p, 128)` | 1500 × 98M packets ≈ 100 GB. 128 B covers the HTTP request line where SQLi/XSS appear. |
| 120 s idle timeout, flow capped | Keep the 20-packet cap, **not** a duration cap | The PS targets slow reconnaissance built to evade flow thresholds — a duration cap truncates exactly those. |
| Labels from attacker MAC | `LabelMatcher` | CIC-IDS2018 has no attacker MAC. Ours is time + IP + service port, verified against Table 2 and the official CSV. |
| Graph-level classification | L1 as encoder only | Classification is what the PS says to move beyond. |

### Add: the two levels they do not have

Their graph has no host nodes and no inter-flow edges, so lateral movement and
attacker progression cannot be expressed in it at all.

```
L1  packets ──contain/link──> flow embedding h_f      ← XG-NID, reused
L2  hosts ──edges = flows in window t──> host graph   ← edges.parquet
L3  S_t sequence ──> P(S_t+1 | S_t) ──> K-step rollout
```

**L2** — nodes are hosts; edges are flows active in window *t* with `h_f` as the
edge feature; node features are per-host aggregates in that window (distinct
peers, distinct ports, SYN rate, bytes in/out). Fan-out patterns live here.

**L3** — `S_t` is the pooled host graph at window *t*. Train `P(S_t+1 | S_t)`
self-supervised on state transitions; labels are the *evaluation* target, not the
training target. Roll out K steps for infiltration probability, with a small
supervised head for MITRE stage.

### Two warnings before training

**Do not feed identity.** No `src_ip`, `dst_ip`, `capture`, `flow_uid`, or raw
`Dst Port` as features. Every Friday attack flow sits in one capture, from two
attacker IPs, on ports 21/80 — a model given those learns the identity and
reports a meaningless F1. Bucket ports; use IPs as graph *structure* only.

**Filter bad timestamps before binning.** About 1,000 flows carry 1970-01-01
epochs (0.01%). Harmless for labels, fatal for time windows.
