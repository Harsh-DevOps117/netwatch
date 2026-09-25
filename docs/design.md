# Architecture

Block-by-block design of the system, from raw packet capture to the world model and the demo. Each block states
its **purpose**, the **code** that implements it, its **input** and **output**, the **transformation**, and the
**checks** it must pass.

**Statuses current as of 2026-09-20**, with the full measured position in [STATUS_2026-09-20.md](STATUS_2026-09-20.md).

**Statuses current as of 2026-09-20.** Blocks 8 and 9 are trained, Block 10 exists as a measured proxy, and Blocks
11–14 do not exist. Results, acceptance criteria for the real Block 10, and a symptom→cause diagnostic table are in
[BLOCK10_PROXY_RESULTS.md](BLOCK10_PROXY_RESULTS.md); what the world model receives is in
[WORLD_MODEL_INPUTS.md](WORLD_MODEL_INPUTS.md).

This document is the design only. Experiment evidence — every measurement, comparison and rejected alternative —
lives in [TESTS.md](TESTS.md). The previous version with that evidence inline is kept as
[design_full_2026-09-15.md](design_full_2026-09-15.md).

Companion documents: [data-reference.md](data-reference.md) for every column,
[LABELING_VERIFICATION.md](LABELING_VERIFICATION.md) for the labelling record,
[model_io_contract.json](model_io_contract.json) for the handoff between the two halves of the team
(current: [model_io_contract_v2.9.json](model_io_contract_v2.9.json)).

**Everything is event-based.** One event is one flow, timestamped at its first packet. Nothing on the main path bins
time into fixed windows; the only windowed artefact is Appendix A, which is not part of the system.

---

## System map

```
PCAP ─► B1 packets.parquet ─┐
     └► B2 flows.parquet ───┼─► B3 labels (on flows and packets)
                            ├─► B4 edges.parquet
                            └─► B5 flow_packet_map.parquet
                                          │
                     B6 events.parquet + node_index.parquet
                                          │
                     B7 per-flow encoder ─► flow_embeddings.parquet  (h_f per event)
                                        └─► alerts (supervised multi-class family classifier)
                                          │
                     B8 event context encoder (link memory h_uv) ─► s_uv(t) per event
                                          │
                     B9 graph autoencoder ─► event_latents.parquet (z, recon_error)
                                          │
                     B10 world model ─► state S_t, H-event rollout, forecasts
                                          │
             B11 explainability · B12 MITRE stages · B13 baselines · B14 demo
```

**What the system is optimised for (2026-09-19).** The product is the **world model**: Block 10 identifying attacks
and network state quickly and correctly over its $H$-step rollout. Blocks 7, 8 and 9 exist to **build its input**, so
a representation change is judged by what it does for rollout, not only by per-flow scores. Per-flow known-family
detection is a component and a diagnostic — necessary, not sufficient.

**Objective on the detection arm:** maximise **recall at a low false-positive rate**. The alert must fire; suppressing
the false positives that a recall-first threshold admits was specified as **Block 9's job** (autoencoders are used for
FPR reduction in the literature) — but measured on 2026-09-20 the gate does nothing on either arm (7 of 8 supervised
cells unchanged; on Block 10 it buys 4 false alarms and costs 8 early positives), because the threshold already does
that job. **The false-positive lever that works is the operating point**: moving the threshold from a 1% budget to
1e-4 cut Block 10's false alarms 105×, per-host incident aggregation a further 3.6×, and a three-event persistence
requirement another 2× at no cost to early recall. So a family with high recall and poor precision is *not* a failure — it is
work handed to Block 9. Precision gained on top is a **bonus**, welcome but never traded against recall.

**Alert timing:** alerting before the attack finishes is the best outcome; some flows end inside the 10 ms budget, and
for those nothing at the model level can beat it, so the rule is *alert as early as possible and report lead time*.
The primary catch is expected at Block 10's rollout, not at the single flow.

| Block | Purpose | Input | Output | Status |
|---|---|---|---|---|
| 0 Raw capture | the dataset as distributed | — | PCAPs per monitored host | given |
| 1 Packet extraction | per-packet detail | one PCAP | `packets.parquet` | built |
| 2 Flow extraction | per-conversation statistics | one PCAP | `flows.parquet` | built |
| 3 Labelling | ground truth from the attack schedule | flow / packet records + rules | 5 label columns | built |
| 4 Graph edges | flows as timestamped edges | `flows.parquet` | `edges.parquet` | built |
| 5 Flow ↔ packet alignment | which flow each packet belongs to | `flows`, `packets` | `flow_packet_map.parquet` | built |
| 6 Event stream | the continuous-time event graph | `flows`, `packets`, `flow_packet_map` | `events.parquet`, `node_index.parquet` | built |
| 7 Per-flow encoder | one vector per flow, early; per-flow alerts | `events`, `flows`, `packets`, `flow_packet_map` | `flow_embeddings.parquet`, alert scores | built |
| 8 Event context encoder | network context per event | `flow_embeddings`, `events` | $s_{u,v}(t)$ per event, link memory | **built, trained** |
| 9 Graph autoencoder | compress each contextual event | $s_{u,v}(t)$ | `event_latents.parquet` | **built, trained** |
| 10 World model | dynamics and rollout | `event_latents` + manifest, `node_index` (+ memory) | $S_t$, forecasts | **proxy built and measured** (teammate to replace) |
| 11 Explainability | why a prediction was made | predictions + events | ranked driving features | specified |
| 12 MITRE stage mapping | kill-chain stage | $S_t$, rollout | stage probabilities | specified |
| 13 Baseline and benchmark | logistic regression and counters | Block 7's feature tensor | F1 / precision / recall / FPR | specified — **nothing built; every number in TESTS.md is unanchored without it** |
| 14 Demonstration interface | offline end-to-end demo | PCAP or CIC CSV | timeline, flagged flows, stages | specified |

Days ingested: Friday-16-02-2018, Friday-02-03-2018, Friday-23-02-2018, Thursday-15-02-2018, Thursday-01-03-2018.

---

## Notation

| Symbol | Meaning |
|---|---|
| $\mathcal{P} = (p_1,\dots,p_N)$ | packets of one capture |
| $\mathcal{F}$ | flows (bidirectional conversation segments) |
| $\mathcal{E} = (e_1,\dots,e_L)$ | events: temporal occurrences of flows, globally ordered |
| $\mathcal{V}$; $u, v$ | hosts; source and destination |
| $t$ / $\tau$ | UTC epoch seconds / schedule-local time (UTC−4) |
| $\kappa(\cdot)$, $\upsilon(\cdot)$, $\mu(\cdot)$ | canonical flow key, unique flow id (`flow_uid`), packet → flow assignment |
| $\ell(\cdot)$ | label |
| $\Phi(\cdot)$ | Bochner time encoder |
| $\mathbf{x}_f \in \mathbb{R}^{68}$ | CICFlowMeter statistics (76 less the 8 Active/Idle columns) |
| $\mathbf{a}_f \in \mathbb{R}^{20}$ | packet aggregates over the first $K$ packets |
| $\mathbf{h}_f \in \mathbb{R}^{32}$ | Block 7 flow embedding |
| $s_{u,v}(t)$, $h_{u,v}$ | Block 8 contextual event representation, link memory |
| $\mathbf{z}$ | Block 9 latent |
| $t^{*}_f$, $t_{\text{obs}}$ | flow start (event time), observation time |
| $K = 20$, $S = 20$, $H$ | packets per flow, sampled neighbours, rollout horizon in events |

---

## Cross-cutting rules

### Two clocks per event

$$
t^{*}_f = \min\{t_p : \mu(p) = \upsilon(f)\} \quad \text{(event time — arrival)}, \qquad
t_{\text{obs}} = \min\big(t^{*}_f + \delta,\ t^{\text{end}}_f\big) \quad \text{(observation time — availability)}
$$

- **Event time** orders the stream and gives identity, $\Delta t^{\text{src}}$, $\Delta t^{\text{dst}}$ and
  neighbourhood membership. It is known the moment the first packet arrives.
- **Observation time** is when anything *derived* from the flow ($\mathbf{a}_f$, packets, $\mathbf{h}_f$, alerts)
  exists. $\delta = 10$ ms.
- **Availability rule.** Event $j$'s representation may affect anything at time $t$ only if $t_{\text{obs},j} \le t$.
  It applies to attention neighbourhoods **and** to recurrent state, and alarms may never precede $t_{\text{obs}}$.

### Observation modes — every result carries one

| Mode | Reads | Valid for |
|---|---|---|
| `offline_full` | $\mathbf{x}_f$ + $\mathbf{a}_f$ + all $K$ packets, after the flow ends | detection and forensics after the fact |
| `online_prefix` | $\mathbf{a}_f(t_{\text{obs}})$ + packets with $t_p \le t_{\text{obs}}$; $\mathbf{x}_f$ refused | early warning; the only mode that may claim lead time |

### Two populations — never pooled

| Population | Condition | Meaning |
|---|---|---|
| `early_observation` | flow still running at $t_{\text{obs}}$ | early warning is possible |
| `completed_before_budget` | flow ended before $t^{*}_f + \delta$ | detection, not forecasting |

### What must never become a feature

| Family | Columns | Why |
|---|---|---|
| Identity | `src_ip`, `dst_ip`, `src_port`, `dst_port`, `capture`, `flow_uid`, `day`, `flow_key` | identifies the attack instead of describing behaviour; IPs reach models only as node indices |
| Labels | `Label`, `attack_name`, `label_source`, `label_confidence`, `label_direction` | evaluation only. `label_direction` is non-empty exactly on attack rows, so it *is* the label |
| Clock | `t`, `Timestamp`, `event_id`, `Active *`, `Idle *` | absolute time locates the attack window; this CICFlowMeter build writes epoch time into `Idle *` |
| Host location | `ttl` in packets and aggregates (blanked) | reports hop distance, not behaviour |

`models/data/inputs.py::check_features` fails closed (raises) if any forbidden column reaches a tensor. Direction
comes from the packet's own endpoints or `reversed`, never from `label_direction`. Raw ports never leave Block 6;
only `port_delta` and `dst_port_new` are exported.

### Data discipline

- **Normalisation** is fitted in the model layer on **benign training rows only**, never during extraction.
- **Autoencoders train on benign rows only**; no rebalancing anywhere.
- **Splits** are temporal, per segment (an attack's observed extent or a benign stretch), with a 120 s embargo;
  evaluation is leave-one-day-out, test rows only.
- **Deduplication** is only for fitting a supervised readout; never for autoencoder training, thresholds,
  evaluation, exports, or anything from Block 8 onward — repetition is the signal.
- **Labels** are evaluation targets and never enter a loss (except the explicitly supervised classifier arm).

---

## Block 0 — Raw capture

**Purpose.** The input to everything: CSE-CIC-IDS2018 as distributed.

**Code / location.** `data/raw/<day>/pcap/` — read-only.

**Input.** —

**Output.** One PCAP per monitored host per day.

**Transformation.** Captures are **selected by content**, not by name: a file is a capture when it starts with a
pcap or pcapng header and its first packet falls on the day in schedule-local time. Every rejected file is reported
with its reason.

**Checks.** Every accepted file is a readable capture of the right day; truncated captures keep their readable
prefix; `capture_name()` keeps a trailing IP octet (it is not an extension).

---

## Block 1 — Packet extraction

**Purpose.** Recover the per-packet detail flow aggregation discards: exact timing, flags, TTL, window, payload.

**Code.** `ingest/sources/packets.py`

**Input.** One PCAP.

**Transformation.** tshark projects each packet onto a fixed field set,

$$
\pi(p_i) = \big(t_i,\ u_i,\ v_i,\ \text{sport}_i,\ \text{dport}_i,\ \text{proto}_i,\ \text{len}_i,\ \text{ttl}_i,\
\text{win}_i,\ \mathbf{g}_i,\ \text{plen}_i,\ \mathbf{b}_i\big)
$$

with TCP flags $\mathbf{g}_i \in \{0,1\}^6$ and payload $\mathbf{b}_i$ truncated to 128 bytes. The capture is split
once into chunks of $C = 250{,}000$ packets (memory $O(C)$), and frame numbers are rebased onto the original capture.
Each packet is labelled by Block 3.

**Output.** `packets.parquet`: one row per packet (29 columns).

**Checks.** `frame_no` unique and monotonic; payload taken from `tcp.payload`; TCP flags parsed from tshark's
boolean output.

---

## Block 2 — Flow extraction

**Purpose.** Per-conversation statistics — the classical NIDS feature view.

**Code.** `ingest/sources/flows.py` (`run_cicflowmeter`, `csv_to_parquet`)

**Input.** One PCAP.

**Transformation.** CICFlowMeter groups packets into bidirectional flows and computes 76 statistics. Each flow gets
a canonical key and a unique id:

$$
\kappa(f) = [\min(a,b)] \,\|\, [\max(a,b)] \,\|\, \text{proto}, \quad a = (u,\text{sport}),\ b = (v,\text{dport});
\qquad \upsilon(f) = \texttt{<capture>\#<row>}
$$

$\kappa$ is **not injective** — CICFlowMeter closes and reopens the same 5-tuple — which is why Block 5 exists.
Each flow is labelled by Block 3.

**Output.** `csv/*_Flow.csv` → `flows.parquet`: 11 identity + 76 feature + 5 label columns.

**Checks.** CSV rows equal Parquet rows; `flow_uid` unique; one flow CSV per capture; `Infinity` / `NaN` literals
become float values.

---

## Block 3 — Labelling

**Purpose.** Attach ground truth from the published attack schedule. The only block that decides what is an attack.

**Code.** `ingest/sources/config.py` (rules), `ingest/sources/flows.py::LabelMatcher` (logic)

**Input.** A flow or packet record, and the day's rules $\mathcal{R}_d$.

**Transformation.** A rule is $r = (\alpha_r, d_r, [\tau^{\text{start}}_r, \tau^{\text{end}}_r], \mathcal{U}_r,
\mathcal{W}_r, \Pi_r, \Sigma_r, c_r)$ — name, day, window, attacker and victim IPs, optional protocols and service
ports, confidence tag. Stored time is UTC; the schedule is local, so $\tau = t - 4$ h in memory only. A record matches
when

$$
\text{date}(\tau) = d_r \ \wedge\ \tau^{\text{start}}_r \le \text{time}(\tau) \le \tau^{\text{end}}_r \ \wedge\
\text{proto} \in \Pi_r \ \wedge\ (\text{fwd} \vee \text{rev})
$$

$$
\text{fwd} = (u \in \mathcal{U}_r) \wedge (v \in \mathcal{W}_r) \wedge (\text{dport} \in \Sigma_r), \qquad
\text{rev} = (u \in \mathcal{W}_r) \wedge (v \in \mathcal{U}_r) \wedge (\text{sport} \in \Sigma_r)
$$

(empty $\Pi_r$ or $\Sigma_r$ = unconstrained). Victim replies are labelled too, marked `reverse`. Rules of one attack
may share a boundary — the earlier rule keeps the row; rules of different attacks may not overlap (raises).

Table 2 of the dataset gives the windows (`time_endpoint`). Tagged rules extend them where the traffic shows the
attack outside the table's windows:

| Tag | Day | Rule |
|---|---|---|
| `c2_heartbeat_between_table_windows` | Friday-02-03 | Bot C2 polling between the table's two Bot windows |
| `attack_tail_after_table_window` | Thursday-15-02 | DoS-Slowloris connections continuing to 11:42:01 |
| `internal_scan_from_compromised_host` | Thursday-01-03 | the compromised victim scanning internal hosts inside the Infiltration windows |

A new rule invalidates only its own day's processed output (per-day fingerprint `label_config_version`).

**Output.** On flows and packets: `Label`, `attack_name`, `label_source`, `label_confidence`, `label_direction`.

**Checks** (`python -m ingest.verify <day>`, non-zero exit on failure). Measured UTC offset equals the configured
one; no labelled row outside its windows; attack-shaped flows outside every window are reported; packet label equals
its flow's label; counts cross-checked against CIC's labelled CSV where it is complete (it lacks IPs, is truncated
on some days and uses a 12-hour clock, so it is a cross-check, not ground truth).

---

## Block 4 — Graph edges

**Purpose.** Flows as timestamped edges with a numeric clock.

**Code.** `ingest/build/join.py::build_edges`

**Input.** `flows.parquet`.

**Transformation.** $\eta(f) = (t_f, \kappa(f), u, v, \text{sport}, \text{dport}, \text{proto}, \text{dur},
n^{\text{fwd}}, n^{\text{bwd}}, \ell(f))$, with $t_f$ the parsed timestamp read as UTC. Each row is a temporal
occurrence, not a distinct relationship.

**Output.** `edges.parquet`: one row per flow (15 columns).

**Checks.** Edge rows equal flow rows; epochs are UTC on a non-UTC host; no NaN timestamps.

---

## Block 5 — Flow ↔ packet alignment

**Purpose.** Attribute each packet to exactly one flow, so flows and packets can be used together.

**Code.** `ingest/build/join.py::build_flow_packet_map`

**Input.** `flows.parquet`, `packets.parquet`.

**Transformation.** An interval join, not a key join. Packet $p$ belongs to flow $f$ when

$$
\kappa(p) = \kappa(f) \ \wedge\ t_f \le t_p \le t_f + \text{dur}_f + s, \qquad s = 1\ \text{s}
$$

Among candidate flows of the key starting at or before $t_p$, the latest start wins and ties go to the widest window;
a packet the chosen window does not cover is retried against every window of its key; a packet in no window maps to
no flow. Implemented as a streamed `merge_asof` on int32 key codes.

**Output.** `flow_packet_map.parquet`: `frame_no`, `flow_uid`, `flow_key` — one row per packet.

**Checks.** Map rows equal packet rows; every `flow_uid` resolves; packet label equals mapped flow label; time
containment holds; the retry changes no existing attribution. Direction and joined flow statistics are
conversation-level (forward and reverse biflows share a key), so direction is taken from the packet itself.

---

## Block 6 — Event stream

**Purpose.** The continuous-time event graph the models consume. The last block without torch.

**Code.** `ingest/build/events.py` (`python -m ingest.build.events <day>`)

**Input.** All captures of one day: `flows`, `packets`, `flow_packet_map`.

**Transformation.**

| Step | Rule |
|---|---|
| (a) Timestamp correction | $t^{*}_f = \min_{p:\mu(p)=\upsilon(f)} t_p$ — first packet, replacing CICFlowMeter's one-second timestamp |
| (b) Packet aggregates | $\mathbf{a}_f \in \mathbb{R}^{20}$ over the first $K = 20$ packets: count, length / TTL / window / IAT moments, flag counts, payload bytes and fraction, retransmissions, fragments |
| (c) Deduplication of twins | drop a packet-less flow only when a same-key twin has the packets; keep orphans with `has_packets = false` and the CICFlowMeter timestamp; drop 1970 epochs |
| (d) Ordering and node indexing | sort by $t$; node ids by first appearance; $\Delta t^{\text{src}}_i$, $\Delta t^{\text{dst}}_i$ = seconds since the endpoint last appeared, $-1$ on first appearance |
| (e) Port access pattern | per initiator, from strictly earlier events: `port_delta` = dialled port minus its previous one, `dst_port_new` = 1 if never dialled before |
| (f) Orientation | `reversed` = 1 if the record runs server → client (from a bare SYN first packet, else the ephemeral-port rule), 0 if not, −1 unknown; never reads a label |

The 76 flow statistics are not copied here; they join on `flow_uid`.

**Output.** `events.parquet`: one row per event, globally time-ordered, 33 columns (`event_id`, `t`, `src_node_id`,
`dst_node_id`, `dt_src`, `dt_dst`, `has_packets`, the 20 aggregates, `port_delta`, `dst_port_new`, `reversed`,
labels, …); `node_index.parquet`: `node_id` ↔ IP.

**Checks.** Sorted by $t$; `event_id` unique; event count reconciles with flows minus twins minus bad epochs; no NaN
or inf in aggregates; identity columns absent; port features read no later event and are keyed on the initiator;
`reversed` reads no label.

---

## Block 7 — Per-flow encoder

**Purpose.** Turn one flow — its aggregates and its first packets, as seen by $t_{\text{obs}}$ — into one vector
$\mathbf{h}_f$ early enough to warn while the flow is running, and raise per-flow alerts.

**Code.** `models/data/` (`inputs`, `splits`, `prefix`, `dataset`, `loader`) and `models/flow_encoder/` (`encoder`,
`train`, `metrics`, `alerts`, `export`, `__main__` CLI).

**Design sources.** XG-NID §3.1 (per-flow heterogeneous subgraph, $K = 20$), GTAE-IDS §III (benign-only autoencoder),
scGNN (nearest benign mode), CTG (Bochner time encoding).

### Input

| Source | Used |
|---|---|
| `events.parquet` | $\mathbf{a}_f$, `pkt_n`, labels (evaluation), `flow_uid` |
| `flows.parquet` (join on `flow_uid`) | `Flow Duration` only, to tag the population; $\mathbf{x}_f$ is never a model input |
| `packets.parquet` via `flow_packet_map` | per packet: length, window, six flags, payload length, retransmission, fragment, direction (TTL blanked) |

### Transformation

**Observation cut** (`models/data/prefix.py::observe`). Keep packets with $t_p \le t_{\text{obs}}$, then the first
$K$ by `frame_no`; rebuild $\mathbf{a}_f(t_{\text{obs}})$ from them; tag the population.

**Side selection.** Packets and aggregates from one side or both:

| Input form | Packets | Aggregates |
|---|---|---|
| response side | the responder's packets only | recomputed on those packets (20) |
| split | both sides kept apart: a chain per direction plus reply edges | initiator and responder aggregates side by side (40) |

**Payload bytes (proposed).** The packet nodes carry header statistics only; the 128 payload bytes per packet that
Block 1 already stores are read by nothing. Both TFE-GNN (a byte-value embedding table per packet, header and payload
embedded separately) and XG-NID (1,500 payload features per packet) treat payload as the *primary* packet signal, and
the families we are weakest on with real sample sizes -- Brute Force -Web, -XSS and SQL Injection, 67 / 39 / 21 test
events carrying 1.2-8 KB of payload each -- are content attacks by definition. Shape: `Embedding(256, 32)` ->
two `Conv1d` -> mean pool -> 32, concatenated to each packet's 13 numeric features, 17,504 parameters including the
wider `packet_in`. It is live-affordable **because the 10 ms budget bounds the buffer**: only ~31 flows are in flight
in a 10 ms window, 81 KB, discarded at $t_{\text{obs}}$ -- holding payload to the 20th packet instead would cost
~242 MB, so payload feeds stage 1 only and never the flow message. Caveats: on TLS this reaches the handshake and no
further, and payload retention is a deployment policy decision.

**Per-flow subgraph.** Flow node $\nu_f$ with feature $\mathbf{a}_f$; packet nodes $\pi_1..\pi_K$; `contain` edges
flow → packet; `link` edges $\pi_i \to \pi_{i+1}$ (or per-direction and reply edges for split) carrying
$\Phi(\log(1+\Delta t))$.

$$
\mathbf{z}^{\text{pkt}}_f = \operatorname{READOUT}\big(\operatorname{GNN}(G_f)\big), \qquad
\mathbf{h}_f(t_{\text{obs}}) = \operatorname{MLP}\big([\mathbf{a}_f(t_{\text{obs}}) \,\|\, \mathbf{z}^{\text{pkt}}_f]\big) \in \mathbb{R}^{32}
$$

GNN: `HeteroConv`, 2 layers, $d = 64$ — `contain` by `SAGEConv`, `link` by `GINEConv`; readout masked mean ‖ max;
ReLU; variant `a_pkt`. The direction-aware packet reader (`dir_gnn`: 4 layers, side embedding, same-side / flip edge
kinds, GRU readout) was used by the anomaly arm, which is dropped (see *Alert arms* below).

**Autoencoder.** Decoders (two linear layers) reconstruct the flow's own normalised inputs — $\mathbf{a}_f$, the
packet slots, and, as an auxiliary target, the completed flow's aggregates (`a_future`). Loss: mean of per-target
MSE, benign training rows only, early stopping on benign validation error, deterministic.

**Alerting — two arms per event** (both populations, each with its own benign reference):

| Arm | For | Score | Threshold |
|---|---|---|---|
| **Classifier** | families seen in training | MLP (64 hidden) on the **split** embedding, trained on labelled rows of every family | PR curve on labelled validation rows |
| **Anomaly (A25)** — *dropped 2026-09-19, see below* | families never seen | mean of benign tail ranks of: response-side k-means distance to the nearest of 8 benign modes, response-side $\mathbf{a}_f$ decoder error (standardised per column), $\lvert\text{iat\_mean}\rvert$, direction-aware $\mathbf{a}_f$ decoder error | benign tail probability $\le \alpha$ ($\alpha = 1\%$) against benign training flows of the same population |

Decision rule (`models/detector/head.py`): **the multi-class head names the family whose score clears its own budget
threshold; highest score wins; otherwise no alert.** The anomaly arm's rule was: classifier confident → alert with that
family; else anomaly past
threshold → "unknown threat"; else benign.** `python -m models.flow_encoder.alerts` scores saved runs of the three
models; the classifier is currently binary (attack / benign), so the family name is not yet produced. A benign tail rank is the share of benign training flows scoring at or below the value. Models used at
inference: response-side, direction-aware and split encoders; the first two keep their $\mathbf{a}_f$ decoders.

### Output

| Artefact | Content |
|---|---|
| `flow_embeddings.parquet` + `flow_embeddings_manifest.json` | one $\mathbf{h}_f$ per event (`--export DIR --export-days ...` writes `DIR/<day>/`), streamed in chunks, `len(H) == len(events)`; `data/flow_embeddings/split/<day>/` (Block 8 input) and `data/flow_embeddings/response/<day>/` (comparison) |
| alert fields per event | `classifier_family`, `classifier_prob`, `classifier_fpr_budget`, `stage` (v2.9 contract; the anomaly fields went with the dropped arm) |

Not called `event_latents.parquet`: that name is Block 9's, with the same width, and a loader must not confuse them.

### Configuration handed forward

Fixed in code (not flags): `online_prefix`, variant `a_pkt`, $K = 20$ packets, TTL blanked, ReLU, $d_h = 32$,
two-layer decoders, `a_future` prediction target, k-means with 8 benign centres, MLP-64 classifier, deterministic.

```
python -m models.flow_encoder --budget-ms 10                         # default
  --side responder --packet-encoder gnn      (response model: anomaly arm only -- dropped, not built for live)
  --side both      --packet-encoder dir_gnn  (direction-aware model: anomaly arm only -- dropped, not built for live)
  --side split     --packet-encoder gnn      (split model: classifier and Block 8 input)
```

### Checks

- Every mapped packet is in exactly one subgraph; no `link` edge crosses a flow; grouping is by `flow_uid`, never by
  `flow_key` or a time bucket.
- No model input reads $\mathbf{x}_f$; every packet used has $t_p \le t_{\text{obs}}$; the export builds its input
  exactly as training does (`models/data/prefix.py::prepare`).
- Forbidden columns fail closed; outputs finite; identity invariant $e_i \leftrightarrow \upsilon(f_i) \leftrightarrow
  \mathbf{h}_{f_i}$ asserted.
- Handoff: a full-day `flow_embeddings.parquet` has exactly one row per event of that day.

**Deployment path.** CICFlowMeter emits flows too late for the online path, so a live system needs its own streaming
5-tuple assembler; the encoder batches flows and flushes every 5 ms.

---

## Block 8 — Event context encoder (CTG)

**Purpose.** Give each event its network context — what its endpoints have been doing, how long ago, in what order.
Block 7 sees one conversation; this block places it in the interaction stream. Owns **macro** time (event → event).

**Design source.** CTG §IV-A→D, redefined for the event stream.

**Input.** From `events.parquet`: `t`, `dt_src`, `dt_dst`, `port_delta`, `dst_port_new`, `has_packets`, `reversed`.
From `data/context_features/<day>/side_features.parquet` (`models.context_encoder.features`, built from the processed
packets): `sender_node_id` and `receiver_node_id` — the host that sent the flow's first packet (Block 7's direction 0)
and the other one — and the side features `request_packets`, `response_packets`, `reply_latency_s`,
`direction_changes`, `no_reply`, all as seen by $t_{\text{obs}}$. From Block 7's exports (`data/flow_embeddings/`):
`observation_time` and the embeddings the arm reads.

**Links are keyed sender → receiver, not on the record's `src_node_id` → `dst_node_id`.** Block 6 keeps the flow
record's orientation, whose source is the responder on `reversed` records; the first packet's sender is the record's
source on 70% of Friday-16's events and 87% of Thursday-01's (50,000 sampled each). Keying on the record would split one
conversation over two links and hand a side's embedding to the wrong one.

**Input arms — both built and compared:**

| Arm | Link memory is updated with | The event's own feature |
|---|---|---|
| 1 — split | sender → receiver: the split embedding | the split embedding |
| 2 — sides | sender → receiver: the request embedding; receiver → sender: the response embedding, or a learned *no reply* vector when no response packet was seen by $t_{\text{obs}}$; each update marked *request* or *response* | request and response embeddings, and the side features |

Arm 2 keeps the directions apart until this block, so how they combine is learned under Block 8's objective rather
than fixed by Block 7's; the side features carry the cross-side timing (reply latency, turns) that a single-side encoder
cannot see. It replaces the planned response-embedding comparison run.

### Transformation

**Part 1 — time encoding.** $\Phi^{*}(\Delta t) = \Phi(\log(1+\Delta t))$ for $\Delta t \ge 0$, and a learned
cold-start vector $\mathbf{c}_{\text{new}}$ for $\Delta t = -1$; source and destination gaps both encoded and
concatenated.

**Part 2 — link memory.** One state per directed link (keyed sender → receiver), updated with the arm's Block 7
embedding as the event feature:

$$
r_{u,v} = \operatorname{MLP}\big(h_{u,v} \,\|\, \Phi(t^{+}-t) \,\|\, \mathbf{h}_f\big), \qquad
h^{+}_{u,v} = \operatorname{GRU}\big(h_{u,v},\ \operatorname{agg}(r_{u,v})\big)
$$

A new link starts at a learned $h^{0}$. Link state is evictable (LRU with TTL); an evicted link restarts at $h^{0}$.
Node-level memory (aggregating a host's links) is an optional extension.

**Part 3 — neighbourhood attention.** Neighbourhood = events launched by $u$ (the sender) or received by $v$ (the
receiver), excluding earlier $u \to v$ events. Keep the latest event of each of the $S = 20$ most recent **distinct
peers** of the availability-gated set — not the $S$ most recent events, which a flood empties: with the event form,
99.9% of DoS-Hulk events had no neighbour left after same-link events were excluded (the attacker's nearest event to
another peer sits a median of 45,449 events back, benign traffic a median of 0), so "no neighbours" was a label
artefact and not traffic. Indexing per distinct peer removes it (DoS-Hulk: 0.0% empty, 19.7 of 20 filled, benign
19.9). How deep the scan goes is itself measured, not assumed: each label's neighbourhood must stop growing with
depth before the depth is fixed. At 80 runs per endpoint Bot still gained 4.5 neighbours from a deeper scan while
benign gained 0.02, so the depth was again deciding which label looked sparse; the scan runs 1,280 deep, where every
label saturates. Multi-head attention with time in keys and values, $\ell$ layers:

$$
s^{(0)}_{u,v}(t) = \mathbf{h}_f \,\|\, h_{u,v}, \qquad
s^{(\ell)}_{u,v}(t) = \operatorname{MLP}\big(s^{(\ell-1)} \,\|\, \operatorname{MHA}(q, K, V)\big)
$$

**Where the neighbourhood search runs.** The search is tensor work -- gathers over a `(block x depth)` window and
one stable sort -- so it runs on the GPU when the block is large enough to pay for the launches, and on the CPU when
it is not. Measured per event (cuda / torch-CPU): batch 1 2873 / 442 us, 16 148 / 91, 64 110 / 73, 256 22 / 35,
512 12 / 31, 4096 4.8 / 24 -- so `GPU_FROM = 256`. The answer is identical either way (a test asserts it), and the
two-stage depth (a shallow pass, deepened only for rows a deeper scan could still change) is what makes the deep
scan affordable: verified **bit-identical to the full-depth search on 300,000 real queries across three days** while
running 33-44x faster (173.6 -> 5.3 us/event on Friday-02, 166.3 -> 3.8 on Friday-16, 186.3 -> 3.9 on Thursday-15).

With that, the whole chain measured end to end (Block 7 -> 8 -> 9, idle machine, real packets and graph):

| batch | Block 7 | prep | Block 8 | Block 9 | total us/event | events/s |
|---|---|---|---|---|---|---|
| 1 | 5171 | 1783 | 5945 | 152 | 13051 | 77 |
| 16 | 382 | 218 | 436 | 9.4 | 1045 | 957 |
| 64 | 102 | 102 | 107 | 1.9 | 313 | 3,194 |
| **512** | **11.9** | **16.3** | **12.0** | **0.2** | **40.5** | **24,688** |

Against a measured peak arrival of 3,149 events/s, batch 512 leaves 7.8x headroom, and the chain is now
**model-bound** rather than prep-bound -- Blocks 7 and 8 are 24 of those 40.5 us. Live must batch: batch 1 is 40x too
slow, and the collection window that fills a batch of 512 at peak (~163 ms) costs nothing that matters, since the
alert budget is the 10 ms observation, not the delivery.

**Availability ordering.** The event stream stays in event-time order; representations enter a pending queue ordered by
$(t_{\text{obs}}, \texttt{event\_id})$. For event $i$ at $t_{\text{obs},i}$: flush every pending representation with
$t_{\text{obs},j} \le t_{\text{obs},i}$ into link memory; build the gated neighbourhood; compute $s_{u,v}(t_i)$; enqueue
its own contribution — never apply it to the state it was computed from. `has_packets = false` events are excluded
from `online_prefix`. The event stream is never deduplicated. In arm 2 a flow's two link updates enter together at
its $t_{\text{obs}}$, request before response; ties across flows resolve by `event_id`.

**Flow messages — a second message type on the link timeline.** A flow's own summary over its first $K = 20$
packets (the 20 aggregate columns of `ingest/build/events.py`) does not exist when the event is scored 10 ms in: it exists
when the last of those packets arrives. It is therefore **not a feature of the event** but a second message to the
same per-link memory, applied at its own availability time. TGN already defines exactly this -- interaction events
and node-wise events, each with its own message function, writing one memory -- and XG-NID caps a flow at 20 packets
for the same reason we do, so that a flow-level summary exists on a live timescale instead of at flow close (up to
120 s later).

Availability time is the last of the first $K$ packets, derived as $t + \texttt{iat\_mean} \times (\texttt{pkt\_n} - 1)$
because `iat_mean` is the mean of those $K - 1$ gaps; checked against the per-packet times on 200,000 events, the
difference is a median of 0.2 ns and at most 8.3 us, which is float32 in the stored aggregates. A message is emitted
only where that time is **after** $t_{\text{obs}}$ -- otherwise every one of those packets was inside the observation
budget and Block 7 has already read them. Measured share of events whose summary lands later: Bot 98.6% (median 2 ms
after scoring), DoS-Hulk 97.0% (median 127 ms), benign 72-78% (median 0.3-1.6 s), DoS-SlowHTTPTest 0.0%.

The rule is the availability rule, unchanged: a summary is held until every event of a batch is at or after its time,
so it is never applied before it exists, and may be applied up to one batch late -- the compromise batching already
makes for event messages. It can never affect the event it came from, only later events on that link. That is the
point: a flood's individual finished flows are indistinguishable one at a time (Block 7 anomaly recall 0.003 on
Friday-16 completed), but hundreds of completion messages accumulating on **one link** are not.

**The flow record as a third message type (proposed).** CICFlowMeter's own columns are a further message on the same
link timeline, at the time its record exists (flow close): `slog` -> `LayerNorm` -> `MLP(76 -> 128 -> 32)` plus its own
marker, 14,168 parameters. $\mathbf{x}_f$ here is **68 validated columns plus 8 Active/Idle recomputed by us** -- this
CICFlowMeter build writes absolute epoch time into `Idle` on ~half of all flows and zero into every `Active` column, and
those eight are exactly a slow-attack signature, so they are derived from packet timestamps with the 5 s activity
threshold instead of trusted. Records arrive promptly where a FIN or RST appears early -- measured 100% of DoS-Hulk and
DoS-SlowHTTPTest, 66.5% GoldenEye, 46.0% Slowloris, 37-41% benign -- so the 120 s idle-timeout tail is mostly benign
and slow attacks.

**Aggregating several kinds on one link.** `LinkMemory.update` mean-pools every message a link receives in a step, so
markers of different kinds blend and one link-level time gap covers all of them. With three kinds that dilutes
identity. The fix is presence-preserving rather than averaging -- type-separated slots
`[event_mean || summary_mean || record_mean || present(3) || log1p(count)(3)]`, the union kept by `max` (a Bloom
filter's OR without the hashing, which is only needed when the universe is larger than three), and each message's own
gap encoded **before** aggregation so a 30 s-old record does not inherit a fresh event's gap. About +12,000
parameters; to be adopted only if it measures better.

**Training — two candidates, both built and kept; the choice is deferred.** Block 7 is frozen in both. Both train
on **benign training events** only.

| | A — joint | B — separate |
|---|---|---|
| How | Blocks 8 and 9 train together as one autoencoder: Block 8 produces $s_{u,v}(t)$, Block 9 compresses it to $\mathbf{z}$, the decoder rebuilds the event's **input features** $\mathbf{x}_e$ (fixed targets, Block 9) | Block 8 trains first on a self-supervised temporal task — predicting whether link $u \to v$ occurs next, against sampled negative links — then is frozen; Block 9's autoencoder then trains on the frozen $s_{u,v}(t)$ |
| Block 8's memory learns | the history that helps rebuild a benign event | the dynamics of benign traffic |
| Loss | reconstruction of $\mathbf{x}_e$ | link prediction (Block 8), then reconstruction of $s_{u,v}(t)$ (Block 9) |

In both, memory is read before a batch updates it, and memory carried across batches is detached (truncated
backpropagation, as in TGN). A never reconstructs $s_{u,v}(t)$ — a trainable encoder could make its own output
trivially easy to rebuild; B may, because Block 8 is frozen by then.

Both variants are exported (Block 9 *Output*) and judged later: by their own checks now, and by Block 10's forecasting
once the world model exists.

### Output

- $s_{u,v}(t) \in \mathbb{R}^{d_s}$ per event → Block 9. **Stateful:** it includes the link memory $h_{u,v}$ carried
  across events and the recent gated neighbourhood, so it depends on history, not only on the event.
- Link memory $h_{u,v}$ after each event → optional export for Block 10 (`link_memory` / `node_memory` in the contract).

### Checks

- No neighbour with $t_{\text{obs},j} > t_{\text{obs},i}$ enters attention, and no $\mathbf{h}_{f_j}$ enters link
  memory before $t_{\text{obs},j}$ — tested by influence with two fixtures (unavailable: no effect; available:
  effect).
- An event's own representation does not change the state it was computed from; equal $t_{\text{obs}}$ resolve
  identically across runs; orphans in `online_prefix` raise.
- $\Phi^{*}$ never evaluates $\Delta t = -1$; state size stays bounded under eviction.
- Every first-packet sender is one of the event's two endpoints (raises otherwise); arm 2's response update never
  precedes its flow's $t_{\text{obs}}$.
- In each variant, removing link memory (same objective, memory zeroed) measurably degrades detection — in A the
  target includes $\mathbf{h}_f$, which can be rebuilt without history, so this is the check that the memory is used;
  the block beats a campaign rate rule
  (≥ 10 flows/s for 40 s, mostly refused) and Block 7 where Block 7 is weakest.
- Test the state transition directly, in order: queue → $h_{u,v}$ → $s_{u,v}$ → $\mathbf{z}$ → score → forecast.

---

## Block 9 — Graph autoencoder (GTAE)

**Purpose.** Compress each contextual event into a latent event representation $\mathbf{z}$ and produce a
reconstruction error usable as an anomaly score without seeing an attack.

**$\mathbf{z}$ is one row per event, but it is not memory-free.** Its input $s_{u,v}(t)$ contains the link memory
$h_{u,v}$ (every earlier event on $u \to v$ since that link started or was evicted) and attention over the $S$ most
recent available neighbour events. So $\mathbf{z}$ is *per-event content conditioned on causal history*. It never
contains future events (availability rule), and it is not the full network state $S_t$, which Block 10 builds. A
consumer building its own state over the $\mathbf{z}$ sequence is summarising history twice. What the history
encodes depends on the training variant (Block 8): benign reconstruction in A, benign traffic dynamics in B.

**Design source.** GTAE-IDS §III-B.

**Input.** $s_{u,v}(t)$ from Block 8 — trained together with this block (variant A) or frozen beforehand (variant
B). Normalisation statistics fitted on benign training events only.

### Transformation

Edge-centric (an event is an edge): graph-transformer encoder, plain DNN decoder.

$$
\mathbf{x}_e = \big[\,\mathbf{h}_f \,\|\, \log(1+\Delta t^{\text{src}}) \,\|\, \log(1+\Delta t^{\text{dst}}) \,\|\,
\mathbb{1}[\Delta t^{\text{src}}=-1] \,\|\, \mathbb{1}[\Delta t^{\text{dst}}=-1] \,\|\, \text{port\_delta} \,\|\,
\text{dst\_port\_new} \,\|\, \text{reversed}\,\big]
$$

(log gap set to 0 on first appearance, where the flag is 1; `port_delta` signed-log scaled). Every target is fixed:
Block 7 is frozen and the rest are Block 6 columns.

$$
\mathbf{x}_e \xrightarrow{\ \text{Block 8}\ } s_{u,v}(t) \xrightarrow{\ f_\phi\ } \mathbf{z}_{u,v}(t)
\xrightarrow{\ h_\theta\ } \hat{\mathbf{x}}_e, \qquad
\mathcal{L}_{AE} = \tfrac{1}{n}\textstyle\sum_i \lVert \mathbf{x}^{(i)}_e - \hat{\mathbf{x}}^{(i)}_e \rVert^{2}
$$

**Variant A** — the loss trains Block 8 and Block 9 together.

**Variant B** — Block 8 is frozen; the loss trains Block 9 alone:

$$
s_{u,v}(t) \xrightarrow{\ f_\phi\ } \mathbf{z}_{u,v}(t) \xrightarrow{\ h_\theta\ } \hat{s}_{u,v}(t), \qquad
\mathcal{L}_{AE} = \tfrac{1}{n}\textstyle\sum_i \lVert s^{(i)} - \hat{s}^{(i)} \rVert^{2}
$$

Input edge features are projected and given Laplacian positional encodings; each layer is multi-head attention over
edges then FFN with residual and LayerNorm. $s$ is standardised on benign training events before it is encoded and
before it is reconstructed, so no single context dimension's scale decides the loss.

**Three encoders $f_\phi$ are built and compared** (`models/compressor/autoencoder.py`); Laplacian encodings are
computed from a whole window, including events later than the one being scored, so the causal forms replace them
with causal structural features:

| Encoder | Reads | Note |
|---|---|---|
| `mlp` | this event's $s$ alone | Block 8 has already folded in memory and neighbourhood attention |
| `conv` | a fixed reach of earlier events (3 causal dilated convolutions, dilations 1/2/4, then a small MLP) | the previous window is handed in as context, so where a window is cut cannot change a score |
| `window` | earlier events of its window, attention biased by a shared sender, receiver or link and by the gap | **disqualified**: re-cutting the windows moved scores by up to 285.7 (correlation 0.618) where `mlp` moved by 1e-5 — the same event scores differently depending on where the batch boundary fell | Trained on **benign events only**, no rebalancing. Score per event:
the reconstruction error of the variant's target ($\lVert \mathbf{x}_e - \hat{\mathbf{x}}_e \rVert^{2}$ in A,
$\lVert s - \hat{s} \rVert^{2}$ in B), terms standardised on benign training rows; operating point from a benign
reference. After training, Block 8 and Block 9's encoder are detached for inference; the decoder is kept only if
`recon_error` is exported.

### Output

`event_latents.parquet` + `latents_manifest.json`, per [model_io_contract.json](model_io_contract.json): `z`
(`event_latent_dim`), `recon_error`, the event's identity, time, node, split and observation fields, `label`
(evaluation only). **One set per training variant**, side by side — `variant_A/` and `variant_B/` for each day — with
`training_variant` recorded in the manifest. Same rows, same order, same columns; only `z`, `recon_error` and the
memory differ.

### Checks

- Benign held-out reconstruction error low and stable; attack error higher.
- $\mathbf{z}$ finite with exactly `event_latent_dim` entries.
- Normaliser fitted on train only; temporal split with embargo ≥ maximum flow duration; benign-only filter asserted.

---

## Two autoencoders, two roles

| | Block 7 autoencoder | Block 8 + 9 autoencoder |
|---|---|---|
| Trained | alone, on benign flows | on benign events, Block 7 frozen — A: Blocks 8 and 9 together; B: Block 8 first (link prediction), then Block 9 |
| Sees | one flow alone, at $t_{\text{obs}}$ — no memory | one event **with network context** from Block 8 — link memory and recent neighbours already folded in |
| Reconstructs | the flow's own aggregates and packet slots | A: the event's input features $\mathbf{x}_e$ from its history; B: Block 8's frozen $s_{u,v}(t)$ |
| Bottleneck | $\mathbf{h}_f$ — the event feature for Block 8 | $\mathbf{z}$ — the event latent for Block 10 |
| Decoder after training | was kept for the dropped anomaly arm (A25); the split model needs none at inference | kept: `recon_error` is what Block 9 reduces false positives with |
| Anomaly it catches | a flow that does not look benign by itself | an interaction that does not fit its network context |
| Architecture | heterogeneous packet GNN + MLP | link memory + neighbourhood attention (Block 8) → graph transformer + DNN (Block 9) |

Block 7's autoencoder learns *what a flow is*; Block 9's learns *what an interaction in its context is*. Block 8
sits between them and is the only one that carries memory over time.

**Dropped from the live system (2026-09-19): the per-flow unsupervised arm (A25).** Its four scores need the response
model *and* the direction-aware model in addition to the split model — 195,856 extra encoder parameters on the
per-flow hot path, three encoders where the supervised line needs one. That is a deployment cost the product does not
carry, so **the supervised arm is the main line** and A25 is not part of it.

Its measurements stay in `TESTS.md` and are not retracted: they are the record of what a benign-only per-flow score
achieves on unseen families (Bot recall 0.989/0.997, Web 0.748, two unseen DoS families ~0.55, benign alert rate
0.65-1.35% against a 1% target). Unknown-attack detection is a **bonus, never a requirement**.

**Block 9 is not dropped, and its role is not the anomaly score.** It is (a) the compressor that hands $\mathbf{z}$ to
Block 10 and (b) the stage that **lowers the false-positive rate** the recall-first detection threshold admits.
Cross-event attention over the window is a live option for it, to be judged by whether it helps Block 10's rollout —
not by the per-flow window-boundary test that ruled it out as a per-event scorer.

---

## Block 10 — World model

**Purpose.** Learn transition dynamics over the event stream and roll it forward to forecast attack progression.

**Status (2026-09-20): a proxy exists and is measured** — `models/world_model_proxy/model.py`, ~75,000 parameters: one state per
key, a `GRUCell` of dynamics, a next-observation head and a per-class head. The K-step forecast comes from **iterating
the dynamics** with the model's own predicted observation fed back in, not from one head per horizon; predicting each
horizon directly scores the same (0.998 vs 0.9976) while never learning a transition, which is the shortcut the problem
statement's wording rules out.

Three design points the proxy settled, each with a measurement behind it:

* **State per key, chunk width 512.** A single state over the interleaved stream reaches recall 0.29 where one state
  per key reaches 0.83+; a wider chunk starves hub nodes (receiver-keyed recall 0.108 at window 4096 against 0.930 at
  512). 512 is also Block 8's live batch, so training and serving see the same staleness.
* **Sender key answers anticipation, link key cannot.** An attacker/victim link carries no benign traffic at all
  (90,039 events, zero benign), so a link-keyed target has no early positives by construction. On the sender key:
  `recall_early` 0.9969 and 275 of 291 campaign onsets flagged before their first attack packet, holding up when the
  attacker's labels are held out of training entirely.
* **The measured lead is ~2 seconds (one event).** Nothing in the objective rewards firing earlier inside the window,
  so the head fires at the last possible moment. This is the proxy's main weakness and the clearest thing a real
  Block 10 should beat — see the acceptance criteria in [BLOCK10_PROXY_RESULTS.md](BLOCK10_PROXY_RESULTS.md).

**Design source.** CTG §IV temporal mechanics.

**Input.** Per day, per [model_io_contract.json](model_io_contract.json):

| File | Required | Carries |
|---|---|---|
| `latents_manifest.json` | yes, read first | day, `n_events`, `event_latent_dim`, time and split policy, label vocabulary |
| `event_latents.parquet` | yes | one row per event sorted by `t`: node ids, `dt_src` / `dt_dst`, `reversed`, `z`, `recon_error`, split, observation fields, `label` |
| `node_index.parquet` | yes | `node_id` ↔ IP (node ids change across days) |
| memory export (`node_memory` / `link_memory`) | optional | Block 8 state after each event |
| alert fields | optional, v2.9 | the supervised arm's per-event multi-class output, and which stage produced it |

### Transformation

$$
S_{t_i^{+}} = F\big(S_{t_i^{-}},\ e_i,\ \mathcal{N}_i\big), \qquad \text{forecast over the next } H \text{ events}
$$

"Next step" means next interaction; lead time is reported in events **and** seconds. Candidate targets share one
state: next attack target host $P(v \in \mathcal{V}^{\text{attack}}_{\text{next}} \mid S_t)$ (primary), attack stage
after $H$ events, next event $P(e_{i+1} \mid S_t)$ (auxiliary). One target is fixed before training.

**Alarm eligibility.** $t_{\text{alarm}} \ge t_{\text{obs}}$; lead time $= t_{\text{attack}} - t_{\text{alarm}}$,
reported per population and per definition (flow-level, campaign-level). Neighbourhoods admit $e_j$ only if
$t_{\text{obs},j} \le t_{\text{obs},i}$. Labels are evaluation targets only.

### Output

State $S_t$ per event, $H$-event rollout, forecast probabilities (propagation, stage) → Blocks 11, 12, 14.

### Checks

- Prediction error rises during attacks and stays low outside; lead time positive, measured from $t_{\text{obs}}$.
- Rollout stays on the data manifold; cold start branched explicitly; trained on train events only with embargo.
- Propagation targets are validated only on days with propagation (Infiltration, Bot), not on single-victim floods.

---

## Block 11 — Explainability

**Purpose.** Attribute every prediction to specific features and neighbouring events; the problem statement rejects
black-box outputs.

**Design source.** XG-NID §3.2.

**Input.** A prediction from Blocks 7, 9 or 10, with its event and neighbourhood.

**Transformation.**

| Path | Answers | Mechanism |
|---|---|---|
| Attention weights | which neighbouring events drove it | Block 8 attention |
| Feature attribution | which input columns | SHAP or Integrated Gradients over Block 7's inputs |
| Reconstruction residual | which dimensions were anomalous | per-dimension residual from Blocks 7 and 9 |

**Output.** Per prediction: ranked driving features with weights and contributing neighbour events.

**Checks.** Stable under a fixed seed; removing a top-ranked feature changes the prediction and a bottom-ranked one
does not; never names a forbidden column.

---

## Block 12 — MITRE ATT&CK stage mapping

**Purpose.** Map behaviour to kill-chain stages.

**Input.** $S_t$ and the rollout from Block 10.

**Transformation.** $P(\text{stage after } H \text{ events} \mid S_t) = \operatorname{softmax}(W S_t + b)$, with stage
labels derived from attack names (a modelling assumption, not ground truth):

| Attack | Stage |
|---|---|
| `DoS-*`, `DDoS-*` | Impact |
| `FTP-BruteForce`, `SSH-Bruteforce`, `Brute Force -Web`, `Brute Force -XSS`, `SQL Injection` | Initial Access |
| `Infiltration` | Lateral Movement |
| `Bot` | Command & Control |

Reconnaissance and Exfiltration have no labels in the dataset and are never reported.

**Output.** Stage probabilities per event → Block 14.

**Checks.** Every configured attack maps to exactly one stage; per-stage support reported.

---

## Block 13 — Baseline and benchmark

**Purpose.** Show that temporal learning beats a logistic-regression baseline on the same features, as the problem
statement requires.

**Input.** The feature tensor Block 7 consumes, per mode, with identical splits.

**Transformation.** $P(\text{attack} \mid \mathbf{x}) = \sigma(\mathbf{w}^{\top}\mathbf{x} + b)$, plus single-feature
counters (`packets_seen`, `payload_bytes`, `iat_mean`) and an identity-only control.

**Output.** F1, precision, recall and false-positive rate at the operating point; per family, per severity tier, and
severity-weighted recall.

**Severity tiers** (a policy assumption; weights 8 / 4 / 2 / 1): tier 1 Infiltration, Bot; tier 2 SQL Injection,
SSH / FTP brute force, web brute force, XSS; tier 3 DDoS and DoS floods; tier 4 DoS-SlowHTTPTest as captured
(connections refused). Labels score results; they never rank flows.

**Checks.** Baseline and model see byte-identical tensors and splits under the same mode; the identity-only control
must not score near 1.0.

---

## Block 14 — Demonstration interface

**Purpose.** Accept a capture or flow file, run the pipeline offline, and show what was found.

**Input.** A PCAP or a CIC flow CSV.

**Transformation.** Blocks 1 → 12 on the file, no network access.

**Output.** Infiltration-probability timeline plotted against `observation_time`; flagged flows with their alert arm
and attribution (Block 11); stage annotations (Block 12).

**Checks.** Runs with networking disabled; accepts both inputs; every displayed alert carries its attribution.

---

## Handoff between the two halves

| Producer → consumer | File(s) | Contract |
|---|---|---|
| Blocks 1–6 → Block 7 | `events.parquet`, `flows.parquet`, `packets.parquet`, `flow_packet_map.parquet`, `node_index.parquet` | [data-reference.md](data-reference.md) |
| Block 7 → Block 8 | `flow_embeddings.parquet` + manifest | Block 7 *Output* |
| Block 9 → Block 10 | `latents_manifest.json`, `event_latents.parquet`, `node_index.parquet`, optional memory, optional alerts | [model_io_contract.json](model_io_contract.json) 2.8-event; [v2.9](model_io_contract_v2.9.json) |

---

## Build and verification order

Each block must earn its place against the one below it before the next is built:

1. **Block 7** — the encoder against single-feature counters and $\mathbf{x}_f$; alert arms per population.
2. **Blocks 8 + 9, in both variants A and B** — each through the same steps: Block 7 output alone → + time gaps →
   + link memory → + neighbourhood attention; benign reconstruction low, attack reconstruction higher, each step
   improving on the one before. Both variants are exported.
3. **Block 10** — positive lead time from $t_{\text{obs}}$, `online_prefix` only.

**Cascade, not end-to-end.** Block 7 trains first; Blocks 8 and 9 train on Block 7's frozen output — together
(variant A) or in sequence (variant B), both kept; Block 10 trains on each variant's frozen output, and the variant is
chosen by that comparison. This keeps failures
attributable to one block, lets both halves of the team work against the contract independently, fits in memory, and
avoids weighting conflicting objectives. End-to-end fine-tuning is a later option that must beat the frozen cascade.

---

## Problem-statement traceability

| Requirement | Block | Status |
|---|---|---|
| Ingest CIC-IDS2018 CSV and raw PCAP | 0–2, 14 | built (PCAP); CSV in the demo |
| Flow features: IPs / ports, flags, protocol, bytes, packets, duration, IAT, direction ratio | 2 | built |
| Packet features: TTL, window size, fragment flags, payload sizes, retransmissions | 1, 6 | built (TTL extracted, excluded from models) |
| Port-scan signatures | 6e | built (`port_delta`, `dst_port_new`) |
| Timestamped normalised feature matrix | 6, 7 | timestamped on disk; normalised in the model layer |
| State as feature vector or graph | 6, 8 | event graph |
| Learn $P(S_{t+1} \mid S_t)$ | 8, 10 | specified |
| Generalise to unseen attacks | 7, 9 | anomaly arm (Block 7) built; Block 9 specified |
| K-step simulation; infiltration probability over the next K steps | 10 | specified, as the next $H$ events |
| MITRE stage mapping | 12 | specified; 3 of 5 stages labellable |
| Driving features via attention or SHAP | 11 | specified |
| Logistic-regression baseline; F1 / precision / recall / FPR | 13 | specified |
| Offline demo | 14 | specified |

**Where the problem statement is met in intent rather than wording.**

- **Events instead of time windows.** "Next K time windows" is delivered as the next $H$ events, with the wall-clock
  span reported beside it; fixed bins would dilute labels and average away slow attacks.
- **Normalisation in the model layer.** Fitting a scaler during extraction would fit it on days that contain attacks.
- **Reconnaissance and Exfiltration** have no labels in CSE-CIC-IDS2018.
- **CTU-13** is not used: CSE-CIC-IDS2018 provides raw PCAPs and a minute-precise schedule; a CTU-13 day needs only
  new rules in `config.py`.
- **Authentication logs** are not published aligned with the captures.
- **tshark** is used directly instead of PyShark / Scapy (the same parser without per-packet Python overhead).

---

# Appendix A — Windowed node features *(not part of the system)*

**Purpose.** A fixed-window per-host view, only as a comparison baseline, a sanity check and for visualisation.

**Code.** `ingest/build/nodes.py` (`python -m ingest.build.nodes <day> --window-seconds 10`) — not imported by the pipeline.

**Input.** `edges.parquet`.

**Transformation.** With bin $W = 10$ s, per host $v$ and bin $w(t) = \lfloor t/W \rfloor W$: out / in flow counts,
distinct peers, distinct destination ports and related counts ($\mathbb{R}^{9}$).

**Output.** `data/nodes/<day>/nodes.parquet`: one row per (bin, host).

---

## References

| Ref | Paper | Used for | Blocks |
|---|---|---|---|
| XG-NID | Farrukh et al., *XG-NID: Dual-Modality Network Intrusion Detection using a Heterogeneous GNN and LLM* | per-flow heterogeneous subgraph, $K = 20$, explainability tools | 6, 7, 11 |
| CTG | Duan et al., *Practical Cyber Attack Detection with Continuous Temporal Graph in Dynamic Network System* | Bochner time encoding, per-link memory, event neighbourhood attention | 7, 8, 10 |
| GTAE | Ghadermazi et al., *GTAE-IDS: Graph Transformer-Based Autoencoder Framework* | benign-only edge autoencoder, detached encoder, identifier stripping | 7, 9 |
| TGN | Rossi et al., *Temporal Graph Networks for Deep Learning on Dynamic Graphs* | memory batching, staleness | 8 |
| scGNN | *scGNN is a novel graph neural network framework* | benign traffic as a mixture of modes | 7 |
| T2V | Liu et al., *Trace2Vec* | pre-train / fine-tune shape | 7, 9, 13 |
| IPv4-frag | *A Dual-Model Framework for Detecting IPv4 Fragmentation-Consistent Traffic Patterns* | correlated features, evasion by shaping | 7 |
| SpecNorm | *Spectral Norm Regularization* | bounded input sensitivity | 7, 9 |
| Belief | *Adaptive Network Security Policies via Belief Aggregation and Rollout* | alarm decisions under uncertainty | 10 |
| DiffOpt | *Differentiable optimization layers* | optimising under an alert budget | 10, 13 |
| GNN-LSTM | *A Hybrid Approach Using GNNs and LSTM for Attack Vector Reconstruction* | alarms into a narrated attack path; calibration | 11 |
| APT-KC | *Learning the APT Kill Chain* | stage vocabulary and transitions | 12 |
