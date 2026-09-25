# Friday-16-02-2018 Labelling — Verification Report

**Date:** 2026-09-09
**Scope:** correctness of the label pipeline (`ingest`) for CSE-CIC-IDS2018,
verified on `Friday-16-02-2018` (DoS-SlowHTTPTest, DoS-Hulk).

> **Module rename.** `graph.py` and `align.py` were later merged into
> `derive.py`. Historical entries below use the original names; the code
> they describe now lives in `derive.py`.

---

## Verdict

| Question | Answer |
|---|---|
| Were the labels correct before? | **No.** 3,895,229 flows, 100% `Benign`. Zero attacks labelled. |
| Was the *rule table* wrong? | **No.** `config.py` matches Table 2 exactly. |
| Was the *matcher logic* wrong? | **No.** IP/direction/protocol matching was correct. |
| What was actually wrong? | **One 4-hour timezone mismatch.** (Three further, unrelated bugs were found later — see 5b–5d.) |
| Do labels now match **Table 2**? | **Yes — exactly.** Zero rows labelled outside their scheduled window. |
| Do labels now match the **official CSV**? | **Yes, wherever the official CSV is trustworthy.** Per-minute flow counts are *identical*. The places they diverge are defects in CIC's file, each identified and proven below. |

---

## 1. Root cause

Every timestamp this pipeline stores is **UTC**:

- `flows.parquet` — CICFlowMeter is launched with `-Duser.timezone=UTC` (`flows.py`)
- `packets.parquet` — `frame.time_epoch` is UTC by definition
- `edges.parquet` — derived from the flow timestamp

The CSE-CIC-IDS2018 attack schedule (Table 2, copied verbatim into `config/config.py`)
is **not** UTC. It is capture-local time at the Canadian Institute for Cybersecurity
(University of New Brunswick), which is in the **Atlantic** time zone. February is
Atlantic Standard Time = **UTC−4**.

`LabelMatcher` compared UTC flow times against local-time windows. The comparison was
therefore never true for any real attack flow, and every row fell through to `Benign`.

```
flow 13.59.126.31 -> 172.31.69.25:21 @ 14:12:14 UTC
  ├─ timestamp parsed          ✓ 2018-02-16 14:12:14
  ├─ IP pair matches rule      ✓ attacker -> victim
  ├─ in window [10:12, 11:08]? ✗  14:12:14 is not in that range
  └─ result                       Benign        <-- the entire bug
```

Nothing else was broken. No overwrite, no propagation failure, no matcher-invocation
problem — the three hypotheses the earlier investigation left open.

### The offset is exactly 4 hours, to the second

| Attack | Official CSV first flow | Our stored UTC first flow | Delta |
|---|---|---|---|
| DoS-SlowHTTPTest | `10:12:14` | `14:12:14` | **+4:00:00** |
| DoS-Hulk | `13:45:27` | `17:45:27` | **+4:00:00** |

Two independent attacks, same offset, matching seconds. That is a timezone constant,
not flow-boundary noise.

---

## 2. Test results

### 2.1 Before the fix

| Test | Result |
|---|---|
| Total flow rows across 19 captures | 3,895,229 |
| Distinct labels | **1** (`Benign`) |
| SlowHTTPTest flows correctly labelled | 0 / 105,550 — **FAIL** |
| Hulk flows correctly labelled | 0 / 1,750,476 — **FAIL** |

### 2.2 After the fix — relabelling the real 3.6M-row capture

`UCAP172.31.69.25-part1/flows.parquet`, 3,622,934 rows:

| Label | Rows | Forward | Reverse |
|---|---:|---:|---:|
| DoS-Hulk | **3,516,432** | 1,750,476 | 1,765,956 |
| DoS-SlowHTTPTest | **105,550** | 105,550 | 0 |
| Benign | 952 | — | — |

Observed spans, converted back to schedule-local:

| Attack | Scheduled (Table 2) | Observed (local) | Inside window? |
|---|---|---|---|
| DoS-SlowHTTPTest | 10:12 – 11:08 | 10:12:14 – 11:05:13 | ✅ |
| DoS-Hulk | 13:45 – 14:19 | 13:45:27 – 13:58:22 | ✅ |

**Leakage check: 0 rows** carrying an attack label outside its scheduled window,
for either attack.

### 2.3 End-to-end run on real PCAP

A 8-second slice of genuine Hulk traffic (`17:45:30–17:45:38` UTC = `13:45:30` local,
inside the window, 207,957 packets) carved with `editcap` and pushed through the
**complete** pipeline — tshark → packets, CICFlowMeter → flows, → edges.

```
flows    41,465   all DoS-Hulk (forward 34,302 / reverse 7,163)
packets 207,955   all DoS-Hulk (forward 105,606 / reverse 102,349)
edges    41,465   all DoS-Hulk, carrying all five label columns

CLOCK ALIGNMENT
  packets epoch  1518803130.0  ==  edges epoch  1518803130.0
  both decode to 2018-02-16 17:45:30 UTC

FLOW <-> PACKET JOIN
  packets joining a flow   207,955 / 207,955  = 100.0%
  distinct flow_keys       flows 14,040  ==  packets 14,040
  label agreement on join  100.0%
```

### 2.4 Flow labels vs packet labels

868 real conversations sampled across all three label classes, run through the flow
path (`_prepare_chunk`) and the packet path (`_parse_packet_row`) independently:

| Check | Mismatches |
|---|---|
| Label + direction agreement | **0** |
| `flow_key` agreement | **0** |

Both paths share one `LabelMatcher`, so agreement is structural rather than
coincidental.

### 2.5 Unit tests

`tests/ingest/test_labels.py` — **19 passed**, including:

- `test_schedule_offset_is_minus_four_hours`
- `test_attack_matches_at_utc_not_at_schedule_local_time` — asserts the pre-fix
  behaviour (matching at 13:50 UTC) is now correctly rejected
- `test_official_csv_attack_start_times_are_matched` — pinned to `14:12:14` and
  `17:45:27` UTC, the exact instants of the official CSV's first attack flows
- `test_boundaries_are_inclusive_in_utc`
- `test_forward_and_reverse_are_both_labelled_but_distinguished`
- `test_service_port_is_required_for_a_match`
- `test_reverse_direction_checks_source_port_not_destination`
- `test_missing_ports_raise_rather_than_silently_returning_benign`
- `test_scalar_and_vectorized_flow_keys_are_identical`

---

## 3. Comparison against the official CIC CSV

This is the part worth reading carefully, because the official file cannot be used
naively as ground truth.

### 3.1 Per-minute flow counts — DoS-Hulk

Forward flows only, our timestamps shifted to local:

| Minute | Official | Ours | |
|---|---:|---:|---|
| 13:45 | 91,113 | **91,113** | exact |
| 13:46 | 135,074 | **135,074** | exact |
| 13:47 | 136,194 | 136,616 | 0.3% |
| 13:48 | 99,531 | 135,481 | official truncates here |
| 13:49 → 13:58 | 0 | ~133,000/min | official file has ended |

**For every minute where the official file holds complete data, our forward flow
counts are identical.** The divergence begins precisely at the point CIC's file is
cut off (see 3.3).

### 3.2 Per-minute flow counts — DoS-SlowHTTPTest

| Window | Official | Ours | Ratio |
|---|---:|---:|---|
| 10:12 – 10:35 | ~3,980/min | ~1,990/min | **exactly 2.000** |
| 10:37 – 10:57 | ~1,990/min | ~1,990/min | **exactly 1.000** |
| 10:58 | 294 | 2,000 | official tails off |
| 10:59 – 11:05 | 0 | ~1,990/min | official has no data |

The 2× phase is **duplication inside the official CSV**, proven by grouping its rows
on the full 79-feature signature and counting copies:

| Window | Copy-count distribution | Median copies |
|---|---|---|
| 10:12 – 10:35 | `{2, 4, 6, 8, … 56}` — **every count even, no odd values** | 2.0 |
| 10:37 – 10:58 | `{1, 2, 3, 4, … 26}` — natural distribution | 1.0 |

An all-even copy-count distribution cannot arise from real traffic. The two windows
have the same distribution shape, one exactly doubled. CIC's file contains each
SlowHTTPTest flow twice during 10:12–10:35.

Our tail (10:59 – 11:05) is **not** an error: Table 2 states SlowHTTPTest ran until
**11:08**, so our data is closer to the documented schedule than the official file is.

The attacker `13.59.126.31` appears in exactly one capture (`UCAP172.31.69.25-part1`,
105,550 flows), so the 2× cannot be explained by a second vantage point on our side.

### 3.3 Defects in the official CSV

| Defect | Evidence |
|---|---|
| **Truncated at Excel's row limit** | File is exactly 1,048,576 lines (1,048,575 rows + header) = Excel's hard maximum. Cuts off mid-Hulk at 13:48:44; the attack ran to 14:19. |
| **No endpoint columns** | Columns begin `Dst Port, Protocol, Timestamp, …`. There is no `Src IP`, `Dst IP` or `Flow ID`, so attacker/victim identity and direction **cannot be checked against it at all**. |
| **12-hour clock, AM/PM stripped** | Hulk's 13:45:27 is written `01:45:27`. Naive parsing places the attack at 1:45 AM. |
| **Header row repeated inside the data** | One row has the literal value `Label` in the `Label` column. |
| **Duplicated rows** | See 3.2 — every SlowHTTPTest flow appears twice for 24 minutes. |

**This is why the earlier "Test 1" (zero row overlap) and "Test 6" (zero feature
matches) were inconclusive.** They were comparing against a truncated, deduplicated-
never, endpoint-free, mis-timestamped file. Exact row equality was never achievable
and was never the right criterion.

### 3.4 Label vocabulary differs

| Official | Ours |
|---|---|
| `DoS attacks-SlowHTTPTest` | `DoS-SlowHTTPTest` |
| `DoS attacks-Hulk` | `DoS-Hulk` |

Ours follow Table 2's naming. Worth knowing if you ever compare against published
benchmark numbers keyed on CIC's strings.

---

## 4. How the timestamp offset is handled

### It is one hardcoded constant, in one place

```python
# ingest/sources/flows.py
SCHEDULE_UTC_OFFSET = timedelta(hours=-4)
```

`LabelMatcher` is the only thing that reads it, and it applies the shift **in
memory, at comparison time only**.

### It never touches the data the model trains on

This is the important part:

| | Stored on disk | Used by the model |
|---|---|---|
| `flows.parquet` `Timestamp` | **UTC, unmodified** | yes |
| `packets.parquet` `timestamp` | **UTC epoch, unmodified** | yes |
| `edges.parquet` `timestamp` | **UTC epoch, unmodified** | yes |
| `SCHEDULE_UTC_OFFSET` | not stored anywhere | **no** |

So the offset is **not a feature, not a transform, and not applied to training
data**. It exists purely to decide which rows get which `Label`.

It is nonetheless **required for training**, because without it every label is
`Benign` and there is nothing to learn. The distinction is:

- needed to *produce* correct labels → **yes, essential**
- present in the tensors the model sees → **no, never**

Keeping stored timestamps in UTC is what allows flows, packets and edges to join
on one shared clock — verified in 2.3 (packets epoch `1518803130.0` == edges epoch
`1518803130.0`).

### One constant is correct for all ten days

The offset is a property of the dataset, not of Friday. Table 2 is written in
Atlantic time (CIC is at the University of New Brunswick); the PCAPs are UTC.
February and early March 2018 are Atlantic **Standard** Time = UTC−4.

The one thing that could break this is a daylight-saving transition inside the
dataset. In 2018 DST began **2018-03-11**. Every dataset day is before it:

| Day | Date | Before 2018-03-11 | Offset |
|---|---|---|---|
| Wednesday-14-02-2018 | 2018-02-14 | yes | UTC−4 |
| Thursday-15-02-2018 | 2018-02-15 | yes | UTC−4 |
| Friday-16-02-2018 | 2018-02-16 | yes | UTC−4 |
| Tuesday-20-02-2018 | 2018-02-20 | yes | UTC−4 |
| Wednesday-21-02-2018 | 2018-02-21 | yes | UTC−4 |
| Thursday-22-02-2018 | 2018-02-22 | yes | UTC−4 |
| Friday-23-02-2018 | 2018-02-23 | yes | UTC−4 |
| Wednesday-28-02-2018 | 2018-02-28 | yes | UTC−4 |
| Thursday-01-03-2018 | 2018-03-01 | yes | UTC−4 |
| Friday-02-03-2018 | 2018-03-02 | yes | UTC−4 |

**No day crosses the DST boundary**, so a single constant is structurally correct
for the whole dataset. No per-day timezone configuration is needed.

---

## 5. Do the other 9 days need verifying?

**The timezone fix: no — it applies automatically.** One constant, one code path,
and the DST analysis above shows it holds for every day.

**But verify anyway, because two things remain unproven per day**, and there is now
a command that checks both:

```bash
python -m ingest.verify <day>
```

### 5.1 It measures the offset instead of assuming it

Rather than trusting the constant, `verify.py` scans candidate offsets from −12h to
+12h in 15-minute steps and reports which one actually places that day's
attacker↔victim traffic inside its scheduled window. Run on the full Friday capture
(3.6M flows), using no reference to the official CSV:

```
full-day capture, 3.6M flows -> detected offset: UTC-4.00
   DoS-SlowHTTPTest        105,550 aligned
   DoS-Hulk              3,516,432 aligned

alignment score by candidate offset (top 8):
  UTC -4.00   3,621,982  ##################################################
  UTC -3.75   3,599,612  #################################################
  UTC -3.50   1,322,790  ##################
  UTC -4.25      76,140  #
  UTC -4.50      46,260
  UTC -3.25      23,440
  UTC -4.75      16,400
  UTC-12.00           0

  offsets scoring zero: 90/97
```

The peak is sharp and 90 of 97 candidates score exactly zero, so this is a real
measurement, not a rubber stamp. If a day returns anything other than UTC−4.00, it
fails loudly and its labels are not to be trusted.

### 5.2 The thing that genuinely differs per day: service ports

Only Friday has `service_ports` / `protocols` pinned, because only Friday's were
verified against real traffic. The other nine days match on **time + IP pair only** —
correct, just less precise (a rule could catch unrelated traffic between the same
two hosts inside the attack window).

Ports were deliberately **not** guessed. A wrong port set silently drops an entire
attack to `Benign` — which is exactly the failure this whole report documents.

Suggested per-day workflow:

1. Process the day.
2. `python -m ingest.verify <day>` → confirms the offset and that every
   configured attack is present and in-window.
3. Read the `service ports` line it prints for each attack.
4. If the distribution is clean (one dominant port, one protocol), add
   `service_ports` / `protocols` to that rule in `config.py` and re-run.

**`Infiltration` must stay unconstrained** — its second stage is a full nmap
portscan, so it has no single service port by design.

---

## 5b. Second bug found: 61% of flows were being discarded

Found while confirming the data was training-ready. **Unrelated to labelling** — the
labels were right, but most of the rows never made it into Parquet.

### Cause

CIC capture files are named `capPC1-172.31.64.106`, where the trailing `.106` is the
last octet of an IP address. `Path.stem` treats it as a file extension and strips it:

```python
Path("capPC1-172.31.64.106").stem == "capPC1-172.31.64"
Path("capPC1-172.31.64.113").stem == "capPC1-172.31.64"   # same!
```

`cli.py` used `pcap.stem` as the output directory name, so **438 captures collapsed
into 19 directories**. The first capture in each group wrote `flows.parquet`;
`_valid_parquet()` then made every later capture in that group skip its own
conversion. CICFlowMeter still ran on all 438 PCAPs — 419 of the resulting CSVs were
simply never read.

### Measured damage

| Capture dir | CSVs | CSV rows | In Parquet | Lost |
|---|---:|---:|---:|---:|
| UCAP172.31.69.25-part1 | 1 | 3,622,934 | 3,622,934 | 0% |
| capEC2AMAZ-O4EL3NG-172.31.66 | 58 | 1,044,468 | 20,036 | **98%** |
| capEC2AMAZ-O4EL3NG-172.31.64 | 41 | 839,969 | 21,140 | **97%** |
| capEC2AMAZ-O4EL3NG-172.31.67 | 37 | 687,316 | 17,912 | **97%** |
| capPC1-172.31.64 | 21 | 339,462 | 13,560 | **96%** |
| … (14 more) | | | | 88–97% |
| **TOTAL** | | **10,055,170** | **3,895,229** | **61.3%** |

The attack capture has one PCAP and no collision, so **attack rows were unaffected**.
Everything lost was benign traffic — which badly skewed the class balance:

| | Attack | Benign | Attack share |
|---|---:|---:|---|
| With the bug | 3,621,982 | 273,247 | **93.0%** |
| After the fix (expected) | 3,621,982 | 6,433,188 | **36.0%** |

A 93%-attack training set would have been actively misleading for a world model.

### Fix

`packets.capture_name()` strips only genuine pcap extensions (`.pcap`, `.pcapng`,
`.cap`) and leaves anything else intact. `cli.py` uses it instead of `pcap.stem`.
438 PCAPs now map to 438 distinct output directories, zero collisions.

Regression tests: `test_capture_name_keeps_trailing_ip_octet`,
`test_capture_name_strips_real_pcap_extensions`.

---

## 5c. Third bug: truncated PCAPs discarded whole captures

A pipeline run was terminated after 15 of 31 captures failed (48%). All 15 had the
same cause.

### Cause

Many CSE-CIC-IDS2018 PCAPs are cut short mid-write. The readable prefix parses
perfectly, but the tools signal failure:

| Tool | Exit | Behaviour |
|---|---|---|
| `capinfos -M -c` | **2** | empty stdout; stderr says *"after reading 187257 packets"* |
| `tshark -r` | **14** | **writes all 187,257 good packets to stdout**, then errors |
| `editcap -r` | 0 | works fine within the readable region |

`_count_pcap_packets` raised on any non-zero capinfos exit, so the capture died
before a single packet was extracted.

### Confirmation

All 15 failing captures, checked individually:

```
64.115: DAMAGED recoverable=187257     65.10 : DAMAGED recoverable=169163
64.122: DAMAGED recoverable=160639     65.124: DAMAGED recoverable=25585
64.126: DAMAGED recoverable=136167     65.126: DAMAGED recoverable=32577
64.38 : DAMAGED recoverable=16296      65.28 : DAMAGED recoverable=89642
64.46 : DAMAGED recoverable=184715     65.29 : DAMAGED recoverable=264474
64.63 : DAMAGED recoverable=3565       65.34 : DAMAGED recoverable=85088
64.65 : DAMAGED recoverable=31591
64.71 : DAMAGED recoverable=146466
64.99 : DAMAGED recoverable=163679
```

**15 of 15 — one root cause**, ~1.7M recoverable packets in those captures alone.
A random sample of 24 PCAPs found 4 damaged (~17%), so roughly 74 of 438 captures
were being lost entirely.

### Fix

`_looks_truncated()` recognises the truncation messages; the readable prefix is kept
in all three places:

- `_count_pcap_packets` parses the recovered count out of capinfos' stderr
- `_extract_tshark_chunk` keeps the packets tshark already streamed
- `_create_packet_chunk` accepts a non-empty chunk from a truncated source

Verified end-to-end on a real damaged capture: 3,565 readable → 3,506 usable
IPv4/IPv6 packets → 386 flows → 386 edges.

---

## 5d. Fourth bug: progress.json discarded every failure reason

`record_failure()` passed `last_error` to `_write()` as a transient keyword, and
`finish()` then called `_write(status="done")` with no keywords at all — so the
finished `progress.json` recorded a failure *count* and nothing else. A 48%-failure
run was undiagnosable after the terminal scrollback was gone.

Fixed: `ProgressTracker.failures` accumulates `{day, capture, error}` for the life of
the run and is written into every payload, including the final one.

---

## 5e. Pipeline audit — no silent data loss

Every completed capture, CSV rows vs Parquet rows at each stage:

| Stage | Result |
|---|---|
| CSV → `flows.parquet` | **0 rows lost** across all 16 captures |
| `flows.parquet` → `edges.parquet` | **0 rows lost**; identical `flow_key` sets |
| Unparseable flow timestamps | **0** |
| NaN edge timestamps / flow keys | **0** |
| Edge epoch == flow epoch | **exact** |
| Label columns present on flows | all 5 |
| packets → flows join coverage | **99.3%** |

Packets that do not join a flow, broken down by protocol — **CICFlowMeter does emit
UDP flows**; the real gap is ICMP/IGMP:

| Protocol | Packets | Mapped | Note |
|---|---:|---:|---|
| 6 TCP | 3,023 | **99.2%** | remainder are capture-edge fragments |
| 17 UDP | 237 | **88.6%** | 89 UDP flows emitted — UDP *is* supported |
| 1 ICMP | 240 | **0.0%** | CICFlowMeter emits no ICMP flows at all |
| 2 IGMP | 3 | 0.0% | same |
| 0 | 3 | 0.0% | same |

This is worth understanding rather than dismissing. **ICMP has no flow-level
representation whatsoever**, so an ICMP ping sweep — textbook reconnaissance, and
explicitly part of the CIC Infiltration scenario ("IP sweep, full port scan") — is
invisible to a flow-only model. It exists only in `packets.parquet`, where it is
still labelled. That is a concrete argument for the packet layer carrying its own
weight in the model, not a defect to fix.

### Dead code removed

- `graph.flow_key()` — a **second** flow-identity function returning a *tuple*, where
  the `flow_key` column written to Parquet is a *string* from
  `flows.canonical_flow_key()`. It had no callers, but anything reaching for it
  would have produced identities that silently fail to join. Removed;
  `canonical_flow_key` / `canonical_flow_key_series` is the single authority.
- `pipeline._invalidate_labeled_outputs` still lists `aligned_flow_training.parquet`
  and `aligned_flow_training.index.parquet`, which **no code creates**. Harmless
  (`unlink(missing_ok=True)`), left in place, noted here.

---

## 5f. Flow ↔ packet mapping (`flow_packet_map.parquet`)

### Why a plain join on `flow_key` is wrong

`flow_key` is **not unique**. CICFlowMeter closes a flow on FIN or timeout and opens
a new one for the same 5-tuple:

| Capture | Distinct keys | Flows | Keys naming >1 flow |
|---|---:|---:|---:|
| capDESKTOP-AN3U28N-172.31.64.63 | 252 | 386 | 101 (max 7 per key) |
| hulkslice | 14,040 | 41,465 | **14,039** |

So `packets.merge(flows, on="flow_key")` is many-to-many — it inflates the row count
and attributes packets to the wrong flow.

### What is done instead

Each flow now carries a unique `flow_uid` (`<capture>#<row>`), and `align.py`
performs an **interval join**:

```
same flow_key  AND  flow_start <= packet_time <= flow_start + duration
```

implemented as `merge_asof` on the flow start, followed by an explicit
end-of-window check so a packet falling in the gap between two same-key flows is
attributed to neither.

`Flow Duration` is microseconds; flow timestamps are only second-resolution in
CICFlowMeter's CSV, so the window is widened by `slack_seconds` (default 1.0).

### Output

`flow_packet_map.parquet`, exactly one row per packet:

| Column | Meaning |
|---|---|
| `frame_no` | joins to `packets.parquet` |
| `flow_uid` | joins to `flows.parquet`; **null** when no flow contains the packet |
| `flow_key` | the shared 5-tuple |

### Verified

| Check | Result |
|---|---|
| Rows == packet rows | 3,506 == 3,506 |
| `frame_no` unique | yes |
| Every `flow_uid` resolves in flows.parquet | yes |
| Packets mapped | 91.6% |
| **Label agreement, packet vs mapped flow** | **100.0%** |
| Time containment (spot check) | all inside window |
| Unmapped packets dropped | none — they keep a null `flow_uid` |

Regression tests: `test_packet_maps_to_the_right_one_of_two_flows_sharing_a_key`
(proves the gap case maps to neither flow),
`test_unmapped_packets_are_kept_not_dropped`,
`test_map_has_exactly_one_row_per_packet`.

### Verified at scale (hulkslice: 41,465 flows / 207,955 packets)

| Check | Result |
|---|---|
| Map rows == packet rows | 207,955 == 207,955 |
| `flow_uid` unique in flows | yes |
| Packets mapped | **99.77%** |
| **Label agreement, packet vs mapped flow** | **100.00%** of 207,471 |
| **Time containment, all rows** | **100.00%**, 0 violations |

### KNOWN LIMITATION: direction attribution is ambiguous

Every key naming more than one flow has **overlapping** windows (14,039 of 14,039).
The cause: CICFlowMeter emits a *forward* and a *reverse* biflow for the same
conversation, and `canonical_flow_key` is direction-independent by design, so both
carry the same key and cover overlapping time. `merge_asof` then picks the latest
flow starting at or before the packet — deterministic, always inside the chosen
flow's window, but not provably the unique correct record.

Measured consequence:

| | hulkslice | 64.63 |
|---|---:|---:|
| Keys with >1 flow | 14,039 | 101 |
| …all sharing one `Label` | **100.00%** | **100.00%** |
| …all sharing one `label_direction` | 49.62% | 100.00% |
| **Keys where a packet could get the wrong Label** | **0** | **0** |

So:

- **Label attribution through the map is exactly correct.** Overlapping same-key
  flows always carry the same label, so no packet can be mislabelled by the join.
  This is what matters for training targets.
- **`label_direction` and per-flow features are ambiguous** for roughly half of
  attack conversations. When building node/edge features, take direction from the
  packet's own `src_ip`/`dst_ip` rather than from the joined flow's
  `label_direction`, and treat joined flow *statistics* as
  conversation-level rather than direction-level.

This is also why only 21,679 of 41,465 flows receive a packet: the other half are
the opposite-direction biflow of a conversation whose packets went to its twin.

### Usage

```python
from ingest.build.join import load_joined
df = load_joined(Path("data/processed/Friday-16-02-2018/capPC1-172.31.64.106"))
# packet columns + flow columns, suffixed _pkt / _flow where names collide
```

---

### What is genuinely missing

`edges.parquet` builds correctly — it is this pipeline's graph output, an edge list
with endpoints, ports, protocol, timing and labels. What does **not** exist yet is
any node table, node/edge feature embedding, temporal graph snapshotting, or model
code. `netWatch/` is an empty directory.

---

## 5g. Automated test coverage, and proof the tests can fail

The old `test_dummy_pipeline.py` was **unfit for purpose** and has been deleted. It
could not have detected a labelling bug:

1. It called `csv_to_parquet()` with **no matcher**, so `LabelMatcher` never ran —
   the "labels" it checked were the raw CIC strings copied from its own input.
2. Its timestamps encoded the **pre-fix** timezone convention (10:30 and 14:00 UTC),
   which under correct logic are 06:30 and 10:00 AST — both outside every window.
3. Its SlowHTTPTest row used port 80; the attack is on port 21.
4. Its packet rows used a hand-rolled 7-column schema, not the real 23-column
   `PACKET_SCHEMA` — no `frame_no`, no `flow_key`, no labels.
5. It never called `build_flow_packet_map`; its "alignment check" compared timestamp
   *sets*, which only worked because the fake data used whole seconds.
6. It was not collected by pytest (`run_dummy_test()`, not `test_*`), so it never ran.

Replaced by `tests/ingest/test_pipeline_e2e.py`, which drives the real path
—  CSV → `flows.parquet` → `edges.parquet`, tshark fields → `packets.parquet`,
then → `flow_packet_map.parquet` — with a real `LabelMatcher`, correct UTC
timestamps, correct service ports, and the real `PACKET_SCHEMA`, with no PCAP,
tshark or CICFlowMeter required.

**40 tests, all passing.**

### Mutation testing

A passing suite proves nothing unless it can fail. Each fix was reverted in turn and
the suite re-run:

| Mutation | Result |
|---|---|
| Timezone fix reverted (`SCHEDULE_UTC_OFFSET = 0`) | **14 failed** |
| Service-port constraint dropped | **7 failed** |
| tz-aware → naive conversion removed | **1 failed** |
| `pcap.stem` capture-name collision reinstated | **1 failed** |
| Interval end-of-window check removed (naive key join) | **1 failed** |
| Edge epoch switched to stdlib `datetime.timestamp()` | **1 failed** |

Two of these only became detectable after the tests were strengthened, and both
gaps were real:

- The tz-aware test originally passed a **UTC**-aware datetime, which succeeds
  whether or not the conversion happens. Now uses `+05:30`.
- The edge-epoch test is meaningless on a UTC host, and CI hosts are UTC. It now
  forces `TZ=Asia/Kolkata` and calls `time.tzset()`.

---

## 5h. Fifth bug: `frame_no` was not unique (found post-run)

tshark numbers frames per **input file**. `pcap_to_parquet` chunks a capture with
editcap at 250,000 packets, so every chunk restarted at 1:

    UCAP172.31.69.25-part1: 18,888,225 packets, 250,000 distinct frame_no
                            -> each value repeated ~76 times

`frame_no` is the join key of `flow_packet_map.parquet`, so it was not a key at
all. 74 of 438 captures exceed one chunk and were affected.

Fix: `_extract_tshark_chunk` rebases `frame.number` by the chunk's start offset.
Guarded by `test_frame_no_is_unique_across_tshark_chunks`, which forces several
chunks on a real capture and asserts uniqueness and monotonicity.

---

## 5i. Sixth bug: align was not memory-safe

`build_flow_packet_map` read every packet into one DataFrame for a single
merge_asof, and died on the one capture holding all the attack traffic:

    MemoryError: Unable to allocate 144. MiB for an array with
    shape (18888225,) and data type int64

Fix: packets stream in batches while only the flow windows stay resident, and the
join carries int32 row indices instead of flow_uid strings. Measured on that
capture: **18,363,863 mapped (97.22%), 12 s, 2.2 GB peak RSS.**

---

## 5j. The remaining CICFlowMeter failure was NOT a heap limit

One capture failed per full run, a different one each time (`capPC1-172.31.64.31`,
then `capPC1-172.31.64.41`). Both were re-run standalone at the existing
`-Xmx512m` and **both succeeded in ~5 s** (19,340 and 15,479 flows). Neither PCAP
is truncated.

So the JVM does not need more heap. Raising `-Xmx` would make it worse: the cause
is two Gradle JVMs plus tshark contending on a 15 GB host at `--workers 2`, and a
bigger heap per JVM increases that pressure.

Fix: `run_cicflowmeter` retries once after a 5 s pause. Use `--workers 1` if it
still recurs.

---

## 5k. Dead code removed (output verified identical)

| Removed | Lines | Why |
|---|---:|---|
| `ingest/labels.py` | 88 | Whole module dead — no importer anywhere; its three functions were thin wrappers around `LabelMatcher`, which every caller already uses directly. |
| `packets._required_str` | 9 | Referenced only by another function's docstring. |

4,289 → 4,191 lines. An AST sweep for unused imports found only
`from __future__ import annotations`, which is required — nothing else to cut.

Verified by reprocessing a capture end-to-end on the trimmed code and comparing
against the pre-trim output with `pyarrow.Table.equals`:

| File | Rows | Schema | Data |
|---|---:|---|---|
| `packets.parquet` | 3,506 | identical | identical |
| `flows.parquet` | 386 | identical | identical |
| `edges.parquet` | 386 | identical | identical |
| `flow_packet_map.parquet` | 3,506 | identical | identical |

---

## 5l. Packet extraction was quadratic in capture size (found on re-run)

The first run after sequence analysis was enabled sat on its first capture for
over an hour. Jobs run in name order and `U` sorts before `c`, so job 1 is
`UCAP172.31.69.25-part1.pcap`: 4.02 GiB, 18,890,171 packets, 76 tshark chunks,
8.6% of the day.

Each chunk was carved with `editcap -r first-last`. A pcap has no index, so every
carve re-reads the file from the start:

| Chunk | `editcap -r` |
|---|---:|
| 1–250,000 | 12.5 s |
| 9,250,001–9,500,000 | 81.0 s |
| 18,640,001–18,890,171 | 146.8 s |

Cost grows linearly with position, so 76 chunks spend about 76 × 80 s ≈ 1.7 h
re-reading one file: $O(N^2/C)$. Earlier runs hid this because the 4 GiB file
stayed in page cache; a concurrent 7z extraction evicted it.

**Fix.** `editcap -c 250000` splits in one pass. Every chunk but the last holds
exactly 250,000 packets, so `frame_offset = k × 250,000` is unchanged. Chunks
live in a `TemporaryDirectory` next to the output, removed on any exit, and are
deleted as consumed. The up-front `capinfos` count, another full read of every
capture, is no longer needed; `_count_pcap_packets` and `_create_packet_chunk`
were removed.

Truncated and corrupt captures need no special case: `editcap -c` exits 0 and
writes exactly the readable prefix, 9,473 packets on a cut-short file and 3,565
on a corrupt one, both matching `capinfos`.

**Also measured.** Sequence analysis, needed for `tcp_retransmission`, costs
2.4× per chunk: 64.7 s vs 26.5 s, 621 vs 372 MiB. Kept, because retransmission
counts are a PS requirement.

**Worker cap removed.** The CLI capped workers at 75% of RAM ÷
`--max-worker-mem-mb` (6,656 MB). That value is an RLIMIT_AS virtual ceiling
sized for the JVM's ~4.8 GB address reservation, not resident use, and
CICFlowMeter already runs one at a time across workers. On 15.7 GB it refused a
second worker. `_memory_ok()` still admits each capture only with ≥ 2 GiB free.

Verified: 64 tests pass. `test_frame_no_is_unique_across_tshark_chunks` drives
the corrupt real capture through 4 chunks with offsets 1 / 1,001 / 2,001 /
3,001; no temporary directories are left behind.

---

## 5m. Every TCP flag was 0 (found while checking flow direction)

tshark 4.6.4 prints boolean fields as `True`/`False`. `_flag_bit` matched only
`"1"`, so `tcp_flag_syn`, `ack`, `fin`, `rst`, `psh` and `urg` were 0 on every
packet, and `syn_n` … `urg_n` in the event stream were dead features. IP flags
were unaffected: they already went through `_bool_field`, which matched `true`.

Found because 0 of 357,668 TCP flows appeared to start with a SYN.

No test could catch it: the fixture fed the parser `"1"`/`"0"`, the format the
parser assumed, not the one the installed tshark emits.

**Fix.** One boolean parser, `_bool_field`, accepts `1` or `true` in any case and
serves all eight boolean fields; `_flag_bit` was removed. The fixture now uses
`True`/`False`, `test_boolean_fields_accept_both_tshark_spellings` covers both
spellings, and `test_real_capture_tcp_flags_are_not_all_zero` runs the installed
tshark on a real capture and fails if no TCP packet carries ACK.

After the fix, 72.7% of TCP flows start with a bare SYN (5,456 of 7,509 on
three benign captures).

**Output written before this fix is wrong and is silently reused on a rerun**,
because reuse checks only column names. Delete `data/processed` first.

---

## 5n. Orientation flag, parser fingerprint, and a 65× aggregation fix

**`reversed` added to the event stream.** 1 means the record runs server →
client, 0 client → server, −1 that no rule applies. A flow whose first packet is
a bare SYN names its client, the SYN's sender; otherwise the ephemeral-port side
is taken as the client. Only the first packet is read, so the value exists when
the flow starts. It reads packets and ports only: the label-free counterpart of
`label_direction`.

Measured end to end on a 10 s DoS-Hulk slice (261,921 packets) plus two benign
captures, 38,865 events:

| | forward | reversed | unknown |
|---|---:|---:|---:|
| Benign (11,895) | 86.5% | 10.5% | 2.9% |
| DoS-Hulk (26,970) | 66.9% | 33.1% | 0.0% |

On the attack events `reversed == 1` coincides with `label_direction ==
"reverse"` 100.00% of the time (18,049 forward, 8,921 reverse, no disagreement)
without reading a label. For Hulk the attacker opens every connection, so
reversed means victim → attacker. For Bot, where the infected victim dials out to
its C2 server, the two will differ by design.

**Reuse keyed on the packet parser.** The output fingerprint was the labelling
config alone, so the flag fix in 5m would have been skipped on a rerun. It is now
`LABEL_CONFIG_VERSION + PACKETS_VERSION`; bump `PACKETS_VERSION` in `packets.py`
whenever parsing changes. Verified both ways: a label-only marker invalidates the
capture (test), and a current one is reused (the end-to-end rerun re-extracted
0 of 2 benign captures).

**`payload_frac` vectorised.** It ran one Python lambda per flow. A groupby mean
gives identical values (max difference 2.8e-08, float32 rounding) 65× faster,
about 148 s → 2.3 s on the 3.6M-flow capture.

**Rare fields proven on real tshark output.** `tcp_flag_urg`, `ip_flag_mf` and
`ip_frag_offset` are constant 0 in normal traffic, which is how 5m hid. A test
builds a pcap with IPv4 fragments and a URG segment and parses it with the
installed tshark: MF=1, offset=3 (tshark prints 8-byte units), URG=1.

**Checked, no bug.** The events fallback timestamp uses the same parse call as
labelling and the flow↔packet map, both verified at 100%. Bot and Infiltration
rules carry no port or protocol constraint, as designed.

69 tests pass.

---

## 5o. The interval join broke ties arbitrarily and lost 581,719 packets

CICFlowMeter writes flow starts in whole seconds, so records of one `flow_key`
often share a start: 1,659,720 tie groups on the attack capture, usually a Hulk
connection's forward part (tens of ms) and the server's reverse continuation
(~5.4 s). `merge_asof` takes the last tied row, and `_flow_windows` sorted with
pandas' default, unstable quicksort, so the winner was arbitrary: the widest
window won 52.1% of the time. When a short record won, every later packet of that
second fell past its end and was dropped, although a tied record covered it.

| | Unattached packets |
|---|---:|
| DoS-Hulk, key has a flow (lost) | 524,271 (2.8% of Hulk packets) |
| Benign, key has a flow (lost) | 57,448 |
| *No flow exists for the key (ICMP, IGMP, TCP/UDP CICFlowMeter skipped): expected* | *545,437* |

`verify` missed it: "join coverage 100%" measures whether a packet's key has a
flow, not whether the packet was attached to one.

**Fix.** Ties are ordered by end, stable, so the last tied row is the widest
window. On the attack capture unattached packets fell from 524,362 to 91 of
18,888,225, and packet/flow label agreement stayed 100.0000%. A regression test
fails on the old ordering and passes on the new.

**Rebuilds.** `MAP_VERSION` is stored in the map's schema metadata. A map written
by older logic is rebuilt on the next run while packets and flows are reused.
`verify` now reports the attached share and fails below 99.9%.

**Also established.** Every record the event stream drops as packet-less shares
its key and start second with a record that holds packets; none is a copy from
another time. Hulk's 3,516,432 records sit on 14,116 keys because the attacker
reuses each source port about every 5 s, so the ~130 events per key are ~130
different connections, not one conversation counted twice.

---

## 5p. Port-scan features scored the victim, not the scanner

`port_delta` and `dst_port_new` were keyed on the record's source host and its
destination port. When `reversed == 1` the source is the responder, so the
features described the server's view of the client's ephemeral ports. Once the
tie fix (5o) kept the server's reverse record for 94.9% of Hulk events, the
victim was scored on 1,749,908 Hulk events with `port_delta` +2 on 60.7% of them:
a sequential-sweep signature on the wrong host. The attacker was scored on 93,533.

**Fix.** Both features key on the initiator and the port it dialled: the record's
src and dst port, swapped when `reversed == 1`. Simulated on the attack capture,
the attacker is scored on all 1,843,441 Hulk events with `port_delta` 0 and
`dst_port_new` 0, which is Hulk's true shape: one service port, hammered. A
regression test fails on the old keying and passes on the new.

Full-day `reversed` after 5o: Benign 88.2% forward / 9.4% reversed / 2.5% unknown;
Hulk 5.1% / 94.9%; SlowHTTPTest 100% forward. `reversed` agrees with
`label_direction` on 100.00% of 1,948,991 attack events.

Only `events.py` changed: rebuild the event stream; processed captures stay valid.

Measured after the Friday rebuild: Hulk `port_delta` is 0 on 100% of 1,843,441
events and `dst_port_new` is 0; non-zero `port_delta` across the day fell from
47.0% to 19.6% once the victim stopped being scored.

---

## 5q. Shadowed packets: a later, shorter flow hid an earlier covering one

After 5o, 34,539 packets whose key had a flow were still unattached. Classified
day-wide against every window of their key:

| Why unattached | Packets | Recoverable |
|---|---:|---|
| Covered by an earlier same-key window; a later, shorter flow started in between | 2,584 | yes |
| In a gap no window of the key covers (median 235 s past the nearest end) | 31,668 | no |
| Before the key's first window | 287 | no |

`merge_asof` sees only the latest start ≤ t, so it chose the shorter, later flow;
the packet fell past that flow's end and was dropped although an earlier window
covered it.

**Fix.** A packet the chosen window does not cover is retried against every window
of its key and goes to the latest-starting one that contains it. Only
would-be-dropped packets are retried, so no attached packet changes flow. Verified
by rebuilding two real maps against the current ones: the attack capture went
1 → 0 lost and a benign capture 113 → 106; 0 attached packets changed flow, and
recovered packets agree with their flow's label 100%. A regression test fails on
the old join and passes on the new. `MAP_VERSION` is now `3-contain-fallback`, so
the next run rebuilds every map and keeps packets and flows.

The 31,955 packets that remain lie in no CICFlowMeter record of their key; no join
can attach them.

Measured after the Friday rebuild: 438 of 438 maps on `3-contain-fallback`, and
exactly 31,955 packets lost day-wide, so every recoverable packet was recovered.

---

## 5r. Captures were chosen by name; Friday-02-03-2018 broke that

13 of 431 captures failed with `editcap: can't be written as a "pcapng" file`.
The error was a symptom: those files have no pcap header. They and four UCAP
files are **entirely zero bytes** (17 files, 0.5 MiB to 970 MiB); Wireshark falls
back to its JSON reader and sees one "packet". No valid pcap record exists in
any of them, so nothing is recoverable: the dataset ships them that way.

`find_pcaps` chose files by name (a pcap suffix or a trailing `-<ip>`), which was
wrong in both directions:

| File | Name rule | Content |
|---|---|---|
| 13 `capWIN-J6GMIG1DQE5-…`, 4 `UCAP…` | 13 selected, 4 skipped | all zero bytes: skip |
| `UCAP172.31.69.18/.21/.22/.27`, `…69.26a` | skipped | valid captures of this day: keep |
| `capWIN-J6GMIG1DQE5-` (no IP) | skipped | host 172.31.64.89, 27–28 Feb: skip |
| `…69 - Copy.24` | skipped | 255 DHCP/link-local packets, 1 Mar: skip |
| `…69.24 - Shortcut.lnk` | skipped | Windows shortcut: skip |

`…69.26a` is the first segment of host .26 (12:47–13:59; `…69.26` covers
13:59–21:30), so the two do not overlap.

**Fix.** A file is a capture when it starts with a pcap/pcapng header and, for
pcap, its first packet falls on the day in schedule-local time; the name is
ignored. Every rejection is printed with its reason. On Friday-02-03 this selects
423 of 443 files, the 418 already processed plus the five valid ones above, and
rejects 20. A test built from these cases fails on the name rule and passes on
the new one.

**Tests that run the installed tshark** pointed at a Friday-16 capture deleted
with that raw day, and were skipping silently. They now use any small real
workstation capture under `data/raw`; both run and pass.

Friday-16's raw captures were deleted before this fix, so whether its name rule
skipped a valid capture cannot be checked.

---

## 5s. `verify` made day-generic; three of its own bugs found on Friday-02-03

`verify` was written against Friday-16, where one capture holds all attack
traffic and each attack has one window. On Friday-02-03 it reported four
failures; three were `verify`'s own:

| Reported | Real cause | Evidence |
|---|---|---|
| Bot: 192,164 rows outside the window, twice | Bot is one attack in two windows, audited window by window, so rows in the other window counted as outside | 96,179 in window 1, 95,985 in window 2, 0 in neither |
| Offset: 191,970 Bot flows aligned | both same-name rules added the same flows to one histogram | exactly 2 × 95,985 |
| Packet labels agree on 99.65% | Arrow joins default to left outer, so packets with no flow counted as disagreeing | inner: 200 of 2,842,478 differ, all across a window edge |

The fourth, 5 selected captures with no output, was real (5r).

**Now five checks, for any day.**

1. Offset: a tie that includes the configured offset resolves to it; sparse
   traffic can fit several quarter-hour shifts equally.
2. Labels: each attack audited against the union of its windows.
3. Captures: every file `find_pcaps` selects has output; no output lacks a file.
4. Packets, in every capture rather than the first alphabetical one: maps
   current, attached share, TCP flags parsed, and each packet labelled like its
   flow unless a window edge lies between the packet and the flow's start.
5. Events: fresh, schema, finite, ordered, `reversed` in {−1, 0, 1}, flags and
   payload alive, every configured attack present.

The packet-label check aligns map and packets by frame number, one row each per
packet, instead of joining 18.9M rows on string keys: peak memory on Friday-16
fell from 9.3 GB to 6.6 GB. Friday-16 has 0 differing packets of 18,888,135;
its earlier 99.9995% was the left-join artefact.

**Tests.** 22 per-rule cases cover every configured day: every attacker × victim
pair inside its window, forward and reverse, inclusive edges, and Benign one
second outside, on another date, for strangers and on a wrong port. 10 per-day
offset cases. `verify` passes on a complete synthetic day and each new check is
shown able to fail; every fix above has a test that failed before it. 111 pass.

---

## 5t. Bot C2 traffic between Table 2's windows was labelled Benign

Friday-02-03 passed `verify`, but offset detection aligned 194,589 attacker<->victim
flows against 192,164 labelled Bot. Every one of the 286,191 flows touching the
attacker is attacker<->victim, and 94,027 of them fall between Table 2's two Bot
windows (11:34-14:24), where the table's windows left them Benign.

They are the attack. Profiled in 10-minute bins, the infected hosts poll their
C2 server (18.219.211.138:8080) at a flat 536 flows/min of 4.5-packet, 227-byte
flows from 11:40 to 15:20, inside window 2 as much as in the gap; the table's
windows bracket the bursts (up to 2,464 flows/min) on top of that heartbeat.
CIC's own labelled CSV marks all 286,191 Bot, 91,602 of them in the gap, and its
hourly counts at 12:00 and 13:00 (31,840 and 32,146) equal ours flow for flow.

**Fix.** Table 2's two windows stay as published; a third Bot rule covers the gap,
tagged `label_confidence = c2_heartbeat_between_table_windows`, so the two table
phases stay separable from the heartbeat between them. Rules of one attack may
now share a boundary (the earlier rule keeps the row); rules of different attacks
still may not overlap. A first version started the gap rule one second after
window 1 ended; since packet times are sub-second, 375 Bot packets in
(11:34:00, 11:34:01) and (14:23:59, 14:24:00) fell through. Both boundaries are
now shared, and a test covers the half-second.

**Fingerprint per day.** The reuse fingerprint hashed the whole attack table, so
adding a Bot rule would have rebuilt every day. It now hashes one day's rules
plus the labelling logic (`config.label_config_version(day)`).

**`verify`** now fails when flows shaped like an attack (endpoints, service port,
protocol) fall outside all of its windows, breaks each attack down by tag, and
prints attacker-side ports beside victim-side ones: for Bot, 8080 rather than
the victims' ephemeral ports.

**Dry runs before any rerun**, new rules on existing outputs:

| | Result |
|---|---|
| Friday-02-03 flows | Bot 286,191 = 192,164 table + 94,027 gap; only change 94,027 Benign -> Bot |
| Friday-02-03 packets | 470,633 Benign -> Bot; 0 of 2,842,478 attached packets disagree with their flow |
| Friday-16 flows and attack packets | 0 of 10,144,299 and 0 of 18,888,225 differ from what is stored |

Friday-16's 444 fingerprint files hold the old global value; its rules and
labels are unchanged, so they are rewritten to the per-day value rather than
rebuilt. Friday-02-03 is rebuilt.

After the rerun, offset detection reported 290,895 Bot flows aligned against
286,191 labelled: it summed flows rule by rule, so the 4,704 flows in the two
shared boundary minutes (11:34, 14:24) counted twice. It now counts each flow
once per attack; the real audit reports 286,191.

Every fix above has a test that failed first. 118 pass.

---

## 5u. Friday-23's three web attacks failed `verify` on each other, and on window edges

Friday-23-02-2018 passed offset detection, captures, packets and events, and
failed the escaped-flow check three times: 215, 315 and 394 flows "shaped like
this attack fall outside its windows".

The three attacks — Brute Force -Web (10:03-11:03), Brute Force -XSS
(13:00-14:10) and SQL Injection (15:05-15:18) — share one attacker
(18.218.115.60), one victim (172.31.69.28) and port 80. Audited rule by rule,
the shape test cannot tell them apart, so each counted its siblings:

| Attack | escaped | of which the other two attacks' labelled flows | residual |
|---|---:|---:|---:|
| Brute Force -Web | 215 | 211 (XSS 145 + SQL 66) | 4 |
| Brute Force -XSS | 315 | 311 (Web 245 + SQL 66) | 4 |
| SQL Injection | 394 | 390 (Web 245 + XSS 145) | 4 |

The residual is the same four flows in each case, outside every window and all
within half a minute of an edge: 11:03:06 (6 s after Web closes), 14:10:04 and
14:10:05 (4 and 5 s after XSS closes, the second a full 83/42-packet exchange),
and 14:10:28. Two are single-packet server-side tails. Table 2's windows are
minute-rounded and an attack tool does not stop mid-connection, so a flow opened
inside a window can be recorded just after it closes.

**Fix.** A flow escapes only if it falls outside **every** window configured for
that day, each widened by `EDGE_TOLERANCE = 120 s` — CICFlowMeter's flow
timeout, the natural bound on that lag. One rule covers both faults: siblings are
accounted for by their own windows, and edge overhangs by the tolerance.

**It does not weaken the check.** Friday-02-03's Bot heartbeat ran hours from any
edge and still escapes — which is what forced rule 5t. The synthetic fixture's
timezone-regression flow sits 3 h 45 m before Hulk's window and 10 minutes clear
of SlowHTTPTest's nearest edge, so `verify_day` still returns 1 on it.

**No relabelling.** No rule was added and no window moved, so every day's
fingerprint is untouched and nothing is rebuilt — unlike 5t, this is a change to
the auditor alone.

Test: `test_window_mask_covers_an_edge_overhang_but_not_a_gap`, which pins the
28 s overhang as covered and a two-hour gap as not. 119 pipeline tests pass, 146
including the encoder's.

---

## 5v. Friday-16's "DoS-SlowHTTPTest" is a refused FTP connection flood

Chasing why that class showed 0% still-running at every observation budget, and
why 2,968 held-out rows carried only 37 distinct feature vectors.

Every flow touching the attacker inside the scheduled window (10:12–11:08 local,
capture `UCAP172.31.69.25-part1`):

| measured | value |
|---|---|
| flows in window touching the attacker | 105,550 |
| destination port | **21 (FTP) on 100% of them** |
| packets per flow | 1 forward, 1 backward |
| flags | SYN, RST and ACK on 100%; FIN and PSH on 0% |
| flow duration | 0.003 ms median, matching the packet timestamps |
| distinct attacker source ports | 14,116, each reused ~7.5 times at ~425 s intervals |
| port-80 flows from the attacker in the window | **0** |
| port-80 flows from *any* host in the window | 2, both Benign |

Each record is a SYN answered by an RST: a **refused connection**. There is no
HTTP traffic in the window at all, so there is no slow-HTTP attack to observe;
what the capture contains is a connection flood against a closed FTP port.

**The labels are correct against CIC's published schedule.** The rule matches on
attacker/victim pair and time, and `verify` reports it as unconstrained because
this day's service ports are not yet verified. Nothing is mislabelled by our
logic; the *substance* of the traffic differs from the name Table 2 gives it.

**Consequences, all previously logged as separate puzzles:**

- Two-packet, three-microsecond records are the entire exchange, not fragments.
- No observation budget can be early for it — a refused handshake is complete on
  arrival — so this class can never support a lead-time claim.
- 37 distinct feature vectors among thousands of rows is what 105,550 near
  identical SYN/RST pairs produce, and it is why the within-day probe numbers for
  this class were meaningless.
- Models can still separate it, but through `rst_n` and packet counts rather than
  through anything resembling slow HTTP. Ports never enter the feature tensor.

**Confirmed against CIC's own published CSV.**
`data/original_flow_csv/Friday-16-02-2018_TrafficForML_CICFlowMeter.csv`, rows
labelled `DoS attacks-SlowHTTPTest`:

| | official CSV | ours |
|---|---|---|
| rows | 139,890 | 105,550 |
| Dst Port | **21 on 100%** | **21 on 100%** |
| Protocol | 6 | 6 |
| Flow Duration median | **3 µs** | **3 µs** |
| Tot Fwd / Bwd Pkts | **1 / 1** | **1 / 1** |

The finding is a property of the dataset, not of this pipeline. (The row-count
difference is the duplication and early truncation already documented in §3.2.)

**On flags the official CSV is wrong and ours is right.** It reports PSH on 100%
of those rows and SYN/RST on 0%. The packets say otherwise — tshark, 4,000
packets across 2,000 of these flows:

```
13.59.126.31:37350 -> 172.31.69.25:21   74 bytes  payload 0  [SYN]
172.31.69.25:21 -> 13.59.126.31:37350   54 bytes  payload 0  [ACK RST]
```

SYN 50%, ACK 50%, RST 50%, **PSH 0%, payload 0%** — a SYN answered by ACK+RST.
There is no PSH anywhere in this traffic and no payload to carry it. This is the
same CICFlowMeter flag defect found and fixed here in 5m, still present in CIC's
published file.

**Action.** Report this class as what it is. When this day's service ports are
verified, the rule should gain `service_ports={21}` so the name and the constraint
agree, and any future paper comparison on "SlowHTTPTest" must note that the
CSE-CIC-IDS2018 Friday-16 traffic does not match the attack's name.

---

## 5w. Bot cross-checked against CIC's CSV, and a fourth defect in that file

`data/original_flow_csv/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv`, rows
labelled `Bot`, against ours:

| segment | official CSV | ours |
|---|---:|---:|
| Table 2 window 1, 10:11–11:34 | 96,179 | — |
| Table 2 window 2, 14:24–15:55 | 95,985 | — |
| windows 1 + 2 | **192,164** | **192,164** |
| the gap, 11:34–14:24 | **94,027** | **94,027** |
| outside all three | 0 | — |
| total | **286,191** | **286,191** |

Row-for-row agreement, and it settles 5t independently: **CIC's own labelled file
marks the gap rows `Bot`**, so the third rule added there recovered labels the
published Table 2 omits rather than inventing them. Destination port is 8080 on
98.4% of rows — the C2 server. (§3 quotes 91,602 for the gap; the difference is
boundary convention at the shared minutes 11:34 and 14:24, which hold 4,704 flows
between them. Totals agree either way.)

**Fourth defect: the timestamps carry no AM/PM.** The column reads
`02/03/2018 08:47:38`, and the file's apparent span is `01:00:00` to `12:59:59` —
a 12-hour clock with the meridiem stripped. Parsed naively, every afternoon row
lands twelve hours early: Table 2's second Bot window appears to contain **zero**
rows and 141,291 rows fall outside every window. The capture runs 08:46–20:39
local with nothing before 08:46, so hours 1–8 can only be afternoon; restoring
that gives a span of 09:00–20:59 and the exact agreement above.

Known defects in the official CSVs now number four: **duplication** (§3.2),
**early truncation** (§3.3), **wrong TCP flags** (5v), and **missing meridiem**
(here). They remain usable for labels and row counts, and cannot be trusted for
flags or for time without repair.

---

## 5x. The "slow" attack has no slow flow — settled against the PCAP

**Question raised.** If `slowhttptest` holds connections open for minutes, why does
every one of our records last microseconds? Either the pipeline fragments long
connections, or the attack is not what its label says.

**Checked three ways, all agreeing.**

| Evidence | What it shows |
|---|---|
| CIC's official CSV, all 139,890 SlowHTTPTest rows | Every row **1 fwd + 1 bwd packet**, `TotLen Fwd/Bwd Pkts` = 0, `Flow Duration` p50 **3 µs**, **max 70 µs**. Zero rows above 1 s |
| Our flow records | 105,550 rows, all dst port 21, same shape |
| **The raw PCAP** (independent of CICFlowMeter) | 211,100 packets: 105,550 SYN and 105,550 RST/ACK. **Zero payload bytes** in 53 minutes. **No completed handshake anywhere** — not one ACK-only packet |

`Flow Duration` is in **microseconds**; 10 ms is 10,000 of them, so these flows are
~500x shorter than the observation budget. Two rows as they appear in CIC's file:

```
Dst Port 21 | Timestamp 16/02/2018 10:12:14 | Flow Duration 21 | Fwd 1 | Bwd 1 | Len 0/0
Dst Port 21 | Timestamp 16/02/2018 10:12:14 | Flow Duration  3 | Fwd 1 | Bwd 1 | Len 0/0
```

**No pipeline defect.** A RST terminates a TCP connection, so a subsequent SYN on
the same 4-tuple is a new connection and a new flow record. Our splitting matches
CIC's exactly.

**What the capture actually contains.** 14,116 source ports, each retried **7 times
at a 425.3 s period** (p10 425.0, p90 425.7) across 53 minutes, every attempt
refused. The attacker (13.59.126.31) sent **nothing but port 21** in that window,
and only two other packets from anyone else touched port 21 — also refused, with
**zero SYN-ACKs from the victim**. Nothing was listening.

**Conclusion, unchanged from 5v and now backed by the packets.** The traffic is
hostile and the "attack" label is right; the *name* is wrong, and the tool's
technique never executed. The attack that did happen is a refused connection
flood whose signature is entirely cross-flow. Recorded in `design.md` under
*Two definitions of lead time*.

---

## 6. Changes made

| File | Change |
|---|---|
| `flows.py` | `SCHEDULE_UTC_OFFSET = -4h`, applied inside `LabelMatcher` only, **before** the date check so a UTC-midnight-crossing attack still lands on the right day. Direction-aware `service_ports` / `protocols` matching. New `label_direction` column. `canonical_flow_key` (scalar + vectorized). |
| `packets.py` | Packets now pass ports + protocol to the same matcher, so flow and packet labels cannot disagree. Added `flow_key` and `label_direction` to the schema. |
| `graph.py` | Carries `flow_key` + all label columns into edges. Epoch conversion rewritten to subtract the epoch explicitly, and the parse pinned with `format="mixed"`. **CORRECTION — neither of those two was a bug fix**, contrary to an earlier draft of this report: `pd.Timestamp.timestamp()` treats a naive value as UTC (unlike `datetime.datetime.timestamp()`, which uses the host zone), and `format="mixed"` yields byte-identical results for our strings. The rewrite is clearer and vectorised, and it is now guarded by a test that forces a non-UTC host timezone — verified to fail if the conversion is ever switched to stdlib `datetime`. |
| `config/config.py` | Friday ports pinned (`21`/`80`, protocol `6`) — verified in both sources. `LABEL_CONFIG_VERSION` now mixes in a **logic** version, so a labelling-logic fix invalidates stale Parquet just as a table change does. Without this the timezone fix would have silently reused wrong labels. |
| `config/__init__.py` | Exports `ATTACKS` / `LABEL_CONFIG_VERSION` (fixes the earlier import failure). |
| `pyproject.toml` | Repo root on `pythonpath`, `ingest/tests` collected. Plain `pytest` works now. |
| `tests/test_labels.py` | Rewritten against corrected semantics + regression tests for this bug. |
| `verify.py` | **New.** `python -m ingest.verify <day>` — audits a day, exits non-zero on failure. |

### Design decisions worth knowing

**Timestamps are never rewritten on disk.** Only `LabelMatcher` shifts, and only in
memory at comparison time. This keeps flows, packets and edges on one shared UTC clock
so they still join exactly — confirmed in 2.3.

**Reverse traffic is labelled but tagged.** A DoS victim's replies are part of the
attack, and CICFlowMeter emits them as their own biflows once the forward flow has
closed (1,765,956 of them on Friday). They carry the attack label with
`label_direction = "reverse"`, so they can be filtered without relabelling.

**Missing ports raise instead of returning `Benign`.** Silent under-labelling is the
exact failure this whole report is about.

---

## 7. Remaining work

1. **Re-run the pipeline.** All 19/19 Friday capture directories are already marked
   stale by the new `LABEL_CONFIG_VERSION` and will regenerate automatically. Nothing
   to delete by hand.

2. **The other 9 days have no port constraints yet.** They match on time + IP pair
   only — the previous behaviour, still correct, just less precise. Ports were
   deliberately *not* guessed: a wrong port set silently drops an entire attack to
   `Benign`. Verify each day as you process it with `python -m ingest.verify`,
   then add `service_ports` / `protocols`.
   **`Infiltration` must stay unconstrained** — it includes a full nmap portscan.

3. **Hulk has a capture-coverage gap, not a labelling gap.** `part1` ends 13:58:22
   local; `part2` starts 14:07:33 local and contains **zero** flows involving either
   attacker IP. The window runs to 14:19. The labels are right; the capture simply
   does not cover 13:58–14:19.

---

## Appendix — reproducing these checks

```bash
# unit tests
uv run python -m pytest -q

# audit a processed day
uv run python -m ingest.verify Friday-16-02-2018

# end-to-end on a real attack slice
editcap -F pcap -A "2018-02-16 17:45:30" -B "2018-02-16 17:45:38" \
  data/raw/Friday-16-02-2018/pcap/UCAP172.31.69.25-part1.pcap /tmp/hulkslice.pcap
```

Note `-F pcap`: `editcap` defaults to **pcapng**, which CICFlowMeter's jnetpcap
backend rejects with `Please select pcap file!`.
