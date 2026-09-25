# `ingest` — packet captures to a labelled event stream

## Purpose

Turns raw CSE-CIC-IDS2018 PCAP captures into the event stream every downstream stage reads. One event per network
flow, ordered by microsecond timestamp; time is never binned into fixed windows.

This stage runs once per dataset day and is the only part of the system that touches PCAPs.

## Function

1. Parse each capture into packet records (`tshark`).
2. Produce CICFlowMeter flow records for the same capture.
3. Join flows to their packets, so an event carries both its record and its first packets.
4. Apply the published attack schedule to label each flow, and verify the result.
5. Emit the event stream and a per-day ip → node id index.

## Layout

Three phases, in the order data moves through them.

```
ingest/
  cli.py          entry point: per-capture scheduling with memory guards
  pipeline.py     orchestrates one capture end to end
  sources/        raw inputs to parquet
    packets.py    PCAP to packet parquet, via tshark
    flows.py      CICFlowMeter records, label matching, the UTC offset
    schedule.py   the attack schedule and a versioned label configuration
  build/          deriving the event graph
    join.py       joins flows to their packets, builds the edge list
    events.py     the event stream, and the ip to node id index
    nodes.py      per-window host aggregates
  verify/
    checks.py     the audits
```

`ingest.verify` and `ingest.build.events` are both runnable:

```bash
uv run python -m ingest.build.events <day>
uv run python -m ingest.verify <day>
```

## Inputs and outputs

**In:** `data/raw/<day>/*.pcap` and the official flow CSVs.
**Out:**
- `data/processed/<day>/<capture>/{flows,packets,flow_packet_map}.parquet`
- `data/events/<day>/events.parquet` — the event stream
- `data/events/<day>/node_index.parquet` — the ip → node id map
- `data/nodes/<day>/nodes.parquet` — per-window host features

## Running

```bash
uv run python -m ingest.cli --days all --workers 1 --max-worker-mem-mb 6656
uv run python -m ingest.verify --days <day>
```

`--max-worker-mem-mb` is a hard `RLIMIT_AS` per worker. It must stay comfortably above the JVM's virtual-memory
reservation (~4.8 GB observed) or CICFlowMeter will not start; the default of 6656 MiB accounts for this. A worker that
would exceed the ceiling fails cleanly and is recorded as a normal job failure, rather than risking a system-wide OOM
kill that can orphan a child process.

## Notes

**Node ids are per day.** `events.py` numbers hosts by first appearance within a single day, so the same host is a
different integer on a different day. Anything keyed on a node id is therefore day-scoped. A live deployment needs its
own stable map — see `models/serving/README.md`.

**Label verification is not optional.** The schedule is published in a local timezone and the captures are UTC;
`flows.py` carries the offset explicitly and `verify.py` checks the resulting attack windows against per-family row
counts. `docs/LABELING_VERIFICATION.md` records that audit.
