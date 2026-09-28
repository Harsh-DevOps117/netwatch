# `ingest` — packet captures to a labelled event stream

Turns raw CSE-CIC-IDS2018 captures into the tables every later stage reads: one event per network flow, ordered by
microsecond timestamp. Time is never cut into fixed windows. It is plain data processing — no learning. The live
services read captures with its code: the same `tshark` fields and options, and the same CICFlowMeter. Design and figure: [docs/architecture.md §3](../docs/architecture.md#3-ingest-from-packet-captures-to-an-event-stream).

## Steps

1. Select a day's captures (a pcap/pcapng header, and a first packet on that day).
2. Extract packet records with `tshark`.
3. Build two-way flow records with CICFlowMeter (a git submodule; `tools/setup_cicflowmeter.sh` fetches, patches and
   builds it once); its CSV output is reused if present.
4. Label flows and packets from the dataset's published attack schedule, and audit the result.
5. Map every packet to its flow by an interval join, and write each flow as an edge.
6. Build the day's event stream and its node index.

## Layout

```
ingest/
  cli.py          entry point: per-capture jobs with memory limits
  pipeline.py     one capture end to end
  sources/
    packets.py    captures to packets.parquet, via tshark
    flows.py      CICFlowMeter records, label matching, the time-zone offset
    schedule.py   the attack schedule and a versioned label configuration
  build/
    join.py       packets to flows (the map) and the edge list
    events.py     the event stream and the per-day node index
    nodes.py      optional per-window host aggregates
  verify/
    checks.py     the audits
```

## Inputs and outputs

| | path |
|---|---|
| in | `data/raw/<day>/` — the day's capture files |
| out, per capture | `data/processed/<day>/<capture>/{packets,flows,edges,flow_packet_map}.parquet` |
| out, per day | `data/events/<day>/events.parquet`, `data/events/<day>/node_index.parquet` |
| optional | `data/nodes/<day>/nodes.parquet` — `python -m ingest.build.nodes <day>` |

Every column, and how the tables join: [docs/data.md](../docs/data.md).

## Running

```bash
uv run python -m ingest.cli --days <day> --workers 1 --max-worker-mem-mb 6656   # captures -> tables
uv run python -m ingest.build.events <day>                                       # the event stream
uv run python -m ingest.verify <day>                                             # audit; must end in RESULT: PASS
```

`--days all` processes every day under `data/raw/`. `--max-worker-mem-mb` is a hard memory limit per worker; it must stay
above the ~4.8 GB the CICFlowMeter JVM reserves, or CICFlowMeter will not start. A worker that reaches the limit fails
cleanly and is reported like any other failed job.

## Notes

- **Node ids are per day.** Hosts are numbered by first appearance within one day, so the same host has another id on
  another day; map through that day's `node_index.parquet`.
- **The schedule is published in local time (UTC−4) and the captures are UTC.** `flows.py` applies the offset
  explicitly, and `ingest.verify` checks the resulting attack windows against per-family row counts.
