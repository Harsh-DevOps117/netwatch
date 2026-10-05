# Netwatch Deterministic Network Threat Detection Engine

> **Project:** Deterministic Network Traffic Ingestion & Threat Detection  
> **Problem Statement (NTRO):** *"AI Based Network Attack Forecasting from Network Traffic Data"*  
> **Language:** Go (1.21+)  
> **Core Library:** `github.com/google/gopacket`  
> **Schema Version:** `2.0`  

---

## 1. Executive Summary & Objective

This project provides a standalone, high-performance, deterministic network threat detection and telemetry extraction engine written in idiomatic Go. It is designed to parse raw PCAP files, segment packets into time-bounded windows, extract deep statistical, packet-level, and relationship graph features, track bidirectional network flows, and apply deterministic rules to identify attack indicators in real-time or offline forensic mode.

### The NTRO Context & World Model
The CLI now consumes the local forecast and early-detection services while keeping deterministic packet telemetry as a separate evidence source.

```
+-------------------------------------------------------------+
|                      CURRENT PHASE                          |
|             (Deterministic Detection Engine)                |
|                                                             |
|   Network Traffic (PCAP / Live Interface)                   |
|          │                                                  |
|          ▼                                                  |
|   Go Deterministic Engine (Zero CGO)                        |
|          │                                                  |
|          ▼                                                  |
|   Temporal Feature Vectors + Graph Topology                 |
|   + Bidirectional Flows + Threat Indicators (JSON Schema 2.0|
+------------------------------┬------------------------------+
                               │ (Clean Boundary)
+------------------------------▼------------------------------+
|                       FUTURE PHASE                          |
|                   (Temporal Forecasting)                    |
|                                                             |
|   Window JSON Feature Sequences & Graph Snapshots           |
|          │                                                  |
|          ▼                                                  |
|   World Model (Predictive ML / Temporal Transition)         |
|          │                                                  |
|          ▼                                                  |
|   Attack Progression & Future State Forecast (MITRE ATT&CK) |
+-------------------------------------------------------------+
```

**Key Architectural Rules:**
- **Zero Hallucination / Zero Simulation:** This engine contains no machine learning, mock prediction logic, or simulated attack progressions.
- **100% Real Packet Telemetry:** Features are mathematically computed from decoded packet headers in each time window.
- **Independence:** It is a standalone, deterministic telemetry and feature extractor that produces clean, structured JSON data to serve as training or inference input for future World Models.

---

## 2. Why Deterministic Detection?

1. **Ground Truth Baseline:** Deterministic rules provide verifiable, reproducible, and explainable evidence without false confidence intervals.
2. **High Throughput & Low Latency:** Written in compiled Go with zero CGO overhead, processing tens of thousands of packets per second.
3. **Evidence, Not Proof:** A threshold breach is treated as an *Indicator* (`PORT_SCAN_INDICATOR`, `SYN_FLOOD_INDICATOR`), not absolute mathematical proof of malice.
4. **Structured Feature Generation:** Every time window produces structured feature vectors, host relationship graphs, and flow records describing the evolving network state.

---

## 3. Architecture Pipeline

```
                  ┌──────────────────────┐
                  │   PCAP / PCAP-NG     │
                  └──────────┬───────────┘
                             │
                             ▼
                  ┌──────────────────────┐
                  │    capture/pcap.go   │  Streams raw packets (offline/live/stdin)
                  └──────────┬───────────┘
                             │
                             ▼
                  ┌──────────────────────┐
                  │   parser/packet.go   │  Extracts IP, Ports, 9 TCP Flags, TTL,
                  └──────────┬───────────┘  Window Size, IP Frag, Seq, Ack, Payload
                             │
                             ▼
                  ┌──────────────────────┐
                  │   window/window.go   │  Slices stream into indexed time windows
                  └──────────┬───────────┘
                             │
                             ▼
                  ┌──────────────────────┐
                  │ features/features.go │  Calculates stats (TTL, IAT, TCP Win, Retrans),
                  │  features/flow.go    │  tracks bidirectional flows with state machines,
                  │  features/graph.go   │  and generates host-to-host topology graphs
                  └──────────┬───────────┘
                             │
                             ▼
                  ┌──────────────────────┐
                  │    rules/engine.go   │  Evaluates 11 deterministic threat rules
                  └──────────┬───────────┘  with MITRE ATT&CK classification
                             │
               ┌─────────────┴─────────────┐
               ▼                           ▼
    ┌──────────────────────┐    ┌──────────────────────┐
    │  output/console.go   │    │    output/json.go    │
    │  (Terminal Reports)  │    │  (Structured Export) │
    └──────────────────────┘    └──────────────────────┘
```

---

## 4. Directory Structure & File Functionality

```
cli/
├── run.sh                  # Universal runner script (live capture, PCAP analysis, builds)
├── main.go                 # Application entry point (delegates to cmd.Execute())
├── go.mod                  # Go module definition
├── go.sum                  # Dependency checksums
├── config.yaml             # Configurable detection thresholds and rule flags
├── Makefile                # Fast build and lint automation
├── README.md               # Complete architectural and usage guide
├── ARCHITECTURE.md         # Detailed system design & feature specification
│
├── cmd/                    # Cobra CLI Commands
│   ├── root.go             # Root command, persistent flags & pipeline runner
│   ├── analyze.go          # 'detector analyze <file>' command
│   ├── live.go             # 'detector live' real-time network capture command
│   └── version.go          # 'detector version' information command
│
├── capture/
│   ├── pcap.go             # Offline PCAP and PCAP-NG reader
│   └── live.go             # Live network interface streamer (tshark / tcpdump / stdin)
│
├── parser/
│   └── packet.go           # Protocol parser & safe field extraction (TTL, TCP Win, Frag, Flags)
│
├── window/
│   └── window.go           # Sliding / tumbling indexed time window manager
│
├── features/
│   ├── features.go         # Statistical feature calculation & state aggregation
│   ├── flow.go             # Bidirectional flow tracker with TCP state machine & memory bounds
│   └── graph.go            # Host-to-host and host-to-port relationship graph builder
│
├── rules/
│   ├── engine.go           # Rule coordinator and multi-rule evaluator
│   ├── portscan.go         # Destination port fan-out detector (MITRE T1046)
│   ├── hostscan.go         # Destination host fan-out detector (MITRE T1018)
│   ├── synflood.go         # High SYN rate & SYN/SYN-ACK ratio detector (MITRE T1498.001)
│   ├── ackflood.go         # High TCP ACK volume detector (MITRE T1498.001)
│   ├── rstflood.go         # High TCP RST rate teardown detector (MITRE T1499)
│   ├── udpflood.go         # High UDP packet/byte rate detector (MITRE T1498.001)
│   ├── icmpflood.go        # ICMP flood & Ping Sweep detector (MITRE T1498.001 / T1595.001)
│   ├── dnsamplification.go # High DNS rate amplification detector (MITRE T1498.002)
│   ├── stealthscan.go      # Stealth TCP scans (NULL, XMAS, FIN scans) (MITRE T1046)
│   ├── connectionburst.go  # Burst TCP connection attempt detector (MITRE T1071)
│   └── flags.go            # Illegal TCP flag combinations (SYN+FIN, etc.) (MITRE T1027)
│
├── alert/
│   └── alert.go            # Alert data structures with MITRE ATT&CK taxonomy
│
├── config/
│   └── config.go           # YAML configuration loader with auto-detection & validation
│
└── output/
    ├── console.go          # Formatted terminal printing (windows, topology & summary)
    └── json.go             # Schema 2.0 JSON exporter (features, flows, graphs & alerts)
```

---

## 5. Comprehensive Feature Breakdown

### 5.1 Deep Packet-Level Features
- **TTL / Hop Limit Statistics**: `TTLMean`, `TTLMin`, `TTLMax`, `TTLStdDev` per window.
- **TCP Window Size Statistics**: `TCPWindowMean`, `TCPWindowMin`, `TCPWindowMax`, `TCPWindowStdDev`.
- **IP Fragmentation Tracking**: `FragmentedPacketsCount`, `FragmentedPacketsRatio`.
- **Payload Distribution**: `PayloadMean`, `PayloadMin`, `PayloadMax`, `PayloadStdDev`, and histogram distribution buckets (`0_64`, `65_512`, `513_1024`, `1025_1500`, `1501_plus`).
- **Inter-Arrival Time (IAT)**: `IATMeanMicroseconds`, `IATStdDevMicroseconds`, `IATMinMicroseconds`, `IATMaxMicroseconds`.
- **TCP Retransmissions**: Tracked via sequence number recurrence: `TCPRetransmissionsCount`, `TCPRetransmissionRatio`.

### 5.2 Bidirectional Flow Tracking (`features/flow.go`)
- 5-tuple canonical bidirectional flow key: `SrcIP:SrcPort <-> DstIP:DstPort (Protocol)`.
- Forward (fwd) and backward (bwd) packets, bytes, payload bytes, and IAT statistics.
- TCP state machine tracking: `INIT`, `SYN_SENT`, `ESTABLISHED`, `FIN_WAIT`, `CLOSED`, `RESET`.
- Expiration & bounded memory management: configurable idle timeout (default 30s) and max active flows limit (default 10,000) with automatic LRU eviction.

### 5.3 Host Relationship & Graph Structure (`features/graph.go`)
- Node features per host: IP, In-degree, Out-degree, packets sent/received, bytes sent/received, distinct destination ports contacted, incomplete connections initiated.
- Directed edge features: source/destination IPs, packet counts, byte volumes, protocols used, distinct destination ports, SYN/ACK/RST counts.
- Graph-level metrics: Total nodes, total edges, density.

### 5.4 Deterministic Threat Detection Rules (11 Rules)
All rules include full MITRE ATT&CK taxonomy:
- **Port Scan (`PORT_SCAN_INDICATOR`)**: MITRE T1046 (Network Service Discovery).
- **Host Scan (`HOST_SCAN_INDICATOR`)**: MITRE T1018 (Remote System Discovery).
- **SYN Flood (`SYN_FLOOD_INDICATOR`)**: MITRE T1498.001 (Direct Network Flood).
- **ACK Flood (`ACK_FLOOD_INDICATOR`)**: MITRE T1498.001 (Direct Network Flood).
- **RST Flood (`RST_FLOOD_INDICATOR`)**: MITRE T1499 (Endpoint DoS: Connection Teardown).
- **UDP Flood (`UDP_FLOOD_INDICATOR`)**: MITRE T1498.001 (Direct Network Flood).
- **ICMP Flood & Ping Sweep (`ICMP_FLOOD_INDICATOR` / `PING_SWEEP_INDICATOR`)**: MITRE T1498.001 / T1595.001.
- **DNS Amplification (`DNS_AMPLIFICATION_INDICATOR`)**: MITRE T1498.002 (Reflection Amplification).
- **Stealth Scans (`NULL_SCAN_INDICATOR`, `XMAS_SCAN_INDICATOR`, `FIN_SCAN_INDICATOR`)**: MITRE T1046.
- **Connection Burst (`CONNECTION_BURST_INDICATOR`)**: MITRE T1071 (Application Layer Protocol Spike).
- **Suspicious Flags (`SUSPICIOUS_TCP_FLAGS`)**: MITRE T1027 (Obfuscated/Abnormal Protocol Signatures).

---

## 6. Configuration Guide (`config.yaml`)

```yaml
# Time window duration in seconds
window_seconds: 10

flow_tracking:
  enabled: true
  idle_timeout_seconds: 30
  max_active_flows: 10000

graph_tracking:
  enabled: true
  max_nodes: 5000
  max_edges: 20000

rules:
  port_scan:
    enabled: true
    unique_ports: 20

  host_scan:
    enabled: true
    unique_hosts: 20

  syn_flood:
    enabled: true
    syn_per_second: 500
    syn_ack_ratio: 5.0
    min_syn_count: 50

  ack_flood:
    enabled: true
    ack_per_second: 1000

  rst_flood:
    enabled: true
    rst_per_second: 500

  udp_flood:
    enabled: true
    udp_packets_per_second: 1000

  icmp_flood:
    enabled: true
    icmp_per_second: 300
    ping_sweep_enabled: true
    unique_targets: 15

  dns_flood:
    enabled: true
    dns_packets_per_second: 500
    dns_bytes_per_second: 500000

  stealth_scan:
    enabled: true
    min_packets: 3

  connection_burst:
    enabled: true
    syn_per_second: 500

  suspicious_flags:
    enabled: true
```

---

## 7. How to Run

### Using the Runner Script (`cli/run.sh`)

```bash
cd cli

# 1. Real-time Live Network Monitoring (auto-detects active Wi-Fi / Ethernet interface)
./run.sh live

# 2. Live Monitoring on specific interface (e.g. eth0, wlo1)
./run.sh live eth0

# 3. Offline PCAP Forensics with JSON Export
./run.sh analyze capture.pcap -w 10 -o output.json

# 4. Stream via standard input pipe
tshark -i eth0 -F pcap -w - | ./run.sh stdin

# 5. Local dashboard: captures live traffic and opens the browser at 127.0.0.1 only
./run.sh dashboard --port 8787

# 6. Read the lag forecast once (or add --watch 5s)
./run.sh model --service lag

# 7. Read forecasts with live early detections
./run.sh model --service lag --detections --watch 5s

# Alarm only on newly arriving observed incidents, or include raw event flags
./run.sh model --service lag --watch 5s --world-alarm incident --detection-alarm both

# 8. Start only the model dashboard when packet capture is unavailable
./run.sh dashboard --capture=false --model-service lag

# 9. Build or Clean
./run.sh build
./run.sh clean

# 10. Response guide for a detector incident, with an optional confirmed host block
./run.sh protect
```

The dashboard uses Server-Sent Events for completed capture windows and polls the
local Go proxy for `GET /forecast` and `GET /detections`. The default forecast is
the lag service at `127.0.0.1:8901`; choose `--model-service live` or `replay`, or
override URLs explicitly. The page is self-contained and has no CDN dependency.
It labels replay as recorded data, shows live state age, calibration, measured
recall and every service caveat, and never presents forecast scores as calibrated
probabilities. If tshark/tcpdump or capture permission is missing, the dashboard
continues in model-only mode.

Open **PCAP analysis** in the dashboard sidebar (or `/offline`) and use the
upload form at the top of the page to ingest a `.pcap` or `.pcapng` file (up to
128 MiB). The floating **Upload another PCAP** button returns to that form when
results are scrolled down. Offline results split the last observed scored
events from up to three imagined world-model event steps per seed path; the
rollout has no wall-clock ETA. Jobs created before the observed-event timeline
was added show aggregated observed links until the PCAP is analyzed again.

The Protection page in the dashboard shows a response guide for a selected detector
incident, and `protect` prints the same guide in the terminal. The guide is built
on this machine from the incident's verified facts: family, opening score, active
state, linked-event count and private/public source scope. One incident always
reads the same, no key is needed and nothing is sent to an outside service. It
says what the flag does and does not establish, what to check first for that
family, what containment this host offers, and how to recover. Forecast links
and raw event flags cannot activate protection. The guide is text only; the one
action Netwatch can take is the block below. For an active incident with a single
validated public source IPv4, an explicit `BLOCK <IP>` confirmation may add a
host-firewall inbound block (`netsh` on Windows, `iptables` on Linux). Both need
administrator rights. Windows shows its approval prompt when the block is added.
On Linux `iptables` needs root even to list its rules, so Netwatch uses `sudo`
when it asks for no password and otherwise the desktop's `pkexec` prompt, once
per action (list, block or unblock). The rule
also supports a consistent private LAN source targeting this host when at least
three linked events exist, but requires the stronger `BLOCK LAN <IP>` confirmation;
blocking a LAN service or device can disrupt legitimate work. Local-host, reserved,
and inconsistent sources remain ineligible. The red button becomes available only
after the guide returns an eligible active-incident plan. A block rule
remains after Netwatch exits (reboot persistence depends on the OS/firewall);
the dashboard offers Undo while its process is running,
and both UI and CLI print the manual removal command. Elevated firewall rights
are needed; Windows requests UAC approval when the dashboard is not elevated.
A single host block cannot stop a distributed flood; use upstream
ISP/CDN controls for DDoS.

The dashboard presents incidents as the operator-facing alerts and exposes
their contributing event flags in each incident's drill-down; it never alarms
on hypothetical forecast links. The CLI watch flags `--world-alarm` and
`--detection-alarm` can include diagnostic event flags when explicitly chosen and ring
the terminal bell for newly arriving matches. The first snapshot only primes the
deduplicator, so old rows do not re-alarm when a watch starts. World incidents
are operational 3-event/120-second groupings with no measured incident FPR.

---

## 8. Summary of Output Formats

### Sample Console Output

```text
================================================================================
DETERMINISTIC NETWORK THREAT DETECTION ENGINE
NTRO Cyber Security & Threat Telemetry
================================================================================

  Traffic Source : PCAP File: capture.pcap
  Operating Mode : Offline PCAP Forensics
  Time Window    : 10 seconds per aggregation slice

┌── WINDOW #1 (10s duration) ───────────────────────── [10:00:00.100 → 10:00:10.100] ┐
│  TRAFFIC VOLUME
│    Packets : 4200     | Volume  : 2.40 MB     | Rate : 420.0 pkts/s (245.8 KB/s)
│
│  PROTOCOL & TRAFFIC DYNAMICS
│    TCP  : 4200   (SYN: 4000 | SYN-ACK: 20 | ACK: 180 | RST: 0 | FIN: 0 | PSH: 0 | URG: 0)
│    UDP  : 0      (0 B) | DNS: 0    (0 B) | ICMP: 0    (Echo: 0)
│    Rate : SYN 400.0/s | ACK 18.0/s | RST 0.0/s | Ratio SYN/SYN-ACK: 200.0 | Incomplete: 3980
│
│  DEEP PACKET TELEMETRY & STATS
│    TTL  : Mean 64.0 (Min 64, Max 64, σ=0.0) | TCP Win: Mean 29200 (Min 29200, Max 29200)
│    IAT  : Mean 2380.5 µs (Min 10.0, Max 12500.0, σ=540.2) | Frag Pkts: 0 | Retrans: 0 (0.00%)
│
│  HOST & GRAPH TOPOLOGY
│    Unique IPs : 15 Src → 2 Dst | Unique Ports: 3500 Src → 80 Dst
│    Graph View : 17 Nodes | 15 Edges | Density: 0.0551 | Active Flows: 15
│
│  DETERMINISTIC THREAT INDICATORS
│    [▲ HIGH ALARM] SYN_FLOOD_INDICATOR  [T1498.001: Direct Network Flood (SYN Flood)]
│        Diagnostic Evidence : Abnormal SYN/SYN-ACK ratio (200.0 with 4000 SYNs and 20 SYN-ACKs).
└──────────────────────────────────────────────────────────────────────────────────────┘
```
