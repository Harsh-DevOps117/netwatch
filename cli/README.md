# Deterministic Network Threat Detection Engine

> **Project:** Deterministic Network Traffic Ingestion & Threat Detection  
> **Problem Statement (NTRO):** *"AI Based Network Attack Forecasting from Network Traffic Data"*  
> **Language:** Go (1.21+)  
> **Core Library:** `github.com/google/gopacket`

---

## 1. Executive Summary & Objective

This project provides a standalone, high-performance, deterministic network threat detection engine written in idiomatic Go. It is designed to parse raw PCAP files, segment packets into time-bounded windows, extract statistical and relationship features, and apply deterministic rules to identify attack indicators in real-time or offline forensic mode.

### The NTRO Context & Future World Model
The ultimate goal of the NTRO problem statement is to build an **Attack Forecasting System** using a **World Model** that predicts how cyberattacks evolve over time.

```
+-------------------------------------------------------------+
|                      CURRENT PHASE                          |
|             (Deterministic Detection Engine)                |
|                                                             |
|   Network Traffic (PCAP)                                    |
|          │                                                  |
|          ▼                                                  |
|   Go Deterministic Engine                                   |
|          │                                                  |
|          ▼                                                  |
|   Window Features + Threat Indicators (JSON Output)         |
+------------------------------┬------------------------------+
                               │ (Clean Boundary)
+------------------------------▼------------------------------+
|                       FUTURE PHASE                          |
|                   (Temporal Forecasting)                    |
|                                                             |
|   Window JSON Feature Vectors                               |
|          │                                                  |
|          ▼                                                  |
|   World Model (Predictive ML / Temporal Transition)         |
|          │                                                  |
|          ▼                                                  |
|   Attack Progression & Future State Forecast                |
+-------------------------------------------------------------+
```

**Key Architectural Rule:**
- **Zero Hallucination / Zero Simulation:** This engine contains no machine learning, mock prediction logic, or simulated attack progressions.
- **Independence:** It is a standalone, deterministic telemetry and feature extractor that produces clean, structured JSON data to serve as training or inference input for future World Models.

---

## 2. Why Deterministic Detection?

1. **Ground Truth Baseline:** Deterministic rules provide verifiable, reproducible, and explainable evidence without false confidence intervals.
2. **High Throughput & Low Latency:** Written in compiled Go with zero CGO overhead, processing tens of thousands of packets per second.
3. **Evidence, Not Proof:** A threshold breach is treated as an *Indicator* (`PORT_SCAN_INDICATOR`, `SYN_FLOOD_INDICATOR`), not absolute mathematical proof of malice.
4. **Structured Feature Generation:** In addition to alerting, every time window produces structured feature vectors that describe the network state.

---

## 3. Architecture Pipeline

Network traffic flows through a strictly decoupled pipeline:

```
                  ┌──────────────────────┐
                  │   PCAP / PCAP-NG     │
                  └──────────┬───────────┘
                             │
                             ▼
                  ┌──────────────────────┐
                  │    capture/pcap.go   │  Streams raw packets
                  └──────────┬───────────┘
                             │
                             ▼
                  ┌──────────────────────┐
                  │   parser/packet.go   │  Extracts IP, Ports, Protocols, TCP Flags
                  └──────────┬───────────┘
                             │
                             ▼
                  ┌──────────────────────┐
                  │   window/window.go   │  Slices stream into 10-second windows
                  └──────────┬───────────┘
                             │
                             ▼
                  ┌──────────────────────┐
                  │ features/features.go │  Aggregates rates, ratios, host/port graphs
                  └──────────┬───────────┘
                             │
                             ▼
                  ┌──────────────────────┐
                  │    rules/engine.go   │  Evaluates 7 deterministic threat rules
                  └──────────┬───────────┘
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
sih-2026/
├── run.sh                      # Universal runner script (live capture, PCAP analysis, builds)
├── README.md                   # Project overview & NTRO problem statement
│
└── cli/
    ├── main.go                 # Application entry point (delegates to cmd.Execute())
    ├── go.mod                  # Go module definition
    ├── go.sum                  # Dependency checksums
    ├── config.yaml             # Configurable detection thresholds and rule flags
    ├── Makefile                # Fast build and lint automation
    ├── README.md               # Complete architectural and usage guide
    │
    ├── cmd/                    # Cobra CLI Commands
    │   ├── root.go             # Root command, persistent flags & pipeline runner
    │   ├── analyze.go          # 'detector analyze <file>' command
    │   ├── live.go             # 'detector live' real-time network capture command
    │   └── version.go          # 'detector version' information command
    │
    ├── capture/
    │   ├── pcap.go             # Offline PCAP and PCAP-NG reader
    │   └── live.go             # Live network interface streamer (tshark / tcpdump)
    │
    ├── parser/
    │   └── packet.go           # Protocol parser & safe field extraction
    │
    ├── window/
    │   └── window.go           # Sliding / tumbling time window manager
    │
    ├── features/
    │   └── features.go         # Statistical feature calculation & state aggregation
    │
    ├── rules/
    │   ├── engine.go           # Rule coordinator and multi-rule evaluator
    │   ├── portscan.go         # Destination port fan-out detector
    │   ├── hostscan.go         # Destination host fan-out detector
    │   ├── synflood.go         # High SYN rate & SYN/SYN-ACK ratio detector
    │   ├── ackflood.go         # High TCP ACK volume detector
    │   ├── rstflood.go         # High TCP RST rate (teardown attack) detector
    │   ├── udpflood.go         # High UDP packet/byte rate detector
    │   ├── icmpflood.go        # ICMP flood & Ping Sweep reconnaissance detector
    │   ├── dnsamplification.go # High DNS packet/byte rate amplification detector
    │   ├── stealthscan.go      # Stealth TCP scans (NULL, XMAS, FIN scans)
    │   ├── connectionburst.go  # Burst TCP connection attempt detector
    │   └── flags.go            # Illegal TCP flag combinations (SYN+FIN, etc.)
    │
    ├── alert/
    │   └── alert.go            # Alert data structures and severity constants
    │
    ├── config/
    │   └── config.go           # YAML configuration loader and default fallback
    │
    └── output/
        ├── console.go          # Formatted terminal printing (windows & summary)
        └── json.go             # JSON exporter for window features & alerts
```

---

## 5. Detailed Component & Function Breakdown

### `capture/pcap.go` & `capture/live.go`
- **Purpose:** Opens offline capture files (PCAP/PCAP-NG) or live network interfaces without CGO dependencies.
- **Key Structs & Functions:**
  - `type Handle struct`: Wraps an `os.File` and a `*gopacket.PacketSource`.
  - `OpenPCAP(path string) (*Handle, error)`: Reads classic PCAP and PCAP-NG.
  - `OpenLive(iface, bpf string) (*LiveHandle, error)`: Streams live network traffic directly from local interfaces.
  - `(h *Handle) Packets() <-chan gopacket.Packet`: Returns packet stream channel.
  - `(h *Handle) Close() error`: Cleans up the underlying file descriptor.

### `parser/packet.go`
- **Purpose:** Safely extracts network layer, transport layer, ICMP, DNS, and TCP flag metadata from raw packets. Gracefully handles missing layers without panicking.
- **Key Structs & Functions:**
  - `type TCPFlags struct`: Holds boolean flags (`SYN`, `ACK`, `RST`, `FIN`, `PSH`, `URG`, `ECE`, `CWR`, `NS`).
  - `type ParsedPacket struct`: Normalized packet representation containing `Timestamp`, `Length`, `SrcIP`, `DstIP`, `SrcPort`, `DstPort`, `Protocol`, `TCPFlags`, `IsICMPEchoRequest`, `IsDNS`.
  - `ParsePacket(pkt gopacket.Packet) *ParsedPacket`: Extracts fields safely from IPv4, IPv6, TCP, UDP, ICMPv4, ICMPv6, and ARP layers.

### `window/window.go`
- **Purpose:** Segments packets into fixed time slices (default: 10 seconds) measured **relative to the first packet's timestamp**.
- **Key Structs & Functions:**
  - `type Manager struct`: Tracks current `windowStart`, `windowEnd`, and delegates packet accumulation to a `features.FeatureAggregator`.
  - `NewManager(duration time.Duration, onWindowClosed func(*features.WindowFeatures)) *Manager`: Initializes the manager.
  - `(m *Manager) ProcessPacket(p *parser.ParsedPacket)`: Places the packet into the active window. If the packet's timestamp exceeds `windowEnd`, it computes the current window's features, triggers `onWindowClosed`, and advances the window span.
  - `(m *Manager) Flush()`: Finalizes and emits the last active window upon reaching EOF.

### `features/features.go`
- **Purpose:** Computes comprehensive statistical, temporal, and relational metrics over a time window.
- **Key Structs & Functions:**
  - `type WindowFeatures struct`: Holds aggregated features:
    - **Basic:** `TotalPackets`, `TotalBytes`, `PacketsPerSecond`, `BytesPerSecond`.
    - **IPs:** `UniqueSourceIPs`, `UniqueDestinationIPs`.
    - **Ports:** `UniqueSourcePorts`, `UniqueDestinationPorts`.
    - **TCP:** `TCPPackets`, `SYNCount`, `SYNACKCount`, `ACKCount`, `RSTCount`, `FINCount`, `PSHCount`, `URGCount`, `SYNPerSecond`, `ACKPerSecond`, `RSTPerSecond`, `SYNAckRatio`.
    - **UDP & DNS:** `UDPPackets`, `UDPBytes`, `UDPPacketsPerSecond`, `UDPBytesPerSecond`, `DNSPackets`, `DNSBytes`, `DNSPacketsPerSecond`, `DNSBytesPerSecond`.
    - **ICMP:** `ICMPPackets`, `ICMPBytes`, `ICMPPacketsPerSecond`, `ICMPEchoRequests`.
    - **Connection State:** `ApproxIncompleteConnections` ($\max(0, \text{SYN} - \text{SYN-ACK})$).
    - **Mappings:** `SrcIPToDstPorts`, `SrcIPToDstIPs`, `SrcIPToPackets`, `SrcIPToSYNs`, `SrcIPToICMPEcho`, `SuspiciousFlagPackets`, `NullScanPackets`, `XmasScanPackets`, `FinScanPackets`.
  - `(a *FeatureAggregator) AddPacket(p *parser.ParsedPacket)`: Updates ongoing counts and relationship maps.
  - `(a *FeatureAggregator) ComputeFinalFeatures() *WindowFeatures`: Normalizes rates against window duration and computes ratios safely.

### `rules/` (Detection Rules)
- **`rules/engine.go`:** Orchestrates and runs all enabled rules against each window.
- **`rules/portscan.go` (`PORT_SCAN_INDICATOR`):** Triggers if a single source IP contacts $\ge \text{unique\_ports}$ (default: 20) destination ports within one window.
- **`rules/hostscan.go` (`HOST_SCAN_INDICATOR`):** Triggers if a single source IP contacts $\ge \text{unique\_hosts}$ (default: 20) destination IPs within one window.
- **`rules/synflood.go` (`SYN_FLOOD_INDICATOR`):** Triggers if `SYNPerSecond >= syn_per_second` (default: 500) OR (`SYNAckRatio >= syn_ack_ratio` (default: 5.0) AND `SYNCount >= min_syn_count`).
- **`rules/ackflood.go` (`ACK_FLOOD_INDICATOR`):** Triggers if `ACKPerSecond >= ack_per_second` (default: 1000).
- **`rules/rstflood.go` (`RST_FLOOD_INDICATOR`):** Triggers if `RSTPerSecond >= rst_per_second` (default: 500) (connection teardown attacks).
- **`rules/udpflood.go` (`UDP_FLOOD_INDICATOR`):** Triggers if `UDPPacketsPerSecond >= udp_packets_per_second` (default: 1000).
- **`rules/icmpflood.go` (`ICMP_FLOOD_INDICATOR` / `PING_SWEEP_INDICATOR`):** Detects ICMP packet floods and single-source ping sweeps across multiple target hosts.
- **`rules/dnsamplification.go` (`DNS_AMPLIFICATION_INDICATOR`):** Detects volumetric DNS request/response amplification floods on port 53.
- **`rules/stealthscan.go` (`NULL_SCAN_INDICATOR` / `XMAS_SCAN_INDICATOR` / `FIN_SCAN_INDICATOR`):** Identifies stealth scanning signatures (no flags, FIN+PSH+URG, isolated FIN).
- **`rules/connectionburst.go` (`CONNECTION_BURST_INDICATOR`):** Triggers on sudden spikes of new TCP connection attempts.
- **`rules/flags.go` (`SUSPICIOUS_TCP_FLAGS`):** Identifies illegal TCP flag combinations: `SYN+FIN`, `SYN+RST`, `FIN+RST`.

---

## 6. Configuration Guide (`config.yaml`)

Thresholds are decoupled from the Go code and configured via YAML:

```yaml
# Time window duration in seconds (relative to capture start)
window_seconds: 10

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

### Using the Runner Script (`run.sh`)

```bash
# 1. Real-time Live Network Monitoring (auto-detects active Wi-Fi / Ethernet interface)
./run.sh live

# 2. Live Monitoring on specific interface (e.g. eth0, wlo1)
./run.sh live eth0

# 3. Offline PCAP Forensics
./run.sh analyze capture.pcap

# 4. Stream via standard input pipe
tshark -i eth0 -F pcap -w - | ./run.sh stdin

# 5. Build or Clean
./run.sh build
./run.sh clean
```

### Direct Go Commands

```bash
# Live monitoring
go run . --live

# Offline analysis with custom window and JSON export
go run . analyze capture.pcap --window 5 --output alerts.json
```

---

## 8. Summary of Output Formats

### Sample Console Output

```text
========================================
DETERMINISTIC NETWORK THREAT DETECTOR
========================================
Traffic Source : capture.pcap
Operating Mode : Offline PCAP Forensics
Time Window    : 10 seconds per aggregation slice

┌── WINDOW #1 (10s duration) ───────────────────────── [10:00:00.100 → 10:00:10.100] ┐
│  TRAFFIC VOLUME
│    Packets : 42       | Volume  : 2.46 KB     | Rate : 4.2 pkts/s (0.2 KB/s)
│
│  PROTOCOL & TRAFFIC DYNAMICS
│    TCP  : 42     (SYN: 42 | SYN-ACK: 0 | ACK: 0 | RST: 0 | FIN: 0 | PSH: 0 | URG: 0)
│    UDP  : 0      (0 B) | DNS: 0    (0 B) | ICMP: 0    (Echo: 0)
│    Rate : SYN 4.2/s | ACK 0.0/s | RST 0.0/s | Ratio SYN/SYN-ACK: 42.0 | Incomplete: 42
│
│  HOST & PORT CARDINALITY
│    Unique Source IPs : 1    | Unique Dest IPs : 1    | Unique Dest Ports : 35  
│
│  DETERMINISTIC THREAT INDICATORS
│    [▲ HIGH ALARM] PORT_SCAN_INDICATOR
│        Attacker / Source IP: 192.168.1.50
│        Diagnostic Evidence : One source contacted an unusually large number of destination ports (35 unique ports in 10s window).
└──────────────────────────────────────────────────────────────────────────────────────┘
```
