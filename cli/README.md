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
├── main.go                     # Application entry point (delegates to cmd.Execute())
├── go.mod                      # Go module definition
├── go.sum                      # Dependency checksums
├── config.yaml                 # Configurable detection thresholds and rule flags
├── README.md                   # Complete architectural and usage guide
│
├── cmd/                        # Cobra CLI Commands
│   ├── root.go                 # Root command, persistent flags & pipeline runner
│   ├── analyze.go              # 'detector analyze <file>' command
│   ├── live.go                 # 'detector live' real-time network capture command
│   └── version.go              # 'detector version' information command
│
├── capture/
│   ├── pcap.go                 # Offline PCAP and PCAP-NG reader
│   └── live.go                 # Live network interface streamer
│
├── parser/
│   └── packet.go               # Protocol parser & safe field extraction
│
├── window/
│   └── window.go               # Sliding / tumbling time window manager
│
├── features/
│   └── features.go             # Statistical feature calculation & state aggregation
│
├── rules/
│   ├── engine.go               # Rule coordinator and multi-rule evaluator
│   ├── portscan.go             # Destination port fan-out detector
│   ├── hostscan.go             # Destination host fan-out detector
│   ├── synflood.go             # High SYN rate and SYN/SYN-ACK ratio detector
│   ├── ackflood.go             # High TCP ACK volume detector
│   ├── udpflood.go             # High UDP packet/byte rate detector
│   ├── connectionburst.go      # Burst TCP connection attempt detector
│   └── flags.go                # Illegal TCP flag combinations (SYN+FIN, etc.)
│
├── alert/
│   └── alert.go                # Alert data structures and severity constants
│
├── config/
│   └── config.go               # YAML configuration loader and default fallback
│
└── output/
    ├── console.go              # Formatted terminal printing (windows & summary)
    └── json.go                 # JSON exporter for window features & alerts
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
- **Purpose:** Safely extracts network layer, transport layer, and TCP flag metadata from raw packets. Gracefully handles missing layers without panicking.
- **Key Structs & Functions:**
  - `type TCPFlags struct`: Holds boolean flags (`SYN`, `ACK`, `RST`, `FIN`, `PSH`).
  - `type ParsedPacket struct`: Normalized packet representation containing `Timestamp`, `Length`, `SrcIP`, `DstIP`, `SrcPort`, `DstPort`, `Protocol`, `TCPFlags`.
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
    - **TCP:** `TCPPackets`, `SYNCount`, `SYNACKCount`, `ACKCount`, `RSTCount`, `FINCount`, `PSHCount`, `SYNPerSecond`, `ACKPerSecond`, `SYNAckRatio`.
    - **UDP:** `UDPPackets`, `UDPBytes`, `UDPPacketsPerSecond`, `UDPBytesPerSecond`.
    - **Connection State:** `ApproxIncompleteConnections` ($\max(0, \text{SYN} - \text{SYN-ACK})$).
    - **Mappings:** `SrcIPToDstPorts`, `SrcIPToDstIPs`, `SrcIPToPackets`, `SrcIPToSYNs`, `SuspiciousFlagPackets`.
  - `(a *FeatureAggregator) AddPacket(p *parser.ParsedPacket)`: Updates ongoing counts and relationship maps.
  - `(a *FeatureAggregator) ComputeFinalFeatures() *WindowFeatures`: Normalizes rates against window duration and computes ratios safely.

### `rules/` (Detection Rules)
- **`rules/engine.go`:**
  - `type Rule interface`: `Name() string`, `Evaluate(feat *features.WindowFeatures) []alert.Alert`.
  - `type Engine struct`: Orchestrates and runs all enabled rules against each window.
- **`rules/portscan.go` (`PORT_SCAN_INDICATOR`):**
  - Triggers if a single source IP contacts $\ge \text{unique\_ports}$ (default: 20) destination ports within one window.
  - Severity: `HIGH`.
- **`rules/hostscan.go` (`HOST_SCAN_INDICATOR`):**
  - Triggers if a single source IP contacts $\ge \text{unique\_hosts}$ (default: 20) destination IPs within one window.
  - Severity: `HIGH`.
- **`rules/synflood.go` (`SYN_FLOOD_INDICATOR`):**
  - Triggers if `SYNPerSecond >= syn_per_second` (default: 500) OR (`SYNAckRatio >= syn_ack_ratio` (default: 5.0) AND `SYNCount >= min_syn_count`).
  - Severity: `HIGH`.
- **`rules/ackflood.go` (`ACK_FLOOD_INDICATOR`):**
  - Triggers if `ACKPerSecond >= ack_per_second` (default: 1000).
  - Severity: `HIGH`.
- **`rules/udpflood.go` (`UDP_FLOOD_INDICATOR`):**
  - Triggers if `UDPPacketsPerSecond >= udp_packets_per_second` (default: 1000).
  - Severity: `HIGH`.
- **`rules/connectionburst.go` (`CONNECTION_BURST_INDICATOR`):**
  - Triggers on sudden spikes of new TCP connection attempts (`SYNPerSecond >= syn_per_second`).
  - Severity: `MEDIUM`.
- **`rules/flags.go` (`SUSPICIOUS_TCP_FLAGS`):**
  - Identifies illegal TCP flag combinations: `SYN+FIN`, `SYN+RST`, `FIN+RST`.
  - Severity: `MEDIUM`.

### `alert/alert.go`
- **Purpose:** Standardized schema for threat indicators.
- **Fields:**
  ```go
  type Alert struct {
      Timestamp     time.Time              `json:"timestamp"`
      WindowStart   time.Time              `json:"window_start"`
      WindowEnd     time.Time              `json:"window_end"`
      Type          string                 `json:"type"`
      Severity      string                 `json:"severity"` // LOW, MEDIUM, HIGH
      SourceIP      string                 `json:"source_ip,omitempty"`
      DestinationIP string                 `json:"destination_ip,omitempty"`
      Protocol      string                 `json:"protocol,omitempty"`
      Reason        string                 `json:"reason"`
      Features      map[string]interface{} `json:"features,omitempty"`
  }
  ```

### `output/console.go` & `output/json.go`
- **`console.go`:** Prints formatted startup banners, per-window telemetry summaries, alerts, and final completion statistics. If no alerts trigger, explicitly confirms: *"No deterministic threat indicators detected."*
- **`json.go`:** Exports an array of `WindowRecord` objects containing timestamp bounds, complete `features` payload, and detected `alerts` array.

---

## 6. Configuration Guide (`config.yaml`)

Thresholds are decoupled from the Go code and configured via YAML:

```yaml
# Time window duration in seconds (relative to capture start)
window_seconds: 10

rules:
  port_scan:
    enabled: true
    unique_ports: 20       # Trigger if 1 IP contacts >= 20 destination ports

  host_scan:
    enabled: true
    unique_hosts: 20       # Trigger if 1 IP contacts >= 20 destination IPs

  syn_flood:
    enabled: true
    syn_per_second: 500    # Trigger if SYN rate exceeds 500/sec
    syn_ack_ratio: 5.0     # Trigger if SYN to SYN-ACK ratio exceeds 5.0
    min_syn_count: 50      # Minimum SYNs required to evaluate ratio

  ack_flood:
    enabled: true
    ack_per_second: 1000   # Trigger if ACK rate exceeds 1000/sec

  udp_flood:
    enabled: true
    udp_packets_per_second: 1000 # Trigger if UDP packet rate exceeds 1000/sec

  connection_burst:
    enabled: true
    syn_per_second: 500    # Trigger on burst connection attempts

  suspicious_flags:
    enabled: true          # Detect SYN+FIN, SYN+RST, FIN+RST
```

---

## 7. How to Run

The engine supports dual operating modes: **Offline PCAP Forensics** and **Real-Time Live Network Monitoring**.

### Mode A: Real-Time Live Monitoring

```bash
# 1. Automatic Live Mode (auto-detects active network interface)
go run . --live

# 2. Live capture on a specific network interface
go run . --interface eth0

# 3. Live capture with BPF packet filter
go run . --interface eth0 --bpf "tcp or udp"

# 4. Live capture with custom 5-second aggregation windows & JSON export
go run . --live --window 5 --output live_telemetry.json

# (Press Ctrl+C at any time to stop live monitoring and print the audit summary)
```

### Mode B: Offline PCAP Forensics

```bash
# 1. Analyze an existing PCAP file
go run . --pcap capture.pcap
# or
go run . analyze capture.pcap

# 2. Custom window duration (e.g. 5 seconds)
go run . --pcap capture.pcap --window 5

# 3. Custom configuration thresholds
go run . --pcap capture.pcap --config config.yaml

# 4. Export JSON features & alerts for downstream ML / World Model
go run . --pcap capture.pcap --output alerts.json

# 5. Read PCAP stream from standard input pipe
tshark -i eth0 -F pcap -w - | go run . --stdin
```

---

## 8. Summary of Output Formats

### Sample Console Output

```text
========================================
DETERMINISTIC NETWORK THREAT DETECTOR
========================================
Input:  capture.pcap
Window: 10 seconds

--------------------------------------------------------------------------------
Window #1: 0s - 10s (10:00:00.100 to 10:00:10.100)
Packets: 42     | Bytes: 2520       | Packets/sec: 4.2     | Bytes/sec: 252.0     
TCP: 42         | SYN: 42    | SYN-ACK: 0     | ACK: 0      | RST: 0   
UDP: 0          | UDP Bytes: 0          | Unique Dst Ports: 36   | Unique Dst IPs: 1   

Threat Indicators:
  [HIGH] PORT_SCAN_INDICATOR
    Source: 192.168.1.50
    Reason: One source contacted an unusually large number of destination ports (35 unique ports in 10s window).

========================================
PROCESSING SUMMARY
========================================
Packets processed:        640
Windows processed:        3
Threat indicators raised: 4

Conclusion: 4 deterministic threat indicator(s) identified for further inspection.
```

### Sample JSON Output (`alerts.json`)

```json
[
  {
    "window_start": "2026-09-05T10:00:00.1Z",
    "window_end": "2026-09-05T10:00:10.1Z",
    "duration_seconds": 10,
    "features": {
      "total_packets": 42,
      "total_bytes": 2520,
      "packets_per_second": 4.2,
      "bytes_per_second": 252,
      "unique_source_ips": 1,
      "unique_destination_ips": 1,
      "unique_source_ports": 35,
      "unique_destination_ports": 35,
      "tcp_packets": 42,
      "syn_count": 42,
      "syn_ack_count": 0,
      "ack_count": 0,
      "rst_count": 0,
      "fin_count": 0,
      "psh_count": 0,
      "syn_per_second": 4.2,
      "ack_per_second": 0,
      "syn_ack_ratio": 42,
      "udp_packets": 0,
      "udp_bytes": 0,
      "udp_packets_per_second": 0,
      "udp_bytes_per_second": 0,
      "approx_incomplete_connections": 42
    },
    "alerts": [
      {
        "timestamp": "2026-09-05T11:27:41Z",
        "window_start": "2026-09-05T10:00:00.1Z",
        "window_end": "2026-09-05T10:00:10.1Z",
        "type": "PORT_SCAN_INDICATOR",
        "severity": "HIGH",
        "source_ip": "192.168.1.50",
        "protocol": "TCP/UDP",
        "reason": "One source contacted an unusually large number of destination ports (35 unique ports in 10s window)."
      }
    ]
  }
]
```
