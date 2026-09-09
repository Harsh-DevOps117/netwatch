# NetFlow Packet Ingestion Pipeline (Go + Npcap + Apache Kafka)

A high-performance network packet capture and ingestion pipeline built in Golang. It captures network traffic concurrently from both **WiFi** and **Ethernet** interfaces on Windows using Npcap, decodes network layer metadata, and stream-publishes JSON events to **Apache Kafka**.

---

## Features

- **Multi-Interface Ingestion**: Captures network packets simultaneously from active WiFi and Ethernet network adapters.
- **Auto-Discovery**: Automatically enumerates and classifies network interfaces (`WiFi`, `Ethernet`, `Loopback`).
- **Kafka Streaming**: High-throughput async batch producer publishing JSON events to topic `network-packets`.
- **Packet Decoding**: Extracts MAC addresses, IP headers (IPv4/IPv6), Transport ports (TCP/UDP/ICMP), protocol types, payload length, and hex payload previews.
- **BPF Filtering**: Custom Berkeley Packet Filter strings support (e.g., `tcp or udp`, `port 80 or port 443`).
- **Built-in Simulator**: Included `-simulate` mode to test Kafka ingestion immediately without needing Npcap or GCC setup.

---

## Architecture

```
                       ┌──────────────────────┐
                       │  WiFi Interface      │──────┐
                       └──────────────────────┘      │
                                                     ▼
                       ┌──────────────────────┐   ┌──────────────────────┐   ┌──────────────────────┐   ┌──────────────────────┐
                       │  Ethernet Interface  │──►│  Npcap / gopacket    │──►│  Packet Decoder      │──►│  Kafka Async Writer  │──► Kafka Broker
                       └──────────────────────┘   │  Capture Engine      │   │  (JSON Serializer)   │   │  (segmentio/kafka-go)│    (localhost:9092)
                                                  └──────────────────────┘   └──────────────────────┘   └──────────────────────┘
```

---

## Prerequisites & Installation

### 1. Apache Kafka
Kafka must be running on `localhost:9092`. (If running in Docker):
```bash
docker ps
```

### 2. Npcap Driver (For Live Packet Capture)
1. Download Npcap from [https://npcap.com/](https://npcap.com/).
2. Run the installer. **IMPORTANT**: Check the option **"Install Npcap in WinPcap API-compatible Mode"** during installation.

### 3. C Compiler for Windows (CGO Requirement for Live Capture)
`gopacket/pcap` connects to Windows `wpcap.dll` using CGO.
To compile live capture mode on Windows, install a C compiler such as **MinGW-w64**:
- Download [w64devkit](https://github.com/skeeto/w64devkit/releases) or install via Chocolatey:
  ```powershell
  choco install mingw
  ```
- Verify `gcc` is in your `PATH`:
  ```powershell
  gcc --version
  ```

---

## Usage Guide

### 1. Test Pipeline Immediately (Simulation Mode - No GCC/Npcap required)
You can test the entire Kafka ingestion pipeline with synthetic traffic right away:
```powershell
go run main.go -simulate
```

### 2. List Network Interfaces
List all available Npcap network devices detected on your system:
```powershell
go run main.go -list-ifaces
```

### 3. Run Live Packet Capture (WiFi + Ethernet -> Kafka)
Run the pipeline to capture live traffic from WiFi and Ethernet adapters:
```powershell
go run main.go -kafka "localhost:9092" -topic "network-packets"
```

### 4. Capture with Specific Interface or Filter
- **Specific Interface Keyword**:
  ```powershell
  go run main.go -iface "Wi-Fi,Ethernet"
  ```
- **BPF Traffic Filter (e.g. TCP/UDP only)**:
  ```powershell
  go run main.go -bpf "tcp or udp"
  ```

---

## Command Line Flags

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-kafka` | `localhost:9092` | Comma-separated list of Kafka broker addresses |
| `-topic` | `network-packets` | Target Kafka topic for packet events |
| `-iface` | `""` | Filter interfaces by name/keyword (defaults to WiFi + Ethernet) |
| `-bpf` | `""` | BPF filter expression (e.g. `port 80`, `tcp`, `icmp`) |
| `-simulate` | `false` | Run synthetic packet generator mode |
| `-list-ifaces` | `false` | Display all Npcap network adapters and exit |
| `-batch-size` | `100` | Kafka producer message batch size |
| `-batch-timeout`| `200ms` | Kafka producer batch timeout |

---

## Sample Kafka Packet Event (JSON Schema)

```json
{
  "id": "1725510000000000000-64",
  "timestamp": "2026-09-05T01:45:00Z",
  "interface_name": "Wi-Fi Adapter (Intel Wi-Fi 6 AX201)",
  "interface_type": "WiFi",
  "src_mac": "00:11:22:33:44:55",
  "dst_mac": "aa:bb:cc:dd:ee:ff",
  "ether_type": "IPv4",
  "src_ip": "192.168.1.105",
  "dst_ip": "142.250.190.46",
  "src_port": 54321,
  "dst_port": 443,
  "protocol": "TCP",
  "length": 64,
  "payload_len": 32,
  "payload_hex": "4500003c1c4640004006b1e6c0a8010108080808"
}
```
