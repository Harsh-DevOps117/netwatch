The detector evaluates traffic in fixed windows—10 seconds by default. All rules are enabled in `cli/config.yaml`, and each raises an “indicator,” not proof of an attack.

| Rule | What it watches | Default trigger |
|---|---|---|
| Port scan | One source IP contacting many destination ports | ≥20 unique ports/window |
| Host scan | One source IP contacting many destination IPs | ≥20 unique hosts/window |
| SYN flood | Excessive TCP connection-start packets or many unanswered SYNs | ≥500 SYN/s, **or** ≥50 SYNs with SYN:SYN-ACK ratio ≥5 |
| ACK flood | Excessive TCP ACK packets | ≥1,000 ACK/s |
| RST flood | Excessive TCP reset packets, possibly tearing down connections | ≥500 RST/s |
| UDP flood | Excessive UDP packet traffic | ≥1,000 UDP packets/s |
| ICMP flood | Excessive ICMP traffic such as ping flooding | ≥300 ICMP packets/s |
| Ping sweep | One source sending ICMP Echo requests to many hosts | ≥15 unique targets/window |
| DNS amplification/flood | Unusually heavy DNS traffic | ≥500 DNS packets/s **or** ≥500,000 bytes/s |
| Stealth scan | TCP scan patterns designed to avoid ordinary SYN-scan detection | ≥3 NULL, XMAS, or FIN-only packets/window |
| Connection burst | Sudden surge of new TCP connection attempts | ≥500 SYN/s |
| Suspicious TCP flags | Invalid/abnormal TCP flag combinations | Any `SYN+FIN`, `SYN+RST`, or `FIN+RST` packet |

The stealth-scan rule is really three detections:

- **NULL scan:** TCP packet has no control flags.
- **XMAS scan:** TCP packet has `FIN + PSH + URG`.
- **FIN scan:** TCP packet has only `FIN` (no ACK).

A few implementation details matter:

- Port and host scan rules count all relevant TCP/UDP packets; they do not require a completed connection.
- SYN flood and connection burst both look at SYN rate, so one burst can intentionally produce both alerts; SYN flood has the extra unacknowledged-SYN ratio test.
- DNS detection is a traffic-volume heuristic. It does not currently validate DNS response/request amplification ratios.
- Flag rules report every detected illegal flag combination in the window.

You can tune or disable any of these in [config.yaml](/home/harshkharwar/Desktop/netwatch/cli/config.yaml).
