from __future__ import annotations

# Single authoritative CIC-IDS2018 Table-2 ground truth.
# Source: the supplied dataset table in Pasted markdown.md.
#
# Where the table gives a private machine IP and its public "Valid IP", both
# are aliases of the same endpoint and are kept together. Multi-attacker rows
# list the complete set explicitly; there is no wildcard.
#
# TIMEZONE: the start/end times below are copied verbatim from Table 2 and are
# in CAPTURE-LOCAL time (Atlantic Standard Time, UTC-4), NOT UTC. Every
# timestamp this pipeline stores is UTC. LabelMatcher applies the conversion
# (flows.SCHEDULE_UTC_OFFSET) -- do not "correct" these times here.
#
# service_ports / protocols are OPTIONAL and constrain matching the way the CIC
# paper describes ("the IPs and ports of the source and destination along with
# the protocol name"). Populate them only for a day whose service ports have
# been verified against real traffic -- a wrong port set silently drops an
# entire attack to Benign. Omitted == unconstrained (time + IP pair only).

ATTACKS = [
    {
        "name": "FTP-BruteForce",
        "day": "Wednesday-14-02-2018",
        "start": "10:32:00", "end": "12:09:00",
        "attacker_ips": ["172.31.70.4", "18.221.219.4"],
        "victim_ips": ["172.31.69.25", "18.217.21.148"],
    },
    {
        "name": "SSH-Bruteforce",
        "day": "Wednesday-14-02-2018",
        "start": "14:01:00", "end": "15:31:00",
        "attacker_ips": ["172.31.70.6", "13.58.98.64"],
        "victim_ips": ["172.31.69.25", "18.217.21.148"],
    },
    {
        "name": "DoS-GoldenEye",
        "day": "Thursday-15-02-2018",
        "start": "09:26:00", "end": "10:09:00",
        "attacker_ips": ["172.31.70.46", "18.219.211.138"],
        "victim_ips": ["172.31.69.25", "18.217.21.148"],
    },
    {
        "name": "DoS-Slowloris",
        "day": "Thursday-15-02-2018",
        "start": "10:59:00", "end": "11:40:00",
        "attacker_ips": ["172.31.70.8", "18.217.165.70"],
        "victim_ips": ["172.31.69.25", "18.217.21.148"],
    },
    # Friday-16-02-2018 ports/protocol are VERIFIED: the official labelled
    # Friday CSV has 139,890/139,890 SlowHTTPTest rows on Dst Port 21 proto 6
    # and 461,912/461,912 Hulk rows on Dst Port 80 proto 6; the generated
    # flows independently agree (105,550 flows 13.59.126.31 -> 172.31.69.25 all
    # on port 21; 1,750,476 flows 18.219.193.20 -> 172.31.69.25 all on port 80).
    {
        "name": "DoS-SlowHTTPTest",
        "day": "Friday-16-02-2018",
        "start": "10:12:00", "end": "11:08:00",
        "attacker_ips": ["172.31.70.23", "13.59.126.31"],
        "victim_ips": ["172.31.69.25", "18.217.21.148"],
        "service_ports": [21],
        "protocols": [6],
    },
    {
        "name": "DoS-Hulk",
        "day": "Friday-16-02-2018",
        "start": "13:45:00", "end": "14:19:00",
        "attacker_ips": ["172.31.70.16", "18.219.193.20"],
        "victim_ips": ["172.31.69.25", "18.217.21.148"],
        "service_ports": [80],
        "protocols": [6],
    },
    {
        "name": "DDoS attacks-LOIC-HTTP",
        "day": "Tuesday-20-02-2018",
        "start": "10:12:00", "end": "11:17:00",
        "attacker_ips": [
            "18.218.115.60", "18.219.9.1", "18.219.32.43",
            "18.218.55.126", "52.14.136.135", "18.219.5.43",
            "18.216.200.189", "18.218.229.235", "18.218.11.51",
            "18.216.24.42",
        ],
        "victim_ips": ["18.217.21.148", "172.31.69.25"],
    },
    {
        "name": "DDoS-LOIC-UDP",
        "day": "Tuesday-20-02-2018",
        "start": "13:13:00", "end": "13:32:00",
        "attacker_ips": [
            "18.218.115.60", "18.219.9.1", "18.219.32.43",
            "18.218.55.126", "52.14.136.135", "18.219.5.43",
            "18.216.200.189", "18.218.229.235", "18.218.11.51",
            "18.216.24.42",
        ],
        "victim_ips": ["18.217.21.148", "172.31.69.25"],
    },
    {
        "name": "DDOS-LOIC-UDP",
        "day": "Wednesday-21-02-2018",
        "start": "10:09:00", "end": "10:43:00",
        "attacker_ips": [
            "18.218.115.60", "18.219.9.1", "18.219.32.43",
            "18.218.55.126", "52.14.136.135", "18.219.5.43",
            "18.216.200.189", "18.218.229.235", "18.218.11.51",
            "18.216.24.42",
        ],
        "victim_ips": ["18.218.83.150", "172.31.69.28"],
    },
    {
        "name": "DDOS-HOIC",
        "day": "Wednesday-21-02-2018",
        "start": "14:05:00", "end": "15:05:00",
        "attacker_ips": [
            "18.218.115.60", "18.219.9.1", "18.219.32.43",
            "18.218.55.126", "52.14.136.135", "18.219.5.43",
            "18.216.200.189", "18.218.229.235", "18.218.11.51",
            "18.216.24.42",
        ],
        "victim_ips": ["18.218.83.150", "172.31.69.28"],
    },
    {
        "name": "Brute Force -Web",
        "day": "Thursday-22-02-2018",
        "start": "10:17:00", "end": "11:24:00",
        "attacker_ips": ["18.218.115.60"],
        "victim_ips": ["18.218.83.150", "172.31.69.28"],
    },
    {
        "name": "Brute Force -XSS",
        "day": "Thursday-22-02-2018",
        "start": "13:50:00", "end": "14:29:00",
        "attacker_ips": ["18.218.115.60"],
        "victim_ips": ["18.218.83.150", "172.31.69.28"],
    },
    {
        "name": "SQL Injection",
        "day": "Thursday-22-02-2018",
        "start": "16:15:00", "end": "16:29:00",
        "attacker_ips": ["18.218.115.60"],
        "victim_ips": ["18.218.83.150", "172.31.69.28"],
    },
    {
        "name": "Brute Force -Web",
        "day": "Friday-23-02-2018",
        "start": "10:03:00", "end": "11:03:00",
        "attacker_ips": ["18.218.115.60"],
        "victim_ips": ["18.218.83.150", "172.31.69.28"],
    },
    {
        "name": "Brute Force -XSS",
        "day": "Friday-23-02-2018",
        "start": "13:00:00", "end": "14:10:00",
        "attacker_ips": ["18.218.115.60"],
        "victim_ips": ["18.218.83.150", "172.31.69.28"],
    },
    {
        "name": "SQL Injection",
        "day": "Friday-23-02-2018",
        "start": "15:05:00", "end": "15:18:00",
        "attacker_ips": ["18.218.115.60"],
        "victim_ips": ["18.218.83.150", "172.31.69.28"],
    },
    {
        "name": "Infiltration",
        "day": "Wednesday-28-02-2018",
        "start": "10:50:00", "end": "12:05:00",
        "attacker_ips": ["13.58.225.34"],
        "victim_ips": ["18.221.148.137", "172.31.69.24"],
    },
    {
        "name": "Infiltration",
        "day": "Wednesday-28-02-2018",
        "start": "13:42:00", "end": "14:40:00",
        "attacker_ips": ["13.58.225.34"],
        "victim_ips": ["18.221.148.137", "172.31.69.24"],
    },
    {
        "name": "Infiltration",
        "day": "Thursday-01-03-2018",
        "start": "09:57:00", "end": "10:55:00",
        "attacker_ips": ["13.58.225.34"],
        "victim_ips": ["18.216.254.154", "172.31.69.13"],
    },
    # The supplied table contains this exact row twice. It is intentionally
    # represented once because duplicate identical rules add no information
    # and would make overlap validation ambiguous.
    {
        "name": "Infiltration",
        "day": "Thursday-01-03-2018",
        "start": "14:00:00", "end": "15:37:00",
        "attacker_ips": ["13.58.225.34"],
        "victim_ips": ["18.216.254.154", "172.31.69.13"],
    },
    {
        "name": "Bot",
        "day": "Friday-02-03-2018",
        "start": "10:11:00", "end": "11:34:00",
        "attacker_ips": ["18.219.211.138"],
        "victim_ips": [
            "18.217.218.111", "172.31.69.23",
            "18.222.10.237", "172.31.69.17",
            "18.222.86.193", "172.31.69.14",
            "18.222.62.221", "172.31.69.12",
            "13.59.9.106", "172.31.69.10",
            "18.222.102.2", "172.31.69.8",
            "18.219.212.0", "172.31.69.6",
            "18.216.105.13", "172.31.69.26",
            "18.219.163.126", "172.31.69.29",
            "18.216.164.12", "172.31.69.30",
        ],
    },
    {
        "name": "Bot",
        "day": "Friday-02-03-2018",
        "start": "14:24:00", "end": "15:55:00",
        "attacker_ips": ["18.219.211.138"],
        "victim_ips": [
            "18.217.218.111", "172.31.69.23",
            "18.222.10.237", "172.31.69.17",
            "18.222.86.193", "172.31.69.14",
            "18.222.62.221", "172.31.69.12",
            "13.59.9.106", "172.31.69.10",
            "18.222.102.2", "172.31.69.8",
            "18.219.212.0", "172.31.69.6",
            "18.216.105.13", "172.31.69.26",
            "18.219.163.126", "172.31.69.29",
            "18.216.164.12", "172.31.69.30",
        ],
    },
    # NOT a Table-2 row. Between the table's two Bot windows the infected hosts
    # never stop polling their C2 server (18.219.211.138:8080): a flat 536
    # flows/min of 4.5-packet, 227-byte flows, identical to the heartbeat inside
    # window 2. CIC's own labelled CSV marks all 286,191 attacker<->victim flows
    # Bot, 91,602 of them in this gap; the table's windows alone left 94,027 as
    # Benign. Labelled Bot and tagged, so the two table phases stay separable.
    # It shares the windows' boundaries, since packet times are sub-second, and
    # is listed after them, so an instant on a boundary keeps the table's tag.
    {
        "name": "Bot",
        "day": "Friday-02-03-2018",
        "start": "11:34:00", "end": "14:24:00",
        "attacker_ips": ["18.219.211.138"],
        "victim_ips": [
            "18.217.218.111", "172.31.69.23",
            "18.222.10.237", "172.31.69.17",
            "18.222.86.193", "172.31.69.14",
            "18.222.62.221", "172.31.69.12",
            "13.59.9.106", "172.31.69.10",
            "18.222.102.2", "172.31.69.8",
            "18.219.212.0", "172.31.69.6",
            "18.216.105.13", "172.31.69.26",
            "18.219.163.126", "172.31.69.29",
            "18.216.164.12", "172.31.69.30",
        ],
        "confidence": "c2_heartbeat_between_table_windows",
    },
    # NOT a Table-2 row. Slowloris connections keep starting after the table's 11:40 end: 712 attacker->victim
    # port-80 flows up to 11:42:01, the same shape (3 s, 2 packets out, 1 back) as inside the window. CIC's
    # labelled CSV marks all of them DoS attacks-Slowloris: its 10,990 rows equal every forward port-80 flow
    # 10:59-11:42:01, minute by minute. The 505 victim replies at 11:41:34 (source port 80) CIC leaves Benign;
    # here they are labelled and marked reverse, as for every DoS rule. Listed after the table row, so an
    # instant on its boundary keeps the table's tag.
    {
        "name": "DoS-Slowloris",
        "day": "Thursday-15-02-2018",
        "start": "11:40:00", "end": "11:42:01",
        "attacker_ips": ["172.31.70.8", "18.217.165.70"],
        "victim_ips": ["172.31.69.25", "18.217.21.148"],
        "confidence": "attack_tail_after_table_window",
    },
    # NOT Table-2 rows. Inside both Infiltration windows the compromised victim 172.31.69.13 scans the internal
    # network: about 1,000 ports on 5 hosts and 21-25 ports on 15 more, none of which it contacts outside the
    # windows -- 38,515 flows, plus 1,470 replies from the probed services (source ports 445, 3389, 22; no
    # backward packets). The table's rows pair only the external attacker with the victim, so they label the
    # C2 session alone (70 flows) and left the scan Benign. CIC's CSV labels 93,063 Infilteration rows in these
    # windows but carries no IPs, so its scope cannot be reproduced; these rules label the scan only. The
    # gateway 172.31.69.1 is left out: 58 scan flows beside its own DHCP traffic. The C2 session between the
    # windows stays Benign, as in CIC's CSV (97 rows, all Benign).
    {
        "name": "Infiltration",
        "day": "Thursday-01-03-2018",
        "start": "09:57:00", "end": "10:55:00",
        "attacker_ips": ["172.31.69.13"],
        "victim_ips": [
            "172.31.69.7",
            "172.31.69.15",
            "172.31.69.18",
            "172.31.69.21",
            "172.31.69.22",
            "172.31.69.4",
            "172.31.69.5",
            "172.31.69.6",
            "172.31.69.8",
            "172.31.69.9",
            "172.31.69.10",
            "172.31.69.11",
            "172.31.69.12",
            "172.31.69.14",
            "172.31.69.16",
            "172.31.69.17",
            "172.31.69.19",
            "172.31.69.20",
            "172.31.69.23",
            "172.31.69.24",
        ],
        "confidence": "internal_scan_from_compromised_host",
    },
    {
        "name": "Infiltration",
        "day": "Thursday-01-03-2018",
        "start": "14:00:00", "end": "15:37:00",
        "attacker_ips": ["172.31.69.13"],
        "victim_ips": [
            "172.31.69.7",
            "172.31.69.15",
            "172.31.69.18",
            "172.31.69.21",
            "172.31.69.22",
            "172.31.69.4",
            "172.31.69.5",
            "172.31.69.6",
            "172.31.69.8",
            "172.31.69.9",
            "172.31.69.10",
            "172.31.69.11",
            "172.31.69.12",
            "172.31.69.14",
            "172.31.69.16",
            "172.31.69.17",
            "172.31.69.19",
            "172.31.69.20",
            "172.31.69.23",
            "172.31.69.24",
        ],
        "confidence": "internal_scan_from_compromised_host",
    },
]

# Content-derived, so editing the table invalidates Parquet written under the
# old one.
#
# The matcher's LOGIC version is mixed in as well: a fix to how labels are
# computed (timezone handling, port matching, direction) invalidates existing
# Parquet exactly as a change to the table above does. Without this, the
# timezone fix would have silently reused Parquet full of wrong labels.
import hashlib
import json

from ingest.sources.flows import LABEL_LOGIC_VERSION

LABEL_CONFIG_VERSION = "cic-ids2018-table-v3-" + hashlib.sha256(
    json.dumps(
        {"attacks": ATTACKS, "logic": LABEL_LOGIC_VERSION},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
).hexdigest()[:16]


def label_config_version(day: str) -> str:
    """Fingerprint of one day's attack rules and the labelling logic.

    Input:  dataset day
    Output: version string

    Per day: a rule added to one day must not invalidate every other day's
    output, as one global hash over the whole table would.
    """
    return "cic-ids2018-day-v1-" + hashlib.sha256(
        json.dumps(
            {"attacks": [a for a in ATTACKS if a["day"] == day], "logic": LABEL_LOGIC_VERSION},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()[:16]
