import time
import random
from scapy.all import IP, TCP, UDP, send, RandShort

# Target is set to localhost to safely test the Netwatch engine
TARGET_IP = "127.0.0.1"
TARGET_PORT = 8080

def xmas_scan():
    """Sends packets with invalid TCP flags (FIN, PSH, URG)."""
    print(f"[*] Sending XMAS Scan to {TARGET_IP}:{TARGET_PORT}...")
    ip = IP(dst=TARGET_IP)
    tcp = TCP(sport=RandShort(), dport=TARGET_PORT, flags="FPU")
    send(ip/tcp, count=10, verbose=False)
    print("[+] XMAS Scan complete.")

def null_scan():
    """Sends TCP packets with absolutely no flags set."""
    print(f"[*] Sending NULL Scan to {TARGET_IP}:{TARGET_PORT}...")
    ip = IP(dst=TARGET_IP)
    tcp = TCP(sport=RandShort(), dport=TARGET_PORT, flags="")
    send(ip/tcp, count=10, verbose=False)
    print("[+] NULL Scan complete.")

def syn_flood(count=2000):
    """Floods the target with TCP SYN requests (simulates DoS)."""
    print(f"[*] Launching SYN Flood ({count} packets) against {TARGET_IP}:{TARGET_PORT}...")
    # Using a list comprehension to build packets quickly, then sending them
    packets = [IP(dst=TARGET_IP)/TCP(sport=RandShort(), dport=TARGET_PORT, flags="S") for _ in range(count)]
    send(packets, verbose=False)
    print("[+] SYN Flood complete.")

def udp_flood(count=2000):
    """Floods random UDP ports to test graph density and protocol shifting."""
    print(f"[*] Launching UDP Flood ({count} packets) against {TARGET_IP}...")
    packets = []
    for _ in range(count):
        ip = IP(dst=TARGET_IP)
        udp = UDP(sport=RandShort(), dport=random.randint(1024, 65535))
        payload = b"X" * 64
        packets.append(ip/udp/payload)
    send(packets, verbose=False)
    print("[+] UDP Flood complete.")

if __name__ == "__main__":
    print("=== Netwatch Attack Simulator ===")

    # 1. Stealth/Recon Attacks
    xmas_scan()
    time.sleep(2)

    null_scan()
    time.sleep(2)

    # 2. Volumetric Attacks
    syn_flood(count=1500)
    time.sleep(3)

    udp_flood(count=1500)

    print("\n=== Simulation Complete ===")
    print("Check your Netwatch dashboard for alerts and protocol shifts!")
