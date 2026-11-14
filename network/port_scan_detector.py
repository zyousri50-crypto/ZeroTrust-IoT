#!/usr/bin/env python3

import csv
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import IP, TCP, sniff

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "logs" / "port_scan_alerts.csv"

INTERFACE = "s1-eth2"
WINDOW_SECONDS = 10
PORT_THRESHOLD = 10
ALERT_COOLDOWN = 30

connections = defaultdict(deque)
last_alert = {}


def save_alert(source, destination, ports):
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    new_file = not LOG_FILE.exists() or LOG_FILE.stat().st_size == 0

    with LOG_FILE.open("a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        if new_file:
            writer.writerow([
                "timestamp",
                "attack_type",
                "source_ip",
                "destination_ip",
                "unique_ports",
                "ports"
            ])

        writer.writerow([
            datetime.now(timezone.utc).isoformat(),
            "port_scan",
            source,
            destination,
            len(ports),
            ",".join(map(str, sorted(ports)))
        ])


def process_packet(packet):
    if IP not in packet or TCP not in packet:
        return

    tcp = packet[TCP]

    # Detect initial SYN packets, not SYN-ACK responses.
    if not (tcp.flags & 0x02) or (tcp.flags & 0x10):
        return

    source = packet[IP].src
    destination = packet[IP].dst
    port = int(tcp.dport)

    key = (source, destination)
    now = time.monotonic()

    events = connections[key]
    events.append((now, port))

    while events and now - events[0][0] > WINDOW_SECONDS:
        events.popleft()

    unique_ports = {p for _, p in events}

    if len(unique_ports) < PORT_THRESHOLD:
        return

    if now - last_alert.get(key, float("-inf")) < ALERT_COOLDOWN:
        return

    last_alert[key] = now

    save_alert(source, destination, unique_ports)

    print(
        f"[PORT SCAN ALERT] {source} -> {destination} "
        f"| Unique ports: {len(unique_ports)} "
        f"| Ports: {sorted(unique_ports)}",
        flush=True
    )


def main():
    print("=" * 60)
    print("ZeroTrust-IoT Port Scan Detector V1")
    print("=" * 60)
    print(f"[INTERFACE] {INTERFACE}")
    print(f"[WINDOW] {WINDOW_SECONDS} seconds")
    print(f"[THRESHOLD] {PORT_THRESHOLD} unique ports")
    print(f"[LOG] {LOG_FILE}")
    print("[MODE] Detection only - no automatic blocking")
    print("[INFO] Press Ctrl+C to stop", flush=True)

    try:
        sniff(
            iface=INTERFACE,
            filter="tcp",
            prn=process_packet,
            store=False
        )
    except KeyboardInterrupt:
        print("\n[STOPPED] Detector stopped")


if __name__ == "__main__":
    main()
