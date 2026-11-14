
import subprocess
import csv
import json
import re
import time
import os
from pathlib import Path
from datetime import datetime, timezone

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = BASE_DIR / "logs"

SECURITY_LOG = LOG_DIR / "security_log.csv"
TRAFFIC_FILE = LOG_DIR / "traffic_stats.json"

SWITCH = "s1"
INTERVAL = 2


def get_flow_stats():
    command = [
        "/usr/bin/ovs-ofctl",
        "-O",
        "OpenFlow13",
        "dump-flows",
        SWITCH
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=5
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip() or "Cannot read switch"
        )

    allowed = 0
    dropped = 0
    total_bytes = 0
    flow_count = 0

    for line in result.stdout.splitlines():
        packet_match = re.search(r"\bn_packets=(\d+)", line)
        byte_match = re.search(r"\bn_bytes=(\d+)", line)

        if not packet_match or not byte_match or "actions=" not in line:
            continue

        packets = int(packet_match.group(1))
        byte_count = int(byte_match.group(1))
        actions = line.split("actions=", 1)[1].strip()

        flow_count += 1
        total_bytes += byte_count

        if actions.lower() == "drop":
            dropped += packets
        elif actions:
            allowed += packets

    return allowed, dropped, total_bytes, flow_count


def save_security_log(packets):
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    new_file = (
        not SECURITY_LOG.exists()
        or SECURITY_LOG.stat().st_size == 0
    )

    with SECURITY_LOG.open(
        "a",
        newline="",
        encoding="utf-8"
    ) as file:
        writer = csv.writer(file)

        if new_file:
            writer.writerow(["Time", "Event", "Packets"])

        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Dropped Traffic",
            packets
        ])


def save_traffic_stats(
    allowed,
    dropped,
    new_dropped,
    counters_reset,
    allowed_packet_rate,
    dropped_packet_rate,
    byte_rate,
    flow_count,
    drop_ratio
):
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "switch": SWITCH,
        "allowed_packets": allowed,
        "dropped_packets": dropped,
        "new_dropped_packets": new_dropped,
        "counters_reset": counters_reset,
        "allowed_packet_rate": round(allowed_packet_rate, 2),
        "dropped_packet_rate": round(dropped_packet_rate, 2),
        "byte_rate": round(byte_rate, 2),
        "flow_count": flow_count,
        "drop_ratio": round(drop_ratio, 4)
    }

    temp_file = TRAFFIC_FILE.with_suffix(".json.tmp")

    with temp_file.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)

    os.replace(temp_file, TRAFFIC_FILE)


def main():
    print("Starting Security Monitoring V3...")
    print("Monitoring switch:", SWITCH)
    print("Press Ctrl+C to stop")

    last_allowed = None
    last_dropped = None
    last_bytes = None
    last_time = None

    try:
        while True:
            try:
                allowed, dropped, total_bytes, flow_count = get_flow_stats()
                current_time = time.monotonic()

                new_dropped = 0
                counters_reset = False
                allowed_packet_rate = 0.0
                dropped_packet_rate = 0.0
                byte_rate = 0.0
                drop_ratio = 0.0

                if last_time is not None:
                    elapsed = current_time - last_time

                    if (
                        allowed < last_allowed
                        or dropped < last_dropped
                        or total_bytes < last_bytes
                    ):
                        counters_reset = True
                        print("Flow counters changed or reset")

                    elif elapsed > 0:
                        new_allowed = allowed - last_allowed
                        new_dropped = dropped - last_dropped
                        new_bytes = total_bytes - last_bytes

                        allowed_packet_rate = new_allowed / elapsed
                        dropped_packet_rate = new_dropped / elapsed
                        byte_rate = new_bytes / elapsed

                        total_new = new_allowed + new_dropped

                        if total_new > 0:
                            drop_ratio = new_dropped / total_new

                        if new_dropped > 0:
                            save_security_log(new_dropped)
                            print(
                                "Security Alert:",
                                new_dropped,
                                "new dropped packets"
                            )

                save_traffic_stats(
                    allowed,
                    dropped,
                    new_dropped,
                    counters_reset,
                    allowed_packet_rate,
                    dropped_packet_rate,
                    byte_rate,
                    flow_count,
                    drop_ratio
                )

                print(
                    "Allowed:", allowed,
                    "| Dropped:", dropped,
                    "| Allowed Rate:", round(allowed_packet_rate, 2),
                    "| Drop Rate:", round(dropped_packet_rate, 2),
                    "| Byte Rate:", round(byte_rate, 2),
                    "| Flows:", flow_count
                )

                last_allowed = allowed
                last_dropped = dropped
                last_bytes = total_bytes
                last_time = current_time

            except (
                RuntimeError,
                subprocess.TimeoutExpired,
                OSError,
                ValueError
            ) as error:
                print("Monitoring error:", error)
                last_allowed = None
                last_dropped = None
                last_bytes = None
                last_time = None

            time.sleep(INTERVAL)

    except KeyboardInterrupt:
        print("\nMonitoring stopped")


if __name__ == "__main__":
    main()
