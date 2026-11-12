
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

    for line in result.stdout.splitlines():
        match = re.search(r"\bn_packets=(\d+)", line)

        if not match or "actions=" not in line:
            continue

        packets = int(match.group(1))
        actions = line.split("actions=", 1)[1].strip()

        if actions == "drop":
            dropped += packets

        elif actions:
            allowed += packets

    return allowed, dropped


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
            writer.writerow([
                "Time",
                "Event",
                "Packets"
            ])

        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Dropped Traffic",
            packets
        ])


def save_traffic_stats(
    allowed,
    dropped,
    new_dropped,
    counters_reset
):
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    data = {
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "switch": SWITCH,
        "allowed_packets": allowed,
        "dropped_packets": dropped,
        "new_dropped_packets": new_dropped,
        "counters_reset": counters_reset
    }

    temp_file = TRAFFIC_FILE.with_suffix(".json.tmp")

    with temp_file.open(
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(data, file, indent=4)

    os.replace(temp_file, TRAFFIC_FILE)


def main():
    print("Starting Security Monitoring V2...")
    print("Monitoring switch:", SWITCH)
    print("Press Ctrl+C to stop")

    last_allowed = None
    last_dropped = None

    try:
        while True:
            try:
                allowed, dropped = get_flow_stats()

                new_dropped = 0
                counters_reset = False

                if last_dropped is not None:
                    if (
                        dropped < last_dropped
                        or allowed < last_allowed
                    ):
                        counters_reset = True
                        print("Flow counters changed or reset")

                    elif dropped > last_dropped:
                        new_dropped = dropped - last_dropped

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
                    counters_reset
                )

                print(
                    "Allowed:", allowed,
                    "| Dropped:", dropped
                )

                last_allowed = allowed
                last_dropped = dropped

            except (
                RuntimeError,
                subprocess.TimeoutExpired,
                OSError,
                ValueError
            ) as error:
                print("Monitoring error:", error)

            time.sleep(INTERVAL)

    except KeyboardInterrupt:
        print("\nMonitoring stopped")


if __name__ == "__main__":
    main()
