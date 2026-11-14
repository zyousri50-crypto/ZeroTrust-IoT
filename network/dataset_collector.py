
#!/usr/bin/env python3
"""
ZeroTrust-IoT Dataset Collector

Collects network traffic statistics from the monitoring JSON file
and stores them in a CSV dataset for future ML experiments.
"""

import csv
import json
import time
from pathlib import Path
from datetime import datetime, timezone


PROJECT_ROOT = Path(__file__).resolve().parent.parent

STATS_FILE = PROJECT_ROOT / "logs" / "traffic_stats.json"
DATASET_FILE = PROJECT_ROOT / "logs" / "traffic_dataset.csv"

COLLECTION_INTERVAL = 2

FIELDS = [
    "timestamp",
    "switch",
    "allowed_packets",
    "dropped_packets",
    "new_dropped_packets",
    "allowed_packet_rate",
    "dropped_packet_rate",
    "byte_rate",
    "flow_count",
    "drop_ratio",
    "counters_reset",
]


def read_traffic_stats():
    """Read the latest network statistics."""

    try:
        with STATS_FILE.open("r", encoding="utf-8") as file:
            data = json.load(file)

        if not isinstance(data, dict):
            raise ValueError("Statistics must be a JSON object")

        missing = [field for field in FIELDS if field not in data]

        if missing:
            raise ValueError(
                "Missing statistics fields: " + ", ".join(missing)
            )

        return data

    except FileNotFoundError:
        print("[WARNING] Monitoring JSON file not found.")

    except (json.JSONDecodeError, ValueError, OSError) as error:
        print(f"[WARNING] Could not read statistics: {error}")

    return None


def initialize_dataset():
    """Create the dataset file and CSV header if necessary."""

    DATASET_FILE.parent.mkdir(parents=True, exist_ok=True)

    if not DATASET_FILE.exists() or DATASET_FILE.stat().st_size == 0:
        with DATASET_FILE.open(
            "w", newline="", encoding="utf-8"
        ) as file:
            writer = csv.DictWriter(file, fieldnames=FIELDS)
            writer.writeheader()

        print("[INFO] Dataset file initialized.")


def save_sample(data):
    """Append one monitoring sample to the dataset."""

    sample = {field: data[field] for field in FIELDS}

    with DATASET_FILE.open(
        "a", newline="", encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)
        writer.writerow(sample)

    print(
        "[SAVED] "
        f"Time: {sample['timestamp']} | "
        f"Allowed Rate: {sample['allowed_packet_rate']} | "
        f"Drop Rate: {sample['dropped_packet_rate']} | "
        f"Byte Rate: {sample['byte_rate']}"
    )


def main():
    print("=" * 55)
    print("ZeroTrust-IoT Dataset Collector V1")
    print("=" * 55)

    print(f"Source: {STATS_FILE}")
    print(f"Dataset: {DATASET_FILE}")
    print(f"Collection interval: {COLLECTION_INTERVAL}s")
    print("Press Ctrl+C to stop.\n")

    initialize_dataset()

    last_timestamp = None

    try:
        while True:
            data = read_traffic_stats()

            if data is not None:
                timestamp = data["timestamp"]

                try:
                    sample_time = datetime.fromisoformat(
                        timestamp.replace("Z", "+00:00")
                    )

                    if sample_time.tzinfo is None:
                        raise ValueError(
                            "Timestamp must contain timezone information"
                        )

                    sample_age = (
                        datetime.now(timezone.utc)
                        - sample_time.astimezone(timezone.utc)
                    ).total_seconds()

                    if sample_age > 10:
                        print(
                            "[WARNING] Monitoring data is stale. "
                            "Waiting for fresh statistics."
                        )

                    elif sample_age < -10:
                        print(
                            "[WARNING] Monitoring timestamp is "
                            "in the future."
                        )

                    elif timestamp != last_timestamp:
                        save_sample(data)
                        last_timestamp = timestamp

                except (ValueError, TypeError) as error:
                    print(f"[WARNING] Invalid timestamp: {error}")

            time.sleep(COLLECTION_INTERVAL)

    except KeyboardInterrupt:
        print("\n[INFO] Dataset collection stopped.")


if __name__ == "__main__":
    main()
