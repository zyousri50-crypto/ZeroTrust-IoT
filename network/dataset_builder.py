
#!/usr/bin/env python3
"""
ZeroTrust-IoT Labeled Dataset Builder V1

Builds a labeled dataset from monitoring samples and
recorded experiment intervals.

Labels describe controlled lab scenarios, not confirmed
real-world attacks.
"""

import csv
import math
from collections import Counter
from datetime import datetime
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = PROJECT_ROOT / "logs"

TRAFFIC_FILE = LOG_DIR / "traffic_dataset.csv"
SCENARIO_FILE = LOG_DIR / "scenario_labels.csv"
OUTPUT_FILE = LOG_DIR / "labeled_dataset.csv"

FEATURES = [
    "allowed_packet_rate",
    "dropped_packet_rate",
    "byte_rate",
    "flow_count",
    "drop_ratio",
]

OUTPUT_FIELDS = [
    "timestamp",
    "scenario_id",
    *FEATURES,
    "label",
]

SUPPORTED_LABELS = {
    "normal",
    "unauthorized_access",
    "port_scan",
    "lateral_movement",
    "ddos",
}


def parse_time(value):
    return datetime.fromisoformat(
        value.strip().replace("Z", "+00:00")
    )


def load_csv(path):
    if not path.exists():
        raise FileNotFoundError(
            f"Required file not found: {path}"
        )

    with path.open(
        "r", newline="", encoding="utf-8"
    ) as file:
        return list(csv.DictReader(file))


def load_scenarios():
    rows = load_csv(SCENARIO_FILE)
    scenarios = []

    for row in rows:
        if not row["end_time"]:
            print(
                f"[SKIP] Active scenario: "
                f"{row['scenario_id']}"
            )
            continue

        if row["label"] not in SUPPORTED_LABELS:
            print(
                f"[SKIP] Unsupported label: "
                f"{row['label']}"
            )
            continue

        start = parse_time(row["start_time"])
        end = parse_time(row["end_time"])

        if end <= start:
            print(
                f"[SKIP] Invalid interval: "
                f"{row['scenario_id']}"
            )
            continue

        scenarios.append({
            "id": row["scenario_id"],
            "label": row["label"],
            "start": start,
            "end": end,
        })

    return scenarios


def find_scenario(timestamp, scenarios):
    matches = [
        scenario
        for scenario in scenarios
        if scenario["start"] <= timestamp <= scenario["end"]
    ]

    if len(matches) != 1:
        return None

    return matches[0]


def valid_features(sample):
    values = {}

    for feature in FEATURES:
        value = float(sample[feature])

        if not math.isfinite(value):
            raise ValueError(
                f"Non-finite feature: {feature}"
            )

        if value < 0:
            raise ValueError(
                f"Negative feature: {feature}"
            )

        values[feature] = value

    return values


def build_dataset():
    samples = load_csv(TRAFFIC_FILE)
    scenarios = load_scenarios()

    accepted = []
    reasons = Counter()
    label_counts = Counter()

    seen_timestamps = set()

    for sample in samples:
        try:
            timestamp = parse_time(sample["timestamp"])

            if timestamp in seen_timestamps:
                reasons["duplicate_timestamp"] += 1
                continue

            seen_timestamps.add(timestamp)

            scenario = find_scenario(
                timestamp, scenarios
            )

            if scenario is None:
                reasons["outside_or_overlapping"] += 1
                continue

            if sample["counters_reset"].strip().lower() in {
                "true", "1", "yes"
            }:
                reasons["counter_reset"] += 1
                continue

            features = valid_features(sample)

            allowed = features["allowed_packet_rate"]
            dropped = features["dropped_packet_rate"]

            if allowed == 0 and dropped == 0:
                reasons["idle_sample"] += 1
                continue

            if allowed > 0 and dropped > 0:
                reasons["mixed_traffic"] += 1
                continue

            label = scenario["label"]

            # Only use samples consistent with the
            # expected traffic direction of each scenario.
            if label == "normal" and not (
                allowed > 0 and dropped == 0
            ):
                reasons["normal_mismatch"] += 1
                continue

            if label == "unauthorized_access" and not (
                dropped > 0 and allowed == 0
            ):
                reasons["unauthorized_mismatch"] += 1
                continue

            # Other attack classes require dedicated
            # experiments and feature validation.
            if label not in {
                "normal",
                "unauthorized_access"
            }:
                reasons["unsupported_experiment"] += 1
                continue

            row = {
                "timestamp": sample["timestamp"],
                "scenario_id": scenario["id"],
                **features,
                "label": label,
            }

            accepted.append(row)
            label_counts[label] += 1

        except (
            ValueError,
            TypeError,
            KeyError,
            OverflowError,
        ) as error:
            reasons["invalid_sample"] += 1
            print(f"[WARNING] Invalid sample: {error}")

    OUTPUT_FILE.parent.mkdir(
        parents=True, exist_ok=True
    )

    # Rebuild from source files, so rerunning the
    # builder will not duplicate existing rows.
    with OUTPUT_FILE.open(
        "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(
            file, fieldnames=OUTPUT_FIELDS
        )
        writer.writeheader()
        writer.writerows(accepted)

    print("=" * 55)
    print("ZeroTrust-IoT Labeled Dataset Builder V1")
    print("=" * 55)

    print(f"Total source samples: {len(samples)}")
    print(f"Completed scenarios: {len(scenarios)}")
    print(f"Accepted samples: {len(accepted)}")

    print("\nAccepted samples by label:")
    for label, count in sorted(label_counts.items()):
        print(f"  {label}: {count}")

    print("\nExcluded samples by reason:")
    for reason, count in sorted(reasons.items()):
        print(f"  {reason}: {count}")

    print(f"\nOutput: {OUTPUT_FILE}")

    if len(label_counts) < 2:
        print(
            "\n[WARNING] Fewer than two classes. "
            "Not ready for supervised classification."
        )

    scenario_counts = Counter(
        row["scenario_id"] for row in accepted
    )

    if len(scenario_counts) < 4:
        print(
            "[WARNING] Too few independent scenarios "
            "for a meaningful train/test evaluation."
        )

    print("\n[DONE] Dataset build completed.")


if __name__ == "__main__":
    try:
        build_dataset()
    except (FileNotFoundError, OSError) as error:
        print(f"[ERROR] {error}")
        raise SystemExit(1)
