
#!/usr/bin/env python3
"""
ZeroTrust-IoT Scenario Labeler V1

Records experiment start/end times and labels.
Does not modify the original traffic dataset.
"""

import argparse
import csv
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCENARIO_FILE = PROJECT_ROOT / "logs" / "scenario_labels.csv"

FIELDS = [
    "scenario_id",
    "label",
    "start_time",
    "end_time",
    "description",
]

ALLOWED_LABELS = [
    "normal",
    "unauthorized_access",
    "port_scan",
    "lateral_movement",
    "ddos",
]


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def initialize_file():
    SCENARIO_FILE.parent.mkdir(parents=True, exist_ok=True)

    if (
        not SCENARIO_FILE.exists()
        or SCENARIO_FILE.stat().st_size == 0
    ):
        with SCENARIO_FILE.open(
            "w", newline="", encoding="utf-8"
        ) as file:
            writer = csv.DictWriter(file, fieldnames=FIELDS)
            writer.writeheader()


def read_scenarios():
    with SCENARIO_FILE.open(
        "r", newline="", encoding="utf-8"
    ) as file:
        return list(csv.DictReader(file))


def write_scenarios(scenarios):
    with SCENARIO_FILE.open(
        "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(scenarios)


def start_scenario(args):
    scenarios = read_scenarios()

    if any(
        row["scenario_id"] == args.id
        for row in scenarios
    ):
        print("[ERROR] Scenario ID already exists.")
        return 1

    if any(not row["end_time"] for row in scenarios):
        print(
            "[ERROR] Another scenario is still active. "
            "Stop it before starting a new one."
        )
        return 1

    scenario = {
        "scenario_id": args.id,
        "label": args.label,
        "start_time": utc_now(),
        "end_time": "",
        "description": args.description,
    }

    with SCENARIO_FILE.open(
        "a", newline="", encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)
        writer.writerow(scenario)

    print(f"[STARTED] Scenario: {args.id}")
    print(f"[LABEL] {args.label}")
    print(f"[TIME] {scenario['start_time']}")
    return 0


def stop_scenario(args):
    scenarios = read_scenarios()

    matching = [
        row for row in scenarios
        if row["scenario_id"] == args.id
    ]

    if not matching:
        print("[ERROR] Scenario ID not found.")
        return 1

    scenario = matching[0]

    if scenario["end_time"]:
        print("[ERROR] Scenario already stopped.")
        return 1

    scenario["end_time"] = utc_now()

    write_scenarios(scenarios)

    print(f"[STOPPED] Scenario: {args.id}")
    print(f"[TIME] {scenario['end_time']}")
    return 0


def list_scenarios():
    scenarios = read_scenarios()

    if not scenarios:
        print("[INFO] No scenarios recorded yet.")
        return 0

    for row in scenarios:
        status = (
            "COMPLETED"
            if row["end_time"]
            else "RUNNING"
        )

        print(
            f"{row['scenario_id']} | "
            f"{row['label']} | "
            f"{status}"
        )

    return 0


def main():
    parser = argparse.ArgumentParser(
        description="ZeroTrust-IoT Scenario Labeler"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    start_parser = subparsers.add_parser("start")

    start_parser.add_argument(
        "--id",
        required=True,
    )

    start_parser.add_argument(
        "--label",
        required=True,
        choices=ALLOWED_LABELS,
    )

    start_parser.add_argument(
        "--description",
        default="",
    )

    stop_parser = subparsers.add_parser("stop")

    stop_parser.add_argument(
        "--id",
        required=True,
    )

    subparsers.add_parser("list")

    args = parser.parse_args()

    initialize_file()

    if args.command == "start":
        return start_scenario(args)

    if args.command == "stop":
        return stop_scenario(args)

    if args.command == "list":
        return list_scenarios()

    return 1


if __name__ == "__main__":
    sys.exit(main())
