
#!/usr/bin/env python3
"""
ZeroTrust-IoT Live ML Detection Engine V3

Experimental Random Forest traffic classification.

Features:
- Live traffic monitoring
- Idle traffic filtering
- Mixed traffic filtering
- Stale sample filtering
- Counter reset filtering
- ML prediction logging
- Mixed traffic logging
- No automatic blocking

IMPORTANT:
This is a laboratory baseline, not a validated IDS.
"""

import csv
import json
import math
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np


PROJECT_ROOT = Path(__file__).resolve().parent.parent

MODEL_FILE = (
    PROJECT_ROOT / "ml" / "models"
    / "random_forest_model.joblib"
)

STATS_FILE = (
    PROJECT_ROOT / "logs" / "traffic_stats.json"
)

DETECTION_LOG = (
    PROJECT_ROOT / "logs" / "ml_detection_log.csv"
)

MIXED_LOG = (
    PROJECT_ROOT / "logs" / "mixed_traffic_log.csv"
)

FEATURES = [
    "allowed_packet_rate",
    "dropped_packet_rate",
    "byte_rate",
    "flow_count",
    "drop_ratio",
]

DETECTION_FIELDS = [
    "timestamp",
    "source_timestamp",
    "prediction",
    "confidence",
] + FEATURES

MIXED_FIELDS = [
    "timestamp",
    "source_timestamp",
    "reason",
] + FEATURES

POLL_INTERVAL = 2
MAX_SAMPLE_AGE = 10


def utc_now():
    return datetime.now(timezone.utc)


def load_model():
    if not MODEL_FILE.exists():
        raise FileNotFoundError(
            f"Model not found: {MODEL_FILE}"
        )

    bundle = joblib.load(MODEL_FILE)

    if not isinstance(bundle, dict):
        raise ValueError("Invalid model bundle")

    if bundle.get("features") != FEATURES:
        raise ValueError(
            "Model feature order mismatch"
        )

    model = bundle.get("model")

    if model is None:
        raise ValueError("Model missing from bundle")

    if not hasattr(model, "predict_proba"):
        raise ValueError(
            "Model does not support predict_proba"
        )

    return model


def read_stats():
    if not STATS_FILE.exists():
        return None

    try:
        with STATS_FILE.open(
            "r",
            encoding="utf-8",
        ) as file:
            data = json.load(file)

        if not isinstance(data, dict):
            raise ValueError(
                "Traffic statistics must be an object"
            )

        return data

    except (
        json.JSONDecodeError,
        OSError,
        ValueError,
    ):
        return None


def extract_features(stats):
    values = []

    for feature in FEATURES:
        value = float(stats[feature])

        if not math.isfinite(value) or value < 0:
            raise ValueError(
                f"Invalid feature: {feature}"
            )

        values.append(value)

    return np.array(
        [values],
        dtype=float,
    )


def classify_traffic_state(stats):
    allowed_rate = float(
        stats["allowed_packet_rate"]
    )

    dropped_rate = float(
        stats["dropped_packet_rate"]
    )

    if allowed_rate == 0 and dropped_rate == 0:
        return "idle"

    if allowed_rate > 0 and dropped_rate > 0:
        return "mixed"

    return "active"


def prepare_csv(path, fieldnames):
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    if (
        not path.exists()
        or path.stat().st_size == 0
    ):
        with path.open(
            "w",
            newline="",
            encoding="utf-8",
        ) as file:
            writer = csv.DictWriter(
                file,
                fieldnames=fieldnames,
            )

            writer.writeheader()


def append_csv(path, fieldnames, row):
    with path.open(
        "a",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writerow(row)


def build_log_row(stats):
    row = {
        "timestamp": utc_now().isoformat(),
        "source_timestamp": stats["timestamp"],
    }

    for feature in FEATURES:
        row[feature] = stats[feature]

    return row


def save_detection(stats, prediction, confidence):
    row = build_log_row(stats)

    row["prediction"] = prediction
    row["confidence"] = round(confidence, 4)

    append_csv(
        DETECTION_LOG,
        DETECTION_FIELDS,
        row,
    )


def save_mixed_traffic(stats):
    row = build_log_row(stats)

    row["reason"] = (
        "allowed_and_dropped_traffic"
    )

    append_csv(
        MIXED_LOG,
        MIXED_FIELDS,
        row,
    )


def parse_sample_time(timestamp):
    sample_time = datetime.fromisoformat(
        timestamp.replace("Z", "+00:00")
    )

    if sample_time.tzinfo is None:
        raise ValueError(
            "Sample timestamp has no timezone"
        )

    return sample_time


def process_sample(stats, model):
    timestamp = stats["timestamp"]

    sample_time = parse_sample_time(timestamp)

    age = (
        utc_now() - sample_time
    ).total_seconds()

    if age < -5 or age > MAX_SAMPLE_AGE:
        print(
            "[SKIP] Stale or future sample"
        )
        return

    if str(
        stats.get("counters_reset", False)
    ).lower() in {
        "true",
        "1",
        "yes",
    }:
        print(
            "[SKIP] OpenFlow counters reset"
        )
        return

    X = extract_features(stats)

    traffic_state = classify_traffic_state(
        stats
    )

    if traffic_state == "idle":
        print(
            "[IDLE] No active traffic "
            "- prediction skipped"
        )
        return

    if traffic_state == "mixed":
        save_mixed_traffic(stats)

        print(
            "[MIXED] Allowed and dropped traffic "
            "detected - prediction skipped"
        )
        return

    prediction = str(
        model.predict(X)[0]
    )

    probabilities = model.predict_proba(X)[0]

    confidence = float(
        np.max(probabilities)
    )

    save_detection(
        stats,
        prediction,
        confidence,
    )

    status = (
        "ALERT-CANDIDATE"
        if prediction == "unauthorized_access"
        else "NORMAL"
    )

    print(
        f"[{status}] "
        f"{prediction} | "
        f"confidence={confidence:.2%} | "
        f"allowed={stats['allowed_packet_rate']} | "
        f"dropped={stats['dropped_packet_rate']}"
    )


def run_detector():
    model = load_model()

    prepare_csv(
        DETECTION_LOG,
        DETECTION_FIELDS,
    )

    prepare_csv(
        MIXED_LOG,
        MIXED_FIELDS,
    )

    print("=" * 60)
    print(
        "ZeroTrust-IoT Live ML Detection Engine V3"
    )
    print("=" * 60)

    print("[READY] Random Forest model loaded")
    print(f"[SOURCE] {STATS_FILE}")
    print(f"[DETECTION LOG] {DETECTION_LOG}")
    print(f"[MIXED LOG] {MIXED_LOG}")
    print("[FILTER] Idle filtering enabled")
    print("[FILTER] Mixed filtering enabled")
    print("[MODE] Experimental monitoring only")
    print("[INFO] Press Ctrl+C to stop\n")

    last_timestamp = None

    try:
        while True:
            stats = read_stats()

            if stats is None:
                print(
                    "[WAIT] Traffic stats unavailable"
                )

            else:
                try:
                    timestamp = stats["timestamp"]

                    if timestamp != last_timestamp:
                        last_timestamp = timestamp

                        process_sample(
                            stats,
                            model,
                        )

                except (
                    ValueError,
                    TypeError,
                    KeyError,
                    OverflowError,
                    AttributeError,
                ) as error:
                    print(
                        f"[WARNING] Invalid sample: {error}"
                    )

            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        print(
            "\n[STOPPED] Detector stopped by user"
        )


if __name__ == "__main__":
    try:
        run_detector()

    except (
        FileNotFoundError,
        ValueError,
        OSError,
        KeyError,
    ) as error:
        print(f"[ERROR] {error}")
        sys.exit(1)
