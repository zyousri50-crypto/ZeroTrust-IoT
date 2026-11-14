
#!/usr/bin/env python3
"""
ZeroTrust-IoT Machine Learning Training V1

Train and evaluate a Random Forest classifier using
scenario-separated network traffic samples.

IMPORTANT:
This is an experimental baseline, not a validated
real-world intrusion detection system.
"""

import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATASET_FILE = (
    PROJECT_ROOT / "logs" / "labeled_dataset.csv"
)

MODEL_DIR = PROJECT_ROOT / "ml" / "models"
MODEL_FILE = MODEL_DIR / "random_forest_model.joblib"
REPORT_FILE = MODEL_DIR / "training_report.json"

FEATURES = [
    "allowed_packet_rate",
    "dropped_packet_rate",
    "byte_rate",
    "flow_count",
    "drop_ratio",
]

LABELS = [
    "normal",
    "unauthorized_access",
]

TRAIN_SCENARIOS = {
    "normal_001",
    "unauthorized_001",
}

TEST_SCENARIOS = {
    "normal_002",
    "unauthorized_002",
}


def load_dataset():
    if not DATASET_FILE.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATASET_FILE}"
        )

    with DATASET_FILE.open(
        "r", newline="", encoding="utf-8"
    ) as file:
        rows = list(csv.DictReader(file))

    if not rows:
        raise ValueError("The dataset is empty.")

    return rows


def prepare_data(rows):
    train_rows = []
    test_rows = []

    for row in rows:
        scenario_id = row["scenario_id"]

        if row["label"] not in LABELS:
            continue

        if scenario_id in TRAIN_SCENARIOS:
            train_rows.append(row)

        elif scenario_id in TEST_SCENARIOS:
            test_rows.append(row)

    if not train_rows or not test_rows:
        raise ValueError(
            "Training or testing data is missing."
        )

    train_labels = {r["label"] for r in train_rows}
    test_labels = {r["label"] for r in test_rows}

    if train_labels != set(LABELS):
        raise ValueError(
            "Training data must contain both classes."
        )

    if test_labels != set(LABELS):
        raise ValueError(
            "Testing data must contain both classes."
        )

    def convert_features(selected_rows):
        matrix = np.array(
            [
                [float(row[feature]) for feature in FEATURES]
                for row in selected_rows
            ],
            dtype=float,
        )

        if not np.isfinite(matrix).all():
            raise ValueError(
                "Dataset contains invalid numeric values."
            )

        return matrix

    X_train = convert_features(train_rows)
    y_train = np.array(
        [row["label"] for row in train_rows]
    )

    X_test = convert_features(test_rows)
    y_test = np.array(
        [row["label"] for row in test_rows]
    )

    return (
        X_train,
        y_train,
        X_test,
        y_test,
        train_rows,
        test_rows,
    )


def train_and_evaluate():
    rows = load_dataset()

    (
        X_train,
        y_train,
        X_test,
        y_test,
        train_rows,
        test_rows,
    ) = prepare_data(rows)

    print("=" * 60)
    print("ZeroTrust-IoT ML Training - Random Forest V1")
    print("=" * 60)

    print(f"Total labeled samples: {len(rows)}")
    print(f"Training samples: {len(train_rows)}")
    print(f"Testing samples: {len(test_rows)}")

    print("\nTraining class distribution:")
    for label, count in sorted(
        Counter(y_train).items()
    ):
        print(f"  {label}: {count}")

    print("\nTesting class distribution:")
    for label, count in sorted(
        Counter(y_test).items()
    ):
        print(f"  {label}: {count}")

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=5,
        min_samples_leaf=2,
        random_state=42,
        class_weight="balanced",
        n_jobs=1,
    )

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    accuracy = accuracy_score(
        y_test, predictions
    )

    precision, recall, f1, _ = (
        precision_recall_fscore_support(
            y_test,
            predictions,
            labels=LABELS,
            zero_division=0,
        )
    )

    matrix = confusion_matrix(
        y_test,
        predictions,
        labels=LABELS,
    )

    print("\nModel Evaluation:")
    print(f"Accuracy: {accuracy:.4f}")

    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            predictions,
            labels=LABELS,
            zero_division=0,
        )
    )

    print("Confusion Matrix:")
    print("Labels:", LABELS)
    print(matrix)

    print("\nFeature Importance:")
    importance = sorted(
        zip(FEATURES, model.feature_importances_),
        key=lambda item: item[1],
        reverse=True,
    )

    for name, score in importance:
        print(f"  {name}: {score:.4f}")

    MODEL_DIR.mkdir(
        parents=True, exist_ok=True
    )

    # Save the model together with its expected feature
    # order, so inference uses the same input structure.
    model_bundle = {
        "model": model,
        "features": FEATURES,
        "labels": LABELS,
        "version": "1.0",
    }

    joblib.dump(model_bundle, MODEL_FILE)

    report = {
        "created_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "model": "RandomForestClassifier",
        "version": "1.0",
        "features": FEATURES,
        "train_scenarios": sorted(TRAIN_SCENARIOS),
        "test_scenarios": sorted(TEST_SCENARIOS),
        "training_samples": len(train_rows),
        "testing_samples": len(test_rows),
        "accuracy": float(accuracy),
        "precision_per_class": {
            label: float(score)
            for label, score in zip(LABELS, precision)
        },
        "recall_per_class": {
            label: float(score)
            for label, score in zip(LABELS, recall)
        },
        "f1_per_class": {
            label: float(score)
            for label, score in zip(LABELS, f1)
        },
        "confusion_matrix": matrix.tolist(),
        "feature_importance": {
            name: float(score)
            for name, score in importance
        },
        "limitations": [
            "Only four independent scenarios were collected.",
            "Only two traffic behavior classes are supported.",
            "Labels were selected using traffic-rate rules.",
            "High accuracy does not establish attack detection.",
            "Additional independent experiments are required.",
        ],
    }

    with REPORT_FILE.open(
        "w", encoding="utf-8"
    ) as file:
        json.dump(
            report,
            file,
            indent=4,
        )

    print("\nSaved files:")
    print(f"  Model: {MODEL_FILE}")
    print(f"  Report: {REPORT_FILE}")

    print(
        "\n[WARNING] Experimental baseline only. "
        "Do not interpret the scores as proof of "
        "real-world intrusion detection performance."
    )

    print("\n[DONE] Model training completed.")


if __name__ == "__main__":
    try:
        train_and_evaluate()
    except (
        FileNotFoundError,
        ValueError,
        KeyError,
        OSError,
    ) as error:
        print(f"[ERROR] {error}")
        raise SystemExit(1)
