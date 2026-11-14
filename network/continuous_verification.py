import csv
import time
from datetime import datetime, timezone
from pathlib import Path

from access_control import get_service_status
from verification_policy import classify_change
from authorization_state import (
    load_authorized_changes,
    validate_block_authorization,
)

CHECK_INTERVAL = 5
LOG_FILE = Path("logs/verification_log.csv")

EXPECTED_POLICY = {
    "camera": {
        "icmp": "Allowed",
        "http": "Allowed",
    },
    "sensor": {
        "icmp": "Allowed",
        "http": "Denied",
    },
}


def log_result(device, service, expected, actual, result):
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    new_file = not LOG_FILE.exists() or LOG_FILE.stat().st_size == 0

    with LOG_FILE.open("a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        if new_file:
            writer.writerow([
                "timestamp",
                "device",
                "service",
                "expected",
                "actual",
                "result",
            ])

        writer.writerow([
            datetime.now(timezone.utc).isoformat(),
            device,
            service,
            expected,
            actual,
            result,
        ])


def verify_once():
    authorized_changes = load_authorized_changes()

    for device, services in EXPECTED_POLICY.items():
        authorization = validate_block_authorization(
            authorized_changes, device
        )

        for service, expected in services.items():
            try:
                actual = get_service_status(device, service)

                verified_authorization = None

                if (
                    authorization is not None
                    and expected == "Allowed"
                    and actual == "Denied"
                ):
                    verified_authorization = {
                        **authorization,
                        "verified": True,
                    }

                result = classify_change(
                    expected, actual, verified_authorization
                )
            except Exception as error:
                actual = f"ERROR: {error}"
                result = "ERROR"

            log_result(device, service, expected, actual, result)
            print(
                f"[{result}] {device} | {service} | "
                f"expected={expected} | actual={actual}",
                flush=True,
            )


if __name__ == "__main__":
    print("[STARTED] Continuous Verification Engine", flush=True)

    try:
        while True:
            verify_once()
            time.sleep(CHECK_INTERVAL)
    except KeyboardInterrupt:
        print("\n[STOPPED] Continuous Verification Engine")
