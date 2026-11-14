import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

STATE_FILE = Path("/var/lib/zerotrust/authorized_state.json")
VALID_DEVICES = {"camera", "sensor"}
VALID_ACTIONS = {"block", "unblock"}


def record_authorization(device, action, source="cli"):
    if device not in VALID_DEVICES:
        raise ValueError("Invalid device")

    if action not in VALID_ACTIONS:
        raise ValueError("Invalid action")

    if source != "cli":
        raise ValueError("Unverified authorization source")

    if os.geteuid() != 0:
        raise PermissionError("Root privileges required")

    with STATE_FILE.open("r", encoding="utf-8") as file:
        state = json.load(file)

    if (
        not isinstance(state, dict)
        or state.get("version") != 1
        or not isinstance(state.get("authorized_changes"), dict)
    ):
        raise ValueError("Invalid authorization state")

    changes = state["authorized_changes"]

    if action == "block":
        changes[device] = {
            "action": "block",
            "username": "access_control_cli",
            "result": "Success",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    else:
        changes.pop(device, None)

    fd, temp_path = tempfile.mkstemp(
        dir=STATE_FILE.parent,
        prefix=".authorized_state_",
    )

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            os.fchmod(file.fileno(), 0o600)
            json.dump(state, file, indent=2)
            file.flush()
            os.fsync(file.fileno())

        os.replace(temp_path, STATE_FILE)

    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
