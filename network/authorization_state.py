import json
import os
import stat
from pathlib import Path

STATE_FILE = Path("/var/lib/zerotrust/authorized_state.json")


def load_authorized_changes():
    try:
        directory = STATE_FILE.parent
        directory_info = directory.lstat()

        if (
            not stat.S_ISDIR(directory_info.st_mode)
            or directory_info.st_uid != 0
            or stat.S_IMODE(directory_info.st_mode) != 0o700
        ):
            return {}

        flags = os.O_RDONLY | os.O_NOFOLLOW
        fd = os.open(STATE_FILE, flags)

        with os.fdopen(fd, "r", encoding="utf-8") as file:
            info = os.fstat(file.fileno())

            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                return {}

            data = json.load(file)

    except (OSError, ValueError):
        return {}

    if not isinstance(data, dict):
        return {}

    if data.get("version") != 1:
        return {}

    changes = data.get("authorized_changes")

    if not isinstance(changes, dict):
        return {}

    return changes


def validate_block_authorization(changes, device, now=None):
    from datetime import datetime, timezone

    if device not in {"camera", "sensor"}:
        return None

    if not isinstance(changes, dict):
        return None

    entry = changes.get(device)
    if not isinstance(entry, dict):
        return None

    if (
        entry.get("action") != "block"
        or entry.get("username") not in {"admin", "access_control_cli"}
        or entry.get("result") != "Success"
    ):
        return None

    try:
        timestamp = datetime.fromisoformat(entry["timestamp"])
        if timestamp.tzinfo is None:
            return None

        current_time = now or datetime.now(timezone.utc)

        if timestamp > current_time:
            return None

    except (KeyError, TypeError, ValueError):
        return None

    return {
        "action": "block",
        "username": entry["username"],
        "result": "Success",
        "timestamp": entry["timestamp"],
    }
