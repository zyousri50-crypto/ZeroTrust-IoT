
import subprocess
import json

devices = [
    {"name": "IoT Camera", "host": "camera", "ip": "10.0.0.11"},
    {"name": "IoT Sensor", "host": "sensor", "ip": "10.0.0.12"},
    {"name": "IoT Server", "host": "server", "ip": "10.0.0.100"}
]


def check_device(device):
    try:
        # Find the Mininet host process
        result = subprocess.run(
            ["pgrep", "-f", "^bash .*mininet:" + device["host"] + "$"],
            capture_output=True,
            text=True,
            timeout=3
        )

        pids = result.stdout.strip().splitlines()

        if result.returncode != 0 or not pids:
            return "Offline"

        # Check the IP inside the host namespace
        for pid in pids:
            check = subprocess.run(
                ["mnexec", "-a", pid, "ip", "-4", "addr", "show"],
                capture_output=True,
                text=True,
                timeout=3
            )

            if (
                check.returncode == 0
                and device["ip"] + "/24" in check.stdout
            ):
                return "Online"

        return "Offline"

    except (subprocess.TimeoutExpired, OSError):
        return "Unknown"


def get_devices():
    result = []

    for device in devices:
        result.append({
            "name": device["name"],
            "host": device["host"],
            "ip": device["ip"],
            "status": check_device(device)
        })

    return result


if __name__ == "__main__":
    print(json.dumps(get_devices(), indent=4))

