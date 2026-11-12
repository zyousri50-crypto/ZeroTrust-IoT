import subprocess
import sys

SWITCH = "s1"
SERVER_IP = "10.0.0.100"
DEVICES = {
    "camera": "10.0.0.11",
    "sensor": "10.0.0.12",
}

def ovs_command(*args):
    result = subprocess.run(
        ["/usr/bin/ovs-ofctl", "-O", "OpenFlow13", *args],
        capture_output=True, text=True, timeout=5
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "OpenFlow command failed")
    return result.stdout

def get_device_ip(device):
    if device not in DEVICES:
        raise ValueError("Unknown device")
    return DEVICES[device]

def block_pairs(ip):
    return ((ip, SERVER_IP), (SERVER_IP, ip))

def get_status(device="camera"):
    ip = get_device_ip(device)
    flows = ovs_command("dump-flows", SWITCH)
    for src, dst in block_pairs(ip):
        for line in flows.splitlines():
            if (
                "priority=300" in line
                and "actions=drop" in line
                and "nw_src=" + src in line
                and "nw_dst=" + dst in line
            ):
                return "Blocked"

    for line in flows.splitlines():
        if (
            "priority=200" in line
            and "actions=NORMAL" in line
            and "nw_src=" + ip in line
            and "nw_dst=" + SERVER_IP in line
        ):
            return "Allowed"
    return "Unknown"

def block_device(device="camera"):
    ip = get_device_ip(device)
    for src, dst in block_pairs(ip):
        rule = (
            "priority=300,ip,"
            + "nw_src=" + src + ","
            + "nw_dst=" + dst + ",actions=drop"
        )
        ovs_command("add-flow", SWITCH, rule)
    return get_status(device)

def unblock_device(device="camera"):
    ip = get_device_ip(device)
    for src, dst in block_pairs(ip):
        rule = (
            "priority=300,ip,"
            + "nw_src=" + src + ","
            + "nw_dst=" + dst
        )
        ovs_command("--strict", "del-flows", SWITCH, rule)
    return get_status(device)

def block_camera():
    return block_device("camera")

def unblock_camera():
    return unblock_device("camera")

if __name__ == "__main__":
    try:
        args = sys.argv[1:]
        if len(args) == 1:
            action, device = args[0], "camera"
        elif len(args) == 2:
            action, device = args
        else:
            print(
                "Usage: access_control.py "
                "[status|block|unblock] [camera|sensor]",
                file=sys.stderr
            )
            sys.exit(1)

        if action == "status":
            print(get_status(device))
        elif action == "block":
            print(block_device(device))
        elif action == "unblock":
            print(unblock_device(device))
        else:
            raise ValueError("Invalid action")
    except (
        RuntimeError, ValueError, subprocess.TimeoutExpired, OSError
    ) as error:
        print("Error:", error, file=sys.stderr)
        sys.exit(1)
