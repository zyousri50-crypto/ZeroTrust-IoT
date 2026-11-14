#!/usr/bin/env bash
set -euo pipefail

if [[ "$EUID" -ne 0 ]]; then
    echo "ERROR: Run using sudo."
    exit 1
fi

if [[ -z "${SUDO_USER:-}" || "$SUDO_USER" == "root" ]]; then
    echo "ERROR: Run as a normal user with sudo."
    exit 1
fi

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_USER="$SUDO_USER"
SUDOERS_FILE="/etc/sudoers.d/zerotrust-access-v2"

for cmd in /usr/bin/python3 /usr/bin/ovs-ofctl /usr/bin/sudo /usr/sbin/visudo; do
    if [[ ! -x "$cmd" ]]; then
        echo "ERROR: Missing $cmd"
        exit 1
    fi
done

if ! command -v mnexec >/dev/null 2>&1; then
    echo "ERROR: Mininet is not installed."
    exit 1
fi

echo "[SETUP] Preparing protected authorization state..."

install -d -o root -g root -m 700 /var/lib/zerotrust

if [[ -L /var/lib/zerotrust/authorized_state.json ]]; then
    echo "ERROR: Authorization state must not be a symbolic link."
    exit 1
fi

if [[ -e /var/lib/zerotrust/authorized_state.json && ! -f /var/lib/zerotrust/authorized_state.json ]]; then
    echo "ERROR: Authorization state must be a regular file."
    exit 1
fi

if [[ ! -e /var/lib/zerotrust/authorized_state.json ]]; then
    printf '%s\n' '{"version":1,"authorized_changes":{}}' \
        > /var/lib/zerotrust/authorized_state.json
fi

chown root:root /var/lib/zerotrust/authorized_state.json
chmod 600 /var/lib/zerotrust/authorized_state.json

echo "[1/4] Installing protected helpers..."

install -o root -g root -m 755 \
    "$PROJECT_DIR/network/authorization_writer.py" \
    /usr/local/sbin/zerotrust-authorization-writer.py

install -o root -g root -m 755 \
    "$PROJECT_DIR/network/access_control_secure.py" \
    /usr/local/sbin/zerotrust-access-v2

install -o root -g root -m 755 \
    "$PROJECT_DIR/network/device_monitor.py" \
    /usr/local/sbin/zerotrust-device-monitor

echo "[2/4] Generating restricted sudo rules..."

TMP_FILE="$(mktemp /etc/sudoers.d/.zerotrust-XXXXXX)"
chmod 440 "$TMP_FILE"

trap 'rm -f "$TMP_FILE"' EXIT

{
    for device in camera sensor; do
        for action in status block unblock; do
            printf '%s ALL=(root) NOPASSWD: /usr/bin/python3 /usr/local/sbin/zerotrust-access-v2 %s %s\n' \
                "$TARGET_USER" "$action" "$device"
        done
    done

    printf '%s ALL=(root) NOPASSWD: /usr/bin/python3 /usr/local/sbin/zerotrust-device-monitor\n' \
        "$TARGET_USER"
} > "$TMP_FILE"

echo "[3/4] Validating sudo rules..."

if ! /usr/sbin/visudo -cf "$TMP_FILE"; then
    echo "ERROR: Invalid sudo rules. No changes applied to sudoers."
    exit 1
fi

echo "[4/4] Installing sudo rules..."

install -o root -g root -m 440 \
    "$TMP_FILE" "$SUDOERS_FILE"

echo
echo "SUCCESS: ZeroTrust-IoT helpers configured."
echo "Authorized user: $TARGET_USER"
