# ZeroTrust-IoT

## Zero Trust Network Security Framework for IoT Devices

An educational cybersecurity graduation project demonstrating selected Zero Trust concepts in a simulated IoT network. It uses Mininet, Open vSwitch, OpenFlow 1.3, Python, and Flask to apply network access rules, monitor flow counters, and record dashboard access-control actions.

This is a lab prototype, not a production security gateway. It does not authenticate device identities.

## Features

- Simulated Mininet camera, sensor, and server hosts.
- OpenFlow 1.3 rules with default-drop handling.
- Dashboard block/unblock controls for IP traffic between a device and the server.
- Administrator login, session expiry, and CSRF checks.
- Flow-counter monitoring, Mininet host status, access audit, and CSV/PDF reports.

## Network policy

| Priority | Rule |
|---:|---|
| 300 | Block IP traffic in both directions between selected host and server |
| 200 | Allow ICMP between each simulated device and server |
| 100 | Handle ARP address resolution |
| 0 | Drop unmatched traffic |

ARP remains available while a host is blocked. Camera and sensor are virtual Mininet hosts, not physical boards. Their Online/Offline status confirms only the Mininet process and configured IP; it is not device attestation or health checking.

The ping demo verifies ICMP behavior only. The project does not implement cryptographic device identity, posture assessment, or continuous policy decisions.

## Requirements

- Kali Linux or another Debian-based Linux system that supports Mininet/Open vSwitch. Windows is not a supported Mininet runtime.
- Python 3, `venv`, Mininet, Open vSwitch, and sudo access.
- ReportLab is installed from `requirements.txt` for PDF export.

## Installation

```bash
git clone https://github.com/zyousri50-crypto/ZeroTrust-IoT.git
cd ZeroTrust-IoT
sudo apt update
sudo apt install -y mininet openvswitch-switch python3 python3-venv sudo
sudo systemctl enable --now openvswitch-switch
python3 -m venv --system-site-packages .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 setup_admin.py
```

Choose an admin password of at least 12 characters. Username: `admin`. Local credentials and the Flask secret key are created in `dashboard/instance/` and excluded from Git. Never commit them.

Review the privileged helper installer before running it: 

```bash
cat scripts/setup_helpers.sh
sudo bash scripts/setup_helpers.sh
```

This installs root-owned helper copies and narrowly scoped sudo rules for the current user. Run it only on a trusted lab machine. Do not run Flask as root.

## Run the project

Open three terminals in the repository directory.

**Terminal 1 — simulated network**

```bash
sudo python3 network/iot_lab.py
```

Keep the Mininet `mininet>` prompt open.

**Terminal 2 — flow-counter monitor**

```bash
sudo python3 network/monitor.py
```

**Terminal 3 — dashboard**

```bash
source .venv/bin/activate
python3 dashboard/app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000) and sign in with `admin` and the password you set. The dashboard binds to localhost; do not expose Flask's development server to the internet.

## Verify access control

At the Mininet prompt, check connectivity:

```text
camera ping -c 5 server
sensor ping -c 5 server
```

Block the camera in the dashboard and repeat `camera ping -c 5 server`; the ping should fail. Unblock it and repeat; it should succeed. The helper adds/removes IP rules in both directions. Inspect active rules with:

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
```

Test other protocols separately before making claims about them.

## Monitoring limits

- `network/monitor.py` reads OpenFlow counters every two seconds. It totals packets on non-drop rules as allowed and on drop rules as dropped; it does not inspect packets or detect attacks.
- Historical drop entries are written when the drop counter increases. They do not identify a source or prove malicious intent. Counters may reset when the network or rules restart.
- Device status is based on the Mininet host process and IP. Audit entries record dashboard block/unblock requests and results.

## Project structure

```text
ZeroTrust-IoT/
├── dashboard/ (app.py, auth.py, templates/)
├── network/ (access_control.py, device_monitor.py, iot_lab.py, monitor.py)
├── scripts/setup_helpers.sh
├── docs/screenshots/
├── logs/
├── requirements.txt
├── setup_admin.py
└── README.md
```

## Limitations and future work

Device identity verification, role-based access control, broader traffic analysis, automated tests, and deployment outside this local lab are not implemented. Treat these as future work. Stronger Zero Trust claims need device identity and posture checks, resource-specific authorization, and documented tests for relevant protocols and failure cases.

## Author

Cybersecurity Graduation Project

## Disclaimer

For educational use and authorized cybersecurity research in a controlled environment only.
