
from flask import Flask, render_template, jsonify, Response, session
from pathlib import Path
from datetime import datetime, timezone
from io import StringIO, BytesIO
from xml.sax.saxutils import escape
import subprocess
import csv
import json
from auth import configure_security
app = Flask(__name__)
configure_security(app)
BASE_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "security_log.csv"
AUDIT_FILE = LOG_DIR / "access_audit.csv"
TRAFFIC_FILE = LOG_DIR / "traffic_stats.json"

DEVICE_MONITOR = "/usr/local/sbin/zerotrust-device-monitor"
ACCESS_CONTROL = Path("/usr/local/sbin/zerotrust-access-v2")

DEVICES = {
    "camera": {
        "name": "IoT Camera",
        "host": "camera",
        "ip": "10.0.0.11"
    },
    "sensor": {
        "name": "IoT Sensor",
        "host": "sensor",
        "ip": "10.0.0.12"
    },
    "server": {
        "name": "IoT Server",
        "host": "server",
        "ip": "10.0.0.100"
    }
}

CONTROLLABLE = {"camera", "sensor"}
ACTIONS = {"block", "unblock"}


def read_csv(path):
    if not path.exists():
        return []

    with path.open(
        "r", newline="", encoding="utf-8"
    ) as file:
        return list(csv.DictReader(file))


def get_logs():
    logs = read_csv(LOG_FILE)
    total = 0

    for item in logs:
        try:
            total += int(item.get("Packets", 0))
        except (ValueError, TypeError):
            pass

    return logs, total


def get_traffic():
    default = {
        "available": False,
        "monitor_status": "Offline",
        "allowed_packets": 0,
        "dropped_packets": 0,
        "new_dropped_packets": 0,
        "counters_reset": False,
        "timestamp": None
    }

    try:
        with TRAFFIC_FILE.open(
            "r", encoding="utf-8"
        ) as file:
            data = json.load(file)

        timestamp = datetime.fromisoformat(
            data["timestamp"]
        )

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(
                tzinfo=timezone.utc
            )

        age = (
            datetime.now(timezone.utc) -
            timestamp.astimezone(timezone.utc)
        ).total_seconds()

        if age < -10 or age > 10:
            return default

        return {
            "available": True,
            "monitor_status": "Online",
            "allowed_packets": int(
                data["allowed_packets"]
            ),
            "dropped_packets": int(
                data["dropped_packets"]
            ),
            "new_dropped_packets": int(
                data["new_dropped_packets"]
            ),
            "counters_reset": bool(
                data["counters_reset"]
            ),
            "timestamp": data["timestamp"]
        }

    except (
        OSError, ValueError, TypeError, KeyError
    ):
        return default


def run_command(args, timeout=10):
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout
    )


def get_devices():
    defaults = [
        {**device, "status": "Unknown"}
        for device in DEVICES.values()
    ]

    try:
        result = run_command([
            "/usr/bin/sudo", "-n",
            "/usr/bin/python3",
            DEVICE_MONITOR
        ], timeout=15)

        if result.returncode != 0:
            raise RuntimeError(
                result.stderr.strip()
            )

        data = json.loads(result.stdout)

        if not isinstance(data, list):
            raise ValueError("Invalid device response")

        statuses = {
            item.get("host"): item.get("status")
            for item in data
            if isinstance(item, dict)
            and item.get("host") in DEVICES
            and item.get("status") in (
                "Online", "Offline", "Unknown"
            )
        }

        return [
            {
                **device,
                "status": statuses.get(
                    device["host"], "Unknown"
                )
            }
            for device in DEVICES.values()
        ]

    except (
        OSError, RuntimeError, ValueError,
        subprocess.TimeoutExpired
    ) as error:
        app.logger.warning(
            "Device monitoring: %s", error
        )
        return defaults


def access_command(action, device):
    if action not in {
        "status", "block", "unblock"
    }:
        raise ValueError("Invalid action")

    if device not in CONTROLLABLE:
        raise ValueError("Invalid device")

    result = run_command([
        "/usr/bin/sudo", "-n",
        "/usr/bin/python3",
        str(ACCESS_CONTROL),
        action,
        device
    ])

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip()
            or "Access control failed"
        )

    status = result.stdout.strip()

    if status not in (
        "Allowed", "Blocked", "Unknown"
    ):
        raise RuntimeError(
            "Invalid access response"
        )

    return status


def write_audit(device, action, status, result):
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    columns = [
        "Time", "Device", "Action",
        "Status", "Result", "Username"
    ]

    if AUDIT_FILE.exists() and AUDIT_FILE.stat().st_size:
        with AUDIT_FILE.open(
            "r", newline="", encoding="utf-8"
        ) as file:
            reader = csv.DictReader(file)
            existing_columns = reader.fieldnames or []

        if existing_columns != columns:
            raise RuntimeError(
                "Audit log schema requires migration"
            )

    new_file = (
        not AUDIT_FILE.exists()
        or AUDIT_FILE.stat().st_size == 0
    )

    username = (
        "admin"
        if session.get("authenticated")
        else "unknown"
    )

    with AUDIT_FILE.open(
        "a", newline="", encoding="utf-8"
    ) as file:
        writer = csv.writer(file)

        if new_file:
            writer.writerow(columns)

        writer.writerow([
            datetime.now(timezone.utc).isoformat(),
            device,
            action,
            status,
            result,
            username
        ])


def parse_time(value):
    try:
        dt = datetime.fromisoformat(
            str(value).strip()
        )

        if dt.tzinfo is None:
            # Old security logs use Kali local time.
            dt = dt.astimezone()

        return dt.astimezone(timezone.utc)

    except (ValueError, TypeError):
        return None


def get_timeline():
    events = []

    for item in read_csv(LOG_FILE):
        raw_time = item.get("Time", "")
        dt = parse_time(raw_time)

        if dt is None:
            continue

        try:
            packets = int(
                item.get("Packets", 0)
            )
        except (ValueError, TypeError):
            packets = 0

        events.append({
            "time": raw_time,
            "timestamp": dt.isoformat(),
            "type": "Dropped Traffic",
            "device": "Network",
            "action": "drop",
            "status": "Blocked",
            "result": "Detected",
            "packets": packets
        })

    for item in read_csv(AUDIT_FILE):
        raw_time = item.get("Time", "")
        dt = parse_time(raw_time)

        if dt is None:
            continue

        events.append({
            "time": raw_time,
            "timestamp": dt.isoformat(),
            "type": "Access Control",
            "device": item.get(
                "Device", "Unknown"
            ),
            "action": item.get(
                "Action", "Unknown"
            ),
            "status": item.get(
                "Status", "Unknown"
            ),
            "result": item.get(
                "Result", "Unknown"
            ),
            "packets": 0
        })

    events.sort(
        key=lambda item: item["timestamp"],
        reverse=True
    )

    return events


def get_summary():
    security_logs, total_dropped = get_logs()
    audit_logs = read_csv(AUDIT_FILE)

    blocks = sum(
        1 for item in audit_logs
        if item.get("Action", "").lower()
        == "block"
    )

    unblocks = sum(
        1 for item in audit_logs
        if item.get("Action", "").lower()
        == "unblock"
    )

    successes = sum(
        1 for item in audit_logs
        if item.get("Result", "").lower()
        == "success"
    )

    failures = sum(
        1 for item in audit_logs
        if item.get("Result", "").lower()
        == "failed"
    )

    return {
        "security_events": len(security_logs),
        "historical_dropped_packets": total_dropped,
        "block_actions": blocks,
        "unblock_actions": unblocks,
        "successful_actions": successes,
        "failed_actions": failures,
        "total_access_actions": len(audit_logs),
        "total_timeline_events": (
            len(security_logs) + len(audit_logs)
        )
    }


@app.route("/")
def home():
    logs, total = get_logs()

    return render_template(
        "index.html",
        logs=logs,
        total_packets=total,
        total_events=len(logs)
    )


@app.route("/api/stats")
def stats():
    logs, total = get_logs()

    return jsonify({
        "total_packets": total,
        "total_events": len(logs),
        "logs": logs
    })


@app.route("/api/traffic")
def traffic():
    return jsonify(get_traffic())


@app.route("/api/devices")
def devices():
    data = get_devices()

    return jsonify({
        "devices": data,
        "total_devices": len(data)
    })


@app.route("/api/audit")
def audit():
    return jsonify({
        "logs": read_csv(
            AUDIT_FILE
        )[-100:][::-1]
    })


@app.route("/api/timeline")
def timeline():
    events = get_timeline()

    return jsonify({
        "total": len(events),
        "events": events[:100]
    })


@app.route("/api/summary")
def summary():
    return jsonify(get_summary())


@app.route("/api/export/csv")
def export_csv():
    output = StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Time",
        "Type",
        "Device",
        "Action",
        "Status",
        "Result",
        "Packets"
    ])

    for item in get_timeline():
        writer.writerow([
            item["time"],
            item["type"],
            item["device"],
            item["action"],
            item["status"],
            item["result"],
            item["packets"]
        ])

    filename = (
        "zerotrust_security_"
        + datetime.now().strftime("%Y%m%d_%H%M%S")
        + ".csv"
    )

    return Response(
        "\ufeff" + output.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={
            "Content-Disposition":
                f'attachment; filename="{filename}"'
        }
    )


@app.route("/api/export/pdf")
def export_pdf():
    try:
        from reportlab.platypus import (
            SimpleDocTemplate,
            Paragraph,
            Spacer,
            Table,
            TableStyle
        )
        from reportlab.lib import colors
        from reportlab.lib.styles import (
            getSampleStyleSheet
        )
        from reportlab.lib.pagesizes import A4
    except ImportError:
        return jsonify({
            "error": "Install python3-reportlab"
        }), 503

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=35,
        leftMargin=35,
        topMargin=35,
        bottomMargin=35
    )

    styles = getSampleStyleSheet()
    story = []

    def paragraph(value):
        return Paragraph(
            escape(str(value)),
            styles["BodyText"]
        )

    story.append(Paragraph(
        "ZeroTrust IoT Security Report",
        styles["Title"]
    ))

    story.append(Spacer(1, 12))

    story.append(paragraph(
        "Generated: "
        + datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    ))

    story.append(Spacer(1, 15))
    story.append(Paragraph(
        "Security Summary",
        styles["Heading2"]
    ))

    summary_data = get_summary()

    summary_rows = [
        ["Metric", "Value"]
    ]

    for key, value in summary_data.items():
        summary_rows.append([
            key.replace("_", " ").title(),
            str(value)
        ])

    summary_table = Table(
        summary_rows,
        colWidths=[300, 170],
        repeatRows=1
    )

    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0),
         colors.HexColor("#17365D")),
        ("TEXTCOLOR", (0, 0), (-1, 0),
         colors.white),
        ("GRID", (0, 0), (-1, -1),
         0.4, colors.grey),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 7)
    ]))

    story.append(summary_table)
    story.append(Spacer(1, 18))

    story.append(Paragraph(
        "Live Traffic Snapshot",
        styles["Heading2"]
    ))

    traffic_data = get_traffic()

    for key in [
        "monitor_status",
        "allowed_packets",
        "dropped_packets",
        "timestamp"
    ]:
        story.append(paragraph(
            key.replace("_", " ").title()
            + ": "
            + str(traffic_data.get(key))
        ))

    story.append(Spacer(1, 18))
    story.append(Paragraph(
        "IoT Devices",
        styles["Heading2"]
    ))

    for device in get_devices():
        story.append(paragraph(
            device["name"]
            + " | "
            + device["ip"]
            + " | "
            + device["status"]
        ))

    story.append(Spacer(1, 18))
    story.append(Paragraph(
        "Recent Security Events",
        styles["Heading2"]
    ))

    event_rows = [[
        "Time", "Type", "Device", "Result"
    ]]

    for item in get_timeline()[:30]:
        event_rows.append([
            paragraph(item["time"]),
            paragraph(item["type"]),
            paragraph(item["device"]),
            paragraph(item["result"])
        ])

    if len(event_rows) == 1:
        event_rows.append([
            "-", "No events", "-", "-"
        ])

    event_table = Table(
        event_rows,
        colWidths=[155, 125, 95, 95],
        repeatRows=1,
        hAlign="LEFT"
    )

    event_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0),
         colors.HexColor("#17365D")),
        ("TEXTCOLOR", (0, 0), (-1, 0),
         colors.white),
        ("GRID", (0, 0), (-1, -1),
         0.3, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6)
    ]))

    story.append(event_table)
    story.append(Spacer(1, 12))

    story.append(paragraph(
        "Note: Historical totals are based on "
        "CSV logs. Live OpenFlow counters may "
        "reset when network rules change. "
        "Online status does not mean access "
        "to the server is allowed."
    ))

    doc.build(story)
    buffer.seek(0)

    filename = (
        "zerotrust_report_"
        + datetime.now().strftime("%Y%m%d_%H%M%S")
        + ".pdf"
    )

    return Response(
        buffer.getvalue(),
        mimetype="application/pdf",
        headers={
            "Content-Disposition":
                f'attachment; filename="{filename}"'
        }
    )


@app.route("/api/access/status")
def camera_status():
    return access_status("camera")


@app.route(
    "/api/access/block",
    methods=["POST"]
)
def camera_block():
    return change_access("camera", "block")


@app.route(
    "/api/access/unblock",
    methods=["POST"]
)
def camera_unblock():
    return change_access("camera", "unblock")


@app.route("/api/access/status/<device>")
def access_status(device):
    if device not in CONTROLLABLE:
        return jsonify({
            "success": False,
            "error": "Invalid device"
        }), 400

    try:
        status = access_command(
            "status", device
        )

        return jsonify({
            "success": True,
            "device": device,
            "status": status
        })

    except (
        RuntimeError,
        OSError,
        subprocess.TimeoutExpired
    ) as error:
        app.logger.warning(
            "Access status: %s", error
        )

        return jsonify({
            "success": False,
            "status": "Unknown",
            "error": "Unable to read access status"
        }), 503


@app.route(
    "/api/access/<device>/<action>",
    methods=["POST"]
)
def device_action(device, action):
    return change_access(device, action)


def change_access(device, action):
    if (
        device not in CONTROLLABLE
        or action not in ACTIONS
    ):
        return jsonify({
            "success": False,
            "error": "Invalid device or action"
        }), 400

    try:
        status = access_command(
            action, device
        )

        expected = (
            "Blocked"
            if action == "block"
            else "Allowed"
        )

        success = status == expected

        write_audit(
            device,
            action,
            status,
            "Success" if success else "Failed"
        )

        return jsonify({
            "success": success,
            "device": device,
            "status": status,
            "message": (
                "Access updated"
                if success
                else "Unexpected status"
            )
        }), 200 if success else 409

    except (
        RuntimeError,
        OSError,
        subprocess.TimeoutExpired
    ) as error:
        app.logger.error(
            "Access control: %s", error
        )

        try:
            write_audit(
                device,
                action,
                "Unknown",
                "Failed"
            )
        except OSError:
            app.logger.exception(
                "Audit logging failed"
            )

        return jsonify({
            "success": False,
            "error": "Access control failed"
        }), 503



@app.route("/api/ml/alerts", methods=["GET"])
def ml_alerts():
    ml_file = LOG_DIR / "ml_detection_log.csv"

    try:
        records = read_csv(ml_file)
    except (OSError, csv.Error, UnicodeError):
        app.logger.exception("Unable to read ML detection log")
        return jsonify({
            "success": False,
            "error": "Unable to read ML detection log"
        }), 500

    recent = records[-100:][::-1]
    alerts = []

    for record in recent:
        prediction = record.get("prediction", "")

        if prediction not in ("normal", "unauthorized_access"):
            continue

        try:
            confidence = float(record.get("confidence", ""))
            if not 0 <= confidence <= 1:
                continue
        except (ValueError, TypeError):
            continue

        alerts.append({
            "timestamp": record.get("timestamp", ""),
            "source_timestamp": record.get("source_timestamp", ""),
            "prediction": prediction,
            "confidence": confidence,
            "status": (
                "alert_candidate"
                if prediction == "unauthorized_access"
                else "normal"
            ),
            "allowed_packet_rate": record.get("allowed_packet_rate", ""),
            "dropped_packet_rate": record.get("dropped_packet_rate", ""),
            "drop_ratio": record.get("drop_ratio", "")
        })

    return jsonify({
        "success": True,
        "experimental": True,
        "warning": (
            "ML predictions are experimental and "
            "do not confirm security incidents."
        ),
        "total": len(alerts),
        "normal_count": sum(
            item["prediction"] == "normal" for item in alerts
        ),
        "alert_candidate_count": sum(
            item["prediction"] == "unauthorized_access"
            for item in alerts
        ),
        "alerts": alerts
    })



@app.route("/api/port-scan/alerts", methods=["GET"])
def api_port_scan_alerts():
    log_file = LOG_DIR / "port_scan_alerts.csv"

    if not log_file.exists():
        return jsonify({
            "success": True,
            "total": 0,
            "alerts": []
        })

    try:
        records = read_csv(log_file)
        alerts = []

        for record in reversed(records[-100:]):
            try:
                alerts.append({
                    "timestamp": record["timestamp"],
                    "attack_type": record["attack_type"],
                    "source_ip": record["source_ip"],
                    "destination_ip": record["destination_ip"],
                    "unique_ports": int(record["unique_ports"]),
                    "ports": record["ports"]
                })
            except (KeyError, ValueError, TypeError):
                continue

        return jsonify({
            "success": True,
            "total": len(alerts),
            "alerts": alerts
        })

    except (OSError, csv.Error) as error:
        return jsonify({
            "success": False,
            "error": "Unable to read port scan alerts"
        }), 500


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )

