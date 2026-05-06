# app.py — Honeypot Intrusion Monitoring System (Full Version)

from flask import Flask, render_template, jsonify
import json, os
from collections import defaultdict, Counter

from mitre_mapper  import map_command_to_mitre
from profiler      import classify_attacker
from geoip_lookup  import lookup_ip
from risk_scorer   import calculate_risk
from chain_detector import detect_chain
from threat_tagger import generate_tags

app = Flask(__name__)

LOG_PATH = os.path.expanduser("~/cowrie/var/log/cowrie/cowrie.json")

# ─────────────────────────────────────────────
# LOG PARSING
# ─────────────────────────────────────────────
def parse_logs():
    events = []
    if not os.path.exists(LOG_PATH):
        return events
    with open(LOG_PATH, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return events


def get_sessions():
    events = parse_logs()
    sessions = defaultdict(lambda: {
        "session": "", "src_ip": "", "commands": [],
        "login_attempts": 0, "login_success": False,
        "start_time": "", "usernames": [], "passwords": [],
        "timeline": []
    })

    for e in events:
        sid    = e.get("session", "unknown")
        eid    = e.get("eventid", "")
        src_ip = e.get("src_ip", "unknown")
        ts     = e.get("timestamp", "")

        sessions[sid]["session"] = sid
        sessions[sid]["src_ip"]  = src_ip
        if not sessions[sid]["start_time"]:
            sessions[sid]["start_time"] = ts

        if eid == "cowrie.login.failed":
            sessions[sid]["login_attempts"] += 1
            if e.get("username"): sessions[sid]["usernames"].append(e["username"])
            if e.get("password"): sessions[sid]["passwords"].append(e["password"])
            sessions[sid]["timeline"].append({
                "time":  ts[11:19] if ts else "",
                "event": f"Login failed — user: {e.get('username','?')} pass: {e.get('password','?')}"
            })

        elif eid == "cowrie.login.success":
            sessions[sid]["login_success"] = True
            sessions[sid]["login_attempts"] += 1
            sessions[sid]["timeline"].append({
                "time":  ts[11:19] if ts else "",
                "event": f"✅ Login SUCCESS — user: {e.get('username','?')}"
            })

        elif eid == "cowrie.command.input":
            cmd = e.get("input", "").strip()
            if cmd:
                sessions[sid]["commands"].append(cmd)
                sessions[sid]["timeline"].append({
                    "time":  ts[11:19] if ts else "",
                    "event": f"$ {cmd}"
                })

        elif eid == "cowrie.session.closed":
            sessions[sid]["timeline"].append({
                "time":  ts[11:19] if ts else "",
                "event": "Session closed"
            })

    return dict(sessions)


# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/sessions")
def api_sessions():
    sessions = get_sessions()
    result   = []

    for sid, s in sessions.items():
        # Core analysis
        profile = classify_attacker(s["commands"])
        risk    = calculate_risk(s)
        chain   = detect_chain(s["commands"])
        tags    = generate_tags(s["commands"])
        geo     = lookup_ip(s["src_ip"])

        # Deduplicated MITRE techniques
        mitre_seen, mitre = set(), []
        for cmd in s["commands"]:
            for t in map_command_to_mitre(cmd):
                if t["id"] not in mitre_seen:
                    mitre.append(t)
                    mitre_seen.add(t["id"])

        result.append({
            "session":        sid[:8],
            "src_ip":         s["src_ip"],
            "start_time":     s["start_time"][:19].replace("T", " ") if s["start_time"] else "N/A",
            "login_attempts": s["login_attempts"],
            "login_success":  s["login_success"],
            "commands":       s["commands"],
            "timeline":       s["timeline"],
            "profile":        profile,
            "risk":           risk,
            "chain":          chain,
            "tags":           tags,
            "mitre":          mitre,
            "geo": {
                "country":     geo.get("country", "Unknown"),
                "city":        geo.get("city", "Unknown"),
                "isp":         geo.get("isp", "Unknown"),
                "countryCode": geo.get("countryCode", "??"),
                "lat":         geo.get("lat", 0),
                "lon":         geo.get("lon", 0)
            }
        })

    result.sort(key=lambda x: x["start_time"], reverse=True)
    return jsonify(result)


@app.route("/api/stats")
def api_stats():
    sessions   = get_sessions()
    all_users  = []
    all_pass   = []
    risk_dist  = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    chain_dist = Counter()

    for s in sessions.values():
        all_users.extend(s["usernames"])
        all_pass.extend(s["passwords"])
        r = calculate_risk(s)
        risk_dist[r["level"]] = risk_dist.get(r["level"], 0) + 1
        c = detect_chain(s["commands"])
        chain_dist[c["name"]] += 1

    return jsonify({
        "total_sessions":    len(sessions),
        "successful_logins": sum(1 for s in sessions.values() if s["login_success"]),
        "total_commands":    sum(len(s["commands"]) for s in sessions.values()),
        "unique_ips":        len(set(s["src_ip"] for s in sessions.values())),
        "risk_distribution": risk_dist,
        "top_chains":        chain_dist.most_common(5),
        "top_usernames":     [{"name": u, "count": c} for u, c in Counter(all_users).most_common(5)],
        "top_passwords":     [{"name": p, "count": c} for p, c in Counter(all_pass).most_common(5)]
    })


@app.route("/api/geomap")
def api_geomap():
    sessions = get_sessions()
    points   = []
    for s in sessions.values():
        geo = lookup_ip(s["src_ip"])
        points.append({
            "ip":      s["src_ip"],
            "lat":     geo.get("lat", 0),
            "lon":     geo.get("lon", 0),
            "country": geo.get("country", "Unknown"),
            "city":    geo.get("city", "Unknown"),
            "isp":     geo.get("isp", "Unknown")
        })
    return jsonify(points)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)