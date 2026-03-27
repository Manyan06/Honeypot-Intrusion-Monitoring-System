from flask import Flask, render_template_string
import json

app = Flask(__name__)

LOG_FILE = "/home/kali/cowrie/var/log/cowrie/cowrie.json"

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Honeypot Dashboard</title>
    <meta http-equiv="refresh" content="3">
    <style>
        body { background: #0f172a; color: #e2e8f0; font-family: Arial; }
        h1 { text-align: center; }
        .card { background: #1e293b; margin: 10px; padding: 10px; border-radius: 8px; }
        .ip { color: #38bdf8; }
        .cmd { color: #facc15; }
        .alert { color: #ef4444; }
    </style>
</head>
<body>

<h1>🚨 Honeypot Intrusion Dashboard</h1>

{% for log in logs %}
<div class="card">
    <b>IP:</b> <span class="ip">{{ log.get('src_ip', '-') }}</span><br>
    <b>Event:</b> {{ log.get('eventid', '-') }}<br>
    <b>Command:</b> <span class="cmd">{{ log.get('input', '-') }}</span>
</div>
{% endfor %}

</body>
</html>
"""

@app.route("/")
def index():
    logs = []
    try:
        with open(LOG_FILE) as f:
            for line in f.readlines()[-25:]:
                logs.append(json.loads(line))
    except Exception as e:
        print(e)
    return render_template_string(HTML, logs=logs)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)