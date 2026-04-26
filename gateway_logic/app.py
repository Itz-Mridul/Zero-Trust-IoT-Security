"""
app.py — Zero-Trust Security Dashboard (Flask)

Serves the alerts dashboard on port 5000.
Run: python3 app.py
"""

import json
import os
from pathlib import Path

from flask import Flask, jsonify, render_template_string

# ---------------------------------------------------------------------------
# PATHS  (resolved relative to this file — works on any machine)
# ---------------------------------------------------------------------------
BASE_DIR    = Path(__file__).resolve().parent
ALERTS_FILE = BASE_DIR / "alerts.json"

app = Flask(__name__)

# ---------------------------------------------------------------------------
# DASHBOARD HTML
# ---------------------------------------------------------------------------
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zero-Trust Gateway Dashboard</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=JetBrains+Mono&display=swap');

        :root {
            --bg:      #0d1117;
            --surface: #161b22;
            --border:  #30363d;
            --text:    #e6edf3;
            --muted:   #8b949e;
            --green:   #2ea043;
            --red:     #f85149;
            --yellow:  #d29922;
            --blue:    #388bfd;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: 'Inter', sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            padding: 32px 24px;
        }

        header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 1px solid var(--border);
            padding-bottom: 20px;
            margin-bottom: 28px;
        }

        header h1 { font-size: 1.6rem; font-weight: 700; }
        header h1 span { color: var(--red); }

        .pill {
            background: rgba(46, 160, 67, .15);
            color: var(--green);
            border: 1px solid var(--green);
            border-radius: 999px;
            padding: 4px 14px;
            font-size: .78rem;
            font-weight: 600;
            letter-spacing: .04em;
        }

        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 14px;
            margin-bottom: 28px;
        }

        .stat-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 18px 20px;
        }

        .stat-card .label {
            font-size: .75rem;
            color: var(--muted);
            text-transform: uppercase;
            letter-spacing: .06em;
            margin-bottom: 8px;
        }

        .stat-card .value {
            font-size: 1.8rem;
            font-weight: 700;
        }

        .value.red    { color: var(--red);    }
        .value.green  { color: var(--green);  }
        .value.yellow { color: var(--yellow); }
        .value.blue   { color: var(--blue);   }

        h2 { font-size: 1rem; font-weight: 600; margin-bottom: 14px; color: var(--muted); }

        .alert-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-left: 4px solid var(--red);
            border-radius: 10px;
            padding: 14px 18px;
            margin-bottom: 12px;
            display: grid;
            grid-template-columns: 1fr auto;
            gap: 6px 12px;
        }

        .alert-card .reason {
            font-weight: 600;
            color: var(--red);
            font-size: .92rem;
        }

        .alert-card .target {
            font-family: 'JetBrains Mono', monospace;
            font-size: .78rem;
            color: var(--blue);
            word-break: break-all;
            grid-column: 1 / -1;
        }

        .alert-card .meta {
            font-size: .75rem;
            color: var(--muted);
        }

        .badge {
            background: rgba(248, 81, 73, .18);
            color: var(--red);
            border: 1px solid var(--red);
            border-radius: 6px;
            padding: 2px 8px;
            font-size: .72rem;
            font-weight: 600;
            align-self: start;
        }

        .empty {
            text-align: center;
            padding: 48px;
            color: var(--muted);
            font-size: 1.1rem;
        }
    </style>
</head>
<body>
    <header>
        <h1>🛡️ Zero-Trust <span>Security</span> Dashboard</h1>
        <span class="pill">● ACTIVE MONITORING</span>
    </header>

    <div class="stats">
        <div class="stat-card">
            <div class="label">Total Alerts</div>
            <div class="value red">{{ alerts | length }}</div>
        </div>
        <div class="stat-card">
            <div class="label">Unique Sources</div>
            <div class="value yellow">{{ alerts | map(attribute='source') | list | unique | list | length }}</div>
        </div>
        <div class="stat-card">
            <div class="label">Status</div>
            <div class="value green" style="font-size:1.1rem;">ONLINE</div>
        </div>
    </div>

    <h2>RECENT SECURITY EVENTS (newest first)</h2>

    {% if alerts %}
        {% for alert in alerts[::-1] %}
        <div class="alert-card">
            <div class="reason">{{ alert.get('action', 'BLOCKED') }}: {{ alert.get('reason', 'Threat detected') }}</div>
            <div class="badge">{{ alert.get('action', 'BLOCK') }}</div>
            <div class="target">{{ alert.get('target', '') }}</div>
            <div class="meta">🕒 {{ alert.get('timestamp', '') }}</div>
            <div class="meta">📡 Source IP: {{ alert.get('source', 'unknown') }}</div>
        </div>
        {% endfor %}
    {% else %}
        <div class="empty">✅ No security events yet — network is clean.</div>
    {% endif %}

    <script>
        // Auto-refresh every 10 seconds
        setTimeout(() => location.reload(), 10000);
    </script>
</body>
</html>
"""

# ---------------------------------------------------------------------------
# ROUTES
# ---------------------------------------------------------------------------
def _load_alerts() -> list:
    try:
        with ALERTS_FILE.open("r") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


@app.route("/")
def index():
    alerts = _load_alerts()
    return render_template_string(HTML_TEMPLATE, alerts=alerts)


@app.route("/api/alerts")
def api_alerts():
    """JSON endpoint — useful for external dashboards / scripts."""
    return jsonify(_load_alerts())


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print(f"[Dashboard] Alerts file : {ALERTS_FILE}")
    print("[Dashboard] Starting on http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
