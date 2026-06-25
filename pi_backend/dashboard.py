#!/usr/bin/env python3
"""
Zero-Trust IoT Security Dashboard
===================================
"Single Pane of Glass" — Flask web app that displays:
  • Live trust score gauges for every ESP32 node
  • Real-time attack event feed
  • Blockchain / forensic evidence log
  • Thermal alerts panel
  • Live MJPEG stream placeholder

Run:
    python3 pi_backend/dashboard.py

Then open http://localhost:5001 in your browser.
"""

import json
import os
import sqlite3
import sys
import time
from pathlib import Path

# Add project root to path so we can import from pi_backend directly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from flask import Flask, Response, jsonify, render_template_string, stream_with_context
except ImportError:
    raise SystemExit("Flask is required: pip install flask")

from pi_backend.forensic_logger import get_recent_access_log
from pi_backend.photo_store import load_device_photo
from pi_backend.photo_store import store_device_photo as persist_device_photo
from pi_backend.thermal_monitor import get_thermal_alerts

# Photo storage: latest JPEG per device (populated by MQTT photo handler)
_latest_photos: dict = {}   # {device_id: bytes}

def store_device_photo(device_id: str, jpeg_bytes: bytes) -> None:
    """Called by the MQTT handler when a photo payload arrives."""
    _latest_photos[device_id] = jpeg_bytes
    persist_device_photo(device_id, jpeg_bytes)

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("IOT_DB_PATH", os.path.join(_BASE_DIR, "security.db"))

app = Flask(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# HTML Template — Dark Mode Single-Page Dashboard
# ─────────────────────────────────────────────────────────────────────────────

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Zero-Trust Command Center</title>
  <meta name="description" content="Real-time Zero-Trust IoT Security monitoring dashboard with AI hardware fingerprinting and blockchain forensic evidence logging." />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&family=JetBrains+Mono:wght@400;600;700&display=swap" rel="stylesheet" />
  <style>
    :root {
      --bg:        #0d0f14;
      --surface:   #161b27;
      --border:    #1f2937;
      --text:      #e2e8f0;
      --muted:     #64748b;
      --green:     #10b981;
      --yellow:    #f59e0b;
      --red:       #ef4444;
      --blue:      #3b82f6;
      --cyan:      #06b6d4;
      --purple:    #8b5cf6;
      --radius:    12px;
      --shadow:    0 8px 32px rgba(0,0,0,.5);
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      background: var(--bg);
      color: var(--text);
      font-family: 'Inter', sans-serif;
      min-height: 100vh;
      overflow-x: hidden;
    }

    /* ── HEADER ── */
    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 1.25rem 2.5rem;
      background: rgba(22, 27, 39, 0.8);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border);
      position: sticky;
      top: 0;
      z-index: 100;
    }
    header h1 {
      font-size: 1.25rem;
      font-weight: 700;
      letter-spacing: -0.5px;
      background: linear-gradient(90deg, var(--cyan), var(--blue));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .status-pill {
      display: flex;
      align-items: center;
      gap: .75rem;
      font-size: .85rem;
      font-weight: 600;
      color: var(--text);
      background: rgba(255,255,255,0.05);
      padding: 0.5rem 1rem;
      border-radius: 99px;
      border: 1px solid var(--border);
    }
    .dot {
      width: 8px; height: 8px;
      border-radius: 50%;
      background: var(--green);
      box-shadow: 0 0 10px var(--green);
      animation: pulse 2s infinite;
    }
    @keyframes pulse {
      0%,100% { opacity: 1; box-shadow: 0 0 10px var(--green); } 
      50% { opacity: .4; box-shadow: 0 0 2px var(--green); }
    }

    /* ── LAYOUT ── */
    main {
      display: grid;
      grid-template-columns: repeat(12, 1fr);
      gap: 1.5rem;
      padding: 2rem 2.5rem;
      max-width: 1600px;
      margin: 0 auto;
    }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 1.5rem;
      box-shadow: var(--shadow);
      display: flex;
      flex-direction: column;
      position: relative;
      overflow: hidden;
    }
    /* Grid span helpers */
    .col-4  { grid-column: span 4; }
    .col-6  { grid-column: span 6; }
    .col-8  { grid-column: span 8; }
    .col-12 { grid-column: span 12; }

    .card h2 {
      font-size: .75rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 1.5px;
      color: var(--muted);
      margin-bottom: 1.25rem;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    /* ── ATTACK COUNTER ── */
    .counter-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1rem;
      height: 100%;
    }
    .counter-item {
      background: rgba(255,255,255,.02);
      border: 1px solid rgba(255,255,255,.05);
      border-radius: 8px;
      padding: 1.5rem 1rem;
      text-align: center;
      display: flex;
      flex-direction: column;
      justify-content: center;
    }
    .counter-num {
      font-size: 2.8rem;
      font-weight: 700;
      font-family: 'JetBrains Mono', monospace;
      line-height: 1;
      text-shadow: 0 0 20px currentColor;
    }
    .counter-label { font-size: .75rem; color: var(--muted); margin-top: .5rem; font-weight: 600; }

    /* ── CAMERA PANEL ── */
    .camera-container {
      width: 100%;
      aspect-ratio: 4/3;
      background: #000;
      border-radius: 8px;
      overflow: hidden;
      position: relative;
      border: 1px solid var(--border);
    }
    .camera-container img {
      width: 100%;
      height: 100%;
      object-fit: cover;
      filter: contrast(1.1);
    }
    .camera-overlay {
      position: absolute;
      bottom: 0; left: 0; right: 0;
      padding: 0.75rem;
      background: linear-gradient(transparent, rgba(0,0,0,0.9));
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.7rem;
      color: var(--cyan);
      display: flex;
      justify-content: space-between;
    }
    .rec-indicator {
      position: absolute;
      top: 10px; right: 10px;
      color: var(--red);
      font-weight: bold;
      font-size: 0.8rem;
      display: flex;
      align-items: center;
      gap: 5px;
      text-shadow: 0 0 5px black;
    }

    /* ── PHYSICAL SECURITY (Arduino) ── */
    .sensor-grid {
      display: grid;
      grid-template-columns: 1fr;
      gap: 1rem;
    }
    .sensor-card {
      background: rgba(255,255,255,.02);
      border-left: 4px solid var(--border);
      padding: 1rem;
      border-radius: 0 8px 8px 0;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .sensor-card.safe { border-left-color: var(--green); }
    .sensor-card.alert { border-left-color: var(--red); background: rgba(239,68,68,0.1); }
    .sensor-value { font-family: 'JetBrains Mono', monospace; font-size: 1.5rem; font-weight: 700; }
    .sensor-label { font-size: 0.7rem; color: var(--muted); text-transform: uppercase; }

    /* ── TRUST GAUGES ── */
    .device-list { display: flex; flex-direction: column; gap: 1rem; }
    .device-row { 
      display: flex; flex-direction: column; gap: .5rem; 
      padding: 1rem;
      background: rgba(255,255,255,0.02);
      border-radius: 8px;
    }
    .device-meta {
      display: flex;
      justify-content: space-between;
      font-size: .85rem;
    }
    .device-id { font-family: 'JetBrains Mono', monospace; font-weight: 700; }
    .trust-bar {
      height: 12px;
      border-radius: 99px;
      background: rgba(0,0,0,0.5);
      border: 1px solid rgba(255,255,255,0.1);
      overflow: hidden;
      box-shadow: inset 0 2px 4px rgba(0,0,0,0.5);
    }
    .trust-fill {
      height: 100%;
      border-radius: 99px;
      transition: width .8s cubic-bezier(0.4, 0, 0.2, 1), background .8s ease;
      box-shadow: inset 0 2px 4px rgba(255,255,255,0.3);
    }

    /* ── EVENT FEED ── */
    .feed { height: 350px; overflow-y: auto; display: flex; flex-direction: column; gap: .5rem; padding-right: 5px; }
    .feed::-webkit-scrollbar { width: 6px; }
    .feed::-webkit-scrollbar-track { background: transparent; }
    .feed::-webkit-scrollbar-thumb { background: var(--border); border-radius: 99px; }
    .event-row {
      display: flex;
      align-items: flex-start;
      gap: 1rem;
      padding: .85rem 1rem;
      border-radius: 8px;
      background: rgba(255,255,255,.02);
      border-left: 3px solid transparent;
      font-size: .8rem;
      animation: fadeIn .4s ease;
    }
    @keyframes fadeIn { from { opacity: 0; transform: translateX(-10px); } to { opacity: 1; } }
    .event-badge {
      font-size: .7rem;
      font-weight: 700;
      padding: .3rem .6rem;
      border-radius: 4px;
      white-space: nowrap;
      width: 120px;
      text-align: center;
    }
    .badge-auth   { background: rgba(16,185,129,.15); color: var(--green); }
    .badge-reject { background: rgba(239,68,68,.15);  color: var(--red); }
    .badge-warn   { background: rgba(245,158,11,.15); color: var(--yellow); }
    .badge-therm  { background: rgba(239,68,68,.25);  color: #ff6060; }
    .badge-tamper { background: var(--red); color: #fff; box-shadow: 0 0 10px var(--red); animation: pulse 1s infinite; }
    
    .event-device { font-family: 'JetBrains Mono', monospace; color: var(--cyan); font-weight: 600;}
    .event-reason { color: var(--muted); font-size: .75rem; margin-top: .3rem; }
    .event-time   { font-size: .7rem; color: var(--muted); margin-left: auto; white-space: nowrap; }

    /* ── EVIDENCE TABLE ── */
    .table-container { height: 350px; overflow-y: auto; overflow-x: auto;}
    .table-container::-webkit-scrollbar { width: 6px; height: 6px;}
    .table-container::-webkit-scrollbar-track { background: transparent; }
    .table-container::-webkit-scrollbar-thumb { background: var(--border); border-radius: 99px; }
    
    .evidence-table { width: 100%; border-collapse: separate; border-spacing: 0; font-size: .8rem; }
    .evidence-table th {
      text-align: left; padding: .85rem 1rem;
      color: var(--muted); font-size: .7rem; text-transform: uppercase;
      border-bottom: 2px solid var(--border);
      position: sticky; top: 0; background: var(--surface); z-index: 10;
    }
    .evidence-table td { padding: .85rem 1rem; border-bottom: 1px solid rgba(255,255,255,.04); }
    .evidence-table tr:hover td { background: rgba(255,255,255,.03); }
    .hash { font-family: 'JetBrains Mono', monospace; font-size: .7rem; color: var(--purple); background: rgba(139,92,246,0.1); padding: 2px 6px; border-radius: 4px;}

    footer {
      text-align: center;
      color: var(--muted);
      font-size: .75rem;
      padding: 2rem;
      grid-column: span 12;
      border-top: 1px solid var(--border);
      margin-top: 2rem;
    }

    /* ── INTRUDER ALERT GALLERY ── */
    .intruder-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
      gap: 1rem;
      max-height: 340px;
      overflow-y: auto;
    }
    .intruder-card {
      background: rgba(239,68,68,0.08);
      border: 1px solid rgba(239,68,68,0.3);
      border-radius: 8px;
      overflow: hidden;
      display: flex;
      flex-direction: column;
      animation: fadeIn .4s ease;
    }
    .intruder-card img {
      width: 100%;
      aspect-ratio: 4/3;
      object-fit: cover;
      background: #111;
    }
    .intruder-meta {
      padding: .5rem;
      font-size: .65rem;
      color: var(--muted);
      font-family: 'JetBrains Mono', monospace;
      line-height: 1.4;
    }
    .intruder-meta .uid { color: var(--red); font-weight: 700; }
    .no-intruders {
      color: var(--green);
      font-size: .85rem;
      padding: 2rem;
      text-align: center;
      opacity: .7;
    }
  </style>
</head>
<body>
  <header>
    <h1>
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
      ZERO-TRUST SECURITY GATEWAY
    </h1>
    <div class="status-pill" id="threat-pill">
      <div class="dot" id="threat-dot"></div>
      <span id="threat-status">SYSTEM SECURE</span>
      <span style="color:var(--muted)">|</span>
      <span id="clock" style="font-family:'JetBrains Mono',monospace">—</span>
    </div>
  </header>

  <main>
    <!-- TOP ROW: Counters & Camera -->
    <div class="card col-8">
      <h2>🛡️ AI Threat Radar (CNN-LSTM)</h2>
      <div class="counter-grid">
        <div class="counter-item">
          <div class="counter-num" id="cnt-total" style="color:var(--cyan)">—</div>
          <div class="counter-label">TOTAL ACCESS ATTEMPTS</div>
        </div>
        <div class="counter-item">
          <div class="counter-num" id="cnt-rejected" style="color:var(--red)">—</div>
          <div class="counter-label">ATTACKS BLOCKED TODAY</div>
        </div>
        <div class="counter-item">
          <div class="counter-num" id="cnt-auth" style="color:var(--green)">—</div>
          <div class="counter-label">AUTHENTICATED</div>
        </div>
        <div class="counter-item">
          <div class="counter-num" id="cnt-score" style="color:var(--yellow)">—</div>
          <div class="counter-label">CURRENT THREAT LEVEL</div>
        </div>
      </div>
    </div>

    <div class="card col-4">
      <h2>📷 Perimeter Edge Node (ESP32-CAM)</h2>
      <div class="camera-container">
        <!-- Defaults to a specific device ID you flash, e.g. ESP32_CAM_PERIMETER -->
        <img id="live-cam" src="/api/photo/ESP32_CAM_PERIMETER" onerror="this.src='data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII='" alt="Live Camera Feed">
        <div class="rec-indicator"><div class="dot" style="background:var(--red);box-shadow:none;width:6px;height:6px"></div> LIVE</div>
        <div class="camera-overlay">
          <span>RGB CHALLENGE: ARMED</span>
          <span id="cam-time">00:00:00</span>
        </div>
      </div>
    </div>

    <!-- MIDDLE ROW: Arduino Sensors & Node Trust -->
    <div class="card col-4">
      <h2>🔥 Physical Watchdog (Arduino Uno)</h2>
      <div class="sensor-grid">
        <div class="sensor-card safe" id="card-vib">
          <div>
            <div class="sensor-label">Case Vibration (SW-420)</div>
            <div style="font-size:0.8rem;color:var(--muted);margin-top:4px" id="vib-status">Monitoring...</div>
          </div>
          <div class="sensor-value" id="val-vib" style="color:var(--green)">SAFE</div>
        </div>
        <div class="sensor-card safe" id="card-temp">
          <div>
            <div class="sensor-label">Room Ambient (DHT22)</div>
            <div style="font-size:0.8rem;color:var(--muted);margin-top:4px">Humidity: <span id="val-hum">—</span>%</div>
          </div>
          <div class="sensor-value" id="val-temp" style="color:var(--cyan)">—°C</div>
        </div>
        <div class="sensor-card safe" id="card-kill">
          <div>
            <div class="sensor-label">Hardware Kill-Switch</div>
            <div style="font-size:0.8rem;color:var(--muted);margin-top:4px">Pin 7 Relay Status</div>
          </div>
          <div class="sensor-value" id="val-kill" style="color:var(--green)">ARMED</div>
        </div>
      </div>
    </div>

    <div class="card col-8">
      <h2>📡 Network Fingerprinting (MAC Spoof Defense)</h2>
      <div class="device-list" id="device-list">
        <p style="color:var(--muted);font-size:.8rem;padding:1rem">Awaiting neural network inference…</p>
      </div>
    </div>

    <!-- BOTTOM ROW: Logs -->
    <div class="card col-6">
      <h2>🔴 Live Security Event Feed</h2>
      <div class="feed" id="event-feed">
        <p style="color:var(--muted);font-size:.8rem;padding:1rem">Waiting for events…</p>
      </div>
    </div>

    <div class="card col-6">
      <h2>⛓️ Forensic Blockchain Ledger (Ganache)</h2>
      <div class="table-container">
        <table class="evidence-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Device</th>
              <th>Result</th>
              <th>Reason</th>
              <th>SHA-256 Signature</th>
            </tr>
          </thead>
          <tbody id="evidence-tbody">
            <tr><td colspan="5" style="text-align:center;color:var(--muted);padding:2rem">Loading blockchain data…</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- INTRUDER ALERT PANEL -->
    <div class="card col-12">
      <h2>🚨 Intruder Alert — Denied Access Photos</h2>
      <div class="intruder-grid" id="intruder-grid">
        <div class="no-intruders">✅ No denied access attempts recorded.</div>
      </div>
    </div>

    <footer>
      Zero-Trust IoT Security Architecture &nbsp;|&nbsp; 
      Hardware-to-Patent Implementation &nbsp;|&nbsp; 
      Auto-refreshing Dashboard
    </footer>
  </main>

  <script>
    // ── Clock ──
    function tick() {
      const now = new Date();
      document.getElementById('clock').textContent = now.toLocaleTimeString();
      document.getElementById('cam-time').textContent = now.toLocaleTimeString('en-US', {hour12:false}) + '.' + String(now.getMilliseconds()).padStart(3,'0');
    }
    setInterval(tick, 50);

    // ── Camera Polling ──
    // Appends timestamp to bypass browser cache
    setInterval(() => {
      const img = document.getElementById('live-cam');
      img.src = '/api/photo/ESP32_CAM_PERIMETER?t=' + new Date().getTime();
    }, 2000); // refresh every 2 seconds

    // ── Helpers ──
    function fmt(ts) { return new Date(ts * 1000).toLocaleTimeString(); }
    function trustColor(score) {
      if (score >= 80) return 'var(--green)';
      if (score >= 50) return 'var(--yellow)';
      return 'var(--red)';
    }
    function badgeClass(result) {
      if (result === 'AUTHENTICATED') return 'badge-auth';
      if (result === 'REJECTED')      return 'badge-reject';
      if (result === 'EMERGENCY_THERMAL') return 'badge-therm';
      if (result === 'PHYSICAL_TAMPER') return 'badge-tamper';
      return 'badge-warn';
    }
    function truncHash(h) { return h ? h.substring(0, 16) + '…' : '—'; }

    // ── Threat Radar & Sensors ──
    async function refreshSensors() {
      try {
        // Fetch Arduino environmental data
        const rEnv = await fetch('/api/environment');
        const env = await rEnv.json();
        if (env.temperature != null) {
          document.getElementById('val-temp').textContent = env.temperature.toFixed(1) + '°C';
          document.getElementById('val-hum').textContent = env.humidity.toFixed(1);
        }

        // Fetch overall Threat Score
        const rThreat = await fetch('/api/threat_level');
        const threat = await rThreat.json();
        document.getElementById('cnt-score').textContent = threat.threat_score + '%';
        
        const pill = document.getElementById('threat-pill');
        const status = document.getElementById('threat-status');
        const dot = document.getElementById('threat-dot');
        const vibCard = document.getElementById('card-vib');
        const valVib = document.getElementById('val-vib');
        const valKill = document.getElementById('val-kill');
        const cardKill = document.getElementById('card-kill');

        if (threat.color === 'RED') {
          pill.style.borderColor = 'var(--red)';
          status.style.color = 'var(--red)';
          status.textContent = 'SYSTEM LOCKDOWN';
          dot.style.background = 'var(--red)';
          document.getElementById('cnt-score').style.color = 'var(--red)';
          
          if (threat.alerts && threat.alerts.includes('PHYSICAL_TAMPER')) {
             vibCard.className = 'sensor-card alert';
             valVib.textContent = 'TAMPER!';
             valVib.style.color = 'var(--red)';
             document.getElementById('vib-status').textContent = 'VIBRATION DETECTED';
             
             cardKill.className = 'sensor-card alert';
             valKill.textContent = 'POWER CUT';
             valKill.style.color = 'var(--red)';
          }
        } else if (threat.color === 'ORANGE' || threat.color === 'YELLOW') {
          pill.style.borderColor = 'var(--yellow)';
          status.style.color = 'var(--yellow)';
          status.textContent = 'ELEVATED RISK';
          dot.style.background = 'var(--yellow)';
          document.getElementById('cnt-score').style.color = 'var(--yellow)';
        } else {
          pill.style.borderColor = 'var(--border)';
          status.style.color = 'var(--text)';
          status.textContent = 'SYSTEM SECURE';
          dot.style.background = 'var(--green)';
          document.getElementById('cnt-score').style.color = 'var(--green)';
          
          vibCard.className = 'sensor-card safe';
          valVib.textContent = 'SAFE';
          valVib.style.color = 'var(--green)';
          document.getElementById('vib-status').textContent = 'Monitoring...';
          
          cardKill.className = 'sensor-card safe';
          valKill.textContent = 'ARMED';
          valKill.style.color = 'var(--green)';
        }
      } catch(e) { console.error(e); }
    }

    // ── Device gauges ──
    async function refreshDevices() {
      try {
        const r = await fetch('/api/devices');
        const devices = await r.json();
        const el = document.getElementById('device-list');
        if (!devices.length) return;
        
        el.innerHTML = devices.map(d => {
          const score = Math.max(0, Math.min(100, d.trust_score));
          const color = trustColor(score);
          const status = d.status || 'UNKNOWN';
          const shadow = score < 50 ? `box-shadow: 0 0 15px ${color}` : '';
          return `
            <div class="device-row" style="border-left: 4px solid ${color}; ${shadow}">
              <div class="device-meta">
                <span class="device-id">${d.device_id}</span>
                <span style="color:${color};font-weight:700;font-size:1rem">${score.toFixed(1)}%</span>
              </div>
              <div class="trust-bar">
                <div class="trust-fill" style="width:${score}%;background:${color}"></div>
              </div>
              <div style="font-size:.75rem;color:var(--muted);display:flex;justify-content:space-between">
                <span>Network Jitter (IPD): <span style="color:var(--text)">${d.last_ipd ? d.last_ipd.toFixed(3) : '—'}s</span></span>
                <span>Signal: <span style="color:var(--text)">${d.last_rssi ?? '—'} dBm</span></span>
              </div>
            </div>
          `;
        }).join('');
      } catch(e) {}
    }

    // ── Counters + Feed ──
    async function refreshFeed() {
      try {
        const r = await fetch('/api/events?limit=30');
        const data = await r.json();

        document.getElementById('cnt-total').textContent    = data.total;
        document.getElementById('cnt-rejected').textContent = data.rejected;
        document.getElementById('cnt-auth').textContent     = data.authenticated;

        const feed = document.getElementById('event-feed');
        if (!data.events.length) return;
        
        feed.innerHTML = data.events.map(e => `
          <div class="event-row">
            <span class="event-badge ${badgeClass(e.result)}">${e.result}</span>
            <div style="flex:1;min-width:0">
              <div class="event-device">${e.device_id}</div>
              <div class="event-reason">${e.reason || 'Hardware Profile Verified'}</div>
            </div>
            <span class="event-time">${fmt(e.timestamp)}</span>
          </div>
        `).join('');
      } catch(e) {}
    }

    // ── Evidence table ──
    async function refreshEvidence() {
      try {
        const r = await fetch('/api/evidence?limit=20');
        const rows = await r.json();
        const tbody = document.getElementById('evidence-tbody');
        if (!rows.length) return;
        
        tbody.innerHTML = rows.map(row => {
          const color = row.result === 'AUTHENTICATED' ? 'var(--green)' :
                        row.result === 'REJECTED'      ? 'var(--red)' : 'var(--yellow)';
          return `
            <tr>
              <td style="color:var(--muted)">${fmt(row.timestamp)}</td>
              <td class="device-id" style="color:var(--cyan)">${row.device_id}</td>
              <td style="color:${color};font-weight:600">${row.result}</td>
              <td style="color:var(--muted);max-width:200px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="${row.reason || ''}">${row.reason || '—'}</td>
              <td><span class="hash" title="${row.event_hash}">${truncHash(row.event_hash)}</span></td>
            </tr>
          `;
        }).join('');
      } catch(e) {}
    }

    // ── Intruder photo gallery ──
    async function refreshIntruders() {
      try {
        const r = await fetch('/api/deny_photos?limit=12');
        const photos = await r.json();
        const grid = document.getElementById('intruder-grid');
        if (!photos.length) {
          grid.innerHTML = '<div class="no-intruders">✅ No denied access attempts recorded.</div>';
          return;
        }
        grid.innerHTML = photos.map(p => `
          <div class="intruder-card">
            <img src="/api/deny_photo_img?path=${encodeURIComponent(p.photo_path)}"
                 onerror="this.style.display='none'" alt="Intruder">
            <div class="intruder-meta">
              <div class="uid">🆔 ${p.uid}</div>
              <div>👤 ${p.name || 'UNKNOWN'}</div>
              <div>❌ ${p.reason}</div>
              <div style="margin-top:4px;color:var(--muted)">${new Date(p.timestamp).toLocaleString()}</div>
            </div>
          </div>
        `).join('');
      } catch(e) {}
    }

    function refreshAll() {
      refreshSensors();
      refreshDevices();
      refreshFeed();
      refreshEvidence();
      refreshIntruders();
    }

    refreshAll();
    setInterval(refreshAll, 2500); // Fast refresh for live demo
  </script>
</body>
</html>
"""


DASHBOARD_HTML = None  # Loaded from file below

def _load_template():
    """Load the HTML template from disk (allows hot-reload during dev)."""
    tpl_path = os.path.join(_BASE_DIR, "dashboard_template.html")
    if os.path.exists(tpl_path):
        with open(tpl_path, encoding="utf-8") as f:
            return f.read()
    # Fallback to old inline template
    return DASHBOARD_HTML or "<h1>Dashboard template not found</h1>"


# ─────────────────────────────────────────────────────────────────────────────
# API Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(_load_template())


@app.route("/api/devices")
def api_devices():
    """Returns all known device statuses."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT device_id, status, trust_score, last_seen,
                       last_rssi, last_ipd, connection_state
                FROM device_status
                ORDER BY last_seen DESC
                """
            ).fetchall()
        return jsonify([dict(r) for r in rows])
    except sqlite3.OperationalError:
        return jsonify([])


@app.route("/api/events")
def api_events():
    """Returns recent access log events + summary counters."""
    from flask import request as req
    limit = int(req.args.get("limit", 50))
    events = get_recent_access_log(limit)
    thermal = get_thermal_alerts(limit)

    # Merge and sort thermal alerts into the event feed
    for t in thermal:
        events.append({
            "device_id": t["device_id"],
            "result": "EMERGENCY_THERMAL",
            "reason": t["details"],
            "trust_score": None,
            "timestamp": t["timestamp"],
        })
    events.sort(key=lambda e: e.get("timestamp", 0), reverse=True)

    # Counters
    all_events = get_recent_access_log(10000)
    today_start = int(time.time()) - 86400
    rejected = sum(1 for e in all_events if e["result"] == "REJECTED" and e["timestamp"] > today_start)
    authenticated = sum(1 for e in all_events if e["result"] == "AUTHENTICATED")

    return jsonify({
        "events": events[:limit],
        "total": len(all_events),
        "rejected": rejected,
        "authenticated": authenticated,
        "thermal": len(thermal),
    })


@app.route("/api/evidence")
def api_evidence():
    """Returns the forensic evidence log for the blockchain table."""
    from flask import request as req
    limit = int(req.args.get("limit", 50))
    return jsonify(get_recent_access_log(limit))


@app.route("/api/stats")
def api_stats():
    """Quick system health stats (compatible with iot_server /stats)."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM heartbeats")
            heartbeats = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM evidence")
            evidence = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(DISTINCT device_id) FROM heartbeats")
            devices = cursor.fetchone()[0]
        return jsonify({"heartbeats": heartbeats, "evidence": evidence, "devices": devices})
    except sqlite3.OperationalError:
        return jsonify({"heartbeats": 0, "evidence": 0, "devices": 0})


# ─────────────────────────────────────────────────────────────────────────────
# New API Endpoints — Phase 2 Dashboard Expansion
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/sensors")
def api_sensors():
    """SW-420 and DHT22 sensor health status."""
    try:
        from pi_backend.defense_sensors import get_sensor_status
        return jsonify(get_sensor_status())
    except Exception as exc:
        return jsonify({"error": str(exc), "gpio_available": False})


@app.route("/api/tamper")
def api_tamper():
    """Recent SW-420 physical tamper events."""
    try:
        from pi_backend.defense_sensors import get_tamper_alerts
        return jsonify(get_tamper_alerts(20))
    except Exception as exc:
        return jsonify([])


@app.route("/api/fault")
def api_fault():
    """Recent laser-glitch / fault injection events."""
    try:
        from pi_backend.fault_detector import get_fault_events
        return jsonify(get_fault_events(20))
    except Exception as exc:
        return jsonify([])


@app.route("/api/threat_level")
def api_threat_level():
    """
    Threat Radar — computes an aggregate threat level (0-100) for the UI.

    Score factors:
      • Devices with trust_score < 50 → +30 each
      • REJECTED events in last 5 min → +5 each (capped at 40)
      • Active thermal alerts         → +20 each (capped at 20)
      • PHYSICAL_TAMPER events        → +50 (immediate RED)
      • CLOCK_TAMPER events           → +30
    """
    threat = 0
    alerts_active = []
    now = int(time.time())

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row

            # Low-trust devices
            devices = conn.execute(
                "SELECT device_id, trust_score FROM device_status "
                "WHERE trust_score < 50"
            ).fetchall()
            for d in devices:
                threat += 30
                alerts_active.append(f"LOW_TRUST:{d['device_id']}({d['trust_score']:.0f})")

            # Recent rejections (last 5 min)
            rejected_count = conn.execute(
                "SELECT COUNT(*) FROM access_log "
                "WHERE result='REJECTED' AND timestamp > ?",
                (now - 300,)
            ).fetchone()[0]
            threat += min(rejected_count * 5, 40)
            if rejected_count:
                alerts_active.append(f"REJECTED_x{rejected_count}")

            # Thermal alerts
            thermal = conn.execute(
                "SELECT COUNT(*) FROM alerts "
                "WHERE event_type IN ('EMERGENCY_THERMAL','SENSOR_TAMPER') "
                "AND timestamp > ?",
                (now - 300,)
            ).fetchone()[0]
            threat += min(thermal * 20, 20)
            if thermal:
                alerts_active.append(f"THERMAL_x{thermal}")

            # Physical tamper
            tamper = conn.execute(
                "SELECT COUNT(*) FROM alerts "
                "WHERE event_type='PHYSICAL_TAMPER' AND timestamp > ?",
                (now - 300,)
            ).fetchone()[0]
            if tamper:
                threat += 50
                alerts_active.append("PHYSICAL_TAMPER")

            # Clock tamper (NTP drift)
            clock = conn.execute(
                "SELECT COUNT(*) FROM alerts "
                "WHERE event_type='CLOCK_TAMPER' AND timestamp > ?",
                (now - 300,)
            ).fetchone()[0]
            if clock:
                threat += 30
                alerts_active.append("CLOCK_TAMPER")

    except sqlite3.OperationalError:
        pass

    threat = min(threat, 100)

    if threat >= 70:
        color = "RED"
    elif threat >= 35:
        color = "ORANGE"
    elif threat >= 10:
        color = "YELLOW"
    else:
        color = "GREEN"

    return jsonify({
        "threat_score": threat,
        "color":        color,
        "alerts":       alerts_active,
        "timestamp":    now,
    })


@app.route("/api/photo/<device_id>")
def api_photo(device_id: str):
    """
    Returns the latest JPEG photo from the ESP32-CAM for this device.
    The dashboard <img> tag polls this endpoint every 5 seconds.
    """
    jpeg = _latest_photos.get(device_id)
    if jpeg is None:
        jpeg = load_device_photo(device_id)
    if jpeg:
        return Response(jpeg, mimetype="image/jpeg")

    # Return a 1×1 transparent placeholder when no photo exists yet
    # (1×1 grey JPEG — minimal valid JPEG bytes)
    placeholder = (
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        b"\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t\x08\n"
        b"\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a\x1f\x1e\x1d"
        b"\x1a\x1c\x1c $.' \",#\x1c\x1c(7),01444\x1f'9=82<.342\x1eG\xc0\x00\x0b"
        b"\x08\x00\x01\x00\x01\x01\x01\x11\x00\xff\xc4\x00\x1f\x00\x00\x01\x05"
        b"\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03"
        b"\x04\x05\x06\x07\x08\t\n\x0b\xff\xda\x00\x08\x01\x01\x00\x00?\x00\xfb"
        b"\xd2\x8a(\x03\xff\xd9"
    )
    return Response(placeholder, mimetype="image/jpeg")


@app.route("/api/environment")
def api_environment():
    """Latest DHT22 temperature and humidity reading."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM heartbeats WHERE device_id='PI_DHT22' "
                "ORDER BY received_at DESC LIMIT 1"
            ).fetchone()
        if row:
            return jsonify(dict(row))
        return jsonify({"temperature": None, "humidity": None})
    except sqlite3.OperationalError:
        return jsonify({"temperature": None, "humidity": None})


@app.route("/api/clock")
def api_clock():
    """Clock drift status from the RTC guard."""
    try:
        from pi_backend.clock_guard import check_clock_drift, is_clock_tampered
        report = check_clock_drift()
        report["tampered"] = is_clock_tampered()
        return jsonify(report)
    except Exception as exc:
        return jsonify({"error": str(exc)})


@app.route("/api/deny_photos")
def api_deny_photos():
    """
    Returns the most recent DENY entries from access_log.json that have
    a saved photo, newest first. Used by the Intruder Alert gallery panel.
    """
    from flask import request as req
    limit = int(req.args.get("limit", 12))
    log_file = os.path.join(os.path.dirname(_BASE_DIR), "access_log.json")
    try:
        with open(log_file) as f:
            log = json.load(f)
    except Exception:
        return jsonify([])

    denied = [
        e for e in log
        if e.get("decision") == "DENY" and e.get("photo_path")
    ]
    denied.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
    return jsonify(denied[:limit])


@app.route("/api/deny_photo_img")
def api_deny_photo_img():
    """
    Serves a saved intruder JPEG by its absolute path.
    The path must be inside the project photos/ directory (security check).
    """
    from flask import request as req, abort, send_file
    raw_path = req.args.get("path", "")
    photos_dir = os.path.join(os.path.dirname(_BASE_DIR), "photos")
    abs_path   = os.path.realpath(raw_path)
    # Security: only serve files that live inside the photos/ folder
    if not abs_path.startswith(os.path.realpath(photos_dir)):
        abort(403)
    if not os.path.isfile(abs_path):
        abort(404)
    return send_file(abs_path, mimetype="image/jpeg")


# ─────────────────────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("DASHBOARD_PORT", "5001"))
    print("\n" + "=" * 60)
    print("  Zero-Trust IoT Security Dashboard")
    print(f"  Open → http://localhost:{port}")
    print("=" * 60 + "\n")
    app.run(host="0.0.0.0", port=port, debug=False)
