#!/usr/bin/env python3
"""
Zero-Trust IoT Security - Single Pane of Glass Dashboard
Flask app running on port 5001
Real-time trust scores, event feed, blockchain forensics, threat metrics
Auto-refreshes every 3 seconds
"""

import sqlite3
import json
import os
import time
from flask import Flask, jsonify, render_template_string
from collections import deque

app = Flask(__name__)

DB_PATH = '/home/mridul/Master_IoT_Project/security.db'

# In-memory event store (acts as live feed buffer)
live_events = deque(maxlen=50)
trust_scores = {}  # {device_id: {"score": float, "status": str, "last_seen": float}}

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_stats():
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM heartbeats")
        total_traffic = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM alerts WHERE event_type='TAMPER'")
        tamper_alerts = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM alerts WHERE event_type='REJECTED'")
        events_blocked = cur.fetchone()[0]
        cur.execute("SELECT COUNT(DISTINCT device_id) FROM heartbeats")
        devices = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM alerts WHERE event_type='THERMAL'")
        thermal_alerts = cur.fetchone()[0]
        conn.close()
        return {
            "total_traffic": total_traffic,
            "tamper_alerts": tamper_alerts,
            "events_blocked": events_blocked,
            "active_devices": devices,
            "thermal_alerts": thermal_alerts
        }
    except Exception as e:
        return {"total_traffic": 0, "tamper_alerts": 0, "events_blocked": 0, "active_devices": 0, "thermal_alerts": 0}

def get_recent_events():
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT device_id, event_type, timestamp, details
            FROM alerts ORDER BY id DESC LIMIT 20
        """)
        rows = cur.fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"[dashboard] get_recent_events error: {e}")
        return []

def get_forensic_log():
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT id, device_id, image_hash, timestamp, blockchain_tx, verified
            FROM evidence ORDER BY id DESC LIMIT 10
        """)
        rows = cur.fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"[dashboard] get_forensic_log error: {e}")
        return []

def get_device_trust():
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT device_id, rssi, inter_packet_delay, received_at, is_legitimate
            FROM heartbeats ORDER BY id DESC LIMIT 100
        """)
        rows = cur.fetchall()
        conn.close()
        # Build per-device latest stats
        seen = {}
        for r in rows:
            did = r['device_id']
            if did not in seen:
                score = 100.0 if r['is_legitimate'] == 1 else 20.0
                seen[did] = {
                    "device_id": did,
                    "score": score,
                    "rssi": r['rssi'],
                    "ipd": r['inter_packet_delay'],
                    "last_seen": r['received_at'],
                    "status": "AUTHENTICATED" if r['is_legitimate'] == 1 else "DENIED"
                }
        return list(seen.values())
    except Exception as e:
        print(f"[dashboard] get_device_trust error: {e}")
        return []


def get_threat_level() -> dict:
    """
    Determines the current system threat level by inspecting recent alerts.
    Returns: {"level": "SECURE"|"HEARTBEAT_LOST"|"THERMAL_BREACH"|"LOCKDOWN", "detail": str}
    """
    try:
        conn = get_db()
        cur = conn.cursor()
        since = int(time.time()) - 60  # last 60 seconds
        cur.execute("""
            SELECT event_type FROM alerts WHERE timestamp > ? ORDER BY id DESC LIMIT 20
        """, (since,))
        recent_types = [r[0] for r in cur.fetchall()]
        conn.close()

        if "TAMPER" in recent_types:
            return {"level": "LOCKDOWN",        "detail": "Kinetic tamper detected — keys wiped"}
        if "THERMAL" in recent_types:
            return {"level": "THERMAL_BREACH",  "detail": "Thermal sabotage detected"}
        if "REJECTED" in recent_types:
            return {"level": "THREAT",           "detail": "Access denied — spoofing attempt"}
        return  {"level": "SECURE",             "detail": "All systems nominal"}
    except Exception as e:
        print(f"[dashboard] get_threat_level error: {e}")
        return {"level": "UNKNOWN", "detail": str(e)}


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Zero-Trust IoT — Command Center</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@700;900&display=swap" rel="stylesheet">
<style>
:root{--bg:#050a0e;--panel:#0d1117;--border:#1a2a1a;--g:#00ff41;--gd:#00aa2a;--r:#ff2244;--y:#ffd700;--c:#00e5ff;--o:#ff8c00;--tx:#c9d1d9;--txd:#586069}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--g);font-family:'Share Tech Mono',monospace;min-height:100vh;overflow-x:hidden;transition:background 0.6s}
body::after{content:'';position:fixed;top:0;left:0;width:100%;height:100%;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,65,.012) 2px,rgba(0,255,65,.012) 4px);pointer-events:none;z-index:9998}

/* HEADER */
header{background:linear-gradient(90deg,#050a0e,#0a1a0a,#050a0e);border-bottom:1px solid var(--gd);padding:14px 28px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}
header h1{font-family:'Orbitron',sans-serif;font-size:17px;color:var(--g);letter-spacing:3px;text-shadow:0 0 18px var(--g)}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--g);margin-right:8px;box-shadow:0 0 7px var(--g);animation:pulse 1.4s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.25}}
#clock{font-size:12px;color:var(--gd)}

/* THREAT BANNER */
#threat-banner{display:none;position:fixed;bottom:0;left:0;right:0;text-align:center;padding:10px;font-family:'Orbitron',sans-serif;font-size:13px;font-weight:900;letter-spacing:2px;z-index:9999;transition:all .4s}

/* GRID */
.wrap{padding:16px 20px;display:flex;flex-direction:column;gap:14px}
.row{display:grid;gap:14px}
.r4{grid-template-columns:repeat(4,1fr)}
.r3{grid-template-columns:1.5fr 1fr 1fr}
.r2{grid-template-columns:1fr 1.6fr}

/* STAT CARDS */
.stat{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:18px;position:relative;overflow:hidden}
.stat::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--g),transparent)}
.stat.r::before{background:linear-gradient(90deg,transparent,var(--r),transparent)}
.stat.y::before{background:linear-gradient(90deg,transparent,var(--y),transparent)}
.stat.c::before{background:linear-gradient(90deg,transparent,var(--c),transparent)}
.slabel{font-size:9px;color:var(--txd);letter-spacing:2px;text-transform:uppercase;margin-bottom:6px}
.sval{font-family:'Orbitron',sans-serif;font-size:32px;color:var(--g);text-shadow:0 0 12px var(--g)}
.stat.r .sval{color:var(--r);text-shadow:0 0 12px var(--r)}
.stat.y .sval{color:var(--y);text-shadow:0 0 12px var(--y)}
.stat.c .sval{color:var(--c);text-shadow:0 0 12px var(--c)}

/* PANELS */
.panel{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:16px}
.panel h3{font-size:10px;color:var(--txd);letter-spacing:2px;text-transform:uppercase;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid var(--border)}

/* CAMERA */
#cam-wrap{text-align:center;position:relative}
#cam-img{width:100%;max-height:220px;object-fit:cover;border-radius:6px;border:1px solid var(--gd);display:block}
#cam-placeholder{width:100%;height:200px;background:#0a0a0a;border:1px dashed var(--border);border-radius:6px;display:flex;align-items:center;justify-content:center;color:var(--txd);font-size:12px}
#cam-timestamp{font-size:9px;color:var(--txd);margin-top:6px}
.rgb-badge{display:inline-block;padding:2px 10px;border-radius:3px;font-size:10px;font-weight:bold;margin-top:6px;letter-spacing:1px}

/* TRUST BARS */
.tcard{background:rgba(0,255,65,.03);border:1px solid var(--border);border-radius:5px;padding:12px;margin-bottom:8px}
.thead2{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px}
.dname{font-size:12px;color:var(--g)}
.badge{font-size:9px;padding:2px 7px;border-radius:3px;font-weight:bold}
.ba{background:rgba(0,255,65,.12);color:var(--g);border:1px solid var(--gd)}
.bd{background:rgba(255,34,68,.12);color:var(--r);border:1px solid var(--r)}
.bar-bg{background:#1a2a1a;border-radius:3px;height:6px;margin-bottom:4px}
.bar{height:6px;border-radius:3px;background:linear-gradient(90deg,var(--gd),var(--g));box-shadow:0 0 6px var(--g);transition:width .6s}
.bar.low{background:linear-gradient(90deg,#880000,var(--r));box-shadow:0 0 6px var(--r)}
.tmeta{font-size:9px;color:var(--txd);display:flex;justify-content:space-between}

/* EVENT FEED */
.erow{display:flex;gap:8px;padding:6px 0;border-bottom:1px solid rgba(26,42,26,.4);font-size:10px;align-items:flex-start}
.erow:last-child{border-bottom:none}
.etype{min-width:80px;padding:2px 5px;border-radius:2px;text-align:center;font-size:8px;font-weight:bold;letter-spacing:.5px}
.type-TAMPER{background:rgba(255,34,68,.2);color:var(--r);border:1px solid var(--r)}
.type-REJECTED{background:rgba(255,215,0,.15);color:var(--y);border:1px solid var(--y)}
.type-AUTHENTICATED{background:rgba(0,255,65,.08);color:var(--g);border:1px solid var(--gd)}
.type-THERMAL{background:rgba(255,100,0,.2);color:#ff6400;border:1px solid #ff6400}
.type-ACOUSTIC_ATTACK{background:rgba(148,0,211,.25);color:#da70d6;border:1px solid #9400d3}
.edev{color:var(--gd);font-size:9px}
.edet{color:var(--tx);flex:1}

/* BLOCKCHAIN TABLE */
table{width:100%;border-collapse:collapse;font-size:10px}
th{color:var(--txd);text-align:left;padding:6px;border-bottom:1px solid var(--border);font-size:9px;letter-spacing:1px}
td{padding:6px;border-bottom:1px solid rgba(26,42,26,.25);color:var(--tx)}
td.hash{color:var(--c);font-size:9px}
td.ok{color:var(--g)}
td.pend{color:var(--txd)}

/* ATTACK SUMMARY */
.asrow{margin-bottom:14px}
.asval{font-size:24px;text-shadow:0 0 8px var(--r);color:var(--r)}
.asval.y{color:var(--y);text-shadow:0 0 8px var(--y)}
footer{text-align:center;padding:10px;color:var(--txd);font-size:9px;border-top:1px solid var(--border);margin-top:8px}
</style>
</head>
<body>
<header>
  <h1><span class="dot"></span>&#x1F6E1;&#xFE0F; ZERO-TRUST IoT SECURITY COMMAND CENTER</h1>
  <div id="clock">SYSTEM ONLINE | <span id="ts"></span> | LIVE</div>
</header>

<div id="threat-banner"></div>

<div class="wrap">
  <!-- STAT CARDS -->
  <div class="row r4">
    <div class="stat c"><div class="slabel">Total Traffic</div><div class="sval" id="s-traffic">--</div><div style="font-size:9px;color:var(--txd);margin-top:4px">packets logged</div></div>
    <div class="stat"><div class="slabel">Active Devices</div><div class="sval" id="s-dev">--</div><div style="font-size:9px;color:var(--txd);margin-top:4px">connected nodes</div></div>
    <div class="stat r"><div class="slabel">Events Blocked</div><div class="sval" id="s-blocked">--</div><div style="font-size:9px;color:var(--r);margin-top:4px">access denied</div></div>
    <div class="stat y"><div class="slabel">Thermal Alerts</div><div class="sval" id="s-thermal">--</div><div style="font-size:9px;color:var(--y);margin-top:4px">temp events</div></div>
  </div>

  <!-- MAIN ROW: Camera | Trust | Events -->
  <div class="row r3">

    <!-- CAMERA PANEL -->
    <div class="panel">
      <h3>&#x1F4F8; Sentry Camera — Live Capture</h3>
      <div id="cam-wrap">
        <div id="cam-placeholder">&#x1F4F7; No capture yet — awaiting RFID scan</div>
        <img id="cam-img" src="" alt="Sentry capture" style="display:none">
        <div id="cam-timestamp"></div>
        <div id="rgb-badge-wrap"></div>
      </div>
      <!-- RGB Challenge status -->
      <div style="margin-top:12px;font-size:10px;color:var(--txd)">
        <span id="rgb-status">RGB Challenge: Idle</span>
      </div>
    </div>

    <!-- TRUST SCORES -->
    <div class="panel">
      <h3>&#x1F512; Live Hardware Trust Scores</h3>
      <div id="trust" style="max-height:340px;overflow-y:auto"><div style="color:var(--txd);font-size:11px">Waiting for device data...</div></div>
    </div>

    <!-- ATTACK SUMMARY -->
    <div class="panel">
      <h3>&#x1F6A8; Tamper / Attack Summary</h3>
      <div class="asrow"><div class="slabel">Wi-Fi Jamming (Heartbeat Loss)</div><div class="asval" id="a-jam">--</div></div>
      <div class="asrow"><div class="slabel">Physical Tamper (SW-420)</div><div class="asval" id="a-tamp">--</div></div>
      <div class="asrow"><div class="slabel">Thermal Sabotage (DHT22)</div><div class="asval y" id="a-therm">--</div></div>
      <div class="asrow"><div class="slabel">AI Spoofing (Jitter Mismatch)</div><div class="asval" id="a-spoof">--</div></div>
    </div>
  </div>

  <!-- SECOND ROW: Events | Blockchain -->
  <div class="row r2">
    <!-- EVENT FEED -->
    <div class="panel">
      <h3>&#x26A1; Security Event Feed</h3>
      <div id="feed" style="max-height:260px;overflow-y:auto"><div style="color:var(--txd);font-size:11px">Monitoring...</div></div>
    </div>

    <!-- BLOCKCHAIN FORENSIC TABLE -->
    <div class="panel">
      <h3>&#x26D3;&#xFE0F; Blockchain Forensic Evidence — Immutable Audit Trail</h3>
      <div style="overflow-x:auto">
        <table>
          <thead><tr><th>#</th><th>Device</th><th>SHA-256 Hash</th><th>Timestamp</th><th>TX Hash</th><th>Verified</th></tr></thead>
          <tbody id="chain"></tbody>
        </table>
      </div>
    </div>
  </div>
</div>

<footer>ZERO-TRUST IoT SECURITY PLATFORM v4.0 &nbsp;|&nbsp; Hardware-to-Patent &nbsp;|&nbsp; Raspberry Pi 5 &nbsp;|&nbsp; Ganache Blockchain &nbsp;|&nbsp; AI LSTM Fingerprinting</footer>

<script>
// Clock
setInterval(()=>{ document.getElementById('ts').textContent=new Date().toLocaleTimeString(); }, 1000);
document.getElementById('ts').textContent=new Date().toLocaleTimeString();

// ── Threat Level ─────────────────────────────────────────────────────────────
const TH = {
  SECURE:         {bg:'#050a0e', banner:null},
  THREAT:         {bg:'#1a0800', banner:{bg:'#ff6400',tx:'#000'}},
  HEARTBEAT_LOST: {bg:'#2a1000', banner:{bg:'#ff8c00',tx:'#000'}},
  THERMAL_BREACH: {bg:'#1a0500', banner:{bg:'#ff2244',tx:'#fff'}},
  LOCKDOWN:       {bg:'#000000', banner:{bg:'#ff2244',tx:'#fff'}},
  UNKNOWN:        {bg:'#050a0e', banner:null},
};
async function pollThreat(){
  try{
    const d=await(await fetch('/api/threat_level')).json();
    const cfg=TH[d.level]||TH.UNKNOWN;
    document.body.style.background=cfg.bg;
    const b=document.getElementById('threat-banner');
    if(cfg.banner){
      b.style.display='block';
      b.style.background=cfg.banner.bg;
      b.style.color=cfg.banner.tx;
      b.style.boxShadow=`0 0 20px ${cfg.banner.bg}`;
      b.textContent=`\u26A0 ${d.level.replace(/_/g,' ')} \u2014 ${d.detail}`;
    } else { b.style.display='none'; }
  } catch(e){}
}
pollThreat(); setInterval(pollThreat, 2000);

// ── Camera Feed ───────────────────────────────────────────────────────────────
async function pollCamera(){
  try{
    const d=await(await fetch('/api/camera')).json();
    if(d.image_b64){
      const img=document.getElementById('cam-img');
      const ph=document.getElementById('cam-placeholder');
      img.src='data:image/jpeg;base64,'+d.image_b64;
      img.style.display='block'; ph.style.display='none';
      document.getElementById('cam-timestamp').textContent=
        'Last capture: '+new Date(d.timestamp*1000).toLocaleTimeString()+' | Device: '+(d.device_id||'?');
      if(d.rgb_color){
        const colors={RED:'#ff2244',GREEN:'#00ff41',BLUE:'#0088ff',CYAN:'#00e5ff',YELLOW:'#ffd700',MAGENTA:'#ff00ff'};
        const c=colors[d.rgb_color]||'#888';
        document.getElementById('rgb-badge-wrap').innerHTML=
          `<span class="rgb-badge" style="background:${c}22;color:${c};border:1px solid ${c}">RGB: ${d.rgb_color}</span>`;
        document.getElementById('rgb-status').textContent='RGB Challenge: '+d.rgb_status;
      }
    }
  } catch(e){}
}
pollCamera(); setInterval(pollCamera, 3000);

// ── Main Data ─────────────────────────────────────────────────────────────────
async function pollData(){
  try{
    const [sR,tR,eR,fR]=await Promise.all([
      fetch('/api/stats'),fetch('/api/trust'),fetch('/api/events'),fetch('/api/forensic')
    ]);
    const [s,t,ev,f]=await Promise.all([sR.json(),tR.json(),eR.json(),fR.json()]);

    // Stats
    document.getElementById('s-traffic').textContent=s.total_traffic;
    document.getElementById('s-dev').textContent=s.active_devices;
    document.getElementById('s-blocked').textContent=s.events_blocked;
    document.getElementById('s-thermal').textContent=s.thermal_alerts;
    document.getElementById('a-jam').textContent=s.tamper_alerts||0;
    document.getElementById('a-tamp').textContent=s.tamper_alerts||0;
    document.getElementById('a-therm').textContent=s.thermal_alerts||0;
    document.getElementById('a-spoof').textContent=s.events_blocked||0;

    // Trust gauges
    const tEl=document.getElementById('trust');
    tEl.innerHTML=t.length===0
      ? '<div style="color:var(--txd);font-size:11px">No devices detected yet.</div>'
      : t.map(d=>{
          const p=Math.min(100,Math.max(0,d.score));
          const low=p<50;
          const bclass=d.status==='AUTHENTICATED'?'ba':'bd';
          return `<div class="tcard">
            <div class="thead2"><span class="dname">${d.device_id}</span><span class="badge ${bclass}">${d.status}</span></div>
            <div class="bar-bg"><div class="bar ${low?'low':''}" style="width:${p}%"></div></div>
            <div class="tmeta"><span>Trust: ${p.toFixed(1)}%</span><span>RSSI: ${d.rssi} dBm | IPD: ${d.ipd}ms</span></div>
          </div>`;
        }).join('');

    // Event feed
    const fEl=document.getElementById('feed');
    fEl.innerHTML=ev.length===0
      ? '<div style="color:var(--txd);font-size:11px">No events yet.</div>'
      : ev.map(e=>{
          const t2=new Date(e.timestamp*1000).toLocaleTimeString();
          return `<div class="erow">
            <span class="etype type-${e.event_type}">${e.event_type}</span>
            <div><div class="edev">${e.device_id} &nbsp;|&nbsp; ${t2}</div>
            <div class="edet">${e.details||''}</div></div>
          </div>`;
        }).join('');

    // Blockchain table
    document.getElementById('chain').innerHTML=f.length===0
      ? '<tr><td colspan="6" style="color:var(--txd);text-align:center">No evidence yet.</td></tr>'
      : f.map(r=>{
          const hash=r.image_hash?r.image_hash.slice(0,18)+'...':'N/A';
          const tx=r.blockchain_tx?r.blockchain_tx.slice(0,16)+'...':'Pending';
          const ts=new Date(r.timestamp*1000).toLocaleString();
          const ver=r.verified
            ? '<span class="ok">\u2713 ON-CHAIN</span>'
            : '<span class="pend">\u23F3 Pending</span>';
          return `<tr>
            <td>${r.id}</td><td>${r.device_id}</td>
            <td class="hash">${hash}</td><td>${ts}</td>
            <td class="hash">${tx}</td><td>${ver}</td>
          </tr>`;
        }).join('');

  } catch(e){ console.error(e); }
}
pollData(); setInterval(pollData, 3000);
</script>
</body>
</html>
"""


@app.route('/api/camera')
def api_camera():
    """Serve the latest sentry camera capture as base64 for the dashboard."""
    import base64, glob
    evidence_dir = '/home/mridul/Master_IoT_Project/static/evidence'
    jpgs = sorted(glob.glob(f'{evidence_dir}/capture_*.jpg'), key=os.path.getmtime, reverse=True)
    if not jpgs:
        return jsonify({'image_b64': None, 'device_id': None, 'timestamp': None,
                        'rgb_color': None, 'rgb_status': 'No capture yet'})
    latest = jpgs[0]
    fname  = os.path.basename(latest)
    parts  = fname.replace('capture_','').replace('.jpg','').rsplit('_', 1)
    dev_id = parts[0] if len(parts) == 2 else 'unknown'
    ts     = float(parts[1]) if len(parts) == 2 else os.path.getmtime(latest)
    with open(latest, 'rb') as fh:
        img_b64 = base64.b64encode(fh.read()).decode()
    return jsonify({'image_b64': img_b64, 'device_id': dev_id, 'timestamp': ts,
                    'rgb_color': None, 'rgb_status': 'Verified'})

@app.route('/api/threat_level')
def api_threat_level():
    return jsonify(get_threat_level())


@app.route('/')
def index():
    return render_template_string(DASHBOARD_HTML)

@app.route('/api/stats')
def api_stats():
    return jsonify(get_stats())

@app.route('/api/trust')
def api_trust():
    return jsonify(get_device_trust())

@app.route('/api/events')
def api_events():
    return jsonify(get_recent_events())

@app.route('/api/forensic')
def api_forensic():
    return jsonify(get_forensic_log())


if __name__ == '__main__':
    print("\n" + "="*60)
    print("📊  ZERO-TRUST IoT SECURITY DASHBOARD")
    print("="*60)
    print(f"\n🌐 Open your browser at: http://0.0.0.0:5001")
    print(f"📡 Auto-refresh: every 3 seconds")
    print(f"💾 Database: {DB_PATH}")
    print("\n✅ Dashboard ready.\n")
    app.run(host='0.0.0.0', port=5001, debug=False)
