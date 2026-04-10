import warnings
warnings.filterwarnings('ignore')

import sys
import os
import threading
import time
import joblib
import numpy as np
import smtplib
import psutil
from email.mime.text import MIMEText
from collections import defaultdict
from flask import Flask, render_template_string, jsonify
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import urllib.request
import json

# ── 1. Load model ─────────────────────────────────────────────────────────────
BASE = '/home/ivan/pi/FinalYearProject IDS/models/'

print("Loading model...")
model         = joblib.load(BASE + 'random_forest.pkl')
scaler        = joblib.load(BASE + 'scaler.pkl')
le            = joblib.load(BASE + 'label_encoder.pkl')
feature_names = joblib.load(BASE + 'feature_names.pkl')
print("Model loaded successfully.")

# ── 2. Shared state ───────────────────────────────────────────────────────────
alerts            = []
alerts_lock       = threading.Lock()
stats             = defaultdict(int)
port_tracker      = defaultdict(set)
port_tracker_lock = threading.Lock()
blocked_ips       = set()

# ── 3. Email alert config ─────────────────────────────────────────────────────
EMAIL_ENABLED   = True
EMAIL_SENDER    = 'iv.stoyanov13@gmail.com'
EMAIL_PASSWORD  = 'jwcd lzii qbez udzs'
EMAIL_RECEIVER  = 'is9038y@gre.ac.uk'
last_email_time = 0

def send_email_alert(label, src_ip):
    global last_email_time
    now = time.time()
    if now - last_email_time < 60:
        return
    last_email_time = now
    try:
        msg = MIMEText(f'Attack detected!\nType: {label}\nSource IP: {src_ip}\nTime: {time.strftime("%H:%M:%S")}')
        msg['Subject'] = f'[IDS ALERT] {label} detected'
        msg['From']    = EMAIL_SENDER
        msg['To']      = EMAIL_RECEIVER
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)
        print(f"[EMAIL] Alert sent for {label}")
    except Exception as e:
        print(f"[EMAIL] Failed: {e}")

# ── 4. Geo-IP lookup ──────────────────────────────────────────────────────────
geo_cache = {}

def get_geo(ip):
    if ip in geo_cache:
        return geo_cache[ip]
    if ip.startswith('192.168') or ip.startswith('10.') or ip.startswith('127.'):
        geo_cache[ip] = 'Local Network'
        return 'Local Network'
    try:
        url = f'http://ip-api.com/json/{ip}?fields=country,city'
        with urllib.request.urlopen(url, timeout=2) as r:
            data = json.loads(r.read())
            result = f"{data.get('city','?')}, {data.get('country','?')}"
            geo_cache[ip] = result
            return result
    except Exception:
        geo_cache[ip] = 'Unknown'
        return 'Unknown'

# ── 5. Flask app ──────────────────────────────────────────────────────────────
app = Flask(__name__)

# ── 6. Feature extraction ─────────────────────────────────────────────────────
def extract_features(packet):
    features = defaultdict(float)
    if IP in packet:
        features['Destination Port']            = float(packet[IP].dport) if TCP in packet or UDP in packet else 0.0
        features['Flow Duration']               = 0.0
        features['Total Fwd Packets']           = 1.0
        features['Total Length of Fwd Packets'] = float(len(packet))
        features['Fwd Packet Length Max']       = float(len(packet))
        features['Fwd Packet Length Min']       = float(len(packet))
        features['Fwd Packet Length Mean']      = float(len(packet))
        features['Fwd Packet Length Std']       = 0.0
        features['Bwd Packet Length Max']       = 0.0
        features['Bwd Packet Length Min']       = 0.0
        features['Bwd Packet Length Mean']      = 0.0
        features['Bwd Packet Length Std']       = 0.0
        features['Flow Bytes/s']                = 0.0
        features['Flow Packets/s']              = 1.0
        features['Flow IAT Mean']               = 0.0
        features['Flow IAT Std']                = 0.0
        features['Flow IAT Max']                = 0.0
        features['Flow IAT Min']                = 0.0
        features['Fwd IAT Total']               = 0.0
        features['Fwd IAT Mean']                = 0.0
        features['Fwd IAT Std']                 = 0.0
        features['Fwd IAT Max']                 = 0.0
        features['Fwd IAT Min']                 = 0.0
        features['Bwd IAT Total']               = 0.0
        features['Bwd IAT Mean']                = 0.0
        features['Bwd IAT Std']                 = 0.0
        features['Bwd IAT Max']                 = 0.0
        features['Bwd IAT Min']                 = 0.0
        features['Fwd Header Length']           = float(packet[IP].ihl * 4)
        features['Bwd Header Length']           = 0.0
        features['Fwd Packets/s']               = 1.0
        features['Bwd Packets/s']               = 0.0
        features['Min Packet Length']           = float(len(packet))
        features['Max Packet Length']           = float(len(packet))
        features['Packet Length Mean']          = float(len(packet))
        features['Packet Length Std']           = 0.0
        features['Packet Length Variance']      = 0.0
        if TCP in packet:
            flags = packet[TCP].flags
            features['FIN Flag Count']          = 1.0 if flags & 0x01 else 0.0
            features['PSH Flag Count']          = 1.0 if flags & 0x08 else 0.0
            features['ACK Flag Count']          = 1.0 if flags & 0x10 else 0.0
            features['Init_Win_bytes_forward']  = float(packet[TCP].window)
            features['Init_Win_bytes_backward'] = 0.0
        else:
            features['FIN Flag Count']          = 0.0
            features['PSH Flag Count']          = 0.0
            features['ACK Flag Count']          = 0.0
            features['Init_Win_bytes_forward']  = 0.0
            features['Init_Win_bytes_backward'] = 0.0
        features['Average Packet Size']         = float(len(packet))
        features['Subflow Fwd Bytes']           = float(len(packet))
        features['act_data_pkt_fwd']            = 1.0
        features['min_seg_size_forward']        = 0.0
        features['Active Mean']                 = 0.0
        features['Active Max']                  = 0.0
        features['Active Min']                  = 0.0
        features['Idle Mean']                   = 0.0
        features['Idle Max']                    = 0.0
        features['Idle Min']                    = 0.0
    return [features[f] for f in feature_names]

# ── 7. Packet processor ───────────────────────────────────────────────────────
def process_packet(packet):
    if IP not in packet:
        return
    try:
        features        = extract_features(packet)
        features_scaled = scaler.transform([features])
        prediction      = model.predict(features_scaled)[0]
        label           = le.inverse_transform([prediction])[0]
        src_ip          = packet[IP].src
        dst_ip          = packet[IP].dst
        proto           = 'TCP' if TCP in packet else 'UDP' if UDP in packet else 'Other'
        ts              = time.strftime('%H:%M:%S')

        if TCP in packet:
            with port_tracker_lock:
                port_tracker[src_ip].add(packet[TCP].dport)
                if len(port_tracker[src_ip]) >= 10:
                    label = 'Port Scanning'

        if len(packet) > 1000 and label == 'Normal Traffic':
            label = 'DoS'

        with alerts_lock:
            stats[label] += 1
            if label != 'Normal Traffic':
                location = get_geo(src_ip)
                alert = {
                    'time':     ts,
                    'src':      src_ip,
                    'dst':      dst_ip,
                    'proto':    proto,
                    'label':    label,
                    'length':   len(packet),
                    'location': location
                }
                alerts.append(alert)
                if len(alerts) > 100:
                    alerts.pop(0)
                ip_attack_count = sum(1 for a in alerts if a['src'] == src_ip)
                if ip_attack_count >= 3:
                    blocked_ips.add(src_ip)
                print(f"[ALERT] {ts} | {label} | {src_ip} ({location}) -> {dst_ip} | {proto}")
                if EMAIL_ENABLED:
                    threading.Thread(target=send_email_alert, args=(label, src_ip), daemon=True).start()

    except Exception:
        pass

# ── 8. Sniffer thread ─────────────────────────────────────────────────────────
def run_sniffer():
    print("Starting packet capture on wlan0...")
    sniff(iface='wlan0', prn=process_packet, store=False)

# ── 9. Dashboard HTML ─────────────────────────────────────────────────────────
HTML = '''
<!DOCTYPE html>
<html data-theme="dark">
<head>
  <title>IDS Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    :root[data-theme="dark"] {
      --bg:        #0f0f0f;
      --bg2:       #1a1a1a;
      --bg3:       #222;
      --border:    #333;
      --text:      #e0e0e0;
      --muted:     #888;
      --accent:    #00ff99;
      --accent2:   #00ccff;
      --alert-red: #ff4444;
    }
    :root[data-theme="light"] {
      --bg:        #f0f2f5;
      --bg2:       #ffffff;
      --bg3:       #e8eaed;
      --border:    #ddd;
      --text:      #1a1a1a;
      --muted:     #666;
      --accent:    #00aa66;
      --accent2:   #0077bb;
      --alert-red: #cc2222;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; transition: background 0.3s, color 0.3s; }
    body { font-family: Arial, sans-serif; background: var(--bg); color: var(--text); padding: 20px; }

    .header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px; }
    h1 { color: var(--accent); font-size: 22px; }
    .subtitle { color: var(--muted); font-size: 11px; margin-bottom: 20px; }
    .toggle-btn { background: var(--bg2); border: 1px solid var(--border); color: var(--text);
                  padding: 6px 14px; border-radius: 20px; cursor: pointer; font-size: 12px; }
    .toggle-btn:hover { border-color: var(--accent); }

    .threat-bar { display: flex; align-items: center; gap: 16px; background: var(--bg2);
                  border: 1px solid var(--border); border-radius: 10px; padding: 12px 20px;
                  margin-bottom: 20px; }
    .threat-label { font-size: 12px; color: var(--muted); min-width: 80px; }
    .threat-value { font-size: 22px; font-weight: bold; min-width: 100px; }
    .threat-LOW      { color: #00ff99; }
    .threat-MEDIUM   { color: #ffaa00; }
    .threat-HIGH     { color: #ff6600; }
    .threat-CRITICAL { color: #ff0000; animation: blink 0.8s infinite; }
    @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.4} }
    .threat-desc { font-size: 12px; color: var(--muted); }
    .threat-dots { display: flex; gap: 6px; margin-left: auto; }
    .threat-dot { width: 18px; height: 18px; border-radius: 50%; background: var(--border); }
    .threat-dot.active-LOW      { background: #00ff99; }
    .threat-dot.active-MEDIUM   { background: #ffaa00; }
    .threat-dot.active-HIGH     { background: #ff6600; }
    .threat-dot.active-CRITICAL { background: #ff0000; }

    h2 { color: var(--accent2); border-bottom: 1px solid var(--border);
         padding-bottom: 6px; margin: 20px 0 12px; font-size: 15px; }
    .stats { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 16px; }
    .stat-card { background: var(--bg2); border: 1px solid var(--border); border-radius: 8px;
                 padding: 12px 18px; min-width: 120px; text-align: center; }
    .stat-card .num  { font-size: 24px; font-weight: bold; color: var(--accent); }
    .stat-card .name { font-size: 11px; color: var(--muted); margin-top: 4px; }

    .charts-row { display: flex; gap: 20px; flex-wrap: wrap; margin-bottom: 24px; }
    .chart-box { background: var(--bg2); border: 1px solid var(--border); border-radius: 10px;
                 padding: 16px; width: 350px; max-width: 100%; }
    .chart-box h3 { color: var(--accent2); font-size: 12px; margin-bottom: 10px; }
    .chart-box canvas { width: 318px !important; height: 318px !important; }

    .sys-row { display: flex; align-items: center; gap: 10px; }
    .sys-label { font-size: 11px; color: var(--muted); min-width: 80px; }
    .sys-bar-wrap { flex: 1; height: 8px; background: var(--bg3); border-radius: 4px; overflow: hidden; }
    .sys-bar { height: 8px; border-radius: 4px; background: #00ff99;
               width: 0%; transition: width 0.8s ease; }
    .sys-bar-ram { background: #00ccff; }
    .sys-bar.warn { background: #ffaa00; }
    .sys-bar.crit { background: #ff4444; }
    .sys-val { font-size: 12px; color: var(--text); min-width: 55px; text-align: right; font-family: monospace; }
    .sys-divider { border: none; border-top: 1px solid var(--border); }
    .sys-stat-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
    .sys-stat { background: var(--bg3); border-radius: 8px; padding: 10px; text-align: center; }
    .sys-stat-val  { font-size: 20px; font-weight: bold; color: var(--accent); }
    .sys-stat-name { font-size: 10px; color: var(--muted); margin-top: 3px; }

    .blocked-list { display: flex; flex-wrap: wrap; gap: 8px; }
    .blocked-ip { background: #3a0000; border: 1px solid #aa0000; color: #ff6666;
                  border-radius: 6px; padding: 5px 12px; font-size: 12px; font-family: monospace; }
    [data-theme="light"] .blocked-ip { background: #ffe0e0; border-color: #cc2222; color: #aa0000; }
    .no-blocked { color: var(--muted); font-size: 13px; padding: 8px 0; }

    .col-head { display: grid;
                grid-template-columns: 65px 130px 1fr 55px 70px 120px;
                gap: 8px; font-size: 11px; color: var(--muted); padding: 0 16px 6px; }
    .alert-row { background: var(--bg2); border-left: 4px solid var(--alert-red);
                 margin-bottom: 5px; padding: 9px 16px; border-radius: 4px;
                 display: grid; grid-template-columns: 65px 130px 1fr 55px 70px 120px;
                 gap: 8px; font-size: 12px; align-items: center; }
    .alert-row span { color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .alert-row .lbl { color: var(--alert-red); font-weight: bold; }
    .alert-row .loc { color: #ffaa44; }
    .none { color: var(--muted); text-align: center; padding: 30px; font-size: 13px; }
    .badge { display: inline-block; background: var(--alert-red); color: white;
             border-radius: 10px; padding: 1px 8px; font-size: 11px; margin-left: 8px; }

    #status { position: fixed; top: 14px; right: 20px; font-size: 11px; color: var(--muted); }
    .dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%;
           background: var(--accent); margin-right: 4px; animation: pulse 1.5s infinite; }
    @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.3} }
  </style>
</head>
<body>
  <div id="status"><span class="dot"></span>Live</div>

  <div class="header">
    <div>
      <h1>IDS Dashboard</h1>
      <p class="subtitle">Raspberry Pi — Real-time Network Intrusion Detection</p>
    </div>
    <button class="toggle-btn" onclick="toggleTheme()">Light / Dark</button>
  </div>

  <div class="threat-bar">
    <div class="threat-label">Threat Level</div>
    <div class="threat-value" id="threat-value">LOW</div>
    <div class="threat-desc" id="threat-desc">Network activity normal</div>
    <div class="threat-dots">
      <div class="threat-dot" id="dot-LOW"      title="LOW"></div>
      <div class="threat-dot" id="dot-MEDIUM"   title="MEDIUM"></div>
      <div class="threat-dot" id="dot-HIGH"     title="HIGH"></div>
      <div class="threat-dot" id="dot-CRITICAL" title="CRITICAL"></div>
    </div>
  </div>

  <h2>Traffic Summary</h2>
  <div class="stats" id="stats-container"></div>

  <div class="charts-row">
    <div class="chart-box">
      <h3>Traffic Distribution</h3>
      <canvas id="pieChart"></canvas>
    </div>
    <div class="chart-box">
      <h3>Attack Frequency</h3>
      <canvas id="barChart"></canvas>
    </div>
    <div class="chart-box" style="display:flex; flex-direction:column; gap:12px;">
      <h3>System Info — Raspberry Pi</h3>
      <div class="sys-row">
        <span class="sys-label">CPU Usage</span>
        <div class="sys-bar-wrap"><div class="sys-bar" id="cpu-bar"></div></div>
        <span class="sys-val" id="cpu-val">--%</span>
      </div>
      <div class="sys-row">
        <span class="sys-label">RAM Usage</span>
        <div class="sys-bar-wrap"><div class="sys-bar sys-bar-ram" id="ram-bar"></div></div>
        <span class="sys-val" id="ram-val">-- MB</span>
      </div>
      <div class="sys-divider"></div>
      <div class="sys-stat-grid">
        <div class="sys-stat">
          <div class="sys-stat-val" id="cpu-num">--</div>
          <div class="sys-stat-name">CPU %</div>
        </div>
        <div class="sys-stat">
          <div class="sys-stat-val" id="ram-num">--</div>
          <div class="sys-stat-name">RAM %</div>
        </div>
        <div class="sys-stat">
          <div class="sys-stat-val" id="ram-mb">--</div>
          <div class="sys-stat-name">RAM Used</div>
        </div>
        <div class="sys-stat">
          <div class="sys-stat-val" id="uptime">--</div>
          <div class="sys-stat-name">Uptime</div>
        </div>
      </div>
      <div class="sys-divider"></div>
      <div style="font-size:11px; color:var(--muted); text-align:center;">
        Raspberry Pi 4B &nbsp;|&nbsp; wlan0 &nbsp;|&nbsp; Random Forest IDS
      </div>
    </div>
  </div>

  <h2>Blocked IPs <span class="badge" id="blocked-count">0</span></h2>
  <div class="blocked-list" id="blocked-container">
    <div class="no-blocked">No IPs blocked yet.</div>
  </div>

  <h2>Recent Alerts <span class="badge" id="alert-count">0</span></h2>
  <div class="col-head">
    <span>Time</span><span>Attack Type</span><span>Source → Dest</span>
    <span>Proto</span><span>Size</span><span>Location</span>
  </div>
  <div id="alerts-container"><div class="none">No attacks detected yet.</div></div>

  <script>
    const COLORS = {
      'Normal Traffic': '#00ff99',
      'Port Scanning':  '#ffaa00',
      'DoS':            '#ff4444',
      'DDoS':           '#ff0088',
      'Brute Force':    '#aa44ff',
      'Web Attacks':    '#00ccff',
      'Bots':           '#ff8800'
    };

    const THREAT_LEVELS = {
      LOW:      { desc: 'Network activity normal',      dots: 1 },
      MEDIUM:   { desc: 'Suspicious activity detected', dots: 2 },
      HIGH:     { desc: 'Active attack in progress',    dots: 3 },
      CRITICAL: { desc: 'Multiple attacks detected!',   dots: 4 }
    };

    function getThreatLevel(stats) {
      const attacks = Object.entries(stats)
        .filter(([k]) => k !== 'Normal Traffic')
        .reduce((a, [,v]) => a + v, 0);
      if (attacks === 0)   return 'LOW';
      if (attacks < 20)    return 'MEDIUM';
      if (attacks < 100)   return 'HIGH';
      return 'CRITICAL';
    }

    function updateThreat(level) {
      const tv = document.getElementById('threat-value');
      tv.textContent = level;
      tv.className = 'threat-value threat-' + level;
      document.getElementById('threat-desc').textContent = THREAT_LEVELS[level].desc;
      const levels = ['LOW','MEDIUM','HIGH','CRITICAL'];
      const active = THREAT_LEVELS[level].dots;
      levels.forEach((l, i) => {
        const dot = document.getElementById('dot-' + l);
        dot.className = 'threat-dot' + (i < active ? ' active-' + level : '');
      });
    }

    const isDark = () => document.documentElement.getAttribute('data-theme') === 'dark';

    function toggleTheme() {
      const t = isDark() ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', t);
      updateChartColors();
    }

    function chartTextColor() { return isDark() ? '#aaa' : '#444'; }
    function chartGridColor()  { return isDark() ? '#222' : '#ddd'; }

    const pieChart = new Chart(document.getElementById('pieChart').getContext('2d'), {
      type: 'pie',
      data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderWidth: 1,
              borderColor: isDark() ? '#0f0f0f' : '#f0f2f5' }] },
      options: {
        plugins: { legend: { position: 'bottom',
          labels: { color: chartTextColor(), font: { size: 10 }, padding: 8 } } },
        maintainAspectRatio: true
      }
    });

    const barChart = new Chart(document.getElementById('barChart').getContext('2d'), {
      type: 'bar',
      data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderRadius: 4 }] },
      options: {
        plugins: { legend: { display: false } },
        scales: {
          x: {
            ticks: { color: chartTextColor(), font: { size: 10 } },
            grid:  { color: chartGridColor() }
          },
          y: {
            ticks: {
              color: chartTextColor(),
              font: { size: 11 },
              stepSize: 25,
              callback: val => val % 25 === 0 ? val : ''
            },
            grid: { color: chartGridColor() },
            beginAtZero: true,
            suggestedMax: 100
          }
        },
        maintainAspectRatio: true
      }
    });

    function updateChartColors() {
      pieChart.data.datasets[0].borderColor = isDark() ? '#0f0f0f' : '#f0f2f5';
      pieChart.options.plugins.legend.labels.color = chartTextColor();
      barChart.options.scales.x.ticks.color = chartTextColor();
      barChart.options.scales.x.grid.color  = chartGridColor();
      barChart.options.scales.y.ticks.color = chartTextColor();
      barChart.options.scales.y.grid.color  = chartGridColor();
      pieChart.update();
      barChart.update();
    }

    function refresh() {
      fetch('/api/alerts')
        .then(r => r.json())
        .then(data => {
          document.getElementById('stats-container').innerHTML =
            Object.entries(data.stats)
              .map(([k,v]) => `<div class="stat-card"><div class="num">${v}</div><div class="name">${k}</div></div>`)
              .join('');

          updateThreat(getThreatLevel(data.stats));

          const labels = Object.keys(data.stats);
          pieChart.data.labels = labels;
          pieChart.data.datasets[0].data = Object.values(data.stats);
          pieChart.data.datasets[0].backgroundColor = labels.map(l => COLORS[l] || '#888');
          pieChart.update();

          const attackStats = Object.fromEntries(
            Object.entries(data.stats).filter(([k]) => k !== 'Normal Traffic')
          );
          const bLabels = Object.keys(attackStats);
          barChart.data.labels = bLabels;
          barChart.data.datasets[0].data = Object.values(attackStats);
          barChart.data.datasets[0].backgroundColor = bLabels.map(l => COLORS[l] || '#888');
          barChart.update();

          const bc = document.getElementById('blocked-container');
          document.getElementById('blocked-count').textContent = data.blocked.length;
          bc.innerHTML = data.blocked.length === 0
            ? '<div class="no-blocked">No IPs blocked yet.</div>'
            : data.blocked.map(ip => `<div class="blocked-ip">⛔ ${ip}</div>`).join('');

          document.getElementById('alert-count').textContent = data.alerts.length;

          const ac = document.getElementById('alerts-container');
          ac.innerHTML = data.alerts.length === 0
            ? '<div class="none">No attacks detected yet.</div>'
            : [...data.alerts].reverse().map(a => `
                <div class="alert-row">
                  <span>${a.time}</span>
                  <span class="lbl">${a.label}</span>
                  <span>${a.src} → ${a.dst}</span>
                  <span>${a.proto}</span>
                  <span>${a.length}B</span>
                  <span class="loc">${a.location || 'Local'}</span>
                </div>`).join('');
        });

      fetch('/api/system')
        .then(r => r.json())
        .then(s => {
          const cpuBar = document.getElementById('cpu-bar');
          cpuBar.style.width = s.cpu + '%';
          cpuBar.className = 'sys-bar' + (s.cpu > 80 ? ' crit' : s.cpu > 50 ? ' warn' : '');
          document.getElementById('ram-bar').style.width  = s.ram_percent + '%';
          document.getElementById('cpu-val').textContent  = s.cpu + '%';
          document.getElementById('ram-val').textContent  = s.ram_used + ' MB / ' + s.ram_total + ' MB';
          document.getElementById('cpu-num').textContent  = s.cpu + '%';
          document.getElementById('ram-num').textContent  = s.ram_percent + '%';
          document.getElementById('ram-mb').textContent   = s.ram_used + 'MB';
          document.getElementById('uptime').textContent   = s.uptime;
        });
    }

    refresh();
    setInterval(refresh, 3000);
  </script>
</body>
</html>
'''

# ── 10. Routes ────────────────────────────────────────────────────────────────
@app.route('/')
def dashboard():
    return render_template_string(HTML)

@app.route('/api/alerts')
def api_alerts():
    with alerts_lock:
        return jsonify({
            'alerts':  list(alerts),
            'stats':   dict(stats),
            'blocked': list(blocked_ips)
        })

@app.route('/api/system')
def api_system():
    cpu    = psutil.cpu_percent(interval=0.5)
    ram    = psutil.virtual_memory()
    uptime = int(time.time() - psutil.boot_time())
    hours, rem = divmod(uptime, 3600)
    mins,  sec = divmod(rem, 60)
    return jsonify({
        'cpu':         cpu,
        'ram_used':    round(ram.used  / 1024 / 1024),
        'ram_total':   round(ram.total / 1024 / 1024),
        'ram_percent': ram.percent,
        'uptime':      f'{hours:02d}:{mins:02d}:{sec:02d}'
    })

# ── 11. Start ─────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    t = threading.Thread(target=run_sniffer, daemon=True)
    t.start()
    print("Dashboard running at http://192.168.0.43:5000")
    app.run(host='0.0.0.0', port=5000, debug=False)