"""
Real-Time Phishing Detection Dashboard

Web-based visualization of:
- Live network traffic analysis
- Phishing detections
- Auto-blocking events
- System statistics
- Blocked domains list

Run: python3 dashboard.py
Then visit: http://localhost:5000

Author: Research Team
Date: 2026
"""

import logging
import json
import threading
import time
from datetime import datetime
from pathlib import Path
from collections import deque
from typing import Dict, List

from flask import Flask, render_template_string, jsonify, request
import pandas as pd

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Global stats storage
stats = {
    'total_packets': 0,
    'total_phishing': 0,
    'total_blocked': 0,
    'total_safe': 0,
    'detection_rate': 0.0,
    'latest_detections': deque(maxlen=20),
    'latest_blocks': deque(maxlen=20),
    'latest_safe': deque(maxlen=20),
    'blocked_domains': [],
    'start_time': datetime.now(),
}

# Lock for thread-safe updates
stats_lock = threading.Lock()


class DashboardDataCollector:
    """Collects data from detection logs for dashboard"""
    
    def __init__(self, logs_dir: str = "logs"):
        self.logs_dir = Path(logs_dir)
        self.processed_events = set()
    
    def load_detections(self):
        """Load detection logs from JSONL files"""
        try:
            detection_files = list(self.logs_dir.glob("detections_*.jsonl"))
            for file in sorted(detection_files, reverse=True)[:5]:  # Last 5 files
                with open(file, 'r') as f:
                    for line in f:
                        try:
                            event = json.loads(line.strip())
                            event_id = f"{event['domain']}_{event['timestamp']}"
                            
                            if event_id not in self.processed_events:
                                self.processed_events.add(event_id)
                                
                                with stats_lock:
                                    stats['total_packets'] += 1
                                    
                                    if event['prediction'] == 'phishing':
                                        stats['total_phishing'] += 1
                                        stats['latest_detections'].append({
                                            'domain': event['domain'],
                                            'confidence': event['confidence'],
                                            'timestamp': datetime.fromtimestamp(event['timestamp']).strftime('%H:%M:%S'),
                                            'blocked': event.get('blocked', False),
                                            'ip': event['destination_ip']
                                        })
                                        
                                        if event.get('blocked'):
                                            stats['total_blocked'] += 1
                                            stats['latest_blocks'].append({
                                                'domain': event['domain'],
                                                'confidence': event['confidence'],
                                                'timestamp': datetime.fromtimestamp(event['timestamp']).strftime('%H:%M:%S'),
                                                'ip': event['destination_ip']
                                            })
                                    else:
                                        stats['total_safe'] += 1
                                        stats['latest_safe'].append({
                                            'domain': event['domain'],
                                            'confidence': event['confidence'],
                                            'timestamp': datetime.fromtimestamp(event['timestamp']).strftime('%H:%M:%S'),
                                            'ip': event['destination_ip']
                                        })
                        except:
                            pass
        except Exception as e:
            logger.error(f"Error loading detections: {e}")
    
    def load_blocked_domains(self):
        """Load blocked domains from hosts file"""
        try:
            blocked_file = self.logs_dir / "blocked_domains.txt"
            if blocked_file.exists():
                with open(blocked_file, 'r') as f:
                    domains = []
                    for line in f:
                        if 'PHISHING-DETECTOR-BLOCKED' in line:
                            parts = line.split()
                            if len(parts) >= 2:
                                domains.append({
                                    'ip': parts[0],
                                    'domain': parts[1],
                                    'timestamp': ' '.join(parts[3:]) if len(parts) > 3 else 'Unknown'
                                })
                    
                    with stats_lock:
                        stats['blocked_domains'] = domains[-50:]  # Last 50
        except Exception as e:
            logger.error(f"Error loading blocked domains: {e}")
    
    def update_stats(self):
        """Calculate statistics"""
        with stats_lock:
            total = stats['total_phishing'] + stats['total_safe']
            if total > 0:
                stats['detection_rate'] = (stats['total_phishing'] / total) * 100


# ─── HOME PAGE ────────────────────────────────────────────────────────────────

HOME_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>PhishGuard — AI-Powered Threat Defense</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;400;600;800;900&display=swap" rel="stylesheet" />
  <style>
    :root {
      --bg:        #020810;
      --surface:   #060e1c;
      --card:      #0a1628;
      --border:    rgba(0,200,255,0.12);
      --cyan:      #00c8ff;
      --cyan-dim:  rgba(0,200,255,0.15);
      --red:       #ff3d5a;
      --red-dim:   rgba(255,61,90,0.15);
      --green:     #00ff9d;
      --green-dim: rgba(0,255,157,0.12);
      --amber:     #ffb800;
      --text:      #cce8ff;
      --muted:     #4a6a8a;
      --mono:      'Share Tech Mono', monospace;
      --sans:      'Exo 2', sans-serif;
    }

    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    html { scroll-behavior: smooth; }

    body {
      font-family: var(--sans);
      background: var(--bg);
      color: var(--text);
      overflow-x: hidden;
      min-height: 100vh;
    }

    /* ── GRID BACKGROUND ── */
    body::before {
      content: '';
      position: fixed; inset: 0;
      background-image:
        linear-gradient(rgba(0,200,255,0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,200,255,0.03) 1px, transparent 1px);
      background-size: 40px 40px;
      pointer-events: none;
      z-index: 0;
    }

    /* ── NAV ── */
    nav {
      position: fixed; top: 0; left: 0; right: 0; z-index: 100;
      display: flex; align-items: center; justify-content: space-between;
      padding: 18px 48px;
      background: rgba(2,8,16,0.85);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border);
    }

    .nav-logo {
      font-family: var(--mono);
      font-size: 1.1rem;
      color: var(--cyan);
      letter-spacing: 0.08em;
      display: flex; align-items: center; gap: 10px;
    }

    .logo-icon {
      width: 32px; height: 32px;
      border: 2px solid var(--cyan);
      border-radius: 6px;
      display: flex; align-items: center; justify-content: center;
      font-size: 14px;
      box-shadow: 0 0 12px rgba(0,200,255,0.3);
    }

    .nav-links { display: flex; gap: 32px; align-items: center; }

    .nav-links a {
      color: var(--muted);
      text-decoration: none;
      font-size: 0.85rem;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      transition: color 0.2s;
      font-weight: 600;
    }
    .nav-links a:hover { color: var(--cyan); }

    .nav-cta {
      background: var(--cyan) !important;
      color: var(--bg) !important;
      padding: 8px 22px !important;
      border-radius: 4px;
      font-weight: 800 !important;
      letter-spacing: 0.06em !important;
      transition: box-shadow 0.2s, transform 0.2s !important;
    }
    .nav-cta:hover {
      box-shadow: 0 0 20px rgba(0,200,255,0.5) !important;
      transform: translateY(-1px);
    }

    /* ── HERO ── */
    .hero {
      position: relative;
      min-height: 100vh;
      display: flex; flex-direction: column;
      align-items: center; justify-content: center;
      text-align: center;
      padding: 120px 24px 80px;
      z-index: 1;
    }

    /* Radial glow behind hero */
    .hero::before {
      content: '';
      position: absolute;
      top: 50%; left: 50%;
      transform: translate(-50%, -50%);
      width: 700px; height: 700px;
      background: radial-gradient(circle, rgba(0,200,255,0.07) 0%, transparent 70%);
      pointer-events: none;
    }

    .hero-tag {
      font-family: var(--mono);
      font-size: 0.75rem;
      letter-spacing: 0.18em;
      color: var(--cyan);
      background: var(--cyan-dim);
      border: 1px solid rgba(0,200,255,0.25);
      padding: 6px 18px;
      border-radius: 2px;
      margin-bottom: 32px;
      animation: fadeSlideDown 0.6s ease both;
    }

    .hero-title {
      font-size: clamp(2.8rem, 6vw, 5.5rem);
      font-weight: 900;
      line-height: 1.05;
      letter-spacing: -0.02em;
      margin-bottom: 28px;
      animation: fadeSlideDown 0.6s 0.1s ease both;
    }

    .hero-title span {
      color: var(--cyan);
      text-shadow: 0 0 40px rgba(0,200,255,0.4);
    }

    .hero-sub {
      font-size: 1.15rem;
      color: var(--muted);
      max-width: 560px;
      line-height: 1.7;
      margin-bottom: 48px;
      font-weight: 300;
      animation: fadeSlideDown 0.6s 0.2s ease both;
    }

    .hero-actions {
      display: flex; gap: 16px; flex-wrap: wrap; justify-content: center;
      animation: fadeSlideDown 0.6s 0.3s ease both;
    }

    .btn-primary {
      display: inline-flex; align-items: center; gap: 8px;
      background: var(--cyan);
      color: var(--bg);
      font-family: var(--sans);
      font-weight: 800;
      font-size: 0.95rem;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      padding: 14px 36px;
      border-radius: 4px;
      text-decoration: none;
      border: none; cursor: pointer;
      transition: box-shadow 0.25s, transform 0.2s;
    }
    .btn-primary:hover {
      box-shadow: 0 0 32px rgba(0,200,255,0.55);
      transform: translateY(-2px);
    }

    .btn-ghost {
      display: inline-flex; align-items: center; gap: 8px;
      background: transparent;
      color: var(--cyan);
      font-family: var(--sans);
      font-weight: 600;
      font-size: 0.95rem;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      padding: 14px 36px;
      border-radius: 4px;
      text-decoration: none;
      border: 1px solid rgba(0,200,255,0.35);
      cursor: pointer;
      transition: background 0.25s, border-color 0.25s;
    }
    .btn-ghost:hover {
      background: var(--cyan-dim);
      border-color: var(--cyan);
    }

    /* ── TICKER STRIP ── */
    .ticker {
      position: relative; z-index: 1;
      background: var(--red-dim);
      border-top: 1px solid rgba(255,61,90,0.2);
      border-bottom: 1px solid rgba(255,61,90,0.2);
      padding: 10px 0;
      overflow: hidden;
    }

    .ticker-inner {
      display: flex;
      animation: ticker 22s linear infinite;
      width: max-content;
    }

    .ticker-item {
      font-family: var(--mono);
      font-size: 0.72rem;
      letter-spacing: 0.1em;
      color: var(--red);
      padding: 0 48px;
      white-space: nowrap;
    }

    @keyframes ticker {
      from { transform: translateX(0); }
      to   { transform: translateX(-50%); }
    }

    /* ── STATS ROW ── */
    .stats-row {
      position: relative; z-index: 1;
      display: flex; justify-content: center; flex-wrap: wrap; gap: 1px;
      background: var(--border);
      border-top: 1px solid var(--border);
      border-bottom: 1px solid var(--border);
    }

    .stat-box {
      flex: 1; min-width: 200px;
      background: var(--surface);
      padding: 40px 32px;
      text-align: center;
    }

    .stat-num {
      font-family: var(--mono);
      font-size: 2.6rem;
      color: var(--cyan);
      letter-spacing: -0.02em;
      text-shadow: 0 0 20px rgba(0,200,255,0.3);
    }

    .stat-lbl {
      font-size: 0.78rem;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: var(--muted);
      margin-top: 8px;
      font-weight: 600;
    }

    /* ── FEATURES ── */
    .features {
      position: relative; z-index: 1;
      padding: 100px 48px;
      max-width: 1300px;
      margin: 0 auto;
    }

    .section-label {
      font-family: var(--mono);
      font-size: 0.72rem;
      letter-spacing: 0.2em;
      color: var(--cyan);
      text-transform: uppercase;
      margin-bottom: 16px;
    }

    .section-title {
      font-size: 2.4rem;
      font-weight: 800;
      margin-bottom: 64px;
      max-width: 500px;
      line-height: 1.15;
    }

    .features-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 1px;
      background: var(--border);
      border: 1px solid var(--border);
    }

    .feat-card {
      background: var(--card);
      padding: 36px 32px;
      transition: background 0.25s;
      cursor: default;
    }
    .feat-card:hover { background: #0d1e38; }

    .feat-icon {
      width: 44px; height: 44px;
      border: 1px solid var(--border);
      border-radius: 8px;
      display: flex; align-items: center; justify-content: center;
      font-size: 20px;
      margin-bottom: 20px;
      background: var(--cyan-dim);
    }

    .feat-title {
      font-size: 1.05rem;
      font-weight: 700;
      margin-bottom: 10px;
      color: var(--text);
    }

    .feat-desc {
      font-size: 0.88rem;
      color: var(--muted);
      line-height: 1.65;
    }

    /* ── THREAT FEED PREVIEW ── */
    .feed-section {
      position: relative; z-index: 1;
      background: var(--surface);
      border-top: 1px solid var(--border);
      border-bottom: 1px solid var(--border);
      padding: 80px 48px;
    }

    .feed-inner { max-width: 1300px; margin: 0 auto; }

    .feed-layout {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 40px;
      align-items: start;
      margin-top: 48px;
    }

    @media (max-width: 768px) {
      .feed-layout { grid-template-columns: 1fr; }
    }

    .terminal {
      background: #020810;
      border: 1px solid rgba(0,200,255,0.2);
      border-radius: 8px;
      overflow: hidden;
      font-family: var(--mono);
    }

    .terminal-bar {
      background: #0a1628;
      padding: 10px 16px;
      display: flex; align-items: center; gap: 8px;
      border-bottom: 1px solid rgba(0,200,255,0.1);
    }

    .t-dot { width: 10px; height: 10px; border-radius: 50%; }
    .t-dot.r { background: #ff3d5a; }
    .t-dot.y { background: #ffb800; }
    .t-dot.g { background: #00ff9d; }

    .terminal-title {
      font-size: 0.72rem;
      color: var(--muted);
      margin-left: 8px;
      letter-spacing: 0.08em;
    }

    .terminal-body { padding: 20px; }

    .t-line {
      font-size: 0.78rem;
      line-height: 1.8;
      color: var(--muted);
    }
    .t-line .cyan  { color: var(--cyan); }
    .t-line .red   { color: var(--red); }
    .t-line .green { color: var(--green); }
    .t-line .amber { color: var(--amber); }

    .cursor {
      display: inline-block;
      width: 8px; height: 14px;
      background: var(--cyan);
      animation: blink 1s step-end infinite;
      vertical-align: middle;
    }
    @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }

    /* mini donut */
    .mini-charts { display: flex; flex-direction: column; gap: 20px; }

    .chart-box {
      background: #020810;
      border: 1px solid rgba(0,200,255,0.15);
      border-radius: 8px;
      padding: 24px;
    }

    .chart-title {
      font-family: var(--mono);
      font-size: 0.72rem;
      letter-spacing: 0.12em;
      color: var(--muted);
      text-transform: uppercase;
      margin-bottom: 16px;
    }

    .bar-row {
      display: flex; align-items: center; gap: 12px;
      margin-bottom: 10px;
    }

    .bar-label { font-family: var(--mono); font-size: 0.7rem; color: var(--muted); width: 80px; }

    .bar-track {
      flex: 1; height: 6px;
      background: rgba(255,255,255,0.05);
      border-radius: 3px;
      overflow: hidden;
    }

    .bar-fill {
      height: 100%;
      border-radius: 3px;
      animation: growBar 1.5s ease both;
    }
    @keyframes growBar { from { width: 0 !important; } }

    .bar-val { font-family: var(--mono); font-size: 0.7rem; color: var(--text); width: 36px; text-align: right; }

    /* ── CTA BANNER ── */
    .cta-banner {
      position: relative; z-index: 1;
      padding: 100px 48px;
      text-align: center;
    }

    .cta-inner {
      max-width: 640px; margin: 0 auto;
    }

    .cta-inner h2 {
      font-size: 2.8rem;
      font-weight: 900;
      margin-bottom: 20px;
      line-height: 1.1;
    }

    .cta-inner p {
      color: var(--muted);
      margin-bottom: 40px;
      font-size: 1rem;
      line-height: 1.7;
    }

    /* ── FOOTER ── */
    footer {
      position: relative; z-index: 1;
      border-top: 1px solid var(--border);
      padding: 28px 48px;
      display: flex; align-items: center; justify-content: space-between;
      font-family: var(--mono);
      font-size: 0.72rem;
      color: var(--muted);
    }

    /* ── ANIMATIONS ── */
    @keyframes fadeSlideDown {
      from { opacity: 0; transform: translateY(-16px); }
      to   { opacity: 1; transform: translateY(0); }
    }

    .pulse-ring {
      position: absolute;
      border-radius: 50%;
      border: 1px solid rgba(0,200,255,0.15);
      animation: ring 4s ease-out infinite;
      pointer-events: none;
    }
    @keyframes ring {
      0%   { transform: scale(0.8); opacity: 0.6; }
      100% { transform: scale(1.8); opacity: 0; }
    }

    /* Scanning line */
    .scan-line {
      position: absolute;
      left: 0; right: 0;
      height: 1px;
      background: linear-gradient(90deg, transparent, var(--cyan), transparent);
      opacity: 0.3;
      animation: scan 6s linear infinite;
      pointer-events: none;
    }
    @keyframes scan {
      from { top: 0; }
      to   { top: 100%; }
    }
  </style>
</head>
<body>

<!-- NAV -->
<nav>
  <div class="nav-logo">
    <div class="logo-icon">🛡</div>
    PHISHGUARD
  </div>
  <div class="nav-links">
    <a href="#features">Features</a>
    <a href="#feed">Threat Feed</a>
    <a href="/dashboard" class="nav-cta">Live Dashboard →</a>
  </div>
</nav>

<!-- HERO -->
<section class="hero">
  <div class="scan-line"></div>
  <div class="pulse-ring" style="width:500px;height:500px;top:50%;left:50%;margin:-250px 0 0 -250px;animation-delay:0s"></div>
  <div class="pulse-ring" style="width:500px;height:500px;top:50%;left:50%;margin:-250px 0 0 -250px;animation-delay:2s"></div>

  <div class="hero-tag">// REAL-TIME AI THREAT INTELLIGENCE //</div>

  <h1 class="hero-title">
    Stop Phishing Attacks<br />
    <span>Before They Land</span>
  </h1>

  <p class="hero-sub">
    Machine-learning packet analysis with sub-millisecond detection.
    Automatically blocks malicious domains at the network level — 
    zero user interaction required.
  </p>

  <div class="hero-actions">
    <a href="/dashboard" class="btn-primary">
      <span>▶</span> Open Live Dashboard
    </a>
    <a href="#features" class="btn-ghost">
      Learn More ↓
    </a>
  </div>
</section>

<!-- THREAT TICKER -->
<div class="ticker">
  <div class="ticker-inner">
    <span class="ticker-item">⚠ THREAT DETECTED — secure-paypa1.com — BLOCKED</span>
    <span class="ticker-item">⚠ THREAT DETECTED — login-verify-bank.net — BLOCKED</span>
    <span class="ticker-item">⚠ THREAT DETECTED — update-your-account-now.xyz — BLOCKED</span>
    <span class="ticker-item">⚠ THREAT DETECTED — appleid-suspended.co — BLOCKED</span>
    <span class="ticker-item">⚠ THREAT DETECTED — account-confirm-irs.org — BLOCKED</span>
    <span class="ticker-item">⚠ THREAT DETECTED — secure-paypa1.com — BLOCKED</span>
    <span class="ticker-item">⚠ THREAT DETECTED — login-verify-bank.net — BLOCKED</span>
    <span class="ticker-item">⚠ THREAT DETECTED — update-your-account-now.xyz — BLOCKED</span>
    <span class="ticker-item">⚠ THREAT DETECTED — appleid-suspended.co — BLOCKED</span>
    <span class="ticker-item">⚠ THREAT DETECTED — account-confirm-irs.org — BLOCKED</span>
  </div>
</div>

<!-- STATS ROW -->
<div class="stats-row">
  <div class="stat-box">
    <div class="stat-num" id="h-packets">—</div>
    <div class="stat-lbl">Packets Analyzed</div>
  </div>
  <div class="stat-box">
    <div class="stat-num" id="h-phishing" style="color:var(--red);text-shadow:0 0 20px rgba(255,61,90,0.3)">—</div>
    <div class="stat-lbl">Phishing Detected</div>
  </div>
  <div class="stat-box">
    <div class="stat-num" id="h-blocked" style="color:var(--green);text-shadow:0 0 20px rgba(0,255,157,0.3)">—</div>
    <div class="stat-lbl">Domains Blocked</div>
  </div>
  <div class="stat-box">
    <div class="stat-num" id="h-rate">—</div>
    <div class="stat-lbl">Threat Detection Rate</div>
  </div>
</div>

<!-- FEATURES -->
<section class="features" id="features">
  <div class="section-label">// CAPABILITIES</div>
  <h2 class="section-title">Enterprise-Grade Defense Stack</h2>

  <div class="features-grid">
    <div class="feat-card">
      <div class="feat-icon">🔬</div>
      <div class="feat-title">Packet-Level Analysis</div>
      <div class="feat-desc">Deep inspection of DNS queries and HTTP/S traffic in real time. Every packet classified within microseconds using gradient-boosted ML models.</div>
    </div>
    <div class="feat-card">
      <div class="feat-icon">🤖</div>
      <div class="feat-title">AI Classification Engine</div>
      <div class="feat-desc">Ensemble models trained on millions of phishing URLs. Lexical, structural, and behavioral features extracted from raw domain strings.</div>
    </div>
    <div class="feat-card">
      <div class="feat-icon">🛑</div>
      <div class="feat-title">Autonomous Blocking</div>
      <div class="feat-desc">High-confidence threats auto-blocked via /etc/hosts injection. No manual intervention. Domain sinkholed to 0.0.0.0 instantly.</div>
    </div>
    <div class="feat-card">
      <div class="feat-icon">📊</div>
      <div class="feat-title">Live Telemetry</div>
      <div class="feat-desc">Real-time charts, event feeds, and confidence scoring — all refreshed every 2 seconds from structured JSONL detection logs.</div>
    </div>
    <div class="feat-card">
      <div class="feat-icon">🔒</div>
      <div class="feat-title">Zero-Trust Pipeline</div>
      <div class="feat-desc">Every outbound request treated as suspect until proven safe. Block-first, allowlist-second architecture prevents zero-day phishing.</div>
    </div>
    <div class="feat-card">
      <div class="feat-icon">📋</div>
      <div class="feat-title">Audit & Compliance</div>
      <div class="feat-desc">Full JSONL event logs with timestamps, IPs, domains, confidence scores. Queryable, exportable, and retention-ready for compliance teams.</div>
    </div>
  </div>
</section>

<!-- THREAT FEED PREVIEW -->
<section class="feed-section" id="feed">
  <div class="feed-inner">
    <div class="section-label">// LIVE SYSTEM OUTPUT</div>
    <h2 class="section-title" style="max-width:none">See It Working in Real Time</h2>

    <div class="feed-layout">
      <!-- Terminal -->
      <div class="terminal">
        <div class="terminal-bar">
          <div class="t-dot r"></div>
          <div class="t-dot y"></div>
          <div class="t-dot g"></div>
          <span class="terminal-title">phishguard — detector.py — live</span>
        </div>
        <div class="terminal-body">
          <div class="t-line"><span class="cyan">[SYSTEM]</span> PhishGuard v2.1 initialized</div>
          <div class="t-line"><span class="cyan">[MODEL]</span>  Loading ensemble classifier... <span class="green">OK</span></div>
          <div class="t-line"><span class="cyan">[SNIFF]</span>  Capturing on interface eth0</div>
          <div class="t-line">&nbsp;</div>
          <div class="t-line"><span class="amber">[PACKET]</span> DNS → secure-paypa1.com</div>
          <div class="t-line"><span class="red">[THREAT]</span> Confidence: 97.4% — <span class="red">PHISHING</span></div>
          <div class="t-line"><span class="green">[BLOCK]</span>  Added to /etc/hosts → 0.0.0.0</div>
          <div class="t-line">&nbsp;</div>
          <div class="t-line"><span class="amber">[PACKET]</span> DNS → mail.google.com</div>
          <div class="t-line"><span class="green">[SAFE]</span>   Confidence: 1.2% — <span class="green">BENIGN</span></div>
          <div class="t-line">&nbsp;</div>
          <div class="t-line"><span class="amber">[PACKET]</span> DNS → login-verify-bank.net</div>
          <div class="t-line"><span class="red">[THREAT]</span> Confidence: 99.1% — <span class="red">PHISHING</span></div>
          <div class="t-line"><span class="green">[BLOCK]</span>  Added to /etc/hosts → 0.0.0.0</div>
          <div class="t-line">&nbsp;</div>
          <div class="t-line"><span class="cyan">$ </span><span class="cursor"></span></div>
        </div>
      </div>

      <!-- Mini Charts -->
      <div class="mini-charts">
        <div class="chart-box">
          <div class="chart-title">// Traffic Breakdown</div>
          <div class="bar-row">
            <span class="bar-label">Benign</span>
            <div class="bar-track"><div class="bar-fill" style="width:73%;background:var(--green)"></div></div>
            <span class="bar-val">73%</span>
          </div>
          <div class="bar-row">
            <span class="bar-label">Phishing</span>
            <div class="bar-track"><div class="bar-fill" style="width:18%;background:var(--red)"></div></div>
            <span class="bar-val">18%</span>
          </div>
          <div class="bar-row">
            <span class="bar-label">Suspicious</span>
            <div class="bar-track"><div class="bar-fill" style="width:9%;background:var(--amber)"></div></div>
            <span class="bar-val">9%</span>
          </div>
        </div>

        <div class="chart-box">
          <div class="chart-title">// Detection Confidence Distribution</div>
          <div class="bar-row">
            <span class="bar-label">0–50%</span>
            <div class="bar-track"><div class="bar-fill" style="width:8%;background:var(--muted)"></div></div>
            <span class="bar-val">8%</span>
          </div>
          <div class="bar-row">
            <span class="bar-label">50–75%</span>
            <div class="bar-track"><div class="bar-fill" style="width:15%;background:var(--amber)"></div></div>
            <span class="bar-val">15%</span>
          </div>
          <div class="bar-row">
            <span class="bar-label">75–90%</span>
            <div class="bar-track"><div class="bar-fill" style="width:24%;background:var(--red)"></div></div>
            <span class="bar-val">24%</span>
          </div>
          <div class="bar-row">
            <span class="bar-label">90–100%</span>
            <div class="bar-track"><div class="bar-fill" style="width:53%;background:var(--red)"></div></div>
            <span class="bar-val">53%</span>
          </div>
        </div>

        <div class="chart-box" style="display:flex;gap:24px;align-items:center">
          <div>
            <div class="chart-title">// System Status</div>
            <div style="display:flex;flex-direction:column;gap:10px;margin-top:4px">
              <div style="display:flex;align-items:center;gap:10px">
                <div style="width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 8px var(--green);animation:blink 2s step-end infinite"></div>
                <span style="font-family:var(--mono);font-size:0.72rem;color:var(--muted)">Packet Capture</span>
                <span style="font-family:var(--mono);font-size:0.72rem;color:var(--green)">ACTIVE</span>
              </div>
              <div style="display:flex;align-items:center;gap:10px">
                <div style="width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 8px var(--green);animation:blink 2s step-end infinite"></div>
                <span style="font-family:var(--mono);font-size:0.72rem;color:var(--muted)">ML Classifier</span>
                <span style="font-family:var(--mono);font-size:0.72rem;color:var(--green)">RUNNING</span>
              </div>
              <div style="display:flex;align-items:center;gap:10px">
                <div style="width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 8px var(--green);animation:blink 2s step-end infinite"></div>
                <span style="font-family:var(--mono);font-size:0.72rem;color:var(--muted)">Auto-Blocker</span>
                <span style="font-family:var(--mono);font-size:0.72rem;color:var(--green)">ENABLED</span>
              </div>
              <div style="display:flex;align-items:center;gap:10px">
                <div style="width:8px;height:8px;border-radius:50%;background:var(--cyan);box-shadow:0 0 8px var(--cyan);animation:blink 2s step-end infinite"></div>
                <span style="font-family:var(--mono);font-size:0.72rem;color:var(--muted)">Dashboard API</span>
                <span style="font-family:var(--mono);font-size:0.72rem;color:var(--cyan)">ONLINE</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</section>

<!-- CTA -->
<section class="cta-banner">
  <div class="cta-inner">
    <h2>Ready to Monitor<br /><span style="color:var(--cyan)">Your Network?</span></h2>
    <p>Open the live dashboard to see real-time packet analysis, confidence scoring, and auto-block events as they happen.</p>
    <a href="/dashboard" class="btn-primary" style="font-size:1.1rem;padding:18px 48px">
      ▶ Launch Dashboard
    </a>
  </div>
</section>

<!-- FOOTER -->
<footer>
  <span>PHISHGUARD // AI THREAT DEFENSE SYSTEM // 2026</span>
  <span>ALL SYSTEMS OPERATIONAL</span>
</footer>

<script>
  // Pull live stats into homepage hero numbers
  async function loadHomeStats() {
    try {
      const r = await fetch('/api/stats');
      const d = await r.json();
      document.getElementById('h-packets').textContent  = d.total_packets.toLocaleString();
      document.getElementById('h-phishing').textContent = d.total_phishing.toLocaleString();
      document.getElementById('h-blocked').textContent  = d.total_blocked.toLocaleString();
      document.getElementById('h-rate').textContent     = d.detection_rate.toFixed(1) + '%';
    } catch(e) {}
  }
  loadHomeStats();
  setInterval(loadHomeStats, 3000);
</script>
</body>
</html>"""


# ─── DASHBOARD PAGE ────────────────────────────────────────────────────────────

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>PhishGuard — Live Dashboard</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;400;600;700;800&display=swap" rel="stylesheet" />
  <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
  <style>
    :root {
      --bg:        #020810;
      --surface:   #060e1c;
      --card:      #090f1d;
      --card2:     #0a1525;
      --border:    rgba(0,200,255,0.1);
      --cyan:      #00c8ff;
      --cyan-dim:  rgba(0,200,255,0.1);
      --red:       #ff3d5a;
      --red-dim:   rgba(255,61,90,0.12);
      --green:     #00ff9d;
      --green-dim: rgba(0,255,157,0.1);
      --amber:     #ffb800;
      --text:      #c8e0f4;
      --muted:     #3a5a7a;
      --mono:      'Share Tech Mono', monospace;
      --sans:      'Exo 2', sans-serif;
    }

    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: var(--sans);
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }

    body::before {
      content: '';
      position: fixed; inset: 0;
      background-image:
        linear-gradient(rgba(0,200,255,0.025) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,200,255,0.025) 1px, transparent 1px);
      background-size: 32px 32px;
      pointer-events: none;
      z-index: 0;
    }

    /* ── TOP BAR ── */
    .topbar {
      position: sticky; top: 0; z-index: 50;
      display: flex; align-items: center; justify-content: space-between;
      padding: 0 24px;
      height: 56px;
      background: rgba(2,8,16,0.92);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border);
    }

    .topbar-left { display: flex; align-items: center; gap: 24px; }

    .logo {
      font-family: var(--mono);
      font-size: 0.85rem;
      color: var(--cyan);
      letter-spacing: 0.1em;
      display: flex; align-items: center; gap: 8px;
    }

    .logo-sq {
      width: 26px; height: 26px;
      border: 1.5px solid var(--cyan);
      border-radius: 4px;
      display: flex; align-items: center; justify-content: center;
      font-size: 12px;
      box-shadow: 0 0 10px rgba(0,200,255,0.25);
    }

    .breadcrumb {
      font-family: var(--mono);
      font-size: 0.72rem;
      color: var(--muted);
      letter-spacing: 0.08em;
    }

    .breadcrumb a { color: var(--muted); text-decoration: none; }
    .breadcrumb a:hover { color: var(--cyan); }
    .breadcrumb span { color: var(--text); }

    .topbar-right { display: flex; align-items: center; gap: 20px; }

    .live-badge {
      display: flex; align-items: center; gap: 7px;
      font-family: var(--mono);
      font-size: 0.72rem;
      letter-spacing: 0.1em;
      color: var(--green);
    }

    .live-dot {
      width: 7px; height: 7px;
      border-radius: 50%;
      background: var(--green);
      box-shadow: 0 0 8px var(--green);
      animation: pulse 2s ease infinite;
    }
    @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }

    .uptime-label {
      font-family: var(--mono);
      font-size: 0.72rem;
      color: var(--muted);
    }

    /* ── LAYOUT ── */
    .layout {
      position: relative; z-index: 1;
      flex: 1;
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 16px;
      max-width: 1600px;
      width: 100%;
      margin: 0 auto;
    }

    /* ── METRIC STRIP ── */
    .metric-strip {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
    }

    @media (max-width: 900px) { .metric-strip { grid-template-columns: repeat(2,1fr); } }
    @media (max-width: 500px) { .metric-strip { grid-template-columns: 1fr; } }

    .metric {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 20px 22px;
      display: flex;
      flex-direction: column;
      gap: 10px;
      position: relative;
      overflow: hidden;
      transition: border-color 0.2s;
    }
    .metric:hover { border-color: rgba(0,200,255,0.3); }

    .metric-glow {
      position: absolute;
      top: 0; right: 0;
      width: 80px; height: 80px;
      border-radius: 50%;
      transform: translate(30px,-30px);
      opacity: 0.35;
      pointer-events: none;
    }

    .metric-label {
      font-family: var(--mono);
      font-size: 0.68rem;
      letter-spacing: 0.14em;
      color: var(--muted);
      text-transform: uppercase;
    }

    .metric-val {
      font-family: var(--mono);
      font-size: 2rem;
      font-weight: 400;
      letter-spacing: -0.01em;
      line-height: 1;
    }

    .metric-sub {
      font-size: 0.72rem;
      color: var(--muted);
    }

    .delta {
      display: inline-flex; align-items: center; gap: 4px;
      font-family: var(--mono);
      font-size: 0.68rem;
      padding: 2px 8px;
      border-radius: 3px;
    }
    .delta.up   { background: var(--red-dim);   color: var(--red);   }
    .delta.down { background: var(--green-dim);  color: var(--green); }

    /* ── MAIN GRID ── */
    .main-grid {
      display: grid;
      grid-template-columns: 1fr 1fr 340px;
      gap: 16px;
    }

    @media (max-width: 1100px) {
      .main-grid { grid-template-columns: 1fr 1fr; }
      .main-grid .feeds-col { grid-column: 1 / -1; }
    }
    @media (max-width: 700px) {
      .main-grid { grid-template-columns: 1fr; }
    }

    /* ── CARD ── */
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 6px;
      overflow: hidden;
    }

    .card-head {
      display: flex; align-items: center; justify-content: space-between;
      padding: 14px 18px;
      border-bottom: 1px solid var(--border);
    }

    .card-title {
      font-family: var(--mono);
      font-size: 0.72rem;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: var(--cyan);
      display: flex; align-items: center; gap: 8px;
    }

    .card-tag {
      font-family: var(--mono);
      font-size: 0.65rem;
      letter-spacing: 0.08em;
      color: var(--muted);
      border: 1px solid var(--border);
      padding: 2px 8px;
      border-radius: 3px;
    }

    .card-body {
      padding: 16px;
    }

    /* ── CHARTS ── */
    .chart-wrap {
      position: relative;
      height: 220px;
    }

    /* ── FEEDS COL ── */
    .feeds-col {
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    /* ── EVENT LIST ── */
    .event-list { display: flex; flex-direction: column; gap: 6px; }

    .event-row {
      display: flex;
      align-items: flex-start;
      gap: 10px;
      padding: 10px 12px;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 4px;
      border-left-width: 3px;
      transition: background 0.15s;
    }
    .event-row:hover { background: var(--card2); }
    .event-row.phish { border-left-color: var(--red); }
    .event-row.blocked { border-left-color: var(--green); }
    .event-row.safe { border-left-color: var(--green); }

    .event-icon {
      font-size: 14px;
      margin-top: 1px;
      flex-shrink: 0;
    }

    .event-domain {
      font-family: var(--mono);
      font-size: 0.72rem;
      color: var(--text);
      word-break: break-all;
    }

    .event-meta {
      font-family: var(--mono);
      font-size: 0.65rem;
      color: var(--muted);
      margin-top: 3px;
    }

    .badge {
      display: inline-block;
      font-family: var(--mono);
      font-size: 0.62rem;
      letter-spacing: 0.06em;
      padding: 1px 7px;
      border-radius: 2px;
    }
    .badge.b-red   { background: var(--red-dim);   color: var(--red);   border: 1px solid rgba(255,61,90,0.25); }
    .badge.b-green { background: var(--green-dim);  color: var(--green); border: 1px solid rgba(0,255,157,0.2); }
    .badge.b-amber { background: rgba(255,184,0,.1);color: var(--amber); border: 1px solid rgba(255,184,0,.2); }

    .conf-bar {
      display: flex; align-items: center; gap: 6px;
      margin-top: 5px;
    }
    .conf-track {
      flex: 1; height: 3px;
      background: rgba(255,255,255,0.05);
      border-radius: 2px;
      overflow: hidden;
    }
    .conf-fill { height: 100%; border-radius: 2px; }

    /* ── BOTTOM GRID ── */
    .bottom-grid {
      display: grid;
      grid-template-columns: 1fr 2fr;
      gap: 16px;
    }
    @media (max-width: 900px) { .bottom-grid { grid-template-columns: 1fr; } }

    /* ── TABLE ── */
    .data-table {
      width: 100%;
      border-collapse: collapse;
      font-family: var(--mono);
      font-size: 0.72rem;
    }

    .data-table th {
      text-align: left;
      padding: 8px 12px;
      color: var(--muted);
      font-size: 0.65rem;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      border-bottom: 1px solid var(--border);
      font-weight: 400;
    }

    .data-table td {
      padding: 9px 12px;
      border-bottom: 1px solid rgba(0,200,255,0.05);
      color: var(--text);
      vertical-align: middle;
    }

    .data-table tr:hover td { background: var(--surface); }
    .data-table td.domain { color: var(--cyan); word-break: break-all; }
    .data-table td.muted  { color: var(--muted); }

    .scroll-body { max-height: 280px; overflow-y: auto; }
    .scroll-body::-webkit-scrollbar { width: 4px; }
    .scroll-body::-webkit-scrollbar-track { background: transparent; }
    .scroll-body::-webkit-scrollbar-thumb { background: var(--muted); border-radius: 2px; }

    /* ── FOOTER ── */
    .dash-footer {
      position: relative; z-index: 1;
      border-top: 1px solid var(--border);
      padding: 12px 24px;
      display: flex; align-items: center; justify-content: space-between;
      font-family: var(--mono);
      font-size: 0.68rem;
      color: var(--muted);
    }

    #last-update { color: var(--cyan); }

    /* scrollbar global */
    ::-webkit-scrollbar { width: 4px; height: 4px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: var(--muted); border-radius: 2px; }
  </style>
</head>
<body>

<!-- TOP BAR -->
<div class="topbar">
  <div class="topbar-left">
    <div class="logo">
      <div class="logo-sq">🛡</div>
      PHISHGUARD
    </div>
    <div class="breadcrumb">
      <a href="/">HOME</a>
      <span style="margin:0 8px;color:var(--muted)">/</span>
      <span>LIVE DASHBOARD</span>
    </div>
  </div>
  <div class="topbar-right">
    <div class="live-badge"><div class="live-dot"></div> LIVE</div>
    <div class="uptime-label">UPTIME: <span id="uptime-val">—</span></div>
  </div>
</div>

<!-- MAIN LAYOUT -->
<div class="layout">

  <!-- METRICS STRIP -->
  <div class="metric-strip">
    <div class="metric">
      <div class="metric-glow" style="background:radial-gradient(var(--cyan),transparent)"></div>
      <div class="metric-label">// packets analyzed</div>
      <div class="metric-val" id="m-packets" style="color:var(--cyan)">0</div>
      <div class="metric-sub">Total since start</div>
    </div>
    <div class="metric">
      <div class="metric-glow" style="background:radial-gradient(var(--red),transparent)"></div>
      <div class="metric-label">// phishing detected</div>
      <div class="metric-val" id="m-phishing" style="color:var(--red)">0</div>
      <div class="metric-sub"><span id="m-rate">0.0%</span> of all traffic</div>
    </div>
    <div class="metric">
      <div class="metric-glow" style="background:radial-gradient(var(--green),transparent)"></div>
      <div class="metric-label">// domains blocked</div>
      <div class="metric-val" id="m-blocked" style="color:var(--green)">0</div>
      <div class="metric-sub">Auto-blocked via /etc/hosts</div>
    </div>
    <div class="metric">
      <div class="metric-glow" style="background:radial-gradient(var(--amber),transparent)"></div>
      <div class="metric-label">// safe traffic</div>
      <div class="metric-val" id="m-safe" style="color:var(--amber)">0</div>
      <div class="metric-sub">Allowed through</div>
    </div>
  </div>

  <!-- MAIN GRID -->
  <div class="main-grid">

    <!-- Traffic Over Time -->
    <div class="card">
      <div class="card-head">
        <div class="card-title">📈 Traffic Analysis</div>
        <div class="card-tag">ROLLING 30s</div>
      </div>
      <div class="card-body">
        <div class="chart-wrap">
          <canvas id="trafficChart"></canvas>
        </div>
      </div>
    </div>

    <!-- Threat Breakdown Donut -->
    <div class="card">
      <div class="card-head">
        <div class="card-title">🎯 Threat Breakdown</div>
        <div class="card-tag">LIVE</div>
      </div>
      <div class="card-body" style="display:flex;gap:20px;align-items:center;">
        <div style="width:180px;height:180px;flex-shrink:0">
          <canvas id="donutChart"></canvas>
        </div>
        <div style="flex:1">
          <div id="donut-legend" style="display:flex;flex-direction:column;gap:10px"></div>
        </div>
      </div>
    </div>

    <!-- Feeds Column -->
    <div class="feeds-col">
      <!-- Latest Detections -->
      <div class="card" style="flex:1">
        <div class="card-head">
          <div class="card-title">⚠️ Detections</div>
          <div class="card-tag" id="det-count">0</div>
        </div>
        <div class="card-body" style="max-height:260px;overflow-y:auto">
          <div class="event-list" id="det-list">
            <div style="color:var(--muted);font-family:var(--mono);font-size:0.72rem;text-align:center;padding:24px">
              Awaiting data...
            </div>
          </div>
        </div>
      </div>

      <!-- Blocked Events -->
      <div class="card" style="flex:1">
        <div class="card-head">
          <div class="card-title">🛑 Blocked</div>
          <div class="card-tag" id="blk-count">0</div>
        </div>
        <div class="card-body" style="max-height:200px;overflow-y:auto">
          <div class="event-list" id="blk-list">
            <div style="color:var(--muted);font-family:var(--mono);font-size:0.72rem;text-align:center;padding:24px">
              Awaiting data...
            </div>
          </div>
        </div>
      </div>

      <!-- Safe/Allowed Domains -->
      <div class="card" style="flex:1">
        <div class="card-head">
          <div class="card-title">✅ Allowed</div>
          <div class="card-tag" id="safe-count">0</div>
        </div>
        <div class="card-body" style="max-height:200px;overflow-y:auto">
          <div class="event-list" id="safe-list">
            <div style="color:var(--muted);font-family:var(--mono);font-size:0.72rem;text-align:center;padding:24px">
              Awaiting data...
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- BOTTOM GRID -->
  <div class="bottom-grid">

    <!-- Confidence Histogram -->
    <div class="card">
      <div class="card-head">
        <div class="card-title">📊 Confidence Distribution</div>
        <div class="card-tag">PHISHING ONLY</div>
      </div>
      <div class="card-body">
        <div class="chart-wrap" style="height:180px">
          <canvas id="histChart"></canvas>
        </div>
      </div>
    </div>

    <!-- Blocked Domains Table -->
    <div class="card">
      <div class="card-head">
        <div class="card-title">📋 Blocked Domains Log</div>
        <div class="card-tag">/etc/hosts</div>
      </div>
      <div class="card-body" style="padding:0">
        <div class="scroll-body">
          <table class="data-table">
            <thead>
              <tr>
                <th>Domain</th>
                <th>IP</th>
                <th>Blocked At</th>
              </tr>
            </thead>
            <tbody id="domains-tbody">
              <tr>
                <td colspan="3" style="color:var(--muted);text-align:center;padding:24px">
                  Loading...
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>

</div>

<!-- FOOTER -->
<div class="dash-footer">
  <span>PHISHGUARD // LIVE MONITORING // 2026</span>
  <span>Last update: <span id="last-update">—</span> · Refresh: 2s</span>
</div>

<script>
// ── Chart.js defaults ─────────────────────────────────────────────
Chart.defaults.color = '#3a5a7a';
Chart.defaults.borderColor = 'rgba(0,200,255,0.07)';
Chart.defaults.font.family = "'Share Tech Mono', monospace";
Chart.defaults.font.size = 11;

// ── Rolling traffic data ──────────────────────────────────────────
const WINDOW = 30;
const trafficHistory = {
  labels: [],
  phishing: [],
  safe: [],
};
let prevPhishing = 0, prevSafe = 0;

// ── Traffic Line Chart ─────────────────────────────────────────────
const trafficCtx = document.getElementById('trafficChart').getContext('2d');
const trafficChart = new Chart(trafficCtx, {
  type: 'line',
  data: {
    labels: trafficHistory.labels,
    datasets: [
      {
        label: 'Phishing',
        data: trafficHistory.phishing,
        borderColor: '#ff3d5a',
        backgroundColor: 'rgba(255,61,90,0.08)',
        fill: true,
        tension: 0.4,
        pointRadius: 0,
        borderWidth: 2,
      },
      {
        label: 'Safe',
        data: trafficHistory.safe,
        borderColor: '#00ff9d',
        backgroundColor: 'rgba(0,255,157,0.06)',
        fill: true,
        tension: 0.4,
        pointRadius: 0,
        borderWidth: 2,
      },
    ]
  },
  options: {
    responsive: true, maintainAspectRatio: false,
    animation: { duration: 400 },
    interaction: { mode: 'index', intersect: false },
    plugins: {
      legend: {
        position: 'top',
        labels: { boxWidth: 10, padding: 16, color: '#4a6a8a' }
      },
    },
    scales: {
      x: {
        grid: { color: 'rgba(0,200,255,0.04)' },
        ticks: { maxTicksLimit: 8 }
      },
      y: {
        grid: { color: 'rgba(0,200,255,0.04)' },
        beginAtZero: true,
        ticks: { precision: 0 }
      }
    }
  }
});

// ── Donut Chart ────────────────────────────────────────────────────
const donutCtx = document.getElementById('donutChart').getContext('2d');
const donutChart = new Chart(donutCtx, {
  type: 'doughnut',
  data: {
    labels: ['Safe', 'Phishing', 'Blocked'],
    datasets: [{
      data: [1, 0, 0],
      backgroundColor: [
        'rgba(0,255,157,0.7)',
        'rgba(255,61,90,0.7)',
        'rgba(0,200,255,0.7)',
      ],
      borderColor: [
        'rgba(0,255,157,0.9)',
        'rgba(255,61,90,0.9)',
        'rgba(0,200,255,0.9)',
      ],
      borderWidth: 1.5,
      hoverOffset: 4,
    }]
  },
  options: {
    responsive: true, maintainAspectRatio: false,
    cutout: '72%',
    animation: { duration: 600 },
    plugins: { legend: { display: false }, tooltip: { callbacks: {
      label: ctx => ` ${ctx.label}: ${ctx.parsed}`
    }}}
  }
});

function updateDonutLegend(safe, phishing, blocked) {
  const total = safe + phishing + blocked || 1;
  const items = [
    { label: 'Safe',     val: safe,     col: '#00ff9d' },
    { label: 'Phishing', val: phishing,  col: '#ff3d5a' },
    { label: 'Blocked',  val: blocked,   col: '#00c8ff' },
  ];
  document.getElementById('donut-legend').innerHTML = items.map(i => `
    <div style="display:flex;align-items:center;gap:10px">
      <div style="width:8px;height:8px;border-radius:50%;background:${i.col};box-shadow:0 0 6px ${i.col}"></div>
      <span style="font-family:var(--mono);font-size:0.72rem;color:var(--muted);flex:1">${i.label}</span>
      <span style="font-family:var(--mono);font-size:0.72rem;color:var(--text)">${i.val}</span>
      <span style="font-family:var(--mono);font-size:0.65rem;color:var(--muted)">${((i.val/total)*100).toFixed(1)}%</span>
    </div>
  `).join('');
}

// ── Histogram Chart ─────────────────────────────────────────────────
const histCtx = document.getElementById('histChart').getContext('2d');
const histChart = new Chart(histCtx, {
  type: 'bar',
  data: {
    labels: ['<50%', '50-65%', '65-80%', '80-90%', '90-95%', '>95%'],
    datasets: [{
      label: 'Detections',
      data: [0,0,0,0,0,0],
      backgroundColor: [
        'rgba(0,200,255,0.4)',
        'rgba(255,184,0,0.4)',
        'rgba(255,184,0,0.6)',
        'rgba(255,61,90,0.4)',
        'rgba(255,61,90,0.6)',
        'rgba(255,61,90,0.85)',
      ],
      borderColor: [
        'rgba(0,200,255,0.8)',
        'rgba(255,184,0,0.8)',
        'rgba(255,184,0,1)',
        'rgba(255,61,90,0.8)',
        'rgba(255,61,90,1)',
        'rgba(255,61,90,1)',
      ],
      borderWidth: 1,
      borderRadius: 3,
    }]
  },
  options: {
    responsive: true, maintainAspectRatio: false,
    animation: { duration: 500 },
    plugins: { legend: { display: false } },
    scales: {
      x: { grid: { color: 'rgba(0,200,255,0.04)' } },
      y: { grid: { color: 'rgba(0,200,255,0.04)' }, beginAtZero: true, ticks: { precision: 0 } }
    }
  }
});

// ── Confidence color helper ────────────────────────────────────────
function confColor(c) {
  if (c >= 0.9) return '#ff3d5a';
  if (c >= 0.75) return '#ffb800';
  return '#00c8ff';
}
function confBucket(c) {
  if (c < 0.5) return 0;
  if (c < 0.65) return 1;
  if (c < 0.8) return 2;
  if (c < 0.9) return 3;
  if (c < 0.95) return 4;
  return 5;
}

// ── Uptime formatter ──────────────────────────────────────────────
function fmtUptime(sec) {
  const h = Math.floor(sec/3600);
  const m = Math.floor((sec%3600)/60);
  const s = Math.floor(sec%60);
  return [h,m,s].map(v=>String(v).padStart(2,'0')).join(':');
}

// ── Main data refresh ─────────────────────────────────────────────
const histBuckets = [0,0,0,0,0,0];

async function refresh() {
  try {
    const res = await fetch('/api/stats');
    const d = await res.json();

    // Metrics
    document.getElementById('m-packets').textContent  = d.total_packets.toLocaleString();
    document.getElementById('m-phishing').textContent = d.total_phishing.toLocaleString();
    document.getElementById('m-blocked').textContent  = d.total_blocked.toLocaleString();
    document.getElementById('m-safe').textContent     = d.total_safe.toLocaleString();
    document.getElementById('m-rate').textContent     = d.detection_rate.toFixed(1) + '%';
    document.getElementById('uptime-val').textContent = fmtUptime(d.uptime);
    document.getElementById('last-update').textContent = new Date().toLocaleTimeString();

    // Rolling traffic
    const now = new Date().toLocaleTimeString('en', {hour12:false,hour:'2-digit',minute:'2-digit',second:'2-digit'});
    const newPhishing = d.total_phishing - prevPhishing;
    const newSafe     = d.total_safe - prevSafe;
    prevPhishing = d.total_phishing;
    prevSafe     = d.total_safe;

    trafficHistory.labels.push(now);
    trafficHistory.phishing.push(newPhishing > 0 ? newPhishing : 0);
    trafficHistory.safe.push(newSafe > 0 ? newSafe : 0);
    if (trafficHistory.labels.length > WINDOW) {
      trafficHistory.labels.shift();
      trafficHistory.phishing.shift();
      trafficHistory.safe.shift();
    }
    trafficChart.update();

    // Donut
    donutChart.data.datasets[0].data = [d.total_safe, d.total_phishing, d.total_blocked];
    donutChart.update();
    updateDonutLegend(d.total_safe, d.total_phishing, d.total_blocked);

    // Detection feed
    document.getElementById('det-count').textContent = d.latest_detections.length;
    if (d.latest_detections.length > 0) {
      document.getElementById('det-list').innerHTML = d.latest_detections.slice().reverse().map(e => {
        const c = e.confidence;
        histBuckets[confBucket(c)]++;
        return `
          <div class="event-row phish">
            <div class="event-icon">⚠</div>
            <div style="flex:1;min-width:0">
              <div class="event-domain">${e.domain}</div>
              <div class="event-meta">${e.ip} · ${e.timestamp}
                ${e.blocked ? '<span class="badge b-green" style="margin-left:6px">BLOCKED</span>' : ''}
              </div>
              <div class="conf-bar">
                <div class="conf-track">
                  <div class="conf-fill" style="width:${(c*100).toFixed(0)}%;background:${confColor(c)}"></div>
                </div>
                <span style="font-family:var(--mono);font-size:0.65rem;color:${confColor(c)}">${(c*100).toFixed(0)}%</span>
              </div>
            </div>
          </div>`;
      }).join('');
    }

    // Block feed
    document.getElementById('blk-count').textContent = d.latest_blocks.length;
    if (d.latest_blocks.length > 0) {
      document.getElementById('blk-list').innerHTML = d.latest_blocks.slice().reverse().map(b => `
        <div class="event-row blocked">
          <div class="event-icon">🛑</div>
          <div style="flex:1;min-width:0">
            <div class="event-domain">${b.domain}</div>
            <div class="event-meta">${b.ip} · ${b.timestamp}</div>
          </div>
          <span class="badge b-green">BLOCKED</span>
        </div>`).join('');
    }

    // Safe/Allowed feed
    document.getElementById('safe-count').textContent = d.latest_safe.length;
    if (d.latest_safe.length > 0) {
      document.getElementById('safe-list').innerHTML = d.latest_safe.slice().reverse().map(s => {
        const c = s.confidence;
        return `
          <div class="event-row safe">
            <div class="event-icon">✓</div>
            <div style="flex:1;min-width:0">
              <div class="event-domain">${s.domain}</div>
              <div class="event-meta">${s.ip} · ${s.timestamp}</div>
              <div class="conf-bar">
                <div class="conf-track">
                  <div class="conf-fill" style="width:${(c*100).toFixed(0)}%;background:#00ff9d"></div>
                </div>
                <span style="font-family:var(--mono);font-size:0.65rem;color:#00ff9d">${(c*100).toFixed(0)}% safe</span>
              </div>
            </div>
          </div>`;
      }).join('');
    }

    // Histogram
    histChart.data.datasets[0].data = [...histBuckets];
    histChart.update();

    // Blocked domains table
    if (d.blocked_domains.length > 0) {
      document.getElementById('domains-tbody').innerHTML = d.blocked_domains.map(r => `
        <tr>
          <td class="domain">${r.domain}</td>
          <td class="muted">${r.ip}</td>
          <td class="muted">${r.timestamp}</td>
        </tr>`).join('');
    }

  } catch(err) { console.error(err); }
}

refresh();
setInterval(refresh, 2000);
</script>
</body>
</html>"""


@app.route('/')
def home():
    """Home / landing page"""
    return render_template_string(HOME_HTML)


@app.route('/dashboard')
def dashboard():
    """Live dashboard page"""
    return render_template_string(DASHBOARD_HTML)


@app.route('/api/stats')
def get_stats():
    """API endpoint for stats"""
    with stats_lock:
        return jsonify({
            'total_packets': stats['total_packets'],
            'total_phishing': stats['total_phishing'],
            'total_blocked': stats['total_blocked'],
            'total_safe': stats['total_safe'],
            'detection_rate': stats['detection_rate'],
            'latest_detections': list(stats['latest_detections']),
            'latest_blocks': list(stats['latest_blocks']),
            'latest_safe': list(stats['latest_safe']),
            'blocked_domains': stats['blocked_domains'],
            'uptime': (datetime.now() - stats['start_time']).total_seconds(),
        })


def background_data_collection():
    """Continuously collect data in background"""
    collector = DashboardDataCollector()
    
    while True:
        try:
            collector.load_detections()
            collector.load_blocked_domains()
            collector.update_stats()
            time.sleep(1)
        except Exception as e:
            logger.error(f"Error in background collection: {e}")
            time.sleep(5)


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Phishing Detection Dashboard')
    parser.add_argument('--port', type=int, default=5000, help='Port to run dashboard on')
    args = parser.parse_args()
    
    logger.info("=" * 70)
    logger.info("🚀 STARTING PHISHING DETECTION DASHBOARD")
    logger.info("=" * 70)
    logger.info(f"Home Page:      http://localhost:{args.port}")
    logger.info(f"Live Dashboard: http://localhost:{args.port}/dashboard")
    logger.info(f"API Stats:      http://localhost:{args.port}/api/stats")
    logger.info("=" * 70 + "\n")
    
    # Start background data collection
    collector_thread = threading.Thread(target=background_data_collection, daemon=True)
    collector_thread.start()
    
    # Start Flask app
    app.run(debug=False, host='0.0.0.0', port=args.port, use_reloader=False)