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


# HTML Dashboard Template
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>🛡️ Phishing Detection Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        header {
            background: rgba(255, 255, 255, 0.95);
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        h1 {
            color: #667eea;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .status {
            display: flex;
            gap: 20px;
            margin-top: 15px;
            flex-wrap: wrap;
        }
        
        .status-item {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .status-indicator {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }
        
        .status-indicator.active { background: #10b981; }
        .status-indicator.warning { background: #f59e0b; }
        .status-indicator.error { background: #ef4444; }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            text-align: center;
        }
        
        .stat-label {
            color: #666;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }
        
        .stat-value {
            font-size: 32px;
            font-weight: bold;
            color: #667eea;
        }
        
        .stat-change {
            font-size: 12px;
            color: #999;
            margin-top: 10px;
        }
        
        .content-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .card {
            background: white;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }
        
        .card-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            font-size: 18px;
            font-weight: bold;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .card-body {
            padding: 20px;
            max-height: 400px;
            overflow-y: auto;
        }
        
        .event-list {
            list-style: none;
        }
        
        .event-item {
            padding: 12px;
            border-left: 4px solid #667eea;
            margin-bottom: 10px;
            background: #f8f9fa;
            border-radius: 4px;
        }
        
        .event-item.phishing {
            border-left-color: #ef4444;
        }
        
        .event-item.blocked {
            border-left-color: #10b981;
            background: #ecfdf5;
        }
        
        .event-domain {
            font-weight: bold;
            color: #333;
            font-family: monospace;
            font-size: 13px;
            word-break: break-all;
        }
        
        .event-meta {
            font-size: 12px;
            color: #666;
            margin-top: 5px;
        }
        
        .confidence {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: bold;
        }
        
        .confidence.high {
            background: #fee2e2;
            color: #991b1b;
        }
        
        .confidence.medium {
            background: #fef3c7;
            color: #92400e;
        }
        
        .confidence.low {
            background: #e0e7ff;
            color: #1e1b4b;
        }
        
        .refresh-info {
            text-align: center;
            color: #999;
            font-size: 12px;
            padding: 20px;
        }
        
        .badge {
            display: inline-block;
            padding: 4px 12px;
            background: #667eea;
            color: white;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
        }
        
        .badge.blocked {
            background: #10b981;
        }
        
        .badge.phishing {
            background: #ef4444;
        }
        
        @media (max-width: 768px) {
            .stats-grid, .content-grid {
                grid-template-columns: 1fr;
            }
            .stat-value {
                font-size: 24px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header>
            <h1>🛡️ Phishing Detection & Blocking Dashboard</h1>
            <div class="status">
                <div class="status-item">
                    <div class="status-indicator active"></div>
                    <span>System Active</span>
                </div>
                <div class="status-item">
                    <div class="status-indicator active"></div>
                    <span>Monitoring Network</span>
                </div>
                <div class="status-item">
                    <div class="status-indicator active"></div>
                    <span>Auto-Blocking Enabled</span>
                </div>
            </div>
        </header>
        
        <!-- Stats Cards -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">📊 Total Packets Analyzed</div>
                <div class="stat-value" id="total-packets">0</div>
                <div class="stat-change">Since start</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-label">⚠️ Phishing Detected</div>
                <div class="stat-value" id="total-phishing">0</div>
                <div class="stat-change" id="detection-rate">0% of traffic</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-label">🛑 Domains Blocked</div>
                <div class="stat-value" id="total-blocked">0</div>
                <div class="stat-change">Auto-blocked</div>
            </div>
            
            <div class="stat-card">
                <div class="stat-label">✓ Safe Domains</div>
                <div class="stat-value" id="total-safe">0</div>
                <div class="stat-change">Allowed through</div>
            </div>
        </div>
        
        <!-- Content Cards -->
        <div class="content-grid">
            <!-- Latest Detections -->
            <div class="card">
                <div class="card-header">
                    ⚠️ Latest Phishing Detections
                </div>
                <div class="card-body">
                    <ul class="event-list" id="detections-list">
                        <li class="event-item">
                            <div style="color: #999; text-align: center; padding: 20px;">
                                Waiting for detections...
                            </div>
                        </li>
                    </ul>
                </div>
            </div>
            
            <!-- Blocked Events -->
            <div class="card">
                <div class="card-header">
                    🛑 Recently Blocked
                </div>
                <div class="card-body">
                    <ul class="event-list" id="blocks-list">
                        <li class="event-item">
                            <div style="color: #999; text-align: center; padding: 20px;">
                                Waiting for blocks...
                            </div>
                        </li>
                    </ul>
                </div>
            </div>
        </div>
        
        <!-- Blocked Domains List -->
        <div class="card">
            <div class="card-header">
                📋 All Blocked Domains (/etc/hosts)
            </div>
            <div class="card-body">
                <div id="blocked-domains-table">
                    <div style="color: #999; text-align: center; padding: 20px;">
                        Loading blocked domains...
                    </div>
                </div>
            </div>
        </div>
        
        <div class="refresh-info">
            Last updated: <span id="last-update">Never</span> | Refreshing every 2 seconds
        </div>
    </div>
    
    <script>
        async function updateDashboard() {
            try {
                const response = await fetch('/api/stats');
                const data = await response.json();
                
                // Update stats
                document.getElementById('total-packets').textContent = data.total_packets;
                document.getElementById('total-phishing').textContent = data.total_phishing;
                document.getElementById('total-blocked').textContent = data.total_blocked;
                document.getElementById('total-safe').textContent = data.total_safe;
                document.getElementById('detection-rate').textContent = 
                    data.detection_rate.toFixed(1) + '% of traffic';
                
                // Update detections list
                const detectionsList = document.getElementById('detections-list');
                if (data.latest_detections.length > 0) {
                    detectionsList.innerHTML = data.latest_detections.map(d => `
                        <li class="event-item phishing">
                            <div class="event-domain">${d.domain}</div>
                            <div class="event-meta">
                                IP: ${d.ip} | Time: ${d.timestamp}
                                <br>
                                Confidence: <span class="confidence ${
                                    d.confidence > 0.85 ? 'high' : d.confidence > 0.65 ? 'medium' : 'low'
                                }">${(d.confidence * 100).toFixed(0)}%</span>
                                ${d.blocked ? '<span class="badge blocked">BLOCKED</span>' : ''}
                            </div>
                        </li>
                    `).join('');
                }
                
                // Update blocks list
                const blocksList = document.getElementById('blocks-list');
                if (data.latest_blocks.length > 0) {
                    blocksList.innerHTML = data.latest_blocks.map(b => `
                        <li class="event-item blocked">
                            <div class="event-domain">${b.domain}</div>
                            <div class="event-meta">
                                IP: ${b.ip} | Time: ${b.timestamp}
                                <br>
                                <span class="badge blocked">🛑 BLOCKED</span>
                            </div>
                        </li>
                    `).join('');
                }
                
                // Update blocked domains table
                if (data.blocked_domains.length > 0) {
                    const table = `
                        <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
                            <tr style="background: #f0f0f0; font-weight: bold;">
                                <th style="padding: 10px; text-align: left; border-bottom: 1px solid #ddd;">Domain</th>
                                <th style="padding: 10px; text-align: left; border-bottom: 1px solid #ddd;">IP Address</th>
                                <th style="padding: 10px; text-align: left; border-bottom: 1px solid #ddd;">Blocked Time</th>
                            </tr>
                            ${data.blocked_domains.map(d => `
                                <tr>
                                    <td style="padding: 10px; border-bottom: 1px solid #eee; font-family: monospace; font-size: 12px;">${d.domain}</td>
                                    <td style="padding: 10px; border-bottom: 1px solid #eee; font-family: monospace; font-size: 12px;">${d.ip}</td>
                                    <td style="padding: 10px; border-bottom: 1px solid #eee; color: #666;">${d.timestamp}</td>
                                </tr>
                            `).join('')}
                        </table>
                    `;
                    document.getElementById('blocked-domains-table').innerHTML = table;
                }
                
                // Update timestamp
                document.getElementById('last-update').textContent = new Date().toLocaleTimeString();
            } catch (error) {
                console.error('Error updating dashboard:', error);
            }
        }
        
        // Initial update
        updateDashboard();
        
        // Auto-update every 2 seconds
        setInterval(updateDashboard, 2000);
    </script>
</body>
</html>
"""


@app.route('/')
def dashboard():
    """Main dashboard page"""
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
    logger.info("=" * 70)
    logger.info("🚀 STARTING PHISHING DETECTION DASHBOARD")
    logger.info("=" * 70)
    logger.info("Web Dashboard: http://localhost:5000")
    logger.info("API Stats: http://localhost:5000/api/stats")
    logger.info("=" * 70 + "\n")
    
    # Start background data collection
    collector_thread = threading.Thread(target=background_data_collection, daemon=True)
    collector_thread.start()
    
    # Start Flask app
    app.run(debug=False, host='0.0.0.0', port=5000, use_reloader=False)
