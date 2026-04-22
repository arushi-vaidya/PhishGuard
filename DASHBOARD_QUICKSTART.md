# Dashboard & Control System - Quick Start Guide

**Status:** ✅ COMPLETE  
**Date:** April 22, 2026  
**Features:** Real-time dashboard + master control script

---

## What's New

### 1. Web Dashboard (`dashboard.py`)
Beautiful, real-time web interface showing:
- Live phishing detection statistics
- Auto-blocking events
- Blocked domains list
- Latest detections with confidence scores
- System status and uptime

**Access:** http://localhost:5000

### 2. Master Control Script (`run_complete_system.py`)
Interactive menu system to:
- Run demo mode
- Start dashboard
- Monitor network traffic
- Enable real DNS blocking
- Run test suite
- View detection logs
- Clear blocks

---

## Quick Start

### Installation (First Time)

```bash
cd phishing_detection

# Install dependencies
pip install -r requirements.txt

# Flask is now included
```

---

## Option A: Interactive Menu (Easiest)

```bash
# Start master control menu
python3 run_complete_system.py

# You'll see:
# [1] Demo Mode
# [2] Dashboard Only
# [3] Real-Time Monitoring
# [4] REAL DNS Blocking (sudo)
# [5] Dashboard + Monitoring
# [6] Test Suite
# [7] View Recent Detections
# [8] Clear All Blocks (sudo)
```

---

## Option B: Dashboard Only

```bash
# Start web dashboard
python3 dashboard.py

# Open browser: http://localhost:5000
# Shows live stats, detections, and blocked domains
# Auto-refreshes every 2 seconds
```

---

## Option C: Demo Mode (No Sudo Needed)

```bash
# Show blocking logic without modifying system
python3 run_complete_system.py --demo

# Or directly:
python3 example_complete_blocking.py

# Tests auto-blocking logic with simulated domains
```

---

## Option D: Real-Time Monitoring

```bash
# Monitor network traffic (no blocking)
python3 run_complete_system.py --monitoring

# Requires: en0 interface (macOS)
# Adjust with: --interface eth0 for Linux
```

---

## Option E: Full System with Dashboard + Monitoring

```bash
# Start both dashboard and monitoring together
python3 run_complete_system.py --run-dashboard-with-monitoring

# Access dashboard: http://localhost:5000
# See live detections in web interface
```

---

## Option F: REAL DNS Blocking (Requires Sudo)

```bash
# Start with automatic DNS blocking enabled
python3 run_complete_system.py --blocking

# You will be prompted to confirm
# Requires: sudo access
# Will modify: /etc/hosts file

# Or in master menu:
# Select option [4]
# Confirm with: yes
# System will block phishing domains in real-time
```

---

## Dashboard Features

### Statistics Cards
- **Total Packets Analyzed** - Network traffic processed
- **Phishing Detected** - Number of phishing attempts
- **Domains Blocked** - Successfully blocked
- **Safe Domains** - Legitimate traffic allowed

### Latest Phishing Detections
Shows recent detections with:
- Domain name
- IP address
- Confidence score (%)
- Timestamp
- Blocked status

### Recently Blocked
Live blocking events with:
- Domain name
- IP address
- Block timestamp

### All Blocked Domains Table
Complete list of domains currently blocked in /etc/hosts:
- IP address
- Domain name
- Block time

---

## Master Control Menu

### 1. Demo Mode
**Use Case:** Testing and demos  
**Requirements:** None  
**What it does:** Tests blocking logic with sample phishing domains

**Example output:**
```
Testing: phishing-site.com
ML Prediction: phishing
Confidence: 92%
Decision Engine Result:
  Action: block_dns
  Blocked: True
  🛑 DOMAIN BLOCKED FOR USER
```

### 2. Dashboard Only
**Use Case:** View live statistics  
**Requirements:** None  
**What it does:** Starts web dashboard on port 5000

**Access:** http://localhost:5000

### 3. Real-Time Monitoring
**Use Case:** Watch for phishing in real-time  
**Requirements:** Network interface (en0)  
**What it does:** Captures packets, detects phishing, shows alerts

**Output:**
```
[Packet #1] DNS Query: google.com
  ✓ SAFE: google.com

[Packet #2] TLS SNI: phishing-verify.com
  ⚠ ALERT: phishing-verify.com (85%)
```

### 4. REAL DNS Blocking
**Use Case:** Production deployment  
**Requirements:** sudo (root access)  
**What it does:** Modifies /etc/hosts to block phishing domains

**Result:** Phishing domains resolve to 127.0.0.1 (localhost)

### 5. Dashboard + Monitoring
**Use Case:** Full system visualization  
**Requirements:** None for monitoring, sudo for blocking  
**What it does:** Dashboard + live packet monitoring

### 6. Test Suite
**Use Case:** Validate all components  
**Requirements:** None  
**What it does:** Runs all example scripts and tests

### 7. View Recent Detections
**Use Case:** Review logs  
**Requirements:** None  
**What it does:** Displays recent phishing from logs

### 8. Clear All Blocks
**Use Case:** Remove blocks  
**Requirements:** sudo  
**What it does:** Removes all phishing detector blocks from /etc/hosts

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  Dashboard Web Interface                │
│                  (http://localhost:5000)                │
└────────────┬────────────────────────────────────────────┘
             │
             ├─→ Real-time stats from logs
             ├─→ Detection events
             └─→ Blocked domains list
                 │
      ┌──────────┴──────────────┐
      │                         │
   [logs/]              [Master Script]
   - detections_*.jsonl    │
   - blocked_domains.txt   ├─→ Packet Capture
   - blocked_ips.txt       ├─→ Feature Engineering
                           ├─→ ML Inference
                           └─→ DNS Blocking
```

---

## Configuration

### Change Network Interface
Edit scripts to use different interface:

```python
# For Linux:
interface="eth0"

# For macOS:
interface="en0"

# For Windows:
interface="Ethernet"
```

### Change Auto-Block Threshold
Default: 80% confidence

Edit `example_complete_blocking.py`:
```python
high_confidence_threshold=0.80  # Change to 0.90 for stricter
```

### Change Dashboard Port
Default: 5000

Edit `dashboard.py`:
```python
app.run(debug=False, host='0.0.0.0', port=8080)  # Use 8080
```

---

## Troubleshooting

### Dashboard Not Loading
```bash
# Check if Flask installed
pip install flask

# Check if port 5000 is available
lsof -i :5000  # macOS/Linux
netstat -ano | findstr :5000  # Windows
```

### Monitoring Not Capturing Packets
```bash
# Check interface name
ifconfig  # macOS/Linux
ipconfig  # Windows

# Try different interface
python3 run_complete_system.py --monitoring --interface eth0
```

### Sudo Issues for Real Blocking
```bash
# Check if sudo available
sudo -l

# Run with full path to Python
sudo $(which python3) run_complete_system.py
```

### Blocks Not Appearing in Dashboard
```bash
# Wait 2-3 seconds for auto-refresh
# Or refresh page manually

# Check logs exist
ls -la logs/

# View raw JSON log
cat logs/detections_*.jsonl | tail -10
```

---

## Performance Tips

1. **Run Dashboard on separate machine** - Better visibility
2. **Use wired connection** - More stable captures
3. **Close other apps** - Reduces CPU usage
4. **Adjust monitoring timeout** - Default 60 seconds
5. **Clear old logs periodically** - Prevents slowdown

---

## Security Recommendations

1. **Always confirm before blocking** - Review domain first
2. **Monitor false positives** - Adjust threshold if needed
3. **Keep logs** - For audit trails
4. **Regular model updates** - Retrain monthly
5. **Use on gateway** - Protects entire network
6. **Test before production** - Use demo mode first

---

## Examples

### Example 1: See Dashboard
```bash
python3 dashboard.py
# Visit: http://localhost:5000
# Shows real-time stats
```

### Example 2: Test Blocking
```bash
python3 run_complete_system.py --demo
# Tests 3 sample phishing domains
# Shows blocking logic
```

### Example 3: Watch Network
```bash
python3 run_complete_system.py --monitoring
# Captures packets for 60 seconds
# Alerts on phishing detected
```

### Example 4: Full System
```bash
python3 run_complete_system.py
# Shows interactive menu
# Pick any option
```

---

## API Reference

### Dashboard Stats Endpoint
```bash
curl http://localhost:5000/api/stats

# Returns JSON:
{
  "total_packets": 150,
  "total_phishing": 12,
  "total_blocked": 10,
  "total_safe": 138,
  "detection_rate": 8.0,
  "latest_detections": [...],
  "latest_blocks": [...],
  "blocked_domains": [...]
}
```

---

## Files

| File | Purpose |
|------|---------|
| `dashboard.py` | Web dashboard (Flask) |
| `run_complete_system.py` | Master control script |
| `realtime_blocking_system.py` | Real-time detection |
| `example_complete_blocking.py` | Demo/test |
| `modules/dns_blocker.py` | DNS blocking engine |

---

## Next Steps

1. **Start Dashboard:** `python3 dashboard.py`
2. **View Menu:** `python3 run_complete_system.py`
3. **Try Demo:** `python3 run_complete_system.py --demo`
4. **Enable Blocking:** `python3 run_complete_system.py --blocking` (with sudo)
5. **Monitor Network:** `python3 run_complete_system.py --monitoring`

---

## Support

For issues:
1. Check logs: `ls -la logs/`
2. View recent detections: `python3 run_complete_system.py` → option [7]
3. Test components: `python3 run_complete_system.py` → option [6]
4. Clear blocks if needed: `python3 run_complete_system.py` → option [8]

---

**Status**: ✅ DASHBOARD & CONTROL SYSTEM COMPLETE

**Project**: Fully operational with web interface, master control, and complete automation
