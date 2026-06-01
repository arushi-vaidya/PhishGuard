# System-Blocked Phishing Detection

## Overview

The system now **detects and displays phishing attempts even when they're blocked by your laptop's built-in security** (firewall, SSL errors, timeouts, etc.).

This gives you **complete visibility** into all phishing threats attempting to reach you — both blocked by our detector AND blocked by system-level security.

---

## What Gets Detected?

The system detects phishing attempts blocked by:

| Block Type | Description | Example |
|-----------|-------------|---------|
| **Firewall** | Connection refused by firewall | `Connection refused - firewall blocked outbound` |
| **SSL Error** | Invalid/self-signed certificate | `SSL certificate verification failed` |
| **Timeout** | Connection timeout (server unreachable) | `Connection timeout after 30s` |
| **DNS Failure** | Domain won't resolve | `DNS resolution failed` |
| **Connection Reset** | Server terminated connection | `Connection reset by peer` |
| **Antivirus** | Blocked by antivirus/security software | `Quarantined by antivirus` |

---

## Dashboard Display

### New Metric: "System Blocked"

A new metric appears in the **metrics strip** showing phishing attempts blocked by system security:

```
┌─────────────────────────────────────────────────────────────┐
│ 🖧 SYSTEM BLOCKED                                           │
│ 24                                                          │
│ Firewall/SSL/Timeouts                                       │
└─────────────────────────────────────────────────────────────┘
```

### New Feed: "System Blocked"

Displays all phishing attempts blocked by system security in real-time:

```
🖧 SYSTEM BLOCKED
────────────────────────────────────────────────────────────

🖧 secure-paypal-login.com
   185.220.101.45 · 14:32:45
   [firewall] Connection refused - firewall blocked outbound

🖧 apple-id-verify.xyz
   45.76.192.101 · 14:31:22
   [ssl_error] SSL certificate verification failed

🖧 verify-bank-account.net
   89.163.128.29 · 14:30:15
   [connection_timeout] Connection timeout after 30s
```

---

## How It Works

### 1. Detection

```
Phishing attempt detected
     ↓
Connection fails (firewall/SSL/timeout/etc)
     ↓
System Block Detector captures error
     ↓
Logged as "system_blocked" event
     ↓
Displayed in dashboard
```

### 2. Logging

All system-blocked attempts are logged to **`logs/system_blocks_YYYYMMDD.jsonl`**:

```json
{
  "domain": "secure-paypal-login.com",
  "destination_ip": "185.220.101.45",
  "block_type": "firewall",
  "timestamp": 1748937945.123,
  "error_message": "Connection refused - firewall blocked outbound",
  "source": "system_security"
}
```

### 3. Dashboard Integration

The dashboard automatically loads and displays:
- Total count of system-blocked attempts (metric box)
- Recent system-blocked domains (feed)
- Block type (firewall, SSL error, timeout, etc.)
- Error details

---

## Usage

### Option 1: Manual Logging

Use the `SystemBlockDetector` to manually log system-blocked attempts:

```python
from modules.system_block_detector import SystemBlockDetector

detector = SystemBlockDetector()

# Log a system-blocked attempt
event = detector.detect_and_log(
    domain="suspicious-paypal.com",
    destination_ip="45.76.192.101",
    error_type="ssl_error",
    error_message="SSL certificate verification failed"
)

print(event)
```

### Option 2: Run Test Script

To see the system in action:

```bash
python3 test_system_blocked.py
```

Output:
```
============================================================
  SYSTEM BLOCK DETECTOR - TEST SCRIPT
============================================================

Simulating system-blocked phishing attempts...

[1/5] secure-paypal-login.com
       IP: 185.220.101.45
    Type: FIREWALL
   Error: Connection refused - firewall blocked outbound
  Status: ✓ LOGGED

[2/5] apple-id-verify.xyz
    ... (more entries)

BLOCK STATISTICS

Total System Blocks: 5

Breakdown by type:
  • firewall: 1
  • ssl_error: 1
  • connection_timeout: 1
  • dns_failure: 1
  • connection_reset: 1
```

### Option 3: Start Dashboard

The dashboard automatically loads system-blocked events:

```bash
python3 dashboard.py
```

Then visit: **http://localhost:5000/dashboard**

The **"🖧 System Blocked"** feed shows all attempts.

---

## API Endpoint

Get system-blocked data via API:

```bash
curl http://localhost:5000/api/stats | jq '.total_system_blocked'
curl http://localhost:5000/api/stats | jq '.latest_system_blocked'
```

Response:
```json
{
  "total_system_blocked": 24,
  "latest_system_blocked": [
    {
      "domain": "secure-paypal-login.com",
      "ip": "185.220.101.45",
      "block_type": "firewall",
      "error": "Connection refused - firewall blocked outbound",
      "timestamp": "14:32:45"
    },
    ...
  ]
}
```

---

## File Structure

New files added:

```
modules/
  └── system_block_detector.py       ← System block detection
      
logs/
  └── system_blocks_YYYYMMDD.jsonl   ← Log file (auto-created)
      
test_system_blocked.py               ← Test script
```

---

## Statistics

### Metric Types

The system tracks and classifies:

| Type | Count | Example |
|------|-------|---------|
| Firewall | 12 | Connection refused |
| SSL Error | 8 | Certificate failed |
| Timeout | 3 | Server unreachable |
| DNS Failure | 1 | Domain won't resolve |
| Connection Reset | 1 | Server terminated |

---

## Integration with ML Model

### Before (ML Only)
```
Phishing detected by ML
  → Confidence: 85%
  → Action: Block
```

### Now (ML + System Blocks)
```
Phishing detected by ML
  → Confidence: 85%
  → Action: Block

+ 

Phishing blocked by System Security
  → Type: Firewall
  → Action: Logged & displayed
```

**Result**: Complete visibility into all phishing threats (both detector blocks and system blocks)

---

## Dashboard Sections

### Metrics Strip
- **Packets Analyzed**: Total packets since start
- **Phishing Detected**: Count of phishing predictions
- **Our Blocks**: Count of domains we blocked via /etc/hosts
- **System Blocked**: ← **NEW** Count of system-blocked attempts
- **Safe Traffic**: Count of legitimate domains

### Feeds
- **Detections**: All phishing detected by ML
- **Our Blocks**: Blocked via /etc/hosts
- **System Blocked**: ← **NEW** Blocked by firewall/SSL/timeout
- **Allowed**: Legitimate traffic

---

## Example Workflow

```
1️⃣ User attempts to visit: phishing-site.com
   
2️⃣ System detects connection attempt
   
3️⃣ Connection fails (firewall blocks)
   
4️⃣ System Block Detector logs:
   {
     "domain": "phishing-site.com",
     "block_type": "firewall",
     "error": "Connection refused"
   }
   
5️⃣ Dashboard displays in "System Blocked" feed:
   🖧 phishing-site.com
      [firewall] Connection refused
   
6️⃣ User sees in dashboard: "+1 System Blocked"
```

---

## Troubleshooting

### System blocks not showing?

1. Check log files exist: `ls logs/system_blocks_*.jsonl`
2. Verify format: `cat logs/system_blocks_*.jsonl | head -1`
3. Restart dashboard: `python3 dashboard.py`

### Not detecting system blocks?

System blocks are detected when:
- A phishing domain is attempted
- Connection fails (firewall/SSL/timeout/DNS/etc.)
- Error is captured and logged

To test manually:
```bash
python3 test_system_blocked.py
```

---

## Summary

| Aspect | Details |
|--------|---------|
| **Purpose** | Detect phishing blocked by system security |
| **Block Types** | Firewall, SSL, Timeout, DNS, Antivirus |
| **Display** | Dashboard metric + feed + API |
| **Logs** | `logs/system_blocks_YYYYMMDD.jsonl` |
| **Color Code** | 🖧 (orange) for system-blocked |
| **Combined View** | Shows both detector blocks + system blocks |

**Result**: 🛡️ **Complete phishing protection visibility** — nothing gets through without being tracked!
