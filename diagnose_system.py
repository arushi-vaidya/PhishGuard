#!/usr/bin/env python3
"""
Diagnostic Script: Check Network Interfaces and System Setup

Run: python3 diagnose_system.py
"""

import sys
from pathlib import Path
import subprocess
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

print("\n" + "="*80)
print("🔧 PHISHING DETECTION SYSTEM - DIAGNOSTIC")
print("="*80 + "\n")

# 1. Check Python environment
print("1️⃣  Python Environment")
print("-" * 80)
print(f"   Python: {sys.version}")
print(f"   Executable: {sys.executable}")
print(f"   Working Directory: {Path.cwd()}")

# 2. Check dependencies
print("\n2️⃣  Dependencies")
print("-" * 80)

deps = ['scapy', 'sklearn', 'pandas', 'numpy', 'flask', 'google']
for dep in deps:
    try:
        __import__(dep)
        print(f"   ✅ {dep:15} installed")
    except ImportError:
        print(f"   ❌ {dep:15} NOT installed")

# 3. Check model files
print("\n3️⃣  Model Files")
print("-" * 80)

model_files = [
    "models/RandomForest_model.pkl",
    "models/RandomForest_metadata.json",
]

for file in model_files:
    exists = Path(file).exists()
    status = "✅" if exists else "❌"
    size = Path(file).stat().st_size if exists else 0
    print(f"   {status} {file:40} ({size:,} bytes)")

# 4. Check network interfaces
print("\n4️⃣  Available Network Interfaces")
print("-" * 80)

try:
    result = subprocess.run(['ifconfig'], capture_output=True, text=True)
    interfaces = []
    for line in result.stdout.split('\n'):
        if line and not line.startswith('\t') and not line.startswith(' '):
            interface = line.split(':')[0]
            if interface:
                interfaces.append(interface)
    
    print("   Active Interfaces:")
    for iface in sorted(set(interfaces)):
        print(f"   • {iface}")
    
    # Most likely one to use
    likely = None
    for iface in ['en0', 'en1', 'eth0', 'wlan0', 'wifi0']:
        if iface in interfaces:
            likely = iface
            break
    
    if likely:
        print(f"\n   ⚡ Recommended for packet capture: {likely}")
    
except Exception as e:
    print(f"   ❌ Could not list interfaces: {e}")

# 5. Check permissions
print("\n5️⃣  Permissions Check")
print("-" * 80)

try:
    import os
    if os.geteuid() == 0:
        print("   ✅ Running as ROOT (sudo) - can capture packets")
    else:
        print("   ⚠️  NOT running as root - may need: sudo python3 realtime_blocking_system.py")
except AttributeError:
    # Windows or macOS might not have geteuid
    print("   ℹ️  Cannot check permissions on this system")

# 6. Check packet capture capability
print("\n6️⃣  Packet Capture Test")
print("-" * 80)

try:
    from scapy.all import conf, get_if_list
    
    ifaces = get_if_list()
    print(f"   Scapy found {len(ifaces)} interfaces:")
    for iface in ifaces[:5]:
        print(f"   • {iface}")
    
    if len(ifaces) > 5:
        print(f"   ... and {len(ifaces) - 5} more")
    
except Exception as e:
    print(f"   ❌ Scapy error: {e}")

# 7. Check logs
print("\n7️⃣  Recent Detection Logs")
print("-" * 80)

log_files = sorted(Path("logs").glob("detections_*.jsonl"), reverse=True)[:3]

if log_files:
    for logfile in log_files:
        size = logfile.stat().st_size
        lines = len(logfile.read_text().strip().split('\n'))
        print(f"   {logfile.name}: {lines} events ({size:,} bytes)")
else:
    print("   ℹ️  No log files yet (system hasn't detected anything)")

# 8. Summary & Recommendations
print("\n" + "="*80)
print("📋 RECOMMENDATIONS")
print("="*80)

print("""
To start detecting traffic:

1. RUN WITH SUDO (required for packet capture):
   
   sudo python3 realtime_blocking_system.py

2. TO USE SPECIFIC INTERFACE:
   
   Edit realtime_blocking_system.py and change:
   RealtimeBlockingSystem(interface="en0")
   
   Replace "en0" with your interface from step 4️⃣ above.

3. TO TEST WITHOUT LIVE TRAFFIC:
   
   python3 example_realtime_inference.py
   python3 example_decision_engine.py

4. TO USE HARDCODED BLOCKLIST (no traffic needed):
   
   python3 test_hardcoded_blocking.py

""")

print("="*80 + "\n")
