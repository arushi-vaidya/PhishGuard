#!/usr/bin/env python3
"""
Test script to verify detection logging is working
"""

import json
from pathlib import Path
from datetime import datetime

def check_detection_logs():
    """Check what's in the detection logs"""
    logs_dir = Path("logs")
    
    print("\n" + "="*70)
    print("📋 CHECKING DETECTION LOGS")
    print("="*70 + "\n")
    
    # List all detection files
    detection_files = list(logs_dir.glob("detections_*.jsonl"))
    print(f"Found {len(detection_files)} detection log files\n")
    
    if not detection_files:
        print("❌ No detection logs found!")
        return
    
    # Read latest file
    latest_file = sorted(detection_files)[-1]
    print(f"📂 Latest file: {latest_file.name}\n")
    
    with open(latest_file, 'r') as f:
        events = [json.loads(line) for line in f if line.strip()]
    
    print(f"📊 Total events in latest log: {len(events)}\n")
    
    if events:
        print("Recent events:")
        print("-" * 70)
        for i, event in enumerate(events[-10:], 1):
            status = "🛑 BLOCKED" if event.get('blocked') else "✓ SAFE" if event['prediction'] == 'legitimate' else "⚠ ALERT"
            print(f"{i}. {status}")
            print(f"   Domain: {event['domain']}")
            print(f"   Prediction: {event['prediction']} ({event['confidence']:.1%})")
            print(f"   Time: {datetime.fromtimestamp(event['timestamp']).strftime('%H:%M:%S')}")
            print()

def check_blocked_domains():
    """Check blocked domains file"""
    logs_dir = Path("logs")
    blocked_file = logs_dir / "blocked_domains.txt"
    
    print("="*70)
    print("🛑 BLOCKED DOMAINS")
    print("="*70 + "\n")
    
    if not blocked_file.exists():
        print("❌ No blocked_domains.txt file found!")
        return
    
    with open(blocked_file, 'r') as f:
        lines = f.readlines()
    
    print(f"Total blocked: {len(lines)}\n")
    
    if lines:
        print("Recent blocks:")
        print("-" * 70)
        for line in lines[-10:]:
            print(line.strip())

def check_logs_dir():
    """Check logs directory"""
    logs_dir = Path("logs")
    
    print("\n" + "="*70)
    print("📁 LOGS DIRECTORY CONTENTS")
    print("="*70 + "\n")
    
    if not logs_dir.exists():
        print("❌ Logs directory doesn't exist!")
        return
    
    files = list(logs_dir.glob("*"))
    print(f"Files in logs/: {len(files)}\n")
    
    for f in sorted(files):
        size_kb = f.stat().st_size / 1024
        print(f"  {f.name:40} {size_kb:8.1f} KB")

if __name__ == "__main__":
    check_logs_dir()
    check_detection_logs()
    check_blocked_domains()
    
    print("\n" + "="*70)
    print("✓ Check complete!")
    print("="*70 + "\n")
