#!/usr/bin/env python3
"""
Clean up all dashboard data and start fresh

Run: python3 cleanup_dashboard.py
"""

import os
from pathlib import Path
import shutil

print("\n" + "="*80)
print("🧹 CLEARING ALL DASHBOARD DATA")
print("="*80 + "\n")

# Directories to clean
dirs_to_clean = [
    ("logs", "Detection logs"),
    ("data", "Datasets"),
]

for dir_path, description in dirs_to_clean:
    if Path(dir_path).exists():
        print(f"Cleaning {description}:")
        
        for file in Path(dir_path).glob("*"):
            if file.is_file():
                try:
                    file.unlink()
                    print(f"  ✓ Deleted: {file.name}")
                except Exception as e:
                    print(f"  ❌ Failed to delete {file.name}: {e}")

print("\n" + "="*80)
print("✅ CLEANUP COMPLETE - Ready for fresh start!")
print("="*80 + "\n")

print("""
Next steps:

1. Start the real-time detection system:
   sudo python3 realtime_blocking_system.py --interface en0 --timeout 60

2. Open Chrome and visit sites to test

3. Open dashboard to see fresh data:
   python3 dashboard.py
   Visit: http://localhost:5000

4. Or test with example scripts:
   python3 example_realtime_inference.py
   python3 example_decision_engine.py

""")
