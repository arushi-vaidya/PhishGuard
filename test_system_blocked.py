#!/usr/bin/env python3
"""
Test script: Log System-Blocked Phishing Attempts

Demonstrates how the system detects and logs phishing domains 
that are blocked by system security (firewall, SSL, timeouts, etc.)

Usage:
    python3 test_system_blocked.py

Author: Research Team
Date: 2026
"""

import sys
import time
from datetime import datetime
from pathlib import Path

# Add modules to path
sys.path.insert(0, str(Path(__file__).parent))

from modules.system_block_detector import SystemBlockDetector, SystemBlockType


def simulate_system_blocks():
    """Simulate various types of system blocks"""
    
    detector = SystemBlockDetector()
    
    print("\n" + "="*70)
    print("  SYSTEM BLOCK DETECTOR - TEST SCRIPT")
    print("="*70 + "\n")
    
    # Test cases: various phishing attempts blocked by system security
    test_cases = [
        {
            'domain': 'secure-paypal-login.com',
            'ip': '185.220.101.45',
            'error_type': 'firewall',
            'error_msg': 'Connection refused - firewall blocked outbound connection',
        },
        {
            'domain': 'apple-id-verify.xyz',
            'ip': '45.76.192.101',
            'error_type': 'ssl_error',
            'error_msg': 'SSL certificate verification failed - self-signed certificate',
        },
        {
            'domain': 'verify-bank-account.net',
            'ip': '89.163.128.29',
            'error_type': 'connection_timeout',
            'error_msg': 'Connection timeout after 30s - server unreachable',
        },
        {
            'domain': 'update-your-amazon-info.co',
            'ip': '193.201.14.97',
            'error_type': 'dns_failure',
            'error_msg': 'DNS resolution failed - domain not resolving',
        },
        {
            'domain': 'confirm-microsoft-account.org',
            'ip': '154.39.96.101',
            'error_type': 'connection_reset',
            'error_msg': 'Connection reset by peer - server terminated connection',
        },
    ]
    
    print(f"\n{'-'*70}")
    print("Simulating system-blocked phishing attempts...")
    print(f"{'-'*70}\n")
    
    for i, case in enumerate(test_cases, 1):
        print(f"[{i}/{len(test_cases)}] {case['domain']}")
        print(f"         IP: {case['ip']}")
        print(f"      Type: {case['error_type'].upper()}")
        print(f"     Error: {case['error_msg']}")
        
        # Log the block
        event = detector.detect_and_log(
            domain=case['domain'],
            destination_ip=case['ip'],
            error_type=case['error_type'],
            error_message=case['error_msg'],
            timestamp=time.time()
        )
        
        print(f"    Status: ✓ LOGGED\n")
        time.sleep(0.5)
    
    # Print statistics
    stats = detector.get_block_stats()
    
    print(f"{'-'*70}")
    print("BLOCK STATISTICS")
    print(f"{'-'*70}\n")
    
    print(f"Total System Blocks: {stats['total_blocks']}\n")
    
    print("Breakdown by type:")
    for block_type, count in sorted(stats['by_type'].items()):
        print(f"  • {block_type.upper()}: {count}")
    
    print(f"\nRecent blocked domains:")
    for j, domain_stat in enumerate(stats['recent_domains'], 1):
        print(f"  {j}. {domain_stat['domain']}")
        print(f"     Type: {domain_stat['type']}")
    
    print(f"\n{'-'*70}")
    print("LOGS CREATED")
    print(f"{'-'*70}\n")
    
    # Show log files
    log_dir = Path("logs")
    if log_dir.exists():
        sys_block_files = list(log_dir.glob("system_blocks_*.jsonl"))
        if sys_block_files:
            for log_file in sorted(sys_block_files, reverse=True)[:1]:
                print(f"✓ {log_file.name}")
                print(f"  Location: {log_file.absolute()}\n")
                
                # Show sample entries
                print("Sample entries:")
                with open(log_file, 'r') as f:
                    for line in f:
                        print(f"  {line.strip()}")
                        break
    
    print(f"\n{'-'*70}")
    print("✓ Test completed successfully!")
    print(f"{'-'*70}\n")
    
    print("Next steps:")
    print("  1. Start the dashboard: python3 dashboard.py")
    print("  2. View system-blocked attempts at: http://localhost:5000/dashboard")
    print("  3. Check the '🖧 System Blocked' feed in the dashboard\n")


if __name__ == '__main__':
    simulate_system_blocks()
