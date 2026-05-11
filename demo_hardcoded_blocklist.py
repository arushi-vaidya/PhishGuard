#!/usr/bin/env python3
"""
Demo: Hardcoded Blocklist - Instant Blocking Without ML

Shows how domains in the hardcoded blocklist are blocked immediately
without running the expensive ML model.

Run: python3 demo_hardcoded_blocklist.py
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from modules.realtime_engine import (
    RealtimeInferenceEngine,
    HARDCODED_PHISHING_DOMAINS,
    HARDCODED_SAFE_DOMAINS
)
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    print("\n" + "="*80)
    print("HARDCODED BLOCKLIST & ALLOWLIST DEMO")
    print("="*80)
    
    # Initialize inference engine
    try:
        engine = RealtimeInferenceEngine(
            model_path="models/RandomForest_model.pkl",
            metadata_path="models/RandomForest_metadata.json"
        )
    except FileNotFoundError:
        logger.error("Model not found - creating demo without actual model")
        engine = None
    
    # Test cases
    print("\n" + "="*80)
    print("TEST 1: HARDCODED PHISHING BLOCKLIST (No ML runs - instant block)")
    print("="*80 + "\n")
    
    phishing_tests = [
        ("paypal-verify.com", "185.25.51.205"),
        ("apple-login.com", "185.225.69.24"),
        ("amazon-account.com", "45.152.72.200"),
        ("google-signin.com", "45.152.72.200"),
        ("microsoft-update.com", "185.25.51.205"),
        ("unknown-phishing.com", "1.2.3.4"),  # Not in hardcoded list - would run ML
    ]
    
    if engine:
        for domain, ip in phishing_tests:
            result = engine.predict(domain, ip, domain)
            
            if result.features_used == 0:
                emoji = "🛑" if result.prediction == "phishing" else "✅"
                print(f"{emoji} {domain:30} | {result.prediction:10} | Confidence: {result.confidence:6.1%} | "
                      f"NO ML (0 features) ← INSTANT BLOCK")
            else:
                emoji = "⚠️" if result.prediction == "phishing" else "✅"
                print(f"{emoji} {domain:30} | {result.prediction:10} | Confidence: {result.confidence:6.1%} | "
                      f"Ran ML ({result.features_used} features)")
    
    print("\n" + "="*80)
    print("TEST 2: HARDCODED SAFE ALLOWLIST (No ML runs - instant allow)")
    print("="*80 + "\n")
    
    safe_tests = [
        ("google.com", "142.250.185.46"),
        ("github.com", "140.82.113.21"),
        ("amazon.com", "54.239.28.30"),
        ("mail.google.com", "142.250.185.46"),  # Subdomain of safe domain
        ("suspicious-domain.com", "1.2.3.4"),  # Not in hardcoded list - would run ML
    ]
    
    if engine:
        for domain, ip in safe_tests:
            result = engine.predict(domain, ip, domain)
            
            if result.features_used == 0:
                emoji = "✅"
                print(f"{emoji} {domain:30} | {result.prediction:10} | Confidence: {result.confidence:6.1%} | "
                      f"NO ML (0 features) ← INSTANT ALLOW")
            else:
                emoji = "⚠️" if result.prediction == "phishing" else "✅"
                print(f"{emoji} {domain:30} | {result.prediction:10} | Confidence: {result.confidence:6.1%} | "
                      f"Ran ML ({result.features_used} features)")
    
    # Show statistics
    print("\n" + "="*80)
    print("PERFORMANCE BENEFIT")
    print("="*80)
    
    print(f"\nHardcoded Phishing Domains: {len(HARDCODED_PHISHING_DOMAINS)}")
    print(f"Hardcoded Safe Domains: {len(HARDCODED_SAFE_DOMAINS)}")
    print(f"Total Hardcoded Entries: {len(HARDCODED_PHISHING_DOMAINS) + len(HARDCODED_SAFE_DOMAINS)}\n")
    
    print(f"Performance Improvement:")
    print(f"  • Domains in blocklist: INSTANT response (0ms ML overhead)")
    print(f"  • Domains in allowlist: INSTANT response (0ms ML overhead)")
    print(f"  • Other domains: Normal ML inference (~10-50ms)\n")
    
    print(f"Example:")
    print(f"  Without hardcoded lists: 100 domains × 25ms = 2.5 seconds")
    print(f"  With hardcoded lists (50 matches): 50 × 0ms + 50 × 25ms = 1.25 seconds")
    print(f"  Speedup: 2x faster! ⚡")
    
    print("\n" + "="*80)
    print("HOW TO ADD MORE DOMAINS")
    print("="*80)
    
    print("""
In modules/realtime_engine.py, add/remove domains:

# PHISHING BLOCKLIST
HARDCODED_PHISHING_DOMAINS = {
    'paypal-verify.com',           # Add any phishing domains here
    'fake-bank.com',               # New entry
    'malicious-site.com',          # New entry
}

# SAFE ALLOWLIST
HARDCODED_SAFE_DOMAINS = {
    'google.com',                  # Add trusted domains here
    'trusted-bank.com',            # New entry
    'company-server.internal',     # New entry
}

✨ Changes take effect INSTANTLY - no model retraining needed!
""")
    
    print("="*80 + "\n")


if __name__ == "__main__":
    main()
