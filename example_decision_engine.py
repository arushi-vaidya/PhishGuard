#!/usr/bin/env python3
"""
STEP 5: Decision Engine - Example Usage

This script demonstrates:
1. Loading trained inference model
2. Making predictions on test domains
3. Applying decision policies
4. Executing blocking/alert actions
5. Logging all decisions

Run with: python3 example_decision_engine.py
"""

import sys
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent / "modules"))

from realtime_engine import RealtimeInferenceEngine
from decision_engine import DecisionEngine, DecisionPolicy, ActionType
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    """Main execution"""
    
    print("\n" + "="*80)
    print("STEP 5: DECISION ENGINE - PHISHING RESPONSE")
    print("="*80)
    print("\nIntegrating inference predictions with response policies...\n")
    
    # Load inference model
    try:
        engine = RealtimeInferenceEngine(
            model_path="models/RandomForest_model.pkl",
            metadata_path="models/RandomForest_metadata.json"
        )
    except FileNotFoundError as e:
        logger.error(f"Model not found: {e}")
        return
    
    # Create decision policy
    policy = DecisionPolicy(
        high_confidence_threshold=0.85,
        low_confidence_threshold=0.65,
        block_phishing_high_confidence=True,
        alert_phishing_any_confidence=True,
        alert_legitimate_low_confidence=False,
        high_risk_action=ActionType.BLOCK_DNS,
        medium_risk_action=ActionType.ALERT,
        send_email_alerts=False,  # Set to True to enable email alerts
    )
    
    # Create decision engine
    decision_engine = DecisionEngine(policy, log_dir="logs")
    
    # Test cases
    test_cases = [
        # Legitimate domains - should allow
        ("google.com", "142.250.185.46", "google.com"),
        ("github.com", "140.82.113.21", "github.com"),
        ("amazon.com", "54.239.28.30", "amazon.com"),
        ("facebook.com", "66.220.158.22", "facebook.com"),
        ("youtube.com", "142.251.41.142", "youtube.com"),
        
        # Phishing domains - should block/alert
        ("paypal-verify.com", "185.25.51.205", "paypal-verify.com"),
        ("apple-login.com", "185.225.69.24", "apple-login.com"),
        ("amazon-account.com", "45.152.72.200", "amazon-account.com"),
        ("google-signin.com", "45.152.72.200", "google-signin.com"),
        ("microsoft-update.com", "185.25.51.205", "microsoft-update.com"),
    ]
    
    print("="*80)
    print("PROCESSING PREDICTIONS & DECISIONS")
    print("="*80 + "\n")
    
    decisions = []
    
    for domain, ip, sni in test_cases:
        # Get inference prediction
        prediction = engine.predict(domain, ip, sni)
        
        # Make decision based on prediction
        decision = decision_engine.decide(
            domain=prediction.domain,
            destination_ip=prediction.destination_ip,
            prediction=prediction.prediction,
            confidence=prediction.confidence,
            risk_level=prediction.risk_level,
            features_used=prediction.features_used,
            timestamp=prediction.timestamp
        )
        
        decisions.append(decision)
        
        # Display result
        action_icon = {
            'block_dns': '🛑',
            'alert': '⚠️',
            'log_only': '📝',
            'none': '✅'
        }.get(decision.action_taken, '❓')
        
        blocked = "[BLOCKED]" if decision.blocked else "[ALLOWED]"
        print(
            f"{action_icon} {domain:30} {blocked:10} | "
            f"Action: {decision.action_taken:15} | "
            f"Conf: {prediction.confidence:6.2%}"
        )
    
    # Statistics
    print("\n" + "="*80)
    print("DECISION STATISTICS")
    print("="*80)
    
    stats = decision_engine.get_statistics()
    print(f"Total Predictions: {stats['total_decisions']}")
    print(f"Phishing Blocked: {stats['phishing_blocked']}")
    print(f"Phishing Alerted: {stats['phishing_alerted']}")
    print(f"Blocking Rate: {stats['blocking_rate']:.2%}")
    print(f"Events Logged: {stats['events_logged']}")
    
    # Blocked domains
    blocked = decision_engine.get_blocked_domains()
    if blocked:
        print(f"\n🛑 Blocked Domains ({len(blocked)}):")
        for domain in blocked:
            print(f"  • {domain}")
    
    # Recent events
    print("\n" + "="*80)
    print("RECENT DETECTIONS (Last 5)")
    print("="*80)
    
    recent = decision_engine.get_recent_events(5)
    for event in recent:
        action_emoji = {
            'block_dns': '🛑',
            'alert': '⚠️',
            'log_only': '📝',
        }.get(event.action_taken, '❓')
        
        print(
            f"\n{action_emoji} {event.domain:30} | "
            f"Action: {event.action_taken:15} | "
            f"Reason: {event.reason}"
        )
    
    # Policy summary
    print("\n" + "="*80)
    print("ACTIVE DECISION POLICY")
    print("="*80)
    print(f"High Confidence Threshold: {policy.high_confidence_threshold:.2%}")
    print(f"Low Confidence Threshold: {policy.low_confidence_threshold:.2%}")
    print(f"Block Phishing (High Conf): {policy.block_phishing_high_confidence}")
    print(f"Alert on Any Phishing: {policy.alert_phishing_any_confidence}")
    print(f"High Risk Action: {policy.high_risk_action.value}")
    print(f"Medium Risk Action: {policy.medium_risk_action.value}")
    print(f"Low Risk Action: {policy.low_risk_action.value}")
    
    # Log files
    print("\n" + "="*80)
    print("LOGS & ARTIFACTS")
    print("="*80)
    
    log_dir = Path("logs")
    if log_dir.exists():
        print(f"Log Directory: {log_dir.absolute()}")
        
        # Detection log
        detection_log = list(log_dir.glob("detections_*.jsonl"))
        if detection_log:
            print(f"  • {detection_log[0].name} - Detailed JSON log")
        
        # Blocked domains
        blocked_file = log_dir / "blocked_domains.txt"
        if blocked_file.exists():
            print(f"  • blocked_domains.txt - DNS block entries")
        
        # Blocked IPs
        blocked_ips = log_dir / "blocked_ips.txt"
        if blocked_ips.exists():
            print(f"  • blocked_ips.txt - Network block entries")
    
    # Summary
    print("\n" + "="*80)
    print("STEP 5 COMPLETE ✓")
    print("="*80)
    print("\nIntegrated Pipeline:")
    print("  STEP 1: Packet Capture → Extract DNS/TLS")
    print("  STEP 2: Feature Engineering → 41+ features")
    print("  STEP 3: ML Inference → Predictions with confidence")
    print("  STEP 4: Real-Time Engine → Load model")
    print("  STEP 5: Decision Engine → Block/Alert/Log ✓")
    print("\nNext: STEP 6 - Dataset expansion (more PhishTank domains)")
    print("      STEP 7 - Evaluation metrics & latency analysis")
    print("      STEP 8 - Research contribution & publication")
    print("\n" + "="*80 + "\n")


if __name__ == "__main__":
    main()
