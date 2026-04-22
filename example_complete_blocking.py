#!/usr/bin/env python3
"""
End-to-End Blocking Test Example

This example demonstrates:
1. Creating a phishing detection prediction
2. Running decision engine
3. Executing real DNS blocking
4. Verifying domain is blocked

Run with: sudo python3 example_complete_blocking.py
(Requires sudo to modify /etc/hosts)

Author: Research Team
Date: 2026
"""

import logging
import sys
from pathlib import Path
from datetime import datetime

# Add modules to path
sys.path.insert(0, str(Path(__file__).parent / "modules"))

from decision_engine import DecisionEngine, DecisionPolicy
from dns_blocker import get_hosts_manager, block_phishing_domain, unblock_phishing_domain

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def test_dns_blocking():
    """Test DNS blocking functionality"""
    
    logger.info("=" * 70)
    logger.info("🧪 END-TO-END PHISHING DETECTION & BLOCKING TEST")
    logger.info("=" * 70)
    
    # Test domains
    test_domains = [
        ("phishing-site.com", "192.0.2.100"),
        ("paypal-verify.com", "192.0.2.101"),
        ("amazon-account-confirm.com", "192.0.2.102"),
    ]
    
    # Initialize decision engine with blocking policy
    logger.info("\n[1/4] Initializing Decision Engine with AUTO-BLOCKING...")
    policy = DecisionPolicy(
        high_confidence_threshold=0.80,
        block_phishing_high_confidence=True,  # AUTO-BLOCK!
        alert_phishing_any_confidence=True,
    )
    decision_engine = DecisionEngine(policy)
    logger.info("  ✓ Decision engine ready (auto-blocking enabled)")
    
    # Initialize DNS blocker
    logger.info("\n[2/4] Initializing DNS Blocker...")
    hosts_manager = get_hosts_manager()
    
    # Get current blocklist
    initial_blocklist = hosts_manager.get_blocklist()
    logger.info(f"  Current blocked domains: {len(initial_blocklist)}")
    
    # Test blocking
    logger.info("\n[3/4] Testing Phishing Detection & Auto-Blocking...")
    blocked_count = 0
    
    for domain, ip in test_domains:
        logger.info(f"\n{'='*70}")
        logger.info(f"Testing: {domain}")
        logger.info(f"{'='*70}")
        
        # Simulate ML prediction
        prediction = "phishing"
        confidence = 0.92  # 92% confidence - should trigger auto-block
        risk_level = "high"
        
        logger.info(f"  ML Prediction: {prediction}")
        logger.info(f"  Confidence: {confidence:.1%}")
        logger.info(f"  Risk Level: {risk_level}")
        
        # Make decision (this will trigger auto-blocking)
        event = decision_engine.decide(
            domain=domain,
            destination_ip=ip,
            prediction=prediction,
            confidence=confidence,
            risk_level=risk_level,
            features_used=48,
            timestamp=datetime.now().timestamp()
        )
        
        # Log result
        logger.info(f"\n  Decision Engine Result:")
        logger.info(f"    Action: {event.action_taken}")
        logger.info(f"    Blocked: {event.blocked}")
        logger.info(f"    Reason: {event.reason}")
        
        if event.blocked:
            blocked_count += 1
            logger.critical(f"  🛑 DOMAIN BLOCKED FOR USER")
    
    # Verify blocking
    logger.info("\n[4/4] Verifying DNS Blocking...")
    final_blocklist = hosts_manager.get_blocklist()
    logger.info(f"  Final blocked domains: {len(final_blocklist)}")
    
    for entry in final_blocklist:
        if entry['domain'] in [d[0] for d in test_domains]:
            logger.critical(f"  ✓ VERIFIED BLOCKED: {entry['domain']} → {entry['ip']}")
    
    # Summary
    logger.info("\n" + "=" * 70)
    logger.info("📊 TEST SUMMARY")
    logger.info("=" * 70)
    logger.info(f"Test Domains: {len(test_domains)}")
    logger.info(f"Auto-Blocked: {blocked_count}")
    logger.info(f"Success Rate: {blocked_count}/{len(test_domains)}")
    
    if blocked_count == len(test_domains):
        logger.critical("\n✅ ALL TESTS PASSED - PHISHING LINKS WOULD BE BLOCKED!")
    else:
        logger.warning(f"\n⚠ {len(test_domains) - blocked_count} domains not blocked")
    
    logger.info("\n" + "=" * 70)
    logger.info("🛡️  WHAT THIS MEANS:")
    logger.info("=" * 70)
    logger.info("  If a user tries to visit a blocked domain:")
    logger.info("  1. Their browser will query DNS for the domain")
    logger.info("  2. DNS will resolve to 127.0.0.1 (localhost)")
    logger.info("  3. Connection fails - phishing page never loads")
    logger.info("  4. User sees 'site not found' error ✓")
    logger.info("\n" + "=" * 70)
    
    # Cleanup option
    response = input("\nClean up test blocks? (y/n): ").lower()
    if response == 'y':
        logger.info("\nCleaning up...")
        for domain, _ in test_domains:
            hosts_manager.unblock_domain(domain)
            logger.info(f"  ✓ Unblocked: {domain}")
    
    logger.info("\n" + "=" * 70)
    logger.info("✅ TEST COMPLETE")
    logger.info("=" * 70 + "\n")


def show_what_happens():
    """Show what happens when a domain is blocked"""
    logger.info("\n" + "=" * 70)
    logger.info("🔍 EXPLANATION: WHAT HAPPENS WHEN A LINK IS BLOCKED")
    logger.info("=" * 70)
    logger.info("""
USER CLICKS SUSPICIOUS LINK: paypal-verify.com
         ↓
[Your System Running]
         ↓
DNS QUERY CAPTURED
         ↓
FEATURES EXTRACTED (48 features)
         ↓
ML MODEL PREDICTS: 92% Phishing Confidence
         ↓
AUTO-BLOCK TRIGGERED (> 80% threshold)
         ↓
/etc/hosts MODIFIED:
  127.0.0.1 paypal-verify.com # PHISHING-DETECTOR-BLOCKED
         ↓
USER'S BROWSER:
  DNS lookup: "paypal-verify.com" 
  → Resolved to: 127.0.0.1 (localhost)
  → Cannot connect to localhost
  → Shows "Site not found" error
         ↓
✅ PHISHING PAGE NEVER LOADS
✅ USER PROTECTED
✅ NO PERSONAL DATA STOLEN

ADVANTAGE: Works at network layer BEFORE browser loads any page
    """)
    logger.info("=" * 70 + "\n")


if __name__ == "__main__":
    logger.info("\n")
    
    # Show explanation first
    show_what_happens()
    
    # Run test
    try:
        test_dns_blocking()
    except PermissionError:
        logger.error("\n❌ PERMISSION DENIED")
        logger.error("To test DNS blocking, you need root/admin access")
        logger.error("Run with: sudo python3 example_complete_blocking.py")
        logger.error("\nOr test without blocking: python3 example_complete_blocking.py --no-blocking")
    except KeyboardInterrupt:
        logger.info("\n\nTest cancelled by user")
    except Exception as e:
        logger.error(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
