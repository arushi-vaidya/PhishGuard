"""
Real-Time Phishing Blocking System - Complete End-to-End Integration

This module integrates:
1. Packet capture (sniff network traffic)
2. Feature engineering (extract features)
3. ML inference (predict phishing)
4. Decision engine (decide on blocking)
5. DNS blocker (execute blocking)

Creates a complete, automatic phishing detection and blocking system.

Author: Research Team
Date: 2026
"""

import logging
import sys
import time
import threading
from typing import Optional, Dict, List
from pathlib import Path
from datetime import datetime

# Add modules to path
sys.path.insert(0, str(Path(__file__).parent))

from modules.packet_capture import RealTimePacketSniffer
from modules.feature_engineering import FeatureEngineeringEngine
from modules.realtime_engine import RealtimeInferenceEngine
from modules.decision_engine import DecisionEngine, DecisionPolicy
from modules.dns_blocker import get_hosts_manager

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class RealtimeBlockingSystem:
    """Complete real-time phishing detection and blocking system"""
    
    def __init__(
        self,
        model_path: str = "models/RandomForest_model.pkl",
        interface: str = "en0",
        timeout: int = 10,
        enable_dns_blocking: bool = True
    ):
        """
        Initialize the blocking system
        
        Args:
            model_path: Path to trained model metadata
            interface: Network interface to sniff (e.g., 'en0', 'eth0')
            timeout: How long to sniff packets (seconds)
            enable_dns_blocking: Whether to enable real DNS blocking
        """
        self.model_path = model_path
        self.interface = interface
        self.timeout = timeout
        self.enable_dns_blocking = enable_dns_blocking
        
        # Initialize components
        logger.info("=" * 70)
        logger.info("🚀 INITIALIZING PHISHING DETECTION & BLOCKING SYSTEM")
        logger.info("=" * 70)
        
        try:
            # 1. Packet sniffer
            logger.info("\n[1/5] Initializing Packet Sniffer...")
            self.packet_sniffer = RealTimePacketSniffer(interface)
            
            # 2. Feature engineering
            logger.info("[2/5] Initializing Feature Engineering Engine...")
            self.feature_engine = FeatureEngineeringEngine()
            
            # 3. ML inference
            logger.info("[3/5] Loading ML Model for Inference...")
            try:
                self.inference_engine = RealtimeInferenceEngine(model_path)
                logger.info("  ✓ ML model loaded for live inference")
            except Exception as e:
                logger.warning(f"  ⚠ Could not load ML model ({e}), falling back to heuristics")
                self.inference_engine = None
            
            # 4. Decision engine with blocking policy
            logger.info("[4/5] Initializing Decision Engine with Blocking Policy...")
            blocking_policy = DecisionPolicy(
                high_confidence_threshold=0.80,  # Block at 80%+ confidence
                low_confidence_threshold=0.60,   # Alert at 60%+ confidence
                block_phishing_high_confidence=True,  # AUTO-BLOCK high confidence phishing
                alert_phishing_any_confidence=True,   # Alert all phishing
                alert_legitimate_low_confidence=False
            )
            self.decision_engine = DecisionEngine(blocking_policy)
            
            # 5. DNS blocker
            logger.info("[5/5] Initializing DNS Blocker...")
            if enable_dns_blocking:
                self.hosts_manager = get_hosts_manager()
                logger.info("  ✓ DNS Blocker ready")
            else:
                logger.info("  ⚠ DNS Blocking disabled")
                self.hosts_manager = None
            
            # Tracking
            self.detected_phishing = []
            self.blocked_domains = []
            self.safe_domains = []
            
            logger.info("\n" + "=" * 70)
            logger.info("✓ SYSTEM READY FOR BLOCKING")
            logger.info("=" * 70)
            
        except Exception as e:
            logger.error(f"❌ Error initializing system: {e}")
            raise
    
    def run(self, timeout: Optional[int] = None) -> Dict:
        """
        Run the complete blocking system
        
        Args:
            timeout: Override timeout (seconds)
            
        Returns:
            Dictionary with statistics
        """
        timeout = timeout or self.timeout
        
        logger.info("\n" + "=" * 70)
        logger.info(f"🔍 MONITORING NETWORK TRAFFIC FOR {timeout} SECONDS")
        logger.info(f"   Interface: {self.interface}")
        logger.info(f"   DNS Blocking: {'ENABLED ✓' if self.enable_dns_blocking else 'DISABLED'}")
        logger.info(f"   High Confidence Threshold: 80%")
        logger.info("=" * 70)
        logger.info("\nPress Ctrl+C to stop\n")
        
        try:
            # Register callbacks for packet types
            self.packet_sniffer.register_callback('dns', self._process_dns_traffic)
            self.packet_sniffer.register_callback('tls', self._process_tls_traffic)
            
            # Start packet capture
            start_time = time.time()
            self.packet_sniffer.start()
            
            # Let it run for timeout seconds
            while time.time() - start_time < timeout:
                time.sleep(0.1)
            
            # Stop capture
            self.packet_sniffer.stop()
            
            # Summary
            return self._print_summary(time.time() - start_time)
            
        except KeyboardInterrupt:
            logger.info("\n\n⏹ Capture stopped by user")
            self.packet_sniffer.stop()
            return self._print_summary(time.time() - start_time)
        except Exception as e:
            logger.error(f"❌ Error during capture: {e}")
            self.packet_sniffer.stop()
            raise
    
    def _process_dns_traffic(self, dns_data):
        """Process DNS traffic and make blocking decision"""
        try:
            domain = dns_data.get('domain', '') if isinstance(dns_data, dict) else getattr(dns_data, 'domain', '')
            if not domain:
                return
            
            # Increment packet counter
            self.packet_num = getattr(self, 'packet_num', 0) + 1
            
            logger.info(f"\n[Packet #{self.packet_num}] DNS Query: {domain}")
            
            # Skip already processed
            if domain in self.safe_domains or domain in self.blocked_domains:
                logger.info(f"  (Already processed)")
                return
            
            # Process DNS packet through feature engine
            self.feature_engine.process_dns_packet(dns_data)

            ip = dns_data.get('source_ip', '0.0.0.0') if isinstance(dns_data, dict) else getattr(dns_data, 'source_ip', '0.0.0.0')

            # Use ML model if loaded, otherwise fall back to heuristics
            if self.inference_engine is not None:
                result = self.inference_engine.predict(domain, ip)
                prediction, confidence, risk_level = result.prediction, result.confidence, result.risk_level
            else:
                prediction, confidence, risk_level = self._demo_predict(dns_data)

            # Make decision
            event = self.decision_engine.decide(
                domain=domain,
                destination_ip=ip,
                prediction=prediction,
                confidence=confidence,
                risk_level=risk_level,
                features_used=48,  # Default feature count
                timestamp=datetime.now().timestamp()
            )
            
            # Track
            if event.blocked:
                self.blocked_domains.append(domain)
                logger.critical(f"  🛑 BLOCKED: {domain}")
            else:
                if prediction == "phishing":
                    self.detected_phishing.append((domain, confidence))
                    logger.warning(f"  ⚠ ALERT: {domain} ({confidence:.1%})")
                else:
                    self.safe_domains.append(domain)
                    logger.info(f"  ✓ SAFE: {domain}")
            
        except Exception as e:
            logger.error(f"  ✗ Error processing DNS: {e}")
    
    def _process_tls_traffic(self, tls_data):
        """Process TLS traffic and make blocking decision"""
        try:
            domain = tls_data.get('sni', '') if isinstance(tls_data, dict) else getattr(tls_data, 'sni', '')
            if not domain:
                return
            
            # Increment packet counter
            self.packet_num = getattr(self, 'packet_num', 0) + 1
            
            logger.info(f"\n[Packet #{self.packet_num}] TLS SNI: {domain}")
            
            # Skip already processed
            if domain in self.safe_domains or domain in self.blocked_domains:
                logger.info(f"  (Already processed)")
                return
            
            # Process TLS packet through feature engine
            self.feature_engine.process_tls_packet(tls_data)

            ip = tls_data.get('source_ip', '0.0.0.0') if isinstance(tls_data, dict) else getattr(tls_data, 'source_ip', '0.0.0.0')

            # Use ML model if loaded, otherwise fall back to heuristics
            if self.inference_engine is not None:
                result = self.inference_engine.predict(domain, ip, sni=domain)
                prediction, confidence, risk_level = result.prediction, result.confidence, result.risk_level
            else:
                prediction, confidence, risk_level = self._demo_predict_tls(tls_data)

            # Make decision
            event = self.decision_engine.decide(
                domain=domain,
                destination_ip=ip,
                prediction=prediction,
                confidence=confidence,
                risk_level=risk_level,
                features_used=48,  # Default feature count
                timestamp=datetime.now().timestamp()
            )
            
            # Track
            if event.blocked:
                self.blocked_domains.append(domain)
                logger.critical(f"  🛑 BLOCKED: {domain}")
            else:
                if prediction == "phishing":
                    self.detected_phishing.append((domain, confidence))
                    logger.warning(f"  ⚠ ALERT: {domain} ({confidence:.1%})")
                else:
                    self.safe_domains.append(domain)
                    logger.info(f"  ✓ SAFE: {domain}")
            
        except Exception as e:
            logger.error(f"  ✗ Error processing TLS: {e}")
    
    def _clean_sni(self, sni: str) -> str:
        """Aggressively clean SNI to extract valid domain name"""
        if not sni:
            return ""
        
        sni = str(sni).strip()
        
        # Remove common protocol/header garbage that appears in binary packets
        garbage_patterns = ['http/1.1', 'h2c', 'h2+', 'h2', '%#', '#%#', '::', '#']
        for pattern in garbage_patterns:
            sni = sni.replace(pattern, ' ')
        
        # Extract only ASCII alphanumeric, dots, hyphens
        # Stop at first non-ASCII or whitespace character (indicates binary data)
        cleaned = ""
        for c in sni:
            # Stop if we hit non-ASCII (corrupted packet data)
            if ord(c) > 127:
                break
            # Stop if we hit whitespace or control characters
            if c in '\n\r\t ' and cleaned:
                break
            # Keep valid domain characters
            if c.isalnum() or c in '.-':
                cleaned += c
        
        cleaned = cleaned.strip('.-')
        
        # Must contain at least one dot and be reasonable length
        if '.' not in cleaned or len(cleaned) < 4 or len(cleaned) > 253:
            return ""
        
        # Check if it looks like a domain
        parts = cleaned.split('.')
        if len(parts) < 2:
            return ""
        
        # Each part must be alphanumeric + hyphens, not pure numbers
        for part in parts:
            if not part or len(part) > 63:
                return ""
            if not any(c.isalpha() for c in part):  # Must have at least one letter
                return ""
        
        return cleaned
    
    def _get_value(self, obj, key: str, default=''):
        """Safely get value from dict or dataclass, cleaning non-printable chars"""
        if isinstance(obj, dict):
            val = obj.get(key, default)
        else:
            val = getattr(obj, key, default)
        
        # Clean SNI specially
        if val and key == 'sni':
            cleaned = self._clean_sni(val)
            return cleaned if cleaned else default
        
        return val
    
    def _demo_predict(self, dns_data) -> tuple:
        """Demo prediction based on DNS patterns"""
        domain = self._get_value(dns_data, 'domain', '').lower().strip()
        
        # Extended phishing indicators
        phishing_indicators = [
            'verify', 'confirm', 'update', 'urgent', 'alert', 'action',
            'paypal', 'amazon', 'apple', 'microsoft', 'google', 'bank',
            'secure', 'login', 'account', 'password', 'reset', 'click'
        ]
        
        # High-confidence phishing patterns
        if any(x in domain for x in ['verify-paypal', 'confirm-amazon', 'update-apple', 'verify-apple']):
            return "phishing", 0.95, "high"
        
        # Check for multiple phishing keywords
        matching_indicators = sum(1 for ind in phishing_indicators if ind in domain)
        if matching_indicators >= 2:
            return "phishing", 0.85, "high"
        elif matching_indicators == 1:
            if any(keyword in domain for keyword in ['verify', 'confirm', 'urgent']):
                return "phishing", 0.82, "high"
            else:
                return "phishing", 0.70, "medium"
        
        return "legitimate", 0.95, "low"
    
    def _demo_predict_tls(self, tls_data) -> tuple:
        """Demo prediction based on TLS patterns - only flag OBVIOUS phishing"""
        sni = self._get_value(tls_data, 'sni', '').lower().strip()
        
        # Skip empty SNI or very short domains
        if not sni or len(sni) < 4:
            return "legitimate", 0.85, "low"
        
        # Known phishing patterns - VERY specific
        high_confidence_phishing = [
            'verify-paypal', 'confirm-paypal', 'update-paypal',
            'verify-amazon', 'confirm-amazon', 'update-amazon',
            'verify-apple', 'confirm-apple', 'update-apple',
            'paypal-verify', 'paypal-confirm', 'amazon-verify', 'amazon-confirm',
            'apple-verify', 'apple-confirm', 'phishing-site', 'fake-',
            'account-verify', 'login-verify', 'secure-verify'
        ]
        
        # Check for high-confidence phishing patterns
        for pattern in high_confidence_phishing:
            if pattern in sni:
                return "phishing", 0.95, "high"
        
        # Medium confidence indicators - only with confirm/verify keywords
        if any(kw in sni for kw in ['verify', 'confirm', 'urgent']):
            # But NOT if it's a known legitimate domain
            known_legit = ['githubcopilot', 'microsoft', 'google', 'apple', 'amazon', 'paypal', 'facebook', 'twitter', 'github']
            if not any(legit in sni for legit in known_legit):
                # Unknown domain with verify/confirm/urgent = suspicious
                return "phishing", 0.75, "medium"
        
        # Everything else is legitimate
        return "legitimate", 0.92, "low"
    
    def _print_summary(self, elapsed_time: float) -> Dict:
        """Print final summary"""
        summary = {
            'total_time': elapsed_time,
            'safe_domains': len(self.safe_domains),
            'detected_phishing': len(self.detected_phishing),
            'blocked_domains': len(self.blocked_domains),
            'decision_stats': self.decision_engine.stats
        }
        
        logger.info("\n" + "=" * 70)
        logger.info("📊 FINAL SUMMARY")
        logger.info("=" * 70)
        logger.info(f"Elapsed Time: {elapsed_time:.1f}s")
        logger.info(f"Safe Domains: {len(self.safe_domains)}")
        logger.info(f"Detected Phishing: {len(self.detected_phishing)}")
        logger.info(f"Blocked Domains: {len(self.blocked_domains)} 🛑")
        
        if self.blocked_domains:
            logger.info(f"\nBlocked Domains:")
            for domain in self.blocked_domains:
                logger.info(f"  - {domain}")
        
        if self.detected_phishing:
            logger.info(f"\nDetected (Not Blocked):")
            for domain, conf in self.detected_phishing:
                logger.info(f"  - {domain} ({conf:.1%})")
        
        logger.info("\n" + "=" * 70)
        logger.info(f"Decision Stats: {summary['decision_stats']}")
        logger.info("=" * 70 + "\n")
        
        return summary


def main():
    """Main entry point"""
    import argparse
    from scapy.all import conf
    
    parser = argparse.ArgumentParser(description="Real-Time Phishing Detection and Blocking System")
    parser.add_argument('--interface', default=None, help='Network interface to sniff (default: system default)')
    parser.add_argument('--timeout', type=int, default=10, help='Capture timeout (seconds)')
    parser.add_argument('--no-blocking', action='store_true', help='Disable DNS blocking')
    parser.add_argument('--model', default='models/RandomForest_model.pkl', help='Path to model .pkl file')
    
    args = parser.parse_args()
    
    # Use system default interface if not specified
    interface = args.interface or conf.iface
    
    try:
        # Create system
        system = RealtimeBlockingSystem(
            model_path=args.model,
            interface=interface,
            timeout=args.timeout,
            enable_dns_blocking=not args.no_blocking
        )
        
        # Run
        results = system.run()
        
        # Return results
        return results
        
    except KeyboardInterrupt:
        logger.info("\n\nShutdown requested")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
