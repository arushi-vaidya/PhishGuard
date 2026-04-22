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
        model_path: str = "models/RandomForest_metadata.json",
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
            except:
                logger.warning("  ⚠ Could not load model, creating demo inference engine")
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
            # Start packet capture
            start_time = time.time()
            packet_count = 0
            
            while time.time() - start_time < timeout:
                # Capture packets
                packets = self.packet_sniffer.sniff_packets(timeout=1, packet_count=10)
                
                if not packets:
                    continue
                
                # Process each packet
                for packet in packets:
                    packet_count += 1
                    
                    # Process packet
                    dns_data, tls_data, flow_data = self.packet_sniffer.processor.process_packet(packet)
                    
                    # Check each data type
                    if dns_data:
                        self._process_dns_traffic(dns_data, packet_count)
                    
                    if tls_data:
                        self._process_tls_traffic(tls_data, packet_count)
            
            # Summary
            return self._print_summary(time.time() - start_time)
            
        except KeyboardInterrupt:
            logger.info("\n\n⏹ Capture stopped by user")
            return self._print_summary(time.time() - start_time)
        except Exception as e:
            logger.error(f"❌ Error during capture: {e}")
            raise
    
    def _process_dns_traffic(self, dns_data: Dict, packet_num: int):
        """Process DNS traffic and make blocking decision"""
        try:
            domain = dns_data.get('domain', '')
            if not domain:
                return
            
            logger.info(f"\n[Packet #{packet_num}] DNS Query: {domain}")
            
            # Skip already processed
            if domain in self.safe_domains or domain in self.blocked_domains:
                logger.info(f"  (Already processed)")
                return
            
            # Extract features
            features = self.feature_engine.extract_features_from_dns(dns_data)
            
            # Predict
            if self.inference_engine:
                prediction_result = self.inference_engine.predict([features])
                prediction = prediction_result.prediction
                confidence = prediction_result.confidence
                risk_level = prediction_result.risk_level
            else:
                # Demo mode - simple heuristic
                prediction, confidence, risk_level = self._demo_predict(dns_data)
            
            # Make decision
            event = self.decision_engine.decide(
                domain=domain,
                destination_ip=dns_data.get('source_ip', '0.0.0.0'),
                prediction=prediction,
                confidence=confidence,
                risk_level=risk_level,
                features_used=len(features),
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
    
    def _process_tls_traffic(self, tls_data: Dict, packet_num: int):
        """Process TLS traffic and make blocking decision"""
        try:
            domain = tls_data.get('sni', '')
            if not domain:
                return
            
            logger.info(f"\n[Packet #{packet_num}] TLS SNI: {domain}")
            
            # Skip already processed
            if domain in self.safe_domains or domain in self.blocked_domains:
                logger.info(f"  (Already processed)")
                return
            
            # Extract features
            features = self.feature_engine.extract_features_from_tls(tls_data)
            
            # Predict
            if self.inference_engine:
                prediction_result = self.inference_engine.predict([features])
                prediction = prediction_result.prediction
                confidence = prediction_result.confidence
                risk_level = prediction_result.risk_level
            else:
                # Demo mode
                prediction, confidence, risk_level = self._demo_predict_tls(tls_data)
            
            # Make decision
            event = self.decision_engine.decide(
                domain=domain,
                destination_ip=tls_data.get('source_ip', '0.0.0.0'),
                prediction=prediction,
                confidence=confidence,
                risk_level=risk_level,
                features_used=len(features),
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
    
    def _demo_predict(self, dns_data: Dict) -> tuple:
        """Demo prediction based on DNS patterns"""
        domain = dns_data.get('domain', '').lower()
        
        # Check for common phishing patterns
        phishing_indicators = ['verify', 'confirm', 'update', 'urgent', 'paypal', 'amazon', 'apple', 'bank']
        
        if any(indicator in domain for indicator in phishing_indicators):
            if 'verify' in domain or 'confirm' in domain:
                return "phishing", 0.85, "high"
            else:
                return "phishing", 0.70, "medium"
        
        return "legitimate", 0.95, "low"
    
    def _demo_predict_tls(self, tls_data: Dict) -> tuple:
        """Demo prediction based on TLS patterns"""
        sni = tls_data.get('sni', '').lower()
        
        # Check for SNI mismatch
        if tls_data.get('sni_mismatch'):
            return "phishing", 0.82, "high"
        
        # Check certificate issuer
        issuer = tls_data.get('issuer', '').lower()
        if 'selfsigned' in issuer or 'unknown' in issuer:
            return "phishing", 0.75, "medium"
        
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
    
    parser = argparse.ArgumentParser(description="Real-Time Phishing Detection and Blocking System")
    parser.add_argument('--interface', default='en0', help='Network interface to sniff')
    parser.add_argument('--timeout', type=int, default=10, help='Capture timeout (seconds)')
    parser.add_argument('--no-blocking', action='store_true', help='Disable DNS blocking')
    parser.add_argument('--model', default='models/RandomForest_metadata.json', help='Model path')
    
    args = parser.parse_args()
    
    try:
        # Create system
        system = RealtimeBlockingSystem(
            model_path=args.model,
            interface=args.interface,
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
