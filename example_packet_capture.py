"""
Example usage of the Packet Capture Module

This script demonstrates:
1. How to initialize the real-time packet sniffer
2. How to register callbacks for different packet types
3. How to process DNS and TLS packets
4. Real-time detection setup

Run with: sudo python3 example_packet_capture.py
"""

import logging
import sys
import time
from pathlib import Path

# Add modules to path
sys.path.insert(0, str(Path(__file__).parent / "modules"))

from packet_capture import (
    RealTimePacketSniffer,
    DNSPacketData,
    TLSPacketData,
    TrafficFlowData,
    PacketCaptureConfig
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class PacketProcessor:
    """Example packet processor with detection logic"""
    
    def __init__(self):
        self.dns_queries = {}
        self.tls_handshakes = {}
    
    def process_dns(self, dns_data: DNSPacketData) -> None:
        """
        Process DNS packet
        
        Why these features matter for phishing detection:
        - Domain entropy: Phishing domains often have random characters
        - Query frequency: Phishing sites may probe multiple domains quickly
        - TTL: Phishing domains often use low TTL to avoid caching
        """
        print(f"\n[DNS] Domain: {dns_data.query_domain}")
        print(f"      Type: {dns_data.query_type}")
        print(f"      TTL: {dns_data.ttl}")
        print(f"      Size: {dns_data.packet_size} bytes")
        print(f"      Source: {dns_data.src_ip} -> {dns_data.dst_ip}")
        
        # Store for later analysis
        if dns_data.query_domain not in self.dns_queries:
            self.dns_queries[dns_data.query_domain] = []
        self.dns_queries[dns_data.query_domain].append(dns_data)
        
        # Early phishing indicators
        self._check_dns_anomalies(dns_data)
    
    def process_tls(self, tls_data: TLSPacketData) -> None:
        """
        Process TLS handshake packet
        
        Why these features matter for phishing detection:
        - SNI (Server Name Indication): Reveals intended domain before cert verification
        - Certificate issuer: Phishing sites often use self-signed or cheap certs
        - TLS version: Outdated TLS indicates suspicious sites
        - Cipher suites: Weak ciphers indicate suspicious configuration
        """
        print(f"\n[TLS] Connection: {tls_data.src_ip}:{tls_data.src_port} -> {tls_data.dst_ip}:{tls_data.dst_port}")
        print(f"      SNI: {tls_data.sni if tls_data.sni else 'N/A'}")
        print(f"      TLS Version: {tls_data.tls_version if tls_data.tls_version else 'N/A'}")
        print(f"      Size: {tls_data.packet_size} bytes")
        
        # Store for later analysis
        key = f"{tls_data.dst_ip}:{tls_data.dst_port}"
        if key not in self.tls_handshakes:
            self.tls_handshakes[key] = []
        self.tls_handshakes[key].append(tls_data)
        
        # Early phishing indicators
        self._check_tls_anomalies(tls_data)
    
    def process_traffic_flow(self, flow_data: TrafficFlowData) -> None:
        """
        Process traffic flow features
        
        Why these features matter for phishing detection:
        - Packet size sequence: Phishing sites may have unusual traffic patterns
        - Flow duration: Phishing detection should happen quickly
        - Inter-arrival time: Unusual timing indicates suspicious activity
        """
        # Only log TLS traffic for now
        if flow_data.protocol == "TCP" and flow_data.dst_port in [443, 8443]:
            print(f"\n[FLOW] {flow_data.protocol} {flow_data.src_ip}:{flow_data.src_port} -> {flow_data.dst_ip}:{flow_data.dst_port}")
            print(f"       Packet Size: {flow_data.packet_size} bytes, TTL: {flow_data.ttl}")
    
    def _check_dns_anomalies(self, dns_data: DNSPacketData) -> None:
        """Check for DNS-based phishing indicators"""
        anomalies = []
        
        # Check 1: Very low TTL (suspicious)
        if 0 < dns_data.ttl < 60:
            anomalies.append(f"Low TTL ({dns_data.ttl}s) - possible phishing")
        
        # Check 2: Domain entropy (simple check)
        if self._high_entropy_domain(dns_data.query_domain):
            anomalies.append("High entropy domain - possible phishing")
        
        if anomalies:
            print(f"      ⚠️  ANOMALIES: {', '.join(anomalies)}")
    
    def _check_tls_anomalies(self, tls_data: TLSPacketData) -> None:
        """Check for TLS-based phishing indicators"""
        anomalies = []
        
        # Check 1: Old TLS version
        if tls_data.tls_version and "1.0" in str(tls_data.tls_version):
            anomalies.append("Old TLS version - security risk")
        
        # Check 2: SNI mismatch (would need certificate comparison)
        if tls_data.sni:
            if self._suspicious_sni(tls_data.sni):
                anomalies.append("Suspicious SNI pattern - possible phishing")
        
        if anomalies:
            print(f"      ⚠️  ANOMALIES: {', '.join(anomalies)}")
    
    @staticmethod
    def _high_entropy_domain(domain: str) -> bool:
        """
        Simple heuristic: domains with random characters are suspicious
        Phishing domains often use: random.chars.com, xyjksd.com, etc.
        """
        import math
        
        # Remove TLD
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        main_part = parts[0]
        
        # Calculate Shannon entropy
        entropy = 0
        for char in set(main_part):
            p = main_part.count(char) / len(main_part)
            entropy -= p * math.log2(p)
        
        # High entropy (>4.5 bits) often indicates random domain
        return entropy > 4.5
    
    @staticmethod
    def _suspicious_sni(sni: str) -> bool:
        """
        Simple heuristic: check for suspicious SNI patterns
        """
        suspicious_patterns = [
            "bit.ly",  # URL shorteners (often used in phishing)
            "tinyurl",
            "goo.gl",
            "amazon-",  # Domain spoofing attempts
            "apple-",
            "google-",
            "microsoft-",
        ]
        
        sni_lower = sni.lower()
        return any(pattern in sni_lower for pattern in suspicious_patterns)


def main():
    """Main execution"""
    logger.info("Initializing Packet Capture Module")
    
    # Display available interfaces
    print("\n" + "="*60)
    print("AVAILABLE NETWORK INTERFACES")
    print("="*60)
    for i, iface in enumerate(PacketCaptureConfig.AVAILABLE_INTERFACES):
        print(f"{i}: {iface}")
    print("="*60)
    
    # Initialize sniffer (uses default interface)
    sniffer = RealTimePacketSniffer(
        interface=PacketCaptureConfig.DEFAULT_INTERFACE,
        packet_count=0  # Unlimited
    )
    
    # Initialize processor
    processor = PacketProcessor()
    
    # Register callbacks
    sniffer.register_callback('dns', processor.process_dns)
    sniffer.register_callback('tls', processor.process_tls)
    sniffer.register_callback('flow', processor.process_traffic_flow)
    
    # Start sniffing
    print(f"\n{'='*60}")
    print("STARTING PACKET SNIFFER")
    print(f"Interface: {sniffer.interface}")
    print(f"{'='*60}\n")
    print("Capturing packets... (Ctrl+C to stop)\n")
    
    sniffer.start()
    
    try:
        # Keep main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\nShutting down...")
        sniffer.stop()
        time.sleep(1)
        
        # Print statistics
        sniffer.print_stats()
        
        print(f"\nDNS Queries captured: {len(processor.dns_queries)}")
        print(f"TLS Handshakes captured: {len(processor.tls_handshakes)}")
        
        logger.info("Packet capture session complete")


if __name__ == "__main__":
    # Note: Requires root/admin privileges for packet capture
    # On macOS/Linux: sudo python3 example_packet_capture.py
    # On Windows: Run as Administrator
    
    main()
