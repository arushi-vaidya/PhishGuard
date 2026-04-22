"""
Example usage of Feature Engineering Module

This script demonstrates:
1. Collecting packets from packet capture
2. Extracting DNS, TLS, and traffic flow features
3. Building complete feature sets for training
4. Exporting features to CSV for ML

Run with: python3 example_feature_engineering.py
"""

import sys
import json
import csv
from pathlib import Path
from datetime import datetime

# Add modules to path
sys.path.insert(0, str(Path(__file__).parent / "modules"))

from packet_capture import (
    RealTimePacketSniffer,
    DNSPacketData,
    TLSPacketData,
    TrafficFlowData,
    PacketCaptureConfig
)
from feature_engineering import (
    FeatureEngineeringEngine,
    FeatureNormalizer
)

import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FeatureCollectionPipeline:
    """Collects packets and extracts features in real-time"""
    
    def __init__(self, phishing_domains_file: str = None):
        """
        Initialize feature collection pipeline
        
        Args:
            phishing_domains_file: Path to file with known phishing domains
        """
        # Load phishing domains
        phishing_domains = []
        if phishing_domains_file and Path(phishing_domains_file).exists():
            with open(phishing_domains_file, 'r') as f:
                phishing_domains = [line.strip() for line in f if line.strip()]
        
        # Initialize components
        self.sniffer = RealTimePacketSniffer(
            interface=PacketCaptureConfig.DEFAULT_INTERFACE
        )
        self.feature_engine = FeatureEngineeringEngine(phishing_domains)
        
        # Tracking
        self.packets_processed = 0
        self.features_generated = 0
    
    def process_dns(self, dns_data: DNSPacketData) -> None:
        """Handle DNS packet"""
        self.feature_engine.process_dns_packet(dns_data)
        self.packets_processed += 1
        
        print(f"\n[DNS PROCESSED] {dns_data.query_domain}")
        print(f"  TTL: {dns_data.ttl}, Type: {dns_data.query_type}")
        print(f"  Packets processed: {self.packets_processed}")
    
    def process_tls(self, tls_data: TLSPacketData) -> None:
        """Handle TLS packet"""
        self.feature_engine.process_tls_packet(tls_data)
        self.packets_processed += 1
        
        sni_info = f"SNI: {tls_data.sni}" if tls_data.sni else "SNI: N/A"
        print(f"\n[TLS PROCESSED] {tls_data.dst_ip}:{tls_data.dst_port}")
        print(f"  {sni_info}")
        print(f"  Packets processed: {self.packets_processed}")
    
    def process_flow(self, flow_data: TrafficFlowData) -> None:
        """Handle traffic flow packet"""
        self.feature_engine.process_flow_packet(flow_data)
        self.packets_processed += 1
    
    def start(self) -> None:
        """Start packet capture and feature extraction"""
        print("\n" + "="*60)
        print("FEATURE ENGINEERING PIPELINE")
        print("="*60)
        print(f"Interface: {self.sniffer.interface}")
        print(f"Collecting packets and extracting features...")
        print("="*60 + "\n")
        
        # Register callbacks
        self.sniffer.register_callback('dns', self.process_dns)
        self.sniffer.register_callback('tls', self.process_tls)
        self.sniffer.register_callback('flow', self.process_flow)
        
        # Start sniffing
        self.sniffer.start()
    
    def stop(self) -> None:
        """Stop packet capture and export features"""
        self.sniffer.stop()
        
        print("\n\nExtracting features from collected packets...")
        
        # Build features
        all_features = self.feature_engine.get_all_features()
        self.features_generated = len(all_features)
        
        print(f"Generated {self.features_generated} feature sets\n")
        
        # Display sample features
        if all_features:
            print("="*60)
            print("SAMPLE FEATURE SET")
            print("="*60)
            sample = all_features[0]
            for key, value in list(sample.items())[:10]:
                print(f"  {key}: {value}")
            print(f"  ... ({len(sample) - 10} more features)")
            print("="*60 + "\n")
        
        # Export to CSV
        self.export_to_csv(all_features)
        
        # Display statistics
        self.print_statistics()
    
    def export_to_csv(self, features: list, output_file: str = "data/extracted_features.csv") -> None:
        """Export features to CSV file"""
        if not features:
            logger.warning("No features to export")
            return
        
        # Create data directory if needed
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        
        # Get all keys
        all_keys = set()
        for feature_dict in features:
            all_keys.update(feature_dict.keys())
        
        # Write CSV
        try:
            with open(output_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=sorted(all_keys))
                writer.writeheader()
                writer.writerows(features)
            
            logger.info(f"Features exported to {output_file}")
            print(f"✓ Features exported to {output_file}")
        except Exception as e:
            logger.error(f"Error exporting features: {e}")
    
    def export_to_json(self, features: list, output_file: str = "data/extracted_features.json") -> None:
        """Export features to JSON file"""
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(features, f, indent=2)
        
        logger.info(f"Features exported to {output_file}")
        print(f"✓ Features exported to {output_file}")
    
    def print_statistics(self) -> None:
        """Print collection statistics"""
        sniffer_stats = self.sniffer.get_stats()
        
        print("\n" + "="*60)
        print("FEATURE EXTRACTION STATISTICS")
        print("="*60)
        print(f"Total packets captured: {sniffer_stats['packets_captured']}")
        print(f"DNS packets: {sniffer_stats['dns_packets']}")
        print(f"TLS packets: {sniffer_stats['tls_packets']}")
        print(f"Flow packets: {sniffer_stats['flow_packets']}")
        print(f"\nFeature sets generated: {self.features_generated}")
        print("="*60 + "\n")


def example_offline_feature_extraction():
    """Example: Extract features from stored packet data"""
    from feature_engineering import (
        FeatureEngineeringEngine,
        DNSFeatureExtractor,
        TLSFeatureExtractor,
        TrafficFlowFeatureExtractor
    )
    
    print("\n" + "="*60)
    print("OFFLINE FEATURE EXTRACTION EXAMPLE")
    print("="*60 + "\n")
    
    # Create fake packet data
    dns_data = DNSPacketData(
        timestamp=datetime.now().timestamp(),
        src_ip="192.168.1.100",
        dst_ip="8.8.8.8",
        query_domain="suspicious-domain-xyza123.com",
        query_type="A",
        ttl=60,
        packet_size=55
    )
    
    tls_data = TLSPacketData(
        timestamp=datetime.now().timestamp(),
        src_ip="192.168.1.100",
        dst_ip="185.25.51.205",
        src_port=54321,
        dst_port=443,
        sni="suspicious-domain-xyza123.com",
        tls_version="TLS 1.0",
        cipher_suites=None,
        packet_size=516
    )
    
    flow_data = [
        TrafficFlowData(
            timestamp=datetime.now().timestamp() + i*0.01,
            src_ip="192.168.1.100",
            dst_ip="185.25.51.205",
            src_port=54321,
            dst_port=443,
            protocol="TCP",
            packet_size=1460 if i > 0 else 66,
            ttl=64
        )
        for i in range(5)
    ]
    
    # Extract features
    engine = FeatureEngineeringEngine()
    
    engine.process_dns_packet(dns_data)
    engine.process_tls_packet(tls_data)
    for fp in flow_data:
        engine.process_flow_packet(fp)
    
    # Build complete feature set
    features = engine.build_complete_features(
        domain="suspicious-domain-xyza123.com",
        destination_ip="185.25.51.205",
        sni="suspicious-domain-xyza123.com",
        label=None
    )
    
    print("EXTRACTED FEATURES:")
    print("-" * 60)
    
    feature_dict = features.to_dict()
    for key, value in sorted(feature_dict.items()):
        if value is not None:
            # Format value nicely
            if isinstance(value, float):
                value = f"{value:.4f}"
            print(f"  {key}: {value}")
    
    print("-" * 60 + "\n")
    
    # Highlight suspicious indicators
    print("SUSPICIOUS INDICATORS DETECTED:")
    print("-" * 60)
    
    if features.dns_features:
        if features.dns_features.domain_entropy > 4.5:
            print(f"✗ High domain entropy: {features.dns_features.domain_entropy:.2f}")
        if features.dns_features.ttl_value < 60:
            print(f"✗ Low TTL: {features.dns_features.ttl_value}")
    
    if features.tls_features:
        if features.tls_features.is_outdated_tls:
            print(f"✗ Outdated TLS version: {features.tls_features.tls_version}")
        if features.tls_features.has_sni_spoofing:
            print(f"✗ Possible SNI spoofing detected")
    
    print("-" * 60 + "\n")


def main():
    """Main execution"""
    import time
    
    # Example 1: Offline feature extraction (no sudo required)
    print("\n[1] Running offline feature extraction example...")
    example_offline_feature_extraction()
    
    # Example 2: Live feature extraction (requires sudo)
    print("[2] Live feature extraction (REQUIRES SUDO)")
    print("\nTo collect features from live traffic, run:")
    print("  sudo python3 example_feature_engineering.py --live")
    print("\nThen in another terminal, generate traffic:")
    print("  dig google.com")
    print("  curl https://example.com")
    
    if len(sys.argv) > 1 and sys.argv[1] == '--live':
        print("\n" + "="*60)
        print("STARTING LIVE FEATURE COLLECTION")
        print("="*60)
        
        pipeline = FeatureCollectionPipeline()
        pipeline.start()
        
        try:
            print("\nCollecting features... (Ctrl+C to stop)")
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n\nStopping feature collection...")
            pipeline.stop()


if __name__ == "__main__":
    main()
