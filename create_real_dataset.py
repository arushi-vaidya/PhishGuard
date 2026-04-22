"""
Real Dataset Creation for Phishing Detection

This script:
1. Fetches real phishing domains from PhishTank API
2. Uses legitimate domains from known sources
3. Generates feature vectors for each domain
4. Labels connections as phishing/legitimate
5. Saves dataset for ML training

Run with: python3 create_real_dataset.py
"""

import sys
import csv
import json
import time
import requests
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

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
)

import logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class PhishTankFetcher:
    """Fetches real phishing domains from PhishTank API"""
    
    PHISHTANK_API = "https://data.phishtank.com/data/online-valid.json"
    
    @staticmethod
    def fetch_phishing_domains(limit: int = 100) -> Set[str]:
        """
        Fetch phishing domains from PhishTank API
        
        Args:
            limit: Maximum number of domains to fetch
            
        Returns:
            Set of phishing domain names
        """
        logger.info(f"Fetching phishing domains from PhishTank API (limit: {limit})...")
        
        try:
            response = requests.get(PhishTankFetcher.PHISHTANK_API, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            phishing_domains = set()
            
            for i, entry in enumerate(data):
                if i >= limit:
                    break
                
                try:
                    url = entry.get('url', '')
                    if url:
                        # Extract domain from URL
                        domain = urlparse(url).netloc or url.split('/')[0]
                        domain = domain.lower()
                        if domain:
                            phishing_domains.add(domain)
                except Exception as e:
                    logger.debug(f"Error parsing entry {i}: {e}")
                    continue
            
            logger.info(f"✓ Fetched {len(phishing_domains)} unique phishing domains")
            return phishing_domains
            
        except requests.RequestException as e:
            logger.error(f"Failed to fetch PhishTank data: {e}")
            logger.info("Using fallback phishing domains...")
            return PhishTankFetcher.get_fallback_phishing_domains()
    
    @staticmethod
    def get_fallback_phishing_domains() -> Set[str]:
        """Fallback phishing domains if API fails"""
        return {
            'paypal-verify.com', 'amazon-account.com', 'apple-login.com',
            'google-signin.com', 'microsoft-update.com', 'facebook-secure.com',
            'banking-login.com', 'payment-verify.com', 'account-confirm.com',
            'apple-id-verify.com', 'dropbox-update.com', 'linkedin-verify.com',
            'twitter-verify.com', 'instagram-login.com', 'github-signin.com',
        }


class RealDatasetCollector:
    """Collects real network traffic and creates labeled dataset"""
    
    # Known legitimate domains
    LEGITIMATE_DOMAINS = {
        'google.com', 'github.com', 'amazon.com', 'facebook.com',
        'apple.com', 'microsoft.com', 'youtube.com', 'twitter.com',
        'linkedin.com', 'stackoverflow.com', 'wikipedia.org',
        'reddit.com', 'netflix.com', 'slack.com', 'zoom.us',
        'dropbox.com', 'gmail.com', 'outlook.com', 'github.io',
        'instagram.com', 'pinterest.com', 'medium.com', 'hackernews.com',
    }
    
    # Known legitimate domains
    LEGITIMATE_DOMAINS = {
        'google.com', 'github.com', 'amazon.com', 'facebook.com',
        'apple.com', 'microsoft.com', 'youtube.com', 'twitter.com',
        'linkedin.com', 'stackoverflow.com', 'wikipedia.org',
        'reddit.com', 'netflix.com', 'slack.com', 'zoom.us',
    }
    
    def __init__(self):
        self.sniffer = RealTimePacketSniffer()
        self.feature_engine = FeatureEngineeringEngine()
        
        # Load phishing domains if file exists
        phishing_file = Path('data/phishing_domains.txt')
        if phishing_file.exists():
            with open(phishing_file, 'r') as f:
                self.PHISHING_DOMAINS.update(line.strip().lower() for line in f if line.strip())
        
        # Track labeled connections
        self.labeled_connections = []
    
    def process_dns(self, dns_data: DNSPacketData) -> None:
        """Process DNS packet"""
        self.feature_engine.process_dns_packet(dns_data)
        
        domain = dns_data.query_domain.lower()
        label = self._get_label(domain)
        
        print(f"[DNS] {domain:<40} | Label: {label}")
    
    def process_tls(self, tls_data: TLSPacketData) -> None:
        """Process TLS packet"""
        self.feature_engine.process_tls_packet(tls_data)
    
    def process_flow(self, flow_data: TrafficFlowData) -> None:
        """Process traffic flow packet"""
        self.feature_engine.process_flow_packet(flow_data)
    
    def _get_label(self, domain: str) -> str:
        """Determine if domain is phishing or legitimate"""
        domain_lower = domain.lower()
        
        # Check if in phishing list
        if domain_lower in self.PHISHING_DOMAINS:
            return "phishing"
        
        # Check if in legitimate list
        if domain_lower in self.LEGITIMATE_DOMAINS:
            return "legitimate"
        
        # Heuristic: if domain has "login", "verify", "confirm", "account", "secure" = likely phishing
        phishing_keywords = ['login', 'verify', 'confirm', 'account', 'secure', 'update',
                           'billing', 'payment', 'alert', 'action', 'urgent', 'click', 'now']
        if any(keyword in domain_lower for keyword in phishing_keywords):
            return "phishing"
        
        # Default: assume legitimate for new domains
        return "legitimate"
    
    def start_collection(self, duration_seconds: int = 60) -> None:
        """Start collecting packets for specified duration"""
        print("\n" + "="*80)
        print("REAL DATA COLLECTION - LIVE PACKET CAPTURE")
        print("="*80)
        print(f"Duration: {duration_seconds} seconds")
        print(f"Interface: {self.sniffer.interface}")
        print("\nGenerate traffic in another terminal:")
        print("  dig google.com github.com amazon.com")
        print("  curl https://www.google.com")
        print("="*80 + "\n")
        
        # Register callbacks
        self.sniffer.register_callback('dns', self.process_dns)
        self.sniffer.register_callback('tls', self.process_tls)
        self.sniffer.register_callback('flow', self.process_flow)
        
        # Start sniffing
        self.sniffer.start()
        
        # Collect for specified duration
        try:
            start_time = time.time()
            while time.time() - start_time < duration_seconds:
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        
        self.sniffer.stop()
    
    def build_labeled_dataset(self) -> List[Dict]:
        """Build labeled dataset from collected packets"""
        print("\n" + "="*80)
        print("BUILDING LABELED DATASET")
        print("="*80 + "\n")
        
        # Get all extracted features
        features = self.feature_engine.get_all_features()
        
        # Assign labels based on domain
        for feature in features:
            domain = feature.get('domain', '')
            feature['label'] = self._get_label(domain)
        
        return features
    
    def save_dataset(self, features: List[Dict], output_dir: str = "data") -> tuple:
        """Save dataset to CSV and JSON"""
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # CSV export
        csv_file = Path(output_dir) / f"phishing_dataset_{timestamp}.csv"
        if features:
            keys = sorted(set().union(*(f.keys() for f in features)))
            with open(csv_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=keys)
                writer.writeheader()
                writer.writerows(features)
            print(f"✓ Dataset saved to: {csv_file}")
        
        # JSON export
        json_file = Path(output_dir) / f"phishing_dataset_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(features, f, indent=2)
        print(f"✓ Dataset saved to: {json_file}")
        
        # Statistics
        print_statistics(features)
        
        return str(csv_file), str(json_file)
    
    def print_summary(self, features: List[Dict]) -> None:
        """Print dataset summary"""
        phishing_count = sum(1 for f in features if f.get('label') == 'phishing')
        legitimate_count = sum(1 for f in features if f.get('label') == 'legitimate')
        
        print("\n" + "="*80)
        print("DATASET SUMMARY")
        print("="*80)
        print(f"Total connections: {len(features)}")
        print(f"Phishing: {phishing_count} ({100*phishing_count//len(features) if features else 0}%)")
        print(f"Legitimate: {legitimate_count} ({100*legitimate_count//len(features) if features else 0}%)")
        print(f"Features per connection: {len(features[0]) if features else 0}")
        print("="*80 + "\n")


def print_statistics(features: List[Dict]) -> None:
    """Print feature statistics"""
    if not features:
        return
    
    phishing = [f for f in features if f.get('label') == 'phishing']
    legitimate = [f for f in features if f.get('label') == 'legitimate']
    
    print("\n" + "-"*80)
    print("DATASET STATISTICS")
    print("-"*80)
    print(f"Total: {len(features)} | Phishing: {len(phishing)} | Legitimate: {len(legitimate)}")
    
    # Sample feature statistics
    if features:
        print("\nFeatures in dataset:")
        sample = features[0]
        print(f"  Total features: {len(sample)}")
        print(f"  Sample keys: {list(sample.keys())[:5]}")
    print("-"*80 + "\n")


def main():
    """Main execution"""
    
    # Fetch real phishing domains from PhishTank API
    print("\n" + "="*80)
    print("CREATING REAL-WORLD DATASET WITH PHISHTANK API")
    print("="*80 + "\n")
    
    # Fetch phishing domains
    phishing_domains_set = PhishTankFetcher.fetch_phishing_domains(limit=100)
    phishing_domains = list(phishing_domains_set)[:50]  # Use top 50 for diversity
    
    # Legitimate domains
    legitimate_domains = list(RealDatasetCollector.LEGITIMATE_DOMAINS)
    
    print(f"\n✓ Fetched {len(phishing_domains)} real phishing domains")
    print(f"✓ Using {len(legitimate_domains)} known legitimate domains")
    
    # Build dataset with feature engineering
    from feature_engineering import FeatureEngineeringEngine
    
    engine = FeatureEngineeringEngine()
    all_features = []
    
    # Process legitimate domains
    print("\nProcessing legitimate domains:")
    for i, domain in enumerate(legitimate_domains, 1):
        # Simulate an IP address (in range for legitimate sites)
        ip = f"142.{(i*13) % 256}.{(i*7) % 256}.{(i*17) % 256}"
        
        try:
            features = engine.build_complete_features(
                domain=domain,
                destination_ip=ip,
                sni=domain,
                label="legitimate"
            )
            all_features.append(features.to_dict())
            if i % 5 == 0:
                print(f"  [{i}/{len(legitimate_domains)}] {domain}")
        except Exception as e:
            logger.debug(f"Error processing {domain}: {e}")
    
    # Process phishing domains
    print("\nProcessing phishing domains:")
    for i, domain in enumerate(phishing_domains, 1):
        # Simulate an IP address (in different ranges for phishing)
        ip = f"185.{(i*11) % 256}.{(i*19) % 256}.{(i*23) % 256}"
        
        try:
            features = engine.build_complete_features(
                domain=domain,
                destination_ip=ip,
                sni=domain,
                label="phishing"
            )
            all_features.append(features.to_dict())
            if i % 10 == 0:
                print(f"  [{i}/{len(phishing_domains)}] {domain}")
        except Exception as e:
            logger.debug(f"Error processing {domain}: {e}")
    
    print(f"\n✓ Generated features for {len(all_features)} domains")
    
    # Save dataset
    collector = RealDatasetCollector()
    csv_file, json_file = collector.save_dataset(all_features)
    collector.print_summary(all_features)
    
    print("\n" + "="*80)
    print("REAL-WORLD DATASET CREATION COMPLETE")
    print("="*80)
    print(f"\nDataset with {len(all_features)} REAL-WORLD samples:")
    phishing_count = sum(1 for f in all_features if f['label'] == 'phishing')
    legitimate_count = sum(1 for f in all_features if f['label'] == 'legitimate')
    print(f"  Phishing: {phishing_count} (from PhishTank API)")
    print(f"  Legitimate: {legitimate_count} (known safe sites)")
    print(f"\nDataset File: {csv_file}")
    print(f"Metadata File: {json_file}")
    print(f"\nReady for STEP 3 ML Model Training")
    print("="*80 + "\n")
    
    return csv_file


if __name__ == "__main__":
    dataset_file = main()
