#!/usr/bin/env python3
"""
STEP 6: Dataset Expansion with Gemini Verification

Collects 100+ domains from PhishTank and verifies with Gemini API
for ground-truth labels.

Features:
- Fetches phishing domains from PhishTank API
- Verifies each domain using Gemini (yes/no phishing)
- Collects legitimate domains from known safe sites
- Cross-validates PhishTank labels with Gemini
- Generates feature vectors for ML training

Usage:
    export GEMINI_API_KEY='your-api-key'
    python3 create_expanded_dataset.py
"""

import sys
from pathlib import Path
import json
import csv
import logging
from datetime import datetime
import time

sys.path.insert(0, str(Path(__file__).parent / "modules"))

from feature_engineering import FeatureEngineeringEngine
from gemini_verification import get_verifier

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ExpandedDatasetCollector:
    """Collects expanded dataset with Gemini verification"""
    
    def __init__(self):
        """Initialize collector"""
        self.feature_engine = FeatureEngineeringEngine()
        self.gemini_verifier = get_verifier()
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.datasets = {
            'phishing': [],
            'legitimate': [],
            'verified': []  # Contains verification source and labels
        }
    
    def get_phishtank_domains(self, limit: int = 100) -> list:
        """Fetch phishing domains from PhishTank API"""
        import requests
        
        logger.info(f"Fetching {limit} phishing domains from PhishTank API...")
        
        try:
            # PhishTank API
            url = "https://data.phishtank.com/data/online-valid.json"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            domains = []
            
            for entry in data[:limit]:
                domain = entry.get("url", "")
                if domain:
                    # Extract domain from URL
                    try:
                        from urllib.parse import urlparse
                        parsed = urlparse(domain)
                        domain_name = parsed.netloc or domain.split('/')[2]
                        if domain_name and '.' in domain_name:
                            domains.append(domain_name)
                    except:
                        pass
            
            logger.info(f"✅ Fetched {len(domains)} phishing domains from PhishTank")
            return domains
            
        except Exception as e:
            logger.warning(f"PhishTank API error: {e}. Using fallback domains...")
            return self.get_fallback_phishing_domains()
    
    def get_fallback_phishing_domains(self) -> list:
        """Fallback phishing domains"""
        return [
            "paypal-verify.com",
            "amazon-account-update.com",
            "apple-id-verify.com",
            "microsoft-security-check.com",
            "google-signin-security.com",
            "facebook-login-verify.com",
            "bank-of-america-security.com",
            "wells-fargo-update.com",
            "chase-banking-secure.com",
            "citibank-signin.com",
            "linkedin-profile-verify.com",
            "dropbox-verify-account.com",
            "onedrive-login-secure.com",
            "icloud-apple-verify.com",
            "spotify-account-verify.com",
            "netflix-update-verify.com",
            "uber-verify-account.com",
            "airbnb-security-check.com",
            "payoneer-verify.com",
            "stripe-verify-account.com",
        ]
    
    def get_legitimate_domains(self) -> list:
        """Known legitimate domains"""
        return [
            "google.com",
            "gmail.com",
            "youtube.com",
            "facebook.com",
            "instagram.com",
            "twitter.com",
            "linkedin.com",
            "github.com",
            "stackoverflow.com",
            "wikipedia.org",
            "amazon.com",
            "ebay.com",
            "apple.com",
            "microsoft.com",
            "netflix.com",
            "spotify.com",
            "reddit.com",
            "medium.com",
            "wordpress.com",
            "wordpress.org",
            "weebly.com",
            "wix.com",
            "shopify.com",
            "stripe.com",
            "paypal.com",
            "zendesk.com",
            "salesforce.com",
            "slack.com",
            "discord.com",
            "twitch.tv",
        ]
    
    def verify_domains_with_gemini(self, domains: list, label: str) -> list:
        """
        Verify domains using Gemini
        
        Args:
            domains: List of domains to verify
            label: "phishing" or "legitimate"
            
        Returns:
            List of (domain, gemini_label, confidence, reason) tuples
        """
        verified = []
        logger.info(f"\n🤖 Verifying {len(domains)} {label} domains with Gemini API...")
        
        for i, domain in enumerate(domains, 1):
            try:
                print(f"[{i}/{len(domains)}] {domain:40}", end=" ", flush=True)
                
                result = self.gemini_verifier.verify_domain(domain)
                gemini_label = "phishing" if result.is_phishing else "legitimate"
                
                verified.append({
                    'domain': domain,
                    'phishtank_label': label,
                    'gemini_label': gemini_label,
                    'gemini_confidence': result.confidence,
                    'gemini_reasoning': result.reasoning,
                    'match': (label == gemini_label)  # Does PhishTank match Gemini?
                })
                
                status = "✅" if result.is_phishing else "❌"
                print(f"| {status} {gemini_label:12} | Conf: {result.confidence:.0%}")
                
                # Rate limiting
                time.sleep(0.3)
                
            except Exception as e:
                logger.error(f"Error verifying {domain}: {e}")
                verified.append({
                    'domain': domain,
                    'phishtank_label': label,
                    'gemini_label': 'unknown',
                    'gemini_confidence': 0.0,
                    'gemini_reasoning': f"Error: {str(e)}",
                    'match': False
                })
        
        return verified
    
    def create_dataset(self, phishing_limit: int = 50, legitimate_limit: int = 50) -> None:
        """
        Create expanded dataset with Gemini verification
        
        Args:
            phishing_limit: Number of phishing domains
            legitimate_limit: Number of legitimate domains
        """
        print("\n" + "="*80)
        print("STEP 6: EXPANDED DATASET WITH GEMINI VERIFICATION")
        print("="*80)
        
        # Fetch domains
        print("\n[PHASE 1] Fetching domains...")
        phishing_domains = self.get_phishtank_domains(limit=phishing_limit)
        legitimate_domains = self.get_legitimate_domains()[:legitimate_limit]
        
        print(f"  Phishing domains: {len(phishing_domains)}")
        print(f"  Legitimate domains: {len(legitimate_domains)}")
        
        # Verify with Gemini
        print("\n[PHASE 2] Gemini Verification...")
        phishing_verified = self.verify_domains_with_gemini(phishing_domains, "phishing")
        legit_verified = self.verify_domains_with_gemini(legitimate_domains, "legitimate")
        
        all_verified = phishing_verified + legit_verified
        
        # Statistics
        print("\n[PHASE 3] Verification Statistics...")
        phishing_match = sum(1 for v in phishing_verified if v['match'])
        legit_match = sum(1 for v in legit_verified if v['match'])
        
        print(f"  PhishTank ↔ Gemini Match Rate (Phishing): {phishing_match}/{len(phishing_verified)} ({100*phishing_match/len(phishing_verified):.1f}%)")
        print(f"  PhishTank ↔ Gemini Match Rate (Legitimate): {legit_match}/{len(legit_verified)} ({100*legit_match/len(legit_verified):.1f}%)")
        print(f"  Overall Match: {phishing_match + legit_match}/{len(all_verified)} ({100*(phishing_match+legit_match)/len(all_verified):.1f}%)")
        
        # Build feature vectors using GEMINI labels as ground truth
        print("\n[PHASE 4] Generating Features...")
        dataset = []
        
        for verified_entry in all_verified:
            domain = verified_entry['domain']
            gemini_label = verified_entry['gemini_label']
            
            # Use Gemini label as ground truth
            label = 1 if gemini_label == "phishing" else 0
            
            try:
                # Build features
                features = self.feature_engine.build_complete_features(
                    domain=domain,
                    destination_ip="0.0.0.0",
                    sni=domain
                )
                
                # Create record
                record = {
                    'domain': domain,
                    'destination_ip': '0.0.0.0',
                    'sni': domain,
                    'timestamp': datetime.now().isoformat(),
                    'label': label,  # 1 = phishing, 0 = legitimate
                    'gemini_label': gemini_label,
                    'gemini_confidence': verified_entry['gemini_confidence'],
                    'phishtank_label': verified_entry['phishtank_label'],
                    'label_match': verified_entry['match'],
                }
                
                # Add features
                if features.dns_features:
                    for key, val in features.dns_features.__dict__.items():
                        if not key.startswith('_'):
                            record[f'dns_{key}'] = val
                
                if features.tls_features:
                    for key, val in features.tls_features.__dict__.items():
                        if not key.startswith('_'):
                            record[f'tls_{key}'] = val
                
                if features.traffic_features:
                    for key, val in features.traffic_features.__dict__.items():
                        if not key.startswith('_'):
                            record[f'traffic_{key}'] = val
                
                dataset.append(record)
                print(f"  ✅ {domain:40} | Label: {gemini_label:12} | Features: {len(record)-8}")
                
            except Exception as e:
                logger.warning(f"Error processing {domain}: {e}")
        
        # Save dataset
        print("\n[PHASE 5] Saving Dataset...")
        self.save_dataset(dataset, all_verified)
    
    def save_dataset(self, dataset: list, verification_log: list) -> None:
        """Save dataset to CSV and JSON"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # CSV
        csv_file = Path("data") / f"expanded_dataset_{timestamp}.csv"
        if dataset:
            with open(csv_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=dataset[0].keys())
                writer.writeheader()
                writer.writerows(dataset)
            logger.info(f"✅ Dataset saved: {csv_file} ({len(dataset)} records)")
        
        # JSON
        json_file = Path("data") / f"expanded_dataset_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump({
                'metadata': {
                    'timestamp': timestamp,
                    'total_records': len(dataset),
                    'phishing_count': sum(1 for d in dataset if d['label'] == 1),
                    'legitimate_count': sum(1 for d in dataset if d['label'] == 0),
                    'verification_source': 'Gemini API',
                    'phishtank_source': 'PhishTank API',
                },
                'dataset': dataset
            }, f, indent=2)
            logger.info(f"✅ Metadata saved: {json_file}")
        
        # Verification log
        log_file = Path("data") / f"gemini_verification_log_{timestamp}.json"
        with open(log_file, 'w') as f:
            json.dump(verification_log, f, indent=2)
            logger.info(f"✅ Verification log saved: {log_file}")
        
        # Summary
        print("\n" + "="*80)
        print("DATASET CREATION COMPLETE")
        print("="*80)
        print(f"Total Records: {len(dataset)}")
        print(f"Phishing: {sum(1 for d in dataset if d['label'] == 1)}")
        print(f"Legitimate: {sum(1 for d in dataset if d['label'] == 0)}")
        print(f"CSV File: {csv_file}")
        print(f"JSON File: {json_file}")
        print(f"Verification Log: {log_file}")
        print("="*80 + "\n")


def main():
    """Main execution"""
    collector = ExpandedDatasetCollector()
    
    # Collect 50 phishing + 50 legitimate = 100 domains
    collector.create_dataset(phishing_limit=50, legitimate_limit=50)


if __name__ == "__main__":
    main()
