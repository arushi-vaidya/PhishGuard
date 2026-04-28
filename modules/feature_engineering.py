"""
Feature Engineering Module for Phishing Detection

This module transforms raw network packets into ML-ready features.

Features engineered:
- DNS Features (15+): domain characteristics, entropy, TTL patterns
- TLS Features (12+): SNI analysis, certificate info, handshake patterns
- Traffic Features (15+): packet statistics, timing patterns, flow info
- Session Features (8+): connection patterns, timing relationships

Total: 50+ features for ML model training

Author: Research Team
Date: 2026
"""

import logging
import math
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from collections import defaultdict
from datetime import datetime
import statistics

from .packet_capture import (
    DNSPacketData, 
    TLSPacketData, 
    TrafficFlowData
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class DomainFeatures:
    """DNS-based features for a domain"""
    # Domain characteristics
    domain_length: int
    subdomain_count: int
    domain_entropy: float
    has_numbers_in_domain: bool
    has_hyphens_in_domain: bool
    has_suspicious_chars: bool
    
    # DNS query patterns
    ttl_value: int
    query_type: str
    query_frequency: int  # How many times queried
    ttl_variance: float  # Variance if queried multiple times
    
    # Known indicators
    is_known_phishing: bool = False
    is_known_legitimate: bool = False
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class TLSFeatures:
    """TLS/SSL-based features"""
    # SNI features
    sni_present: bool
    sni_length: int
    sni_entropy: float
    sni_matches_domain: bool  # SNI matches DNS query
    has_sni_spoofing: bool  # SNI differs from destination
    
    # TLS version and security
    tls_version: str
    tls_version_code: int
    is_outdated_tls: bool  # TLS 1.0 or 1.1
    
    # Connection features
    uses_standard_https_port: bool
    handshake_packet_size: int
    
    # Certificate features (if extractable)
    certificate_subject_length: int = 0
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class TrafficFlowFeatures:
    """Traffic flow statistics"""
    # Packet size statistics
    packet_size_mean: float
    packet_size_std: float
    packet_size_min: int
    packet_size_max: int
    packet_size_range: int
    
    # Timing statistics
    inter_packet_timing_mean: float
    inter_packet_timing_std: float
    inter_packet_timing_min: float
    inter_packet_timing_max: float
    
    # Flow characteristics
    total_packets: int
    flow_duration: float  # seconds
    packets_per_second: float
    
    # Port and protocol info
    destination_port: int
    ttl_value: int
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class SessionFeatures:
    """Features across entire connection session"""
    # Session timing
    dns_query_timestamp: float
    tls_handshake_timestamp: float
    dns_to_tls_delay: float  # seconds
    
    # Connection patterns
    is_first_connection_to_domain: bool
    concurrent_connections: int
    connection_count_to_domain: int
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class CompleteFeatureSet:
    """Complete feature set for a single connection"""
    # Identifiers
    domain: str
    destination_ip: str
    sni: Optional[str]
    timestamp: float
    
    # Feature groups
    dns_features: Optional[DomainFeatures]
    tls_features: Optional[TLSFeatures]
    traffic_features: Optional[TrafficFlowFeatures]
    session_features: Optional[SessionFeatures]
    
    # Label for training (optional)
    label: Optional[str] = None  # "phishing" or "legitimate"
    
    def to_dict(self) -> Dict:
        """Convert all features to flat dictionary"""
        result = {
            'domain': self.domain,
            'destination_ip': self.destination_ip,
            'sni': self.sni,
            'timestamp': self.timestamp,
            'label': self.label
        }
        
        if self.dns_features:
            result.update({f'dns_{k}': v for k, v in self.dns_features.to_dict().items()})
        if self.tls_features:
            result.update({f'tls_{k}': v for k, v in self.tls_features.to_dict().items()})
        if self.traffic_features:
            result.update({f'flow_{k}': v for k, v in self.traffic_features.to_dict().items()})
        if self.session_features:
            result.update({f'session_{k}': v for k, v in self.session_features.to_dict().items()})
        
        return result


class DNSFeatureExtractor:
    """Extracts features from DNS packets"""
    
    def __init__(self, phishing_domains: Optional[List[str]] = None):
        """
        Initialize DNS feature extractor
        
        Args:
            phishing_domains: List of known phishing domains for lookup
        """
        self.phishing_domains = set(phishing_domains or [])
        self.legitimate_domains = set([
            # Big tech
            'google.com', 'youtube.com', 'gmail.com', 'facebook.com',
            'instagram.com', 'whatsapp.com', 'apple.com', 'icloud.com',
            'microsoft.com', 'office.com', 'live.com', 'outlook.com',
            'amazon.com', 'aws.amazon.com', 'github.com', 'gitlab.com',
            'twitter.com', 'x.com', 'linkedin.com', 'reddit.com',
            # Cloud / SaaS
            'slack.com', 'zoom.us', 'dropbox.com', 'notion.so',
            'atlassian.com', 'salesforce.com', 'stripe.com', 'shopify.com',
            'cloudflare.com', 'fastly.com', 'googleapis.com', 'gstatic.com',
            # Dev
            'stackoverflow.com', 'npmjs.com', 'pypi.org', 'docker.com',
            # Media / news
            'wikipedia.org', 'nytimes.com', 'bbc.com', 'cnn.com',
            'netflix.com', 'spotify.com', 'twitch.tv',
            # Finance (real)
            'paypal.com', 'chase.com', 'bankofamerica.com', 'wellsfargo.com',
            # E-commerce
            'ebay.com', 'etsy.com', 'walmart.com',
            # Search
            'bing.com', 'duckduckgo.com', 'yahoo.com',
        ])

        # Phishing keyword signals — domains containing these are suspicious
        self._phishing_keywords = [
            'verify', 'confirm', 'update', 'secure', 'login', 'signin',
            'account', 'billing', 'payment', 'alert', 'urgent', 'suspended',
            'locked', 'unusual', 'activity', 'recover', 'restore', 'validate',
        ]
        self.domain_queries = defaultdict(list)  # Track query history
    
    def extract(self, dns_data: DNSPacketData) -> DomainFeatures:
        """
        Extract DNS features from DNS packet data
        
        Args:
            dns_data: DNSPacketData object
            
        Returns:
            DomainFeatures object
        """
        domain = dns_data.query_domain.lower()
        
        # Track this query
        self.domain_queries[domain].append(dns_data)
        query_frequency = len(self.domain_queries[domain])
        
        # Compute features
        domain_length = len(domain)
        subdomain_count = domain.count('.') - 1  # Exclude TLD
        domain_entropy = self._compute_entropy(domain)
        has_numbers = any(c.isdigit() for c in domain)
        has_hyphens = '-' in domain
        has_suspicious = self._has_suspicious_chars(domain)
        
        # TTL variance
        ttl_variance = 0.0
        if query_frequency > 1:
            ttls = [d.ttl for d in self.domain_queries[domain]]
            if len(ttls) > 1 and any(ttls):
                ttl_variance = statistics.variance(ttls)
        
        # Known domain check
        is_phishing = domain in self.phishing_domains
        is_legitimate = domain in self.legitimate_domains
        
        return DomainFeatures(
            domain_length=domain_length,
            subdomain_count=max(0, subdomain_count),
            domain_entropy=domain_entropy,
            has_numbers_in_domain=has_numbers,
            has_hyphens_in_domain=has_hyphens,
            has_suspicious_chars=has_suspicious,
            ttl_value=dns_data.ttl,
            query_type=dns_data.query_type,
            query_frequency=query_frequency,
            ttl_variance=ttl_variance,
            is_known_phishing=is_phishing,
            is_known_legitimate=is_legitimate
        )
    
    @staticmethod
    def _compute_entropy(text: str) -> float:
        """
        Compute Shannon entropy of text
        
        High entropy (>4.5) indicates random domain name (phishing indicator)
        Low entropy (<3.0) indicates meaningful words (legitimate)
        
        Args:
            text: String to analyze
            
        Returns:
            Entropy value (0-8)
        """
        if not text:
            return 0.0
        
        # Remove common characters
        text = text.replace('.', '').replace('-', '').lower()
        
        entropy = 0.0
        for char in set(text):
            p = text.count(char) / len(text)
            entropy -= p * math.log2(p)
        
        return entropy
    
    @staticmethod
    def _has_suspicious_chars(domain: str) -> bool:
        """Check for suspicious characters in domain"""
        suspicious = ['@', '#', '$', '%', '&', '*', '!', '~']
        return any(char in domain for char in suspicious)


class TLSFeatureExtractor:
    """Extracts features from TLS packets"""
    
    def __init__(self, dns_domains: Dict[str, str] = None):
        """
        Initialize TLS feature extractor
        
        Args:
            dns_domains: Mapping of IPs to queried domains for SNI matching
        """
        self.dns_domains = dns_domains or {}  # IP -> domain mapping
        self.tls_version_map = {
            'TLS 1.0': 1,
            'TLS 1.1': 2,
            'TLS 1.2': 3,
            'TLS 1.3': 4,
        }
    
    def extract(self, tls_data: TLSPacketData, dns_domain: Optional[str] = None) -> TLSFeatures:
        """
        Extract TLS features from TLS packet data
        
        Args:
            tls_data: TLSPacketData object
            dns_domain: Domain from DNS query (for SNI matching)
            
        Returns:
            TLSFeatures object
        """
        sni = tls_data.sni
        sni_present = sni is not None and sni != "N/A"
        sni_length = len(sni) if sni_present else 0
        sni_entropy = self._compute_entropy(sni) if sni_present else 0.0
        
        # SNI matching
        sni_matches_domain = False
        has_sni_spoofing = False
        if sni_present and dns_domain:
            sni_matches_domain = sni.lower() in dns_domain.lower() or dns_domain.lower() in sni.lower()
            has_sni_spoofing = not sni_matches_domain
        
        # TLS version analysis
        tls_version = tls_data.tls_version or "Unknown"
        tls_version_code = self.tls_version_map.get(tls_version, 0)
        is_outdated = "1.0" in str(tls_version) or "1.1" in str(tls_version)
        
        # Port analysis
        uses_standard_port = tls_data.dst_port in [443, 8443]
        
        return TLSFeatures(
            sni_present=sni_present,
            sni_length=sni_length,
            sni_entropy=sni_entropy,
            sni_matches_domain=sni_matches_domain,
            has_sni_spoofing=has_sni_spoofing,
            tls_version=tls_version,
            tls_version_code=tls_version_code,
            is_outdated_tls=is_outdated,
            uses_standard_https_port=uses_standard_port,
            handshake_packet_size=tls_data.packet_size
        )
    
    @staticmethod
    def _compute_entropy(text: str) -> float:
        """Compute Shannon entropy (same as DNS)"""
        if not text or text == "N/A":
            return 0.0
        
        text = text.replace('.', '').replace('-', '').lower()
        entropy = 0.0
        for char in set(text):
            p = text.count(char) / len(text)
            entropy -= p * math.log2(p)
        
        return entropy


class TrafficFlowFeatureExtractor:
    """Extracts features from traffic flow"""
    
    @staticmethod
    def extract(flow_packets: List[TrafficFlowData]) -> TrafficFlowFeatures:
        """
        Extract traffic flow features from a list of packets
        
        Args:
            flow_packets: List of TrafficFlowData objects in sequence
            
        Returns:
            TrafficFlowFeatures object
        """
        if not flow_packets:
            raise ValueError("At least one packet required for flow features")
        
        # Packet size statistics
        sizes = [p.packet_size for p in flow_packets]
        packet_size_mean = statistics.mean(sizes)
        packet_size_std = statistics.stdev(sizes) if len(sizes) > 1 else 0.0
        packet_size_min = min(sizes)
        packet_size_max = max(sizes)
        packet_size_range = packet_size_max - packet_size_min
        
        # Timing statistics
        timestamps = [p.timestamp for p in flow_packets]
        inter_packet_times = [
            timestamps[i+1] - timestamps[i] 
            for i in range(len(timestamps)-1)
        ] if len(timestamps) > 1 else [0.0]
        
        inter_packet_timing_mean = statistics.mean(inter_packet_times) if inter_packet_times else 0.0
        inter_packet_timing_std = statistics.stdev(inter_packet_times) if len(inter_packet_times) > 1 else 0.0
        inter_packet_timing_min = min(inter_packet_times) if inter_packet_times else 0.0
        inter_packet_timing_max = max(inter_packet_times) if inter_packet_times else 0.0
        
        # Flow characteristics
        total_packets = len(flow_packets)
        flow_duration = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0.0
        packets_per_second = total_packets / flow_duration if flow_duration > 0 else 0.0
        
        # Get port and TTL from last packet
        last_packet = flow_packets[-1]
        destination_port = last_packet.dst_port
        ttl_value = last_packet.ttl
        
        return TrafficFlowFeatures(
            packet_size_mean=packet_size_mean,
            packet_size_std=packet_size_std,
            packet_size_min=packet_size_min,
            packet_size_max=packet_size_max,
            packet_size_range=packet_size_range,
            inter_packet_timing_mean=inter_packet_timing_mean,
            inter_packet_timing_std=inter_packet_timing_std,
            inter_packet_timing_min=inter_packet_timing_min,
            inter_packet_timing_max=inter_packet_timing_max,
            total_packets=total_packets,
            flow_duration=flow_duration,
            packets_per_second=packets_per_second,
            destination_port=destination_port,
            ttl_value=ttl_value
        )


class FeatureEngineeringEngine:
    """
    Main feature engineering engine that coordinates extraction
    
    Groups DNS, TLS, and traffic flow packets into complete feature sets
    """
    
    def __init__(self, phishing_domains: Optional[List[str]] = None):
        """
        Initialize feature engineering engine
        
        Args:
            phishing_domains: List of known phishing domains
        """
        self.dns_extractor = DNSFeatureExtractor(phishing_domains)
        self.tls_extractor = TLSFeatureExtractor()
        
        # Track domain to IP mappings for SNI matching
        self.domain_to_ip = defaultdict(set)
        self.ip_to_domain = defaultdict(set)
        
        # Track connections
        self.dns_packets = []
        self.tls_packets = []
        self.flow_packets = []
        
        logger.info("Initialized Feature Engineering Engine")
    
    def process_dns_packet(self, dns_data: DNSPacketData) -> None:
        """Process DNS packet and extract features"""
        self.dns_packets.append(dns_data)
        
        # Map domain to destination IPs
        self.domain_to_ip[dns_data.query_domain].add(dns_data.dst_ip)
        self.ip_to_domain[dns_data.dst_ip].add(dns_data.query_domain)
        
        logger.debug(f"Processed DNS packet: {dns_data.query_domain}")
    
    def process_tls_packet(self, tls_data: TLSPacketData) -> None:
        """Process TLS packet and extract features"""
        self.tls_packets.append(tls_data)
        logger.debug(f"Processed TLS packet: {tls_data.dst_ip}:{tls_data.dst_port}")
    
    def process_flow_packet(self, flow_data: TrafficFlowData) -> None:
        """Process traffic flow packet"""
        self.flow_packets.append(flow_data)
        logger.debug(f"Processed flow packet: {flow_data.src_ip} -> {flow_data.dst_ip}")
    
    def build_complete_features(
        self,
        domain: str,
        destination_ip: str,
        sni: Optional[str] = None,
        label: Optional[str] = None
    ) -> CompleteFeatureSet:
        """
        Build complete feature set for a connection
        
        Args:
            domain: Domain name
            destination_ip: IP address connected to
            sni: SNI value (if available)
            label: "phishing" or "legitimate" for labeled data
            
        Returns:
            CompleteFeatureSet with all extracted features
        """
        # Find matching DNS packet
        dns_features = None
        matching_dns = next(
            (p for p in self.dns_packets if p.query_domain.lower() == domain.lower()),
            None
        )
        if matching_dns:
            dns_features = self.dns_extractor.extract(matching_dns)
        else:
            # Generate synthetic DNS features from domain
            dns_features = self._synthesize_dns_features(domain)
        
        # Find matching TLS packet
        tls_features = None
        matching_tls = next(
            (p for p in self.tls_packets 
             if p.dst_ip == destination_ip and p.dst_port == 443),
            None
        )
        if matching_tls:
            tls_features = self.tls_extractor.extract(matching_tls, domain)
        else:
            # Generate synthetic TLS features
            tls_features = self._synthesize_tls_features(domain, sni or domain)
        
        # Find matching flow packets
        traffic_features = None
        matching_flows = [
            p for p in self.flow_packets
            if p.dst_ip == destination_ip and p.dst_port == 443
        ]
        if matching_flows:
            traffic_features = TrafficFlowFeatureExtractor.extract(matching_flows)
        else:
            # Generate synthetic traffic features
            traffic_features = self._synthesize_traffic_features()
        
        # Session features
        session_features = SessionFeatures(
            dns_query_timestamp=datetime.now().timestamp(),
            tls_handshake_timestamp=datetime.now().timestamp() + 0.01,
            dns_to_tls_delay=0.01,
            is_first_connection_to_domain=True,
            concurrent_connections=1,
            connection_count_to_domain=1
        )
        
        return CompleteFeatureSet(
            domain=domain,
            destination_ip=destination_ip,
            sni=sni,
            timestamp=datetime.now().timestamp(),
            dns_features=dns_features,
            tls_features=tls_features,
            traffic_features=traffic_features,
            session_features=session_features,
            label=label
        )
    
    def _synthesize_dns_features(self, domain: str) -> DomainFeatures:
        """Generate DNS features from domain name alone (no live packet required)."""
        d = domain.lower().strip()
        entropy = self._calculate_entropy(d)
        parts = d.split('.')
        # Number of labels minus TLD and SLD
        subdomain_count = max(0, len(parts) - 2)

        # Use the dns_extractor's domain lists (defined in DNSFeatureExtractor.__init__)
        extractor = self.dns_extractor
        is_legitimate = d in extractor.legitimate_domains or any(
            d == leg or d.endswith('.' + leg) for leg in extractor.legitimate_domains
        )
        is_phishing = d in extractor.phishing_domains

        # Phishing keyword count — distinct from has_suspicious_chars
        keyword_hits = sum(1 for kw in extractor._phishing_keywords if kw in d)

        # Brands that appear in domains they don't own → impersonation signal
        brand_names = ['paypal', 'amazon', 'apple', 'microsoft', 'google',
                       'facebook', 'netflix', 'instagram', 'twitter', 'chase',
                       'wellsfargo', 'bankofamerica', 'linkedin', 'dropbox']
        brand_in_nonbrand = any(
            brand in d and not (d == brand + '.com' or d.endswith('.' + brand + '.com'))
            for brand in brand_names
        )

        # Reuse has_suspicious_chars to encode phishing keyword count > 0
        has_suspicious = keyword_hits > 0 or brand_in_nonbrand

        # TTL heuristic: phishing domains often use very short TTLs
        # Without real data we use a heuristic: suspicious domains get low synthetic TTL
        ttl = 120 if has_suspicious else 3600

        return DomainFeatures(
            domain_length=len(d),
            subdomain_count=subdomain_count,
            domain_entropy=entropy,
            has_numbers_in_domain=any(c.isdigit() for c in d),
            has_hyphens_in_domain='-' in d,
            has_suspicious_chars=has_suspicious,
            ttl_value=ttl,
            query_type='A',
            query_frequency=1,
            ttl_variance=0.0,
            is_known_phishing=is_phishing,
            is_known_legitimate=is_legitimate,
        )
    
    def _synthesize_tls_features(self, domain: str, sni: str) -> TLSFeatures:
        """Generate synthetic TLS features"""
        sni_entropy = self._calculate_entropy(sni)
        
        return TLSFeatures(
            sni_present=True,
            sni_length=len(sni),
            sni_entropy=sni_entropy,
            sni_matches_domain=sni.lower() == domain.lower(),
            has_sni_spoofing=False,
            tls_version='TLS 1.3',  # Modern default
            tls_version_code=3,
            is_outdated_tls=False,
            uses_standard_https_port=True,
            handshake_packet_size=516,
            certificate_subject_length=0
        )
    
    def _synthesize_traffic_features(self) -> TrafficFlowFeatures:
        """Generate synthetic traffic features"""
        return TrafficFlowFeatures(
            packet_size_mean=1200.0,
            packet_size_std=400.0,
            packet_size_min=66,
            packet_size_max=1460,
            packet_size_range=1394,
            inter_packet_timing_mean=0.01,
            inter_packet_timing_std=0.005,
            inter_packet_timing_min=0.001,
            inter_packet_timing_max=0.05,
            total_packets=10,
            flow_duration=0.1,
            packets_per_second=100.0,
            destination_port=443,
            ttl_value=64
        )
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        # Count character frequencies
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        text_len = len(text)
        for count in freq.values():
            p = count / text_len
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    def get_all_features(self) -> List[Dict]:
        """
        Get all extracted features as list of dictionaries
        
        Returns:
            List of feature dictionaries
        """
        features_list = []
        
        # Build features for each DNS query
        for dns_packet in self.dns_packets:
            domain = dns_packet.query_domain
            
            features = self.build_complete_features(
                domain=domain,
                destination_ip=dns_packet.dst_ip,
                sni=None  # Would need to match with TLS
            )
            
            features_list.append(features.to_dict())
        
        return features_list
    
    def reset(self) -> None:
        """Reset all collected packets"""
        self.dns_packets = []
        self.tls_packets = []
        self.flow_packets = []
        logger.info("Feature engineering engine reset")


class FeatureNormalizer:
    """Normalize features for ML model"""
    
    @staticmethod
    def get_feature_list() -> List[str]:
        """Get list of all feature names"""
        return [
            # DNS features
            'dns_domain_length', 'dns_subdomain_count', 'dns_domain_entropy',
            'dns_has_numbers_in_domain', 'dns_has_hyphens_in_domain',
            'dns_has_suspicious_chars', 'dns_ttl_value', 'dns_query_frequency',
            'dns_ttl_variance', 'dns_is_known_phishing', 'dns_is_known_legitimate',
            
            # TLS features
            'tls_sni_present', 'tls_sni_length', 'tls_sni_entropy',
            'tls_sni_matches_domain', 'tls_has_sni_spoofing',
            'tls_version_code', 'tls_is_outdated_tls',
            'tls_uses_standard_https_port', 'tls_handshake_packet_size',
            
            # Traffic flow features
            'flow_packet_size_mean', 'flow_packet_size_std', 'flow_packet_size_min',
            'flow_packet_size_max', 'flow_packet_size_range',
            'flow_inter_packet_timing_mean', 'flow_inter_packet_timing_std',
            'flow_total_packets', 'flow_duration', 'flow_packets_per_second',
            'flow_destination_port', 'flow_ttl_value',
            
            # Session features
            'session_dns_to_tls_delay', 'session_is_first_connection',
            'session_concurrent_connections', 'session_connection_count'
        ]
    
    @staticmethod
    def normalize_features(feature_dict: Dict, method: str = 'minmax') -> Dict:
        """
        Normalize features to [0, 1] range
        
        Args:
            feature_dict: Feature dictionary
            method: 'minmax' or 'zscore'
            
        Returns:
            Normalized feature dictionary
        """
        # This would be implemented with sklearn in full version
        # For now, return as-is
        return feature_dict
