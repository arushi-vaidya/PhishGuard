"""
Real-Time Inference Engine for Phishing Detection

This module:
1. Loads trained ML model
2. Extracts features from live network traffic
3. Makes real-time phishing/legitimate predictions
4. Outputs confidence scores and alerts

Author: Research Team
Date: 2026
"""

import logging
import pickle
import json
from typing import Dict, Optional, Tuple, List
from pathlib import Path
import numpy as np
import pandas as pd

from packet_capture import (
    RealTimePacketSniffer,
    DNSPacketData,
    TLSPacketData,
    TrafficFlowData,
)
from feature_engineering import FeatureEngineeringEngine

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class PredictionResult:
    """Result of a single phishing detection prediction"""
    
    def __init__(
        self,
        domain: str,
        destination_ip: str,
        prediction: str,  # "phishing" or "legitimate"
        confidence: float,  # 0.0 to 1.0
        risk_level: str,  # "low", "medium", "high"
        features_used: int,
        timestamp: float
    ):
        self.domain = domain
        self.destination_ip = destination_ip
        self.prediction = prediction
        self.confidence = confidence
        self.risk_level = risk_level
        self.features_used = features_used
        self.timestamp = timestamp
    
    def __str__(self) -> str:
        icon = "⚠️ PHISHING" if self.prediction == "phishing" else "✓ SAFE"
        return (
            f"{icon}\n"
            f"  Domain: {self.domain}\n"
            f"  IP: {self.destination_ip}\n"
            f"  Confidence: {self.confidence:.2%}\n"
            f"  Risk Level: {self.risk_level.upper()}"
        )
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for logging/alerts"""
        return {
            'domain': self.domain,
            'destination_ip': self.destination_ip,
            'prediction': self.prediction,
            'confidence': float(self.confidence),
            'risk_level': self.risk_level,
            'features_used': self.features_used,
            'timestamp': self.timestamp
        }


class RealtimeInferenceEngine:
    """Real-time phishing detection inference engine"""
    
    def __init__(self, model_path: str, metadata_path: Optional[str] = None):
        """
        Initialize inference engine with trained model
        
        Args:
            model_path: Path to trained model pickle file
            metadata_path: Path to model metadata JSON file
        """
        self.model_path = Path(model_path)
        self.metadata_path = Path(metadata_path) if metadata_path else None
        
        # Load model
        self.model = self._load_model()
        self.metadata = self._load_metadata()
        self.feature_names = self.metadata.get('features', [])
        
        # Feature engineering engine
        self.feature_engine = FeatureEngineeringEngine()
        
        # Cache for connections
        self.connection_cache = {}
        self.predictions_log = []
        
        logger.info(f"✓ Inference engine initialized with model: {self.model_path.name}")
        logger.info(f"  Features: {len(self.feature_names)}")
        logger.info(f"  Model type: {self.metadata.get('model_type', 'unknown')}")
    
    def _load_model(self):
        """Load trained model from pickle file"""
        if not self.model_path.exists():
            raise FileNotFoundError(f"Model not found: {self.model_path}")
        
        with open(self.model_path, 'rb') as f:
            model = pickle.load(f)
        
        logger.info(f"✓ Model loaded: {self.model_path}")
        return model
    
    def _load_metadata(self) -> Dict:
        """Load model metadata"""
        metadata = {
            'model_type': 'RandomForest',
            'features': [],
            'accuracy': 0.0,
            'timestamp': None
        }
        
        if self.metadata_path and self.metadata_path.exists():
            with open(self.metadata_path, 'r') as f:
                metadata = json.load(f)
            logger.info(f"✓ Metadata loaded: {self.metadata_path}")
        
        return metadata
    
    def predict(self, domain: str, destination_ip: str, sni: Optional[str] = None) -> PredictionResult:
        """
        Make phishing prediction for a domain/connection
        
        Args:
            domain: Domain name being connected to
            destination_ip: Destination IP address
            sni: SNI value from TLS handshake
            
        Returns:
            PredictionResult with prediction and confidence
        """
        # Build feature vector
        features_dict = self._build_feature_vector(domain, destination_ip, sni)
        
        if not features_dict or features_dict.get('features') is None:
            logger.warning(f"Could not build features for {domain}")
            return PredictionResult(
                domain=domain,
                destination_ip=destination_ip,
                prediction="unknown",
                confidence=0.0,
                risk_level="unknown",
                features_used=0,
                timestamp=0
            )
        
        # Extract feature values in correct order
        X = features_dict['features']
        num_features = len(X)
        
        # Make prediction with ML model
        prediction_numeric = self.model.predict([X])[0]
        probabilities = self.model.predict_proba([X])[0]
        
        # Convert numeric prediction to string (0='legitimate', 1='phishing')
        prediction_label = "phishing" if prediction_numeric == 1 else "legitimate"
        
        # Get confidence (probability of predicted class)
        confidence = float(max(probabilities))
        
        # Determine risk level
        risk_level = self._get_risk_level(prediction_label, confidence)
        
        # Create result
        result = PredictionResult(
            domain=domain,
            destination_ip=destination_ip,
            prediction=prediction_label,
            confidence=confidence,
            risk_level=risk_level,
            features_used=num_features,
            timestamp=features_dict.get('timestamp', 0)
        )
        
        # Log prediction
        self.predictions_log.append(result)
        
        return result
    
    def _build_feature_vector(self, domain: str, destination_ip: str, sni: Optional[str]) -> Optional[Dict]:
        """
        Build feature vector from domain/IP information
        
        Args:
            domain: Domain name
            destination_ip: Destination IP
            sni: SNI value
            
        Returns:
            Dictionary with 'features' array and metadata
        """
        try:
            # Build complete feature set
            features = self.feature_engine.build_complete_features(
                domain=domain,
                destination_ip=destination_ip,
                sni=sni or domain
            )
            
            # Convert to dictionary
            features_dict = features.to_dict()
            
            # Extract numeric features in order
            feature_vector = []
            for feat_name in self.feature_names:
                value = features_dict.get(feat_name, 0)
                
                # Handle non-numeric values
                if isinstance(value, bool):
                    value = int(value)
                elif isinstance(value, str):
                    # Try to convert string to float
                    try:
                        value = float(value)
                    except (ValueError, TypeError):
                        value = 0
                elif not isinstance(value, (int, float)):
                    value = 0
                
                feature_vector.append(float(value))
            
            return {
                'features': np.array(feature_vector),
                'domain': domain,
                'destination_ip': destination_ip,
                'timestamp': features_dict.get('timestamp', 0)
            }
        
        except Exception as e:
            logger.error(f"Error building features for {domain}: {e}")
            return None
    
    def _get_risk_level(self, prediction: str, confidence: float) -> str:
        """Determine risk level based on prediction and confidence"""
        if prediction == "phishing":
            if confidence >= 0.95:
                return "high"
            elif confidence >= 0.80:
                return "medium"
            else:
                return "low"
        else:
            # Legitimate domain with high confidence = low risk
            if confidence >= 0.95:
                return "low"
            elif confidence >= 0.80:
                return "low"
            else:
                return "medium"
    
    def predict_batch(self, domains: List[Tuple[str, str, Optional[str]]]) -> List[PredictionResult]:
        """
        Make predictions for batch of domains
        
        Args:
            domains: List of (domain, destination_ip, sni) tuples
            
        Returns:
            List of PredictionResult objects
        """
        results = []
        for domain, ip, sni in domains:
            result = self.predict(domain, ip, sni)
            results.append(result)
        
        return results
    
    def get_prediction_statistics(self) -> Dict:
        """Get statistics about recent predictions"""
        if not self.predictions_log:
            return {
                'total_predictions': 0,
                'phishing_detected': 0,
                'legitimate_count': 0,
                'average_confidence': 0.0,
                'high_risk_count': 0
            }
        
        predictions = self.predictions_log
        phishing_count = sum(1 for p in predictions if p.prediction == "phishing")
        legitimate_count = sum(1 for p in predictions if p.prediction == "legitimate")
        high_risk_count = sum(1 for p in predictions if p.risk_level == "high")
        avg_confidence = np.mean([p.confidence for p in predictions])
        
        return {
            'total_predictions': len(predictions),
            'phishing_detected': phishing_count,
            'legitimate_count': legitimate_count,
            'average_confidence': float(avg_confidence),
            'high_risk_count': high_risk_count
        }
    
    def clear_log(self):
        """Clear prediction log"""
        self.predictions_log = []
        logger.info("Prediction log cleared")


class RealtimeDetectionSystem:
    """Complete real-time phishing detection system"""
    
    def __init__(self, model_path: str, interface: str = "en0"):
        """
        Initialize real-time detection system
        
        Args:
            model_path: Path to trained model
            interface: Network interface to sniff on
        """
        self.inference_engine = RealtimeInferenceEngine(model_path)
        self.packet_sniffer = RealTimePacketSniffer(interface=interface)
        self.detections = []
        
        logger.info(f"✓ Real-time detection system initialized")
    
    def on_dns_packet(self, dns_data: DNSPacketData):
        """Handle DNS packet"""
        domain = dns_data.query_domain.lower()
        
        # Make prediction
        result = self.inference_engine.predict(
            domain=domain,
            destination_ip=dns_data.dst_ip,
            sni=None
        )
        
        # Log if phishing detected
        if result.prediction == "phishing":
            logger.warning(f"🚨 PHISHING DETECTED: {domain}")
            self.detections.append(result)
    
    def on_tls_packet(self, tls_data: TLSPacketData):
        """Handle TLS packet"""
        if tls_data.sni:
            domain = tls_data.sni.lower()
            
            # Make prediction
            result = self.inference_engine.predict(
                domain=domain,
                destination_ip=tls_data.dst_ip,
                sni=domain
            )
            
            # Log if phishing detected
            if result.prediction == "phishing":
                logger.warning(f"🚨 PHISHING DETECTED: {domain} (SNI)")
                self.detections.append(result)
    
    def start(self, duration_seconds: int = 60):
        """Start real-time monitoring"""
        logger.info(f"Starting real-time phishing detection for {duration_seconds} seconds...")
        
        # Register callbacks
        self.packet_sniffer.register_callback('dns', self.on_dns_packet)
        self.packet_sniffer.register_callback('tls', self.on_tls_packet)
        
        # Start sniffer
        self.packet_sniffer.start()
        
        # Run for specified duration
        import time
        start = time.time()
        try:
            while time.time() - start < duration_seconds:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Interrupted by user")
        
        # Stop
        self.packet_sniffer.stop()
    
    def print_summary(self):
        """Print detection summary"""
        stats = self.inference_engine.get_prediction_statistics()
        
        print("\n" + "="*80)
        print("REAL-TIME DETECTION SUMMARY")
        print("="*80)
        print(f"Total Predictions: {stats['total_predictions']}")
        print(f"Phishing Detected: {stats['phishing_detected']} ({100*stats['phishing_detected']//max(stats['total_predictions'],1)}%)")
        print(f"Legitimate: {stats['legitimate_count']}")
        print(f"High Risk Alerts: {stats['high_risk_count']}")
        print(f"Average Confidence: {stats['average_confidence']:.2%}")
        
        if self.detections:
            print("\n" + "-"*80)
            print("PHISHING DETECTIONS")
            print("-"*80)
            for detection in self.detections:
                print(f"\n{detection}")
        
        print("\n" + "="*80 + "\n")


if __name__ == "__main__":
    # Example usage
    model_path = "models/RandomForest_model.pkl"
    
    logger.info("STEP 4: Real-Time Inference Engine")
    logger.info("="*80)
    
    # Create inference engine
    engine = RealtimeInferenceEngine(model_path)
    
    # Test predictions
    test_cases = [
        ("google.com", "142.250.185.46"),
        ("amazon.com", "54.239.28.30"),
        ("paypal-verify.com", "185.25.51.205"),
        ("apple-login.com", "185.225.69.24"),
    ]
    
    print("\n" + "="*80)
    print("TESTING REAL-TIME INFERENCE")
    print("="*80 + "\n")
    
    for domain, ip in test_cases:
        result = engine.predict(domain, ip)
        print(f"\n{result}")
    
    # Print statistics
    stats = engine.get_prediction_statistics()
    print("\n" + "="*80)
    print("INFERENCE STATISTICS")
    print("="*80)
    print(f"Total: {stats['total_predictions']}")
    print(f"Phishing: {stats['phishing_detected']}")
    print(f"Legitimate: {stats['legitimate_count']}")
    print(f"Average Confidence: {stats['average_confidence']:.2%}")
    print(f"High Risk: {stats['high_risk_count']}")
    print("="*80 + "\n")
