#!/usr/bin/env python3
"""
STEP 4: Real-Time Inference Engine - Example Usage

This script demonstrates:
1. Loading trained model
2. Making predictions on test domains
3. Testing batch inference
4. Displaying predictions with confidence scores

Run with: python3 example_realtime_inference.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "modules"))

from realtime_engine import RealtimeInferenceEngine, RealtimeDetectionSystem
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    """Main execution"""
    
    print("\n" + "="*80)
    print("STEP 4: REAL-TIME INFERENCE ENGINE")
    print("="*80)
    print("\nLoading trained model for real-time phishing detection...\n")
    
    # Initialize inference engine
    model_path = "models/RandomForest_model.pkl"
    metadata_path = "models/RandomForest_metadata.json"
    
    try:
        engine = RealtimeInferenceEngine(
            model_path=model_path,
            metadata_path=metadata_path
        )
    except FileNotFoundError as e:
        logger.error(f"Model not found: {e}")
        logger.info("Please train a model first (STEP 3)")
        return
    
    # Test cases: mix of phishing and legitimate
    test_cases = [
        # Legitimate domains
        ("google.com", "142.250.185.46", "google.com"),
        ("github.com", "140.82.113.21", "github.com"),
        ("amazon.com", "54.239.28.30", "amazon.com"),
        ("facebook.com", "66.220.158.22", "facebook.com"),
        ("youtube.com", "142.251.41.142", "youtube.com"),
        
        # Phishing domains (from PhishTank)
        ("paypal-verify.com", "185.25.51.205", "paypal-verify.com"),
        ("apple-login.com", "185.225.69.24", "apple-login.com"),
        ("amazon-account.com", "45.152.72.200", "amazon-account.com"),
        ("google-signin.com", "45.152.72.200", "google-signin.com"),
        ("microsoft-update.com", "185.25.51.205", "microsoft-update.com"),
    ]
    
    print("="*80)
    print("INDIVIDUAL PREDICTIONS")
    print("="*80 + "\n")
    
    predictions = []
    for domain, ip, sni in test_cases:
        result = engine.predict(domain, ip, sni)
        predictions.append(result)
        
        # Print result
        emoji = "⚠️" if result.prediction == "phishing" else "✅"
        print(f"{emoji} {domain:30} | Prediction: {result.prediction:10} | "
              f"Confidence: {result.confidence:6.2%} | Risk: {result.risk_level.upper():6}")
    
    # Batch inference
    print("\n" + "="*80)
    print("BATCH PREDICTIONS")
    print("="*80)
    
    batch_results = engine.predict_batch(test_cases)
    print(f"\nProcessed {len(batch_results)} domains in batch")
    
    # Statistics
    stats = engine.get_prediction_statistics()
    print("\n" + "="*80)
    print("INFERENCE STATISTICS")
    print("="*80)
    print(f"Total Predictions: {stats['total_predictions']}")
    print(f"Phishing Detected: {stats['phishing_detected']}")
    print(f"Legitimate: {stats['legitimate_count']}")
    print(f"Average Confidence: {stats['average_confidence']:.2%}")
    print(f"High Risk Alerts: {stats['high_risk_count']}")
    
    # Detailed results
    print("\n" + "="*80)
    print("DETAILED PREDICTIONS")
    print("="*80 + "\n")
    
    phishing_detections = [p for p in predictions if p.prediction == "phishing"]
    legitimate_domains = [p for p in predictions if p.prediction == "legitimate"]
    
    print(f"\n✅ LEGITIMATE ({len(legitimate_domains)}):")
    for p in legitimate_domains:
        print(f"  {p.domain:30} | Confidence: {p.confidence:6.2%}")
    
    print(f"\n⚠️  PHISHING ({len(phishing_detections)}):")
    for p in phishing_detections:
        print(f"  {p.domain:30} | Confidence: {p.confidence:6.2%} | Risk: {p.risk_level.upper()}")
    
    # Model metadata
    print("\n" + "="*80)
    print("MODEL INFORMATION")
    print("="*80)
    print(f"Model Type: {engine.metadata.get('model_type')}")
    print(f"Features Used: {len(engine.feature_names)}")
    print(f"Training Accuracy: {engine.metadata.get('accuracy', 'unknown')}")
    print(f"Trained: {engine.metadata.get('timestamp', 'unknown')}")
    
    print("\n" + "="*80)
    print("STEP 4 COMPLETE ✓")
    print("="*80)
    print("\nNext: STEP 5 - Decision Engine (alerts, blocking, actions)")
    print("      STEP 6 - Real-world dataset expansion")
    print("      STEP 7 - Evaluation & metrics")
    print("      STEP 8 - Research contribution")
    print("\n" + "="*80 + "\n")


if __name__ == "__main__":
    main()
