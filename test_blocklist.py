#!/usr/bin/env python3
"""Test hardcoded blocklist directly"""

from modules.realtime_engine import RealtimeInferenceEngine
from pathlib import Path

# Get model path
model_path = Path("models/RandomForest_metadata.json").parent / "RandomForest_model.pkl"
metadata_path = Path("models/RandomForest_metadata.json")

print("=" * 60)
print("Testing Hardcoded Blocklist")
print("=" * 60)

# Initialize engine
engine = RealtimeInferenceEngine(str(model_path), str(metadata_path))

# Test domains
test_domains = [
    "apple-verify.com",
    "google-login.com",
    "paypal-verify.com",
    "amazon-account.com",
    "google.com",  # should be SAFE
    "github.com",  # should be SAFE
]

print("\n")
for domain in test_domains:
    result = engine.predict(domain, "192.168.1.27", domain)
    status = "🛑 BLOCKED" if result.prediction == "phishing" else "✅ SAFE"
    print(f"{status} | {domain:30} | {result.confidence:.1%} | Features: {result.features_used}")

print("\n" + "=" * 60)
