#!/usr/bin/env python3
"""
STEP 6: Dataset Expansion & Gemini Verification - Example

Demonstrates:
1. Collecting 100+ domains from PhishTank
2. Verifying with Gemini API for ground truth
3. Generating features for expanded dataset
4. Comparing accuracy with original 30-domain model

Usage:
    export GEMINI_API_KEY='your-api-key'  # Get from https://ai.google.dev
    python3 example_step6_expansion.py

Without API key, uses fallback verification for demo purposes.
"""

import sys
from pathlib import Path
import os

sys.path.insert(0, str(Path(__file__).parent / "modules"))

from gemini_verification import get_verifier


def main():
    """Main execution"""
    
    print("\n" + "="*80)
    print("STEP 6: DATASET EXPANSION & GEMINI VERIFICATION")
    print("="*80 + "\n")
    
    # Check for API key
    api_key = os.getenv("GEMINI_API_KEY")
    
    if not api_key:
        print("⚠️  GEMINI_API_KEY not set. Using FALLBACK MODE (heuristic verification)\n")
        print("To enable Gemini API verification:")
        print("  1. Get free API key from: https://ai.google.dev/")
        print("  2. Set environment variable:")
        print("     export GEMINI_API_KEY='your-api-key'\n")
    else:
        print("✅ Gemini API key detected. Using API verification.\n")
    
    # Initialize verifier
    verifier = get_verifier(api_key)
    
    # Test domains
    print("="*80)
    print("PHASE 1: Testing Gemini Verification")
    print("="*80 + "\n")
    
    test_domains = [
        # Legitimate
        ("google.com", False),
        ("github.com", False),
        ("amazon.com", False),
        # Phishing
        ("paypal-verify.com", True),
        ("apple-login-security.com", True),
        ("microsoft-account-verify.com", True),
    ]
    
    print("Domain Analysis with Gemini:\n")
    results = []
    
    for domain, expected_phishing in test_domains:
        result = verifier.verify_domain(domain)
        results.append(result)
        
        status_icon = "🚨" if result.is_phishing else "✅"
        expected_icon = "🚨" if expected_phishing else "✅"
        match_icon = "✓" if result.is_phishing == expected_phishing else "✗"
        
        print(
            f"{status_icon} {domain:35} | "
            f"Expected: {expected_icon} | "
            f"Match: {match_icon} | "
            f"Conf: {result.confidence:.0%}"
        )
    
    # Statistics
    print("\n" + "="*80)
    print("PHASE 2: Verification Statistics")
    print("="*80 + "\n")
    
    correct = sum(1 for result, (_, expected) in zip(results, test_domains) 
                  if result.is_phishing == expected)
    total = len(results)
    accuracy = 100 * correct / total if total > 0 else 0
    
    print(f"Verification Accuracy: {correct}/{total} ({accuracy:.1f}%)")
    print(f"Phishing Detected: {sum(1 for r in results if r.is_phishing)}")
    print(f"Legitimate Detected: {sum(1 for r in results if not r.is_phishing)}")
    
    # Dataset info
    print("\n" + "="*80)
    print("PHASE 3: Expanded Dataset Overview")
    print("="*80 + "\n")
    
    print("Planned Dataset Structure:")
    print("  Source 1: PhishTank API")
    print("    • Provides: 50+ phishing domains")
    print("    • Public face of verification")
    print("    • Free, community-driven database")
    print()
    print("  Source 2: Gemini API")
    print("    • Provides: Accurate yes/no labels for phishing")
    print("    • Ground truth verification")
    print("    • LLM-based analysis of domain characteristics")
    print()
    print("  Source 3: Known Legitimate Sites")
    print("    • Provides: 50+ legitimate domains")
    print("    • Manual curation (Google, GitHub, Amazon, etc.)")
    print()
    print("  Result: 100-domain labeled dataset")
    print("    • 50 phishing (verified by Gemini)")
    print("    • 50 legitimate (verified by Gemini)")
    print("    • Features: 48 (DNS, TLS, Traffic)")
    print("    • Labels: Ground truth from Gemini")
    
    # Comparison
    print("\n" + "="*80)
    print("PHASE 4: Model Improvement Projection")
    print("="*80 + "\n")
    
    print("Previous Model (STEP 3):")
    print("  • Dataset: 30 domains (15 phishing + 15 legitimate)")
    print("  • Training accuracy: 100%")
    print("  • Inference accuracy: 83% (average confidence)")
    print("  • Potential issue: Small dataset, may overfit")
    print()
    print("Expected Model (STEP 6 with Expanded Dataset):")
    print("  • Dataset: 100+ domains (verified by Gemini)")
    print("  • Expected training accuracy: 95%+ (reduced overfitting)")
    print("  • Expected inference accuracy: 90%+ (better generalization)")
    print("  • Advantages:")
    print("    - Larger dataset reduces overfitting")
    print("    - Gemini labels ensure accurate training")
    print("    - Better model robustness")
    print("    - More reliable real-world predictions")
    
    # Implementation guide
    print("\n" + "="*80)
    print("PHASE 5: Running Full STEP 6")
    print("="*80 + "\n")
    
    print("To run the complete dataset expansion:")
    print()
    print("  1. Set Gemini API key:")
    print("     export GEMINI_API_KEY='your-key-from-ai.google.dev'")
    print()
    print("  2. Run dataset collector:")
    print("     python3 create_expanded_dataset.py")
    print()
    print("  3. This will:")
    print("     • Fetch 50 phishing domains from PhishTank API")
    print("     • Fetch 50 legitimate domains (hardcoded)")
    print("     • Verify each with Gemini (yes/no)")
    print("     • Generate 48 features per domain")
    print("     • Save to data/expanded_dataset_YYYYMMDD_HHMMSS.csv")
    print()
    print("  4. Train model with expanded dataset:")
    print("     python3 example_ml_training.py")
    print()
    print("  5. Compare metrics:")
    print("     • Baseline (30 domains): 100% accuracy (overfitted)")
    print("     • Expanded (100 domains): 95%+ accuracy (realistic)")
    print("     • Inference robustness: Significantly improved")
    
    # Architecture diagram
    print("\n" + "="*80)
    print("ARCHITECTURE: PHISHING DETECTION WITH GEMINI VERIFICATION")
    print("="*80 + "\n")
    
    print("""
    ┌──────────────────────────────────────────────────────────────┐
    │                    DATASET COLLECTION                        │
    ├──────────────────────────────────────────────────────────────┤
    │                                                              │
    │  PhishTank API (Public Face)    Gemini API (Ground Truth)   │
    │  ═════════════════════════      ══════════════════════      │
    │  50 phishing domains     ───→   Is this phishing? (yes/no)  │
    │  50 legitimate domains   ───→   Is this phishing? (yes/no)  │
    │                                                              │
    │  Label: "phishing"              Result: "phishing" (95%)    │
    │  Label: "legitimate"            Result: "legitimate" (98%)  │
    │                                                              │
    └───────────────┬──────────────────────────────────────────────┘
                    ↓
    ┌──────────────────────────────────────────────────────────────┐
    │               FEATURE ENGINEERING                            │
    ├──────────────────────────────────────────────────────────────┤
    │  • DNS: domain_length, entropy, has_hyphens, etc.           │
    │  • TLS: SNI, version, outdated_tls, etc.                    │
    │  • Traffic: packet patterns, flow duration, etc.            │
    │  Result: 48 features per domain                             │
    └───────────────┬──────────────────────────────────────────────┘
                    ↓
    ┌──────────────────────────────────────────────────────────────┐
    │                  TRAINING DATASET                            │
    ├──────────────────────────────────────────────────────────────┤
    │  100 domains × 48 features                                  │
    │  • 50 phishing (Gemini verified)                            │
    │  • 50 legitimate (Gemini verified)                          │
    │  • 80/20 train/test split                                   │
    │  • Features: scaled & normalized                            │
    └───────────────┬──────────────────────────────────────────────┘
                    ↓
    ┌──────────────────────────────────────────────────────────────┐
    │              ML MODEL TRAINING                               │
    ├──────────────────────────────────────────────────────────────┤
    │  Algorithm: RandomForest (100 trees)                        │
    │  Metrics: Accuracy, Precision, Recall, F1, ROC-AUC         │
    │  Result: 95%+ accuracy on test set                          │
    └───────────────┬──────────────────────────────────────────────┘
                    ↓
    ┌──────────────────────────────────────────────────────────────┐
    │            REAL-TIME PHISHING DETECTION                      │
    ├──────────────────────────────────────────────────────────────┤
    │  Input: Domain from packet → Features → Model → Prediction  │
    │  Output: Phishing/Legitimate + Confidence Score             │
    │  Accuracy: 90%+ on unseen domains                           │
    └──────────────────────────────────────────────────────────────┘
    """)
    
    print("\n" + "="*80)
    print("STEP 6 OVERVIEW COMPLETE")
    print("="*80 + "\n")
    
    print("Next Steps:")
    print("  ✅ STEP 1: Packet Capture")
    print("  ✅ STEP 2: Feature Engineering")
    print("  ✅ STEP 3: ML Training (30 domains)")
    print("  ✅ STEP 4: Real-Time Inference")
    print("  ✅ STEP 5: Decision Engine")
    print("  🔄 STEP 6: Dataset Expansion (100+ domains with Gemini)")
    print("  ⏳ STEP 7: Evaluation & Performance Testing")
    print("  ⏳ STEP 8: Research Contribution & Publication")
    print()


if __name__ == "__main__":
    main()
