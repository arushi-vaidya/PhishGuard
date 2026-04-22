"""
Example ML Model Training with Real Data

This script:
1. Creates a real labeled dataset
2. Trains Random Forest and XGBoost models
3. Evaluates performance
4. Saves best model for inference

Run with: python3 example_ml_training.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "modules"))

from create_real_dataset import main as create_dataset
from ml_model import train_model_from_csv

import logging
logging.basicConfig(level=logging.INFO)


def main():
    """Main execution"""
    
    print("\n" + "="*80)
    print("STEP 3: MACHINE LEARNING MODEL TRAINING")
    print("="*80 + "\n")
    
    # Step 1: Create real dataset
    print("[1/3] Creating real labeled dataset...")
    print("-" * 80)
    dataset_file = create_dataset()
    print(f"✓ Dataset created: {dataset_file}\n")
    
    # Step 2: Train model
    print("[2/3] Training ML models...")
    print("-" * 80)
    result = train_model_from_csv(dataset_file)
    print(f"✓ Model trained and saved\n")
    
    # Step 3: Display results
    print("[3/3] Training results summary")
    print("-" * 80)
    best_results = result['results']
    
    print(f"\nBest Model: {result['best_model']}")
    print(f"\nPerformance Metrics:")
    print(f"  Accuracy:  {best_results['accuracy']:.2%}")
    print(f"  Precision: {best_results['precision']:.2%}")
    print(f"  Recall:    {best_results['recall']:.2%}")
    print(f"  F1-Score:  {best_results['f1']:.2%}")
    print(f"  ROC-AUC:   {best_results['roc_auc']:.2%}")
    
    print(f"\nModel saved to: {result['model_file']}")
    print(f"Metadata saved to: {result['metadata_file']}")
    
    print("\n" + "="*80)
    print("STEP 3 COMPLETE ✓")
    print("="*80)
    print("\nNext: STEP 4 - Real-Time Inference with trained model")
    print("="*80 + "\n")


if __name__ == "__main__":
    main()
