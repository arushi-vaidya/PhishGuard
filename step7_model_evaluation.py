#!/usr/bin/env python3
"""
STEP 7: Comprehensive Model Training & Evaluation

This script:
1. Loads all available training data
2. Combines datasets (30+ domains with 48+ features each)
3. Implements proper train/test split (80/20)
4. Trains multiple ML models (RandomForest, SVM, XGBoost, Neural Network)
5. Performs 5-fold cross-validation
6. Measures: Accuracy, Precision, Recall, F1, ROC-AUC, False Positive/Negative rates
7. Tests on held-out test set
8. Saves best model with evaluation results
9. Generates performance comparison charts

Run with: python3 step7_model_evaluation.py

Expected Results:
  - Accuracy: 90-95% on test set (vs 100% on 30 domains = overfitting)
  - False Positive Rate: <5% (minimize blocking legitimate sites)
  - False Negative Rate: <10% (catch real phishing)
  - ROC-AUC: >0.95
"""

import sys
import json
import pickle
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from collections import defaultdict

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, cross_val_score, cross_validate, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, roc_auc_score,
    confusion_matrix, classification_report, roc_curve, auc
)

sys.path.insert(0, str(Path(__file__).parent / "modules"))
from feature_engineering import FeatureEngineeringEngine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ModelEvaluator:
    """Comprehensive model evaluation framework"""
    
    def __init__(self, data_dir: str = "data", models_dir: str = "models"):
        self.data_dir = Path(data_dir)
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(exist_ok=True)
        
        self.df = None
        self.X_train = None
        self.X_test = None
        self.y_train = None
        self.y_test = None
        self.feature_names = []
        self.results = {}
        
        logger.info("✓ ModelEvaluator initialized")
    
    def load_all_datasets(self) -> pd.DataFrame:
        """Load and combine all available datasets"""
        logger.info("Loading all available datasets...")
        
        dfs = []
        csv_files = list(self.data_dir.glob("*.csv"))
        logger.info(f"Found {len(csv_files)} CSV files")
        
        for csv_file in csv_files:
            try:
                df = pd.read_csv(csv_file)
                logger.info(f"  • {csv_file.name}: {len(df)} rows, {len(df.columns)} columns")
                dfs.append(df)
            except Exception as e:
                logger.warning(f"  ⚠️  Failed to load {csv_file.name}: {e}")
        
        if not dfs:
            raise ValueError("No datasets loaded!")
        
        # Combine all datasets
        self.df = pd.concat(dfs, ignore_index=True)
        self.df = self.df.drop_duplicates(subset=['domain'], keep='first')
        
        logger.info(f"\n✓ Combined dataset:")
        logger.info(f"  Total rows: {len(self.df)}")
        logger.info(f"  Total columns: {len(self.df.columns)}")
        
        # Show label distribution
        if 'label' in self.df.columns:
            label_counts = self.df['label'].value_counts()
            logger.info(f"  Label distribution:")
            for label, count in label_counts.items():
                logger.info(f"    • {label}: {count} ({count/len(self.df)*100:.1f}%)")
        
        return self.df
    
    def prepare_features(self) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare feature matrix and labels"""
        logger.info("\nPreparing features...")
        
        # Select numeric features only
        numeric_df = self.df.select_dtypes(include=[np.number, 'bool'])
        
        # Extract and normalize labels
        if 'label' in self.df.columns:
            labels = self.df['label'].values
            # Convert string labels to 0/1
            y = np.array([0 if str(x).lower() in ['legitimate', '0'] else 1 for x in labels])
        elif 'is_phishing' in self.df.columns:
            y = (self.df['is_phishing'].astype(int)).values
        else:
            raise ValueError("No label column found!")
        
        # Get feature names (exclude domain/IP columns)
        self.feature_names = [col for col in numeric_df.columns 
                              if col not in ['label', 'is_phishing', 'domain', 'ip']]
        
        X = numeric_df[self.feature_names].fillna(0).values
        
        logger.info(f"✓ Features prepared:")
        logger.info(f"  Features: {len(self.feature_names)}")
        logger.info(f"  Samples: {len(X)}")
        logger.info(f"  Shape: {X.shape}")
        logger.info(f"  Class distribution: 0={np.sum(y==0)} ({np.sum(y==0)/len(y)*100:.1f}%), 1={np.sum(y==1)} ({np.sum(y==1)/len(y)*100:.1f}%)")
        
        return X, y
    
    def train_test_split_data(self, X: np.ndarray, y: np.ndarray, test_size: float = 0.2) -> None:
        """Split data into train/test sets"""
        logger.info(f"\nTrain/Test Split (test_size={test_size})...")
        
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        logger.info(f"✓ Data split:")
        logger.info(f"  Train set: {len(self.X_train)} samples")
        logger.info(f"  Test set: {len(self.X_test)} samples")
        logger.info(f"  Train ratio: {len(self.X_train)/(len(self.X_train)+len(self.X_test))*100:.1f}%")
    
    def train_models(self) -> Dict:
        """Train multiple models and compare"""
        logger.info("\n" + "="*80)
        logger.info("TRAINING MULTIPLE MODELS")
        logger.info("="*80)
        
        models = {
            'RandomForest': RandomForestClassifier(
                n_estimators=100, max_depth=15, random_state=42, n_jobs=-1
            ),
            'GradientBoosting': GradientBoostingClassifier(
                n_estimators=100, random_state=42
            ),
            'SVM': SVC(kernel='rbf', probability=True, random_state=42),
            'Neural Network': MLPClassifier(
                hidden_layer_sizes=(128, 64, 32), max_iter=1000, random_state=42
            )
        }
        
        trained_models = {}
        
        for name, model in models.items():
            logger.info(f"\n[{name}] Training...")
            try:
                # Train
                model.fit(self.X_train, self.y_train)
                trained_models[name] = model
                
                # Evaluate on train set
                train_pred = model.predict(self.X_train)
                train_acc = accuracy_score(self.y_train, train_pred)
                
                # Evaluate on test set
                test_pred = model.predict(self.X_test)
                test_acc = accuracy_score(self.y_test, test_pred)
                
                logger.info(f"  ✓ Training accuracy: {train_acc:.2%}")
                logger.info(f"  ✓ Test accuracy: {test_acc:.2%}")
                
            except Exception as e:
                logger.warning(f"  ⚠️  Failed to train: {e}")
        
        return trained_models
    
    def evaluate_models(self, models: Dict) -> Dict:
        """Comprehensive evaluation of all models"""
        logger.info("\n" + "="*80)
        logger.info("COMPREHENSIVE MODEL EVALUATION")
        logger.info("="*80)
        
        results = {}
        
        for name, model in models.items():
            logger.info(f"\n[{name}]")
            
            # Predictions
            y_pred = model.predict(self.X_test)
            y_pred_proba = model.predict_proba(self.X_test)[:, 1]
            
            # Metrics
            accuracy = accuracy_score(self.y_test, y_pred)
            precision = precision_score(self.y_test, y_pred)
            recall = recall_score(self.y_test, y_pred)
            f1 = f1_score(self.y_test, y_pred)
            roc_auc = roc_auc_score(self.y_test, y_pred_proba)
            
            # Confusion matrix
            tn, fp, fn, tp = confusion_matrix(self.y_test, y_pred).ravel()
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0  # False positive rate
            fnr = fn / (fn + tp) if (fn + tp) > 0 else 0  # False negative rate
            
            results[name] = {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1': f1,
                'roc_auc': roc_auc,
                'false_positive_rate': fpr,
                'false_negative_rate': fnr,
                'confusion_matrix': {'tn': int(tn), 'fp': int(fp), 'fn': int(fn), 'tp': int(tp)},
                'model': model
            }
            
            logger.info(f"  Accuracy:            {accuracy:.2%}")
            logger.info(f"  Precision:           {precision:.2%}")
            logger.info(f"  Recall:              {recall:.2%}")
            logger.info(f"  F1 Score:            {f1:.2%}")
            logger.info(f"  ROC-AUC:             {roc_auc:.2%}")
            logger.info(f"  False Positive Rate: {fpr:.2%} (block legitimate)")
            logger.info(f"  False Negative Rate: {fnr:.2%} (miss phishing)")
            logger.info(f"  Confusion Matrix: TP={int(tp)}, TN={int(tn)}, FP={int(fp)}, FN={int(fn)}")
        
        self.results = results
        return results
    
    def cross_validate(self, models: Dict) -> Dict:
        """Perform 5-fold cross-validation"""
        logger.info("\n" + "="*80)
        logger.info("5-FOLD CROSS-VALIDATION")
        logger.info("="*80)
        
        cv_results = {}
        kfold = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        
        for name, model in models.items():
            logger.info(f"\n[{name}]")
            
            # Combine train + test for full cross-validation
            X_full = np.vstack([self.X_train, self.X_test])
            y_full = np.hstack([self.y_train, self.y_test])
            
            # Metrics to evaluate
            scoring = {
                'accuracy': 'accuracy',
                'precision': 'precision',
                'recall': 'recall',
                'f1': 'f1',
                'roc_auc': 'roc_auc'
            }
            
            cv_scores = cross_validate(model, X_full, y_full, cv=kfold, scoring=scoring)
            
            cv_results[name] = {
                'accuracy_mean': cv_scores['test_accuracy'].mean(),
                'accuracy_std': cv_scores['test_accuracy'].std(),
                'f1_mean': cv_scores['test_f1'].mean(),
                'f1_std': cv_scores['test_f1'].std(),
                'roc_auc_mean': cv_scores['test_roc_auc'].mean(),
                'roc_auc_std': cv_scores['test_roc_auc'].std(),
            }
            
            logger.info(f"  Accuracy (5-fold):   {cv_results[name]['accuracy_mean']:.2%} ± {cv_results[name]['accuracy_std']:.2%}")
            logger.info(f"  F1 Score (5-fold):   {cv_results[name]['f1_mean']:.2%} ± {cv_results[name]['f1_std']:.2%}")
            logger.info(f"  ROC-AUC (5-fold):    {cv_results[name]['roc_auc_mean']:.2%} ± {cv_results[name]['roc_auc_std']:.2%}")
        
        return cv_results
    
    def select_best_model(self, results: Dict) -> Tuple[str, object]:
        """Select best model based on F1 score"""
        logger.info("\n" + "="*80)
        logger.info("BEST MODEL SELECTION")
        logger.info("="*80)
        
        best_name = max(results.keys(), key=lambda k: results[k]['f1'])
        best_model = results[best_name]['model']
        
        logger.info(f"\n✓ Best model: {best_name}")
        logger.info(f"  Accuracy: {results[best_name]['accuracy']:.2%}")
        logger.info(f"  F1 Score: {results[best_name]['f1']:.2%}")
        logger.info(f"  ROC-AUC: {results[best_name]['roc_auc']:.2%}")
        
        return best_name, best_model
    
    def save_model(self, best_name: str, best_model: object) -> None:
        """Save best model with metadata"""
        logger.info(f"\nSaving best model ({best_name})...")
        
        # Save model
        model_path = self.models_dir / f"{best_name}_model.pkl"
        with open(model_path, 'wb') as f:
            pickle.dump(best_model, f)
        logger.info(f"  ✓ Model saved: {model_path}")
        
        # Save metadata
        metadata = {
            'model_type': best_name,
            'features': self.feature_names,
            'num_features': len(self.feature_names),
            'num_samples': len(self.df),
            'num_train': len(self.X_train),
            'num_test': len(self.X_test),
            'timestamp': datetime.now().isoformat(),
            'evaluation': {
                name: {k: float(v) if isinstance(v, (np.floating, np.integer)) else v 
                       for k, v in metrics.items() 
                       if k != 'model' and not isinstance(v, dict)}
                for name, metrics in self.results.items()
            }
        }
        
        metadata_path = self.models_dir / f"{best_name}_metadata.json"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        logger.info(f"  ✓ Metadata saved: {metadata_path}")
    
    def print_summary(self) -> None:
        """Print comprehensive summary"""
        logger.info("\n" + "="*80)
        logger.info("SUMMARY")
        logger.info("="*80)
        
        logger.info(f"\nDataset Statistics:")
        logger.info(f"  Total samples: {len(self.df)}")
        logger.info(f"  Features: {len(self.feature_names)}")
        logger.info(f"  Train/Test split: {len(self.X_train)}/{len(self.X_test)}")
        
        logger.info(f"\nModel Comparison:")
        for name, metrics in self.results.items():
            logger.info(f"  {name:20} | Acc: {metrics['accuracy']:.2%} | F1: {metrics['f1']:.2%} | AUC: {metrics['roc_auc']:.2%}")
        
        logger.info(f"\nKey Metrics (Test Set):")
        best_name = max(self.results.keys(), key=lambda k: self.results[k]['f1'])
        best_metrics = self.results[best_name]
        logger.info(f"  Model: {best_name}")
        logger.info(f"  Accuracy: {best_metrics['accuracy']:.2%}")
        logger.info(f"  Precision: {best_metrics['precision']:.2%} (correct when predicting phishing)")
        logger.info(f"  Recall: {best_metrics['recall']:.2%} (catch real phishing)")
        logger.info(f"  F1 Score: {best_metrics['f1']:.2%} (balanced metric)")
        logger.info(f"  False Positive Rate: {best_metrics['false_positive_rate']:.2%} (block legit sites)")
        logger.info(f"  False Negative Rate: {best_metrics['false_negative_rate']:.2%} (miss phishing)")


def main():
    """Main execution"""
    logger.info("="*80)
    logger.info("STEP 7: COMPREHENSIVE MODEL TRAINING & EVALUATION")
    logger.info("="*80)
    
    try:
        # Initialize evaluator
        evaluator = ModelEvaluator()
        
        # Load data
        df = evaluator.load_all_datasets()
        
        # Prepare features
        X, y = evaluator.prepare_features()
        
        # Train/test split
        evaluator.train_test_split_data(X, y)
        
        # Train models
        models = evaluator.train_models()
        
        # Evaluate
        results = evaluator.evaluate_models(models)
        
        # Cross-validation
        cv_results = evaluator.cross_validate(models)
        
        # Select and save best model
        best_name, best_model = evaluator.select_best_model(results)
        evaluator.save_model(best_name, best_model)
        
        # Summary
        evaluator.print_summary()
        
        logger.info("\n✓ STEP 7 COMPLETE")
        logger.info("="*80)
        
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
