"""
Machine Learning Model Module for Phishing Detection

This module:
1. Loads labeled feature datasets
2. Preprocesses and scales features
3. Trains multiple models (Random Forest, XGBoost)
4. Evaluates and selects best model
5. Saves trained model for inference

Author: Research Team
Date: 2026
"""

import logging
import pickle
import json
from typing import Dict, Tuple, List, Optional, Any
from pathlib import Path
from datetime import datetime
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score, roc_curve
)
import warnings
warnings.filterwarnings('ignore')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

try:
    import xgboost as xgb
    HAS_XGBOOST = True
except (ImportError, Exception) as e:
    HAS_XGBOOST = False
    logger.warning(f"XGBoost not available: {type(e).__name__}. Using Random Forest only.")


@pd.api.extensions.register_dataframe_accessor("ml")
class MLAccessor:
    """Pandas accessor for ML operations"""
    def __init__(self, pandas_obj):
        self._obj = pandas_obj


class DataPreprocessor:
    """Preprocesses feature data for ML"""
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_columns = None
        self.is_fitted = False
    
    def load_dataset(self, csv_file: str) -> pd.DataFrame:
        """Load dataset from CSV"""
        logger.info(f"Loading dataset: {csv_file}")
        df = pd.read_csv(csv_file)
        logger.info(f"Dataset shape: {df.shape}")
        logger.info(f"Columns: {list(df.columns)}")
        return df
    
    def prepare_features(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """
        Prepare features and labels for training
        
        Returns:
            X: Feature matrix
            y: Label vector
            feature_columns: List of feature names used
        """
        logger.info("Preparing features...")
        
        # Drop non-feature columns.
        # Absolute timestamps are dropped: their values differ between training and
        # inference (different wall-clock times), causing the scaler to produce
        # out-of-range values at prediction time.  Use dns_to_tls_delay instead.
        drop_cols = [
            'domain', 'destination_ip', 'sni', 'timestamp', 'label',
            'session_dns_query_timestamp', 'session_tls_handshake_timestamp',
        ]
        X = df.drop(columns=[c for c in drop_cols if c in df.columns], errors='ignore')
        
        # Drop string/object columns (non-numeric)
        X = X.select_dtypes(include=[np.number, 'bool'])
        
        # Store feature columns
        self.feature_columns = X.columns.tolist()
        logger.info(f"Features: {len(self.feature_columns)}")
        
        # Handle missing values
        X = X.fillna(0)
        
        # Convert boolean columns to int
        for col in X.columns:
            if X[col].dtype == bool:
                X[col] = X[col].astype(int)
        
        # Get labels
        y = df['label'].values
        y_encoded = self.label_encoder.fit_transform(y)
        
        logger.info(f"Class distribution:")
        for label, count in zip(self.label_encoder.classes_, np.bincount(y_encoded)):
            logger.info(f"  {label}: {count} ({100*count//len(y)}%)")
        
        return X.values, y_encoded, self.feature_columns
    
    def scale_features(self, X: np.ndarray, fit: bool = False) -> np.ndarray:
        """Scale features using StandardScaler"""
        if fit:
            X_scaled = self.scaler.fit_transform(X)
            self.is_fitted = True
        else:
            X_scaled = self.scaler.transform(X)
        
        return X_scaled
    
    def get_feature_names(self) -> List[str]:
        """Get list of feature names"""
        return self.feature_columns or []


class ModelTrainer:
    """Trains and evaluates ML models"""
    
    def __init__(self):
        self.models = {}
        self.results = {}
        self.best_model = None
        self.best_model_name = None
    
    def train_random_forest(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        n_estimators: int = 100,
        max_depth: int = 15,
        random_state: int = 42
    ) -> RandomForestClassifier:
        """Train Random Forest model"""
        logger.info("Training Random Forest...")
        
        model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=random_state,
            n_jobs=-1,
            verbose=0,
            class_weight='balanced',  # corrects for phishing-heavy datasets
        )
        
        model.fit(X_train, y_train)
        logger.info("✓ Random Forest trained")
        
        self.models['RandomForest'] = model
        return model
    
    def train_xgboost(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        max_depth: int = 6,
        learning_rate: float = 0.1,
        n_estimators: int = 100,
        random_state: int = 42
    ) -> Optional[Any]:
        """Train XGBoost model (if available)"""
        if not HAS_XGBOOST:
            logger.warning("XGBoost not installed, skipping")
            return None
        
        logger.info("Training XGBoost...")
        
        model = xgb.XGBClassifier(
            max_depth=max_depth,
            learning_rate=learning_rate,
            n_estimators=n_estimators,
            random_state=random_state,
            use_label_encoder=False,
            eval_metric='logloss',
            verbosity=0
        )
        
        model.fit(X_train, y_train)
        logger.info("✓ XGBoost trained")
        
        self.models['XGBoost'] = model
        return model
    
    def evaluate_models(
        self,
        X_test: np.ndarray,
        y_test: np.ndarray
    ) -> Dict[str, Dict]:
        """Evaluate all trained models"""
        logger.info("Evaluating models...")
        
        for name, model in self.models.items():
            logger.info(f"\nEvaluating {name}...")
            
            # Predictions
            y_pred = model.predict(X_test)
            y_pred_proba = model.predict_proba(X_test)[:, 1]
            
            # Metrics
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred, zero_division=0)
            recall = recall_score(y_test, y_pred, zero_division=0)
            f1 = f1_score(y_test, y_pred, zero_division=0)
            roc_auc = roc_auc_score(y_test, y_pred_proba)
            
            cm = confusion_matrix(y_test, y_pred)
            
            results = {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1': f1,
                'roc_auc': roc_auc,
                'confusion_matrix': cm.tolist(),
                'y_pred': y_pred.tolist(),
                'y_pred_proba': y_pred_proba.tolist()
            }
            
            self.results[name] = results
            
            logger.info(f"  Accuracy:  {accuracy:.4f}")
            logger.info(f"  Precision: {precision:.4f}")
            logger.info(f"  Recall:    {recall:.4f}")
            logger.info(f"  F1-Score:  {f1:.4f}")
            logger.info(f"  ROC-AUC:   {roc_auc:.4f}")
        
        return self.results
    
    def select_best_model(self) -> Tuple[str, Any, Dict]:
        """Select best model based on F1 score"""
        best_f1 = -1
        
        for name, results in self.results.items():
            f1 = results['f1']
            if f1 > best_f1:
                best_f1 = f1
                self.best_model_name = name
                self.best_model = self.models[name]
        
        logger.info(f"\n✓ Best model: {self.best_model_name} (F1: {best_f1:.4f})")
        
        return self.best_model_name, self.best_model, self.results[self.best_model_name]
    
    def cross_validate(
        self,
        X: np.ndarray,
        y: np.ndarray,
        model_name: str = 'RandomForest',
        k: int = 5
    ) -> Dict:
        """Run stratified k-fold cross-validation on a trained model"""
        model = self.models.get(model_name)
        if model is None:
            logger.warning(f"Model {model_name} not found for CV")
            return {}

        cv = StratifiedKFold(n_splits=k, shuffle=True, random_state=42)
        for metric, scorer in [('accuracy', 'accuracy'), ('f1', 'f1'), ('roc_auc', 'roc_auc')]:
            scores = cross_val_score(model, X, y, cv=cv, scoring=scorer, n_jobs=-1)
            logger.info(f"  CV {metric}: {scores.mean():.4f} ± {scores.std():.4f}")

        scores_f1 = cross_val_score(model, X, y, cv=cv, scoring='f1', n_jobs=-1)
        return {'cv_f1_mean': float(scores_f1.mean()), 'cv_f1_std': float(scores_f1.std())}

    def save_model(
        self,
        feature_names: Optional[List[str]] = None,
        scaler: Optional[StandardScaler] = None,
        output_dir: str = "models"
    ) -> Tuple[str, str]:
        """Save best model and scaler to disk"""
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        if not self.best_model:
            raise ValueError("No model trained yet")

        # Save model
        model_file = Path(output_dir) / f"{self.best_model_name}_model.pkl"
        with open(model_file, 'wb') as f:
            pickle.dump(self.best_model, f)
        logger.info(f"✓ Model saved: {model_file}")

        # Save scaler alongside model so inference uses the same scaling
        if scaler is not None:
            scaler_file = Path(output_dir) / "scaler.pkl"
            with open(scaler_file, 'wb') as f:
                pickle.dump(scaler, f)
            logger.info(f"✓ Scaler saved: {scaler_file}")

        # Save metadata with features
        metadata = {
            'model_name': self.best_model_name,
            'model_type': self.best_model_name,
            'features': feature_names or [],
            'accuracy': self.results[self.best_model_name]['accuracy'],
            'precision': self.results[self.best_model_name]['precision'],
            'recall': self.results[self.best_model_name]['recall'],
            'f1': self.results[self.best_model_name]['f1'],
            'roc_auc': self.results[self.best_model_name]['roc_auc'],
            'timestamp': datetime.now().isoformat(),
            'model_file': str(model_file),
            'results': self.results[self.best_model_name]
        }

        # Convert non-serializable types
        metadata['results']['confusion_matrix'] = metadata['results']['confusion_matrix']
        metadata['results']['y_pred'] = metadata['results']['y_pred']
        metadata['results']['y_pred_proba'] = metadata['results']['y_pred_proba']

        metadata_file = Path(output_dir) / f"{self.best_model_name}_metadata.json"
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        logger.info(f"✓ Metadata saved: {metadata_file}")

        return str(model_file), str(metadata_file)


class MLPipeline:
    """End-to-end ML pipeline"""
    
    def __init__(self, csv_file: str):
        self.csv_file = csv_file
        self.preprocessor = DataPreprocessor()
        self.trainer = ModelTrainer()
    
    def run(self, test_size: float = 0.2) -> Dict:
        """Run complete ML pipeline"""
        
        print("\n" + "="*80)
        print("PHISHING DETECTION ML PIPELINE")
        print("="*80 + "\n")
        
        # 1. Load data
        df = self.preprocessor.load_dataset(self.csv_file)
        
        # 2. Prepare features
        X, y, feature_names = self.preprocessor.prepare_features(df)
        print(f"\n✓ Features prepared: {X.shape}")
        
        # 3. Train-test split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        print(f"✓ Train set: {X_train.shape[0]} | Test set: {X_test.shape[0]}")
        
        # 4. Scale features
        X_train_scaled = self.preprocessor.scale_features(X_train, fit=True)
        X_test_scaled = self.preprocessor.scale_features(X_test, fit=False)
        print(f"✓ Features scaled")
        
        # 5. Train models
        print(f"\n{'='*80}")
        print("TRAINING MODELS")
        print("="*80)
        self.trainer.train_random_forest(X_train_scaled, y_train)
        self.trainer.train_xgboost(X_train_scaled, y_train)
        
        # 6. Evaluate models
        print(f"\n{'='*80}")
        print("EVALUATING MODELS")
        print("="*80)
        self.trainer.evaluate_models(X_test_scaled, y_test)
        
        # 7. Select best model
        best_name, best_model, best_results = self.trainer.select_best_model()

        # 8. Cross-validation on the full scaled dataset
        print(f"\n{'='*80}")
        print("CROSS-VALIDATION (5-fold stratified)")
        print("="*80)
        X_all_scaled = self.preprocessor.scale_features(X, fit=False)
        cv_results = self.trainer.cross_validate(X_all_scaled, y, model_name=best_name, k=5)

        # 9. Save model + scaler
        print(f"\n{'='*80}")
        print("SAVING MODEL")
        print("="*80)
        model_file, metadata_file = self.trainer.save_model(
            feature_names=feature_names,
            scaler=self.preprocessor.scaler
        )
        
        print(f"\n{'='*80}")
        print("ML PIPELINE COMPLETE ✓")
        print("="*80)
        print(f"\nBest Model: {best_name}")
        print(f"  Accuracy:  {best_results['accuracy']:.2%}")
        print(f"  Precision: {best_results['precision']:.2%}")
        print(f"  Recall:    {best_results['recall']:.2%}")
        print(f"  F1-Score:  {best_results['f1']:.2%}")
        print(f"  ROC-AUC:   {best_results['roc_auc']:.2%}")
        if cv_results:
            print(f"  CV F1:     {cv_results['cv_f1_mean']:.2%} ± {cv_results['cv_f1_std']:.2%}")
        print(f"\nModel saved to: {model_file}")
        print("="*80 + "\n")

        return {
            'best_model': best_name,
            'model_file': model_file,
            'metadata_file': metadata_file,
            'results': best_results,
            'cv_results': cv_results,
            'preprocessor': self.preprocessor
        }


def train_model_from_csv(csv_file: str) -> Dict:
    """Convenient function to train model from CSV"""
    pipeline = MLPipeline(csv_file)
    return pipeline.run()


if __name__ == "__main__":
    # Example usage
    csv_file = "data/phishing_dataset.csv"
    if Path(csv_file).exists():
        train_model_from_csv(csv_file)
    else:
        print(f"Dataset not found: {csv_file}")
        print("Run: python3 create_real_dataset.py")
