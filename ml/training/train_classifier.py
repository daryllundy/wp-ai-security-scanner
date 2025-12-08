"""
Model Training Script for PHP Malware Detection

This script trains machine learning models to classify PHP code as
malicious or benign based on extracted features.

Models Supported:
- Random Forest (baseline, interpretable)
- XGBoost (production candidate)
- Neural Network (MLP, highest accuracy)

Usage:
    python train_classifier.py --model xgboost --data data/dataset.json
    python train_classifier.py --model all --data data/dataset.json
"""

import argparse
import json
import os
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
import numpy as np
import joblib

# ML imports
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score
)

try:
    import xgboost as xgb
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False
    print("Warning: XGBoost not installed. Install with: pip install xgboost")

# Local imports
from feature_extraction import PHPFeatureExtractor, extract_features_batch
from dataset_preparation import DatasetLoader, split_dataset, Dataset


@dataclass
class TrainingConfig:
    """Configuration for model training."""
    model_type: str = 'xgboost'
    n_estimators: int = 500
    max_depth: int = 10
    learning_rate: float = 0.1
    random_state: int = 42
    n_jobs: int = -1
    early_stopping_rounds: int = 50
    output_dir: str = 'models'


@dataclass
class TrainingResult:
    """Results from model training."""
    model_name: str
    accuracy: float
    precision: float
    recall: float
    f1: float
    auc_roc: float
    confusion_matrix: np.ndarray
    training_time_seconds: float
    feature_importance: Optional[Dict[str, float]] = None


class MalwareClassifierTrainer:
    """
    Train and evaluate malware detection models.
    """

    def __init__(self, config: TrainingConfig):
        """
        Initialize the trainer.

        Args:
            config: Training configuration
        """
        self.config = config
        self.extractor = PHPFeatureExtractor()
        self.scaler = StandardScaler()
        self.model = None
        self.feature_names = self.extractor.feature_names

        # Create output directory
        Path(config.output_dir).mkdir(parents=True, exist_ok=True)

    def prepare_features(
        self,
        dataset: Dataset,
        fit_scaler: bool = True
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Extract and prepare features from dataset.

        Args:
            dataset: Input dataset
            fit_scaler: Whether to fit the scaler (True for training)

        Returns:
            Tuple of (features, labels)
        """
        print(f"Extracting features from {len(dataset.samples)} samples...")

        # Extract features
        files = [(s.file_path, s.content) for s in dataset.samples]
        X, _ = extract_features_batch(files, self.extractor)
        y = dataset.labels

        # Scale features
        if fit_scaler:
            X = self.scaler.fit_transform(X)
        else:
            X = self.scaler.transform(X)

        return X, y

    def create_model(self, model_type: str):
        """
        Create a model instance.

        Args:
            model_type: Type of model to create

        Returns:
            Sklearn-compatible model
        """
        if model_type == 'random_forest':
            return RandomForestClassifier(
                n_estimators=self.config.n_estimators,
                max_depth=self.config.max_depth,
                random_state=self.config.random_state,
                n_jobs=self.config.n_jobs,
                class_weight='balanced'
            )

        elif model_type == 'xgboost':
            if not HAS_XGBOOST:
                raise ImportError("XGBoost not installed")

            return xgb.XGBClassifier(
                n_estimators=self.config.n_estimators,
                max_depth=self.config.max_depth,
                learning_rate=self.config.learning_rate,
                random_state=self.config.random_state,
                n_jobs=self.config.n_jobs,
                use_label_encoder=False,
                eval_metric='logloss',
                scale_pos_weight=1.0  # Adjust for imbalanced data
            )

        elif model_type == 'mlp':
            return MLPClassifier(
                hidden_layer_sizes=(128, 64, 32),
                activation='relu',
                solver='adam',
                alpha=0.001,
                batch_size=32,
                learning_rate='adaptive',
                max_iter=500,
                random_state=self.config.random_state,
                early_stopping=True,
                validation_fraction=0.1
            )

        else:
            raise ValueError(f"Unknown model type: {model_type}")

    def train(
        self,
        train_dataset: Dataset,
        val_dataset: Optional[Dataset] = None
    ) -> TrainingResult:
        """
        Train the model.

        Args:
            train_dataset: Training dataset
            val_dataset: Optional validation dataset for early stopping

        Returns:
            TrainingResult with metrics
        """
        print(f"\nTraining {self.config.model_type} model...")
        start_time = time.time()

        # Prepare features
        X_train, y_train = self.prepare_features(train_dataset, fit_scaler=True)

        # Create and train model
        self.model = self.create_model(self.config.model_type)

        if val_dataset and self.config.model_type == 'xgboost' and HAS_XGBOOST:
            # Use early stopping with XGBoost
            X_val, y_val = self.prepare_features(val_dataset, fit_scaler=False)
            self.model.fit(
                X_train, y_train,
                eval_set=[(X_val, y_val)],
                verbose=False
            )
        else:
            self.model.fit(X_train, y_train)

        training_time = time.time() - start_time
        print(f"Training completed in {training_time:.2f} seconds")

        # Evaluate on training data (for sanity check)
        return self.evaluate(train_dataset, 'train', training_time)

    def evaluate(
        self,
        dataset: Dataset,
        split_name: str = 'test',
        training_time: float = 0.0
    ) -> TrainingResult:
        """
        Evaluate model on a dataset.

        Args:
            dataset: Dataset to evaluate on
            split_name: Name of the split (for logging)
            training_time: Training time in seconds

        Returns:
            TrainingResult with metrics
        """
        X, y_true = self.prepare_features(dataset, fit_scaler=False)

        y_pred = self.model.predict(X)
        y_proba = self.model.predict_proba(X)[:, 1] if hasattr(self.model, 'predict_proba') else y_pred

        # Calculate metrics
        accuracy = accuracy_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        auc_roc = roc_auc_score(y_true, y_proba) if len(np.unique(y_true)) > 1 else 0.0
        cm = confusion_matrix(y_true, y_pred)

        # Get feature importance
        feature_importance = self._get_feature_importance()

        print(f"\n{split_name.upper()} Results:")
        print(f"  Accuracy:  {accuracy:.4f}")
        print(f"  Precision: {precision:.4f}")
        print(f"  Recall:    {recall:.4f}")
        print(f"  F1 Score:  {f1:.4f}")
        print(f"  AUC-ROC:   {auc_roc:.4f}")
        print(f"\nConfusion Matrix:\n{cm}")

        return TrainingResult(
            model_name=self.config.model_type,
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1=f1,
            auc_roc=auc_roc,
            confusion_matrix=cm,
            training_time_seconds=training_time,
            feature_importance=feature_importance
        )

    def _get_feature_importance(self) -> Optional[Dict[str, float]]:
        """Get feature importance from the model."""
        if hasattr(self.model, 'feature_importances_'):
            importances = self.model.feature_importances_
            return dict(zip(self.feature_names, importances))
        return None

    def save_model(self, path: Optional[str] = None):
        """
        Save trained model to disk.

        Args:
            path: Output path (default: models/{model_type}_model.joblib)
        """
        if path is None:
            path = f"{self.config.output_dir}/{self.config.model_type}_model.joblib"

        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'config': self.config
        }

        joblib.dump(model_data, path)
        print(f"Model saved to {path}")

    def load_model(self, path: str):
        """
        Load trained model from disk.

        Args:
            path: Path to model file
        """
        model_data = joblib.load(path)
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.feature_names = model_data['feature_names']
        print(f"Model loaded from {path}")

    def export_onnx(self, path: Optional[str] = None):
        """
        Export model to ONNX format for cross-platform inference.

        Args:
            path: Output path (default: models/{model_type}_model.onnx)
        """
        try:
            from skl2onnx import convert_sklearn
            from skl2onnx.common.data_types import FloatTensorType
        except ImportError:
            print("Warning: skl2onnx not installed. Install with: pip install skl2onnx")
            return

        if path is None:
            path = f"{self.config.output_dir}/{self.config.model_type}_model.onnx"

        # Define input type
        initial_type = [('features', FloatTensorType([None, len(self.feature_names)]))]

        # Convert to ONNX
        onnx_model = convert_sklearn(self.model, initial_types=initial_type)

        with open(path, 'wb') as f:
            f.write(onnx_model.SerializeToString())

        print(f"ONNX model exported to {path}")


def train_all_models(
    train_dataset: Dataset,
    val_dataset: Dataset,
    test_dataset: Dataset,
    output_dir: str = 'models'
) -> Dict[str, TrainingResult]:
    """
    Train and evaluate all available models.

    Args:
        train_dataset: Training data
        val_dataset: Validation data
        test_dataset: Test data
        output_dir: Output directory

    Returns:
        Dictionary of model name to results
    """
    results = {}
    models = ['random_forest', 'mlp']

    if HAS_XGBOOST:
        models.append('xgboost')

    for model_type in models:
        print(f"\n{'='*60}")
        print(f"Training {model_type}")
        print(f"{'='*60}")

        config = TrainingConfig(model_type=model_type, output_dir=output_dir)
        trainer = MalwareClassifierTrainer(config)

        # Train
        trainer.train(train_dataset, val_dataset)

        # Evaluate on test set
        result = trainer.evaluate(test_dataset, 'test')
        results[model_type] = result

        # Save model
        trainer.save_model()

        # Export to ONNX (for random forest and MLP)
        if model_type in ['random_forest', 'mlp']:
            try:
                trainer.export_onnx()
            except Exception as e:
                print(f"Warning: ONNX export failed: {e}")

    return results


def print_model_comparison(results: Dict[str, TrainingResult]):
    """Print a comparison table of model results."""
    print(f"\n{'='*80}")
    print("MODEL COMPARISON")
    print(f"{'='*80}")
    print(f"{'Model':<20} {'Accuracy':>10} {'Precision':>10} {'Recall':>10} {'F1':>10} {'AUC-ROC':>10}")
    print(f"{'-'*80}")

    for name, result in results.items():
        print(f"{name:<20} {result.accuracy:>10.4f} {result.precision:>10.4f} "
              f"{result.recall:>10.4f} {result.f1:>10.4f} {result.auc_roc:>10.4f}")

    # Find best model
    best_model = max(results.items(), key=lambda x: x[1].f1)
    print(f"\nBest model (by F1): {best_model[0]} with F1={best_model[1].f1:.4f}")


def main():
    parser = argparse.ArgumentParser(description='Train PHP malware detection models')
    parser.add_argument('--model', type=str, default='xgboost',
                       choices=['random_forest', 'xgboost', 'mlp', 'all'],
                       help='Model type to train')
    parser.add_argument('--data', type=str, default=None,
                       help='Path to dataset JSON file')
    parser.add_argument('--demo', action='store_true',
                       help='Use demo samples for training')
    parser.add_argument('--output', type=str, default='models',
                       help='Output directory for models')
    parser.add_argument('--n-estimators', type=int, default=500,
                       help='Number of estimators for ensemble models')
    parser.add_argument('--max-depth', type=int, default=10,
                       help='Maximum tree depth')

    args = parser.parse_args()

    # Load dataset
    loader = DatasetLoader()

    if args.data:
        dataset = loader.load_labeled_json(args.data)
    elif args.demo:
        dataset = loader.load_demo_samples()
    else:
        print("Error: Specify --data or --demo")
        return

    print(f"Dataset loaded: {dataset.stats()}")

    if len(dataset.samples) < 10:
        print("Error: Need at least 10 samples for training")
        return

    # Split dataset
    train_ds, val_ds, test_ds = split_dataset(dataset)

    if args.model == 'all':
        # Train all models
        results = train_all_models(train_ds, val_ds, test_ds, args.output)
        print_model_comparison(results)
    else:
        # Train single model
        config = TrainingConfig(
            model_type=args.model,
            n_estimators=args.n_estimators,
            max_depth=args.max_depth,
            output_dir=args.output
        )
        trainer = MalwareClassifierTrainer(config)
        trainer.train(train_ds, val_ds)
        result = trainer.evaluate(test_ds, 'test')
        trainer.save_model()

        # Print feature importance
        if result.feature_importance:
            print("\nTop 10 Most Important Features:")
            sorted_features = sorted(
                result.feature_importance.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]
            for name, importance in sorted_features:
                print(f"  {name}: {importance:.4f}")


if __name__ == '__main__':
    main()
