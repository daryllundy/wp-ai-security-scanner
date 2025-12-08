"""
Model Evaluation Module for PHP Malware Detection

This module provides comprehensive evaluation metrics, visualization,
and model comparison utilities.

Metrics:
- Classification metrics (accuracy, precision, recall, F1, AUC-ROC)
- Confusion matrix analysis
- ROC curves and Precision-Recall curves
- Feature importance analysis
- Cross-validation evaluation
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
import numpy as np

from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score,
    roc_curve, precision_recall_curve, average_precision_score
)
from sklearn.model_selection import cross_val_score, StratifiedKFold


@dataclass
class EvaluationMetrics:
    """Container for evaluation metrics."""
    accuracy: float
    precision: float
    recall: float
    f1: float
    auc_roc: float
    average_precision: float
    true_positives: int
    true_negatives: int
    false_positives: int
    false_negatives: int
    support_positive: int
    support_negative: int

    @property
    def false_positive_rate(self) -> float:
        """Calculate false positive rate."""
        return self.false_positives / max(self.false_positives + self.true_negatives, 1)

    @property
    def false_negative_rate(self) -> float:
        """Calculate false negative rate."""
        return self.false_negatives / max(self.false_negatives + self.true_positives, 1)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        d = asdict(self)
        d['false_positive_rate'] = self.false_positive_rate
        d['false_negative_rate'] = self.false_negative_rate
        return d


class ModelEvaluator:
    """
    Comprehensive model evaluation utilities.
    """

    def __init__(self, model, scaler=None, feature_names: Optional[List[str]] = None):
        """
        Initialize the evaluator.

        Args:
            model: Trained sklearn-compatible model
            scaler: Optional fitted scaler
            feature_names: Optional list of feature names
        """
        self.model = model
        self.scaler = scaler
        self.feature_names = feature_names

    def evaluate(
        self,
        X: np.ndarray,
        y_true: np.ndarray,
        threshold: float = 0.5
    ) -> EvaluationMetrics:
        """
        Evaluate model on test data.

        Args:
            X: Feature matrix
            y_true: True labels
            threshold: Classification threshold

        Returns:
            EvaluationMetrics object
        """
        # Scale features if scaler provided
        if self.scaler is not None:
            X = self.scaler.transform(X)

        # Get predictions
        y_pred = self.model.predict(X)

        # Get probabilities if available
        if hasattr(self.model, 'predict_proba'):
            y_proba = self.model.predict_proba(X)[:, 1]
            # Apply custom threshold
            y_pred = (y_proba >= threshold).astype(int)
        else:
            y_proba = y_pred.astype(float)

        # Calculate confusion matrix
        cm = confusion_matrix(y_true, y_pred)
        tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)

        # Calculate metrics
        return EvaluationMetrics(
            accuracy=accuracy_score(y_true, y_pred),
            precision=precision_score(y_true, y_pred, zero_division=0),
            recall=recall_score(y_true, y_pred, zero_division=0),
            f1=f1_score(y_true, y_pred, zero_division=0),
            auc_roc=roc_auc_score(y_true, y_proba) if len(np.unique(y_true)) > 1 else 0.0,
            average_precision=average_precision_score(y_true, y_proba) if len(np.unique(y_true)) > 1 else 0.0,
            true_positives=int(tp),
            true_negatives=int(tn),
            false_positives=int(fp),
            false_negatives=int(fn),
            support_positive=int(sum(y_true == 1)),
            support_negative=int(sum(y_true == 0))
        )

    def cross_validate(
        self,
        X: np.ndarray,
        y: np.ndarray,
        cv: int = 5,
        scoring: str = 'f1'
    ) -> Dict[str, float]:
        """
        Perform cross-validation.

        Args:
            X: Feature matrix
            y: Labels
            cv: Number of folds
            scoring: Scoring metric

        Returns:
            Dictionary with mean and std of scores
        """
        # Scale features if scaler provided
        if self.scaler is not None:
            X = self.scaler.transform(X)

        # Stratified K-Fold for imbalanced data
        skf = StratifiedKFold(n_splits=cv, shuffle=True, random_state=42)

        scores = cross_val_score(self.model, X, y, cv=skf, scoring=scoring)

        return {
            'mean': float(np.mean(scores)),
            'std': float(np.std(scores)),
            'scores': scores.tolist()
        }

    def get_roc_curve(
        self,
        X: np.ndarray,
        y_true: np.ndarray
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Calculate ROC curve data.

        Args:
            X: Feature matrix
            y_true: True labels

        Returns:
            Tuple of (fpr, tpr, thresholds)
        """
        if self.scaler is not None:
            X = self.scaler.transform(X)

        if hasattr(self.model, 'predict_proba'):
            y_proba = self.model.predict_proba(X)[:, 1]
        else:
            y_proba = self.model.predict(X).astype(float)

        fpr, tpr, thresholds = roc_curve(y_true, y_proba)
        return fpr, tpr, thresholds

    def get_precision_recall_curve(
        self,
        X: np.ndarray,
        y_true: np.ndarray
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Calculate Precision-Recall curve data.

        Args:
            X: Feature matrix
            y_true: True labels

        Returns:
            Tuple of (precision, recall, thresholds)
        """
        if self.scaler is not None:
            X = self.scaler.transform(X)

        if hasattr(self.model, 'predict_proba'):
            y_proba = self.model.predict_proba(X)[:, 1]
        else:
            y_proba = self.model.predict(X).astype(float)

        precision, recall, thresholds = precision_recall_curve(y_true, y_proba)
        return precision, recall, thresholds

    def get_feature_importance(self) -> Optional[Dict[str, float]]:
        """
        Get feature importance scores.

        Returns:
            Dictionary mapping feature names to importance scores
        """
        if not hasattr(self.model, 'feature_importances_'):
            return None

        importances = self.model.feature_importances_

        if self.feature_names:
            return dict(zip(self.feature_names, importances))
        else:
            return {f'feature_{i}': imp for i, imp in enumerate(importances)}

    def find_optimal_threshold(
        self,
        X: np.ndarray,
        y_true: np.ndarray,
        metric: str = 'f1'
    ) -> Tuple[float, float]:
        """
        Find optimal classification threshold.

        Args:
            X: Feature matrix
            y_true: True labels
            metric: Metric to optimize ('f1', 'precision', 'recall')

        Returns:
            Tuple of (optimal_threshold, metric_value)
        """
        if self.scaler is not None:
            X = self.scaler.transform(X)

        if not hasattr(self.model, 'predict_proba'):
            return 0.5, 0.0

        y_proba = self.model.predict_proba(X)[:, 1]

        best_threshold = 0.5
        best_score = 0.0

        for threshold in np.arange(0.1, 0.9, 0.05):
            y_pred = (y_proba >= threshold).astype(int)

            if metric == 'f1':
                score = f1_score(y_true, y_pred, zero_division=0)
            elif metric == 'precision':
                score = precision_score(y_true, y_pred, zero_division=0)
            elif metric == 'recall':
                score = recall_score(y_true, y_pred, zero_division=0)
            else:
                raise ValueError(f"Unknown metric: {metric}")

            if score > best_score:
                best_score = score
                best_threshold = threshold

        return best_threshold, best_score

    def generate_report(
        self,
        X: np.ndarray,
        y_true: np.ndarray,
        output_path: Optional[str] = None
    ) -> Dict:
        """
        Generate comprehensive evaluation report.

        Args:
            X: Feature matrix
            y_true: True labels
            output_path: Optional path to save report

        Returns:
            Report dictionary
        """
        metrics = self.evaluate(X, y_true)
        cv_results = self.cross_validate(X, y_true)
        optimal_threshold, optimal_score = self.find_optimal_threshold(X, y_true)
        feature_importance = self.get_feature_importance()

        report = {
            'metrics': metrics.to_dict(),
            'cross_validation': cv_results,
            'optimal_threshold': {
                'threshold': optimal_threshold,
                'f1_score': optimal_score
            },
            'feature_importance': feature_importance,
            'classification_report': classification_report(
                y_true,
                self.model.predict(self.scaler.transform(X) if self.scaler else X),
                output_dict=True
            )
        }

        if output_path:
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            print(f"Report saved to {output_path}")

        return report


def compare_models(
    models: Dict[str, Tuple[Any, Any]],
    X_test: np.ndarray,
    y_test: np.ndarray,
    feature_names: Optional[List[str]] = None
) -> Dict[str, EvaluationMetrics]:
    """
    Compare multiple models.

    Args:
        models: Dictionary of model_name -> (model, scaler)
        X_test: Test features
        y_test: Test labels
        feature_names: Optional feature names

    Returns:
        Dictionary of model_name -> metrics
    """
    results = {}

    for name, (model, scaler) in models.items():
        evaluator = ModelEvaluator(model, scaler, feature_names)
        metrics = evaluator.evaluate(X_test, y_test)
        results[name] = metrics

    return results


def print_comparison_table(results: Dict[str, EvaluationMetrics]):
    """Print a formatted comparison table."""
    print(f"\n{'='*90}")
    print("MODEL COMPARISON")
    print(f"{'='*90}")
    print(f"{'Model':<20} {'Acc':>8} {'Prec':>8} {'Recall':>8} {'F1':>8} {'AUC':>8} {'FPR':>8} {'FNR':>8}")
    print(f"{'-'*90}")

    for name, m in results.items():
        print(f"{name:<20} {m.accuracy:>8.4f} {m.precision:>8.4f} {m.recall:>8.4f} "
              f"{m.f1:>8.4f} {m.auc_roc:>8.4f} {m.false_positive_rate:>8.4f} "
              f"{m.false_negative_rate:>8.4f}")

    print(f"{'='*90}")


if __name__ == '__main__':
    # Example usage with dummy data
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler

    # Generate dummy data
    np.random.seed(42)
    X = np.random.randn(200, 10)
    y = (X[:, 0] + X[:, 1] > 0).astype(int)

    # Split data
    X_train, X_test = X[:150], X[150:]
    y_train, y_test = y[:150], y[150:]

    # Train model
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train_scaled, y_train)

    # Evaluate
    feature_names = [f'feature_{i}' for i in range(10)]
    evaluator = ModelEvaluator(model, scaler, feature_names)

    metrics = evaluator.evaluate(X_test, y_test)
    print(f"Metrics: {metrics.to_dict()}")

    cv_results = evaluator.cross_validate(X_train, y_train)
    print(f"CV Results: {cv_results}")

    optimal_threshold, optimal_f1 = evaluator.find_optimal_threshold(X_test, y_test)
    print(f"Optimal threshold: {optimal_threshold:.2f} (F1={optimal_f1:.4f})")

    feature_importance = evaluator.get_feature_importance()
    print(f"Top features: {sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)[:5]}")
