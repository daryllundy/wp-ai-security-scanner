"""
Training module for PHP Malware Detection ML Pipeline.
"""

from .feature_extraction import PHPFeatureExtractor, FeatureVector, extract_features_batch
from .dataset_preparation import DatasetLoader, Dataset, Sample, split_dataset, merge_datasets
from .train_classifier import MalwareClassifierTrainer, TrainingConfig
from .evaluation import ModelEvaluator, EvaluationMetrics

__all__ = [
    'PHPFeatureExtractor',
    'FeatureVector',
    'extract_features_batch',
    'DatasetLoader',
    'Dataset',
    'Sample',
    'split_dataset',
    'merge_datasets',
    'MalwareClassifierTrainer',
    'TrainingConfig',
    'ModelEvaluator',
    'EvaluationMetrics',
]
