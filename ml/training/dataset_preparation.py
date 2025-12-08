"""
Dataset Preparation Module for PHP Malware Detection

This module handles loading, preprocessing, and splitting datasets
for training malware detection models.

Data Sources:
- Malware samples from curated PHP malware repositories
- Benign samples from WordPress core, popular plugins, and themes
- Demo samples included with the plugin
"""

import os
import json
import hashlib
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, field
import numpy as np


@dataclass
class Sample:
    """Represents a single code sample."""
    file_path: str
    content: str
    label: int  # 0 = benign, 1 = malicious
    source: str  # e.g., 'demo', 'wordpress_core', 'malware_repo'
    hash: str = field(default='')
    metadata: Dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.hash:
            self.hash = hashlib.sha256(self.content.encode('utf-8', errors='ignore')).hexdigest()


@dataclass
class Dataset:
    """Container for training/validation/test datasets."""
    samples: List[Sample]
    name: str
    version: str = '1.0'

    @property
    def features(self) -> List[str]:
        return [s.content for s in self.samples]

    @property
    def labels(self) -> np.ndarray:
        return np.array([s.label for s in self.samples])

    @property
    def malicious_count(self) -> int:
        return sum(1 for s in self.samples if s.label == 1)

    @property
    def benign_count(self) -> int:
        return sum(1 for s in self.samples if s.label == 0)

    def stats(self) -> Dict:
        """Return dataset statistics."""
        return {
            'total_samples': len(self.samples),
            'malicious': self.malicious_count,
            'benign': self.benign_count,
            'balance_ratio': self.malicious_count / max(self.benign_count, 1),
            'sources': list(set(s.source for s in self.samples))
        }


class DatasetLoader:
    """
    Load and prepare datasets from various sources.
    """

    # Known malware signatures for auto-labeling
    MALWARE_INDICATORS = [
        r'eval\s*\(\s*\$_(GET|POST|REQUEST)',
        r'eval\s*\(\s*base64_decode',
        r'shell_exec\s*\(\s*\$_',
        r'system\s*\(\s*\$_',
        r'passthru\s*\(\s*\$_',
        r'c99|r57|b374k|wso|alfa',
        r'FilesMan|Pwned|Hacked\s*By',
    ]

    def __init__(self, data_dir: str = 'data'):
        """
        Initialize the dataset loader.

        Args:
            data_dir: Directory containing data files
        """
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def load_demo_samples(self, demo_dir: str = '../demo/sample-threats') -> Dataset:
        """
        Load samples from the plugin's demo directory.

        Args:
            demo_dir: Path to demo sample threats directory

        Returns:
            Dataset with demo samples
        """
        samples = []
        demo_path = Path(demo_dir)

        if not demo_path.exists():
            # Try relative to this file
            demo_path = Path(__file__).parent.parent.parent / 'demo' / 'sample-threats'

        if not demo_path.exists():
            print(f"Warning: Demo directory not found: {demo_path}")
            return Dataset(samples=[], name='demo')

        for php_file in demo_path.glob('*.php'):
            try:
                content = php_file.read_text(encoding='utf-8', errors='ignore')

                # Auto-label based on filename and content
                is_malicious = self._auto_label(php_file.name, content)

                samples.append(Sample(
                    file_path=str(php_file),
                    content=content,
                    label=is_malicious,
                    source='demo',
                    metadata={'filename': php_file.name}
                ))
            except Exception as e:
                print(f"Error loading {php_file}: {e}")

        return Dataset(samples=samples, name='demo')

    def load_directory(
        self,
        directory: str,
        label: int,
        source: str,
        extensions: Set[str] = {'.php'}
    ) -> Dataset:
        """
        Load all PHP files from a directory with a given label.

        Args:
            directory: Path to directory
            label: Label to assign (0=benign, 1=malicious)
            source: Source identifier
            extensions: File extensions to include

        Returns:
            Dataset with loaded samples
        """
        samples = []
        dir_path = Path(directory)

        if not dir_path.exists():
            print(f"Warning: Directory not found: {dir_path}")
            return Dataset(samples=[], name=source)

        for file_path in dir_path.rglob('*'):
            if file_path.suffix.lower() not in extensions:
                continue

            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')

                # Skip very small or very large files
                if len(content) < 10 or len(content) > 1_000_000:
                    continue

                samples.append(Sample(
                    file_path=str(file_path),
                    content=content,
                    label=label,
                    source=source
                ))
            except Exception as e:
                print(f"Error loading {file_path}: {e}")

        return Dataset(samples=samples, name=source)

    def load_labeled_json(self, json_path: str) -> Dataset:
        """
        Load dataset from a JSON file with labels.

        Expected format:
        {
            "samples": [
                {"file_path": "...", "content": "...", "label": 0/1, "source": "..."},
                ...
            ]
        }

        Args:
            json_path: Path to JSON file

        Returns:
            Dataset with loaded samples
        """
        samples = []

        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        for item in data.get('samples', []):
            samples.append(Sample(
                file_path=item.get('file_path', ''),
                content=item.get('content', ''),
                label=item.get('label', 0),
                source=item.get('source', 'json'),
                metadata=item.get('metadata', {})
            ))

        return Dataset(
            samples=samples,
            name=data.get('name', 'json_dataset'),
            version=data.get('version', '1.0')
        )

    def save_dataset(self, dataset: Dataset, output_path: str):
        """
        Save dataset to JSON file.

        Args:
            dataset: Dataset to save
            output_path: Output file path
        """
        data = {
            'name': dataset.name,
            'version': dataset.version,
            'stats': dataset.stats(),
            'samples': [
                {
                    'file_path': s.file_path,
                    'content': s.content,
                    'label': s.label,
                    'source': s.source,
                    'hash': s.hash,
                    'metadata': s.metadata
                }
                for s in dataset.samples
            ]
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

        print(f"Saved {len(dataset.samples)} samples to {output_path}")

    def _auto_label(self, filename: str, content: str) -> int:
        """
        Automatically determine if a sample is malicious.

        Args:
            filename: Name of the file
            content: File content

        Returns:
            1 if malicious, 0 if benign
        """
        import re

        # Check filename indicators
        benign_names = ['clean', 'safe', 'legitimate', 'normal']
        if any(name in filename.lower() for name in benign_names):
            return 0

        malicious_names = ['malware', 'backdoor', 'shell', 'exploit', 'injection',
                          'obfuscated', 'crypto', 'eval']
        if any(name in filename.lower() for name in malicious_names):
            return 1

        # Check content patterns
        for pattern in self.MALWARE_INDICATORS:
            if re.search(pattern, content, re.IGNORECASE):
                return 1

        return 0


def split_dataset(
    dataset: Dataset,
    train_ratio: float = 0.7,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
    stratify: bool = True,
    random_state: int = 42
) -> Tuple[Dataset, Dataset, Dataset]:
    """
    Split dataset into train/validation/test sets.

    Args:
        dataset: Input dataset
        train_ratio: Fraction for training
        val_ratio: Fraction for validation
        test_ratio: Fraction for testing
        stratify: Whether to maintain label distribution
        random_state: Random seed for reproducibility

    Returns:
        Tuple of (train_dataset, val_dataset, test_dataset)
    """
    from sklearn.model_selection import train_test_split

    assert abs(train_ratio + val_ratio + test_ratio - 1.0) < 0.001, \
        "Ratios must sum to 1.0"

    samples = dataset.samples
    labels = [s.label for s in samples]

    # First split: train vs (val + test)
    train_samples, temp_samples, train_labels, temp_labels = train_test_split(
        samples, labels,
        train_size=train_ratio,
        stratify=labels if stratify else None,
        random_state=random_state
    )

    # Second split: val vs test
    val_ratio_adjusted = val_ratio / (val_ratio + test_ratio)
    val_samples, test_samples = train_test_split(
        temp_samples,
        train_size=val_ratio_adjusted,
        stratify=temp_labels if stratify else None,
        random_state=random_state
    )

    return (
        Dataset(samples=train_samples, name=f'{dataset.name}_train'),
        Dataset(samples=val_samples, name=f'{dataset.name}_val'),
        Dataset(samples=test_samples, name=f'{dataset.name}_test')
    )


def merge_datasets(*datasets: Dataset, name: str = 'merged') -> Dataset:
    """
    Merge multiple datasets into one.

    Args:
        *datasets: Datasets to merge
        name: Name for merged dataset

    Returns:
        Merged dataset
    """
    all_samples = []
    seen_hashes: Set[str] = set()

    for ds in datasets:
        for sample in ds.samples:
            # Deduplicate by content hash
            if sample.hash not in seen_hashes:
                all_samples.append(sample)
                seen_hashes.add(sample.hash)

    return Dataset(samples=all_samples, name=name)


def balance_dataset(
    dataset: Dataset,
    strategy: str = 'undersample',
    random_state: int = 42
) -> Dataset:
    """
    Balance dataset by under/over-sampling.

    Args:
        dataset: Input dataset
        strategy: 'undersample' or 'oversample'
        random_state: Random seed

    Returns:
        Balanced dataset
    """
    np.random.seed(random_state)

    malicious = [s for s in dataset.samples if s.label == 1]
    benign = [s for s in dataset.samples if s.label == 0]

    if strategy == 'undersample':
        # Reduce majority class
        target_size = min(len(malicious), len(benign))
        if len(malicious) > len(benign):
            malicious = list(np.random.choice(malicious, target_size, replace=False))
        else:
            benign = list(np.random.choice(benign, target_size, replace=False))
    elif strategy == 'oversample':
        # Increase minority class
        target_size = max(len(malicious), len(benign))
        if len(malicious) < len(benign):
            malicious = list(np.random.choice(malicious, target_size, replace=True))
        else:
            benign = list(np.random.choice(benign, target_size, replace=True))

    balanced_samples = malicious + benign
    np.random.shuffle(balanced_samples)

    return Dataset(
        samples=list(balanced_samples),
        name=f'{dataset.name}_balanced'
    )


if __name__ == '__main__':
    # Example usage
    loader = DatasetLoader()

    # Load demo samples
    demo_dataset = loader.load_demo_samples()
    print(f"Demo dataset: {demo_dataset.stats()}")

    if demo_dataset.samples:
        # Split into train/val/test
        train, val, test = split_dataset(demo_dataset)
        print(f"Train: {train.stats()}")
        print(f"Val: {val.stats()}")
        print(f"Test: {test.stats()}")

        # Save dataset
        loader.save_dataset(demo_dataset, 'data/demo_dataset.json')
