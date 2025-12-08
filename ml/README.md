# Machine Learning Pipeline for PHP Malware Detection

This directory contains the ML training pipeline for the WordPress AI Security Scanner plugin. It provides tools for training, evaluating, and deploying machine learning models for malware detection.

## Directory Structure

```
ml/
├── training/
│   ├── feature_extraction.py    # PHP code feature engineering (100+ features)
│   ├── dataset_preparation.py   # Data loading and preprocessing
│   ├── train_classifier.py      # Main training script
│   └── evaluation.py            # Model evaluation and comparison
├── inference/
│   └── inference_server.py      # REST API for predictions
├── notebooks/
│   └── (Jupyter notebooks for analysis)
├── data/
│   └── (Training datasets)
├── models/
│   └── (Saved model files)
├── requirements.txt             # Python dependencies
└── README.md                    # This file
```

## Quick Start

### 1. Install Dependencies

```bash
cd ml
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Train a Model

Using demo samples:
```bash
cd training
python train_classifier.py --demo --model xgboost
```

Using custom dataset:
```bash
python train_classifier.py --data ../data/dataset.json --model xgboost
```

Train all models and compare:
```bash
python train_classifier.py --demo --model all
```

### 3. Start Inference Server

```bash
cd inference
python inference_server.py --model ../models/xgboost_model.joblib --port 5000
```

### 4. Make Predictions

```bash
curl -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"content": "<?php eval($_POST[\"cmd\"]); ?>", "file_path": "test.php"}'
```

## Feature Engineering

The feature extractor generates 100 numerical features from PHP code:

### Feature Categories

| Category | Count | Description |
|----------|-------|-------------|
| Lexical | 30 | Function calls, dangerous APIs |
| Statistical | 20 | Entropy, character distribution |
| Structural | 20 | Code complexity, nesting depth |
| Behavioral | 15 | User input, network, file ops |
| WordPress | 15 | Hooks, capabilities, DB access |

### Key Features

- **Shannon Entropy**: Detects encrypted/obfuscated code (threshold: 7.5 bits/byte)
- **Obfuscation Score**: Multi-factor scoring for code obfuscation patterns
- **Behavioral Score**: Cumulative risk scoring for suspicious behaviors
- **WordPress Security**: Checks for proper nonce/capability usage

## Models

### Supported Architectures

1. **Random Forest** (baseline)
   - 500 trees, max depth 10
   - Best for interpretability
   - Feature importance available

2. **XGBoost** (recommended)
   - Gradient boosting with early stopping
   - Best accuracy/speed tradeoff
   - Production-ready

3. **Neural Network (MLP)**
   - Architecture: 128 → 64 → 32 → 1
   - ReLU activation, dropout 0.3
   - Highest accuracy

### Model Export

Models can be exported to ONNX format for cross-platform inference:

```python
from train_classifier import MalwareClassifierTrainer, TrainingConfig

config = TrainingConfig(model_type='random_forest')
trainer = MalwareClassifierTrainer(config)
# ... train model ...
trainer.export_onnx('model.onnx')
```

## Dataset Preparation

### Expected Format

JSON format:
```json
{
  "name": "my_dataset",
  "version": "1.0",
  "samples": [
    {
      "file_path": "/path/to/file.php",
      "content": "<?php ... ?>",
      "label": 1,
      "source": "malware_repo"
    }
  ]
}
```

Labels:
- `0` = Benign
- `1` = Malicious

### Creating a Dataset

```python
from dataset_preparation import DatasetLoader, merge_datasets

loader = DatasetLoader()

# Load malware samples
malware = loader.load_directory('path/to/malware', label=1, source='malware')

# Load benign samples (WordPress core, plugins)
benign = loader.load_directory('path/to/wordpress', label=0, source='wordpress')

# Merge and save
dataset = merge_datasets(malware, benign, name='training_data')
loader.save_dataset(dataset, 'data/training_data.json')
```

## Evaluation Metrics

The evaluation module provides comprehensive metrics:

- **Accuracy**: Overall correctness
- **Precision**: True positives / (True positives + False positives)
- **Recall**: True positives / (True positives + False negatives)
- **F1 Score**: Harmonic mean of precision and recall
- **AUC-ROC**: Area under the ROC curve
- **False Positive Rate**: Critical for avoiding false alarms
- **False Negative Rate**: Critical for catching actual malware

### Target Performance

| Metric | Target | Notes |
|--------|--------|-------|
| Recall | >99% | Catch most malware |
| Precision | >95% | Minimize false positives |
| F1 Score | >0.97 | Balance precision/recall |
| FPR | <1% | Avoid annoying users |

## API Reference

### POST /predict

Predict single file maliciousness.

**Request:**
```json
{
  "content": "<?php echo 'hello'; ?>",
  "file_path": "test.php"
}
```

**Response:**
```json
{
  "success": true,
  "prediction": {
    "is_malicious": false,
    "confidence": 0.95,
    "malicious_probability": 0.05,
    "severity": "none",
    "label": "benign"
  },
  "metadata": {
    "inference_ms": 12.5
  }
}
```

### POST /predict_batch

Predict multiple files.

**Request:**
```json
{
  "files": [
    {"content": "...", "file_path": "file1.php"},
    {"content": "...", "file_path": "file2.php"}
  ]
}
```

### GET /health

Health check endpoint.

### GET /model_info

Get loaded model information.

## Integration with WordPress Plugin

The inference server can be integrated with the WordPress plugin via HTTP:

```php
// In class-malware-detector.php
private function ml_analysis($file_path, $content) {
    $response = wp_remote_post('http://localhost:5000/predict', [
        'body' => json_encode([
            'content' => $content,
            'file_path' => $file_path
        ]),
        'headers' => ['Content-Type' => 'application/json'],
        'timeout' => 30
    ]);

    if (is_wp_error($response)) {
        return [];
    }

    $result = json_decode(wp_remote_retrieve_body($response), true);

    if ($result['success'] && $result['prediction']['is_malicious']) {
        return [[
            'type' => 'ml_detection',
            'severity' => $result['prediction']['severity'],
            'confidence' => $result['prediction']['confidence'],
            'description' => 'Machine learning model detected potential malware'
        ]];
    }

    return [];
}
```

## Development

### Running Tests

```bash
pytest tests/ -v --cov=training
```

### Code Style

```bash
black training/ inference/
flake8 training/ inference/
mypy training/ inference/
```

### Adding New Features

1. Add feature extraction logic to `feature_extraction.py`
2. Update `_build_feature_names()` to include new feature names
3. Ensure feature count matches `feature_count` parameter
4. Retrain models with new features

## Troubleshooting

### Low Accuracy

- Ensure balanced dataset (use `balance_dataset()`)
- Try different model architectures
- Increase `n_estimators` for ensemble models
- Add more training data

### High False Positives

- Increase confidence threshold
- Add more benign samples to training data
- Use `find_optimal_threshold()` to tune threshold

### Memory Issues

- Reduce batch size
- Use `--max-depth` to limit tree depth
- Process files in smaller chunks

## References

- [PHP Malware Analysis Best Practices](https://owasp.org/www-project-web-security-testing-guide/)
- [Scikit-learn Documentation](https://scikit-learn.org/stable/)
- [XGBoost Documentation](https://xgboost.readthedocs.io/)
- [ONNX Runtime](https://onnxruntime.ai/)
