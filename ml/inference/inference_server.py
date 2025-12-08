"""
Inference Server for PHP Malware Detection

A lightweight Flask REST API for serving malware detection predictions.
Designed for integration with the WordPress plugin via HTTP requests.

Usage:
    # Start server
    python inference_server.py --model models/xgboost_model.joblib --port 5000

    # Or with gunicorn (production)
    gunicorn -w 4 -b 0.0.0.0:5000 inference_server:app

API Endpoints:
    POST /predict         - Predict single file
    POST /predict_batch   - Predict multiple files
    GET  /health          - Health check
    GET  /model_info      - Model information
"""

import argparse
import logging
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Any

import numpy as np
import joblib
from flask import Flask, request, jsonify

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / 'training'))

from feature_extraction import PHPFeatureExtractor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Flask application
app = Flask(__name__)

# Global model and extractor
model = None
scaler = None
feature_names = None
extractor = None
model_info = {}


def load_model(model_path: str) -> bool:
    """
    Load model from disk.

    Args:
        model_path: Path to model file

    Returns:
        True if successful
    """
    global model, scaler, feature_names, extractor, model_info

    try:
        logger.info(f"Loading model from {model_path}")

        model_data = joblib.load(model_path)

        model = model_data['model']
        scaler = model_data['scaler']
        feature_names = model_data.get('feature_names', [])
        config = model_data.get('config', {})

        extractor = PHPFeatureExtractor()

        model_info = {
            'model_type': getattr(config, 'model_type', 'unknown'),
            'feature_count': len(feature_names),
            'model_path': model_path,
            'loaded_at': time.strftime('%Y-%m-%d %H:%M:%S')
        }

        logger.info(f"Model loaded successfully: {model_info}")
        return True

    except Exception as e:
        logger.error(f"Failed to load model: {e}")
        return False


def predict_single(content: str, file_path: str = '') -> Dict[str, Any]:
    """
    Predict maliciousness of a single file.

    Args:
        content: PHP code content
        file_path: Optional file path for context

    Returns:
        Prediction result dictionary
    """
    start_time = time.time()

    try:
        # Extract features
        fv = extractor.extract(content, file_path)
        features = fv.features.reshape(1, -1)

        # Scale features
        if scaler is not None:
            features = scaler.transform(features)

        # Predict
        prediction = int(model.predict(features)[0])

        # Get probability if available
        if hasattr(model, 'predict_proba'):
            probabilities = model.predict_proba(features)[0]
            confidence = float(probabilities[1]) if prediction == 1 else float(probabilities[0])
            malicious_probability = float(probabilities[1])
        else:
            confidence = 1.0 if prediction == 1 else 0.0
            malicious_probability = float(prediction)

        # Determine severity based on confidence
        if prediction == 1:
            if malicious_probability >= 0.9:
                severity = 'critical'
            elif malicious_probability >= 0.7:
                severity = 'high'
            elif malicious_probability >= 0.5:
                severity = 'medium'
            else:
                severity = 'low'
        else:
            severity = 'none'

        inference_time = (time.time() - start_time) * 1000

        return {
            'success': True,
            'prediction': {
                'is_malicious': bool(prediction),
                'confidence': round(confidence, 4),
                'malicious_probability': round(malicious_probability, 4),
                'severity': severity,
                'label': 'malicious' if prediction == 1 else 'benign'
            },
            'metadata': {
                'file_path': file_path,
                'feature_extraction_ms': round(fv.extraction_time_ms, 2),
                'inference_ms': round(inference_time, 2),
                'total_ms': round(fv.extraction_time_ms + inference_time, 2)
            }
        }

    except Exception as e:
        logger.error(f"Prediction error: {e}")
        return {
            'success': False,
            'error': str(e)
        }


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    if model is None:
        return jsonify({
            'status': 'unhealthy',
            'message': 'Model not loaded'
        }), 503

    return jsonify({
        'status': 'healthy',
        'model_loaded': True,
        'model_info': model_info
    })


@app.route('/model_info', methods=['GET'])
def get_model_info():
    """Get model information."""
    if model is None:
        return jsonify({
            'error': 'Model not loaded'
        }), 503

    return jsonify({
        'model_info': model_info,
        'feature_names': feature_names[:20] if feature_names else [],  # First 20 features
        'feature_count': len(feature_names) if feature_names else 0
    })


@app.route('/predict', methods=['POST'])
def predict():
    """
    Predict single file.

    Request body:
    {
        "content": "<?php ... ?>",
        "file_path": "optional/path.php"
    }

    Response:
    {
        "success": true,
        "prediction": {
            "is_malicious": true/false,
            "confidence": 0.95,
            "malicious_probability": 0.95,
            "severity": "critical|high|medium|low|none",
            "label": "malicious|benign"
        },
        "metadata": {
            "file_path": "...",
            "inference_ms": 15.2
        }
    }
    """
    if model is None:
        return jsonify({
            'success': False,
            'error': 'Model not loaded'
        }), 503

    data = request.get_json()

    if not data or 'content' not in data:
        return jsonify({
            'success': False,
            'error': 'Missing required field: content'
        }), 400

    content = data['content']
    file_path = data.get('file_path', '')

    # Limit content size
    max_size = 1_000_000  # 1MB
    if len(content) > max_size:
        return jsonify({
            'success': False,
            'error': f'Content too large. Maximum size: {max_size} bytes'
        }), 400

    result = predict_single(content, file_path)
    status_code = 200 if result['success'] else 500

    return jsonify(result), status_code


@app.route('/predict_batch', methods=['POST'])
def predict_batch():
    """
    Predict multiple files.

    Request body:
    {
        "files": [
            {"content": "<?php ... ?>", "file_path": "path1.php"},
            {"content": "<?php ... ?>", "file_path": "path2.php"}
        ]
    }

    Response:
    {
        "success": true,
        "predictions": [...],
        "summary": {
            "total": 10,
            "malicious": 3,
            "benign": 7
        }
    }
    """
    if model is None:
        return jsonify({
            'success': False,
            'error': 'Model not loaded'
        }), 503

    data = request.get_json()

    if not data or 'files' not in data:
        return jsonify({
            'success': False,
            'error': 'Missing required field: files'
        }), 400

    files = data['files']

    # Limit batch size
    max_batch = 100
    if len(files) > max_batch:
        return jsonify({
            'success': False,
            'error': f'Batch too large. Maximum: {max_batch} files'
        }), 400

    predictions = []
    malicious_count = 0
    benign_count = 0

    for file_data in files:
        content = file_data.get('content', '')
        file_path = file_data.get('file_path', '')

        result = predict_single(content, file_path)
        predictions.append(result)

        if result['success'] and result['prediction']['is_malicious']:
            malicious_count += 1
        else:
            benign_count += 1

    return jsonify({
        'success': True,
        'predictions': predictions,
        'summary': {
            'total': len(predictions),
            'malicious': malicious_count,
            'benign': benign_count
        }
    })


@app.route('/features', methods=['POST'])
def get_features():
    """
    Get extracted features for debugging/analysis.

    Request body:
    {
        "content": "<?php ... ?>"
    }

    Response:
    {
        "success": true,
        "features": {...}
    }
    """
    data = request.get_json()

    if not data or 'content' not in data:
        return jsonify({
            'success': False,
            'error': 'Missing required field: content'
        }), 400

    content = data['content']

    try:
        fv = extractor.extract(content)

        # Create feature dict
        features_dict = {}
        for name, value in zip(fv.feature_names, fv.features):
            if value != 0:  # Only include non-zero features
                features_dict[name] = float(value)

        return jsonify({
            'success': True,
            'features': features_dict,
            'extraction_time_ms': fv.extraction_time_ms
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors."""
    return jsonify({
        'error': 'Endpoint not found',
        'available_endpoints': [
            'GET /health',
            'GET /model_info',
            'POST /predict',
            'POST /predict_batch',
            'POST /features'
        ]
    }), 404


@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors."""
    logger.error(f"Server error: {e}")
    return jsonify({
        'error': 'Internal server error',
        'message': str(e)
    }), 500


def main():
    parser = argparse.ArgumentParser(description='Malware Detection Inference Server')
    parser.add_argument('--model', type=str, required=True,
                       help='Path to model file (.joblib)')
    parser.add_argument('--host', type=str, default='0.0.0.0',
                       help='Host to bind to')
    parser.add_argument('--port', type=int, default=5000,
                       help='Port to listen on')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug mode')

    args = parser.parse_args()

    # Load model
    if not load_model(args.model):
        logger.error("Failed to load model. Exiting.")
        sys.exit(1)

    # Start server
    logger.info(f"Starting server on {args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == '__main__':
    main()
