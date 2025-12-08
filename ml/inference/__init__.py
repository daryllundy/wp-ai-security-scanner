"""
Inference module for PHP Malware Detection ML Pipeline.
"""

from .inference_server import app, load_model, predict_single

__all__ = ['app', 'load_model', 'predict_single']
