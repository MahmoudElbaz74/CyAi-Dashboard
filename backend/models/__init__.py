"""
AI Models Integration Module
This module provides integration for pre-trained AI models:
- log_classifier: classifies and labels network/system logs
- phishing_detector: classifies URLs as Safe/Suspicious/Malicious  
- malware_detector: scans uploaded files and predicts maliciousness + type/family
"""

from .log_classifier import LogClassifier
from .phishing_detector import PhishingDetector
from .malware_detector import MalwareDetector

__all__ = ['LogClassifier', 'PhishingDetector', 'MalwareDetector']
