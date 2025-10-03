"""
Model Manager - Centralized management of all pre-trained AI models
"""

import logging
from typing import Dict, Any, Optional
from .log_classifier import LogClassifier
from .phishing_detector import PhishingDetector
from .malware_detector import MalwareDetector

logger = logging.getLogger(__name__)

class ModelManager:
    """
    Centralized manager for all pre-trained AI models
    """
    
    def __init__(self):
        """Initialize the model manager"""
        self.models = {}
        self._initialize_models()
    
    def _initialize_models(self):
        """Initialize all pre-trained models"""
        try:
            # Initialize log classifier
            self.models['log_classifier'] = LogClassifier()
            logger.info("Log classifier initialized")
            
            # Initialize phishing detector
            self.models['phishing_detector'] = PhishingDetector()
            logger.info("Phishing detector initialized")
            
            # Initialize malware detector
            self.models['malware_detector'] = MalwareDetector()
            logger.info("Malware detector initialized")
            
            logger.info("All models initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize models: {e}")
            raise
    
    def get_model(self, model_name: str):
        """
        Get a specific model by name
        
        Args:
            model_name: Name of the model to retrieve
            
        Returns:
            Model instance
        """
        if model_name not in self.models:
            raise ValueError(f"Model '{model_name}' not found. Available models: {list(self.models.keys())}")
        
        return self.models[model_name]
    
    def get_log_classifier(self) -> LogClassifier:
        """Get the log classifier model"""
        return self.get_model('log_classifier')
    
    def get_phishing_detector(self) -> PhishingDetector:
        """Get the phishing detector model"""
        return self.get_model('phishing_detector')
    
    def get_malware_detector(self) -> MalwareDetector:
        """Get the malware detector model"""
        return self.get_model('malware_detector')
    
    def get_all_models_info(self) -> Dict[str, Any]:
        """
        Get information about all loaded models
        
        Returns:
            Dictionary with information about all models
        """
        models_info = {}
        for name, model in self.models.items():
            try:
                models_info[name] = model.get_model_info()
            except Exception as e:
                logger.error(f"Error getting info for model {name}: {e}")
                models_info[name] = {"error": str(e)}
        
        return {
            "total_models": len(self.models),
            "models": models_info,
            "status": "all_loaded" if len(self.models) == 3 else "partial_load"
        }
    
    def health_check(self) -> Dict[str, Any]:
        """
        Perform health check on all models
        
        Returns:
            Health check results
        """
        health_status = {
            "overall_status": "healthy",
            "models": {},
            "timestamp": None
        }
        
        from datetime import datetime
        health_status["timestamp"] = datetime.now().isoformat()
        
        for name, model in self.models.items():
            try:
                # Simple health check - try to get model info
                model_info = model.get_model_info()
                health_status["models"][name] = {
                    "status": "healthy",
                    "info": model_info
                }
            except Exception as e:
                health_status["models"][name] = {
                    "status": "unhealthy",
                    "error": str(e)
                }
                health_status["overall_status"] = "degraded"
        
        return health_status

# Global model manager instance
_model_manager = None

def get_model_manager() -> ModelManager:
    """
    Get the global model manager instance (singleton pattern)
    
    Returns:
        ModelManager instance
    """
    global _model_manager
    if _model_manager is None:
        _model_manager = ModelManager()
    return _model_manager

def initialize_models() -> ModelManager:
    """
    Initialize and return the model manager
    
    Returns:
        ModelManager instance
    """
    return get_model_manager()
