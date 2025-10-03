from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import logging
import sys
import os

# Add the backend directory to the path to import models
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.model_manager import get_model_manager, ModelManager
from models.log_classifier import LogClassificationRequest, LogClassificationResponse

router = APIRouter()
logger = logging.getLogger(__name__)

class TrafficData(BaseModel):
    source_ip: str
    destination_ip: str
    protocol: str
    payload: str
    timestamp: Optional[str] = None

class DetectionResult(BaseModel):
    is_malicious: bool
    confidence_score: float
    classification: str
    labels: List[str]
    analysis_details: Dict[str, Any]

class NetworkLogData(BaseModel):
    log_entries: List[str]
    log_type: Optional[str] = "network"
    include_confidence: Optional[bool] = True

# Dependency injection
def get_model_manager_dependency() -> ModelManager:
    """Dependency to get model manager"""
    return get_model_manager()

@router.post("/detect", response_model=DetectionResult)
async def detect_traffic(
    data: TrafficData,
    model_manager: ModelManager = Depends(get_model_manager_dependency)
):
    """
    Detect malicious traffic using pre-trained log classifier model
    
    Args:
        data: Traffic data to analyze
        model_manager: Model manager dependency
        
    Returns:
        Detection result with classification
    """
    try:
        # Convert traffic data to log format for classification
        log_entry = f"{data.timestamp or 'N/A'} {data.source_ip} -> {data.destination_ip} {data.protocol} {data.payload}"
        
        # Create log classification request
        log_request = LogClassificationRequest(
            log_data=log_entry,
            log_type=data.log_type or "network",
            include_confidence=True
        )
        
        # Get log classifier model
        log_classifier = model_manager.get_log_classifier()
        
        # Classify the log
        classification_result = log_classifier.classify_log(log_request)
        
        # Convert classification to detection result
        is_malicious = classification_result.classification in ["Suspicious", "Malicious"]
        
        return DetectionResult(
            is_malicious=is_malicious,
            confidence_score=classification_result.confidence,
            classification=classification_result.classification,
            labels=classification_result.labels,
            analysis_details={
                "log_analysis": classification_result.details,
                "traffic_info": {
                    "source_ip": data.source_ip,
                    "destination_ip": data.destination_ip,
                    "protocol": data.protocol
                }
            }
        )
        
    except Exception as e:
        logger.error(f"Error in traffic detection: {e}")
        raise HTTPException(status_code=500, detail=f"Traffic detection failed: {str(e)}")

@router.post("/classify-logs", response_model=List[LogClassificationResponse])
async def classify_network_logs(
    log_data: NetworkLogData,
    model_manager: ModelManager = Depends(get_model_manager_dependency)
):
    """
    Classify multiple network log entries using pre-trained model
    
    Args:
        log_data: Network log data to classify
        model_manager: Model manager dependency
        
    Returns:
        List of classification results
    """
    try:
        # Get log classifier model
        log_classifier = model_manager.get_log_classifier()
        
        # Create classification requests for each log entry
        log_requests = [
            LogClassificationRequest(
                log_data=log_entry,
                log_type=log_data.log_type,
                include_confidence=log_data.include_confidence
            )
            for log_entry in log_data.log_entries
        ]
        
        # Classify all logs in batch
        results = log_classifier.classify_batch(log_requests)
        
        return results
        
    except Exception as e:
        logger.error(f"Error in log classification: {e}")
        raise HTTPException(status_code=500, detail=f"Log classification failed: {str(e)}")

@router.get("/model-info")
async def get_network_detection_model_info(
    model_manager: ModelManager = Depends(get_model_manager_dependency)
):
    """
    Get information about the network detection model
    
    Returns:
        Model information
    """
    try:
        log_classifier = model_manager.get_log_classifier()
        return log_classifier.get_model_info()
    except Exception as e:
        logger.error(f"Error getting model info: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get model info: {str(e)}")