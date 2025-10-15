from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import logging

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
    labels: Optional[List[str]] = []
    analysis_details: Optional[Dict[str, Any]] = {}

class NetworkLogData(BaseModel):
    log_entries: List[str]
    log_type: Optional[str] = "network"
    include_confidence: Optional[bool] = True

# Dependency injection
def get_model_manager_dependency() -> ModelManager:
    return get_model_manager()

@router.post("/detect", response_model=DetectionResult)
async def detect_traffic(
    data: TrafficData,
    model_manager: ModelManager = Depends(get_model_manager_dependency)
):
    # Use fixed default log_type = 'network' (TrafficData doesn't contain log_type)
    try:
        log_entry = f"{data.timestamp or 'N/A'} {data.source_ip} -> {data.destination_ip} {data.protocol} {data.payload}"

        log_request = LogClassificationRequest(
            log_data=log_entry,
            log_type="network",
            include_confidence=True
        )

        log_classifier = model_manager.get_log_classifier()

        # ensure model loaded or use heuristic fallback explicitly
        if not getattr(log_classifier, 'model', None) and not getattr(log_classifier, 'feature_names', None):
            raise HTTPException(status_code=500, detail="Log classification model not loaded on server")

        classification_result = log_classifier.classify_log(log_request)

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

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in traffic detection: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Traffic detection failed: {str(e)}")

@router.post("/analyze-logs", response_model=List[LogClassificationResponse])
async def classify_network_logs(
    log_data: NetworkLogData,
    model_manager: ModelManager = Depends(get_model_manager_dependency)
):
    try:
        log_classifier = model_manager.get_log_classifier()

        # Prevent silent failure if model loading failed unexpectedly
        if log_classifier is None:
            raise HTTPException(status_code=500, detail="Log classifier unavailable")

        # Build requests
        log_requests = [
            LogClassificationRequest(
                log_data=log_entry,
                log_type=log_data.log_type,
                include_confidence=log_data.include_confidence
            )
            for log_entry in log_data.log_entries
        ]

        results = log_classifier.classify_batch(log_requests)

        # Always return a list for consistency
        return results

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in log classification: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Log classification failed: {str(e)}")

@router.get("/model-info")
async def get_network_detection_model_info(
    model_manager: ModelManager = Depends(get_model_manager_dependency)
):
    try:
        log_classifier = model_manager.get_log_classifier()
        info = log_classifier.get_model_info() if log_classifier else {}
        return {"model_info": info}
    except Exception as e:
        logger.error(f"Error getting model info: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to get model info: {str(e)}")
