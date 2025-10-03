from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import logging
import sys
import os

# Add the backend directory to the path to import models
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.model_manager import get_model_manager, ModelManager
from models.phishing_detector import PhishingDetectionRequest, PhishingDetectionResponse

router = APIRouter()
logger = logging.getLogger(__name__)

class LinkAnalysisRequest(BaseModel):
    """Request model for link analysis"""
    url: str
    include_analysis: Optional[bool] = True
    check_reputation: Optional[bool] = True

class LinkAnalysisResponse(BaseModel):
    """Response model for link analysis"""
    classification: str  # Safe, Suspicious, Malicious
    confidence: float
    risk_score: float
    analysis_details: Dict[str, Any]
    recommendations: List[str]

class BatchLinkAnalysisRequest(BaseModel):
    """Request model for batch link analysis"""
    urls: List[str]
    include_analysis: Optional[bool] = True
    check_reputation: Optional[bool] = True

# Dependency injection
def get_model_manager_dependency() -> ModelManager:
    """Dependency to get model manager"""
    return get_model_manager()

@router.post("/analyze", response_model=LinkAnalysisResponse)
async def analyze_link(
    request: LinkAnalysisRequest,
    model_manager: ModelManager = Depends(get_model_manager_dependency)
):
    """
    Analyze a URL for phishing using pre-trained model
    
    Args:
        request: Link analysis request
        model_manager: Model manager dependency
        
    Returns:
        Link analysis result
    """
    try:
        # Get phishing detector model
        phishing_detector = model_manager.get_phishing_detector()
        
        # Create detection request
        detection_request = PhishingDetectionRequest(
            url=request.url,
            include_analysis=request.include_analysis,
            check_reputation=request.check_reputation
        )
        
        # Detect phishing
        result = phishing_detector.detect_phishing(detection_request)
        
        return LinkAnalysisResponse(
            classification=result.classification,
            confidence=result.confidence,
            risk_score=result.risk_score,
            analysis_details=result.analysis_details,
            recommendations=result.recommendations
        )
        
    except Exception as e:
        logger.error(f"Error in link analysis: {e}")
        raise HTTPException(status_code=500, detail=f"Link analysis failed: {str(e)}")

@router.post("/analyze-batch", response_model=List[LinkAnalysisResponse])
async def analyze_batch_links(
    request: BatchLinkAnalysisRequest,
    model_manager: ModelManager = Depends(get_model_manager_dependency)
):
    """
    Analyze multiple URLs in batch using pre-trained model
    
    Args:
        request: Batch link analysis request
        model_manager: Model manager dependency
        
    Returns:
        List of link analysis results
    """
    try:
        # Get phishing detector model
        phishing_detector = model_manager.get_phishing_detector()
        
        # Create detection requests
        detection_requests = [
            PhishingDetectionRequest(
                url=url,
                include_analysis=request.include_analysis,
                check_reputation=request.check_reputation
            )
            for url in request.urls
        ]
        
        # Detect phishing for all URLs in batch
        results = phishing_detector.detect_batch(detection_requests)
        
        # Convert to response format
        response_results = [
            LinkAnalysisResponse(
                classification=result.classification,
                confidence=result.confidence,
                risk_score=result.risk_score,
                analysis_details=result.analysis_details,
                recommendations=result.recommendations
            )
            for result in results
        ]
        
        return response_results
        
    except Exception as e:
        logger.error(f"Error in batch link analysis: {e}")
        raise HTTPException(status_code=500, detail=f"Batch link analysis failed: {str(e)}")

@router.get("/model-info")
async def get_link_analysis_model_info(
    model_manager: ModelManager = Depends(get_model_manager_dependency)
):
    """
    Get information about the link analysis model
    
    Returns:
        Model information
    """
    try:
        phishing_detector = model_manager.get_phishing_detector()
        return phishing_detector.get_model_info()
    except Exception as e:
        logger.error(f"Error getting model info: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get model info: {str(e)}")

# Legacy link analyzer (kept for backward compatibility)
class LegacyLinkAnalyzer:
    """Legacy link analyzer using simple domain blacklist"""
    
    def __init__(self):
        self.malicious_domains = ["malicious.com", "phishing.com"]  # Example list of malicious domains

    def is_malicious(self, url: str) -> bool:
        """Check if URL is in malicious domains list"""
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        return domain in self.malicious_domains

    def analyze_links(self, urls: List[str]) -> dict:
        """Analyze multiple URLs"""
        results = {}
        for url in urls:
            results[url] = self.is_malicious(url)
        return results

    def check_url(self, url: str) -> str:
        """Get human-readable URL check result"""
        if self.is_malicious(url):
            return f"The URL {url} is malicious."
        else:
            return f"The URL {url} is safe."