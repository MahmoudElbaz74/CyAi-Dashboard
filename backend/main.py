from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import sys
import os
import logging
import asyncio
import time
from datetime import datetime

# Add the backend directory to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from models.model_manager import get_model_manager, ModelManager
from gemini_integration.gemini_client import get_gemini_client, GeminiClient
from ai_agent import get_ai_agent, AIAgent
from utils.logging_utils import setup_logging, log_analysis_result
from utils.validation_utils import validate_model_input
from utils.file_utils import get_file_metadata, is_safe_file_size

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="CyAi Dashboard API",
    description="Cybersecurity AI Dashboard with Pre-trained Models and Gemini Integration",
    version="2.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global model manager instance
_model_manager = None

@app.on_event("startup")
async def startup_event():
    """Initialize models on startup to avoid loading delays during requests"""
    global _model_manager
    logger.info("🚀 Starting CyAi Dashboard API...")
    start_time = time.time()
    
    try:
        # Initialize model manager
        _model_manager = ModelManager()
        load_time = time.time() - start_time
        logger.info(f"✅ All models loaded successfully in {load_time:.2f} seconds")
        
        # Log model status
        models_info = _model_manager.get_all_models_info()
        logger.info(f"📊 Model status: {models_info['status']}")
        
    except Exception as e:
        logger.error(f"❌ Failed to initialize models: {e}")
        raise

def get_model_manager() -> ModelManager:
    """
    Get the global model manager instance (singleton pattern)
    
    Returns:
        ModelManager instance
    """
    global _model_manager
    if _model_manager is None:
        logger.warning("⚠️ Model manager not initialized! This should not happen after startup.")
        _model_manager = ModelManager()
    return _model_manager

# Pydantic models for requests/responses
class LogAnalysisRequest(BaseModel):
    logs: List[str]
    log_type: Optional[str] = "network"

class LogAnalysisResponse(BaseModel):
    classification: str
    confidence: float
    threat_level: str
    explanation: str
    recommended_action: str
    metadata: Dict[str, Any]

class URLAnalysisRequest(BaseModel):
    url: str
    include_analysis: Optional[bool] = True

class URLAnalysisResponse(BaseModel):
    classification: str
    confidence: float
    threat_level: str
    risk_score: float
    explanation: str
    recommended_action: str
    details: Dict[str, Any]

class FileAnalysisResponse(BaseModel):
    classification: str
    confidence: float
    threat_level: str
    malware_family: Optional[str] = None
    explanation: str
    recommended_action: str
    file_info: Dict[str, Any]

class AIAssistantRequest(BaseModel):
    # Accept 'query' in request body while keeping internal name 'text'
    text: str = Field(..., alias="query")
    model_output: Optional[Dict[str, Any]] = None
    logs: Optional[List[str]] = None
    analysis_type: Optional[str] = "general"

    class Config:
        # Allow population by both alias ('query') and field name ('text') for backward compatibility
        populate_by_name = True

class AIAssistantResponse(BaseModel):
    explanation: str
    threat_intelligence: Optional[Dict[str, Any]] = None
    remediation_steps: Optional[Dict[str, Any]] = None
    recommended_action: str
    confidence: float

@app.get("/")
def read_root():
    return {
        "message": "Welcome to the CyAi Dashboard API",
        "version": "2.0.0",
        "features": [
            "Pre-trained Log Classifier for network/system logs",
            "Pre-trained Phishing Detector for URL analysis", 
            "Pre-trained Malware Detector for file scanning",
            "Gemini-1.5-Pro integration for AI explanations"
        ],
        "endpoints": {
            "analyze_logs": "/analyze-logs",
            "analyze_url": "/analyze-url",
            "analyze_file": "/analyze-file",
            "ai_assistant": "/ai-assistant"
        }
    }

@app.post("/analyze-logs", response_model=List[LogAnalysisResponse])
async def analyze_logs(
    request: LogAnalysisRequest,
    model_manager: ModelManager = Depends(get_model_manager),
    gemini_client: GeminiClient = Depends(get_gemini_client)
):
    """
    Analyze raw logs using log_classifier and get AI explanations
    
    Args:
        request: Log analysis request with logs and type
        model_manager: Model manager dependency
        gemini_client: Gemini client dependency
        
    Returns:
        List of analysis results with AI explanations
    """
    try:
        # Get log classifier model
        log_classifier = model_manager.get_log_classifier()
        
        # Classify logs
        from models.log_classifier import LogClassificationRequest
        log_requests = [
            LogClassificationRequest(
                log_data=log_entry,
                log_type=request.log_type,
                include_confidence=True
            )
            for log_entry in request.logs
        ]
        
        classification_results = log_classifier.classify_batch(log_requests)
        
        # Get AI explanations for each result
        responses = []
        for i, result in enumerate(classification_results):
            try:
                # Get Gemini explanation
                explanation_data = await gemini_client.get_explanation(
                    analysis_type="log",
                    classification=result.classification,
                    confidence=result.confidence,
                    raw_data=request.logs[i],
                    analysis_details=result.details
                )
                
                # Build response
                response = LogAnalysisResponse(
                    classification=result.classification,
                    confidence=result.confidence,
                    threat_level=explanation_data.get("threat_level", "Low"),
                    explanation=explanation_data.get("explanation", "No explanation available"),
                    recommended_action=explanation_data.get("recommended_action", "Review and investigate"),
                    metadata={
                        "log_type": request.log_type,
                        "labels": result.labels,
                        "analysis_details": result.details,
                        "confidence_interpretation": explanation_data.get("confidence_interpretation", "")
                    }
                )
                responses.append(response)
                
            except Exception as e:
                logger.error(f"Error getting explanation for log {i}: {e}")
                # Fallback response without AI explanation
                response = LogAnalysisResponse(
                    classification=result.classification,
                    confidence=result.confidence,
                    threat_level="Unknown",
                    explanation=f"Log classified as {result.classification} with {result.confidence:.2%} confidence. AI explanation unavailable.",
                    recommended_action="Review and investigate as needed",
                    metadata={
                        "log_type": request.log_type,
                        "labels": result.labels,
                        "analysis_details": result.details,
                        "error": str(e)
                    }
                )
                responses.append(response)
        
        return responses
        
    except Exception as e:
        logger.error(f"Error in log analysis: {e}")
        raise HTTPException(status_code=500, detail=f"Log analysis failed: {str(e)}")

@app.post("/analyze-url", response_model=URLAnalysisResponse)
async def analyze_url(
    request: URLAnalysisRequest,
    model_manager: ModelManager = Depends(get_model_manager),
    gemini_client: GeminiClient = Depends(get_gemini_client)
):
    """
    Analyze URL using phishing_detector and get AI explanations
    
    Args:
        request: URL analysis request
        model_manager: Model manager dependency
        gemini_client: Gemini client dependency
        
    Returns:
        URL analysis result with AI explanation
    """
    start_time = time.time()
    request_id = f"req_{int(time.time() * 1000)}"
    
    try:
        logger.info(f"🔍 [{request_id}] Starting URL analysis for: {request.url}")
        
        # Get phishing detector model
        model_start = time.time()
        phishing_detector = model_manager.get_phishing_detector()
        model_time = time.time() - model_start
        logger.info(f"⚡ [{request_id}] Model loaded in {model_time:.3f}s")
        
        # Detect phishing
        from models.phishing_detector import PhishingDetectionRequest
        detection_request = PhishingDetectionRequest(
            url=request.url,
            include_analysis=request.include_analysis,
            check_reputation=True
        )
        
        detection_start = time.time()
        detection_result = phishing_detector.detect_phishing(detection_request)
        detection_time = time.time() - detection_start
        logger.info(f"🎯 [{request_id}] Phishing detection completed in {detection_time:.3f}s - Result: {detection_result.classification}")
        
        # Get AI explanation
        gemini_start = time.time()
        try:
            explanation_data = await gemini_client.get_explanation(
                analysis_type="url",
                classification=detection_result.classification,
                confidence=detection_result.confidence,
                raw_data=request.url,
                analysis_details=detection_result.analysis_details
            )
            
            explanation = explanation_data.get("explanation", "No explanation available")
            recommended_action = explanation_data.get("recommended_action", "Review and investigate")
            threat_level = explanation_data.get("threat_level", "Low")
            
            gemini_time = time.time() - gemini_start
            logger.info(f"🤖 [{request_id}] Gemini explanation completed in {gemini_time:.3f}s")
            
        except Exception as e:
            logger.error(f"❌ [{request_id}] Error getting Gemini explanation: {e}")
            explanation = f"URL classified as {detection_result.classification} with {detection_result.confidence:.2%} confidence. AI explanation unavailable."
            recommended_action = "Review and investigate as needed"
            threat_level = "Unknown"
            gemini_time = time.time() - gemini_start
            logger.info(f"⚠️ [{request_id}] Using fallback explanation after {gemini_time:.3f}s")
        
        total_time = time.time() - start_time
        logger.info(f"✅ [{request_id}] URL analysis completed successfully in {total_time:.3f}s")
        
        return URLAnalysisResponse(
            classification=detection_result.classification,
            confidence=detection_result.confidence,
            threat_level=threat_level,
            risk_score=detection_result.risk_score,
            explanation=explanation,
            recommended_action=recommended_action,
            details={
                "analysis_details": detection_result.analysis_details,
                "recommendations": detection_result.recommendations,
                "url_analysis": detection_result.analysis_details.get("url_analysis", {}),
                "performance_metrics": {
                    "total_time": round(total_time, 3),
                    "model_load_time": round(model_time, 3),
                    "detection_time": round(detection_time, 3),
                    "gemini_time": round(gemini_time, 3)
                }
            }
        )
        
    except Exception as e:
        total_time = time.time() - start_time
        logger.error(f"❌ [{request_id}] Error in URL analysis after {total_time:.3f}s: {e}")
        raise HTTPException(
            status_code=500, 
            detail={
                "error": "URL analysis failed",
                "message": str(e),
                "request_id": request_id,
                "processing_time": round(total_time, 3)
            }
        )

@app.post("/analyze-file", response_model=FileAnalysisResponse)
async def analyze_file(
    file: UploadFile = File(...),
    scan_type: str = Form("quick"),
    include_family_detection: bool = Form(True),
    model_manager: ModelManager = Depends(get_model_manager),
    gemini_client: GeminiClient = Depends(get_gemini_client)
):
    """
    Analyze uploaded file using malware_detector and get AI explanations
    
    Args:
        file: Uploaded file
        scan_type: Type of scan to perform
        include_family_detection: Whether to include malware family detection
        model_manager: Model manager dependency
        gemini_client: Gemini client dependency
        
    Returns:
        File analysis result with AI explanation
    """
    try:
        # Read file content
        file_content = await file.read()
        
        # Get malware detector model
        malware_detector = model_manager.get_malware_detector()
        
        # Analyze file
        from models.malware_detector import MalwareDetectionRequest
        detection_request = MalwareDetectionRequest(
            file_content=file_content,
            file_name=file.filename,
            scan_type=scan_type,
            include_family_detection=include_family_detection
        )
        
        detection_result = malware_detector.analyze_file(detection_request)
        
        # Get AI explanation
        try:
            explanation_data = await gemini_client.get_explanation(
                analysis_type="file",
                classification="Malicious" if detection_result.is_malicious else "Safe",
                confidence=detection_result.confidence,
                raw_data=file.filename,
                analysis_details=detection_result.analysis_details
            )
            
            explanation = explanation_data.get("explanation", "No explanation available")
            recommended_action = explanation_data.get("recommended_action", "Review and investigate")
            threat_level = explanation_data.get("threat_level", detection_result.threat_level)
            
        except Exception as e:
            logger.error(f"Error getting Gemini explanation: {e}")
            explanation = f"File classified as {'Malicious' if detection_result.is_malicious else 'Safe'} with {detection_result.confidence:.2%} confidence. AI explanation unavailable."
            recommended_action = "Review and investigate as needed"
            threat_level = detection_result.threat_level
        
        return FileAnalysisResponse(
            classification="Malicious" if detection_result.is_malicious else "Safe",
            confidence=detection_result.confidence,
            threat_level=threat_level,
            malware_family=detection_result.malware_family,
            explanation=explanation,
            recommended_action=recommended_action,
            file_info={
                "file_name": file.filename,
                "file_size": len(file_content),
                "scan_type": scan_type,
                "analysis_details": detection_result.analysis_details,
                "recommendations": detection_result.recommendations
            }
        )
        
    except Exception as e:
        logger.error(f"Error in file analysis: {e}")
        raise HTTPException(status_code=500, detail=f"File analysis failed: {str(e)}")

@app.post("/ai-assistant", response_model=AIAssistantResponse)
async def ai_assistant(
    request: AIAssistantRequest,
    ai_agent: AIAgent = Depends(get_ai_agent)
):
    """
    AI Assistant endpoint that accepts text, model output, or logs and sends them to AI Agent for expert analysis
    
    Args:
        request: AI assistant request with text, model output, or logs
        ai_agent: AI Agent dependency for expert analysis
        
    Returns:
        AI assistant response with detailed explanation and recommendations
    """
    try:
        # Build context for AI Agent
        context = {}
        
        if request.text:
            context['user_query'] = request.text
        
        if request.model_output:
            context['model_outputs'] = request.model_output
        
        if request.logs:
            context['logs'] = request.logs
        
        # Add analysis type to context
        context['analysis_type'] = request.analysis_type
        
        # Use AI Agent for expert analysis
        expert_analysis = await ai_agent.ask_ai_agent(request.text, context)
        
        # Extract additional insights if available
        threat_intelligence = None
        remediation_steps = None
        
        if request.analysis_type == "threat_intelligence":
            # Get additional threat intelligence context
            try:
                gemini_client = get_gemini_client()
                threat_intelligence = await gemini_client.get_threat_intelligence(
                    threat_type=request.text,
                    indicators=request.logs or [],
                    context=request.model_output
                )
                
                remediation_steps = await gemini_client.get_remediation_steps(
                    threat_level="High",
                    threat_type=request.text,
                    affected_systems=request.logs
                )
            except Exception as e:
                logger.warning(f"Could not get additional threat intelligence: {e}")
        
        return AIAssistantResponse(
            explanation=expert_analysis,
            threat_intelligence=threat_intelligence,
            remediation_steps=remediation_steps,
            recommended_action="Review the expert analysis and implement recommended security measures",
            confidence=0.95
        )
        
    except Exception as e:
        logger.error(f"Error in AI assistant: {e}")
        raise HTTPException(status_code=500, detail=f"AI assistant failed: {str(e)}")

@app.get("/models/status")
async def get_models_status(model_manager: ModelManager = Depends(get_model_manager)):
    """Get status of all pre-trained models"""
    return model_manager.get_all_models_info()

@app.get("/models/health")
async def get_models_health(model_manager: ModelManager = Depends(get_model_manager)):
    """Perform health check on all models"""
    return model_manager.health_check()

@app.get("/models/info")
async def get_models_info(model_manager: ModelManager = Depends(get_model_manager)):
    """Get detailed information about all models"""
    return {
        "available_models": [
            {
                "name": "log_classifier",
                "description": "Classifies and labels network/system logs (Normal, Suspicious, Malicious)",
                "endpoint": "/analyze-logs"
            },
            {
                "name": "phishing_detector", 
                "description": "Classifies URLs as Safe/Suspicious/Malicious",
                "endpoint": "/analyze-url"
            },
            {
                "name": "malware_detector",
                "description": "Scans uploaded files and predicts maliciousness + type/family",
                "endpoint": "/analyze-file"
            }
        ],
        "model_manager": model_manager.get_all_models_info()
    }