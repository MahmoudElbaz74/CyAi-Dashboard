from pydantic import BaseModel
from typing import List, Optional, Dict, Any, Union

# Network Detection Schemas
class NetworkDetectionRequest(BaseModel):
    traffic_data: List[float]

class NetworkDetectionResponse(BaseModel):
    classification: str
    confidence: float

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

# Malware Analysis Schemas
class MalwareAnalysisRequest(BaseModel):
    file_path: Optional[str] = None
    file_name: Optional[str] = None
    scan_type: Optional[str] = "quick"
    include_family_detection: Optional[bool] = True

class MalwareAnalysisResponse(BaseModel):
    is_malicious: bool
    confidence: float
    threat_level: str
    malware_family: Optional[str] = None
    malware_type: Optional[str] = None
    file_info: Dict[str, Any]
    analysis_details: Dict[str, Any]
    recommendations: List[str]

# Link Analysis Schemas
class LinkAnalysisRequest(BaseModel):
    url: str
    include_analysis: Optional[bool] = True
    check_reputation: Optional[bool] = True

class LinkAnalysisResponse(BaseModel):
    classification: str  # Safe, Suspicious, Malicious
    confidence: float
    risk_score: float
    analysis_details: Dict[str, Any]
    recommendations: List[str]

class BatchLinkAnalysisRequest(BaseModel):
    urls: List[str]
    include_analysis: Optional[bool] = True
    check_reputation: Optional[bool] = True

# AI Agent Schemas
class AIRequest(BaseModel):
    prompt: str
    max_tokens: Optional[int] = 100

class AIResponse(BaseModel):
    response: str
    usage: dict

# Model Integration Schemas
class LogClassificationRequest(BaseModel):
    log_data: Union[str, List[str], Dict[str, Any]]
    log_type: Optional[str] = "network"
    include_confidence: Optional[bool] = True

class LogClassificationResponse(BaseModel):
    classification: str
    confidence: float
    labels: List[str]
    details: Dict[str, Any]
    log_type: str

class PhishingDetectionRequest(BaseModel):
    url: str
    include_analysis: Optional[bool] = True
    check_reputation: Optional[bool] = True

class PhishingDetectionResponse(BaseModel):
    classification: str
    confidence: float
    risk_score: float
    analysis_details: Dict[str, Any]
    recommendations: List[str]

class MalwareDetectionRequest(BaseModel):
    file_path: Optional[str] = None
    file_content: Optional[bytes] = None
    file_name: Optional[str] = None
    scan_type: Optional[str] = "quick"
    include_family_detection: Optional[bool] = True

class MalwareDetectionResponse(BaseModel):
    is_malicious: bool
    confidence: float
    threat_level: str
    malware_family: Optional[str] = None
    malware_type: Optional[str] = None
    file_info: Dict[str, Any]
    analysis_details: Dict[str, Any]
    recommendations: List[str]

# Model Manager Schemas
class ModelInfo(BaseModel):
    model_name: str
    model_type: str
    version: str
    status: str

class ModelHealthStatus(BaseModel):
    overall_status: str
    models: Dict[str, Any]
    timestamp: str