from pydantic import BaseModel
from typing import List, Optional

class NetworkDetectionRequest(BaseModel):
    traffic_data: List[float]

class NetworkDetectionResponse(BaseModel):
    classification: str
    confidence: float

class MalwareAnalysisRequest(BaseModel):
    file_path: str
    scan_type: Optional[str] = "quick"

class MalwareAnalysisResponse(BaseModel):
    is_malicious: bool
    threats: List[str]

class LinkAnalysisRequest(BaseModel):
    url: str

class LinkAnalysisResponse(BaseModel):
    is_malicious: bool
    reason: Optional[str] = None

class AIRequest(BaseModel):
    prompt: str
    max_tokens: Optional[int] = 100

class AIResponse(BaseModel):
    response: str
    usage: dict