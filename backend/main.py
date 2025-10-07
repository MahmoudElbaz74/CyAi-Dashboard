from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional, Tuple
import sys
import os
import logging
import asyncio
import time
from datetime import datetime
import tempfile
import subprocess
import json
import shutil
from pathlib import Path
import math
try:
    import torch  # type: ignore
except Exception:  # pragma: no cover
    torch = None  # type: ignore

# Add the backend directory to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from models.model_manager import get_model_manager, ModelManager
from gemini_integration.gemini_client import get_gemini_client, GeminiClient
from ai_agent import get_ai_agent, AIAgent
from utils.logging_utils import setup_logging, log_analysis_result
from utils.validation_utils import validate_model_input
from utils.file_utils import get_file_metadata, is_safe_file_size
from fastapi.staticfiles import StaticFiles

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="CyFort AI API",
    description="CyFort AI: Cybersecurity Analysis with Pre-trained Models and Gemini Integration",
    version="2.0.0"
)
# Serve static dashboard assets (if present)
static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


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
    logger.info("🚀 Starting CyFort AI API...")
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
    # Top-level fields now reflect Gemini's final decision
    classification: str
    confidence: float
    threat_level: str
    risk_score: float
    explanation: str
    recommended_action: str
    # details contains: model, virustotal, gemini_final, notes, timestamp, url, performance_metrics
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


class PcapAnalysisResponse(BaseModel):
    model_summary: Dict[str, Any]
    gemini_analysis: List[Dict[str, Any]]
    final_verdict: str
    classified_logs: Optional[List[Dict[str, Any]]] = None
    recommendations: Optional[List[str]] = None


def _get_packet_model_path() -> Path:
    base_dir = Path(__file__).parent / "models"
    return base_dir / "packet_model.pt"


_packet_model = None


def get_packet_model():
    """Lazy-load and cache the local PyTorch packet model."""
    global _packet_model
    if _packet_model is not None:
        return _packet_model
    model_path = _get_packet_model_path()
    if not model_path.exists():
        logger.warning(f"packet_model.pt not found at {model_path}; will use rule-based fallback.")
        _packet_model = None
        return _packet_model
    if torch is None:
        logger.warning("PyTorch not available; will use rule-based fallback.")
        _packet_model = None
        return _packet_model
    try:
        _packet_model = torch.jit.load(str(model_path)) if str(model_path).endswith('.pt') else torch.load(str(model_path), map_location='cpu')
        if hasattr(_packet_model, 'eval'):
            _packet_model.eval()
        logger.info("Packet model loaded successfully")
    except Exception as e:
        logger.error(f"Failed to load packet model: {e}")
        _packet_model = None
    return _packet_model


def _run_tshark_extract(input_path: Path) -> Tuple[Path, List[Dict[str, Any]]]:
    """Run tshark to extract readable logs into a temp JSON file and return parsed records."""
    tmp_json = Path(tempfile.mkstemp(prefix="pcap_logs_", suffix=".json")[1])
    fields = [
        'frame.time_epoch',
        'ip.src',
        'ip.dst',
        '_ws.col.Protocol',
        'frame.len',
        '_ws.col.Info'
    ]
    cmd = [
        'tshark', '-r', str(input_path),
        '-T', 'json',
        '-e', 'frame.time_epoch',
        '-e', 'ip.src',
        '-e', 'ip.dst',
        '-e', '_ws.col.Protocol',
        '-e', 'frame.len',
        '-e', '_ws.col.Info'
    ]
    try:
        # Prefer -T jsonraw for structure; fall back to fields CSV-style if json fails
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        # tshark -T json returns a JSON array of packets with layers; best-effort parse
        data = json.loads(result.stdout)
        records: List[Dict[str, Any]] = []
        for pkt in data:
            layers = pkt.get('_source', {}).get('layers', {})
            def first(layer_key: str) -> Optional[str]:
                val = layers.get(layer_key)
                if isinstance(val, list) and val:
                    return val[0]
                if isinstance(val, str):
                    return val
                return None
            ts = first('frame.time_epoch') or first('frame.time') or ''
            src = first('ip.src') or ''
            dst = first('ip.dst') or ''
            proto = first('_ws.col.Protocol') or first('ip.proto') or ''
            length = first('frame.len') or '0'
            info = first('_ws.col.Info') or ''
            try:
                length_int = int(float(length))
            except Exception:
                length_int = 0
            records.append({
                'timestamp': ts,
                'src_ip': src,
                'dst_ip': dst,
                'protocol': proto,
                'length': length_int,
                'info': info
            })
        tmp_json.write_text(json.dumps(records, ensure_ascii=False))
        return tmp_json, records
    except subprocess.CalledProcessError as e:
        logger.error(f"tshark failed: {e.stderr}")
        raise HTTPException(status_code=500, detail="tshark processing failed. Ensure tshark is installed and the pcap is valid.")
    except json.JSONDecodeError:
        # Fallback: try fields mode to TSV then convert
        tmp_txt = Path(tempfile.mkstemp(prefix="pcap_logs_", suffix=".txt")[1])
        cmd_f = [
            'tshark', '-r', str(input_path),
            '-T', 'fields', '-E', 'separator=\t',
            *sum([['-e', f] for f in fields], [])
        ]
        try:
            result2 = subprocess.run(cmd_f, capture_output=True, text=True, check=True)
            lines = [ln for ln in result2.stdout.splitlines() if ln.strip()]
            records = []
            for ln in lines:
                parts = ln.split('\t')
                while len(parts) < len(fields):
                    parts.append('')
                ts, src, dst, proto, length, info = parts[:6]
                try:
                    length_int = int(float(length))
                except Exception:
                    length_int = 0
                records.append({
                    'timestamp': ts,
                    'src_ip': src,
                    'dst_ip': dst,
                    'protocol': proto,
                    'length': length_int,
                    'info': info
                })
            tmp_json.write_text(json.dumps(records, ensure_ascii=False))
            try:
                if tmp_txt.exists():
                    tmp_txt.unlink(missing_ok=True)  # type: ignore[arg-type]
            except Exception:
                pass
            return tmp_json, records
        except Exception as e2:
            logger.error(f"tshark fallback failed: {e2}")
            raise HTTPException(status_code=500, detail="Failed to extract logs from pcap.")


def _simple_rule_based_classify(rec: Dict[str, Any]) -> Tuple[str, float]:
    """Fallback classification if model unavailable."""
    proto = (rec.get('protocol') or '').upper()
    length = int(rec.get('length') or 0)
    info = (rec.get('info') or '').lower()
    score = 0.0
    # Simple heuristics
    if proto in ("TCP", "UDP") and length > 1500:
        score += 0.6
    if any(k in info for k in ["syn", "fin", "scan", "exploit", "smb", "powershell", "meterpreter", "sqlmap", "nmap"]):
        score += 0.5
    if "dns" in proto and ("exfil" in info or "tunn" in info):
        score += 0.5
    if score >= 0.9:
        return "Malicious", min(score, 1.0)
    if score >= 0.6:
        return "Suspicious", score
    return "Benign", 1.0 - score


def _featurize_for_model(rec: Dict[str, Any]) -> Optional['torch.Tensor']:
    if torch is None:
        return None
    try:
        length = float(rec.get('length') or 0)
        proto = (rec.get('protocol') or '').upper()
        proto_map = {"TCP": 1.0, "UDP": 2.0, "ICMP": 3.0, "DNS": 4.0, "HTTP": 5.0, "TLS": 6.0}
        proto_id = proto_map.get(proto, 0.0)
        # Very small numeric feature vector as generic input
        vec = torch.tensor([length, proto_id], dtype=torch.float32).unsqueeze(0)
        return vec
    except Exception:
        return None


async def _analyze_with_gemini(gemini_client: GeminiClient, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Chunk logs and request deep analysis with mapping to MITRE."""
    if not logs:
        return []
    # Chunk by count to keep prompts small
    chunk_size = 100
    chunks = [logs[i:i + chunk_size] for i in range(0, len(logs), chunk_size)]
    analyses: List[Dict[str, Any]] = []
    for idx, chunk in enumerate(chunks):
        prompt = (
            "You are a senior network security analyst. Analyze the following suspicious/malicious network logs.\n"
            "For each chunk, provide: 1) overall verdict (benign/suspicious/malicious), 2) likely attack technique/threat type, "
            "3) possible MITRE ATT&CK techniques (IDs and names), 4) short incident response recommendation.\n"
            "Respond as JSON with keys: summary, verdict, threats, mitre_mapping, recommendations.\n\n"
            f"LOG CHUNK {idx+1}/{len(chunks)}:\n" + json.dumps(chunk)[:15000]
        )
        try:
            response_text = await gemini_client._generate_response(prompt)  # type: ignore[attr-defined]
            try:
                analyses.append(json.loads(response_text))
            except Exception:
                analyses.append({
                    "summary": response_text,
                    "verdict": "Analysis",
                    "threats": [],
                    "mitre_mapping": [],
                    "recommendations": ["Manual review recommended."]
                })
        except Exception as e:
            logger.error(f"Gemini analysis error: {e}")
            analyses.append({
                "summary": "AI analysis unavailable",
                "verdict": "Unknown",
                "threats": [],
                "mitre_mapping": [],
                "recommendations": ["Manual review recommended."]
            })
    return analyses

@app.get("/")
def read_root():
    return {
        "message": "Welcome to the CyFort AI API",
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
        
        # Get Gemini final decision (verdict) using combined sources
        gemini_start = time.time()
        try:
            model_section = detection_result.analysis_details.get("model", {})
            vt_section = detection_result.analysis_details.get("virustotal", {})
            final_verdict = await gemini_client.get_final_url_verdict(
                url=request.url,
                model_result=model_section,
                vt_result=vt_section,
            )
            gemini_time = time.time() - gemini_start
            logger.info(f"🤖 [{request_id}] Gemini final verdict completed in {gemini_time:.3f}s")

            # Top-level fields adopt Gemini decision
            final_label = final_verdict.get("final_label", detection_result.classification)
            final_threat = final_verdict.get("threat_level", "Low")
            final_explanation = final_verdict.get("explanation", "")
            final_confidence = final_verdict.get("confidence")
            final_risk_score = final_verdict.get("risk_score")
            notes_merge = list(detection_result.analysis_details.get("notes", [])) + list(final_verdict.get("notes", []))

            # Prefer Gemini-provided recommended action; fallback to dynamic rules
            recommended_action = final_verdict.get("recommended_action")
            if not recommended_action:
                if final_label == "Malicious" and final_threat == "High":
                    recommended_action = "Immediate investigation required."
                elif final_label in ("Malicious",) or final_threat in ("High",):
                    recommended_action = "Immediate investigation required."
                elif final_label in ("Suspicious", "Likely False Positive") or final_threat in ("Moderate", "Medium"):
                    recommended_action = "Caution advised. Manual review recommended."
                else:
                    recommended_action = "No immediate action required."

            threat_level = final_threat
            explanation = final_explanation
            classification = final_label
            # Prefer Gemini-provided confidence/risk if present
            if isinstance(final_confidence, (int, float)):
                detection_result.confidence = float(final_confidence)
            if isinstance(final_risk_score, (int, float)):
                detection_result.risk_score = float(final_risk_score)
        except Exception as e:
            logger.error(f"❌ [{request_id}] Error getting Gemini final verdict: {e}")
            # Fallback: use explanation-only mode
            try:
                explanation_data = await gemini_client.get_explanation(
                    analysis_type="url",
                    classification=detection_result.classification,
                    confidence=detection_result.confidence,
                    raw_data=request.url,
                    analysis_details=detection_result.analysis_details,
                )
                explanation = explanation_data.get("explanation", "No explanation available")
                recommended_action = explanation_data.get("recommended_action", "Review and investigate")
                threat_level = explanation_data.get("threat_level", "Low")
                classification = detection_result.classification
            except Exception:
                explanation = f"URL classified as {detection_result.classification} with {detection_result.confidence:.2%} confidence. AI explanation unavailable."
                recommended_action = "Review and investigate as needed"
                threat_level = "Unknown"
                classification = detection_result.classification
            gemini_time = time.time() - gemini_start
            logger.info(f"⚠️ [{request_id}] Using fallback explanation after {gemini_time:.3f}s")
        
        total_time = time.time() - start_time
        logger.info(f"✅ [{request_id}] URL analysis completed successfully in {total_time:.3f}s")
        
        # Build separated sections for frontend consumption
        details = detection_result.analysis_details or {}
        # Record Gemini final verdict for frontend rendering
        if 'gemini_final' not in details:
            details['gemini_final'] = {
                'final_label': classification,
                'threat_level': threat_level,
                'explanation': explanation,
            }
        else:
            # If previous set exists, update with latest values
            details['gemini_final'].update({
                'final_label': classification,
                'threat_level': threat_level,
                'explanation': explanation,
            })
        details["performance_metrics"] = {
            "total_time": round(total_time, 3),
            "model_load_time": round(model_time, 3),
            "detection_time": round(detection_time, 3),
            "gemini_time": round(gemini_time, 3)
        }

        return URLAnalysisResponse(
            classification=classification,  # Gemini final label
            confidence=detection_result.confidence,  # retain model confidence for transparency
            threat_level=threat_level,
            risk_score=detection_result.risk_score,
            explanation=explanation,
            recommended_action=recommended_action,
            details=details,
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


@app.post("/analyze-pcap", response_model=PcapAnalysisResponse)
async def analyze_pcap(
    file: UploadFile = File(...),
    model_manager: ModelManager = Depends(get_model_manager),  # reserved for consistency
    gemini_client: GeminiClient = Depends(get_gemini_client)
):
    """Analyze a .pcap or .pcapng file: extract logs, classify with local PyTorch model, and run Gemini deep analysis."""
    start_time = time.time()
    if not file.filename.lower().endswith((".pcap", ".pcapng")):
        raise HTTPException(status_code=400, detail="Only .pcap or .pcapng files are supported")

    tmp_dir = Path(tempfile.mkdtemp(prefix="pcap_"))
    pcap_path = tmp_dir / file.filename
    try:
        content = await file.read()
        pcap_path.write_bytes(content)

        # Extract logs with tshark
        logs_path, records = _run_tshark_extract(pcap_path)

        # Classify each record
        pkt_model = get_packet_model()
        classified: List[Dict[str, Any]] = []
        for rec in records:
            label = "Benign"
            conf = 0.5
            if pkt_model is not None and torch is not None:
                try:
                    features = _featurize_for_model(rec)
                    if features is not None:
                        with torch.no_grad():
                            output = pkt_model(features)
                            if isinstance(output, (list, tuple)):
                                output = output[0]
                            if hasattr(output, 'softmax'):
                                probs = output.softmax(dim=-1)
                            else:
                                probs = torch.softmax(output, dim=-1)
                            probs_list = probs.squeeze(0).tolist()
                            # Map indices 0/1/2 => Benign/Suspicious/Malicious
                            idx = int(max(range(len(probs_list)), key=lambda i: probs_list[i]))
                            mapping = {0: "Benign", 1: "Suspicious", 2: "Malicious"}
                            label = mapping.get(idx, "Benign")
                            conf = float(probs_list[idx]) if probs_list else 0.5
                    else:
                        label, conf = _simple_rule_based_classify(rec)
                except Exception as ie:
                    logger.warning(f"Model inference failed, using fallback: {ie}")
                    label, conf = _simple_rule_based_classify(rec)
            else:
                label, conf = _simple_rule_based_classify(rec)

            rec_out = dict(rec)
            rec_out.update({
                'classification': label,
                'confidence': conf
            })
            classified.append(rec_out)

        # Filter suspicious/malicious
        filtered = [r for r in classified if (r.get('classification') or '').lower() in ("suspicious", "malicious")]

        # Compute model summary
        benign_count = sum(1 for r in classified if (r.get('classification') or '').lower() == 'benign')
        suspicious_count = sum(1 for r in classified if (r.get('classification') or '').lower() == 'suspicious')
        malicious_count = sum(1 for r in classified if (r.get('classification') or '').lower() == 'malicious')
        avg_conf = 0.0
        if classified:
            avg_conf = float(sum(float(r.get('confidence') or 0.0) for r in classified) / len(classified))
        model_summary = {
            'total_packets': len(records),
            'benign': benign_count,
            'suspicious': suspicious_count,
            'malicious': malicious_count,
            'avg_confidence': round(avg_conf, 4)
        }

        if not filtered:
            return PcapAnalysisResponse(
                model_summary=model_summary,
                gemini_analysis=[],
                final_verdict='Safe',
                classified_logs=[],
                recommendations=["Continue monitoring."]
            )

        # LLM deep analysis
        analyses = await _analyze_with_gemini(gemini_client, filtered)

        # Build recommendations
        recs: List[str] = []
        for a in analyses:
            if isinstance(a, dict):
                rx = a.get('recommendations')
                if isinstance(rx, list):
                    recs.extend([str(x) for x in rx][:5])
        if not recs:
            recs = [
                "Isolate affected hosts if compromise suspected.",
                "Block malicious IPs/domains at the perimeter.",
                "Collect relevant logs and artifacts for IR.",
            ]

        # Determine final verdict (prioritize Gemini verdicts if present)
        def verdict_rank(v: str) -> int:
            vv = (v or '').lower()
            if vv == 'malicious':
                return 3
            if vv == 'suspicious':
                return 2
            return 1

        gemini_verdicts: List[str] = []
        for a in analyses:
            if isinstance(a, dict):
                v = a.get('verdict') or a.get('final_label') or a.get('classification')
                if isinstance(v, str):
                    gemini_verdicts.append(v)
        final_verdict = None
        if gemini_verdicts:
            final_verdict = max(gemini_verdicts, key=verdict_rank)
        else:
            final_verdict = 'Malicious' if malicious_count > 0 else ('Suspicious' if suspicious_count > 0 else 'Safe')

        return PcapAnalysisResponse(
            model_summary=model_summary,
            gemini_analysis=analyses,
            final_verdict=final_verdict,
            classified_logs=filtered,
            recommendations=recs[:10]
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in PCAP analysis: {e}")
        raise HTTPException(status_code=500, detail=f"PCAP analysis failed: {str(e)}")
    finally:
        # Cleanup
        try:
            if tmp_dir.exists():
                shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass


@app.post("/upload_pcap")
async def upload_pcap(file: UploadFile = File(...)):
    """Accept a .pcap or .pcapng, parse basic details, and return a concise summary.

    Response JSON:
    - total_packets: int
    - protocol_counts: Dict[str, int]
    - sample_packets: List[{
        timestamp, protocol, src_ip, dst_ip, src_port, dst_port
      }] (first 5)
    """
    filename = file.filename or "pcap.pcap"
    if not filename.lower().endswith((".pcap", ".pcapng")):
        raise HTTPException(status_code=400, detail="Only .pcap or .pcapng files are supported")

    try:
        content = await file.read()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read upload: {e}")

    # Size guard (50MB default)
    if not is_safe_file_size(len(content)):
        raise HTTPException(status_code=413, detail="File too large. Max 50MB allowed.")

    tmp_dir = Path(tempfile.mkdtemp(prefix="upload_pcap_"))
    pcap_path = tmp_dir / filename
    try:
        pcap_path.write_bytes(content)

        # Try Scapy first
        try:
            from scapy.all import rdpcap, IP, IPv6, TCP, UDP  # type: ignore
            packets = rdpcap(str(pcap_path))
            total_packets = len(packets)

            protocol_counts: Dict[str, int] = {}
            sample_packets: List[Dict[str, Any]] = []

            def detect_protocol(pkt) -> str:
                try:
                    if TCP in pkt:
                        return "TCP"
                    if UDP in pkt:
                        return "UDP"
                    # ICMP/ICMPv6 may not be imported explicitly; identify by layer name
                    layer_names = {l.name.upper() for l in pkt.layers()}
                    if "ICMP" in layer_names:
                        return "ICMP"
                    if "ICMPV6" in layer_names:
                        return "ICMPv6"
                    # Fall back to top-most layer name
                    try:
                        return str(pkt.lastlayer().name).upper()
                    except Exception:
                        return "OTHER"
                except Exception:
                    return "OTHER"

            def get_ips_ports(pkt) -> Dict[str, Any]:
                src_ip = dst_ip = None
                src_port = dst_port = None
                try:
                    if IP in pkt:
                        src_ip = pkt[IP].src
                        dst_ip = pkt[IP].dst
                    elif IPv6 in pkt:
                        src_ip = pkt[IPv6].src
                        dst_ip = pkt[IPv6].dst
                except Exception:
                    pass
                try:
                    if TCP in pkt:
                        src_port = int(pkt[TCP].sport)
                        dst_port = int(pkt[TCP].dport)
                    elif UDP in pkt:
                        src_port = int(pkt[UDP].sport)
                        dst_port = int(pkt[UDP].dport)
                except Exception:
                    pass
                return {
                    "src_ip": src_ip or "",
                    "dst_ip": dst_ip or "",
                    "src_port": src_port,
                    "dst_port": dst_port,
                }

            for idx, pkt in enumerate(packets):
                proto = detect_protocol(pkt)
                protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
                if len(sample_packets) < 5:
                    ts = None
                    try:
                        ts = float(getattr(pkt, "time", None))
                    except Exception:
                        ts = None
                    infos = get_ips_ports(pkt)
                    sample_packets.append({
                        "timestamp": ts,
                        "protocol": proto,
                        **infos,
                    })

            return {
                "total_packets": total_packets,
                "protocol_counts": dict(sorted(protocol_counts.items(), key=lambda kv: (-kv[1], kv[0]))),
                "sample_packets": sample_packets,
            }
        except Exception as scapy_err:
            # As a fallback, attempt tshark-based extraction if available via existing helper
            try:
                _, records = _run_tshark_extract(pcap_path)
                total_packets = len(records)
                protocol_counts: Dict[str, int] = {}
                for r in records:
                    proto = (r.get("protocol") or "OTHER").upper()
                    protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
                sample = []
                for r in records[:5]:
                    # Attempt to parse numeric timestamp
                    ts_raw = r.get("timestamp")
                    try:
                        ts = float(ts_raw)
                    except Exception:
                        ts = None
                    sample.append({
                        "timestamp": ts,
                        "protocol": (r.get("protocol") or "").upper(),
                        "src_ip": r.get("src_ip") or "",
                        "dst_ip": r.get("dst_ip") or "",
                        "src_port": None,
                        "dst_port": None,
                    })
                return {
                    "total_packets": total_packets,
                    "protocol_counts": dict(sorted(protocol_counts.items(), key=lambda kv: (-kv[1], kv[0]))),
                    "sample_packets": sample,
                }
            except Exception as tshark_err:
                raise HTTPException(status_code=500, detail=f"Failed to parse PCAP (Scapy: {scapy_err}; tshark: {tshark_err})")
    finally:
        try:
            if tmp_dir.exists():
                shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass

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