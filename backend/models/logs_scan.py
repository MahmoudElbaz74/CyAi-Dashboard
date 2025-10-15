# backend/endpoints/logs_scan.py
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from models.model_manager import get_model_manager

router = APIRouter()

class LogAnalysisRequest(BaseModel):
    logs: list[str]
    log_type: str = "network"
    include_confidence: bool = True

@router.post("/analyze-logs")
async def analyze_logs(request: LogAnalysisRequest):
    try:
        model_manager = get_model_manager()
        log_classifier = model_manager.log_classifier

        if not log_classifier:
            raise HTTPException(status_code=500, detail="Log classifier model not initialized")

        result = log_classifier.predict(request.logs)
        return {"status": "success", "results": result}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
