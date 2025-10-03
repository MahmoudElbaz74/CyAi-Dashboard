"""
AI Agent API Module
Handles API endpoints for AI agent functionality
"""

from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any, Optional
import logging
from pydantic import BaseModel

from .hf_model import get_model_manager, HFModelManager
from .prompt_templates import get_prompt_templates, PromptTemplates, PromptType
from .context_builder import get_context_builder, ContextBuilder

logger = logging.getLogger(__name__)

# Initialize router
router = APIRouter(prefix="/ai", tags=["AI Agent"])

# Pydantic models for request/response
class AIRequest(BaseModel):
    """Request model for AI analysis"""
    prompt: str
    prompt_type: Optional[str] = "general_query"
    context_data: Optional[Dict[str, Any]] = None
    additional_context: Optional[str] = None

class AIResponse(BaseModel):
    """Response model for AI analysis"""
    response: str
    prompt_type: str
    model_info: Dict[str, Any]
    context_summary: Dict[str, Any]

class ModelInfo(BaseModel):
    """Model information response"""
    model_name: str
    device: str
    is_loaded: bool
    tokenizer_loaded: bool

class ContextSummary(BaseModel):
    """Context summary response"""
    total_logs: int
    total_contexts: int
    recent_logs: list
    context_types: list
    last_updated: str

# Dependency injection
def get_model_manager_dependency() -> HFModelManager:
    """Dependency to get model manager"""
    return get_model_manager()

def get_prompt_templates_dependency() -> PromptTemplates:
    """Dependency to get prompt templates"""
    return get_prompt_templates()

def get_context_builder_dependency() -> ContextBuilder:
    """Dependency to get context builder"""
    return get_context_builder()

@router.post("/analyze", response_model=AIResponse)
async def analyze_with_ai(
    request: AIRequest,
    model_manager: HFModelManager = Depends(get_model_manager_dependency),
    prompt_templates: PromptTemplates = Depends(get_prompt_templates_dependency),
    context_builder: ContextBuilder = Depends(get_context_builder_dependency)
) -> AIResponse:
    """
    Analyze data using AI with context building
    
    Args:
        request: AI analysis request
        model_manager: Model manager dependency
        prompt_templates: Prompt templates dependency
        context_builder: Context builder dependency
        
    Returns:
        AI analysis response
    """
    try:
        # Add log entry
        context_builder.add_log(
            level="INFO",
            source="ai_api",
            message=f"Processing AI request: {request.prompt_type}",
            metadata={"prompt_length": len(request.prompt)}
        )
        
        # Determine prompt type
        try:
            prompt_type = PromptType(request.prompt_type)
        except ValueError:
            prompt_type = PromptType.GENERAL_QUERY
            context_builder.add_log(
                level="WARNING",
                source="ai_api",
                message=f"Invalid prompt type '{request.prompt_type}', using general_query"
            )
        
        # Build context if context_data is provided
        if request.context_data:
            context_builder.add_analysis_context(
                data_type=request.prompt_type or "general_query",
                raw_data=request.context_data,
                processed_data={},
                metadata={"source": "api_request"}
            )
        
        # Format prompt with context
        formatted_prompt = prompt_templates.format_prompt(
            prompt_type=prompt_type,
            data=request.prompt,
            additional_context=request.additional_context or ""
        )
        
        # Generate AI response
        ai_response = model_manager.generate_response(formatted_prompt)
        
        # Add success log
        context_builder.add_log(
            level="INFO",
            source="ai_api",
            message="AI response generated successfully",
            metadata={"response_length": len(ai_response)}
        )
        
        return AIResponse(
            response=ai_response,
            prompt_type=prompt_type.value,
            model_info=model_manager.get_model_info(),
            context_summary=context_builder.get_context_summary()
        )
        
    except Exception as e:
        logger.error(f"Error in AI analysis: {e}")
        context_builder.add_log(
            level="ERROR",
            source="ai_api",
            message=f"AI analysis failed: {str(e)}"
        )
        raise HTTPException(status_code=500, detail=f"AI analysis failed: {str(e)}")

@router.post("/analyze/network")
async def analyze_network_data(
    pcap_data: Dict[str, Any],
    analysis_results: Dict[str, Any],
    model_manager: HFModelManager = Depends(get_model_manager_dependency),
    prompt_templates: PromptTemplates = Depends(get_prompt_templates_dependency),
    context_builder: ContextBuilder = Depends(get_context_builder_dependency)
) -> AIResponse:
    """
    Analyze network data with AI
    
    Args:
        pcap_data: PCAP data to analyze
        analysis_results: Results from network analysis
        model_manager: Model manager dependency
        prompt_templates: Prompt templates dependency
        context_builder: Context builder dependency
        
    Returns:
        AI analysis response
    """
    try:
        # Build network context
        context = context_builder.build_network_context(pcap_data, analysis_results)
        
        # Format prompt for network analysis
        formatted_prompt = prompt_templates.format_prompt(
            prompt_type=PromptType.NETWORK_ANALYSIS,
            data=context
        )
        
        # Generate AI response
        ai_response = model_manager.generate_response(formatted_prompt)
        
        return AIResponse(
            response=ai_response,
            prompt_type=PromptType.NETWORK_ANALYSIS.value,
            model_info=model_manager.get_model_info(),
            context_summary=context_builder.get_context_summary()
        )
        
    except Exception as e:
        logger.error(f"Error in network analysis: {e}")
        raise HTTPException(status_code=500, detail=f"Network analysis failed: {str(e)}")

@router.post("/analyze/malware")
async def analyze_malware_data(
    sample_data: Dict[str, Any],
    analysis_results: Dict[str, Any],
    model_manager: HFModelManager = Depends(get_model_manager_dependency),
    prompt_templates: PromptTemplates = Depends(get_prompt_templates_dependency),
    context_builder: ContextBuilder = Depends(get_context_builder_dependency)
) -> AIResponse:
    """
    Analyze malware data with AI
    
    Args:
        sample_data: Malware sample data
        analysis_results: Results from malware analysis
        model_manager: Model manager dependency
        prompt_templates: Prompt templates dependency
        context_builder: Context builder dependency
        
    Returns:
        AI analysis response
    """
    try:
        # Build malware context
        context = context_builder.build_malware_context(sample_data, analysis_results)
        
        # Format prompt for malware analysis
        formatted_prompt = prompt_templates.format_prompt(
            prompt_type=PromptType.MALWARE_ANALYSIS,
            data=context
        )
        
        # Generate AI response
        ai_response = model_manager.generate_response(formatted_prompt)
        
        return AIResponse(
            response=ai_response,
            prompt_type=PromptType.MALWARE_ANALYSIS.value,
            model_info=model_manager.get_model_info(),
            context_summary=context_builder.get_context_summary()
        )
        
    except Exception as e:
        logger.error(f"Error in malware analysis: {e}")
        raise HTTPException(status_code=500, detail=f"Malware analysis failed: {str(e)}")

@router.post("/analyze/link")
async def analyze_link_data(
    url_data: Dict[str, Any],
    analysis_results: Dict[str, Any],
    model_manager: HFModelManager = Depends(get_model_manager_dependency),
    prompt_templates: PromptTemplates = Depends(get_prompt_templates_dependency),
    context_builder: ContextBuilder = Depends(get_context_builder_dependency)
) -> AIResponse:
    """
    Analyze link data with AI
    
    Args:
        url_data: URL data to analyze
        analysis_results: Results from link analysis
        model_manager: Model manager dependency
        prompt_templates: Prompt templates dependency
        context_builder: Context builder dependency
        
    Returns:
        AI analysis response
    """
    try:
        # Build link context
        context = context_builder.build_link_context(url_data, analysis_results)
        
        # Format prompt for link analysis
        formatted_prompt = prompt_templates.format_prompt(
            prompt_type=PromptType.LINK_ANALYSIS,
            data=context
        )
        
        # Generate AI response
        ai_response = model_manager.generate_response(formatted_prompt)
        
        return AIResponse(
            response=ai_response,
            prompt_type=PromptType.LINK_ANALYSIS.value,
            model_info=model_manager.get_model_info(),
            context_summary=context_builder.get_context_summary()
        )
        
    except Exception as e:
        logger.error(f"Error in link analysis: {e}")
        raise HTTPException(status_code=500, detail=f"Link analysis failed: {str(e)}")

@router.get("/model/info", response_model=ModelInfo)
async def get_model_info(
    model_manager: HFModelManager = Depends(get_model_manager_dependency)
) -> ModelInfo:
    """
    Get information about the loaded model
    
    Returns:
        Model information
    """
    try:
        info = model_manager.get_model_info()
        return ModelInfo(**info)
    except Exception as e:
        logger.error(f"Error getting model info: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get model info: {str(e)}")

@router.get("/context/summary", response_model=ContextSummary)
async def get_context_summary(
    context_builder: ContextBuilder = Depends(get_context_builder_dependency)
) -> ContextSummary:
    """
    Get context summary
    
    Returns:
        Context summary information
    """
    try:
        summary = context_builder.get_context_summary()
        return ContextSummary(**summary)
    except Exception as e:
        logger.error(f"Error getting context summary: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get context summary: {str(e)}")

@router.delete("/context/clear")
async def clear_context(
    context_builder: ContextBuilder = Depends(get_context_builder_dependency)
) -> Dict[str, str]:
    """
    Clear all context data
    
    Returns:
        Success message
    """
    try:
        context_builder.clear_context()
        return {"message": "Context cleared successfully"}
    except Exception as e:
        logger.error(f"Error clearing context: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to clear context: {str(e)}")

@router.get("/templates")
async def get_available_templates(
    prompt_templates: PromptTemplates = Depends(get_prompt_templates_dependency)
) -> Dict[str, Any]:
    """
    Get available prompt templates
    
    Returns:
        List of available templates
    """
    try:
        templates = prompt_templates.get_available_templates()
        return {
            "available_templates": templates,
            "template_count": len(templates)
        }
    except Exception as e:
        logger.error(f"Error getting templates: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get templates: {str(e)}")

@router.get("/status")
async def get_ai_status() -> Dict[str, Any]:
    """
    Get AI agent status
    
    Returns:
        AI agent status information
    """
    try:
        model_manager = get_model_manager()
        context_builder = get_context_builder()
        
        return {
            "status": "AI agent is running",
            "model_loaded": model_manager.model is not None,
            "model_name": model_manager.model_name,
            "device": model_manager.device,
            "context_logs_count": len(context_builder.logs),
            "context_entries_count": len(context_builder.contexts)
        }
    except Exception as e:
        logger.error(f"Error getting AI status: {e}")
        return {
            "status": "AI agent error",
            "error": str(e)
        }


