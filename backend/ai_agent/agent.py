"""
AI Agent Module - Updated Architecture
This module now serves as the main entry point for the AI agent functionality
using the new modular architecture with hf_model, prompt_templates, context_builder, and api modules.
"""

from fastapi import APIRouter
from typing import Any, Dict
import logging

# Import the new modular components
from .api import router as api_router
from .hf_model import get_model_manager, initialize_model
from .prompt_templates import get_prompt_templates
from .context_builder import get_context_builder

logger = logging.getLogger(__name__)

# Create main router that includes the API router
router = APIRouter()
router.include_router(api_router)

# Initialize components on module import
try:
    # Initialize the model manager
    model_manager = initialize_model()
    logger.info("AI Agent initialized successfully with new architecture")
except Exception as e:
    logger.error(f"Failed to initialize AI Agent: {e}")
    model_manager = None

# Legacy endpoints for backward compatibility
@router.post("/ai/response")
async def get_ai_response_legacy(prompt: str) -> Dict[str, Any]:
    """
    Legacy endpoint for AI response - now uses the new architecture
    
    Args:
        prompt: User prompt
        
    Returns:
        AI response
    """
    try:
        if model_manager is None:
            return {"response": "AI agent not properly initialized", "error": True}
        
        # Use the new architecture
        prompt_templates = get_prompt_templates()
        context_builder = get_context_builder()
        
        # Add log entry
        context_builder.add_log(
            level="INFO",
            source="legacy_api",
            message=f"Processing legacy request: {prompt[:50]}..."
        )
        
        # Generate response using the new system
        response = model_manager.generate_response(prompt)
        
        return {
            "response": response,
            "architecture": "new_modular",
            "model_info": model_manager.get_model_info()
        }
        
    except Exception as e:
        logger.error(f"Error in legacy AI response: {e}")
        return {
            "response": f"Error processing request: {str(e)}",
            "error": True
        }

@router.get("/ai/status")
async def get_ai_status_legacy() -> Dict[str, Any]:
    """
    Legacy endpoint for AI status - now provides enhanced status information
    
    Returns:
        Enhanced AI agent status
    """
    try:
        if model_manager is None:
            return {
                "status": "AI agent initialization failed",
                "error": True
            }
        
        context_builder = get_context_builder()
        
        return {
            "status": "AI agent is running",
            "architecture": "new_modular",
            "model_loaded": model_manager.model is not None,
            "model_name": model_manager.model_name,
            "device": model_manager.device,
            "context_logs_count": len(context_builder.logs),
            "context_entries_count": len(context_builder.contexts),
            "components": {
                "hf_model": "loaded",
                "prompt_templates": "available",
                "context_builder": "active",
                "api": "ready"
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting AI status: {e}")
        return {
            "status": "AI agent error",
            "error": str(e)
        }