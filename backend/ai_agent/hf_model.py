"""
Hugging Face Model Integration Module
Handles integration with Hugging Face models for AI responses
"""

from typing import Dict, Any, Optional
import logging
from transformers import pipeline, AutoTokenizer, AutoModelForCausalLM
import torch

logger = logging.getLogger(__name__)

class HFModelManager:
    """Manages Hugging Face model operations"""
    
    def __init__(self, model_name: str = "microsoft/DialoGPT-medium"):
        """
        Initialize the Hugging Face model manager
        
        Args:
            model_name: Name of the Hugging Face model to use
        """
        self.model_name = model_name
        self.model = None
        self.tokenizer = None
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self._load_model()
    
    def _load_model(self):
        """Load the Hugging Face model and tokenizer"""
        try:
            logger.info(f"Loading model: {self.model_name}")
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self.model = AutoModelForCausalLM.from_pretrained(self.model_name)
            
            # Move model to appropriate device
            self.model.to(self.device)
            
            # Add padding token if it doesn't exist
            if self.tokenizer.pad_token is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token
                
            logger.info(f"Model loaded successfully on {self.device}")
            
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            raise
    
    def generate_response(self, prompt: str, max_length: int = 150, 
                         temperature: float = 0.7, top_p: float = 0.9) -> str:
        """
        Generate a response using the loaded model
        
        Args:
            prompt: Input prompt for the model
            max_length: Maximum length of generated response
            temperature: Sampling temperature
            top_p: Top-p sampling parameter
            
        Returns:
            Generated response text
        """
        try:
            # Tokenize input
            inputs = self.tokenizer.encode(prompt, return_tensors="pt").to(self.device)
            
            # Generate response
            with torch.no_grad():
                outputs = self.model.generate(
                    inputs,
                    max_length=max_length,
                    temperature=temperature,
                    top_p=top_p,
                    do_sample=True,
                    pad_token_id=self.tokenizer.eos_token_id,
                    eos_token_id=self.tokenizer.eos_token_id
                )
            
            # Decode response
            response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            
            # Remove the original prompt from response
            if prompt in response:
                response = response.replace(prompt, "").strip()
            
            return response
            
        except Exception as e:
            logger.error(f"Error generating response: {e}")
            return "Sorry, I encountered an error while generating a response."
    
    def get_model_info(self) -> Dict[str, Any]:
        """
        Get information about the loaded model
        
        Returns:
            Dictionary containing model information
        """
        return {
            "model_name": self.model_name,
            "device": self.device,
            "is_loaded": self.model is not None,
            "tokenizer_loaded": self.tokenizer is not None
        }

# Global model manager instance
model_manager: Optional[HFModelManager] = None

def get_model_manager() -> HFModelManager:
    """Get the global model manager instance"""
    global model_manager
    if model_manager is None:
        model_manager = HFModelManager()
    return model_manager

def initialize_model(model_name: str = "microsoft/DialoGPT-medium") -> HFModelManager:
    """
    Initialize the model manager with a specific model
    
    Args:
        model_name: Name of the Hugging Face model to use
        
    Returns:
        Initialized model manager
    """
    global model_manager
    model_manager = HFModelManager(model_name)
    return model_manager

