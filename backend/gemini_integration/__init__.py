"""
Gemini Integration Module
Handles integration with Google's Gemini-1.5-Pro API for AI explanations and analysis
"""

from .gemini_client import GeminiClient, get_gemini_client

__all__ = ['GeminiClient', 'get_gemini_client']
