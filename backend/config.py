"""
Configuration management for CyAi Dashboard
Handles environment variables and application settings
"""

import os
from typing import Optional
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Application configuration"""
    
    # Gemini API Configuration
    GEMINI_API_KEY: str = os.getenv('GEMINI_API_KEY', '')
    
    # Backend Configuration
    BACKEND_HOST: str = os.getenv('BACKEND_HOST', '0.0.0.0')
    BACKEND_PORT: int = int(os.getenv('BACKEND_PORT', '8000'))
    DEBUG: bool = os.getenv('DEBUG', 'False').lower() == 'true'
    
    # Model Configuration
    LOG_LEVEL: str = os.getenv('LOG_LEVEL', 'INFO')
    MAX_FILE_SIZE: str = os.getenv('MAX_FILE_SIZE', '50MB')
    MAX_BATCH_SIZE: int = int(os.getenv('MAX_BATCH_SIZE', '100'))
    
    # Security Configuration
    CORS_ORIGINS: list = os.getenv('CORS_ORIGINS', '*').split(',')
    
    @classmethod
    def validate_config(cls) -> bool:
        """Validate configuration"""
        if not cls.GEMINI_API_KEY:
            print("Warning: GEMINI_API_KEY not set. AI explanations will not work.")
            return False
        return True
    
    @classmethod
    def get_file_size_bytes(cls) -> int:
        """Convert MAX_FILE_SIZE to bytes"""
        size_str = cls.MAX_FILE_SIZE.upper()
        if size_str.endswith('MB'):
            return int(size_str[:-2]) * 1024 * 1024
        elif size_str.endswith('KB'):
            return int(size_str[:-2]) * 1024
        elif size_str.endswith('GB'):
            return int(size_str[:-2]) * 1024 * 1024 * 1024
        else:
            return int(size_str)

# Global config instance
config = Config()
