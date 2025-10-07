"""
Logging utility functions for CyFort AI
Handles logging configuration and analysis result logging
"""

import logging
import json
from datetime import datetime
from typing import Dict, Any, Optional
import os

def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None) -> None:
    """
    Setup logging configuration for the application
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional log file path
    """
    # Convert string level to logging constant
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # File handler (if specified)
    if log_file:
        try:
            # Create log directory if it doesn't exist
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir)
            
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(numeric_level)
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
        except Exception as e:
            print(f"Warning: Could not setup file logging: {e}")
    
    # Set specific logger levels
    logging.getLogger('uvicorn').setLevel(logging.WARNING)
    logging.getLogger('fastapi').setLevel(logging.WARNING)

def log_analysis_result(
    analysis_type: str,
    input_data: Any,
    result: Dict[str, Any],
    processing_time: float,
    user_id: Optional[str] = None
) -> None:
    """
    Log analysis result for audit and monitoring
    
    Args:
        analysis_type: Type of analysis performed
        input_data: Input data that was analyzed
        result: Analysis result
        processing_time: Time taken for analysis in seconds
        user_id: Optional user identifier
    """
    logger = logging.getLogger('analysis')
    
    # Prepare log data
    log_data = {
        'timestamp': datetime.utcnow().isoformat(),
        'analysis_type': analysis_type,
        'processing_time': processing_time,
        'user_id': user_id,
        'result': {
            'classification': result.get('classification'),
            'confidence': result.get('confidence'),
            'threat_level': result.get('threat_level'),
            'success': result.get('success', True)
        }
    }
    
    # Add input data summary (without sensitive information)
    if analysis_type == 'log':
        log_data['input_summary'] = {
            'type': 'log',
            'count': len(input_data) if isinstance(input_data, list) else 1,
            'sample': str(input_data)[:100] if isinstance(input_data, str) else 'batch'
        }
    elif analysis_type == 'url':
        log_data['input_summary'] = {
            'type': 'url',
            'domain': input_data.split('/')[2] if '/' in input_data else input_data
        }
    elif analysis_type == 'file':
        log_data['input_summary'] = {
            'type': 'file',
            'size': len(input_data) if isinstance(input_data, bytes) else 0,
            'hash': result.get('file_info', {}).get('sha256', '')[:16] if result.get('file_info') else ''
        }
    
    # Log the result
    logger.info(f"Analysis completed: {json.dumps(log_data)}")

def log_security_event(
    event_type: str,
    severity: str,
    description: str,
    details: Optional[Dict[str, Any]] = None
) -> None:
    """
    Log security-related events
    
    Args:
        event_type: Type of security event
        severity: Event severity (LOW, MEDIUM, HIGH, CRITICAL)
        description: Event description
        details: Optional additional details
    """
    logger = logging.getLogger('security')
    
    event_data = {
        'timestamp': datetime.utcnow().isoformat(),
        'event_type': event_type,
        'severity': severity,
        'description': description,
        'details': details or {}
    }
    
    # Log based on severity
    if severity == 'CRITICAL':
        logger.critical(f"Security event: {json.dumps(event_data)}")
    elif severity == 'HIGH':
        logger.error(f"Security event: {json.dumps(event_data)}")
    elif severity == 'MEDIUM':
        logger.warning(f"Security event: {json.dumps(event_data)}")
    else:
        logger.info(f"Security event: {json.dumps(event_data)}")

def log_model_performance(
    model_name: str,
    input_size: int,
    processing_time: float,
    memory_usage: Optional[float] = None
) -> None:
    """
    Log model performance metrics
    
    Args:
        model_name: Name of the model
        input_size: Size of input data
        processing_time: Processing time in seconds
        memory_usage: Optional memory usage in MB
    """
    logger = logging.getLogger('performance')
    
    performance_data = {
        'timestamp': datetime.utcnow().isoformat(),
        'model_name': model_name,
        'input_size': input_size,
        'processing_time': processing_time,
        'memory_usage': memory_usage
    }
    
    logger.info(f"Model performance: {json.dumps(performance_data)}")

def log_api_request(
    endpoint: str,
    method: str,
    status_code: int,
    response_time: float,
    user_agent: Optional[str] = None,
    ip_address: Optional[str] = None
) -> None:
    """
    Log API request for monitoring and analytics
    
    Args:
        endpoint: API endpoint
        method: HTTP method
        status_code: Response status code
        response_time: Response time in seconds
        user_agent: Optional user agent string
        ip_address: Optional client IP address
    """
    logger = logging.getLogger('api')
    
    request_data = {
        'timestamp': datetime.utcnow().isoformat(),
        'endpoint': endpoint,
        'method': method,
        'status_code': status_code,
        'response_time': response_time,
        'user_agent': user_agent,
        'ip_address': ip_address
    }
    
    # Log based on status code
    if status_code >= 500:
        logger.error(f"API request: {json.dumps(request_data)}")
    elif status_code >= 400:
        logger.warning(f"API request: {json.dumps(request_data)}")
    else:
        logger.info(f"API request: {json.dumps(request_data)}")

def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance with the specified name
    
    Args:
        name: Logger name
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)
