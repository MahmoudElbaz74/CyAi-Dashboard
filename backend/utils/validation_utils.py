"""
Validation utility functions for CyFort AI
Handles input validation and sanitization
"""

import re
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

def validate_url(url: str) -> Dict[str, Any]:
    """
    Validate URL format and extract components
    
    Args:
        url: URL string to validate
        
    Returns:
        Dictionary with validation result and URL components
    """
    try:
        # Basic URL format check
        if not url or not isinstance(url, str):
            return {
                'valid': False,
                'error': 'URL is empty or not a string',
                'components': None
            }
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Parse URL
        parsed = urlparse(url)
        
        # Check if URL has required components
        if not parsed.netloc:
            return {
                'valid': False,
                'error': 'Invalid URL format - missing domain',
                'components': None
            }
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
            r'bit\.ly|tinyurl|t\.co|goo\.gl',  # URL shorteners
            r'[a-zA-Z0-9-]+\.tk|\.ml|\.ga|\.cf',  # Suspicious TLDs
        ]
        
        suspicious = False
        for pattern in suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                suspicious = True
                break
        
        return {
            'valid': True,
            'error': None,
            'components': {
                'scheme': parsed.scheme,
                'netloc': parsed.netloc,
                'path': parsed.path,
                'query': parsed.query,
                'fragment': parsed.fragment,
                'full_url': url
            },
            'suspicious': suspicious
        }
        
    except Exception as e:
        logger.error(f"Error validating URL: {e}")
        return {
            'valid': False,
            'error': f'URL validation error: {str(e)}',
            'components': None
        }

def validate_log_format(log_entry: str) -> Dict[str, Any]:
    """
    Validate log entry format and extract components
    
    Args:
        log_entry: Log entry string to validate
        
    Returns:
        Dictionary with validation result and log components
    """
    try:
        if not log_entry or not isinstance(log_entry, str):
            return {
                'valid': False,
                'error': 'Log entry is empty or not a string',
                'components': None
            }
        
        # Common log patterns
        patterns = {
            'syslog': r'^<(\d+)>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.+)$',
            'apache': r'^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d+)\s+(\d+)$',
            'nginx': r'^(\S+)\s+-\s+-\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"$',
            'windows': r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\w+)\s+(.+)$',
            'network': r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+->\s+(\S+)\s+(\w+)\s+(.+)$'
        }
        
        detected_format = None
        components = None
        
        for format_name, pattern in patterns.items():
            match = re.match(pattern, log_entry.strip())
            if match:
                detected_format = format_name
                components = match.groups()
                break
        
        # If no specific format detected, check for basic structure
        if not detected_format:
            # Check for timestamp
            timestamp_pattern = r'\d{4}-\d{2}-\d{2}|\d{2}:\d{2}:\d{2}|\w{3}\s+\d{1,2}'
            has_timestamp = bool(re.search(timestamp_pattern, log_entry))
            
            # Check for IP addresses
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            has_ip = bool(re.search(ip_pattern, log_entry))
            
            # Check for common log keywords
            keywords = ['error', 'warning', 'info', 'debug', 'access', 'denied', 'allowed']
            has_keywords = any(keyword in log_entry.lower() for keyword in keywords)
            
            if has_timestamp or has_ip or has_keywords:
                detected_format = 'generic'
                components = (log_entry,)
        
        return {
            'valid': detected_format is not None,
            'error': None if detected_format else 'Log format not recognized',
            'components': {
                'format': detected_format,
                'parsed_components': components,
                'raw_entry': log_entry
            }
        }
        
    except Exception as e:
        logger.error(f"Error validating log format: {e}")
        return {
            'valid': False,
            'error': f'Log validation error: {str(e)}',
            'components': None
        }

def validate_model_input(data: Any, input_type: str) -> Dict[str, Any]:
    """
    Validate input data for model processing
    
    Args:
        data: Input data to validate
        input_type: Type of input (log, url, file)
        
    Returns:
        Dictionary with validation result
    """
    try:
        if input_type == 'log':
            if isinstance(data, str):
                return validate_log_format(data)
            elif isinstance(data, list):
                results = []
                for log_entry in data:
                    result = validate_log_format(log_entry)
                    results.append(result)
                return {
                    'valid': all(r['valid'] for r in results),
                    'error': None,
                    'components': {'batch_results': results}
                }
            else:
                return {
                    'valid': False,
                    'error': 'Log data must be string or list of strings',
                    'components': None
                }
        
        elif input_type == 'url':
            return validate_url(data)
        
        elif input_type == 'file':
            if isinstance(data, bytes):
                return {
                    'valid': True,
                    'error': None,
                    'components': {'size': len(data), 'type': 'bytes'}
                }
            else:
                return {
                    'valid': False,
                    'error': 'File data must be bytes',
                    'components': None
                }
        
        else:
            return {
                'valid': False,
                'error': f'Unknown input type: {input_type}',
                'components': None
            }
            
    except Exception as e:
        logger.error(f"Error validating model input: {e}")
        return {
            'valid': False,
            'error': f'Input validation error: {str(e)}',
            'components': None
        }

def sanitize_input(data: str) -> str:
    """
    Sanitize user input to prevent injection attacks
    
    Args:
        data: Input string to sanitize
        
    Returns:
        Sanitized string
    """
    try:
        if not isinstance(data, str):
            return str(data)
        
        # Remove null bytes
        data = data.replace('\x00', '')
        
        # Remove control characters except newlines and tabs
        data = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', data)
        
        # Limit length
        if len(data) > 10000:  # 10KB limit
            data = data[:10000]
        
        return data.strip()
        
    except Exception as e:
        logger.error(f"Error sanitizing input: {e}")
        return ""

def validate_confidence_score(confidence: float) -> bool:
    """
    Validate confidence score is within valid range
    
    Args:
        confidence: Confidence score to validate
        
    Returns:
        True if confidence is valid, False otherwise
    """
    return isinstance(confidence, (int, float)) and 0.0 <= confidence <= 1.0

def validate_threat_level(threat_level: str) -> bool:
    """
    Validate threat level is a valid value
    
    Args:
        threat_level: Threat level to validate
        
    Returns:
        True if threat level is valid, False otherwise
    """
    valid_levels = ['Low', 'Medium', 'High', 'Critical']
    return threat_level in valid_levels
