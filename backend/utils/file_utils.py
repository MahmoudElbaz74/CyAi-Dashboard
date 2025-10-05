"""
File utility functions for CyAi Dashboard
Handles file operations, validation, and processing
"""

import hashlib
import os
from typing import Optional, List, Dict, Any
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    magic = None
    MAGIC_AVAILABLE = False
import logging

logger = logging.getLogger(__name__)

def validate_file_type(file_path: str, allowed_types: List[str]) -> bool:
    """
    Validate file type based on extension and MIME type
    
    Args:
        file_path: Path to the file
        allowed_types: List of allowed file extensions
        
    Returns:
        True if file type is allowed, False otherwise
    """
    try:
        # Check file extension
        file_ext = os.path.splitext(file_path)[1].lower()
        if file_ext not in allowed_types:
            return False
        
        # Check MIME type
        if MAGIC_AVAILABLE and magic:
            mime_type = magic.from_file(file_path, mime=True)
        else:
            mime_type = "application/octet-stream"
        allowed_mime_types = {
            '.exe': ['application/x-executable', 'application/x-msdownload'],
            '.pdf': ['application/pdf'],
            '.doc': ['application/msword'],
            '.docx': ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
            '.zip': ['application/zip'],
            '.rar': ['application/x-rar-compressed'],
            '.dll': ['application/x-msdownload'],
            '.bat': ['application/x-msdos-program'],
            '.cmd': ['application/x-msdos-program'],
            '.scr': ['application/x-msdownload'],
            '.txt': ['text/plain'],
            '.py': ['text/x-python'],
            '.js': ['application/javascript', 'text/javascript'],
            '.html': ['text/html'],
            '.php': ['application/x-php', 'text/x-php']
        }
        
        if file_ext in allowed_mime_types:
            return mime_type in allowed_mime_types[file_ext]
        
        return True
        
    except Exception as e:
        logger.error(f"Error validating file type: {e}")
        return False

def get_file_hash(file_content: bytes, algorithm: str = 'sha256') -> str:
    """
    Calculate hash of file content
    
    Args:
        file_content: File content as bytes
        algorithm: Hash algorithm to use (sha256, md5, sha1)
        
    Returns:
        Hexadecimal hash string
    """
    try:
        if algorithm == 'sha256':
            hash_obj = hashlib.sha256()
        elif algorithm == 'md5':
            hash_obj = hashlib.md5()
        elif algorithm == 'sha1':
            hash_obj = hashlib.sha1()
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
        
        hash_obj.update(file_content)
        return hash_obj.hexdigest()
        
    except Exception as e:
        logger.error(f"Error calculating file hash: {e}")
        return ""

def get_file_size(file_content: bytes) -> int:
    """
    Get file size in bytes
    
    Args:
        file_content: File content as bytes
        
    Returns:
        File size in bytes
    """
    return len(file_content)

def get_file_metadata(file_content: bytes, filename: str) -> Dict[str, Any]:
    """
    Extract file metadata
    
    Args:
        file_content: File content as bytes
        filename: Original filename
        
    Returns:
        Dictionary containing file metadata
    """
    try:
        metadata = {
            'filename': filename,
            'size': get_file_size(file_content),
            'sha256': get_file_hash(file_content, 'sha256'),
            'md5': get_file_hash(file_content, 'md5'),
            'sha1': get_file_hash(file_content, 'sha1'),
            'extension': os.path.splitext(filename)[1].lower(),
        }
        
        # Try to get MIME type
        try:
            if MAGIC_AVAILABLE and magic:
                metadata['mime_type'] = magic.from_buffer(file_content, mime=True)
            else:
                metadata['mime_type'] = "application/octet-stream"
        except:
            metadata['mime_type'] = 'unknown'
        
        return metadata
        
    except Exception as e:
        logger.error(f"Error extracting file metadata: {e}")
        return {
            'filename': filename,
            'size': len(file_content),
            'sha256': '',
            'md5': '',
            'sha1': '',
            'extension': os.path.splitext(filename)[1].lower(),
            'mime_type': 'unknown'
        }

def is_safe_file_size(file_size: int, max_size: int = 50 * 1024 * 1024) -> bool:
    """
    Check if file size is within safe limits
    
    Args:
        file_size: File size in bytes
        max_size: Maximum allowed file size in bytes (default: 50MB)
        
    Returns:
        True if file size is safe, False otherwise
    """
    return file_size <= max_size

def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent path traversal attacks
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    # Remove path traversal characters
    filename = filename.replace('..', '').replace('/', '').replace('\\', '')
    
    # Remove null bytes
    filename = filename.replace('\x00', '')
    
    # Limit filename length
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[:255-len(ext)] + ext
    
    return filename
