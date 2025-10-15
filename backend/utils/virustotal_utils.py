"""
VirusTotal API integration utilities
Handles file scanning with VirusTotal API using asynchronous polling
"""

import os
import logging
import asyncio
import httpx
import time
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class VirusTotalScanner:
    """VirusTotal API scanner for file analysis"""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize VirusTotal scanner
        
        Args:
            api_key: VirusTotal API key (if None, will try to get from environment)
        """
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": self.api_key} if self.api_key else {}
        
    async def test_connectivity(self) -> Dict[str, Any]:
        """
        Test VirusTotal API connectivity with a simple GET request
        
        Returns:
            Dictionary with connectivity test results
        """
        if not self.api_key:
            return {
                "success": False,
                "error": "VirusTotal API key not found. Please set VIRUSTOTAL_API_KEY in your .env file.",
                "status": "no_api_key"
            }
        
        try:
            # Test with a known file hash (EICAR test file)
            test_url = f"{self.base_url}/files/44d88612fea8a8f36de82e1278abb02f"
            
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(test_url, headers=self.headers)
                
                if response.status_code == 200:
                    logger.info("VirusTotal connection OK")
                    return {
                        "success": True,
                        "status": "connected",
                        "message": "VirusTotal API connection successful"
                    }
                elif response.status_code == 401:
                    logger.error("Invalid API key")
                    return {
                        "success": False,
                        "error": "Invalid VirusTotal API key",
                        "status": "invalid_key"
                    }
                elif response.status_code == 429:
                    logger.warning("Rate limit reached")
                    return {
                        "success": False,
                        "error": "VirusTotal rate limit reached",
                        "status": "rate_limited"
                    }
                else:
                    logger.error(f"VirusTotal connection failed (status: {response.status_code})")
                    return {
                        "success": False,
                        "error": f"VirusTotal API returned status {response.status_code}",
                        "status": "api_error"
                    }
                    
        except httpx.TimeoutException:
            logger.error("VirusTotal connection failed (timeout)")
            return {
                "success": False,
                "error": "VirusTotal API connection timeout",
                "status": "timeout"
            }
        except Exception as e:
            logger.error(f"VirusTotal connection failed: {str(e)}")
            return {
                "success": False,
                "error": f"VirusTotal API connection failed: {str(e)}",
                "status": "connection_error"
            }
        
    async def scan_file_async(self, file_path: str, max_wait_time: int = 90, poll_interval: int = 5) -> Dict[str, Any]:
        """
        Asynchronously scan a file with VirusTotal using polling
        
        Args:
            file_path: Path to the file to scan
            max_wait_time: Maximum time to wait for analysis completion (seconds)
            poll_interval: Interval between status checks (seconds)
            
        Returns:
            Dictionary with scan results
        """
        if not self.api_key:
            return {
                "error": "VirusTotal API key not found. Please set VIRUSTOTAL_API_KEY in your .env file.",
                "success": False
            }
        
        try:
            # Step 0: Test connectivity first
            connectivity_result = await self.test_connectivity()
            if not connectivity_result.get("success"):
                return {
                    "error": f"VirusTotal API connection failed. Check your API key or network. Details: {connectivity_result.get('error')}",
                    "success": False
                }
            
            # Step 1: Upload file to VirusTotal
            upload_result = await self._upload_file_async(file_path)
            if not upload_result.get("success"):
                return upload_result
            
            analysis_id = upload_result.get("analysis_id")
            if not analysis_id:
                return {
                    "error": "No analysis ID received from VirusTotal",
                    "success": False
                }
            
            # Step 2: Poll for analysis completion
            return await self._poll_analysis_results(analysis_id, max_wait_time, poll_interval)
            
        except Exception as e:
            logger.error(f"VirusTotal async scan failed: {e}")
            return {
                "error": f"VirusTotal scan failed: {str(e)}",
                "success": False
            }
    
    def scan_file(self, file_path: str, timeout: int = 60) -> Dict[str, Any]:
        """
        Synchronous wrapper for VirusTotal scan (for backward compatibility)
        
        Args:
            file_path: Path to the file to scan
            timeout: Timeout in seconds for the scan
            
        Returns:
            Dictionary with scan results
        """
        # Run the async version in a new event loop
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # If we're already in an async context, create a new task
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(asyncio.run, self.scan_file_async(file_path, timeout))
                    return future.result()
            else:
                return loop.run_until_complete(self.scan_file_async(file_path, timeout))
        except RuntimeError:
            # No event loop running, create a new one
            return asyncio.run(self.scan_file_async(file_path, timeout))
    
    async def _upload_file_async(self, file_path: str) -> Dict[str, Any]:
        """Asynchronously upload file to VirusTotal for analysis"""
        try:
            url = f"{self.base_url}/files"
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                with open(file_path, 'rb') as file:
                    files = {'file': (os.path.basename(file_path), file)}
                    
                    response = await client.post(url, headers=self.headers, files=files)
                    
                    if response.status_code == 200:
                        result_data = response.json()
                        analysis_id = result_data.get("data", {}).get("id")
                        return {
                            "success": True,
                            "analysis_id": analysis_id,
                            "raw_response": result_data
                        }
                    elif response.status_code == 429:
                        return {
                            "error": "VirusTotal rate limit exceeded",
                            "success": False
                        }
                    else:
                        return {
                            "error": f"VirusTotal upload failed with status {response.status_code}",
                            "success": False
                        }
                
        except httpx.TimeoutException:
            return {
                "error": "VirusTotal upload timeout",
                "success": False
            }
        except Exception as e:
            return {
                "error": f"VirusTotal upload failed: {str(e)}",
                "success": False
            }
    
    def _upload_file(self, file_path: str) -> Dict[str, Any]:
        """Synchronous upload file to VirusTotal for analysis (for backward compatibility)"""
        try:
            url = f"{self.base_url}/files"
            
            with open(file_path, 'rb') as file:
                files = {'file': (os.path.basename(file_path), file)}
                response = requests.post(url, headers=self.headers, files=files, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                analysis_id = data.get("data", {}).get("id")
                return {
                    "success": True,
                    "analysis_id": analysis_id,
                    "raw_response": data
                }
            elif response.status_code == 429:
                return {
                    "error": "VirusTotal rate limit exceeded",
                    "success": False
                }
            else:
                return {
                    "error": f"VirusTotal upload failed with status {response.status_code}",
                    "success": False
                }
                
        except requests.exceptions.Timeout:
            return {
                "error": "VirusTotal upload timeout",
                "success": False
            }
        except Exception as e:
            return {
                "error": f"VirusTotal upload failed: {str(e)}",
                "success": False
            }
    
    async def _poll_analysis_results(self, analysis_id: str, max_wait_time: int = 90, poll_interval: int = 5) -> Dict[str, Any]:
        """Asynchronously poll for analysis results from VirusTotal"""
        try:
            url = f"{self.base_url}/analyses/{analysis_id}"
            start_time = time.time()
            
            async with httpx.AsyncClient(timeout=10.0) as client:
                while time.time() - start_time < max_wait_time:
                    response = await client.get(url, headers=self.headers)
                    
                    if response.status_code == 200:
                        data = response.json()
                        status = data.get("data", {}).get("attributes", {}).get("status")
                        
                        if status == "completed":
                            # Get the file analysis results
                            file_id = data.get("data", {}).get("attributes", {}).get("stats", {}).get("file_id")
                            if file_id:
                                return await self._get_file_report_async(file_id)
                            else:
                                return self._parse_analysis_data(data)
                        elif status in ["queued", "running"]:
                            logger.info(f"Analysis {analysis_id} status: {status}, waiting {poll_interval}s...")
                            await asyncio.sleep(poll_interval)
                            continue
                        else:
                            return {
                                "error": f"Analysis status: {status}",
                                "success": False
                            }
                    elif response.status_code == 429:
                        return {
                            "error": "VirusTotal rate limit exceeded",
                            "success": False
                        }
                    else:
                        return {
                            "error": f"Failed to get analysis results: {response.status_code}",
                            "success": False
                        }
                
                return {
                    "error": f"VirusTotal analysis timeout after {max_wait_time} seconds. Analysis may still be processing.",
                    "success": False
                }
                
        except httpx.TimeoutException:
            return {
                "error": f"VirusTotal analysis timeout after {max_wait_time} seconds. Analysis may still be processing.",
                "success": False
            }
        except Exception as e:
            return {
                "error": f"Failed to get analysis results: {str(e)}",
                "success": False
            }
    
    def _get_analysis_results(self, analysis_id: str, timeout: int = 30) -> Dict[str, Any]:
        """Synchronous get analysis results from VirusTotal (for backward compatibility)"""
        try:
            url = f"{self.base_url}/analyses/{analysis_id}"
            start_time = time.time()
            
            while time.time() - start_time < timeout:
                response = requests.get(url, headers=self.headers, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    status = data.get("data", {}).get("attributes", {}).get("status")
                    
                    if status == "completed":
                        # Get the file analysis results
                        file_id = data.get("data", {}).get("attributes", {}).get("stats", {}).get("file_id")
                        if file_id:
                            return self._get_file_report(file_id)
                        else:
                            return self._parse_analysis_data(data)
                    elif status == "queued":
                        time.sleep(3)  # Wait 3 seconds before checking again
                        continue
                    elif status == "running":
                        time.sleep(3)  # Wait 3 seconds before checking again
                        continue
                    else:
                        return {
                            "error": f"Analysis status: {status}",
                            "success": False
                        }
                elif response.status_code == 429:
                    return {
                        "error": "VirusTotal rate limit exceeded",
                        "success": False
                    }
                else:
                    return {
                        "error": f"Failed to get analysis results: {response.status_code}",
                        "success": False
                    }
            
            return {
                "error": f"VirusTotal analysis timeout after {timeout} seconds. Analysis may still be processing.",
                "success": False
            }
            
        except Exception as e:
            return {
                "error": f"Failed to get analysis results: {str(e)}",
                "success": False
            }
    
    async def _get_file_report_async(self, file_id: str) -> Dict[str, Any]:
        """Asynchronously get detailed file report from VirusTotal"""
        try:
            url = f"{self.base_url}/files/{file_id}"
            
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(url, headers=self.headers)
                
                if response.status_code == 200:
                    data = response.json()
                    return self._parse_file_report(data)
                else:
                    return {
                        "error": f"Failed to get file report: {response.status_code}",
                        "success": False
                    }
        except Exception as e:
            return {
                "error": f"Failed to get file report: {str(e)}",
                "success": False
            }
    
    def _get_file_report(self, file_id: str) -> Dict[str, Any]:
        """Synchronous get detailed file report from VirusTotal (for backward compatibility)"""
        try:
            url = f"{self.base_url}/files/{file_id}"
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_file_report(data)
            else:
                return {
                    "error": f"Failed to get file report: {response.status_code}",
                    "success": False
                }
        except Exception as e:
            return {
                "error": f"Failed to get file report: {str(e)}",
                "success": False
            }
    
    def _parse_analysis_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse analysis data from VirusTotal"""
        try:
            stats = data.get("data", {}).get("attributes", {}).get("stats", {})
            
            return {
                "success": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0),
                "raw_data": data
            }
        except Exception as e:
            return {
                "error": f"Failed to parse analysis data: {str(e)}",
                "success": False
            }
    
    def _parse_file_report(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse file report data from VirusTotal"""
        try:
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            
            return {
                "success": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0),
                "raw_data": data
            }
        except Exception as e:
            return {
                "error": f"Failed to parse file report: {str(e)}",
                "success": False
            }
