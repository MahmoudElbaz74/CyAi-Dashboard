"""
Context Builder Module
Prepares and structures logs and data before sending to LLM
"""

from typing import Dict, List, Any, Optional, Union
import json
import logging
from datetime import datetime
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)

@dataclass
class LogEntry:
    """Represents a single log entry"""
    timestamp: str
    level: str
    source: str
    message: str
    metadata: Optional[Dict[str, Any]] = None

@dataclass
class AnalysisContext:
    """Represents analysis context for AI processing"""
    data_type: str
    raw_data: Any
    processed_data: Dict[str, Any]
    metadata: Dict[str, Any]
    timestamp: str

class ContextBuilder:
    """Builds and structures context for AI analysis"""
    
    def __init__(self):
        self.logs: List[LogEntry] = []
        self.contexts: List[AnalysisContext] = []
    
    def add_log(self, level: str, source: str, message: str, 
                metadata: Optional[Dict[str, Any]] = None) -> None:
        """
        Add a log entry to the context
        
        Args:
            level: Log level (INFO, WARNING, ERROR, DEBUG)
            source: Source of the log (e.g., 'network_detector', 'malware_analyzer')
            message: Log message
            metadata: Additional metadata
        """
        log_entry = LogEntry(
            timestamp=datetime.now().isoformat(),
            level=level,
            source=source,
            message=message,
            metadata=metadata
        )
        self.logs.append(log_entry)
        logger.debug(f"Added log entry: {level} from {source}")
    
    def add_analysis_context(self, data_type: str, raw_data: Any, 
                           processed_data: Dict[str, Any], 
                           metadata: Optional[Dict[str, Any]] = None) -> None:
        """
        Add analysis context for AI processing
        
        Args:
            data_type: Type of data being analyzed
            raw_data: Original raw data
            processed_data: Processed/structured data
            metadata: Additional metadata
        """
        context = AnalysisContext(
            data_type=data_type,
            raw_data=raw_data,
            processed_data=processed_data,
            metadata=metadata or {},
            timestamp=datetime.now().isoformat()
        )
        self.contexts.append(context)
        logger.debug(f"Added analysis context for {data_type}")
    
    def build_network_context(self, pcap_data: Dict[str, Any], 
                            analysis_results: Dict[str, Any]) -> str:
        """
        Build context for network analysis
        
        Args:
            pcap_data: Raw PCAP data
            analysis_results: Results from network analysis
            
        Returns:
            Formatted context string
        """
        self.add_analysis_context(
            data_type="network_traffic",
            raw_data=pcap_data,
            processed_data=analysis_results,
            metadata={"analysis_type": "network_detection"}
        )
        
        context = {
            "analysis_type": "Network Traffic Analysis",
            "timestamp": datetime.now().isoformat(),
            "raw_data_summary": {
                "packet_count": pcap_data.get("packet_count", 0),
                "duration": pcap_data.get("duration", 0),
                "protocols": pcap_data.get("protocols", [])
            },
            "analysis_results": analysis_results,
            "relevant_logs": self._get_relevant_logs("network_detector")
        }
        
        return json.dumps(context, indent=2)
    
    def build_malware_context(self, sample_data: Dict[str, Any], 
                            analysis_results: Dict[str, Any]) -> str:
        """
        Build context for malware analysis
        
        Args:
            sample_data: Raw malware sample data
            analysis_results: Results from malware analysis
            
        Returns:
            Formatted context string
        """
        self.add_analysis_context(
            data_type="malware_sample",
            raw_data=sample_data,
            processed_data=analysis_results,
            metadata={"analysis_type": "malware_analysis"}
        )
        
        context = {
            "analysis_type": "Malware Analysis",
            "timestamp": datetime.now().isoformat(),
            "sample_info": {
                "file_size": sample_data.get("file_size", 0),
                "file_type": sample_data.get("file_type", "unknown"),
                "hash": sample_data.get("hash", "unknown")
            },
            "analysis_results": analysis_results,
            "relevant_logs": self._get_relevant_logs("malware_analyzer")
        }
        
        return json.dumps(context, indent=2)
    
    def build_link_context(self, url_data: Dict[str, Any], 
                         analysis_results: Dict[str, Any]) -> str:
        """
        Build context for link analysis
        
        Args:
            url_data: Raw URL data
            analysis_results: Results from link analysis
            
        Returns:
            Formatted context string
        """
        self.add_analysis_context(
            data_type="url_analysis",
            raw_data=url_data,
            processed_data=analysis_results,
            metadata={"analysis_type": "link_analysis"}
        )
        
        context = {
            "analysis_type": "URL/Link Analysis",
            "timestamp": datetime.now().isoformat(),
            "url_info": {
                "url": url_data.get("url", ""),
                "domain": url_data.get("domain", ""),
                "status_code": url_data.get("status_code", 0)
            },
            "analysis_results": analysis_results,
            "relevant_logs": self._get_relevant_logs("link_analyzer")
        }
        
        return json.dumps(context, indent=2)
    
    def build_general_context(self, query: str, additional_data: Optional[Dict[str, Any]] = None) -> str:
        """
        Build context for general queries
        
        Args:
            query: User query
            additional_data: Additional data to include
            
        Returns:
            Formatted context string
        """
        context = {
            "query_type": "General Query",
            "timestamp": datetime.now().isoformat(),
            "user_query": query,
            "additional_data": additional_data or {},
            "system_logs": self._get_recent_logs(limit=10)
        }
        
        return json.dumps(context, indent=2)
    
    def _get_relevant_logs(self, source: str) -> List[Dict[str, Any]]:
        """
        Get logs relevant to a specific source
        
        Args:
            source: Source to filter logs by
            
        Returns:
            List of relevant log entries
        """
        relevant_logs = []
        for log in self.logs:
            if log.source == source:
                relevant_logs.append(asdict(log))
        return relevant_logs[-10:]  # Return last 10 relevant logs
    
    def _get_recent_logs(self, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Get recent logs
        
        Args:
            limit: Maximum number of logs to return
            
        Returns:
            List of recent log entries
        """
        return [asdict(log) for log in self.logs[-limit:]]
    
    def get_context_summary(self) -> Dict[str, Any]:
        """
        Get a summary of all contexts
        
        Returns:
            Summary of contexts and logs
        """
        return {
            "total_logs": len(self.logs),
            "total_contexts": len(self.contexts),
            "recent_logs": self._get_recent_logs(5),
            "context_types": [ctx.data_type for ctx in self.contexts],
            "last_updated": datetime.now().isoformat()
        }
    
    def clear_context(self) -> None:
        """Clear all stored contexts and logs"""
        self.logs.clear()
        self.contexts.clear()
        logger.info("Context builder cleared")
    
    def export_context(self, format_type: str = "json") -> Union[str, Dict[str, Any]]:
        """
        Export all context data
        
        Args:
            format_type: Export format ('json' or 'dict')
            
        Returns:
            Exported context data
        """
        export_data = {
            "logs": [asdict(log) for log in self.logs],
            "contexts": [asdict(ctx) for ctx in self.contexts],
            "export_timestamp": datetime.now().isoformat()
        }
        
        if format_type == "json":
            return json.dumps(export_data, indent=2)
        else:
            return export_data

# Global context builder instance
context_builder = ContextBuilder()

def get_context_builder() -> ContextBuilder:
    """Get the global context builder instance"""
    return context_builder


