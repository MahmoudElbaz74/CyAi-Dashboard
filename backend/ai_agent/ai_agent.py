"""
AI Agent Module - Expert Cybersecurity Analysis with Gemini-1.5-Pro
Provides explain, reason, correlate, and summarize capabilities
"""

import logging
from typing import Dict, Any, List, Optional, Union
from datetime import datetime
import json

from gemini_integration.gemini_client import get_gemini_client, GeminiClient

logger = logging.getLogger(__name__)

class AIAgent:
    """
    AI Agent for expert cybersecurity analysis, explanation, and correlation
    """
    
    def __init__(self, gemini_client: Optional[GeminiClient] = None):
        """
        Initialize AI Agent
        
        Args:
            gemini_client: Gemini client instance (if None, will get global instance)
        """
        self.gemini_client = gemini_client or get_gemini_client()
        self.mitre_attack_techniques = self._load_mitre_attack_techniques()
        
        logger.info("AI Agent initialized successfully")
    
    def _load_mitre_attack_techniques(self) -> Dict[str, Dict[str, Any]]:
        """
        Load MITRE ATT&CK techniques for mapping
        
        Returns:
            Dictionary of MITRE ATT&CK techniques
        """
        return {
            "T1071": {
                "name": "Application Layer Protocol",
                "description": "Adversaries may communicate using application layer protocols to avoid detection/network filtering",
                "tactics": ["Command and Control", "Communication"]
            },
            "T1055": {
                "name": "Process Injection",
                "description": "Adversaries may inject code into processes to evade process-based defenses",
                "tactics": ["Defense Evasion", "Privilege Escalation"]
            },
            "T1027": {
                "name": "Obfuscated Files or Information",
                "description": "Adversaries may attempt to make an executable or file difficult to discover or analyze",
                "tactics": ["Defense Evasion"]
            },
            "T1083": {
                "name": "File and Directory Discovery",
                "description": "Adversaries may enumerate files and directories to gather information",
                "tactics": ["Discovery"]
            },
            "T1049": {
                "name": "System Network Connections Discovery",
                "description": "Adversaries may attempt to get a listing of network connections",
                "tactics": ["Discovery"]
            },
            "T1016": {
                "name": "System Network Configuration Discovery",
                "description": "Adversaries may look for details about the network configuration",
                "tactics": ["Discovery"]
            },
            "T1105": {
                "name": "Ingress Tool Transfer",
                "description": "Adversaries may transfer tools or other files from an external system",
                "tactics": ["Command and Control"]
            },
            "T1059": {
                "name": "Command and Scripting Interpreter",
                "description": "Adversaries may abuse command and script interpreters to execute commands",
                "tactics": ["Execution"]
            },
            "T1070": {
                "name": "Indicator Removal",
                "description": "Adversaries may delete or modify artifacts generated within systems",
                "tactics": ["Defense Evasion"]
            },
            "T1036": {
                "name": "Masquerading",
                "description": "Adversaries may attempt to manipulate features of their artifacts",
                "tactics": ["Defense Evasion"]
            }
        }
    
    async def ask_ai_agent(self, prompt: str, context: Dict[str, Any]) -> str:
        """
        Main AI Agent function - Explain, reason, correlate, and summarize
        
        Args:
            prompt: User question or analysis request
            context: Context data including model outputs, logs, and findings
            
        Returns:
            Expert-level explanation and analysis
        """
        try:
            # Determine analysis type based on context
            analysis_type = self._determine_analysis_type(context)
            
            # Build comprehensive prompt
            full_prompt = self._build_expert_prompt(prompt, context, analysis_type)
            
            # Get AI response
            response = await self.gemini_client._generate_response(full_prompt)
            
            # Post-process response for additional insights
            enhanced_response = await self._enhance_response(response, context, analysis_type)
            
            return enhanced_response
            
        except Exception as e:
            logger.error(f"Error in AI Agent: {e}")
            return f"AI Agent analysis failed: {str(e)}. Please try again or contact support."
    
    def _determine_analysis_type(self, context: Dict[str, Any]) -> str:
        """
        Determine the type of analysis based on context
        
        Args:
            context: Context data
            
        Returns:
            Analysis type string
        """
        if context.get('logs') and context.get('urls') and context.get('files'):
            return "comprehensive_correlation"
        elif context.get('logs') and context.get('urls'):
            return "network_correlation"
        elif context.get('files') and context.get('urls'):
            return "threat_correlation"
        elif context.get('logs'):
            return "log_analysis"
        elif context.get('urls'):
            return "url_analysis"
        elif context.get('files'):
            return "file_analysis"
        elif context.get('model_outputs'):
            return "model_explanation"
        else:
            return "general_analysis"
    
    def _build_expert_prompt(self, prompt: str, context: Dict[str, Any], analysis_type: str) -> str:
        """
        Build comprehensive expert prompt for Gemini
        
        Args:
            prompt: User prompt
            context: Context data
            analysis_type: Type of analysis
            
        Returns:
            Formatted prompt for Gemini
        """
        base_prompt = f"""
You are an expert cybersecurity analyst with deep knowledge of:
- MITRE ATT&CK framework and threat modeling
- Network security analysis and log interpretation
- Malware analysis and threat intelligence
- Incident response and remediation strategies
- Security architecture and best practices

USER REQUEST: {prompt}

ANALYSIS TYPE: {analysis_type}

CONTEXT DATA:
"""
        
        # Add context sections
        if context.get('logs'):
            base_prompt += f"""
LOG ANALYSIS RESULTS:
{json.dumps(context['logs'], indent=2)}
"""
        
        if context.get('urls'):
            base_prompt += f"""
URL ANALYSIS RESULTS:
{json.dumps(context['urls'], indent=2)}
"""
        
        if context.get('files'):
            base_prompt += f"""
FILE ANALYSIS RESULTS:
{json.dumps(context['files'], indent=2)}
"""
        
        if context.get('model_outputs'):
            base_prompt += f"""
MODEL OUTPUTS:
{json.dumps(context['model_outputs'], indent=2)}
"""
        
        if context.get('correlation_data'):
            base_prompt += f"""
CORRELATION DATA:
{json.dumps(context['correlation_data'], indent=2)}
"""
        
        # Add analysis-specific instructions
        if analysis_type == "comprehensive_correlation":
            base_prompt += """
COMPREHENSIVE ANALYSIS REQUIRED:
1. Correlate all findings across logs, URLs, and files
2. Identify potential attack chains and patterns
3. Map behaviors to MITRE ATT&CK techniques
4. Assess overall threat level and impact
5. Provide prioritized remediation steps
6. Suggest monitoring and detection improvements
"""
        
        elif analysis_type == "network_correlation":
            base_prompt += """
NETWORK CORRELATION ANALYSIS:
1. Analyze network traffic patterns and anomalies
2. Correlate URL findings with network logs
3. Identify potential command and control communications
4. Map network behaviors to MITRE ATT&CK techniques
5. Assess network security posture
6. Recommend network security improvements
"""
        
        elif analysis_type == "threat_correlation":
            base_prompt += """
THREAT CORRELATION ANALYSIS:
1. Correlate file and URL analysis results
2. Identify potential malware distribution chains
3. Map threat behaviors to MITRE ATT&CK techniques
4. Assess threat actor capabilities and intent
5. Provide threat intelligence context
6. Recommend threat hunting strategies
"""
        
        elif analysis_type == "log_analysis":
            base_prompt += """
LOG ANALYSIS:
1. Explain why specific logs are classified as malicious/suspicious
2. Identify attack patterns and techniques
3. Map log events to MITRE ATT&CK techniques
4. Correlate with known threat behaviors
5. Provide incident response guidance
6. Suggest log monitoring improvements
"""
        
        elif analysis_type == "model_explanation":
            base_prompt += """
MODEL EXPLANATION:
1. Explain the model's classification reasoning
2. Provide context for the confidence level
3. Map findings to known attack patterns
4. Suggest additional investigation steps
5. Provide remediation recommendations
6. Explain potential false positives/negatives
"""
        
        # Add standard analysis requirements
        base_prompt += """

ANALYSIS REQUIREMENTS:
1. **EXPLANATION**: Provide clear, technical explanations of findings
2. **MITRE ATT&CK MAPPING**: Map behaviors to specific MITRE ATT&CK techniques
3. **CORRELATION**: Identify relationships between different findings
4. **THREAT ASSESSMENT**: Assess threat level and potential impact
5. **REMEDIATION**: Provide specific, actionable remediation steps
6. **PREVENTION**: Suggest prevention and detection improvements
7. **THREAT INTELLIGENCE**: Provide context from known threat behaviors

FORMAT YOUR RESPONSE AS:
- **Executive Summary**: High-level overview of findings
- **Technical Analysis**: Detailed technical explanation
- **MITRE ATT&CK Mapping**: Specific technique mappings
- **Threat Assessment**: Risk and impact assessment
- **Remediation Steps**: Prioritized action items
- **Prevention Recommendations**: Long-term security improvements
- **Additional Context**: Relevant threat intelligence

Be thorough, professional, and actionable in your analysis.
"""
        
        return base_prompt
    
    async def _enhance_response(self, response: str, context: Dict[str, Any], analysis_type: str) -> str:
        """
        Enhance the AI response with additional analysis
        
        Args:
            response: Initial AI response
            context: Context data
            analysis_type: Type of analysis
            
        Returns:
            Enhanced response with additional insights
        """
        try:
            # Add MITRE ATT&CK technique details if mentioned
            enhanced_response = self._add_mitre_attack_details(response)
            
            # Add correlation insights if multiple data sources
            if analysis_type in ["comprehensive_correlation", "network_correlation", "threat_correlation"]:
                correlation_insights = self._generate_correlation_insights(context)
                enhanced_response += f"\n\n**CORRELATION INSIGHTS:**\n{correlation_insights}"
            
            # Add threat intelligence context
            threat_intel = self._add_threat_intelligence_context(context)
            if threat_intel:
                enhanced_response += f"\n\n**THREAT INTELLIGENCE CONTEXT:**\n{threat_intel}"
            
            return enhanced_response
            
        except Exception as e:
            logger.error(f"Error enhancing response: {e}")
            return response  # Return original response if enhancement fails
    
    def _add_mitre_attack_details(self, response: str) -> str:
        """
        Add detailed MITRE ATT&CK technique information to response
        
        Args:
            response: AI response text
            
        Returns:
            Enhanced response with MITRE ATT&CK details
        """
        enhanced_response = response
        
        # Look for MITRE ATT&CK technique mentions
        for technique_id, technique_info in self.mitre_attack_techniques.items():
            if technique_id in response:
                details = f"""
**{technique_id} - {technique_info['name']}**
- Description: {technique_info['description']}
- Tactics: {', '.join(technique_info['tactics'])}
"""
                enhanced_response += details
        
        return enhanced_response
    
    def _generate_correlation_insights(self, context: Dict[str, Any]) -> str:
        """
        Generate correlation insights from multiple data sources
        
        Args:
            context: Context data with multiple analysis results
            
        Returns:
            Correlation insights text
        """
        insights = []
        
        # Analyze temporal correlations
        if self._has_temporal_data(context):
            insights.append("**Temporal Analysis**: Multiple events occurred within a short timeframe, suggesting coordinated activity.")
        
        # Analyze behavioral correlations
        if self._has_behavioral_correlations(context):
            insights.append("**Behavioral Correlation**: Similar attack patterns detected across different data sources.")
        
        # Analyze infrastructure correlations
        if self._has_infrastructure_correlations(context):
            insights.append("**Infrastructure Correlation**: Shared infrastructure elements suggest potential threat actor attribution.")
        
        # Analyze payload correlations
        if self._has_payload_correlations(context):
            insights.append("**Payload Correlation**: Similar payloads or techniques suggest potential campaign attribution.")
        
        if not insights:
            insights.append("**Correlation Analysis**: No significant correlations detected between data sources.")
        
        return "\n".join(insights)
    
    def _add_threat_intelligence_context(self, context: Dict[str, Any]) -> str:
        """
        Add threat intelligence context to the response
        
        Args:
            context: Context data
            
        Returns:
            Threat intelligence context text
        """
        context_items = []
        
        # Check for known malicious indicators
        if self._has_known_malicious_indicators(context):
            context_items.append("**Known Malicious Indicators**: Some indicators match known threat actor infrastructure or techniques.")
        
        # Check for campaign attribution
        if self._has_campaign_indicators(context):
            context_items.append("**Campaign Attribution**: Indicators suggest potential attribution to known threat campaigns.")
        
        # Check for geographic indicators
        if self._has_geographic_indicators(context):
            context_items.append("**Geographic Indicators**: Some indicators suggest specific geographic origins or targeting.")
        
        # Check for industry targeting
        if self._has_industry_targeting(context):
            context_items.append("**Industry Targeting**: Indicators suggest potential targeting of specific industries or sectors.")
        
        return "\n".join(context_items) if context_items else ""
    
    # Helper methods for correlation analysis
    def _has_temporal_data(self, context: Dict[str, Any]) -> bool:
        """Check if context has temporal data for correlation"""
        # Simplified check - in real implementation, would analyze timestamps
        return len(context) > 1
    
    def _has_behavioral_correlations(self, context: Dict[str, Any]) -> bool:
        """Check for behavioral correlations"""
        # Simplified check - in real implementation, would analyze behavior patterns
        return any('malicious' in str(context).lower() for _ in [1])
    
    def _has_infrastructure_correlations(self, context: Dict[str, Any]) -> bool:
        """Check for infrastructure correlations"""
        # Simplified check - in real implementation, would analyze IPs, domains, etc.
        return any('ip' in str(context).lower() or 'domain' in str(context).lower() for _ in [1])
    
    def _has_payload_correlations(self, context: Dict[str, Any]) -> bool:
        """Check for payload correlations"""
        # Simplified check - in real implementation, would analyze file hashes, etc.
        return any('hash' in str(context).lower() or 'payload' in str(context).lower() for _ in [1])
    
    def _has_known_malicious_indicators(self, context: Dict[str, Any]) -> bool:
        """Check for known malicious indicators"""
        # Simplified check - in real implementation, would check threat intel feeds
        return any('malicious' in str(context).lower() for _ in [1])
    
    def _has_campaign_indicators(self, context: Dict[str, Any]) -> bool:
        """Check for campaign indicators"""
        # Simplified check - in real implementation, would check campaign databases
        return any('campaign' in str(context).lower() for _ in [1])
    
    def _has_geographic_indicators(self, context: Dict[str, Any]) -> bool:
        """Check for geographic indicators"""
        # Simplified check - in real implementation, would analyze IP geolocation
        return any('ip' in str(context).lower() for _ in [1])
    
    def _has_industry_targeting(self, context: Dict[str, Any]) -> bool:
        """Check for industry targeting indicators"""
        # Simplified check - in real implementation, would analyze targeting patterns
        return any('target' in str(context).lower() for _ in [1])

# Global AI Agent instance
_ai_agent = None

def get_ai_agent() -> AIAgent:
    """
    Get the global AI Agent instance (singleton pattern)
    
    Returns:
        AIAgent instance
    """
    global _ai_agent
    if _ai_agent is None:
        _ai_agent = AIAgent()
    return _ai_agent

async def ask_ai_agent(prompt: str, context: Dict[str, Any]) -> str:
    """
    Main function to ask the AI Agent for expert analysis
    
    Args:
        prompt: User question or analysis request
        context: Context data including model outputs, logs, and findings
        
    Returns:
        Expert-level explanation and analysis
    """
    ai_agent = get_ai_agent()
    return await ai_agent.ask_ai_agent(prompt, context)
