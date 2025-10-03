"""
Prompt Templates Module
Manages and provides templates for different types of AI prompts
"""

from typing import Dict, List, Any
from enum import Enum

class PromptType(Enum):
    """Enumeration of different prompt types"""
    CYBERSECURITY_ANALYSIS = "cybersecurity_analysis"
    MALWARE_ANALYSIS = "malware_analysis"
    NETWORK_ANALYSIS = "network_analysis"
    LINK_ANALYSIS = "link_analysis"
    GENERAL_QUERY = "general_query"
    THREAT_INTELLIGENCE = "threat_intelligence"

class PromptTemplates:
    """Manages prompt templates for different use cases"""
    
    def __init__(self):
        self.templates = self._initialize_templates()
    
    def _initialize_templates(self) -> Dict[PromptType, str]:
        """Initialize all prompt templates"""
        return {
            PromptType.CYBERSECURITY_ANALYSIS: """
You are a cybersecurity expert AI assistant. Analyze the following data and provide insights:

Data: {data}

Please provide:
1. Risk assessment
2. Potential threats identified
3. Recommended actions
4. Security implications

Response:
""",
            
            PromptType.MALWARE_ANALYSIS: """
You are a malware analysis expert. Analyze the following malware sample information:

Sample Data: {data}

Please provide:
1. Malware type and family
2. Behavior analysis
3. Indicators of Compromise (IOCs)
4. Mitigation strategies
5. Detection recommendations

Response:
""",
            
            PromptType.NETWORK_ANALYSIS: """
You are a network security analyst. Analyze the following network traffic data:

Network Data: {data}

Please provide:
1. Traffic pattern analysis
2. Suspicious activities detected
3. Network anomalies
4. Security recommendations
5. Monitoring suggestions

Response:
""",
            
            PromptType.LINK_ANALYSIS: """
You are a web security expert. Analyze the following URL/link information:

Link Data: {data}

Please provide:
1. URL safety assessment
2. Potential threats
3. Reputation analysis
4. Security recommendations
5. Risk level (Low/Medium/High)

Response:
""",
            
            PromptType.THREAT_INTELLIGENCE: """
You are a threat intelligence analyst. Analyze the following threat data:

Threat Data: {data}

Please provide:
1. Threat actor identification
2. Attack vector analysis
3. Tactics, Techniques, and Procedures (TTPs)
4. Intelligence recommendations
5. Countermeasures

Response:
""",
            
            PromptType.GENERAL_QUERY: """
You are a helpful cybersecurity AI assistant. Please answer the following question:

Question: {data}

Provide a clear, accurate, and helpful response with relevant cybersecurity context when applicable.

Response:
"""
        }
    
    def get_template(self, prompt_type: PromptType) -> str:
        """
        Get a specific prompt template
        
        Args:
            prompt_type: Type of prompt template to retrieve
            
        Returns:
            Prompt template string
        """
        return self.templates.get(prompt_type, self.templates[PromptType.GENERAL_QUERY])
    
    def format_prompt(self, prompt_type: PromptType, data: Any, 
                     additional_context: str = "") -> str:
        """
        Format a prompt template with data
        
        Args:
            prompt_type: Type of prompt to format
            data: Data to include in the prompt
            additional_context: Additional context to append
            
        Returns:
            Formatted prompt string
        """
        template = self.get_template(prompt_type)
        
        # Convert data to string if it's not already
        if isinstance(data, (dict, list)):
            import json
            data_str = json.dumps(data, indent=2)
        else:
            data_str = str(data)
        
        # Format the template
        formatted_prompt = template.format(data=data_str)
        
        # Add additional context if provided
        if additional_context:
            formatted_prompt += f"\n\nAdditional Context: {additional_context}"
        
        return formatted_prompt
    
    def get_available_templates(self) -> List[str]:
        """
        Get list of available template types
        
        Returns:
            List of available prompt type names
        """
        return [template.value for template in PromptType]
    
    def create_custom_prompt(self, system_message: str, user_input: str, 
                           context: str = "") -> str:
        """
        Create a custom prompt with system message and user input
        
        Args:
            system_message: System message defining the AI's role
            user_input: User's input/question
            context: Additional context information
            
        Returns:
            Formatted custom prompt
        """
        prompt = f"{system_message}\n\n"
        
        if context:
            prompt += f"Context: {context}\n\n"
        
        prompt += f"User Input: {user_input}\n\nResponse:"
        
        return prompt

# Global prompt templates instance
prompt_templates = PromptTemplates()

def get_prompt_templates() -> PromptTemplates:
    """Get the global prompt templates instance"""
    return prompt_templates


