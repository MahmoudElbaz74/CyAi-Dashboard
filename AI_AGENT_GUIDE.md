# AI Agent Module Guide

## Overview

The AI Agent module provides expert cybersecurity analysis capabilities using Gemini-1.5-Pro. It specializes in **explaining, reasoning, correlating, and summarizing** cybersecurity findings with MITRE ATT&CK framework integration.

## Core Capabilities

### 1. **Explain** - Why is this malicious?
- Provides detailed technical explanations of why logs, URLs, or files are classified as malicious
- Explains model confidence levels and reasoning
- Contextualizes findings within cybersecurity best practices

### 2. **Reason** - What does this mean?
- Correlates multiple data sources to identify attack patterns
- Maps behaviors to known threat actor techniques
- Provides threat intelligence context and attribution

### 3. **Correlate** - How do these findings relate?
- Cross-references logs, URLs, and file analysis results
- Identifies potential attack chains and coordinated activities
- Provides comprehensive threat landscape assessment

### 4. **Summarize** - What's the big picture?
- Synthesizes complex multi-source analysis into actionable insights
- Prioritizes findings by threat level and potential impact
- Provides executive-level summaries with technical details

## MITRE ATT&CK Integration

The AI Agent includes built-in MITRE ATT&CK technique mapping:

### Supported Techniques
- **T1071** - Application Layer Protocol
- **T1055** - Process Injection
- **T1027** - Obfuscated Files or Information
- **T1083** - File and Directory Discovery
- **T1049** - System Network Connections Discovery
- **T1016** - System Network Configuration Discovery
- **T1105** - Ingress Tool Transfer
- **T1059** - Command and Scripting Interpreter
- **T1070** - Indicator Removal
- **T1036** - Masquerading

### Tactical Mapping
- **Initial Access** - How attackers gain initial foothold
- **Execution** - Techniques for running malicious code
- **Persistence** - Methods to maintain access
- **Privilege Escalation** - Gaining higher-level permissions
- **Defense Evasion** - Avoiding detection
- **Credential Access** - Stealing account credentials
- **Discovery** - Learning about the environment
- **Lateral Movement** - Moving through the network
- **Collection** - Gathering data of interest
- **Command and Control** - Communicating with compromised systems
- **Exfiltration** - Stealing data
- **Impact** - Disrupting operations or data

## API Integration

### Main Function
```python
async def ask_ai_agent(prompt: str, context: Dict[str, Any]) -> str
```

**Parameters:**
- `prompt`: User question or analysis request
- `context`: Context data including model outputs, logs, and findings

**Returns:**
- Expert-level explanation and analysis

### Context Structure
```python
context = {
    "user_query": "Explain why this log is malicious",
    "model_outputs": {
        "classification": "Malicious",
        "confidence": 0.95,
        "threat_level": "High",
        "labels": ["malware_detected", "command_injection"]
    },
    "logs": ["2024-01-15 10:30:45 Command injection attempt detected"],
    "urls": [{"classification": "Suspicious", "confidence": 0.78}],
    "files": [{"classification": "Malicious", "malware_family": "Trojan"}],
    "analysis_type": "comprehensive_correlation"
}
```

## Analysis Types

### 1. **General Analysis**
- Basic cybersecurity questions and explanations
- General threat intelligence and best practices
- Security architecture guidance

### 2. **Log Analysis**
- Explains why specific logs are classified as malicious/suspicious
- Maps log events to MITRE ATT&CK techniques
- Provides incident response guidance

### 3. **URL Analysis**
- Explains URL classification reasoning
- Maps URL behaviors to attack patterns
- Provides phishing and malware distribution context

### 4. **File Analysis**
- Explains malware detection results
- Maps file behaviors to threat families
- Provides malware analysis context

### 5. **Network Correlation**
- Correlates network traffic patterns and anomalies
- Identifies potential command and control communications
- Maps network behaviors to MITRE ATT&CK techniques

### 6. **Threat Correlation**
- Correlates file and URL analysis results
- Identifies potential malware distribution chains
- Maps threat behaviors to MITRE ATT&CK techniques

### 7. **Comprehensive Correlation**
- Correlates all findings across logs, URLs, and files
- Identifies potential attack chains and patterns
- Provides complete threat landscape assessment

## Response Format

The AI Agent provides structured responses with:

### **Executive Summary**
- High-level overview of findings
- Key threats and risks identified
- Priority recommendations

### **Technical Analysis**
- Detailed technical explanation of findings
- Model reasoning and confidence interpretation
- Technical context and implications

### **MITRE ATT&CK Mapping**
- Specific technique mappings with IDs
- Tactical context and descriptions
- Attack chain analysis

### **Threat Assessment**
- Risk and impact assessment
- Threat actor attribution (if possible)
- Campaign context and indicators

### **Remediation Steps**
- Prioritized action items
- Immediate containment measures
- Long-term security improvements

### **Prevention Recommendations**
- Detection and monitoring improvements
- Security architecture enhancements
- Threat hunting strategies

### **Additional Context**
- Relevant threat intelligence
- Historical context and prevalence
- Industry-specific implications

## Usage Examples

### Example 1: Log Analysis Explanation
```python
context = {
    "user_query": "Explain why this log is classified as malicious",
    "model_outputs": {
        "classification": "Malicious",
        "confidence": 0.95,
        "threat_level": "High",
        "labels": ["command_injection", "privilege_escalation"]
    },
    "logs": ["2024-01-15 10:30:45 192.168.1.100 -> 10.0.0.1 TCP Command injection: ; cat /etc/passwd"],
    "analysis_type": "log_analysis"
}

response = await ask_ai_agent("Explain this malicious log", context)
```

**Expected Response:**
- Explanation of command injection techniques
- MITRE ATT&CK T1059 (Command and Scripting Interpreter) mapping
- Privilege escalation context
- Remediation steps for command injection attacks

### Example 2: Comprehensive Correlation
```python
context = {
    "user_query": "Analyze these findings and identify attack patterns",
    "model_outputs": {
        "logs": [
            {"classification": "Suspicious", "confidence": 0.85, "source_ip": "192.168.1.100"},
            {"classification": "Malicious", "confidence": 0.92, "destination_ip": "10.0.0.1"}
        ],
        "urls": [
            {"classification": "Suspicious", "confidence": 0.78, "url": "https://suspicious-site.com"}
        ],
        "files": [
            {"classification": "Malicious", "confidence": 0.95, "malware_family": "Trojan"}
        ]
    },
    "analysis_type": "comprehensive_correlation"
}

response = await ask_ai_agent("Correlate these findings", context)
```

**Expected Response:**
- Correlation analysis across all data sources
- Potential attack chain identification
- Multiple MITRE ATT&CK technique mappings
- Comprehensive threat assessment
- Prioritized remediation strategy

### Example 3: Threat Intelligence Context
```python
context = {
    "user_query": "Provide threat intelligence context for this malware",
    "model_outputs": {
        "classification": "Malicious",
        "confidence": 0.88,
        "malware_family": "Ransomware",
        "threat_level": "Critical"
    },
    "analysis_type": "threat_intelligence"
}

response = await ask_ai_agent("Analyze this ransomware threat", context)
```

**Expected Response:**
- Ransomware threat intelligence context
- Known threat actor attribution
- Campaign and infrastructure analysis
- Industry targeting patterns
- Historical context and prevalence

## Integration with Main API

The AI Agent is integrated into the main API through the `/ai-assistant` endpoint:

```python
POST /ai-assistant
{
    "text": "Explain why this log is malicious",
    "model_output": {
        "classification": "Malicious",
        "confidence": 0.95,
        "threat_level": "High"
    },
    "logs": ["suspicious_activity.log"],
    "analysis_type": "log_analysis"
}
```

## Error Handling

The AI Agent includes comprehensive error handling:

- **Gemini API Failures**: Graceful fallback with basic explanations
- **Context Parsing Errors**: Clear error messages and guidance
- **Timeout Handling**: Configurable timeouts for long analyses
- **Rate Limiting**: Built-in rate limiting for API calls

## Performance Optimization

- **Async Processing**: Non-blocking analysis for better performance
- **Context Caching**: Intelligent caching of analysis results
- **Batch Processing**: Support for multiple analysis requests
- **Response Streaming**: Large responses streamed for better UX

## Security Considerations

- **Input Sanitization**: All inputs validated and sanitized
- **API Key Security**: Secure handling of Gemini API keys
- **Response Filtering**: Sensitive information filtered from responses
- **Audit Logging**: Comprehensive logging for security analysis

## Testing

Use the provided test script to verify AI Agent capabilities:

```bash
python test_ai_agent.py
```

The test script covers:
- Explanation capabilities
- Correlation analysis
- MITRE ATT&CK mapping
- Remediation recommendations

## Future Enhancements

### Planned Features
- **Custom MITRE ATT&CK Techniques**: Support for custom technique definitions
- **Threat Actor Attribution**: Enhanced threat actor identification
- **Campaign Analysis**: Advanced campaign correlation and attribution
- **Industry-Specific Analysis**: Tailored analysis for different industries
- **Real-time Threat Intelligence**: Integration with live threat feeds

### Integration Points
- **SIEM Integration**: Export analysis results to security information systems
- **Threat Hunting**: Automated threat hunting based on AI Agent insights
- **Incident Response**: Integration with incident response workflows
- **Security Orchestration**: Integration with SOAR platforms

---

**Note**: The AI Agent provides expert-level cybersecurity analysis with deep technical knowledge and practical recommendations. It serves as a virtual cybersecurity expert for explaining, reasoning, correlating, and summarizing security findings.
