# CyAi Dashboard API Endpoints Guide

## Overview

The CyAi Dashboard now implements the exact endpoint specifications with Gemini-1.5-Pro integration for AI explanations and analysis.

## Environment Setup

### Required Environment Variables

Create a `.env` file in the backend directory:

```bash
# Gemini API Configuration
GEMINI_API_KEY=your_gemini_api_key_here

# Backend Configuration
BACKEND_HOST=0.0.0.0
BACKEND_PORT=8000
DEBUG=True

# Model Configuration
LOG_LEVEL=INFO
MAX_FILE_SIZE=50MB
MAX_BATCH_SIZE=100
```

### Installation

```bash
cd backend
pip install -r requirements.txt
```

## API Endpoints

### 1. `/analyze-logs` - Log Analysis

**Purpose**: Accepts raw logs → runs `log_classifier` → returns classification + metadata

**Method**: `POST`

**Request Body**:
```json
{
  "logs": [
    "2024-01-15 10:30:45 192.168.1.100 -> 10.0.0.1 TCP Connection established",
    "2024-01-15 10:31:00 192.168.1.101 -> 8.8.8.8 DNS Query"
  ],
  "log_type": "network"
}
```

**Response**:
```json
[
  {
    "classification": "Normal|Suspicious|Malicious",
    "confidence": 0.85,
    "threat_level": "Low|Medium|High|Critical",
    "explanation": "AI-generated explanation from Gemini",
    "recommended_action": "Specific recommended actions",
    "metadata": {
      "log_type": "network",
      "labels": ["normal_operation"],
      "analysis_details": {...},
      "confidence_interpretation": "What the confidence level means"
    }
  }
]
```

**Example Usage**:
```python
import requests

response = requests.post("http://localhost:8000/analyze-logs", json={
    "logs": ["2024-01-15 10:30:45 192.168.1.100 -> 10.0.0.1 TCP Connection established"],
    "log_type": "network"
})

results = response.json()
for result in results:
    print(f"Classification: {result['classification']}")
    print(f"Confidence: {result['confidence']:.2%}")
    print(f"Explanation: {result['explanation']}")
```

### 2. `/analyze-url` - URL Analysis

**Purpose**: Accepts URL → runs `phishing_detector` → returns risk level + details

**Method**: `POST`

**Request Body**:
```json
{
  "url": "https://example.com",
  "include_analysis": true
}
```

**Response**:
```json
{
  "classification": "Safe|Suspicious|Malicious",
  "confidence": 0.92,
  "threat_level": "Low|Medium|High|Critical",
  "risk_score": 0.15,
  "explanation": "AI-generated explanation from Gemini",
  "recommended_action": "Specific recommended actions",
  "details": {
    "analysis_details": {...},
    "recommendations": [...],
    "url_analysis": {...}
  }
}
```

**Example Usage**:
```python
import requests

response = requests.post("http://localhost:8000/analyze-url", json={
    "url": "https://suspicious-site.com",
    "include_analysis": True
})

result = response.json()
print(f"Classification: {result['classification']}")
print(f"Risk Score: {result['risk_score']}")
print(f"Explanation: {result['explanation']}")
```

### 3. `/analyze-file` - File Analysis

**Purpose**: Accepts uploaded file → runs `malware_detector` → returns classification + malware family if found

**Method**: `POST`

**Request**: `multipart/form-data`

**Form Data**:
- `file`: Uploaded file
- `scan_type`: "quick" | "deep" | "full" (default: "quick")
- `include_family_detection`: boolean (default: true)

**Response**:
```json
{
  "classification": "Safe|Malicious",
  "confidence": 0.88,
  "threat_level": "Low|Medium|High|Critical",
  "malware_family": "Trojan|Virus|Worm|...",
  "explanation": "AI-generated explanation from Gemini",
  "recommended_action": "Specific recommended actions",
  "file_info": {
    "file_name": "suspicious.exe",
    "file_size": 1024000,
    "scan_type": "quick",
    "analysis_details": {...},
    "recommendations": [...]
  }
}
```

**Example Usage**:
```python
import requests

with open("suspicious_file.exe", "rb") as f:
    files = {"file": ("suspicious_file.exe", f, "application/octet-stream")}
    data = {
        "scan_type": "quick",
        "include_family_detection": True
    }
    
    response = requests.post("http://localhost:8000/analyze-file", 
                           files=files, data=data)

result = response.json()
print(f"Classification: {result['classification']}")
print(f"Malware Family: {result.get('malware_family', 'None')}")
print(f"Explanation: {result['explanation']}")
```

### 4. `/ai-assistant` - AI Assistant

**Purpose**: Accepts text, model output, or logs → sends them to **Gemini-1.5-Pro** → returns detailed explanation, remediation steps, or threat intelligence context

**Method**: `POST`

**Request Body**:
```json
{
  "text": "What is DNS amplification attack?",
  "model_output": {
    "classification": "Malicious",
    "confidence": 0.95,
    "threat_level": "High"
  },
  "logs": ["suspicious_activity.log"],
  "analysis_type": "general|threat_intelligence"
}
```

**Response**:
```json
{
  "explanation": "Detailed AI-generated explanation",
  "threat_intelligence": {
    "threat_patterns": "Known patterns",
    "historical_context": "Historical information",
    "attack_vectors": "Potential attack methods",
    "threat_actors": "Related actors/campaigns",
    "industry_impact": "Industry-specific implications"
  },
  "remediation_steps": {
    "immediate_actions": "Urgent steps to take",
    "investigation_steps": "How to investigate further",
    "containment_measures": "How to contain the threat",
    "hardening_recommendations": "System hardening steps",
    "monitoring_improvements": "Detection improvements",
    "prevention_strategies": "Long-term prevention"
  },
  "recommended_action": "Specific recommended actions",
  "confidence": 0.90
}
```

**Example Usage**:
```python
import requests

# General AI assistant
response = requests.post("http://localhost:8000/ai-assistant", json={
    "text": "What is DNS amplification attack?",
    "analysis_type": "general"
})

result = response.json()
print(f"Explanation: {result['explanation']}")
print(f"Recommended Action: {result['recommended_action']}")

# Threat intelligence analysis
response = requests.post("http://localhost:8000/ai-assistant", json={
    "text": "Analyze this threat",
    "model_output": {
        "classification": "Malicious",
        "confidence": 0.95,
        "threat_level": "High"
    },
    "logs": ["suspicious_activity.log"],
    "analysis_type": "threat_intelligence"
})

result = response.json()
print(f"Threat Intelligence: {result.get('threat_intelligence')}")
print(f"Remediation Steps: {result.get('remediation_steps')}")
```

## Model Status Endpoints

### `/models/status`
Get status of all pre-trained models

### `/models/health`
Perform health check on all models

### `/models/info`
Get detailed information about all models

## Response Format Standards

All endpoints return JSON responses with the following standard fields:

- `classification`: The classification result
- `confidence`: Confidence score (0.0 to 1.0)
- `threat_level`: Threat level assessment
- `explanation`: AI-generated explanation from Gemini
- `recommended_action`: Specific recommended actions

## Error Handling

All endpoints include comprehensive error handling:

- **400 Bad Request**: Invalid input data
- **500 Internal Server Error**: Model or AI service errors
- **503 Service Unavailable**: Model or Gemini service unavailable

Error responses include detailed error messages:
```json
{
  "detail": "Detailed error message",
  "error_code": "SPECIFIC_ERROR_CODE"
}
```

## Gemini Integration

The system integrates with Google's Gemini-1.5-Pro API for:

1. **AI Explanations**: Detailed explanations of analysis results
2. **Threat Intelligence**: Context and historical information about threats
3. **Remediation Steps**: Specific steps to address detected threats
4. **General Cybersecurity Guidance**: Expert advice on security topics

### Gemini API Requirements

- Valid `GEMINI_API_KEY` in environment variables
- Internet connection for API calls
- Proper error handling for API failures

## Testing

Use the provided test script to verify all endpoints:

```bash
python test_new_endpoints.py
```

The test script will:
1. Test all four main endpoints
2. Verify response formats
3. Check Gemini integration
4. Validate error handling

## Frontend Integration

The frontend pages have been updated to work with the new endpoint structure:

- **Network Analysis**: Uses `/analyze-logs` endpoint
- **Malware Analysis**: Uses `/analyze-file` endpoint  
- **Link Checker**: Uses `/analyze-url` endpoint
- **AI Assistant**: Uses `/ai-assistant` endpoint

## Security Considerations

- All file uploads are validated and size-limited
- Input sanitization for all text inputs
- Rate limiting ready for implementation
- Comprehensive logging for audit trails
- Secure handling of API keys

## Performance

- Async endpoints for better performance
- Batch processing support for multiple items
- Efficient model loading and caching
- Optimized Gemini API usage

## Monitoring

- Health check endpoints for all models
- Detailed logging for troubleshooting
- Performance metrics collection
- Error tracking and reporting

---

**Note**: This API structure provides a clean, modular interface for cybersecurity analysis with AI-powered explanations and recommendations.
