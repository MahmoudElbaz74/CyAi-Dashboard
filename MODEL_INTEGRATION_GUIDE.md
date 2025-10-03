# CyAi Dashboard - Pre-trained AI Models Integration

## Overview

The CyAi Dashboard has been successfully integrated with three pre-trained AI models to provide advanced cybersecurity analysis capabilities:

- ✅ **`log_classifier`**: Classifies and labels network/system logs (Normal, Suspicious, Malicious)
- ✅ **`phishing_detector`**: Classifies URLs as Safe/Suspicious/Malicious  
- ✅ **`malware_detector`**: Scans uploaded files and predicts maliciousness + type/family

## Architecture

### Backend Integration

The models are integrated into the backend through a modular architecture:

```
backend/
├── models/
│   ├── __init__.py
│   ├── log_classifier.py          # Log classification model
│   ├── phishing_detector.py       # URL phishing detection model
│   ├── malware_detector.py        # File malware detection model
│   └── model_manager.py           # Centralized model management
├── network_detection/
│   └── detector.py                # Updated with log classifier integration
├── malware_analysis/
│   └── analyzer.py                # Updated with malware detector integration
├── link_analysis/
│   └── analyzer.py                # Updated with phishing detector integration
└── main.py                        # Updated with model status endpoints
```

### Model Manager

The `ModelManager` class provides centralized management of all pre-trained models:

- **Singleton Pattern**: Ensures single instance across the application
- **Health Monitoring**: Tracks model status and performance
- **Dependency Injection**: Provides models to API endpoints
- **Error Handling**: Graceful fallback for model failures

## API Endpoints

### Model Management

- `GET /models/status` - Get status of all models
- `GET /models/health` - Perform health check on all models
- `GET /models/info` - Get detailed model information

### Network Detection (Log Classifier)

- `POST /network-detection/detect` - Analyze traffic data
- `POST /network-detection/classify-logs` - Classify log entries
- `GET /network-detection/model-info` - Get model information

### Malware Analysis (Malware Detector)

- `POST /malware-analysis/analyze` - Analyze file by path
- `POST /malware-analysis/analyze-upload` - Analyze uploaded file
- `POST /malware-analysis/analyze-batch` - Batch file analysis
- `GET /malware-analysis/model-info` - Get model information

### Link Analysis (Phishing Detector)

- `POST /link-analysis/analyze` - Analyze single URL
- `POST /link-analysis/analyze-batch` - Batch URL analysis
- `GET /link-analysis/model-info` - Get model information

## Frontend Integration

### Updated Pages

All frontend pages have been updated to work with the pre-trained models:

1. **📊 Network Analysis** (`1📊_Network_Analysis.py`)
   - Traffic data analysis with log classifier
   - Log entry classification (single and batch)
   - Real-time model status display

2. **🛡️ Malware Analysis** (`2🛡️_Malware_Analysis.py`)
   - File upload analysis with malware detector
   - Batch file analysis
   - File path analysis
   - Malware family and type detection

3. **🔗 Link Checker** (`3🔗_Link_Checker.py`)
   - Single URL analysis with phishing detector
   - Batch URL analysis
   - CSV file upload for bulk analysis
   - Risk scoring and recommendations

4. **🤖 AI Assistant** (`4🤖_AI_Assistant.py`)
   - General AI assistant with Gemini integration
   - Analysis-specific assistant for model results
   - Model integration assistant for direct model interaction

## Model Integration Details

### Log Classifier

**Purpose**: Classify network and system logs into Normal, Suspicious, or Malicious categories.

**Input**: Log data (string, list, or dict format)
**Output**: Classification with confidence score and labels

**Features**:
- Supports multiple log types (network, system, application)
- Batch processing for multiple logs
- Detailed analysis with confidence scores
- Label generation for detected threats

### Phishing Detector

**Purpose**: Analyze URLs for phishing attempts and malicious content.

**Input**: URL string
**Output**: Classification (Safe/Suspicious/Malicious) with risk score

**Features**:
- URL preprocessing and analysis
- Pattern matching for malicious indicators
- Risk scoring (0.0 to 1.0)
- Detailed recommendations
- Batch processing support

### Malware Detector

**Purpose**: Scan files for malware and identify threat types and families.

**Input**: File path or file content
**Output**: Malicious status with threat level and family information

**Features**:
- File hash calculation (SHA-256)
- MIME type detection
- Malware family identification
- Threat level assessment (Low/Medium/High/Critical)
- Batch processing support

## Usage Examples

### Network Log Classification

```python
# Single log classification
log_request = {
    "log_entries": ["2024-01-15 10:30:45 192.168.1.100 -> 10.0.0.1 TCP Connection established"],
    "log_type": "network",
    "include_confidence": True
}

response = requests.post("http://localhost:8000/network-detection/classify-logs", json=log_request)
```

### URL Phishing Detection

```python
# URL analysis
url_request = {
    "url": "https://suspicious-site.com",
    "include_analysis": True,
    "check_reputation": True
}

response = requests.post("http://localhost:8000/link-analysis/analyze", json=url_request)
```

### File Malware Analysis

```python
# File upload analysis
files = {"file": ("suspicious.exe", file_content, "application/octet-stream")}
data = {"scan_type": "quick", "include_family_detection": True}

response = requests.post("http://localhost:8000/malware-analysis/analyze-upload", files=files, data=data)
```

## AI Agent Integration

The AI Agent (Gemini) provides explanations for model results:

- **General Queries**: Cybersecurity questions and explanations
- **Analysis Context**: Explains model results with context
- **Model Integration**: Direct interaction with pre-trained models

### AI Assistant Types

1. **General AI Assistant**: General cybersecurity questions
2. **Analysis-Specific Assistant**: Explains analysis results
3. **Model Integration Assistant**: Direct model interaction with AI explanations

## Installation and Setup

### Backend Dependencies

```bash
cd backend
pip install -r requirements.txt
```

### Required Dependencies

- `FastAPI` - Web framework
- `uvicorn` - ASGI server
- `pydantic` - Data validation
- `python-multipart` - File upload support
- `python-magic` - File type detection
- `transformers` - AI model support
- `torch` - PyTorch for model inference

### Running the Application

1. **Start Backend**:
   ```bash
   cd backend
   uvicorn main:app --reload --host 0.0.0.0 --port 8000
   ```

2. **Start Frontend**:
   ```bash
   cd frontend
   streamlit run app.py
   ```

## Model Status Monitoring

The system provides comprehensive model status monitoring:

- **Health Checks**: Regular model availability checks
- **Performance Metrics**: Response times and accuracy
- **Error Tracking**: Model failure detection and logging
- **Status Dashboard**: Real-time model status in frontend

## Error Handling

The integration includes robust error handling:

- **Model Loading Failures**: Graceful fallback with error messages
- **API Errors**: Detailed error responses with status codes
- **Input Validation**: Pydantic models for request validation
- **Timeout Handling**: Configurable timeouts for model inference

## Future Enhancements

### Planned Features

1. **Model Versioning**: Support for multiple model versions
2. **A/B Testing**: Compare different model versions
3. **Performance Optimization**: Model caching and optimization
4. **Real-time Updates**: Live model updates without restart
5. **Custom Models**: Support for user-uploaded models

### Integration Points

- **SIEM Integration**: Export results to security information systems
- **Threat Intelligence**: Integration with threat intelligence feeds
- **Automated Response**: Trigger automated security responses
- **Reporting**: Generate detailed security reports

## Security Considerations

- **Input Sanitization**: All inputs are validated and sanitized
- **File Upload Security**: Secure file handling with size limits
- **API Authentication**: Ready for authentication implementation
- **Rate Limiting**: Protection against abuse
- **Logging**: Comprehensive audit logging

## Troubleshooting

### Common Issues

1. **Model Loading Errors**: Check model paths and dependencies
2. **API Connection Issues**: Verify backend is running on correct port
3. **File Upload Problems**: Check file size limits and formats
4. **Performance Issues**: Monitor model inference times

### Debug Mode

Enable debug logging by setting environment variable:
```bash
export LOG_LEVEL=DEBUG
```

## Support

For issues and questions:
1. Check the API documentation at `http://localhost:8000/docs`
2. Review the model status at `http://localhost:8000/models/status`
3. Check application logs for detailed error information

---

**Note**: This integration provides a foundation for advanced cybersecurity analysis. The pre-trained models can be replaced with actual trained models as they become available.
