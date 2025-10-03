# CyAi Dashboard Frontend Guide

## Overview

The CyAi Dashboard frontend is a Streamlit-based web application with a dark-themed UI that provides four main analysis tools for cybersecurity analysis with AI-powered explanations.

## Features

### 🎨 Dark Theme UI
- **Professional dark theme** with cybersecurity-focused color scheme
- **Status indicators** with color-coded classifications (Safe/Suspicious/Malicious)
- **Responsive design** that works on desktop and mobile devices
- **Modern card-based layout** with proper spacing and typography

### 📊 Analysis Tools

#### 1. **📊 Log Analyzer**
- **Purpose**: Paste logs to get classification results with AI explanations
- **Input**: Multi-line log entries with log type selection
- **Output**: 
  - Status indicator (Safe/Suspicious/Malicious)
  - Model output with classification, confidence, and threat level
  - AI explanation of the classification
  - Recommended actions
- **Features**:
  - Supports network, system, and application logs
  - Batch processing of multiple log entries
  - Expandable results for detailed analysis

#### 2. **🔗 URL Checker**
- **Purpose**: Check URLs for phishing risk with AI explanations
- **Input**: Single URL with optional detailed analysis
- **Output**:
  - Status indicator (Safe/Suspicious/Malicious)
  - Model output with classification, confidence, risk score, and threat level
  - AI explanation of the URL analysis
  - Recommended actions
  - Additional details in expandable section
- **Features**:
  - Real-time URL analysis
  - Risk scoring (0.0 to 1.0)
  - Detailed analysis options

#### 3. **🦠 File Scanner**
- **Purpose**: Upload files to scan for malware with AI explanations
- **Input**: File upload with scan type and family detection options
- **Output**:
  - Status indicator (Safe/Suspicious/Malicious)
  - Model output with classification, confidence, threat level, and malware family
  - AI explanation of the file analysis
  - Recommended actions
  - File analysis details in expandable section
- **Features**:
  - Support for multiple file types (exe, pdf, doc, zip, etc.)
  - Multiple scan types (quick, deep, full)
  - Malware family detection
  - File metadata display

#### 4. **🤖 AI Assistant**
- **Purpose**: Chat interface for cybersecurity questions and analysis
- **Input**: Natural language questions about cybersecurity topics
- **Output**:
  - AI-generated explanations and analysis
  - Recommended actions
  - Additional information (threat intelligence, remediation steps)
- **Features**:
  - Conversational chat interface
  - Chat history management
  - Context-aware responses
  - Expert cybersecurity knowledge

## UI Components

### Status Indicators
- **🟢 Safe**: Green background with black text
- **🟡 Suspicious**: Orange background with black text  
- **🔴 Malicious**: Red background with white text

### Information Cards
- **📊 Model Output**: Green left border, displays raw model results
- **🤖 AI Explanation**: Blue left border, displays AI-generated explanations
- **📋 Recommended Action**: Info box with actionable recommendations

### Navigation
- **Sidebar Navigation**: Easy switching between analysis tools
- **Backend Status**: Real-time connection status indicator
- **Quick Stats**: Metrics display for analysis counts

## Technical Implementation

### Frontend Architecture
```
frontend/
├── app.py                 # Main Streamlit application
├── requirements.txt       # Python dependencies
└── pages/                 # (Removed - consolidated into app.py)
```

### Key Technologies
- **Streamlit**: Web application framework
- **Requests**: HTTP client for backend communication
- **Custom CSS**: Dark theme styling and component design
- **JSON**: Data exchange format with backend

### Backend Integration
- **RESTful API**: Communication with FastAPI backend
- **Real-time Status**: Backend connection monitoring
- **Error Handling**: Graceful error display and user feedback
- **Async Support**: Non-blocking UI during analysis

## API Endpoints Used

### Log Analysis
```python
POST /analyze-logs
{
    "logs": ["log_entry_1", "log_entry_2"],
    "log_type": "network"
}
```

### URL Analysis
```python
POST /analyze-url
{
    "url": "https://example.com",
    "include_analysis": true
}
```

### File Analysis
```python
POST /analyze-file
Content-Type: multipart/form-data
{
    "file": <uploaded_file>,
    "scan_type": "quick",
    "include_family_detection": true
}
```

### AI Assistant
```python
POST /ai-assistant
{
    "text": "user_question",
    "model_output": null,
    "logs": null,
    "analysis_type": "general"
}
```

## Response Format

### Standard Response Structure
All analysis endpoints return responses with:
- `classification`: Safe/Suspicious/Malicious
- `confidence`: Confidence score (0.0 to 1.0)
- `threat_level`: Low/Medium/High/Critical
- `explanation`: AI-generated explanation
- `recommended_action`: Specific recommended actions

### Additional Fields by Analysis Type

#### Log Analysis
- `metadata`: Additional log analysis details
- `labels`: Detected labels and categories

#### URL Analysis
- `risk_score`: Risk score (0.0 to 1.0)
- `details`: Additional URL analysis information

#### File Analysis
- `malware_family`: Detected malware family
- `file_info`: File metadata and analysis details

#### AI Assistant
- `threat_intelligence`: Threat intelligence context
- `remediation_steps`: Detailed remediation steps

## Styling and Theme

### Color Scheme
- **Background**: Dark (#0e1117)
- **Cards**: Dark gray (#1e1e1e, #2d2d2d)
- **Borders**: Medium gray (#333333, #555555)
- **Text**: White (#ffffff)
- **Accents**: Blue (#2196F3), Green (#4CAF50)

### Component Styling
- **Status Indicators**: Rounded badges with appropriate colors
- **Information Cards**: Left-bordered cards with distinct colors
- **Buttons**: Green theme with hover effects
- **Inputs**: Dark theme with proper contrast
- **Headers**: Gradient backgrounds for visual appeal

## Error Handling

### Backend Connection
- **Connection Status**: Real-time backend status in sidebar
- **Timeout Handling**: Graceful timeout handling for API calls
- **Error Display**: User-friendly error messages

### Input Validation
- **Required Fields**: Validation for required inputs
- **File Types**: Support for common file types
- **URL Format**: Basic URL format validation

### API Error Handling
- **HTTP Errors**: Proper error code handling
- **JSON Parsing**: Safe JSON parsing with fallbacks
- **Network Issues**: Offline detection and user notification

## Performance Optimization

### Frontend Performance
- **Lazy Loading**: Components loaded as needed
- **Caching**: Chat history and session state management
- **Efficient Updates**: Minimal re-rendering with Streamlit

### Backend Communication
- **Async Requests**: Non-blocking API calls
- **Timeout Management**: Reasonable timeouts for different operations
- **Error Recovery**: Graceful degradation on API failures

## Security Considerations

### Input Sanitization
- **File Uploads**: Secure file handling
- **URL Validation**: Basic URL format validation
- **Text Input**: Safe text input handling

### Data Privacy
- **No Data Storage**: No persistent storage of sensitive data
- **Session Management**: Secure session state handling
- **API Security**: Secure communication with backend

## Testing

### Test Coverage
- **Backend Integration**: API endpoint testing
- **UI Components**: Component functionality testing
- **Response Format**: Data format compatibility testing
- **Error Handling**: Error scenario testing

### Test Script
```bash
python test_frontend.py
```

The test script covers:
- Backend endpoint functionality
- Frontend structure verification
- Response format compatibility
- UI component presence
- Dark theme implementation

## Deployment

### Local Development
```bash
# Install dependencies
cd frontend
pip install -r requirements.txt

# Start frontend
streamlit run app.py

# Access at http://localhost:8501
```

### Production Deployment
- **Streamlit Cloud**: Easy deployment to Streamlit Cloud
- **Docker**: Containerized deployment option
- **Custom Server**: Deploy on custom infrastructure

## Browser Compatibility

### Supported Browsers
- **Chrome**: Full support
- **Firefox**: Full support
- **Safari**: Full support
- **Edge**: Full support

### Mobile Support
- **Responsive Design**: Works on mobile devices
- **Touch Interface**: Touch-friendly controls
- **Mobile Navigation**: Optimized for mobile screens

## Future Enhancements

### Planned Features
- **Real-time Updates**: WebSocket integration for real-time analysis
- **Advanced Visualizations**: Charts and graphs for analysis results
- **Export Functionality**: Export analysis results to various formats
- **User Authentication**: User accounts and analysis history
- **Custom Themes**: Multiple theme options
- **Offline Mode**: Basic offline functionality

### Integration Opportunities
- **SIEM Integration**: Export to security information systems
- **Threat Intelligence**: Integration with threat intelligence feeds
- **Incident Response**: Integration with incident response workflows
- **Reporting**: Automated report generation

---

**Note**: The frontend provides a professional, user-friendly interface for cybersecurity analysis with AI-powered explanations. The dark theme and status indicators make it easy to quickly identify threats and understand analysis results.
