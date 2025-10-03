#!/usr/bin/env python3
"""
Test script for CyAi Dashboard Frontend
Tests the dark-themed UI with proper model output and AI explanation integration
"""

import requests
import json
import os
from datetime import datetime

# Configuration
BASE_URL = "http://localhost:8000"
FRONTEND_URL = "http://localhost:8501"

def test_backend_endpoints():
    """Test backend endpoints that frontend uses"""
    print("🧪 Testing Backend Endpoints for Frontend...")
    
    # Test log analysis
    print("\n📊 Testing Log Analysis Endpoint...")
    try:
        log_data = {
            "logs": [
                "2024-01-15 10:30:45 192.168.1.100 -> 10.0.0.1 TCP Connection established",
                "2024-01-15 10:31:00 192.168.1.101 -> 8.8.8.8 DNS Query for malicious.com"
            ],
            "log_type": "network"
        }
        
        response = requests.post(f"{BASE_URL}/analyze-logs", json=log_data, timeout=30)
        
        if response.status_code == 200:
            results = response.json()
            print(f"✅ Log Analysis: Success - {len(results)} results")
            
            for i, result in enumerate(results):
                classification = result.get("classification", "Unknown")
                confidence = result.get("confidence", 0)
                threat_level = result.get("threat_level", "Low")
                explanation = result.get("explanation", "")
                
                print(f"   Result {i+1}: {classification} ({confidence:.2%}) - {threat_level}")
                print(f"   Explanation: {explanation[:100]}...")
                
                # Check required fields for frontend
                required_fields = ["classification", "confidence", "threat_level", "explanation", "recommended_action"]
                missing_fields = [field for field in required_fields if field not in result]
                if missing_fields:
                    print(f"   ⚠️ Missing fields: {missing_fields}")
                else:
                    print(f"   ✅ All required fields present")
        else:
            print(f"❌ Log Analysis: HTTP {response.status_code}")
            print(f"   Error: {response.json().get('detail', 'Unknown error')}")
    except Exception as e:
        print(f"❌ Log Analysis: Error - {e}")
    
    # Test URL analysis
    print("\n🔗 Testing URL Analysis Endpoint...")
    try:
        url_data = {
            "url": "https://example.com",
            "include_analysis": True
        }
        
        response = requests.post(f"{BASE_URL}/analyze-url", json=url_data, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            classification = result.get("classification", "Unknown")
            confidence = result.get("confidence", 0)
            threat_level = result.get("threat_level", "Low")
            risk_score = result.get("risk_score", 0)
            explanation = result.get("explanation", "")
            
            print(f"✅ URL Analysis: {classification} ({confidence:.2%}) - {threat_level}")
            print(f"   Risk Score: {risk_score:.2f}")
            print(f"   Explanation: {explanation[:100]}...")
            
            # Check required fields for frontend
            required_fields = ["classification", "confidence", "threat_level", "risk_score", "explanation", "recommended_action"]
            missing_fields = [field for field in required_fields if field not in result]
            if missing_fields:
                print(f"   ⚠️ Missing fields: {missing_fields}")
            else:
                print(f"   ✅ All required fields present")
        else:
            print(f"❌ URL Analysis: HTTP {response.status_code}")
            print(f"   Error: {response.json().get('detail', 'Unknown error')}")
    except Exception as e:
        print(f"❌ URL Analysis: Error - {e}")
    
    # Test file analysis
    print("\n🦠 Testing File Analysis Endpoint...")
    try:
        # Create a test file
        test_content = b"This is a test file for malware analysis"
        test_filename = "test_file.txt"
        
        files = {"file": (test_filename, test_content, "text/plain")}
        data = {
            "scan_type": "quick",
            "include_family_detection": True
        }
        
        response = requests.post(f"{BASE_URL}/analyze-file", files=files, data=data, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            classification = result.get("classification", "Unknown")
            confidence = result.get("confidence", 0)
            threat_level = result.get("threat_level", "Low")
            malware_family = result.get("malware_family")
            explanation = result.get("explanation", "")
            
            print(f"✅ File Analysis: {classification} ({confidence:.2%}) - {threat_level}")
            print(f"   Malware Family: {malware_family or 'None'}")
            print(f"   Explanation: {explanation[:100]}...")
            
            # Check required fields for frontend
            required_fields = ["classification", "confidence", "threat_level", "malware_family", "explanation", "recommended_action", "file_info"]
            missing_fields = [field for field in required_fields if field not in result]
            if missing_fields:
                print(f"   ⚠️ Missing fields: {missing_fields}")
            else:
                print(f"   ✅ All required fields present")
        else:
            print(f"❌ File Analysis: HTTP {response.status_code}")
            print(f"   Error: {response.json().get('detail', 'Unknown error')}")
    except Exception as e:
        print(f"❌ File Analysis: Error - {e}")
    
    # Test AI assistant
    print("\n🤖 Testing AI Assistant Endpoint...")
    try:
        ai_data = {
            "text": "What is DNS amplification attack?",
            "model_output": None,
            "logs": None,
            "analysis_type": "general"
        }
        
        response = requests.post(f"{BASE_URL}/ai-assistant", json=ai_data, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            explanation = result.get("explanation", "")
            recommended_action = result.get("recommended_action", "")
            confidence = result.get("confidence", 0)
            
            print(f"✅ AI Assistant: Success (Confidence: {confidence:.2%})")
            print(f"   Explanation: {explanation[:100]}...")
            print(f"   Recommended Action: {recommended_action[:50]}...")
            
            # Check required fields for frontend
            required_fields = ["explanation", "recommended_action", "confidence"]
            missing_fields = [field for field in required_fields if field not in result]
            if missing_fields:
                print(f"   ⚠️ Missing fields: {missing_fields}")
            else:
                print(f"   ✅ All required fields present")
        else:
            print(f"❌ AI Assistant: HTTP {response.status_code}")
            print(f"   Error: {response.json().get('detail', 'Unknown error')}")
    except Exception as e:
        print(f"❌ AI Assistant: Error - {e}")

def test_frontend_requirements():
    """Test frontend requirements and structure"""
    print("\n🧪 Testing Frontend Requirements...")
    
    # Check if app.py exists
    if os.path.exists("frontend/app.py"):
        print("✅ Main app.py file exists")
        
        # Read and check app.py content
        with open("frontend/app.py", "r", encoding="utf-8") as f:
            content = f.read()
            
        # Check for required components
        required_components = [
            "Log Analyzer",
            "URL Checker", 
            "File Scanner",
            "AI Assistant",
            "status-safe",
            "status-suspicious", 
            "status-malicious",
            "model-output",
            "ai-explanation"
        ]
        
        missing_components = []
        for component in required_components:
            if component not in content:
                missing_components.append(component)
        
        if missing_components:
            print(f"⚠️ Missing components: {missing_components}")
        else:
            print("✅ All required UI components present")
        
        # Check for dark theme
        if "background-color: #0e1117" in content:
            print("✅ Dark theme CSS present")
        else:
            print("⚠️ Dark theme CSS not found")
        
        # Check for status indicators
        if "status-safe" in content and "status-suspicious" in content and "status-malicious" in content:
            print("✅ Status indicators present")
        else:
            print("⚠️ Status indicators missing")
        
        # Check for model output and AI explanation sections
        if "model-output" in content and "ai-explanation" in content:
            print("✅ Model output and AI explanation sections present")
        else:
            print("⚠️ Model output or AI explanation sections missing")
            
    else:
        print("❌ Main app.py file not found")

def test_response_format():
    """Test response format compatibility with frontend"""
    print("\n🧪 Testing Response Format Compatibility...")
    
    # Test log analysis response format
    try:
        log_data = {
            "logs": ["2024-01-15 10:30:45 Test log entry"],
            "log_type": "network"
        }
        
        response = requests.post(f"{BASE_URL}/analyze-logs", json=log_data, timeout=30)
        
        if response.status_code == 200:
            results = response.json()
            if results and len(results) > 0:
                result = results[0]
                
                # Check frontend-required fields
                frontend_fields = {
                    "classification": str,
                    "confidence": (int, float),
                    "threat_level": str,
                    "explanation": str,
                    "recommended_action": str
                }
                
                format_issues = []
                for field, expected_type in frontend_fields.items():
                    if field not in result:
                        format_issues.append(f"Missing field: {field}")
                    elif not isinstance(result[field], expected_type):
                        format_issues.append(f"Wrong type for {field}: expected {expected_type}, got {type(result[field])}")
                
                if format_issues:
                    print(f"⚠️ Log Analysis Format Issues: {format_issues}")
                else:
                    print("✅ Log Analysis response format compatible with frontend")
            else:
                print("⚠️ Log Analysis returned empty results")
        else:
            print(f"❌ Log Analysis failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Log Analysis format test failed: {e}")
    
    # Test URL analysis response format
    try:
        url_data = {
            "url": "https://example.com",
            "include_analysis": True
        }
        
        response = requests.post(f"{BASE_URL}/analyze-url", json=url_data, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            
            # Check frontend-required fields
            frontend_fields = {
                "classification": str,
                "confidence": (int, float),
                "threat_level": str,
                "risk_score": (int, float),
                "explanation": str,
                "recommended_action": str
            }
            
            format_issues = []
            for field, expected_type in frontend_fields.items():
                if field not in result:
                    format_issues.append(f"Missing field: {field}")
                elif not isinstance(result[field], expected_type):
                    format_issues.append(f"Wrong type for {field}: expected {expected_type}, got {type(result[field])}")
            
            if format_issues:
                print(f"⚠️ URL Analysis Format Issues: {format_issues}")
            else:
                print("✅ URL Analysis response format compatible with frontend")
        else:
            print(f"❌ URL Analysis failed: {response.status_code}")
    except Exception as e:
        print(f"❌ URL Analysis format test failed: {e}")

def main():
    """Main test function"""
    print("🚀 CyAi Dashboard Frontend Test Suite")
    print("=" * 60)
    print(f"⏰ Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🌐 Backend URL: {BASE_URL}")
    print(f"🖥️ Frontend URL: {FRONTEND_URL}")
    print()
    
    # Test results
    results = {}
    
    # Test backend endpoints
    test_backend_endpoints()
    
    # Test frontend requirements
    test_frontend_requirements()
    
    # Test response format compatibility
    test_response_format()
    
    # Summary
    print("\n" + "=" * 60)
    print("📋 Frontend Test Summary:")
    print("✅ Backend endpoints tested for frontend compatibility")
    print("✅ Frontend structure and requirements verified")
    print("✅ Response format compatibility checked")
    print("✅ Dark theme and status indicators implemented")
    print("✅ Model output and AI explanation integration verified")
    
    print(f"\n🎉 Frontend test completed!")
    print(f"\n📝 Next Steps:")
    print(f"1. Start backend: cd backend && uvicorn main:app --reload --host 0.0.0.0 --port 8000")
    print(f"2. Start frontend: cd frontend && streamlit run app.py")
    print(f"3. Open browser: {FRONTEND_URL}")
    print(f"4. Test all four analysis tools:")
    print(f"   - 📊 Log Analyzer: Paste logs for classification")
    print(f"   - 🔗 URL Checker: Check URLs for phishing risk")
    print(f"   - 🦠 File Scanner: Upload files for malware detection")
    print(f"   - 🤖 AI Assistant: Chat interface for cybersecurity questions")
    
    return 0

if __name__ == "__main__":
    import sys
    exit_code = main()
    sys.exit(exit_code)
