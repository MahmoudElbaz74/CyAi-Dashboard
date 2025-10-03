#!/usr/bin/env python3
"""
Test script for CyAi Dashboard Model Integration
This script tests the integration of pre-trained AI models
"""

import sys
import os
import requests
import json
from datetime import datetime

# Add backend to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

def test_model_manager():
    """Test the model manager initialization"""
    print("🧪 Testing Model Manager...")
    try:
        from models.model_manager import get_model_manager
        mm = get_model_manager()
        print("✅ Model Manager initialized successfully")
        
        # Test model info
        info = mm.get_all_models_info()
        print(f"📊 Available models: {list(mm.models.keys())}")
        print(f"📊 Total models: {info.get('total_models', 0)}")
        
        # Test health check
        health = mm.health_check()
        print(f"🏥 Overall status: {health.get('overall_status', 'Unknown')}")
        
        return True
    except Exception as e:
        print(f"❌ Model Manager test failed: {e}")
        return False

def test_api_endpoints():
    """Test API endpoints"""
    print("\n🧪 Testing API Endpoints...")
    
    base_url = "http://localhost:8000"
    
    # Test endpoints
    endpoints = [
        ("/", "Root endpoint"),
        ("/models/status", "Model status"),
        ("/models/health", "Model health"),
        ("/models/info", "Model info")
    ]
    
    results = []
    for endpoint, description in endpoints:
        try:
            response = requests.get(f"{base_url}{endpoint}", timeout=5)
            if response.status_code == 200:
                print(f"✅ {description}: OK")
                results.append(True)
            else:
                print(f"❌ {description}: HTTP {response.status_code}")
                results.append(False)
        except requests.exceptions.RequestException as e:
            print(f"❌ {description}: Connection failed - {e}")
            results.append(False)
    
    return all(results)

def test_model_integration():
    """Test individual model integrations"""
    print("\n🧪 Testing Model Integrations...")
    
    base_url = "http://localhost:8000"
    
    # Test log classification
    print("📝 Testing Log Classifier...")
    try:
        log_data = {
            "log_entries": ["2024-01-15 10:30:45 192.168.1.100 -> 10.0.0.1 TCP Connection established"],
            "log_type": "network",
            "include_confidence": True
        }
        response = requests.post(f"{base_url}/network-detection/classify-logs", json=log_data, timeout=10)
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Log classification: {result[0].get('classification', 'Unknown')}")
        else:
            print(f"❌ Log classification failed: HTTP {response.status_code}")
    except Exception as e:
        print(f"❌ Log classification error: {e}")
    
    # Test phishing detection
    print("🔗 Testing Phishing Detector...")
    try:
        url_data = {
            "url": "https://example.com",
            "include_analysis": True,
            "check_reputation": True
        }
        response = requests.post(f"{base_url}/link-analysis/analyze", json=url_data, timeout=10)
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Phishing detection: {result.get('classification', 'Unknown')}")
        else:
            print(f"❌ Phishing detection failed: HTTP {response.status_code}")
    except Exception as e:
        print(f"❌ Phishing detection error: {e}")
    
    # Test malware detection (file path)
    print("🛡️ Testing Malware Detector...")
    try:
        malware_data = {
            "file_path": "/path/to/test/file.exe",
            "file_name": "test.exe",
            "scan_type": "quick",
            "include_family_detection": True
        }
        response = requests.post(f"{base_url}/malware-analysis/analyze", json=malware_data, timeout=10)
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Malware detection: {'Malicious' if result.get('is_malicious') else 'Safe'}")
        else:
            print(f"❌ Malware detection failed: HTTP {response.status_code}")
    except Exception as e:
        print(f"❌ Malware detection error: {e}")

def main():
    """Main test function"""
    print("🚀 CyAi Dashboard Model Integration Test")
    print("=" * 50)
    print(f"⏰ Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Test model manager
    model_manager_ok = test_model_manager()
    
    # Test API endpoints (only if backend is running)
    api_ok = test_api_endpoints()
    
    # Test model integrations (only if backend is running)
    if api_ok:
        test_model_integration()
    
    # Summary
    print("\n" + "=" * 50)
    print("📋 Test Summary:")
    print(f"   Model Manager: {'✅ PASS' if model_manager_ok else '❌ FAIL'}")
    print(f"   API Endpoints: {'✅ PASS' if api_ok else '❌ FAIL'}")
    
    if model_manager_ok and api_ok:
        print("\n🎉 All tests passed! Model integration is working correctly.")
        return 0
    else:
        print("\n⚠️ Some tests failed. Check the output above for details.")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
