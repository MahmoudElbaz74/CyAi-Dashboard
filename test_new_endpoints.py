#!/usr/bin/env python3
"""
Test script for CyAi Dashboard New Endpoints
Tests the exact endpoint specifications with Gemini integration
"""

import requests
import json
import os
from datetime import datetime

# Configuration
BASE_URL = "http://localhost:8000"
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', 'your_gemini_api_key_here')

def test_analyze_logs():
    """Test /analyze-logs endpoint"""
    print("🧪 Testing /analyze-logs endpoint...")
    
    test_data = {
        "logs": [
            "2024-01-15 10:30:45 192.168.1.100 -> 10.0.0.1 TCP Connection established",
            "2024-01-15 10:31:00 192.168.1.101 -> 8.8.8.8 DNS Query for malicious.com",
            "2024-01-15 10:31:15 192.168.1.102 -> 10.0.0.1 HTTP GET /suspicious"
        ],
        "log_type": "network"
    }
    
    try:
        response = requests.post(f"{BASE_URL}/analyze-logs", json=test_data, timeout=30)
        
        if response.status_code == 200:
            results = response.json()
            print(f"✅ /analyze-logs: Success - {len(results)} results")
            
            for i, result in enumerate(results):
                print(f"   Log {i+1}: {result.get('classification')} ({result.get('confidence', 0):.2%})")
                print(f"   Threat Level: {result.get('threat_level')}")
                print(f"   Explanation: {result.get('explanation', '')[:100]}...")
                print(f"   Recommended Action: {result.get('recommended_action', '')[:50]}...")
                print()
            
            return True
        else:
            print(f"❌ /analyze-logs: HTTP {response.status_code}")
            print(f"   Error: {response.json().get('detail', 'Unknown error')}")
            return False
            
    except Exception as e:
        print(f"❌ /analyze-logs: Error - {e}")
        return False

def test_analyze_url():
    """Test /analyze-url endpoint"""
    print("🧪 Testing /analyze-url endpoint...")
    
    test_urls = [
        "https://example.com",
        "https://google.com", 
        "https://suspicious-site.com"
    ]
    
    success_count = 0
    
    for url in test_urls:
        test_data = {
            "url": url,
            "include_analysis": True
        }
        
        try:
            response = requests.post(f"{BASE_URL}/analyze-url", json=test_data, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                print(f"✅ URL {url}: {result.get('classification')} ({result.get('confidence', 0):.2%})")
                print(f"   Risk Score: {result.get('risk_score', 0):.2f}")
                print(f"   Threat Level: {result.get('threat_level')}")
                print(f"   Explanation: {result.get('explanation', '')[:100]}...")
                print(f"   Recommended Action: {result.get('recommended_action', '')[:50]}...")
                print()
                success_count += 1
            else:
                print(f"❌ URL {url}: HTTP {response.status_code}")
                print(f"   Error: {response.json().get('detail', 'Unknown error')}")
                
        except Exception as e:
            print(f"❌ URL {url}: Error - {e}")
    
    return success_count == len(test_urls)

def test_analyze_file():
    """Test /analyze-file endpoint"""
    print("🧪 Testing /analyze-file endpoint...")
    
    # Create a test file
    test_content = b"This is a test file for malware analysis"
    test_filename = "test_file.txt"
    
    try:
        files = {"file": (test_filename, test_content, "text/plain")}
        data = {
            "scan_type": "quick",
            "include_family_detection": True
        }
        
        response = requests.post(f"{BASE_URL}/analyze-file", files=files, data=data, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ /analyze-file: Success")
            print(f"   Classification: {result.get('classification')}")
            print(f"   Confidence: {result.get('confidence', 0):.2%}")
            print(f"   Threat Level: {result.get('threat_level')}")
            print(f"   Malware Family: {result.get('malware_family', 'None')}")
            print(f"   Explanation: {result.get('explanation', '')[:100]}...")
            print(f"   Recommended Action: {result.get('recommended_action', '')[:50]}...")
            print()
            return True
        else:
            print(f"❌ /analyze-file: HTTP {response.status_code}")
            print(f"   Error: {response.json().get('detail', 'Unknown error')}")
            return False
            
    except Exception as e:
        print(f"❌ /analyze-file: Error - {e}")
        return False

def test_ai_assistant():
    """Test /ai-assistant endpoint"""
    print("🧪 Testing /ai-assistant endpoint...")
    
    test_requests = [
        {
            "text": "What is DNS amplification attack?",
            "model_output": None,
            "logs": None,
            "analysis_type": "general"
        },
        {
            "text": "Analyze this threat",
            "model_output": {
                "classification": "Malicious",
                "confidence": 0.95,
                "threat_level": "High"
            },
            "logs": ["suspicious_activity.log"],
            "analysis_type": "threat_intelligence"
        }
    ]
    
    success_count = 0
    
    for i, test_data in enumerate(test_requests):
        try:
            response = requests.post(f"{BASE_URL}/ai-assistant", json=test_data, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                print(f"✅ AI Assistant Test {i+1}: Success")
                print(f"   Explanation: {result.get('explanation', '')[:100]}...")
                print(f"   Recommended Action: {result.get('recommended_action', '')[:50]}...")
                print(f"   Confidence: {result.get('confidence', 0):.2%}")
                
                if result.get('threat_intelligence'):
                    print(f"   Threat Intelligence: Available")
                if result.get('remediation_steps'):
                    print(f"   Remediation Steps: Available")
                print()
                success_count += 1
            else:
                print(f"❌ AI Assistant Test {i+1}: HTTP {response.status_code}")
                print(f"   Error: {response.json().get('detail', 'Unknown error')}")
                
        except Exception as e:
            print(f"❌ AI Assistant Test {i+1}: Error - {e}")
    
    return success_count == len(test_requests)

def test_model_status():
    """Test model status endpoints"""
    print("🧪 Testing model status endpoints...")
    
    endpoints = [
        ("/models/status", "Model Status"),
        ("/models/health", "Model Health"),
        ("/models/info", "Model Info")
    ]
    
    success_count = 0
    
    for endpoint, description in endpoints:
        try:
            response = requests.get(f"{BASE_URL}{endpoint}", timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                print(f"✅ {description}: OK")
                success_count += 1
            else:
                print(f"❌ {description}: HTTP {response.status_code}")
                
        except Exception as e:
            print(f"❌ {description}: Error - {e}")
    
    return success_count == len(endpoints)

def main():
    """Main test function"""
    print("🚀 CyAi Dashboard New Endpoints Test")
    print("=" * 60)
    print(f"⏰ Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🌐 Base URL: {BASE_URL}")
    print(f"🔑 Gemini API Key: {'Set' if GEMINI_API_KEY != 'your_gemini_api_key_here' else 'Not Set'}")
    print()
    
    # Test results
    results = {}
    
    # Test model status first
    results['model_status'] = test_model_status()
    print()
    
    # Test main endpoints
    results['analyze_logs'] = test_analyze_logs()
    print()
    
    results['analyze_url'] = test_analyze_url()
    print()
    
    results['analyze_file'] = test_analyze_file()
    print()
    
    results['ai_assistant'] = test_ai_assistant()
    print()
    
    # Summary
    print("=" * 60)
    print("📋 Test Summary:")
    print(f"   Model Status: {'✅ PASS' if results['model_status'] else '❌ FAIL'}")
    print(f"   Analyze Logs: {'✅ PASS' if results['analyze_logs'] else '❌ FAIL'}")
    print(f"   Analyze URL: {'✅ PASS' if results['analyze_url'] else '❌ FAIL'}")
    print(f"   Analyze File: {'✅ PASS' if results['analyze_file'] else '❌ FAIL'}")
    print(f"   AI Assistant: {'✅ PASS' if results['ai_assistant'] else '❌ FAIL'}")
    
    total_tests = len(results)
    passed_tests = sum(results.values())
    
    print(f"\n📊 Overall: {passed_tests}/{total_tests} tests passed")
    
    if passed_tests == total_tests:
        print("\n🎉 All tests passed! New endpoint structure is working correctly.")
        return 0
    else:
        print(f"\n⚠️ {total_tests - passed_tests} tests failed. Check the output above for details.")
        return 1

if __name__ == "__main__":
    import sys
    exit_code = main()
    sys.exit(exit_code)
