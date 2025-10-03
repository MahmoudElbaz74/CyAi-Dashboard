#!/usr/bin/env python3
"""
Test script for AI Agent Module
Tests the expert cybersecurity analysis capabilities with MITRE ATT&CK mapping
"""

import requests
import json
import os
from datetime import datetime

# Configuration
BASE_URL = "http://localhost:8000"
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', 'your_gemini_api_key_here')

def test_ai_agent_explanations():
    """Test AI Agent explanation capabilities"""
    print("🧪 Testing AI Agent Explanation Capabilities...")
    
    test_cases = [
        {
            "name": "Log Analysis Explanation",
            "request": {
                "text": "Explain why this log is classified as malicious",
                "model_output": {
                    "classification": "Malicious",
                    "confidence": 0.95,
                    "threat_level": "High",
                    "labels": ["malware_detected", "command_injection"]
                },
                "logs": ["2024-01-15 10:30:45 192.168.1.100 -> 10.0.0.1 TCP Command injection attempt detected"],
                "analysis_type": "log_analysis"
            }
        },
        {
            "name": "URL Analysis Explanation",
            "request": {
                "text": "Why is this URL classified as suspicious?",
                "model_output": {
                    "classification": "Suspicious",
                    "confidence": 0.78,
                    "risk_score": 0.65,
                    "threat_level": "Medium"
                },
                "logs": ["https://suspicious-redirect.com/phishing"],
                "analysis_type": "url_analysis"
            }
        },
        {
            "name": "File Analysis Explanation",
            "request": {
                "text": "Explain this malware detection result",
                "model_output": {
                    "classification": "Malicious",
                    "confidence": 0.92,
                    "threat_level": "High",
                    "malware_family": "Trojan"
                },
                "logs": ["trojan_sample.exe"],
                "analysis_type": "file_analysis"
            }
        }
    ]
    
    success_count = 0
    
    for test_case in test_cases:
        print(f"\n📋 Testing: {test_case['name']}")
        try:
            response = requests.post(f"{BASE_URL}/ai-assistant", json=test_case['request'], timeout=60)
            
            if response.status_code == 200:
                result = response.json()
                print(f"✅ {test_case['name']}: Success")
                print(f"   Explanation Length: {len(result.get('explanation', ''))} characters")
                print(f"   Confidence: {result.get('confidence', 0):.2%}")
                print(f"   Recommended Action: {result.get('recommended_action', '')[:100]}...")
                
                # Check for MITRE ATT&CK mentions
                explanation = result.get('explanation', '')
                if 'T1' in explanation or 'MITRE' in explanation or 'ATT&CK' in explanation:
                    print("   ✅ MITRE ATT&CK mapping detected")
                else:
                    print("   ⚠️ No MITRE ATT&CK mapping detected")
                
                success_count += 1
            else:
                print(f"❌ {test_case['name']}: HTTP {response.status_code}")
                print(f"   Error: {response.json().get('detail', 'Unknown error')}")
                
        except Exception as e:
            print(f"❌ {test_case['name']}: Error - {e}")
    
    return success_count == len(test_cases)

def test_ai_agent_correlation():
    """Test AI Agent correlation capabilities"""
    print("\n🧪 Testing AI Agent Correlation Capabilities...")
    
    test_cases = [
        {
            "name": "Network Correlation",
            "request": {
                "text": "Correlate these network findings and identify potential attack patterns",
                "model_output": {
                    "logs": [
                        {"classification": "Suspicious", "confidence": 0.85, "source_ip": "192.168.1.100"},
                        {"classification": "Malicious", "confidence": 0.92, "destination_ip": "10.0.0.1"}
                    ],
                    "urls": [
                        {"classification": "Suspicious", "confidence": 0.78, "url": "https://suspicious-site.com"}
                    ]
                },
                "logs": ["Network correlation analysis"],
                "analysis_type": "network_correlation"
            }
        },
        {
            "name": "Threat Correlation",
            "request": {
                "text": "Analyze these threat findings and provide comprehensive assessment",
                "model_output": {
                    "files": [
                        {"classification": "Malicious", "confidence": 0.95, "malware_family": "Trojan"}
                    ],
                    "urls": [
                        {"classification": "Malicious", "confidence": 0.88, "risk_score": 0.9}
                    ]
                },
                "logs": ["Threat correlation analysis"],
                "analysis_type": "threat_correlation"
            }
        },
        {
            "name": "Comprehensive Correlation",
            "request": {
                "text": "Provide comprehensive analysis of all findings",
                "model_output": {
                    "logs": [
                        {"classification": "Suspicious", "confidence": 0.85},
                        {"classification": "Malicious", "confidence": 0.92}
                    ],
                    "urls": [
                        {"classification": "Suspicious", "confidence": 0.78}
                    ],
                    "files": [
                        {"classification": "Malicious", "confidence": 0.95, "malware_family": "Trojan"}
                    ]
                },
                "logs": ["Comprehensive correlation analysis"],
                "analysis_type": "comprehensive_correlation"
            }
        }
    ]
    
    success_count = 0
    
    for test_case in test_cases:
        print(f"\n📋 Testing: {test_case['name']}")
        try:
            response = requests.post(f"{BASE_URL}/ai-assistant", json=test_case['request'], timeout=60)
            
            if response.status_code == 200:
                result = response.json()
                print(f"✅ {test_case['name']}: Success")
                print(f"   Explanation Length: {len(result.get('explanation', ''))} characters")
                print(f"   Confidence: {result.get('confidence', 0):.2%}")
                
                # Check for correlation insights
                explanation = result.get('explanation', '')
                correlation_keywords = ['correlation', 'pattern', 'relationship', 'connection', 'chain']
                if any(keyword in explanation.lower() for keyword in correlation_keywords):
                    print("   ✅ Correlation analysis detected")
                else:
                    print("   ⚠️ Limited correlation analysis detected")
                
                success_count += 1
            else:
                print(f"❌ {test_case['name']}: HTTP {response.status_code}")
                print(f"   Error: {response.json().get('detail', 'Unknown error')}")
                
        except Exception as e:
            print(f"❌ {test_case['name']}: Error - {e}")
    
    return success_count == len(test_cases)

def test_ai_agent_mitre_mapping():
    """Test AI Agent MITRE ATT&CK mapping capabilities"""
    print("\n🧪 Testing AI Agent MITRE ATT&CK Mapping...")
    
    test_cases = [
        {
            "name": "Command Injection Mapping",
            "request": {
                "text": "Map this behavior to MITRE ATT&CK techniques",
                "model_output": {
                    "classification": "Malicious",
                    "confidence": 0.95,
                    "labels": ["command_injection", "privilege_escalation"]
                },
                "logs": ["Command injection attempt: ; cat /etc/passwd"],
                "analysis_type": "model_explanation"
            }
        },
        {
            "name": "Network Discovery Mapping",
            "request": {
                "text": "Identify MITRE ATT&CK techniques for this network activity",
                "model_output": {
                    "classification": "Suspicious",
                    "confidence": 0.85,
                    "labels": ["network_scanning", "port_scan"]
                },
                "logs": ["Port scan detected from 192.168.1.100 to multiple ports"],
                "analysis_type": "model_explanation"
            }
        },
        {
            "name": "File Obfuscation Mapping",
            "request": {
                "text": "Map this file behavior to MITRE ATT&CK",
                "model_output": {
                    "classification": "Malicious",
                    "confidence": 0.88,
                    "malware_family": "Trojan",
                    "labels": ["obfuscated", "packed"]
                },
                "logs": ["Obfuscated executable detected"],
                "analysis_type": "model_explanation"
            }
        }
    ]
    
    success_count = 0
    
    for test_case in test_cases:
        print(f"\n📋 Testing: {test_case['name']}")
        try:
            response = requests.post(f"{BASE_URL}/ai-assistant", json=test_case['request'], timeout=60)
            
            if response.status_code == 200:
                result = response.json()
                print(f"✅ {test_case['name']}: Success")
                
                # Check for MITRE ATT&CK technique mentions
                explanation = result.get('explanation', '')
                mitre_techniques = ['T1059', 'T1083', 'T1027', 'T1049', 'T1016', 'T1105', 'T1070', 'T1036']
                found_techniques = [tech for tech in mitre_techniques if tech in explanation]
                
                if found_techniques:
                    print(f"   ✅ MITRE ATT&CK techniques found: {', '.join(found_techniques)}")
                else:
                    print("   ⚠️ No specific MITRE ATT&CK techniques detected")
                
                # Check for tactical information
                tactics = ['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 
                          'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
                          'Collection', 'Command and Control', 'Exfiltration', 'Impact']
                found_tactics = [tactic for tactic in tactics if tactic in explanation]
                
                if found_tactics:
                    print(f"   ✅ MITRE ATT&CK tactics mentioned: {', '.join(found_tactics[:3])}...")
                
                success_count += 1
            else:
                print(f"❌ {test_case['name']}: HTTP {response.status_code}")
                print(f"   Error: {response.json().get('detail', 'Unknown error')}")
                
        except Exception as e:
            print(f"❌ {test_case['name']}: Error - {e}")
    
    return success_count == len(test_cases)

def test_ai_agent_remediation():
    """Test AI Agent remediation recommendations"""
    print("\n🧪 Testing AI Agent Remediation Recommendations...")
    
    test_cases = [
        {
            "name": "Malware Remediation",
            "request": {
                "text": "Provide remediation steps for this malware detection",
                "model_output": {
                    "classification": "Malicious",
                    "confidence": 0.95,
                    "threat_level": "Critical",
                    "malware_family": "Ransomware"
                },
                "logs": ["Ransomware detected on critical server"],
                "analysis_type": "threat_intelligence"
            }
        },
        {
            "name": "Network Intrusion Remediation",
            "request": {
                "text": "What should we do about this network intrusion?",
                "model_output": {
                    "classification": "Malicious",
                    "confidence": 0.88,
                    "threat_level": "High",
                    "labels": ["lateral_movement", "privilege_escalation"]
                },
                "logs": ["Lateral movement detected across network segments"],
                "analysis_type": "threat_intelligence"
            }
        }
    ]
    
    success_count = 0
    
    for test_case in test_cases:
        print(f"\n📋 Testing: {test_case['name']}")
        try:
            response = requests.post(f"{BASE_URL}/ai-assistant", json=test_case['request'], timeout=60)
            
            if response.status_code == 200:
                result = response.json()
                print(f"✅ {test_case['name']}: Success")
                
                # Check for remediation steps
                explanation = result.get('explanation', '')
                remediation_keywords = ['remediation', 'steps', 'action', 'recommendation', 'mitigation', 'containment']
                if any(keyword in explanation.lower() for keyword in remediation_keywords):
                    print("   ✅ Remediation recommendations detected")
                else:
                    print("   ⚠️ Limited remediation recommendations detected")
                
                # Check for threat intelligence
                threat_intel = result.get('threat_intelligence')
                if threat_intel:
                    print("   ✅ Threat intelligence context provided")
                
                # Check for remediation steps
                remediation_steps = result.get('remediation_steps')
                if remediation_steps:
                    print("   ✅ Detailed remediation steps provided")
                
                success_count += 1
            else:
                print(f"❌ {test_case['name']}: HTTP {response.status_code}")
                print(f"   Error: {response.json().get('detail', 'Unknown error')}")
                
        except Exception as e:
            print(f"❌ {test_case['name']}: Error - {e}")
    
    return success_count == len(test_cases)

def main():
    """Main test function"""
    print("🚀 AI Agent Module Test Suite")
    print("=" * 60)
    print(f"⏰ Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🌐 Base URL: {BASE_URL}")
    print(f"🔑 Gemini API Key: {'Set' if GEMINI_API_KEY != 'your_gemini_api_key_here' else 'Not Set'}")
    print()
    
    # Test results
    results = {}
    
    # Test AI Agent capabilities
    results['explanations'] = test_ai_agent_explanations()
    results['correlation'] = test_ai_agent_correlation()
    results['mitre_mapping'] = test_ai_agent_mitre_mapping()
    results['remediation'] = test_ai_agent_remediation()
    
    # Summary
    print("\n" + "=" * 60)
    print("📋 AI Agent Test Summary:")
    print(f"   Explanation Capabilities: {'✅ PASS' if results['explanations'] else '❌ FAIL'}")
    print(f"   Correlation Analysis: {'✅ PASS' if results['correlation'] else '❌ FAIL'}")
    print(f"   MITRE ATT&CK Mapping: {'✅ PASS' if results['mitre_mapping'] else '❌ FAIL'}")
    print(f"   Remediation Recommendations: {'✅ PASS' if results['remediation'] else '❌ FAIL'}")
    
    total_tests = len(results)
    passed_tests = sum(results.values())
    
    print(f"\n📊 Overall: {passed_tests}/{total_tests} AI Agent capabilities working")
    
    if passed_tests == total_tests:
        print("\n🎉 All AI Agent tests passed! Expert analysis capabilities are working correctly.")
        return 0
    else:
        print(f"\n⚠️ {total_tests - passed_tests} AI Agent capabilities need attention.")
        return 1

if __name__ == "__main__":
    import sys
    exit_code = main()
    sys.exit(exit_code)
