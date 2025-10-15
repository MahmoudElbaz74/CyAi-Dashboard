import streamlit as st
import requests
import json
from datetime import datetime
import os

# Centralized backend URL and request helpers
API_BASE = os.getenv('CYFORT_API_BASE', os.getenv('CYAI_API_BASE', 'http://localhost:8000'))

def api_get(path: str, timeout: int = 5):
    try:
        resp = requests.get(f"{API_BASE}{path}", timeout=timeout)
        return resp, None
    except requests.exceptions.RequestException as e:
        detail = ""
        try:
            if hasattr(e, 'response') and e.response is not None:
                detail = e.response.json().get('detail', '')
        except Exception:
            pass
        return None, detail or str(e)

def api_post(path: str, *, json: dict | None = None, files=None, data=None, timeout: int = 120):
    try:
        resp = requests.post(f"{API_BASE}{path}", json=json, files=files, data=data, timeout=timeout)
        return resp, None
    except requests.exceptions.RequestException as e:
        detail = ""
        try:
            if hasattr(e, 'response') and e.response is not None:
                detail = e.response.json().get('detail', '')
        except Exception:
            pass
        return None, detail or str(e)

# Page configuration
st.set_page_config(
    page_title="CyFort AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Dark theme CSS
st.markdown("""
<style>
    /* Main theme colors */
    .main {
        background-color: #0e1117;
        color: #ffffff;
    }
    
    .stApp {
        background-color: #0e1117;
        color: #ffffff;
    }
    
    /* Status indicators */
    .status-safe {
        background-color: #00ff00;
        color: #000000;
        padding: 8px 16px;
        border-radius: 20px;
        font-weight: bold;
        text-align: center;
        margin: 10px 0;
    }
    
    .status-suspicious {
        background-color: #ffaa00;
        color: #000000;
        padding: 8px 16px;
        border-radius: 20px;
        font-weight: bold;
        text-align: center;
        margin: 10px 0;
    }
    
    .status-malicious {
        background-color: #ff0000;
        color: #ffffff;
        padding: 8px 16px;
        border-radius: 20px;
        font-weight: bold;
        text-align: center;
        margin: 10px 0;
    }
    
    /* Model output styling */
    .model-output {
        background-color: #2d2d2d;
        padding: 15px;
        border-radius: 8px;
        border-left: 4px solid #4CAF50;
        margin: 10px 0;
    }
    
    .ai-explanation {
        background-color: #2d2d2d;
        padding: 15px;
        border-radius: 8px;
        border-left: 4px solid #2196F3;
        margin: 10px 0;
    }
    
    /* Header styling */
    .page-header {
        background: linear-gradient(90deg, #1e3c72 0%, #2a5298 100%);
        padding: 20px;
        border-radius: 10px;
        margin-bottom: 20px;
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)

# Main header
st.markdown("""
<div class="page-header">
    <h1>🛡️ CyFort AI</h1>
    <p>AI-Powered Cybersecurity Analysis Platform</p>
</div>
""", unsafe_allow_html=True)

# Sidebar navigation
st.sidebar.title("🛡️ CyFort AI")
st.sidebar.markdown("---")

# Check backend status
resp, err = api_get("/")
if resp and resp.status_code == 200:
    st.sidebar.success("✅ Backend Connected")
else:
    st.sidebar.error(f"❌ Backend Offline{f' - {err}' if err else ''}")

st.sidebar.markdown("---")

# Navigation
st.sidebar.markdown("### 📊 Analysis Tools")
page = st.sidebar.selectbox("Select Analysis Tool:", [
    "📊 Log Analyzer",
    "🔗 URL Checker", 
    "🦠 File Scanner",
    "🤖 AI Assistant"
])

st.sidebar.markdown("---")

# Quick stats
st.sidebar.markdown("### 📈 Quick Stats")
col1, col2 = st.sidebar.columns(2)
col1.metric("Logs Analyzed", "0")
col2.metric("URLs Checked", "0")
col3, col4 = st.sidebar.columns(2)
col3.metric("Files Scanned", "0")
col4.metric("AI Queries", "0")

# helper renderer (keep in the same file)
def render_result(result):
    classification = result.get("classification", "Unknown")
    confidence = result.get("confidence", 0)
    labels = result.get("labels", []) or []
    details = result.get("details", {}) or {}
    log_type = result.get("log_type", "N/A")

    # Status display
    if classification == "Malicious":
        st.markdown(f'<div class="status-malicious">🚨 {classification}</div>', unsafe_allow_html=True)
    elif classification == "Suspicious":
        st.markdown(f'<div class="status-suspicious">⚠️ {classification}</div>', unsafe_allow_html=True)
    else:
        st.markdown(f'<div class="status-safe">✅ {classification}</div>', unsafe_allow_html=True)

    st.markdown(f"""
    <div class="model-output">
        <strong>Log Type:</strong> {log_type}<br>
        <strong>Confidence:</strong> {confidence:.2%}<br>
        <strong>Labels:</strong> {", ".join(labels)}<br>
        <strong>Details:</strong> {json.dumps(details, indent=2)}
    </div>
    """, unsafe_allow_html=True)

# Main content based on page selection
if page == "📊 Log Analyzer":
    st.markdown("## 📊 Log Analyzer")
    st.markdown("Upload a .pcap/.pcapng or a log file (.csv/.txt) to analyze")

    tab_pcap, tab_logs = st.tabs(["📁 PCAP Analysis", "🧾 Log File Analysis"])

    with tab_pcap:
        uploaded_pcap = st.file_uploader(
            "Choose a PCAP file:",
            type=["pcap", "pcapng"],
            help="Upload a packet capture file for basic analysis",
            key="pcap_file"  # unique key added
        )

        if uploaded_pcap:
            st.info("PCAP uploaded — basic summary below.")
            st.write({"filename": uploaded_pcap.name, "size_bytes": uploaded_pcap.size})

    with tab_logs:
        uploaded_log = st.file_uploader(
            "Choose a log file:",
            type=["csv", "txt"],
            help="Upload a system/network log file for AI analysis",
            key="log_file"  # unique key added
        )

        if uploaded_log and st.button("🔍 Analyze Logs"):
            try:
                text_data = uploaded_log.read().decode("utf-8", errors="ignore")
                if not text_data.strip():
                    st.warning("Uploaded log file is empty or unreadable.")
                else:
                    log_lines = [line.strip() for line in text_data.splitlines() if line.strip()]

                    payload = {
                        "log_entries": log_lines,
                        "log_type": "network",
                        "include_confidence": True
                    }

                    with st.spinner("Analyzing logs using AI model..."):
                        response, err = api_post("/analyze-logs", json=payload, timeout=120)

                    if err:
                        st.error(f"Request failed: {err}")
                    elif not response:
                        st.error("No response from backend")
                    elif response.status_code != 200:
                        # try to extract detail
                        try:
                            detail = response.json().get('detail', response.text)
                        except Exception:
                            detail = response.text
                        st.error(f"Backend error: {detail}")
                    else:
                        result = response.json()

                        # result expected to be a list of items, but support single-object too
                        if isinstance(result, list):
                            st.markdown("### 🧾 Batch Log Analysis Results")
                            for i, log_result in enumerate(result, 1):
                                render_result(log_result)
                                if i < len(result):
                                    st.markdown("---")
                        else:
                            st.markdown("### 🧠 AI Log Classification Result")
                            render_result(result)

            except Exception as e:
                st.error(f"Error during log analysis: {str(e)}")



elif page == "🔗 URL Checker":
    st.markdown("## 🔗 URL Checker")
    st.markdown("Paste URLs to check for phishing risk with AI explanations")
    
    url_input = st.text_input(
        "Enter URL to check:",
        placeholder="https://example.com"
    )
    
    include_analysis = st.checkbox("Include detailed analysis", value=True)
    
    if st.button("🔍 Check URL") and url_input:
        try:
            request_data = {
                "url": url_input,
                "include_analysis": include_analysis
            }
            
            with st.spinner("Analyzing URL with AI..."):
                response, err = api_post("/analyze-url", json=request_data)
            
            if response and response.status_code == 200:
                result = response.json()
                
                details = result.get("details", {})
                model_section = details.get("model", {})
                vt_section = details.get("virustotal", {})
                gemini_final = details.get("gemini_final", {})
                notes = details.get("notes", [])
                timestamp = details.get("timestamp")
                analyzed_url = details.get("url", url_input)

                # Header with URL and date
                st.markdown(f"**URL:** {analyzed_url}")
                if timestamp:
                    st.markdown(f"**Analysis Date:** {timestamp}")

                # Risk header based on model verdict
                classification = result.get("classification", gemini_final.get("final_label", model_section.get("label", "Unknown")))
                confidence = result.get("confidence", 0)
                risk_score = model_section.get("score", result.get("risk_score", 0))

                if classification == "Malicious":
                    st.markdown(f'<div class="status-malicious">🔴 {classification}</div>', unsafe_allow_html=True)
                elif classification == "Suspicious":
                    st.markdown(f'<div class="status-suspicious">🟡 {classification}</div>', unsafe_allow_html=True)
                else:
                    st.markdown(f'<div class="status-safe">🟢 {classification}</div>', unsafe_allow_html=True)

                # Model Verdict card
                st.markdown("### 🧠 Model Verdict")
                st.markdown(f"""
                <div class="model-output">
                    <strong>Risk Score:</strong> {risk_score:.2f} / 1.0<br>
                    <strong>Final Label:</strong> {classification}<br>
                    <strong>Reason:</strong> {model_section.get('reason', 'No reasoning available')}
                </div>
                """, unsafe_allow_html=True)

                # VirusTotal Verdict card
                st.markdown("### 🧪 VirusTotal Verdict")
                vt_verdict = vt_section.get("verdict", "Unknown")
                vt_detections = vt_section.get("detections", 0)
                vt_summary = vt_section.get("summary", "Unavailable")
                st.markdown(f"""
                <div class="ai-explanation">
                    <strong>Detections:</strong> {vt_detections}<br>
                    <strong>Verdict:</strong> {vt_verdict}<br>
                    <strong>Summary:</strong> {vt_summary}
                </div>
                """, unsafe_allow_html=True)

                # Gemini Final Verdict section
                st.markdown("### 🤖 Gemini Final Verdict")
                final_label = gemini_final.get("final_label", classification)
                final_threat = gemini_final.get("threat_level", result.get("threat_level", "Low"))
                final_expl = gemini_final.get("explanation", result.get("explanation", ""))
                st.markdown(f"""
                <div class="ai-explanation">
                    <strong>Final Label:</strong> {final_label}<br>
                    <strong>Threat Level:</strong> {final_threat}<br>
                    <strong>Explanation:</strong> {final_expl}
                </div>
                """, unsafe_allow_html=True)

                # Summary comparison section
                st.markdown("### 📊 Summary")
                st.markdown(f"- **Model**: {model_section.get('label', 'Unknown')} (score: {model_section.get('score', 0):.2f})")
                st.markdown(f"- **VirusTotal**: {vt_section.get('verdict', 'Unknown')} (detections: {vt_section.get('detections', 0)})")
                st.markdown(f"- **Final**: {final_label} ({final_threat})")

                # Notes/Insights section
                st.markdown("### 📝 Notes / Insights")
                if notes:
                    for n in notes:
                        st.info(n)
                else:
                    st.info("Model and VirusTotal results are in agreement or insufficient data.")

                # Explanation and recommendation from AI
                explanation = result.get("explanation", gemini_final.get("explanation", "No explanation available"))
                st.markdown("### 🤖 AI Explanation")
                st.markdown(f"""
                <div class="ai-explanation">
                    {explanation}
                </div>
                """, unsafe_allow_html=True)

                recommended_action = result.get("recommended_action", "")
                if recommended_action:
                    st.markdown("### 📋 Recommended Action")
                    st.info(recommended_action)

                # Optional: show performance metrics
                perf = details.get("performance_metrics")
                if perf:
                    with st.expander("⏱️ Performance Metrics"):
                        st.json(perf)
            else:
                st.error(f"Backend error: {response.json().get('detail', 'Unknown error') if response else err}")
        except Exception as e:
            st.error(f"Error: {str(e)}")

elif page == "🦠 File Scanner":
    st.markdown("## 🦠 File Scanner")
    st.markdown("Upload files to scan for malware using local Xception model and VirusTotal")
    
    uploaded_file = st.file_uploader(
        "Choose a file to scan:",
        type=["exe", "pdf", "doc", "docx", "zip", "rar", "dll", "bat", "cmd", "scr", "txt", "py", "js", "html", "php"],
        help="Upload a file to scan for malware"
    )
    
    if uploaded_file and st.button("🔍 Scan File"):
        try:
            with st.spinner("Scanning file with local model and VirusTotal..."):
                # Try comprehensive scan first
                files = {"file": (uploaded_file.name, uploaded_file, "application/octet-stream")}
                response, err = api_post("/scan-file-comprehensive", files=files)
                
                if response and response.status_code == 200:
                    results = response.json()
                    
                    # Local Model Results
                    st.markdown("### 🧠 Local Model Scan")
                    local_model = results.get("local_model", {})
                    
                    if local_model.get("success"):
                        predicted_class = local_model.get("predicted_class", "Unknown")
                        confidence = local_model.get("confidence", 0)
                        threat_level = local_model.get("threat_level", "Low")
                        file_name = local_model.get("file_name", uploaded_file.name)
                        file_size = local_model.get("file_size", uploaded_file.size)
                        
                        # Display results
                        col1, col2 = st.columns([2, 1])
                        with col1:
                            if predicted_class == "Malicious":
                                st.markdown(f'<div class="status-malicious">🚨 {predicted_class} - {threat_level} Threat</div>', unsafe_allow_html=True)
                            else:
                                st.markdown(f'<div class="status-safe">✅ {predicted_class} - {threat_level} Threat</div>', unsafe_allow_html=True)
                        
                        with col2:
                            st.metric("Confidence", f"{confidence:.1%}")
                        
                        # Model details
                        st.markdown(f"""
                        <div class="model-output">
                            <strong>Predicted Class:</strong> {predicted_class}<br>
                            <strong>Confidence Score:</strong> {confidence:.2%}<br>
                            <strong>Threat Level:</strong> {threat_level}<br>
                            <strong>File Name:</strong> {file_name}<br>
                            <strong>File Size:</strong> {file_size:,} bytes
                        </div>
                        """, unsafe_allow_html=True)
                    else:
                        st.error(f"Local model scan failed: {local_model.get('error', 'Unknown error')}")
                    
                    # VirusTotal Results
                    st.markdown("### 🛡️ VirusTotal Scan")
                    virustotal = results.get("virustotal", {})
                    
                    if virustotal.get("success"):
                        malicious = virustotal.get("malicious", 0)
                        suspicious = virustotal.get("suspicious", 0)
                        undetected = virustotal.get("undetected", 0)
                        harmless = virustotal.get("harmless", 0)
                        
                        # Display VirusTotal results in a clean layout
                        st.markdown("#### VirusTotal Engine Results")
                        
                        col1, col2, col3, col4 = st.columns(4)
                        with col1:
                            st.metric("🚨 Malicious", malicious, delta=None)
                        with col2:
                            st.metric("⚠️ Suspicious", suspicious, delta=None)
                        with col3:
                            st.metric("✅ Harmless", harmless, delta=None)
                        with col4:
                            st.metric("❓ Undetected", undetected, delta=None)
                        
                        # Overall VirusTotal verdict
                        if malicious > 0:
                            vt_verdict = "🚨 Malicious"
                            vt_color = "red"
                        elif suspicious > 0:
                            vt_verdict = "⚠️ Suspicious"
                            vt_color = "orange"
                        elif harmless > 0:
                            vt_verdict = "✅ Clean"
                            vt_color = "green"
                        else:
                            vt_verdict = "❓ Unknown"
                            vt_color = "gray"
                        
                        st.markdown(f"**VirusTotal Verdict:** <span style='color: {vt_color}'>{vt_verdict}</span>", unsafe_allow_html=True)
                        
                    else:
                        error_msg = virustotal.get('error', 'Unknown error')
                        if "timeout" in error_msg.lower():
                            st.warning(f"⏱️ VirusTotal scan timeout: {error_msg}")
                            st.info("💡 **Tip**: VirusTotal analysis can take up to 60 seconds for larger files. You can try again later or check the VirusTotal website directly.")
                        else:
                            st.warning(f"VirusTotal scan failed: {error_msg}")
                        
                else:
                    # Fallback to local model only if comprehensive scan fails
                    st.warning("Comprehensive scan failed, trying local model only...")
                    response, err = api_post("/scan-file-local", files=files)
                    
                    if response and response.status_code == 200:
                        result = response.json()
                        
                        if result.get("success"):
                            st.markdown("### 🧠 Local Model Scan")
                            
                            predicted_class = result.get("predicted_class", "Unknown")
                            confidence = result.get("confidence", 0)
                            threat_level = result.get("threat_level", "Low")
                            file_name = result.get("file_name", uploaded_file.name)
                            file_size = result.get("file_size", uploaded_file.size)
                            
                            # Display results
                            col1, col2 = st.columns([2, 1])
                            with col1:
                                if predicted_class == "Malicious":
                                    st.markdown(f'<div class="status-malicious">🚨 {predicted_class} - {threat_level} Threat</div>', unsafe_allow_html=True)
                                else:
                                    st.markdown(f'<div class="status-safe">✅ {predicted_class} - {threat_level} Threat</div>', unsafe_allow_html=True)
                            
                            with col2:
                                st.metric("Confidence", f"{confidence:.1%}")
                            
                            # Model details
                            st.markdown(f"""
                            <div class="model-output">
                                <strong>Predicted Class:</strong> {predicted_class}<br>
                                <strong>Confidence Score:</strong> {confidence:.2%}<br>
                                <strong>Threat Level:</strong> {threat_level}<br>
                                <strong>File Name:</strong> {file_name}<br>
                                <strong>File Size:</strong> {file_size:,} bytes
                            </div>
                            """, unsafe_allow_html=True)
                            
                            st.info("ℹ️ Only local model results available (VirusTotal scan unavailable)")
                        else:
                            st.error(f"Local model scan failed: {result.get('error', 'Unknown error')}")
                    else:
                        st.error(f"Backend error: {response.json().get('detail', 'Unknown error') if response else err}")
                    
        except Exception as e:
            st.error(f"Scanning error: {str(e)}")

else:  # AI Assistant
    st.markdown("## 🤖 AI Assistant")
    st.markdown("Chat interface for cybersecurity questions and analysis")
    
    if "messages" not in st.session_state:
        st.session_state.messages = []
    
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
    
    prompt = st.chat_input("Ask about logs, threats, attack types, etc...")
    
    if prompt:
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)
        
        try:
            with st.spinner("AI is thinking..."):
                # Send request using 'query' key as expected by backend
                response, err = api_post(
                    "/ai-assistant",
                    json={
                        "query": prompt,
                        "model_output": None,
                        "logs": None,
                        "analysis_type": "general"
                    },
                    timeout=60
                )
            
            if response and response.status_code == 200:
                result = response.json()
                ai_response = result.get("explanation", "No response from AI.")
                recommended_action = result.get("recommended_action", "")
                
                st.session_state.messages.append({"role": "assistant", "content": ai_response})
                with st.chat_message("assistant"):
                    st.markdown(ai_response)
                    if recommended_action:
                        st.info(f"**Recommended Action:** {recommended_action}")
                
                threat_intelligence = result.get("threat_intelligence")
                remediation_steps = result.get("remediation_steps")
                if threat_intelligence or remediation_steps:
                    with st.expander("Additional Information"):
                        if threat_intelligence:
                            st.write("**Threat Intelligence:**")
                            st.json(threat_intelligence)
                        if remediation_steps:
                            st.write("**Remediation Steps:**")
                            st.json(remediation_steps)
            else:
                # Improve error message for timeouts and connection issues
                if err and ("Read timed out" in err or "timed out" in err.lower()):
                    st.error("The request to the AI Assistant timed out. Please try again or refine your query.")
                else:
                    try:
                        detail = response.json().get('detail', 'Unknown error') if response else err
                    except Exception:
                        detail = err or (response.text if response else 'Unknown error')
                    st.error(f"Backend error: {detail}")
        except Exception as e:
            # Catch-all for unexpected errors
            msg = str(e)
            if "Read timed out" in msg or "timed out" in msg.lower():
                st.error("The AI Assistant request timed out. Please try again.")
            else:
                st.error(f"Error: {msg}")
    
    if st.button("🗑️ Clear Chat History"):
        st.session_state.messages = []
        st.rerun()
