```python
import streamlit as st

st.set_page_config(page_title="Cyber AI Dashboard", layout="wide", page_icon="🛡️")

st.title("🛡️ Cyber AI Dashboard")
st.markdown("""
Welcome to the **Cyber AI Dashboard**, your all-in-one platform for AI-driven cybersecurity analysis.  
Navigate using the sidebar to access the following tools:

- **📊 Network Traffic Monitor**: Analyze PCAP files or live traffic for threats.
- **🛡️ Malware File Analysis**: Scan files for malware and view detailed reports.
- **🔗 Link Analyzer**: Check URLs for malicious content.
- **🤖 AI Assistant**: Get explanations and insights from an AI-powered assistant.
""")

# Quick stats or placeholder (optional)
st.subheader("Dashboard Overview")
col1, col2, col3, col4 = st.columns(4)
col1.metric("Network Scans", "0", help="Number of PCAP files analyzed")
col2.metric("Files Scanned", "0", help="Number of files checked for malware")
col3.metric("URLs Analyzed", "0", help="Number of URLs evaluated")
col4.metric("AI Queries", "0", help="Number of questions asked to the AI assistant")
```