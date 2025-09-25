```python
import streamlit as st
import requests
import pandas as pd
import io

st.title("🔗 Link Analyzer")

# Option to input single URL or upload file
option = st.radio("Choose input method:", ("Enter URL", "Upload URL File"))
urls = []

if option == "Enter URL":
    url_input = st.text_input("Enter a URL to analyze (e.g., https://example.com)")
    if url_input:
        urls.append(url_input)
else:
    uploaded_file = st.file_uploader("Upload a CSV file with URLs (column: 'url')", type=["csv"])
    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        urls = df["url"].tolist()

if urls:
    st.write("### Analysis Results")
    for url in urls:
        try:
            # Send URL to backend
            response = requests.post("http://localhost:8000/link/check", json={"url": url})
            
            if response.status_code == 200:
                result = response.json()
                is_malicious = result.get("is_malicious", False)
                status = "❌ Malicious" if is_malicious else "✅ Safe"
                st.write(f"**URL:** {url}")
                st.write(f"**Status:** {status}")
                
                # Display reasons (extend backend for detailed reasons)
                if is_malicious:
                    reasons = [
                        f"Domain: {result['features']['domain']}",
                        "Suspicious redirect detected" if not result['features']['https'] else "",
                        "IP-based URL" if result['features']['has_ip'] else ""
                    ]
                    reasons = [r for r in reasons if r]  # Remove empty reasons
                    st.write("**Reasons:**")
                    for reason in reasons:
                        st.write(f"- {reason}")
                st.write("---")
            else:
                st.error(f"Error analyzing {url}: {response.json().get('error')}")
        except Exception as e:
            st.error(f"Error analyzing {url}: {str(e)}")
```