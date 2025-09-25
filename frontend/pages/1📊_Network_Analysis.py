```python
import streamlit as st
import requests
import pandas as pd

st.title("📊 Network Traffic Monitor")

# Option to choose between PCAP upload or live traffic
analysis_type = st.radio("Choose analysis type:", ("Upload PCAP File", "Monitor Live Traffic"))

if analysis_type == "Upload PCAP File":
    uploaded_file = st.file_uploader("Upload a PCAP file", type=["pcap", "pcapng"])
    
    if uploaded_file:
        try:
            # Send file to backend
            files = {"file": (uploaded_file.name, uploaded_file, "application/octet-stream")}
            response = requests.post("http://localhost:8000/network/analyze", files=files)
            
            if response.status_code == 200:
                result = response.json()
                features_df = pd.DataFrame(result["features"])
                predictions = result["predictions"]
                
                # Display classification
                is_threat = any(pred == 1 for pred in predictions)
                st.write(f"**Status:** {'🚨 Potential Threat' if is_threat else '✅ Safe'}")
                
                # Display statistics
                st.subheader("Traffic Statistics")
                st.write("### Packet Details")
                st.dataframe(features_df[["src_ip", "dst_ip", "protocol", "pkt_len", "timestamp"]])
                
                # Calculate and display summary statistics
                total_packets = len(features_df)
                total_size = features_df["pkt_len"].sum()
                protocol_counts = features_df["protocol"].value_counts().to_dict()
                st.write(f"**Total Packets:** {total_packets}")
                st.write(f"**Total Traffic Size:** {total_size} bytes")
                
                # Protocol distribution chart
                st.write("### Protocol Distribution")
                protocol_labels = [f"Protocol {p}" for p in protocol_counts.keys()]
                protocol_values = list(protocol_counts.values())
                
                ```chartjs
                {
                    "type": "pie",
                    "data": {
                        "labels": protocol_labels,
                        "datasets": [{
                            "label": "Protocol Distribution",
                            "data": protocol_values,
                            "backgroundColor": ["#36A2EB", "#FF6384", "#FFCE56", "#4BC0C0", "#9966FF"],
                            "borderColor": ["#ffffff"],
                            "borderWidth": 1
                        }]
                    },
                    "options": {
                        "responsive": true,
                        "plugins": {
                            "legend": {
                                "position": "top",
                                "labels": {
                                    "color": "#333333"
                                }
                            },
                            "title": {
                                "display": true,
                                "text": "Protocol Distribution in Traffic",
                                "color": "#333333"
                            }
                        }
                    }
                }
                ```
                
                # Display threat details (if any)
                if is_threat:
                    st.subheader("Threat Details")
                    # Placeholder: Extend backend to provide attack type
                    threat_packets = features_df[pd.Series(predictions) == 1]
                    for idx, row in threat_packets.iterrows():
                        st.write(f"- **Source IP:** {row['src_ip']}")
                        st.write(f"  **Protocol:** {row['protocol']}")
                        st.write(f"  **Attack Type:** {result.get('attack_type', 'Unknown')}")
                        st.write("---")
            else:
                st.error(f"Error: {response.json().get('error')}")
        except Exception as e:
            st.error(f"Error: {str(e)}")

else:
    st.subheader("Monitor Live Traffic")
    st.info("Live traffic monitoring is not fully implemented. Start capturing live traffic below.")
    if st.button("Start Live Capture"):
        try:
            # Placeholder: Send request to backend for live capture
            response = requests.get("http://localhost:8000/network/live_capture")
            if response.status_code == 200:
                st.write("Capturing live traffic... Check backend logs for details.")
            else:
                st.error(f"Error: {response.json().get('error')}")
        except Exception as e:
            st.error(f"Error: {str(e)}")
```