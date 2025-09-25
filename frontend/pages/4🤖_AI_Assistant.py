```python
import streamlit as st
import requests

st.title("🤖 AI Assistant")

# Initialize chat history
if "messages" not in st.session_state:
    st.session_state.messages = []

# Display chat history
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# Chat input
prompt = st.chat_input("Ask the AI Assistant anything (e.g., 'What is DNS Amplification?')")

if prompt:
    # Add user message to history
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    # Query backend AI API
    try:
        response = requests.post("http://localhost:8000/ai/query", json={"prompt": prompt})
        if response.status_code == 200:
            result = response.json()
            ai_response = result.get("response", "No response from AI.")
            # Add AI response to history
            st.session_state.messages.append({"role": "assistant", "content": ai_response})
            with st.chat_message("assistant"):
                st.markdown(ai_response)
        else:
            st.error(f"Error: {response.json().get('error')}")
    except Exception as e:
        st.error(f"Error: {str(e)}")
```