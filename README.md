# CyAi Dashboard

AI-powered cybersecurity analysis platform providing log analysis, URL phishing detection, malware file scanning, and an AI assistant augmented by Gemini-1.5-Pro. The system includes a FastAPI backend with pre-trained model modules and a Streamlit frontend.

## Contents
- Overview
- Architecture
- Project Structure
- Components
  - Backend
  - Frontend
  - Models
  - AI Agent and Gemini
  - Utilities and Types
- End-to-End Flow
- Local Setup and Running
- Configuration and Environment
- API Endpoints and Examples
- Deployment
- Security and Authentication (Future)
- Development and Testing
- Roadmap

## Overview
CyAi Dashboard enables analysts to:
- Classify and label logs with AI explanations
- Detect phishing risks for URLs with a multi-stage pipeline and an AI-driven final verdict
- Scan uploaded files for malware indicators and families
- Ask an AI assistant security questions with contextual insights

## Architecture
- Backend: FastAPI app exposing analysis endpoints, orchestrating model inference, and fetching AI explanations from Gemini.
- Frontend: Streamlit UI providing tools for logs, URL, files, and AI chat.
- Models: Lightweight pre-trained placeholders with clear interfaces for log classification, phishing detection, and malware analysis.
- AI Agent: Modular AI agent with prompt templates, context builder, and optional HF model hooks, accessible via a dedicated router.
- Integrations: Gemini-1.5-Pro client for explanation, threat intel, and remediation steps.

## Project Structure
```
Root
├─ README.md, guides (AI_AGENT_GUIDE.md, API_ENDPOINTS_GUIDE.md, FRONTEND_GUIDE.md, MODEL_INTEGRATION_GUIDE.md), LICENSE
├─ requirements.txt, env_template.txt
├─ datasets/
│  ├─ links_samples/ (datasets_links.txt)
│  ├─ malware_samples/ (datasets_links.txt)
│  └─ pcap_samples/ (datasets_links.txt)
├─ backend/
│  ├─ main.py
│  ├─ config.py
│  ├─ gemini_integration/
│  │  └─ gemini_client.py
│  ├─ ai_agent/
│  │  ├─ __init__.py
│  │  ├─ agent.py
│  │  ├─ ai_agent.py
│  │  ├─ api.py
│  │  ├─ context_builder.py
│  │  ├─ hf_model.py
│  │  └─ prompt_templates.py
│  ├─ link_analysis/ (analyzer.py)
│  ├─ malware_analysis/ (analyzer.py)
│  ├─ network_detection/ (detector.py)
│  ├─ models/
│  │  ├─ model_manager.py
│  │  ├─ log_classifier.py
│  │  ├─ phishing_detector.py
│  │  └─ malware_detector.py
│  ├─ types/ (schemas.py)
│  └─ utils/
│     ├─ file_utils.py
│     ├─ logging_utils.py
│     └─ validation_utils.py
├─ frontend/
│  ├─ app.py
│  └─ requirements.txt
├─ tests (test_*.py)
└─ venv/ (local virtual environment)
```

## Components

### Backend (`backend/`)
- `main.py`: FastAPI app exposing endpoints:
  - `GET /`: API info and feature list
  - `POST /analyze-logs`: Classifies logs via `LogClassifier` and augments results with Gemini explanations
  - `POST /analyze-url`: Multi-stage URL analysis that combines a local model, VirusTotal, and a Gemini final decision (see “URL Analysis Pipeline”)
  - `POST /analyze-file`: Scans file bytes via `MalwareDetector` with Gemini explanations
  - `POST /ai-assistant`: AI Agent analysis combining user text with optional model outputs/logs
  - `GET /models/status`, `/models/health`, `/models/info`: Model status and info
- `config.py`: Central configuration using environment variables; parses `MAX_FILE_SIZE` etc.
- `gemini_integration/gemini_client.py`:
  - Wraps Gemini-1.5/2.5 models: `get_explanation`, `get_threat_intelligence`, `get_remediation_steps`, and `get_final_url_verdict`
  - Implements a structured prompt for the final phishing decision with clear decision rules; parses model JSON or returns robust fallbacks
  - Enforces conservative defaults in fallback mode (e.g., any VirusTotal detections ≥ 1 ⇒ at least Suspicious)
- `models/model_manager.py`: Singleton manager instantiating:
  - `LogClassifier`, `PhishingDetector`, `MalwareDetector`
  - Provides `get_*` helpers, `health_check`, and `get_all_models_info`
- `models/log_classifier.py`:
  - Preprocesses logs and classifies as Normal/Suspicious/Malicious (placeholder heuristic)
  - Batch classification, model info
- `models/phishing_detector.py`:
  - URL preprocessing, heuristic phishing detection with risk scoring and recommendations
  - Batch detection, model info
- `models/malware_detector.py`:
  - File content analysis with `is_malicious`, `confidence`, `threat_level`, `malware_family`, `recommendations` (placeholder)
- `types/schemas.py`: Pydantic schemas for requests/responses for models, link/malware/network, and AI agent shapes.
- `ai_agent/`:
  - `api.py`: Router under `/ai` for AI-augmented analyses; model/context/template dependencies; context summary and template discovery
  - `agent.py`: Aggregates router and exposes legacy endpoints for compatibility; initializes model on import
  - `hf_model.py`: HF model manager abstraction used by AI agent (load/generate)
  - `prompt_templates.py`: Enum and templates for various analysis prompt formats
  - `context_builder.py`: Tracks logs/contexts and summarizes them
- `link_analysis/`, `malware_analysis/`, `network_detection/`: Domain analyzers/detectors (extensible; referenced by AI agent context-building).

### Frontend (`frontend/`)
- `app.py` (Streamlit):
  - Pages: Log Analyzer, URL Checker, File Scanner, AI Assistant
  - Calls backend endpoints at `http://localhost:8000`
  - Custom dark theme CSS and status indicators
- `requirements.txt`: Frontend dependencies.

### Utilities and Types
- `utils/`: `logging_utils.py` (setup and audit logs), `validation_utils.py` (input validation), `file_utils.py` (file metadata and size checks).
- `types/schemas.py`: Canonical request/response definitions shared across modules.

### AI Agent and Gemini
- The AI Agent provides contextualized responses using prompt templates and a context builder.
- Gemini client enriches model outputs with explanations, threat intelligence, and remediation guidance. If `GEMINI_API_KEY` is absent, the system warns and falls back to deterministic messages without AI augmentation.

### Datasets (`datasets/`)
Sample URLs, malware links, and PCAP references for testing and demos.

## End-to-End Flow
1. User selects a tool in the Streamlit UI (`frontend/app.py`).
2. Frontend sends a request to the FastAPI backend:
   - Logs → `POST /analyze-logs`
   - URL → `POST /analyze-url` (multi-stage URL pipeline)
   - File → `POST /analyze-file` (multipart)
   - AI chat → `POST /ai-assistant`
3. Backend uses `ModelManager` to invoke the appropriate model.
4. For URLs, backend fetches VirusTotal reputation and then calls Gemini to make the final decision.
5. Backend returns structured responses with the Gemini final verdict, model transparency fields, and performance metrics.
6. Frontend renders a professional report separating Model, VirusTotal, and Gemini Final Verdict sections.

## URL Analysis Pipeline

The URL checker uses a professional, explainable, multi-stage pipeline:

- Stage 1 — Model Analysis (Local):
  - Validates and normalizes the URL
  - Preprocesses and infers a risk score using the local `PhishingDetector`
  - Produces a model label (Safe/Suspicious/Malicious) and a concise reasoning string

- Stage 2 — VirusTotal Reputation:
  - Submits the URL to VirusTotal with safe timeouts and error handling
  - Parses detections and summarizes a `verdict` and stats for display

- Stage 3 — Gemini Final Verdict:
  - Combines the URL, the model’s score/label/reason, and VirusTotal summary
  - Applies explicit decision rules to yield a final label, threat level, explanation, and recommended action
  - Conservative defaults are enforced if the AI is unavailable (e.g., any VT detections ≥ 1 ⇒ at least Suspicious)

Returned structure (abbreviated):

```json
{
  "classification": "Malicious",          // Gemini final label
  "threat_level": "High",                // Gemini threat level
  "confidence": 0.91,                      // Prefer Gemini confidence if provided
  "risk_score": 0.88,                      // Prefer Gemini risk if provided
  "explanation": "…",                     // Gemini explanation
  "recommended_action": "…",              // Gemini action or dynamic fallback
  "details": {
    "url": "https://…",
    "timestamp": "2025-10-05T20:41:06Z",
    "model": { "score": 0.88, "label": "Malicious", "reason": "…" },
    "virustotal": { "verdict": "Malicious", "detections": 7, "summary": "…" },
    "gemini_final": { "final_label": "Malicious", "threat_level": "High", "explanation": "…" },
    "notes": ["Model and VT agree on malicious"],
    "performance_metrics": { "total_time": 0.74, "model_load_time": 0.01, "detection_time": 0.22, "gemini_time": 0.51 }
  }
}
```

### Decision Rules (abridged)
- If VirusTotal shows any malicious detections (≥ 1) ⇒ at least Suspicious; do not return Safe.
- If both model and VirusTotal say malicious ⇒ Malicious/High.
- If model says suspicious/malicious but VirusTotal shows 0 detections and the domain is known good ⇒ Likely False Positive.
- If both indicate safe and domain is well-known ⇒ Safe.
- If results conflict with no strong evidence of maliciousness ⇒ Suspicious with lower confidence.

### Dynamic Recommended Actions
- Malicious / High: Immediate investigation required.
- Suspicious / Moderate: Caution advised. Manual review recommended.
- Safe / Likely False Positive / Low: No immediate action required.

## Local Setup and Running

### Prerequisites
- Python 3.10+
- Windows PowerShell or a Unix-like shell
- Gemini API key (optional but recommended for AI explanations)

### Environment
Copy `env_template.txt` to `.env` and set values:
```
GEMINI_API_KEY=your_api_key_here
BACKEND_HOST=0.0.0.0
BACKEND_PORT=8000
DEBUG=false
LOG_LEVEL=INFO
MAX_FILE_SIZE=50MB
CORS_ORIGINS=*
```

### Install
From project root, install backend and frontend deps:
```bash
# (Optional) python -m venv venv && venv\Scripts\activate  # Windows
```

### Run Backend
```bash
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```
venv\Scripts\activate

### Run Frontend
```bash
streamlit run main.py
```

### Verify
- Streamlit app: http://localhost:8501
- Backend root: http://localhost:8000/
- API docs: http://localhost:8000/docs

## Configuration and Environment
- `backend/config.py` reads environment variables:
  - `GEMINI_API_KEY`: Required for Gemini explanations
  - `BACKEND_HOST`, `BACKEND_PORT`: FastAPI bind address/port
  - `DEBUG`, `LOG_LEVEL`: Logging/diagnostics
  - `MAX_FILE_SIZE`: e.g., 50MB; `Config.get_file_size_bytes()` helper
  - `CORS_ORIGINS`: CSV list for CORS
- Missing `GEMINI_API_KEY` logs a warning; explanations fall back to defaults.

## API Endpoints and Examples

### Root
```bash
curl http://localhost:8000/
```

### Analyze Logs
```bash
curl -X POST http://localhost:8000/analyze-logs \
  -H "Content-Type: application/json" \
  -d '{
    "logs": [
      "2024-01-15 10:31:00 192.168.1.101 -> 8.8.8.8 DNS Query for malicious.com"
    ],
    "log_type": "network"
  }'
```

### Analyze URL
```bash
curl -X POST http://localhost:8000/analyze-url \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com","include_analysis":true}'
```

Response fields of interest:
- Top-level `classification` and `threat_level` are produced by Gemini.
- `details.model` and `details.virustotal` expose transparency for the underlying signals.
- `details.gemini_final` mirrors the final decision for UI rendering.

### Analyze File (multipart)
```bash
curl -X POST http://localhost:8000/analyze-file \
  -F "file=@/path/to/sample.exe" \
  -F "scan_type=quick" \
  -F "include_family_detection=true"
```

### AI Assistant (Example)
```bash
curl -X POST http://localhost:8000/ai-assistant \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Explain signs of DNS tunneling in these logs",
    "model_output": {"last_classification":"Suspicious"},
    "logs": [
      "2024-01-15 10:31:00 client -> 8.8.8.8 DNS TXT verylongsubdomain.example.com"
    ],
    "analysis_type": "general"
  }'
```

### Models Info and Health
```bash
curl http://localhost:8000/models/status
curl http://localhost:8000/models/health
curl http://localhost:8000/models/info
```

## Deployment

### Option A: Uvicorn/Gunicorn (Linux)
```bash
# App server
pip install -r backend/requirements.txt
pip install -r frontend/requirements.txt
export GEMINI_API_KEY=... ; export BACKEND_HOST=0.0.0.0 ; export BACKEND_PORT=8000
# Start API (Gunicorn + Uvicorn workers)
gunicorn backend.main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
# Start UI
streamlit run frontend/app.py --server.port 8501 --server.address 0.0.0.0
```

### Option B: Docker (example)
```dockerfile
# Dockerfile (backend)
FROM python:3.11-slim
WORKDIR /app
COPY backend/requirements.txt .
RUN pip install -r requirements.txt
COPY backend/ ./backend/
ENV BACKEND_HOST=0.0.0.0 BACKEND_PORT=8000
EXPOSE 8000
CMD ["gunicorn","backend.main:app","-w","4","-k","uvicorn.workers.UvicornWorker","--bind","0.0.0.0:8000"]
```
```dockerfile
# Dockerfile.frontend
FROM python:3.11-slim
WORKDIR /app
COPY frontend/requirements.txt .
RUN pip install -r requirements.txt
COPY frontend/ ./frontend/
EXPOSE 8501
CMD ["streamlit","run","frontend/app.py","--server.port","8501","--server.address","0.0.0.0"]
```
```yaml
# docker-compose.yml (example)
version: "3.9"
services:
  api:
    build: { context: ., dockerfile: Dockerfile }
    environment:
      - GEMINI_API_KEY=${GEMINI_API_KEY}
      - BACKEND_HOST=0.0.0.0
      - BACKEND_PORT=8000
    ports: ["8000:8000"]
  ui:
    build: { context: ., dockerfile: Dockerfile.frontend }
    depends_on: [api]
    environment: []
    ports: ["8501:8501"]
```

### Reverse Proxy (Nginx) Notes
- Terminate TLS at Nginx, proxy `/` to Streamlit and `/api` to FastAPI if desired.
- Ensure CORS in backend allows the UI origin in production.

## Security and Authentication (Future)
- Current build has no auth; for production add one of:
  - API key or OAuth2/JWT for backend endpoints (FastAPI `fastapi.security`)
  - Session or token-based auth for the UI
- Rate limiting and abuse protection at the proxy level (e.g., Nginx/Traefik) recommended.
- Secrets management via environment or a vault.

## Development and Testing
- Code style: Python typing with Pydantic schemas; modular architecture for AI agent.
- Tests: `test_*.py` in root cover backend, frontend, integration, and structure.
- Linting/formatting: Configure as preferred; ensure no new linter errors.

## Roadmap
- Replace placeholder heuristics with real model inference
- Add persistence for analysis history
- Implement authentication and RBAC
- Improve error handling and observability
- Extend datasets and benchmarks