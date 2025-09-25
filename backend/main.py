from fastapi import FastAPI
from network_detection.detector import router as network_detection_router
from malware_analysis.analyzer import router as malware_analysis_router
from link_analysis.analyzer import router as link_analysis_router
from ai_agent.agent import router as ai_agent_router

app = FastAPI()

app.include_router(network_detection_router, prefix="/network-detection", tags=["Network Detection"])
app.include_router(malware_analysis_router, prefix="/malware-analysis", tags=["Malware Analysis"])
app.include_router(link_analysis_router, prefix="/link-analysis", tags=["Link Analysis"])
app.include_router(ai_agent_router, prefix="/ai-agent", tags=["AI Agent"])

@app.get("/")
def read_root():
    return {"message": "Welcome to the Cybersecurity Application API"}