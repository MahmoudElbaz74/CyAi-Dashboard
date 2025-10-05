"""
Phishing Detector - Integrated with Keras model, VirusTotal, and Gemini
"""

import os
import re
import json
import logging
import numpy as np
import requests
from typing import Dict, List, Any, Optional
from datetime import datetime
from urllib.parse import urlparse

from pydantic import BaseModel
# TensorFlow/Keras imports with fallbacks
try:
    from tensorflow.keras.models import load_model
    from tensorflow.keras.preprocessing.sequence import pad_sequences
    from tensorflow.keras.preprocessing.text import tokenizer_from_json
    TENSORFLOW_AVAILABLE = True
except ImportError:
    try:
        # Fallback for newer TensorFlow versions
        from keras.models import load_model
        from keras.preprocessing.sequence import pad_sequences
        from keras.preprocessing.text import tokenizer_from_json
        TENSORFLOW_AVAILABLE = True
    except ImportError:
        # If neither works, create dummy functions
        TENSORFLOW_AVAILABLE = False
        def load_model(*args, **kwargs):
            return None
        def pad_sequences(*args, **kwargs):
            return None
        def tokenizer_from_json(*args, **kwargs):
            return None

# Google GenerativeAI import with fallback
try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    genai = None
    GEMINI_AVAILABLE = False

logger = logging.getLogger(__name__)

MAXLEN = 100  # نفس اللي استخدمته في التدريب

class PhishingDetectionRequest(BaseModel):
    url: str
    include_analysis: Optional[bool] = True
    check_reputation: Optional[bool] = True

class PhishingDetectionResponse(BaseModel):
    classification: str
    confidence: float
    risk_score: float
    analysis_details: Dict[str, Any]
    recommendations: List[str]

class PhishingDetector:
    def __init__(self, model_path: Optional[str] = None, tokenizer_path: Optional[str] = None):
        self.model_path = model_path or "backend/models/phishing_detector.keras"
        self.tokenizer_path = tokenizer_path or "backend/models/tokenizer.json"
        self.model = None
        self.tokenizer = None
        self.classifications = ["Safe", "Suspicious", "Malicious"]
        self._load_model()

    def _load_model(self):
        """تحميل الموديل و الـ tokenizer"""
        if not TENSORFLOW_AVAILABLE:
            logger.error("❌ TensorFlow/Keras not available")
            self.model = None
            self.tokenizer = None
            return
            
        try:
            # Check if model file exists
            if not os.path.exists(self.model_path):
                logger.error(f"❌ Model file not found: {self.model_path}")
                self.model = None
                self.tokenizer = None
                return
            
            if not os.path.exists(self.tokenizer_path):
                logger.error(f"❌ Tokenizer file not found: {self.tokenizer_path}")
                self.model = None
                self.tokenizer = None
                return
            
            self.model = load_model(self.model_path)
            with open(self.tokenizer_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                # Convert dict to JSON string before passing to tokenizer_from_json
                self.tokenizer = tokenizer_from_json(json.dumps(data))
            logger.info("✅ Keras model and tokenizer loaded successfully.")
        except Exception as e:
            logger.error(f"❌ Failed to load model/tokenizer: {e}")
            # Set to None to prevent errors in prediction
            self.model = None
            self.tokenizer = None

    def _preprocess_for_model(self, url: str) -> np.ndarray:
        """تجهيز URL بنفس طريقة التدريب"""
        if self.tokenizer is None:
            logger.error("❌ Tokenizer not loaded")
            # Return dummy data to prevent crashes
            return np.zeros((1, MAXLEN), dtype=np.int32)
            
        url = str(url).lower().strip()
        parsed = urlparse(url)
        clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        domain = parsed.netloc or ""
        path = parsed.path or ""
        final_url = domain + " " + path.replace("/", " / ")

        seq = self.tokenizer.texts_to_sequences([final_url])
        padded = pad_sequences(seq, maxlen=MAXLEN, padding="post", truncating="post")
        return padded

    def _virus_total_lookup(self, url: str) -> Dict[str, Any]:
        """استعلام VirusTotal API"""
        vt_key = os.getenv("Virustotal_API_KEY")
        if not vt_key:
            logger.warning("⚠️ VirusTotal API key not found.")
            return {}

        headers = {"x-apikey": vt_key}
        try:
            r = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
            analysis_id = r.json()["data"]["id"]
            report = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers).json()
            return report
        except Exception as e:
            logger.error(f"❌ VirusTotal lookup failed: {e}")
            return {}

    def _ask_gemini(self, local_pred: float, vt_result: Dict[str, Any], url: str) -> Dict[str, Any]:
        """إرسال النتائج إلى Gemini لتحليل نهائي"""
        if not GEMINI_AVAILABLE or genai is None:
            logger.warning("⚠️ Google GenerativeAI not available")
            return {
                "classification": "Safe" if local_pred < 0.4 else "Suspicious" if local_pred < 0.7 else "Malicious",
                "confidence": float(local_pred),
                "risk_score": float(local_pred),
                "recommendations": ["Manual review required - AI analysis unavailable"]
            }
            
        gemini_key = os.getenv("GOOGLE_API_KEY")
        if not gemini_key:
            logger.error("❌ GEMINI_API_KEY not found in environment.")
            return {
                "classification": "Safe" if local_pred < 0.4 else "Suspicious" if local_pred < 0.7 else "Malicious",
                "confidence": float(local_pred),
                "risk_score": float(local_pred),
                "recommendations": ["Manual review required - API key not found"]
            }

        try:
            genai.configure(api_key=gemini_key)
            model = genai.GenerativeModel("models/gemini-1.5-pro")
        except Exception as e:
            logger.error(f"❌ Failed to configure Gemini: {e}")
            return {
                "classification": "Safe" if local_pred < 0.4 else "Suspicious" if local_pred < 0.7 else "Malicious",
                "confidence": float(local_pred),
                "risk_score": float(local_pred),
                "recommendations": ["Manual review required - Gemini configuration failed"]
            }

        if local_pred > 0.7:
            local_class = "Malicious"
        elif local_pred > 0.4:
            local_class = "Suspicious"
        else:
            local_class = "Safe"

        prompt = f"""
        Analyze the following phishing detection information and decide the final classification.
        - URL: {url}
        - Local model prediction: {local_class} (score: {local_pred:.2f})
        - VirusTotal raw result: {json.dumps(vt_result)}

        Return ONLY a JSON object with keys:
        classification (Safe/Suspicious/Malicious),
        confidence (0-1),
        risk_score (0-1),
        recommendations (list of strings)
        """

        try:
            response = model.generate_content(prompt)
            text = response.text.strip()
            return json.loads(text)
        except Exception as e:
            logger.error(f"❌ Gemini analysis failed: {e}")
            return {
                "classification": local_class,
                "confidence": float(local_pred),
                "risk_score": float(local_pred),
                "recommendations": ["Manual review required."]
            }

    def detect_phishing(self, request: PhishingDetectionRequest) -> PhishingDetectionResponse:
        """التحليل الكامل للـ URL"""
        try:
            # Check if model is loaded
            if self.model is None:
                logger.error("❌ Model not loaded")
                return PhishingDetectionResponse(
                    classification="Error",
                    confidence=0.0,
                    risk_score=0.0,
                    analysis_details={"error": "Model not loaded"},
                    recommendations=["Model loading failed - manual review required"]
                )
            
            # 1️⃣ تجهيز الداتا وإرسالها للموديل
            padded = self._preprocess_for_model(request.url)
            prediction = float(self.model.predict(padded)[0][0])

            # 2️⃣ فحص VirusTotal (اختياري)
            vt_result = self._virus_total_lookup(request.url) if request.check_reputation else {}

            # 3️⃣ تحليل Gemini (قرار نهائي)
            gemini_decision = self._ask_gemini(prediction, vt_result, request.url)

            return PhishingDetectionResponse(
                classification=gemini_decision.get("classification", "Unknown"),
                confidence=gemini_decision.get("confidence", prediction),
                risk_score=gemini_decision.get("risk_score", prediction),
                analysis_details={
                    "local_prediction": prediction,
                    "virustotal": vt_result,
                    "gemini_raw": gemini_decision
                },
                recommendations=gemini_decision.get("recommendations", [])
            )

        except Exception as e:
            logger.error(f"❌ Error in phishing detection: {e}")
            raise

    def detect_batch(self, urls: List[PhishingDetectionRequest]) -> List[PhishingDetectionResponse]:
        results = []
        for url_request in urls:
            try:
                results.append(self.detect_phishing(url_request))
            except Exception as e:
                logger.error(f"Batch detection error: {e}")
                results.append(
                    PhishingDetectionResponse(
                        classification="Error",
                        confidence=0.0,
                        risk_score=0.0,
                        analysis_details={"error": str(e)},
                        recommendations=["Detection failed"]
                    )
                )
        return results

    def get_model_info(self) -> Dict[str, Any]:
        return {
            "model_name": "PhishingDetector-Keras",
            "model_type": "keras_binary",
            "version": "1.0.0",
            "status": "loaded" if self.model else "not_loaded"
        }
