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
from utils.validation_utils import validate_url  # URL validation and basic sanitization
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
        """Prepare URL text similar to training: normalize case, scheme, and tokenization.

        Returns a padded sequence; falls back to zeros if tokenizer is unavailable.
        """
        if self.tokenizer is None:
            logger.error("❌ Tokenizer not loaded")
            return np.zeros((1, MAXLEN), dtype=np.int32)

        normalized_url = str(url).strip().lower()
        if not normalized_url.startswith(("http://", "https://")):
            normalized_url = "https://" + normalized_url

        parsed = urlparse(normalized_url)
        domain = parsed.netloc or ""
        path = parsed.path or ""
        # Split path with separators to retain structure cues
        tokenizable_text = (domain + " " + path.replace("/", " / ")).strip()

        seq = self.tokenizer.texts_to_sequences([tokenizable_text])
        padded = pad_sequences(seq, maxlen=MAXLEN, padding="post", truncating="post")
        return padded

    def _virus_total_lookup(self, url: str) -> Dict[str, Any]:
        """Query VirusTotal URL analysis with safe timeouts and error handling."""
        vt_key = os.getenv("Virustotal_API_KEY")
        if not vt_key:
            logger.warning("⚠️ VirusTotal API key not found.")
            return {}

        headers = {"x-apikey": vt_key}
        try:
            submit = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=10,
            )
            if submit.status_code == 429:
                logger.warning("⚠️ VirusTotal rate limit reached (429)")
                return {"error": "rate_limited"}
            submit.raise_for_status()
            analysis_id = submit.json().get("data", {}).get("id")
            if not analysis_id:
                return {"error": "no_analysis_id", "raw": submit.text}

            report_resp = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=10,
            )
            if report_resp.status_code == 429:
                logger.warning("⚠️ VirusTotal rate limit reached on report (429)")
                return {"error": "rate_limited"}
            report_resp.raise_for_status()
            return report_resp.json()
        except requests.exceptions.Timeout:
            logger.error("❌ VirusTotal lookup timed out")
            return {"error": "timeout"}
        except requests.exceptions.RequestException as e:
            logger.error(f"❌ VirusTotal lookup failed: {e}")
            return {"error": "request_failed", "message": str(e)}

    def _parse_vt_verdict(self, vt_result: Dict[str, Any]) -> Dict[str, Any]:
        """Summarize VirusTotal analysis into detections and verdict."""
        if not vt_result or vt_result.get("error"):
            return {
                "verdict": "Unknown",
                "detections": 0,
                "stats": {},
                "summary": vt_result.get("error") if isinstance(vt_result, dict) else "unavailable",
            }

        try:
            attrs = vt_result.get("data", {}).get("attributes", {})
            stats = attrs.get("stats", {})
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            undetected = int(stats.get("undetected", 0))
            harmless = int(stats.get("harmless", 0))
            detections = malicious + suspicious

            if malicious > 0:
                verdict = "Malicious"
            elif suspicious > 0:
                verdict = "Suspicious"
            elif harmless > 0 and detections == 0:
                verdict = "Safe"
            else:
                verdict = "Unknown"

            return {
                "verdict": verdict,
                "detections": detections,
                "stats": stats,
                "summary": f"{malicious} malicious, {suspicious} suspicious, {harmless} harmless, {undetected} undetected",
            }
        except Exception as e:
            logger.error(f"❌ Failed to parse VirusTotal result: {e}")
            return {"verdict": "Unknown", "detections": 0, "stats": {}, "summary": "parse_error"}

    @staticmethod
    def _label_from_score(score: float) -> str:
        if score > 0.7:
            return "Malicious"
        if score > 0.4:
            return "Suspicious"
        return "Safe"

    @staticmethod
    def _reason_from_features(url: str, score: float, vt_summary: Optional[Dict[str, Any]] = None) -> str:
        # Lightweight heuristic reasoning to aid UI
        hints: list[str] = []
        if re.search(r"\d{1,3}(?:\.\d{1,3}){3}", url):
            hints.append("URL contains raw IP address")
        if any(tld in url for tld in [".tk", ".ml", ".ga", ".cf", ".gq"]):
            hints.append("Suspicious TLD present")
        if "@" in url or "//" in url[8:]:  # after scheme
            hints.append("Potential obfuscation patterns")
        if vt_summary and vt_summary.get("detections", 0) > 0:
            hints.append(f"VirusTotal engines flagged: {vt_summary['detections']}")
        if not hints:
            return f"Model risk score {score:.2f} with no obvious red flags detected"
        return f"Model risk score {score:.2f}. Indicators: " + "; ".join(hints)

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

        local_class = self._label_from_score(local_pred)

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
        """Full URL analysis: validate, model predict, VirusTotal reputation, and structured summary."""
        try:
            # 0️⃣ Validate URL early
            validation = validate_url(request.url)
            if not validation.get("valid"):
                return PhishingDetectionResponse(
                    classification="Error",
                    confidence=0.0,
                    risk_score=0.0,
                    analysis_details={"error": validation.get("error", "invalid_url"), "url": request.url},
                    recommendations=["Provide a valid URL including domain."]
                )

            # Ensure model availability
            if self.model is None:
                logger.error("❌ Model not loaded")
                return PhishingDetectionResponse(
                    classification="Error",
                    confidence=0.0,
                    risk_score=0.0,
                    analysis_details={"error": "model_not_loaded"},
                    recommendations=["Model loading failed - manual review required"]
                )

            # 1️⃣ Model prediction
            padded = self._preprocess_for_model(request.url)
            prediction = float(self.model.predict(padded)[0][0])
            model_label = self._label_from_score(prediction)

            # 2️⃣ VirusTotal reputation (optional)
            vt_raw = self._virus_total_lookup(request.url) if request.check_reputation else {}
            vt_summary = self._parse_vt_verdict(vt_raw) if request.check_reputation else {"verdict": "Unknown", "detections": 0, "stats": {}, "summary": "disabled"}

            # 3️⃣ Notes/insights on disagreement
            notes: list[str] = []
            if request.check_reputation and vt_summary.get("verdict") != "Unknown" and vt_summary.get("verdict") != model_label:
                notes.append("Model and VirusTotal verdicts differ; consider manual review.")
                if vt_summary.get("detections", 0) == 0 and model_label in ("Suspicious", "Malicious"):
                    notes.append("Possible model false positive or VirusTotal not yet updated.")
                if vt_summary.get("detections", 0) > 0 and model_label == "Safe":
                    notes.append("Model may have missed indicators flagged by VT engines.")

            # Lightweight reasoning for model verdict
            reason = self._reason_from_features(request.url, prediction, vt_summary)

            # Build structured analysis details for frontend
            analysis = {
                "model": {
                    "score": prediction,
                    "label": model_label,
                    "reason": reason,
                },
                "virustotal": {
                    "verdict": vt_summary.get("verdict"),
                    "detections": vt_summary.get("detections"),
                    "stats": vt_summary.get("stats"),
                    "summary": vt_summary.get("summary"),
                },
                "notes": notes,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "url": request.url,
                # Keep raw under a nested key to avoid bloating the main object
                "raw": {"virustotal": vt_raw} if request.check_reputation else {},
            }

            # Recommendations based on risk
            recommendations: list[str] = []
            if model_label == "Malicious" or vt_summary.get("verdict") == "Malicious":
                recommendations = [
                    "Block the URL at network perimeter",
                    "Do not visit or submit credentials",
                    "Investigate related indicators (domains, IPs)"
                ]
            elif model_label == "Suspicious" or vt_summary.get("verdict") == "Suspicious":
                recommendations = [
                    "Open in isolated environment if needed",
                    "Perform manual verification and WHOIS/DNS checks"
                ]
            else:
                recommendations = ["No immediate action required. Continue monitoring."]

            # Return top-level focused on model verdict for clarity; details contain VT and notes
            return PhishingDetectionResponse(
                classification=model_label,
                confidence=float(prediction),
                risk_score=float(prediction),
                analysis_details=analysis,
                recommendations=recommendations,
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
