import logging
import os
import json
from typing import Dict, List, Any, Optional, Union

import joblib
import numpy as np
import pandas as pd
from pydantic import BaseModel

from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import IncrementalPCA
from sklearn.ensemble import IsolationForest

# ============================================================
# Support class from training script
# ============================================================

class DataPreprocessorTransformer:
    def __init__(self, columns_to_drop=None, skewed_features=None):
        self.columns_to_drop = columns_to_drop or [
            "IPV4_SRC_ADDR", "L4_SRC_PORT", "L4_DST_PORT",
            "IPV4_DST_ADDR", "DNS_QUERY_ID", "FTP_COMMAND_RET_CODE",
            "PROTOCOL", "Attack", "Label"
        ]
        self.skewed_features = skewed_features or ['SRC_TO_DST_SECOND_BYTES']
        self.feature_names_ = None

    def fit(self, X, y=None):
        if isinstance(X, pd.DataFrame):
            X_clean = X.drop(columns=self.columns_to_drop, errors='ignore')
            self.feature_names_ = X_clean.columns.tolist()
        return self

    def transform(self, X):
        if isinstance(X, pd.DataFrame):
            X = X.copy()
            X = X.drop(columns=self.columns_to_drop, errors='ignore')
            X = X.fillna(0)
            for col in self.skewed_features:
                if col in X.columns:
                    X[col] = np.log1p(X[col])
            if self.feature_names_ is not None:
                X = X[self.feature_names_]
            return X.values
        return X


# ============================================================
# Main pipeline class
# ============================================================

class AnomalyDetectionPipeline:
    def __init__(self):
        self.pipeline = Pipeline([
            ('preprocessor', DataPreprocessorTransformer()),
            ('scaler', StandardScaler()),
            ('pca', IncrementalPCA(n_components=20)),
            ('model', IsolationForest(
                n_estimators=100,
                contamination=0.1,
                max_samples='auto',
                random_state=42,
                n_jobs=-1
            ))
        ])
        self.is_fitted_ = False

    def predict(self, X):
        preds = self.pipeline.predict(X)
        return np.where(preds == 1, 0, 1)

    @staticmethod
    def load(filepath):
        import __main__
        # مهم جدًا علشان joblib يعرف الكلاسات وقت التحميل
        from backend.models.log_classifier import DataPreprocessorTransformer, AnomalyDetectionPipeline
        __main__.DataPreprocessorTransformer = DataPreprocessorTransformer
        __main__.AnomalyDetectionPipeline = AnomalyDetectionPipeline
        return joblib.load(filepath)


logger = logging.getLogger(__name__)


# ============================================================
# Pydantic Models
# ============================================================

class LogClassificationRequest(BaseModel):
    log_data: Union[str, List[str], Dict[str, Any]]
    log_type: Optional[str] = "network"
    include_confidence: Optional[bool] = True


class LogClassificationResponse(BaseModel):
    classification: str
    confidence: float
    labels: List[str]
    details: Dict[str, Any]
    log_type: str


# ============================================================
# Classifier Class
# ============================================================

class LogClassifier:
    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or os.path.join(os.path.dirname(__file__), "anomaly_detection_pipeline.joblib")
        self.model = None
        self.feature_names = None
        self.labels = ["Normal", "Suspicious", "Malicious"]
        self.log_types = ["network", "system", "application"]
        self._load_model()

    def _load_model(self):
        try:
            if not os.path.exists(self.model_path):
                logger.warning(f"Model file not found: {self.model_path}")
                self.model = None
                return

            # ✅ الحل هنا
            import __main__
            from backend.models.log_classifier import DataPreprocessorTransformer, AnomalyDetectionPipeline
            __main__.DataPreprocessorTransformer = DataPreprocessorTransformer
            __main__.AnomalyDetectionPipeline = AnomalyDetectionPipeline

            self.model = joblib.load(self.model_path)
            logger.info(f"✅ Loaded anomaly pipeline from {self.model_path}")

            # حاول استخراج أسماء الخصائص
            pre = None
            if hasattr(self.model, 'pipeline') and hasattr(self.model.pipeline, 'named_steps'):
                pre = self.model.pipeline.named_steps.get('preprocessor')
            elif hasattr(self.model, 'named_steps'):
                pre = self.model.named_steps.get('preprocessor')

            if pre is not None and hasattr(pre, 'feature_names_'):
                self.feature_names = list(pre.feature_names_)
                logger.info(f"Detected {len(self.feature_names)} input features.")
            else:
                logger.warning("Could not detect preprocessor.feature_names_. Structured inputs may fail.")

        except Exception as e:
            logger.exception(f"Failed to load model: {e}")
            self.model = None

    # ============================================================
    # Feature Processing
    # ============================================================

    def preprocess_log(self, log_data: Union[str, List[str], Dict[str, Any]]) -> str:
        if isinstance(log_data, str):
            return log_data.strip()
        elif isinstance(log_data, list):
            return " ".join(str(x) for x in log_data)
        elif isinstance(log_data, dict):
            return json.dumps(log_data, sort_keys=True)
        else:
            return str(log_data)

    def _text_to_features(self, text: str) -> np.ndarray:
        length = len(text)
        digits = sum(c.isdigit() for c in text)
        symbols = sum(1 for c in text if not c.isalnum() and not c.isspace())
        words = len(text.split())
        uniq_chars = len(set(text))
        avg_word_len = (sum(len(w) for w in text.split()) / (words + 1e-6)) if words else 0.0

        feats = np.array([[length, words, avg_word_len, digits / (length + 1e-6),
                           symbols / (length + 1e-6), uniq_chars]])
        return feats

    def _dict_to_row(self, d: Dict[str, Any]) -> pd.DataFrame:
        if not self.feature_names:
            raise ValueError("Feature names not available in loaded pipeline.")
        row = {k: 0 for k in self.feature_names}
        for k, v in d.items():
            if k in row:
                try:
                    row[k] = float(v)
                except Exception:
                    row[k] = 0
        return pd.DataFrame([row], columns=self.feature_names)

    def _get_decision_score(self, X):
        try:
            if hasattr(self.model, 'decision_function'):
                return self.model.decision_function(X)
            if hasattr(self.model, 'named_steps'):
                for name in ['clf', 'estimator', 'classifier', 'isolationforest', 'iforest']:
                    if name in self.model.named_steps:
                        step = self.model.named_steps[name]
                        if hasattr(step, 'decision_function'):
                            return step.decision_function(X)
                last = list(self.model.named_steps.values())[-1]
                if hasattr(last, 'decision_function'):
                    return last.decision_function(X)
            return np.zeros(len(X))
        except Exception as e:
            logger.warning(f"Could not obtain decision scores: {e}")
            return np.zeros(len(X))

    # ============================================================
    # Classification Logic
    # ============================================================

    def classify_log(self, request: LogClassificationRequest) -> LogClassificationResponse:
        try:
            if isinstance(request.log_data, dict) and self.feature_names:
                intersection = set(request.log_data.keys()).intersection(set(self.feature_names))
                if len(intersection) >= max(1, len(self.feature_names) // 4):
                    row_df = self._dict_to_row(request.log_data)
                    if self.model:
                        pred = self.model.predict(row_df)[0]
                        score = float(self._get_decision_score(row_df)[0])
                        confidence = float(np.clip(1 - abs(score), 0, 1))
                        classification, labels = self._interpret_prediction(pred, confidence)
                    else:
                        classification, confidence, labels = self._mock_classify(self.preprocess_log(request.log_data), request.log_type)
                    return LogClassificationResponse(
                        classification=classification,
                        confidence=confidence,
                        labels=labels,
                        details={"method": "structured_mapping", "used_keys": list(intersection)},
                        log_type=request.log_type
                    )

            processed_text = self.preprocess_log(request.log_data)
            text_feats = self._text_to_features(processed_text)

            if self.feature_names and text_feats.shape[1] == len(self.feature_names):
                df = pd.DataFrame(text_feats, columns=self.feature_names)
                if self.model:
                    pred = self.model.predict(df)[0]
                    score = float(self._get_decision_score(df)[0])
                    confidence = float(np.clip(1 - abs(score), 0, 1))
                    classification, labels = self._interpret_prediction(pred, confidence)
                    return LogClassificationResponse(
                        classification=classification,
                        confidence=confidence,
                        labels=labels,
                        details={"method": "text_to_features_exact_match"},
                        log_type=request.log_type
                    )

            if self.model and self.feature_names:
                k = len(self.feature_names)
                vec = np.tile(text_feats.flatten(), int(np.ceil(k / text_feats.shape[1])))[:k]
                df = pd.DataFrame([vec], columns=self.feature_names)
                pred = self.model.predict(df)[0]
                score = float(self._get_decision_score(df)[0])
                confidence = float(np.clip(1 - abs(score), 0, 1))
                classification, labels = self._interpret_prediction(pred, confidence)
                return LogClassificationResponse(
                    classification=classification,
                    confidence=confidence,
                    labels=labels,
                    details={"method": "text_to_features_tiled_to_structured"},
                    log_type=request.log_type
                )

            classification, confidence, labels = self._mock_classify(processed_text, request.log_type)
            return LogClassificationResponse(
                classification=classification,
                confidence=confidence,
                labels=labels,
                details={"method": "heuristic_fallback"},
                log_type=request.log_type
            )

        except Exception as e:
            logger.exception(f"Error in classify_log: {e}")
            return LogClassificationResponse(
                classification="Error",
                confidence=0.0,
                labels=["classification_failed"],
                details={"error": str(e)},
                log_type=request.log_type
            )

    # ============================================================
    # Helpers
    # ============================================================

    def _interpret_prediction(self, pred_value: int, confidence: float):
        if pred_value == -1:
            if confidence > 0.8:
                return "Malicious", ["malicious_activity", "security_threat"]
            else:
                return "Suspicious", ["anomaly_detected", "requires_review"]
        else:
            return "Normal", ["normal_operation"]

    def _mock_classify(self, log_text: str, log_type: str):
        suspicious_keywords = ["error", "failed", "denied", "blocked", "attack", "timeout"]
        malicious_keywords = ["malware", "virus", "trojan", "exploit", "payload", "ransom"]
        text = log_text.lower()
        if any(k in text for k in malicious_keywords):
            return "Malicious", 0.95, ["malware_detected", "security_threat"]
        elif any(k in text for k in suspicious_keywords):
            return "Suspicious", 0.75, ["anomaly_detected", "requires_review"]
        else:
            return "Normal", 0.85, ["normal_operation"]

    def classify_batch(self, logs: List[LogClassificationRequest]) -> List[LogClassificationResponse]:
        results = []
        for i, r in enumerate(logs):
            try:
                results.append(self.classify_log(r))
            except Exception as e:
                logger.error(f"Batch item {i} failed: {e}", exc_info=True)
                results.append(LogClassificationResponse(
                    classification="Error",
                    confidence=0.0,
                    labels=["classification_failed"],
                    details={"error": str(e)},
                    log_type=r.log_type
                ))
        return results

    def get_model_info(self) -> Dict[str, Any]:
        return {
            "model_name": os.path.basename(self.model_path),
            "model_type": "IsolationForest_pipeline",
            "version": "1.0",
            "loaded": bool(self.model),
            "n_expected_features": len(self.feature_names) if self.feature_names else None
        }
