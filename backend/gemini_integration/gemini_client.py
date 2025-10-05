"""
Gemini Client for AI explanations and analysis
Integrates with Google's Gemini-2.5-Pro API
"""

import os
import logging
from typing import Dict, Any, Optional, List
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get Google API key from environment
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
if not GOOGLE_API_KEY:
	raise ValueError("❌ GOOGLE_API_KEY not found in environment variables. Please set GOOGLE_API_KEY in your .env file or environment.")

logger = logging.getLogger(__name__)

# Optional import: allow server to start without the SDK
try:
	import google.generativeai as genai  # type: ignore
	# Configure Gemini with the API key
	genai.configure(api_key=GOOGLE_API_KEY)
	logger.info("✅ Gemini API configured successfully")
except Exception as e:  # pragma: no cover
	genai = None
	logger.warning("google.generativeai not available; falling back to non-AI explanations. Install 'google-generativeai' to enable.")

class GeminiClient:
	"""
	Client for interacting with Google's Gemini-1.5-Pro API
	"""
	
	def __init__(self, api_key: Optional[str] = None):
		"""
		Initialize Gemini client
		
		Args:
			api_key: Gemini API key (if None, will use the pre-configured key)
		"""
		self.api_key = api_key or GOOGLE_API_KEY
		self.model = None
		
		if genai is None:
			logger.warning("Gemini SDK not available; AI explanations will use fallback responses.")
		else:
			try:
				# Prefer GenerativeModel if available; otherwise fall back to Client
				self.model = None
				self.client = None
				self._use_client = False
				try:
					if hasattr(genai, 'GenerativeModel'):
						self.model = genai.GenerativeModel('models/gemini-2.5-pro')
					elif hasattr(genai, 'Client'):
						self.client = genai.Client(api_key=self.api_key)
						self._use_client = True
					else:
						# Use the pre-configured genai instance
						self.model = genai.GenerativeModel('models/gemini-2.5-pro')
				except Exception as e:
					logger.warning(f"Failed to initialize Gemini model: {e}")
					self.model = None
					self.client = None
					self._use_client = False
				logger.info("Gemini client initialized successfully")
			except Exception as e:  # pragma: no cover
				logger.warning(f"Failed to initialize Gemini model; using fallbacks: {e}")
				self.model = None
				self.client = None
				self._use_client = False
	
	async def get_explanation(
		self, 
		analysis_type: str,
		classification: str,
		confidence: float,
		raw_data: Any,
		analysis_details: Optional[Dict[str, Any]] = None
	) -> Dict[str, Any]:
		"""
		Get AI explanation for analysis results
		"""
		try:
			prompt = self._build_explanation_prompt(
				analysis_type, classification, confidence, raw_data, analysis_details
			)
			response = await self._generate_response(prompt)
			return self._parse_explanation_response(response, classification, confidence)
		except Exception as e:
			logger.error(f"Error getting Gemini explanation: {e}")
			return self._get_fallback_explanation(classification, confidence)

	async def get_final_url_verdict(
		self,
		*,
		url: str,
		model_result: Dict[str, Any],
		vt_result: Dict[str, Any]
	) -> Dict[str, Any]:
		"""Compute final URL verdict by combining model + VirusTotal using Gemini.

		Returns JSON with keys: final_label, threat_level, explanation, notes.
		"""
		try:
			prompt = self._build_final_verdict_prompt(url, model_result, vt_result)
			response = await self._generate_response(prompt)
			return self._parse_final_verdict_response(response, model_result, vt_result)
		except Exception as e:
			logger.error(f"Error getting final URL verdict from Gemini: {e}")
			return self._fallback_final_verdict(model_result, vt_result)

	def _build_final_verdict_prompt(self, url: str, model_result: Dict[str, Any], vt_result: Dict[str, Any]) -> str:
		"""Builds the decision prompt with explicit decision rules and required JSON fields."""
		from urllib.parse import urlparse
		domain = urlparse(url).netloc
		local_pred = float(model_result.get("score", 0.5))
		local_label = model_result.get("label", "Suspicious")
		prompt = f"""
You are a senior cybersecurity threat analyst. Your job is to make the **final phishing verdict** based on the following three sources of evidence:

1️⃣ Local AI Model Output:
- Classification: {local_label}
- Risk Score: {local_pred:.2f}

2️⃣ VirusTotal Report:
{str(vt_result)[:1500]}

3️⃣ URL Information:
{url}

📊 Your decision rules:
- If VirusTotal shows **any malicious detections (>=1)** → classify as at least **"Suspicious"**. Do NOT return "Safe".
- If model and VT both say malicious → **"Malicious"**.
- If model says safe but VT flags something → **"Suspicious"** (or **"Malicious"** if >5 detections).
- If model says suspicious/malicious but VirusTotal shows 0 detections AND the domain is a well-known legitimate service (e.g., github.com, google.com, openai.com, microsoft.com, cloudflare.com) → **"Likely False Positive"**.
- If both say safe and the domain is well-known legitimate → **"Safe"**.
- If results conflict but there’s **NO strong evidence of malicious behavior** → choose **"Suspicious"** with lower confidence.
- If you strongly suspect the model is overfitting or hallucinating → choose **"Likely False Positive"**.

Return ONLY a valid JSON object with the following keys:
- classification: (Safe, Suspicious, Malicious, Likely False Positive)
- confidence: (0-1 float, how confident you are in the decision)
- risk_score: (0-1 float overall risk assessment)
- threat_level: (Low, Medium, High)
- explanation: A short but clear explanation for why you made this decision.
- recommended_action: Clear step-by-step instructions on what the security team should do next.
"""
		return prompt

	def _parse_final_verdict_response(self, response: str, model_result: Dict[str, Any], vt_result: Dict[str, Any]) -> Dict[str, Any]:
		"""Parse the final verdict JSON; provide robust fallback if parsing fails."""
		import json
		try:
			parsed = json.loads(response)
			# Support both our schema and user's classification schema
			classification = parsed.get("final_label") or parsed.get("classification") or model_result.get("label", "Suspicious")
			final_label = classification
			threat_level = parsed.get("threat_level") or self._assess_threat_level(final_label, float(model_result.get("score", 0.5)))
			explanation = parsed.get("explanation") or "Combined decision based on model and VirusTotal."
			recommended_action = parsed.get("recommended_action")
			confidence = parsed.get("confidence")
			risk_score = parsed.get("risk_score")
			return {
				"final_label": final_label,
				"threat_level": threat_level,
				"explanation": explanation,
				"recommended_action": recommended_action,
				"confidence": confidence,
				"risk_score": risk_score,
			}
		except Exception:
			return self._fallback_final_verdict(model_result, vt_result, response)

	def _fallback_final_verdict(self, model_result: Dict[str, Any], vt_result: Dict[str, Any], raw: str = "") -> Dict[str, Any]:
		"""Heuristic fallback when Gemini is unavailable or parsing fails."""
		model_label = (model_result or {}).get("label", "Suspicious")
		score = float((model_result or {}).get("score", 0.5))
		vt_verdict = (vt_result or {}).get("verdict", "Unknown")
		detections = int((vt_result or {}).get("detections", 0))
		# Enforce conservative rule: any VT detections >=1 => at least Suspicious
		if detections >= 1:
			if detections > 5 or vt_verdict == "Malicious":
				final_label = "Malicious"
				threat = "High"
			else:
				final_label = "Suspicious"
				threat = "Medium"
		elif detections == 0 and model_label in ("Suspicious", "Malicious") and score >= 0.6:
			# Likely false positive on well-known/clean domains should be handled by LLM; fallback marks as likely FP
			final_label = "Likely False Positive"
			threat = "Low"
		elif vt_verdict in ("Safe", "Unknown") and score < 0.4:
			final_label = "Safe"
			threat = "Low"
		elif vt_verdict in ("Safe", "Unknown") and score >= 0.7:
			final_label = "Suspicious"
			threat = "Medium"
		else:
			final_label = model_label
			threat = self._assess_threat_level(model_label, score)
		expl = "Heuristic final verdict based on model and VirusTotal in fallback mode."
		notes = []
		if vt_verdict not in ("Unknown", final_label):
			notes.append("Model and VirusTotal differ; manual review recommended.")
		if raw:
			notes.append("AI response parsing failed; used fallback rules.")
		return {"final_label": final_label, "threat_level": threat, "explanation": expl, "notes": notes}
	
	async def get_threat_intelligence(
		self,
		threat_type: str,
		indicators: List[str],
		context: Optional[Dict[str, Any]] = None
	) -> Dict[str, Any]:
		"""Get threat intelligence context for detected threats"""
		try:
			prompt = self._build_threat_intelligence_prompt(threat_type, indicators, context)
			response = await self._generate_response(prompt)
			return self._parse_threat_intelligence_response(response)
		except Exception as e:
			logger.error(f"Error getting threat intelligence: {e}")
			return {"error": str(e), "fallback": True}
	
	async def get_remediation_steps(
		self,
		threat_level: str,
		threat_type: str,
		affected_systems: Optional[List[str]] = None
	) -> Dict[str, Any]:
		"""Get remediation steps for detected threats"""
		try:
			prompt = self._build_remediation_prompt(threat_level, threat_type, affected_systems)
			response = await self._generate_response(prompt)
			return self._parse_remediation_response(response)
		except Exception as e:
			logger.error(f"Error getting remediation steps: {e}")
			return {"error": str(e), "fallback": True}
	
	def _build_explanation_prompt(
		self,
		analysis_type: str,
		classification: str,
		confidence: float,
		raw_data: Any,
		analysis_details: Optional[Dict[str, Any]] = None
	) -> str:
		"""Build context-specific explanation prompt"""
		
		base_prompt = f"""
You are a cybersecurity expert AI assistant. Analyze the following {analysis_type} analysis result and provide a detailed explanation.

ANALYSIS RESULT:
- Classification: {classification}
- Confidence: {confidence:.2%}
- Analysis Type: {analysis_type}

RAW DATA:
{str(raw_data)[:1000]}  # Limit to prevent token overflow

"""
		
		if analysis_details:
			base_prompt += f"""
ANALYSIS DETAILS:
{str(analysis_details)[:1000]}

"""
		
		base_prompt += """
Please provide:
1. A clear explanation of what this classification means
2. Why the system classified it this way
3. The confidence level interpretation
4. Recommended actions based on the classification
5. Any additional context or warnings

Format your response as JSON with these fields:
- "explanation": Detailed explanation
- "confidence_interpretation": What the confidence level means
- "recommended_action": Specific recommended actions
- "additional_context": Any additional relevant information
- "threat_level": Assessed threat level (Low/Medium/High/Critical)
"""
		return base_prompt
	
	def _build_threat_intelligence_prompt(
		self,
		threat_type: str,
		indicators: List[str],
		context: Optional[Dict[str, Any]] = None
	) -> str:
		"""Build threat intelligence prompt"""
		
		prompt = f"""
You are a cybersecurity threat intelligence expert. Provide threat intelligence context for the following:

THREAT TYPE: {threat_type}
INDICATORS: {', '.join(indicators)}

"""
		
		if context:
			prompt += f"ADDITIONAL CONTEXT: {str(context)[:500]}\n"
		
		prompt += """
Provide threat intelligence information including:
1. Known threat patterns and behaviors
2. Historical context and prevalence
3. Potential attack vectors
4. Related threat actors or campaigns
5. Industry-specific implications

Format as JSON with:
- "threat_patterns": Known patterns
- "historical_context": Historical information
- "attack_vectors": Potential attack methods
- "threat_actors": Related actors/campaigns
- "industry_impact": Industry-specific implications
"""
		return prompt
	
	def _build_remediation_prompt(
		self,
		threat_level: str,
		threat_type: str,
		affected_systems: Optional[List[str]] = None
	) -> str:
		"""Build remediation steps prompt"""
		
		prompt = f"""
You are a cybersecurity incident response expert. Provide remediation steps for:

THREAT LEVEL: {threat_level}
THREAT TYPE: {threat_type}

"""
		
		if affected_systems:
			prompt += f"AFFECTED SYSTEMS: {', '.join(affected_systems)}\n"
		
		prompt += """
Provide comprehensive remediation steps including:
1. Immediate containment actions
2. Investigation steps
3. System hardening measures
4. Monitoring and detection improvements
5. Long-term prevention strategies

Format as JSON with:
- "immediate_actions": Urgent steps to take
- "investigation_steps": How to investigate further
- "containment_measures": How to contain the threat
- "hardening_recommendations": System hardening steps
- "monitoring_improvements": Detection improvements
- "prevention_strategies": Long-term prevention
"""
		return prompt
	
	async def _generate_response(self, prompt: str) -> str:
		"""Generate response from Gemini or return fallback"""
		try:
			if getattr(self, '_use_client', False) and self.client is not None:
				response = self.client.models.generate_content(model='models/gemini-2.5-pro', contents=prompt)
				# client API may return dict-like structures
				text = getattr(response, 'text', None)
				if text is None and hasattr(response, 'candidates') and response.candidates:
					text = getattr(response.candidates[0], 'content', None)
				return text or str(response)
			elif self.model is not None:
				response = self.model.generate_content(prompt)
				return response.text
			else:
				# Return fallback response when Gemini is not available
				return self._get_fallback_ai_response(prompt)
		except Exception as e:  # pragma: no cover
			logger.error(f"Error generating Gemini response: {e}")
			# Return fallback response instead of raising
			return self._get_fallback_ai_response(prompt)
	
	def _parse_explanation_response(self, response: str, classification: str, confidence: float) -> Dict[str, Any]:
		"""Parse explanation response from Gemini"""
		try:
			import json
			parsed = json.loads(response)
			return parsed
		except Exception:
			return {
				"explanation": response,
				"confidence_interpretation": f"Confidence of {confidence:.2%} indicates {'high' if confidence > 0.8 else 'moderate' if confidence > 0.6 else 'low'} certainty",
				"recommended_action": self._get_default_recommendation(classification),
				"additional_context": "AI-generated explanation based on analysis results",
				"threat_level": self._assess_threat_level(classification, confidence)
			}
	
	def _parse_threat_intelligence_response(self, response: str) -> Dict[str, Any]:
		"""Parse threat intelligence response"""
		try:
			import json
			return json.loads(response)
		except Exception:
			return {
				"threat_patterns": "AI-generated threat intelligence analysis",
				"historical_context": response,
				"attack_vectors": "Multiple potential attack vectors identified",
				"threat_actors": "Analysis of potential threat actors",
				"industry_impact": "Industry-specific threat implications"
			}
	
	def _parse_remediation_response(self, response: str) -> Dict[str, Any]:
		"""Parse remediation response"""
		try:
			import json
			return json.loads(response)
		except Exception:
			return {
				"immediate_actions": "Take immediate security measures",
				"investigation_steps": response,
				"containment_measures": "Implement containment procedures",
				"hardening_recommendations": "Apply security hardening",
				"monitoring_improvements": "Enhance monitoring capabilities",
				"prevention_strategies": "Implement long-term prevention"
			}
	
	def _get_fallback_explanation(self, classification: str, confidence: float) -> Dict[str, Any]:
		"""Get fallback explanation when Gemini is unavailable"""
		return {
			"explanation": f"Analysis classified as {classification} with {confidence:.2%} confidence. AI explanation unavailable.",
			"confidence_interpretation": f"Confidence of {confidence:.2%} indicates {'high' if confidence > 0.8 else 'moderate' if confidence > 0.6 else 'low'} certainty",
			"recommended_action": self._get_default_recommendation(classification),
			"additional_context": "AI explanation service unavailable",
			"threat_level": self._assess_threat_level(classification, confidence)
		}
	
	def _get_default_recommendation(self, classification: str) -> str:
		"""Get default recommendation based on classification"""
		recommendations = {
			"Malicious": "Immediate action required. Isolate affected systems and investigate further.",
			"Suspicious": "Monitor closely and investigate. Consider additional security measures.",
			"Safe": "No immediate action required. Continue normal monitoring.",
			"Normal": "No action required. This appears to be normal activity."
		}
		return recommendations.get(classification, "Review and investigate as needed.")
	
	def _assess_threat_level(self, classification: str, confidence: float) -> str:
		"""Assess threat level based on classification and confidence"""
		if classification in ["Malicious"] and confidence > 0.8:
			return "Critical"
		elif classification in ["Malicious", "Suspicious"] and confidence > 0.6:
			return "High"
		elif classification in ["Suspicious"] or confidence < 0.6:
			return "Medium"
		else:
			return "Low"
	
	def _get_fallback_ai_response(self, prompt: str) -> str:
		"""Provide fallback AI response when Gemini is unavailable"""
		# Analyze the prompt to provide a relevant fallback response
		prompt_lower = prompt.lower()
		
		if "explain" in prompt_lower or "analysis" in prompt_lower:
			return """**AI Analysis (Fallback Mode)**

Based on the provided data, here's my cybersecurity analysis:

**Key Findings:**
- The system has detected potential security indicators that require attention
- Analysis shows various patterns that suggest both normal and potentially suspicious activity
- Confidence levels indicate the reliability of the detection

**Recommendations:**
1. **Immediate Action**: Review the flagged items for any immediate threats
2. **Investigation**: Conduct deeper analysis of suspicious patterns
3. **Monitoring**: Enhance monitoring for similar indicators
4. **Documentation**: Document findings for future reference

**Note**: This is a fallback analysis. For advanced AI-powered insights, please configure the Google API key.

**Next Steps:**
- Set up GEMINI_API_KEY environment variable for enhanced AI analysis
- Review the detailed findings in the analysis results
- Implement recommended security measures based on the findings"""
		
		elif "correlate" in prompt_lower or "correlation" in prompt_lower:
			return """**Correlation Analysis (Fallback Mode)**

**Temporal Patterns:**
- Analysis of time-based indicators shows potential clustering of events
- Some activities appear to follow predictable patterns

**Behavioral Correlations:**
- Similar attack vectors or techniques detected across different indicators
- Consistent patterns in the observed activities

**Infrastructure Correlations:**
- Shared infrastructure elements identified across multiple indicators
- Common network characteristics or domains

**Recommendations:**
1. Investigate shared infrastructure elements
2. Look for common attack patterns
3. Check for coordinated activities
4. Review temporal clustering for potential campaigns

**Note**: Enhanced correlation analysis available with Google API key configuration."""
		
		else:
			return """**Cybersecurity Analysis (Fallback Mode)**

**Summary:**
The system has analyzed the provided cybersecurity data and identified several key indicators that require attention.

**Key Points:**
- Multiple security indicators have been detected
- Various confidence levels suggest different degrees of certainty
- Both automated and manual review may be necessary

**Immediate Actions:**
1. Review all flagged items for immediate threats
2. Investigate high-confidence detections first
3. Document findings for security team review
4. Implement appropriate security measures

**Long-term Recommendations:**
1. Enhance monitoring capabilities
2. Improve detection accuracy
3. Develop response procedures
4. Regular security assessments

**Note**: For advanced AI-powered analysis with detailed explanations, threat intelligence, and remediation steps, please configure the GEMINI_API_KEY environment variable."""

# Global client instance
_gemini_client = None

def get_gemini_client() -> GeminiClient:
	"""Get the global Gemini client instance (singleton pattern)"""
	global _gemini_client
	if _gemini_client is None:
		_gemini_client = GeminiClient()
	return _gemini_client
