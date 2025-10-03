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

logger = logging.getLogger(__name__)

# Optional import: allow server to start without the SDK
try:
	import google.generativeai as genai  # type: ignore
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
			api_key: Gemini API key (if None, will try to get from environment)
		"""
		self.api_key = api_key or os.getenv('GEMINI_API_KEY')
		self.model = None
		
		if not self.api_key:
			logger.warning("GEMINI_API_KEY not set; AI explanations will use fallback responses.")
		elif genai is None:
			logger.warning("Gemini SDK not available; AI explanations will use fallback responses.")
		else:
			try:
				os.environ["GOOGLE_API_KEY"] = self.api_key
				# Prefer GenerativeModel if available; otherwise fall back to Client
				self.model = None
				self.client = None
				self._use_client = False
				if hasattr(genai, 'GenerativeModel'):
					self.model = genai.GenerativeModel('models/gemini-2.5-pro')
				elif hasattr(genai, 'Client'):
					self.client = genai.Client(api_key=self.api_key)
					self._use_client = True
				else:
					raise RuntimeError("google.generativeai SDK missing required classes")
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
		"""Generate response from Gemini or raise to trigger fallbacks"""
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
			raise RuntimeError("Gemini model unavailable")
		except Exception as e:  # pragma: no cover
			logger.error(f"Error generating Gemini response: {e}")
			raise
	
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

# Global client instance
_gemini_client = None

def get_gemini_client() -> GeminiClient:
	"""Get the global Gemini client instance (singleton pattern)"""
	global _gemini_client
	if _gemini_client is None:
		_gemini_client = GeminiClient()
	return _gemini_client
