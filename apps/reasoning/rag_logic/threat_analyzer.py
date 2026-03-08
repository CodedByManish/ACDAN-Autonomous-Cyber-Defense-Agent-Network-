"""
LLM-based threat analysis and reasoning.
"""

import json
import re
from typing import Dict, List, Optional
import os
from datetime import datetime
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from agents.llm_reasoning.prompt_templates import (
    THREAT_ANALYSIS_PROMPT,
    CVE_CONTEXT_PROMPT,
    RESPONSE_RECOMMENDATION_PROMPT,
    SUMMARIZE_LOGS_PROMPT
)


class LLMThreatAnalyzer:
    """Threat analysis using LLMs."""
    
    def __init__(self, llm_type: str = "ollama", model_name: str = "mistral"):
        """
        Initialize threat analyzer.
        
        Args:
            llm_type: "ollama" or "huggingface"
            model_name: Model to use
        """
        self.llm_type = llm_type
        self.model_name = model_name
        self.llm_client = None
        
        self._initialize_llm()
    
    def _initialize_llm(self) -> None:
        """Initialize LLM client based on type."""
        if self.llm_type == "ollama":
            try:
                import ollama
                self.llm_client = ollama
                print(f"Initialized Ollama with model: {self.model_name}")
            except ImportError:
                print("⚠️  Ollama not installed. Using fallback LLM.")
                self.llm_client = None
        else:
            try:
                from transformers import pipeline
                self.llm_client = pipeline("text-generation", model=self.model_name)
                print(f"Initialized HuggingFace with model: {self.model_name}")
            except ImportError:
                print("⚠️  Transformers not installed. Using fallback LLM.")
                self.llm_client = None
    
    def analyze_threat(
        self,
        attack_type: str,
        confidence: float,
        source_ip: str,
        dest_ip: str,
        protocol: str,
        port: int,
        cve_context: Optional[str] = None
    ) -> Dict:
        """
        Analyze detected threat using LLM.
        
        Args:
            attack_type: Type of attack detected
            confidence: Confidence score (0-1)
            source_ip: Source IP address
            dest_ip: Destination IP address
            protocol: Network protocol
            port: Port number
            cve_context: Optional CVE context
            
        Returns:
            Threat analysis dictionary
        """
        # Build prompt
        prompt = THREAT_ANALYSIS_PROMPT.format(
            attack_type=attack_type,
            confidence=confidence,
            source_ip=source_ip,
            dest_ip=dest_ip,
            protocol=protocol,
            port=port
        )
        
        # Get LLM response
        response = self._call_llm(prompt)
        
        # Parse response
        analysis = self._parse_json_response(response)
        
        # If CVE context provided, enhance with CVE analysis
        if cve_context:
            analysis['cve_analysis'] = self._analyze_cve_context(
                analysis, cve_context
            )
        
        # Add metadata
        analysis['timestamp'] = datetime.now().isoformat()
        analysis['source_ip'] = source_ip
        analysis['dest_ip'] = dest_ip
        analysis['attack_type'] = attack_type
        
        return analysis
    
    def get_response_recommendation(
        self,
        threat_analysis: Dict
    ) -> Dict:
        """
        Get response recommendations for a threat.
        
        Args:
            threat_analysis: Threat analysis from analyze_threat()
            
        Returns:
            Response recommendations
        """
        # Build prompt
        prompt = RESPONSE_RECOMMENDATION_PROMPT.format(
            threat_analysis=json.dumps(threat_analysis, indent=2)
        )
        
        # Get LLM response
        response = self._call_llm(prompt)
        
        # Parse response
        recommendations = self._parse_json_response(response)
        
        return recommendations
    
    def _analyze_cve_context(
        self,
        threat_analysis: Dict,
        cve_context: str
    ) -> Dict:
        """Analyze threat with CVE context."""
        prompt = CVE_CONTEXT_PROMPT.format(
            threat_summary=threat_analysis.get('threat_summary', ''),
            cve_context=cve_context
        )
        
        response = self._call_llm(prompt)
        return self._parse_json_response(response)
    
    def summarize_logs(self, logs: str) -> str:
        """Summarize logs for threat indicators."""
        prompt = SUMMARIZE_LOGS_PROMPT.format(logs=logs)
        return self._call_llm(prompt)
    
    def _call_llm(self, prompt: str, max_tokens: int = 1000) -> str:
        """
        Call LLM with prompt.
        
        Args:
            prompt: Prompt text
            max_tokens: Maximum tokens to generate
            
        Returns:
            LLM response
        """
        if self.llm_client is None:
            return self._fallback_analysis(prompt)
        
        try:
            if self.llm_type == "ollama":
                response = self.llm_client.generate(
                    model=self.model_name,
                    prompt=prompt,
                    stream=False,
                    options={
                        "num_predict": max_tokens,
                        "temperature": 0.7,
                        "top_p": 0.9,
                    }
                )
                return response['response']
            else:
                # HuggingFace
                outputs = self.llm_client(
                    prompt,
                    max_length=max_tokens,
                    num_return_sequences=1,
                    temperature=0.7
                )
                return outputs[0]['generated_text']
        
        except Exception as e:
            print(f"LLM error: {e}. Using fallback analysis.")
            return self._fallback_analysis(prompt)
    
    def _fallback_analysis(self, prompt: str) -> str:
        """Fallback analysis when LLM unavailable."""
        # Rule-based threat analysis
        if "dos" in prompt.lower():
            return json.dumps({
                "threat_summary": "Denial of Service attack detected",
                "risk_level": "HIGH",
                "attack_vector": "Volumetric attack overwhelming target resources",
                "potential_impact": ["Service unavailability", "Resource exhaustion"],
                "indicators_of_compromise": "Excessive traffic from single source",
                "immediate_actions": ["Block source IP", "Rate limit connections"],
                "long_term_mitigation": ["Deploy DDoS protection", "Enable traffic filtering"],
                "mitre_tactics": ["Impact"]
            })
        
        elif "probe" in prompt.lower():
            return json.dumps({
                "threat_summary": "Reconnaissance probe detected",
                "risk_level": "MEDIUM",
                "attack_vector": "Network scanning for vulnerabilities",
                "potential_impact": ["Information gathering", "Attack planning"],
                "indicators_of_compromise": "Port scanning activity",
                "immediate_actions": ["Monitor for follow-up attacks", "Review firewall logs"],
                "long_term_mitigation": ["Harden systems", "Reduce attack surface"],
                "mitre_tactics": ["Reconnaissance"]
            })
        
        else:
            return json.dumps({
                "threat_summary": "Anomaly detected in network traffic",
                "risk_level": "MEDIUM",
                "attack_vector": "Unusual network behavior detected",
                "potential_impact": ["Potential compromise"],
                "indicators_of_compromise": "Anomalous traffic patterns",
                "immediate_actions": ["Investigate source", "Enable monitoring"],
                "long_term_mitigation": ["Review security policies"],
                "mitre_tactics": ["Unknown"]
            })
    
    def _parse_json_response(self, response: str) -> Dict:
        """
        Parse JSON from LLM response.
        
        Args:
            response: LLM response text
            
        Returns:
            Parsed JSON as dictionary
        """
        try:
            # Try to find JSON in response
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                json_str = json_match.group()
                return json.loads(json_str)
        except json.JSONDecodeError:
            pass
        
        # Fallback to structured response
        return {
            "threat_summary": response[:200],
            "risk_level": "UNKNOWN",
            "attack_vector": "Analysis pending",
            "raw_response": response
        }