"""
Prompt templates for LLM-based threat analysis.
"""

THREAT_ANALYSIS_PROMPT = """You are a cybersecurity expert AI analyzing network threats.

Given the following detected anomaly, provide a structured threat analysis.

ANOMALY DETECTED:
Attack Type: {attack_type}
Confidence: {confidence:.2%}
Source IP: {source_ip}
Destination IP: {dest_ip}
Protocol: {protocol}
Port: {port}

Provide your analysis in the following JSON format:
{{
    "threat_summary": "Brief 1-2 sentence summary",
    "risk_level": "LOW|MEDIUM|HIGH|CRITICAL",
    "attack_vector": "Description of how this attack works",
    "potential_impact": "List 2-3 potential impacts",
    "indicators_of_compromise": "What to look for",
    "immediate_actions": "List 2-3 recommended immediate actions",
    "long_term_mitigation": "List 2-3 long-term mitigations",
    "mitre_tactics": "Relevant MITRE ATT&CK tactics"
}}

Analyze thoroughly and be precise."""

CVE_CONTEXT_PROMPT = """Using the provided CVE context, enhance the threat analysis:

THREAT: {threat_summary}
CVE CONTEXT: {cve_context}

Provide updated analysis with:
1. Relevant CVEs that match this attack pattern
2. Known exploitation techniques
3. Specific remediation steps based on CVE data
4. Affected systems and versions to prioritize

Format as structured JSON."""

RESPONSE_RECOMMENDATION_PROMPT = """Based on the threat analysis, recommend defensive responses:

THREAT ANALYSIS:
{threat_analysis}

Recommend the following in JSON format:
{{
    "immediate_response": "What to do right now (0-5 minutes)",
    "short_term": "Actions for next hour",
    "medium_term": "Actions for next 24 hours",
    "blocking_rules": "Specific firewall/WAF rules to implement",
    "monitoring_points": "What to monitor after response",
    "estimated_severity": "1-10 severity score",
    "confidence_in_analysis": "1-10 confidence score"
}}"""

SUMMARIZE_LOGS_PROMPT = """Summarize the following network logs focusing on threat indicators:

LOGS:
{logs}

Provide a concise threat summary highlighting:
1. Key abnormal behaviors
2. Attack patterns
3. Potential attacker objectives
4. Recommended analysis priority

Keep response under 500 characters."""