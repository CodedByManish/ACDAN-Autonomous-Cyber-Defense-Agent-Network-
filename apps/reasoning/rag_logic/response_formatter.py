"""
Format threat analysis responses for consistent output.
"""

import json
from typing import Dict, List
from datetime import datetime


class ThreatResponseFormatter:
    """Format threat analysis for API/dashboard output."""
    
    @staticmethod
    def format_threat_alert(
        threat_id: str,
        threat_analysis: Dict,
        recommendations: Dict = None
    ) -> Dict:
        """
        Format threat into alert structure.
        
        Args:
            threat_id: Unique threat identifier
            threat_analysis: Output from LLM analyzer
            recommendations: Response recommendations
            
        Returns:
            Formatted alert dictionary
        """
        alert = {
            'id': threat_id,
            'timestamp': datetime.now().isoformat(),
            'threat': {
                'type': threat_analysis.get('attack_type', 'UNKNOWN'),
                'summary': threat_analysis.get('threat_summary', ''),
                'risk_level': threat_analysis.get('risk_level', 'UNKNOWN'),
                'confidence': threat_analysis.get('confidence', 0),
            },
            'source': {
                'ip': threat_analysis.get('source_ip', ''),
                'port': threat_analysis.get('port', ''),
            },
            'destination': {
                'ip': threat_analysis.get('dest_ip', ''),
            },
            'analysis': {
                'vector': threat_analysis.get('attack_vector', ''),
                'indicators': threat_analysis.get('indicators_of_compromise', ''),
                'impact': threat_analysis.get('potential_impact', []),
            },
            'recommendations': recommendations or {},
            'status': 'OPEN',
        }
        
        return alert
    
    @staticmethod
    def format_dashboard_summary(
        threats: List[Dict],
        time_window: str = "24h"
    ) -> Dict:
        """
        Format threats for dashboard display.
        
        Args:
            threats: List of threat alerts
            time_window: Time window for summary
            
        Returns:
            Dashboard summary dictionary
        """
        risk_levels = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        attack_types = {}
        
        for threat in threats:
            risk = threat.get('threat', {}).get('risk_level', 'UNKNOWN')
            if risk in risk_levels:
                risk_levels[risk] += 1
            
            attack_type = threat.get('threat', {}).get('type', 'UNKNOWN')
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
        
        return {
            'time_window': time_window,
            'total_threats': len(threats),
            'risk_distribution': risk_levels,
            'attack_types': attack_types,
            'threat_list': threats,
            'critical_actions': ThreatResponseFormatter._extract_critical_actions(threats),
        }
    
    @staticmethod
    def _extract_critical_actions(threats: List[Dict]) -> List[str]:
        """Extract critical actions from threats."""
        actions = set()
        
        for threat in threats:
            if threat.get('threat', {}).get('risk_level') == 'CRITICAL':
                rec = threat.get('recommendations', {})
                immediate = rec.get('immediate_response', '')
                if immediate:
                    actions.add(immediate)
        
        return list(actions)