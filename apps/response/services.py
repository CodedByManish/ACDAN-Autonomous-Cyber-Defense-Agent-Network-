import numpy as np
from pathlib import Path
from .rl_logic.policy import ResponsePolicy

class ResponseService:
    def __init__(self):
        self.model_dir = Path("data/models")
        self._policy = None

    @property
    def policy(self):
        """Lazy load the RL policy and model weights."""
        if self._policy is None:
            self._policy = ResponsePolicy(models_path=str(self.model_dir))
            model_path = self.model_dir / "rl_policy.pt"
            
            if model_path.exists():
                print(f"--- Loading RL Policy from {model_path} ---")
                self._policy.load_policy()
            else:
                print(f"--- WARNING: No RL model found. Running on uninitialized weights. ---")
        return self._policy

    def determine_action(self, predicted_class: str, risk_level: str):
        """
        Maps the Phase 2 (Reasoning) output to RL state inputs.
        """
        # Map textual risk to numerical severity (0.0 - 1.0)
        risk_map = {
            "LOW": 0.2,
            "MEDIUM": 0.5,
            "HIGH": 0.8,
            "CRITICAL": 1.0
        }
        severity = risk_map.get(risk_level.upper(), 0.5)

        # Simulate frequency and load for the decision (or fetch from telemetry)
        # In a real system, you'd pull these from a DB or Redis
        simulated_frequency = 0.7 if severity > 0.5 else 0.2
        simulated_load = 0.3 

        # Get recommendation from RL Agent
        recommendation = self.policy.predict_action(
            threat_severity=severity,
            attack_frequency=simulated_frequency,
            system_load=simulated_load
        )

        return {
            "attack_identified": predicted_class,
            "recommended_action": recommendation["recommended_action"],
            "confidence_score": round(recommendation["confidence"], 4),
            "rationale": recommendation["rationale"],
            "impact_on_system": recommendation["threat_state"]["system_load"]
        }

# Instantiate for use in API
response_service = ResponseService()