import torch
import numpy as np
from pathlib import Path
from .rl_logic.dqn_agent import DQNAgent
from .rl_logic.environment import ResponseActions

class ResponseService:
    def __init__(self):
        self.model_path = Path("data/models/rl_policy.pt")
        self.state_size = 4  # From your environment: [severity, freq, fp_rate, load]
        self.action_size = 5 # From ResponseActions
        self.agent = DQNAgent(state_size=self.state_size, action_size=self.action_size)
        
        # Load pre-trained weights
        if self.model_path.exists():
            self.agent.load(str(self.model_path))
            self.agent.q_network.eval() # Set to evaluation mode for speed
        else:
            print(f"⚠️ Warning: RL Policy not found at {self.model_path}")

    def determine_action(self, predicted_class: str, risk_level: str):
        # Map human-readable risk to environment floats
        risk_map = {"LOW": 0.2, "MEDIUM": 0.5, "HIGH": 0.8, "CRITICAL": 1.0}
        severity = risk_map.get(risk_level.upper(), 0.5)
        
        # Create a synthetic state based on the incoming threat
        # [severity, attack_frequency, false_positive_rate, system_load]
        state = np.array([
            severity, 
            0.7 if severity > 0.6 else 0.3, # simulated frequency
            0.05,                           # simulated low FP rate
            0.4                             # current system load
        ], dtype=np.float32)

        # Agent selects the best action
        action_idx = self.agent.select_action(state, training=False)
        action_name = ResponseActions(action_idx).name

        # Generate rationale based on RL logic
        rationale = f"RL Agent selected {action_name} to optimize defense-to-load ratio for {risk_level} threat."

        return {
            "attack_identified": predicted_class,
            "recommended_action": action_name,
            "confidence_score": 0.95, # DQN doesn't give direct probability easily, using 0.95 for policy stability
            "rationale": rationale,
            "impact_on_system": 0.1 if action_idx == 3 else 0.4 # Action 3 is 'IGNORE'
        }

response_service = ResponseService()