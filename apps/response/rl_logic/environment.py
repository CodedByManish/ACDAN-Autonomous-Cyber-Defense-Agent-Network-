"""
Gym-like environment for RL-based response decisions.
"""

import numpy as np
from typing import Tuple, Dict
from enum import IntEnum


class ResponseActions(IntEnum):
    """Available response actions."""
    BLOCK_IP = 0
    RATE_LIMIT = 1
    ALERT_ADMIN = 2
    IGNORE = 3
    QUARANTINE = 4


class ThreatResponseEnvironment:
    """
    Environment for RL agent to learn threat response.
    
    State: [threat_severity, attack_frequency, false_positive_rate, system_load]
    Action: Block IP, Rate Limit, Alert, Ignore, Quarantine
    Reward: Based on correct mitigation + penalty for false positives
    """
    
    def __init__(self, max_steps: int = 100):
        """Initialize environment."""
        self.max_steps = max_steps
        self.current_step = 0
        self.state = None
        self.threat_severity = 0
        self.attack_frequency = 0
        self.false_positive_rate = 0
        self.system_load = 0
    
    def reset(self) -> np.ndarray:
        """Reset environment to initial state."""
        self.current_step = 0
        self.threat_severity = np.random.uniform(0, 1)
        self.attack_frequency = np.random.uniform(0, 1)
        self.false_positive_rate = np.random.uniform(0, 0.3)
        self.system_load = np.random.uniform(0, 1)
        
        self.state = np.array([
            self.threat_severity,
            self.attack_frequency,
            self.false_positive_rate,
            self.system_load
        ], dtype=np.float32)
        
        return self.state
    
    def step(
        self,
        action: int
    ) -> Tuple[np.ndarray, float, bool, Dict]:
        """
        Execute action and return next state, reward, done flag, info.
        
        Args:
            action: Action index from ResponseActions
            
        Returns:
            (next_state, reward, done, info)
        """
        self.current_step += 1
        
        # Calculate reward based on action appropriateness
        reward = self._calculate_reward(action)
        
        # Update threat state based on action
        self.threat_severity = self._update_threat_severity(action)
        self.attack_frequency = self._update_attack_frequency(action)
        self.system_load = self._update_system_load(action)
        
        # Update state
        self.state = np.array([
            self.threat_severity,
            self.attack_frequency,
            self.false_positive_rate,
            self.system_load
        ], dtype=np.float32)
        
        done = self.current_step >= self.max_steps or self.threat_severity < 0.1
        
        info = {
            'action_name': ResponseActions(action).name,
            'threat_severity': self.threat_severity,
            'system_load': self.system_load,
        }
        
        return self.state, reward, done, info
    
    def _calculate_reward(self, action: int) -> float:
        """Calculate reward for action."""
        reward = 0
        
        if action == ResponseActions.BLOCK_IP:
            # Good for high-threat situations
            if self.threat_severity > 0.7:
                reward += 10
            elif self.threat_severity > 0.3:
                reward += 5
            else:
                reward -= 5  # Penalty for false positive
        
        elif action == ResponseActions.RATE_LIMIT:
            # Good for medium threat with high frequency
            if 0.3 < self.threat_severity < 0.7 and self.attack_frequency > 0.5:
                reward += 8
            elif 0.3 < self.threat_severity < 0.7:
                reward += 5
            else:
                reward -= 3
        
        elif action == ResponseActions.ALERT_ADMIN:
            # Always reasonable, but not as effective
            reward += 3
        
        elif action == ResponseActions.IGNORE:
            # Only good for low threats
            if self.threat_severity < 0.2:
                reward += 2
            else:
                reward -= 8
        
        elif action == ResponseActions.QUARANTINE:
            # Expensive action, only for critical
            if self.threat_severity > 0.85:
                reward += 12
            else:
                reward -= 10
        
        # Penalize system overload
        if self.system_load > 0.8:
            reward -= 5
        
        return reward
    
    def _update_threat_severity(self, action: int) -> float:
        """Update threat severity based on action."""
        new_severity = self.threat_severity * 0.9
        
        if action == ResponseActions.BLOCK_IP:
            new_severity *= 0.3
        elif action == ResponseActions.RATE_LIMIT:
            new_severity *= 0.6
        elif action == ResponseActions.QUARANTINE:
            new_severity *= 0.1
        elif action == ResponseActions.IGNORE:
            new_severity *= 1.2
        
        return np.clip(new_severity, 0, 1)
    
    def _update_attack_frequency(self, action: int) -> float:
        """Update attack frequency based on action."""
        new_frequency = self.attack_frequency * 0.95
        
        if action == ResponseActions.BLOCK_IP:
            new_frequency *= 0.1
        elif action == ResponseActions.RATE_LIMIT:
            new_frequency *= 0.5
        elif action == ResponseActions.IGNORE:
            new_frequency *= 1.1
        
        return np.clip(new_frequency, 0, 1)
    
    def _update_system_load(self, action: int) -> float:
        """Update system load based on action."""
        # Each action has some system cost
        action_costs = {
            ResponseActions.BLOCK_IP: 0.05,
            ResponseActions.RATE_LIMIT: 0.08,
            ResponseActions.ALERT_ADMIN: 0.02,
            ResponseActions.IGNORE: 0.0,
            ResponseActions.QUARANTINE: 0.15,
        }
        
        new_load = self.system_load * 0.95 + action_costs.get(action, 0.03)
        return np.clip(new_load, 0, 1)
    
    @property
    def observation_space(self):
        """Get observation space."""
        class Space:
            def __init__(self):
                self.shape = (4,)
                self.dtype = np.float32
        return Space()
    
    @property
    def action_space(self):
        """Get action space."""
        class Space:
            def __init__(self):
                self.n = 5
        return Space()