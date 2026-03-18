"""
Training loop and policy management for RL agent.
"""

import numpy as np
from typing import Dict, List, Tuple
from pathlib import Path
import json
from apps.response.rl_logic.dqn_agent import DQNAgent
from apps.response.rl_logic.environment import ThreatResponseEnvironment, ResponseActions


class ResponsePolicy:
    """Manages RL-based threat response policy."""
    
    def __init__(self, models_path: str = "./data/models"):
        """Initialize policy."""
        self.models_path = Path(models_path)
        self.models_path.mkdir(parents=True, exist_ok=True)
        
        self.env = ThreatResponseEnvironment()
        self.agent = DQNAgent(
            state_size=self.env.observation_space.shape[0],
            action_size=self.env.action_space.n
        )
        
        self.training_history = []
        self.q_table_history = []
    
    def train(
        self,
        episodes: int = 200,
        batch_size: int = 32,
        max_steps: int = 100,
        update_interval: int = 10
    ) -> Dict:
        """
        Train the RL agent.
        
        Args:
            episodes: Number of training episodes
            batch_size: Batch size for replay
            max_steps: Maximum steps per episode
            update_interval: How often to log metrics
            
        Returns:
            Training history
        """
        episode_rewards = []
        episode_losses = []
        
        for episode in range(episodes):
            state = self.env.reset()
            episode_reward = 0
            episode_loss = 0
            
            for step in range(max_steps):
                # Select and execute action
                action = self.agent.select_action(state, training=True)
                next_state, reward, done, info = self.env.step(action)
                
                # Store experience
                self.agent.remember(state, action, reward, next_state, done)
                
                # Train on batch
                loss = self.agent.replay(batch_size)
                
                episode_reward += reward
                episode_loss += loss
                
                state = next_state
                
                if done:
                    break
            
            episode_rewards.append(episode_reward)
            episode_losses.append(episode_loss / (step + 1))
            
            if (episode + 1) % update_interval == 0:
                avg_reward = np.mean(episode_rewards[-update_interval:])
                avg_loss = np.mean(episode_losses[-update_interval:])
                print(f"Episode {episode + 1}/{episodes}, Avg Reward: {avg_reward:.2f}, Avg Loss: {avg_loss:.4f}")
        
        print(f"\nTraining complete!")
        
        history = {
            'episode_rewards': episode_rewards,
            'episode_losses': episode_losses,
            'total_episodes': episodes,
            'final_epsilon': self.agent.epsilon,
        }
        
        self.training_history = history
        return history
    
    def predict_action(
        self,
        threat_severity: float,
        attack_frequency: float,
        false_positive_rate: float = 0.0,
        system_load: float = 0.0
    ) -> Dict:
        """
        Predict optimal response action for a threat.
        
        Args:
            threat_severity: Severity of threat (0-1)
            attack_frequency: Frequency of attacks (0-1)
            false_positive_rate: Current false positive rate (0-1)
            system_load: Current system load (0-1)
            
        Returns:
            Action recommendation with details
        """
        state = np.array([
            threat_severity,
            attack_frequency,
            false_positive_rate,
            system_load
        ], dtype=np.float32)
        
        # Get action and Q-values
        action = self.agent.select_action(state, training=False)
        
        # Get Q-values for all actions
        import torch
        state_tensor = torch.FloatTensor(state).unsqueeze(0).to(self.agent.device)
        with torch.no_grad():
            q_values = self.agent.q_network(state_tensor)[0].cpu().numpy()
        
        recommendation = {
            'recommended_action': ResponseActions(action).name,
            'action_id': int(action),
            'confidence': float(np.max(q_values)),
            'q_values': {
                ResponseActions(i).name: float(q_values[i])
                for i in range(len(q_values))
            },
            'threat_state': {
                'severity': float(threat_severity),
                'frequency': float(attack_frequency),
                'system_load': float(system_load),
            },
            'rationale': self._get_action_rationale(action, threat_severity)
        }
        
        return recommendation
    
    def _get_action_rationale(self, action: int, threat_severity: float) -> str:
        """Get explanation for recommended action."""
        action_name = ResponseActions(action).name
        
        if action_name == "BLOCK_IP":
            return f"IP blocking recommended due to high threat severity ({threat_severity:.2%})"
        elif action_name == "RATE_LIMIT":
            return f"Rate limiting recommended to mitigate repeated attacks"
        elif action_name == "ALERT_ADMIN":
            return f"Alert admin for manual investigation and decision"
        elif action_name == "IGNORE":
            return f"Threat severity is low ({threat_severity:.2%}), no immediate action needed"
        elif action_name == "QUARANTINE":
            return f"Critical threat detected ({threat_severity:.2%}), quarantine recommended"
        else:
            return "Unable to determine action"
    
    def save_policy(self) -> None:
        """Save trained policy."""
        model_path = self.models_path / "rl_policy.pt"
        self.agent.save(str(model_path))
        
        history_path = self.models_path / "rl_training_history.json"
        with open(history_path, 'w') as f:
            json.dump(self.training_history, f, indent=2)
        
        print(f"Policy saved to {self.models_path}")
    
    def load_policy(self) -> None:
        """Load trained policy."""
        model_path = self.models_path / "rl_policy.pt"
        if model_path.exists():
            self.agent.load(str(model_path))
            print(f"Policy loaded from {model_path}")
        else:
            print(f"No saved policy found at {model_path}")