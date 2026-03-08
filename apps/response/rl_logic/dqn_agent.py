"""
Deep Q-Network agent for threat response decisions.
"""

import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from collections import deque
import random
from typing import Tuple, List
import os


class QNetwork(nn.Module):
    """Q-value network."""
    
    def __init__(self, state_size: int, action_size: int, hidden_dim: int = 128):
        """Initialize Q-network."""
        super(QNetwork, self).__init__()
        
        self.fc1 = nn.Linear(state_size, hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, hidden_dim)
        self.fc3 = nn.Linear(hidden_dim, action_size)
        
        self.relu = nn.ReLU()
    
    def forward(self, state: torch.Tensor) -> torch.Tensor:
        """Forward pass to get Q-values."""
        x = self.relu(self.fc1(state))
        x = self.relu(self.fc2(x))
        return self.fc3(x)


class DQNAgent:
    """
    Deep Q-Network agent for learning optimal threat responses.
    """
    
    def __init__(
        self,
        state_size: int = 4,
        action_size: int = 5,
        learning_rate: float = 0.001,
        gamma: float = 0.99,
        epsilon: float = 1.0,
        epsilon_decay: float = 0.995,
        epsilon_min: float = 0.01,
        device: str = None
    ):
        """
        Initialize DQN agent.
        
        Args:
            state_size: Size of state vector
            action_size: Number of actions
            learning_rate: Learning rate for optimizer
            gamma: Discount factor
            epsilon: Exploration rate
            epsilon_decay: Decay rate for epsilon
            epsilon_min: Minimum epsilon
            device: "cuda" or "cpu"
        """
        self.state_size = state_size
        self.action_size = action_size
        self.learning_rate = learning_rate
        self.gamma = gamma
        self.epsilon = epsilon
        self.epsilon_decay = epsilon_decay
        self.epsilon_min = epsilon_min
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        
        # Q-networks
        self.q_network = QNetwork(state_size, action_size).to(self.device)
        self.target_network = QNetwork(state_size, action_size).to(self.device)
        self.target_network.load_state_dict(self.q_network.state_dict())
        
        self.optimizer = optim.Adam(self.q_network.parameters(), lr=learning_rate)
        self.criterion = nn.MSELoss()
        
        # Experience replay
        self.memory = deque(maxlen=2000)
        self.update_frequency = 10
        self.update_counter = 0
    
    def select_action(self, state: np.ndarray, training: bool = True) -> int:
        """
        Select action using epsilon-greedy policy.
        
        Args:
            state: Current state
            training: Whether in training mode
            
        Returns:
            Action index
        """
        if training and random.random() < self.epsilon:
            return random.randint(0, self.action_size - 1)
        
        # Exploit: use Q-network
        state_tensor = torch.FloatTensor(state).unsqueeze(0).to(self.device)
        with torch.no_grad():
            q_values = self.q_network(state_tensor)
        
        return q_values.argmax(dim=1).item()
    
    def remember(
        self,
        state: np.ndarray,
        action: int,
        reward: float,
        next_state: np.ndarray,
        done: bool
    ) -> None:
        """Store experience in memory."""
        self.memory.append((state, action, reward, next_state, done))
    
    def replay(self, batch_size: int = 32) -> float:
        """
        Train on batch from experience replay.
        
        Args:
            batch_size: Size of batch
            
        Returns:
            Loss value
        """
        if len(self.memory) < batch_size:
            return 0.0
        
        batch = random.sample(self.memory, batch_size)
        
        states = torch.FloatTensor(np.array([exp[0] for exp in batch])).to(self.device)
        actions = torch.LongTensor(np.array([exp[1] for exp in batch])).to(self.device)
        rewards = torch.FloatTensor(np.array([exp[2] for exp in batch])).to(self.device)
        next_states = torch.FloatTensor(np.array([exp[3] for exp in batch])).to(self.device)
        dones = torch.FloatTensor(np.array([exp[4] for exp in batch])).to(self.device)
        
        # Current Q-values
        q_values = self.q_network(states).gather(1, actions.unsqueeze(1)).squeeze(1)
        
        # Target Q-values
        with torch.no_grad():
            next_q_values = self.target_network(next_states).max(dim=1)[0]
            target_q_values = rewards + (1 - dones) * self.gamma * next_q_values
        
        # Compute loss
        loss = self.criterion(q_values, target_q_values)
        
        # Optimize
        self.optimizer.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(self.q_network.parameters(), max_norm=1.0)
        self.optimizer.step()
        
        # Update target network periodically
        self.update_counter += 1
        if self.update_counter % self.update_frequency == 0:
            self.target_network.load_state_dict(self.q_network.state_dict())
        
        # Decay epsilon
        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay
        
        return loss.item()
    
    def save(self, filepath: str) -> None:
        """Save agent."""
        torch.save(self.q_network.state_dict(), filepath)
        print(f"Agent saved to {filepath}")
    
    def load(self, filepath: str) -> None:
        """Load agent."""
        self.q_network.load_state_dict(torch.load(filepath, map_location=self.device))
        self.target_network.load_state_dict(self.q_network.state_dict())
        print(f"Agent loaded from {filepath}")