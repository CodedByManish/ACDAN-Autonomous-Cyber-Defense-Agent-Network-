"""
Transformer-based neural network for network intrusion detection.
Built with PyTorch.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Tuple


class TransformerAnomalyDetector(nn.Module):
    """
    Transformer-based model for anomaly detection in network traffic.
    Uses self-attention to capture feature relationships.
    """
    
    def __init__(
        self,
        input_size: int,
        num_classes: int,
        hidden_dim: int = 128,
        num_layers: int = 2,
        num_heads: int = 4,
        dropout: float = 0.1
    ):
        """
        Initialize the model.
        
        Args:
            input_size: Number of input features
            num_classes: Number of output classes
            hidden_dim: Hidden dimension size
            num_layers: Number of transformer layers
            num_heads: Number of attention heads
            dropout: Dropout probability
        """
        super(TransformerAnomalyDetector, self).__init__()
        
        self.input_size = input_size
        self.num_classes = num_classes
        self.hidden_dim = hidden_dim
        
        # Input projection
        self.input_projection = nn.Linear(input_size, hidden_dim)
        
        # Transformer encoder
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=hidden_dim,
            nhead=num_heads,
            dim_feedforward=hidden_dim * 4,
            dropout=dropout,
            batch_first=True,
            activation='relu'
        )
        self.transformer_encoder = nn.TransformerEncoder(
            encoder_layer,
            num_layers=num_layers
        )
        
        # Output classification head
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim // 2, num_classes)
        )
        
        self._init_weights()
    
    def _init_weights(self) -> None:
        """Initialize model weights."""
        for module in self.modules():
            if isinstance(module, nn.Linear):
                nn.init.xavier_uniform_(module.weight)
                if module.bias is not None:
                    nn.init.constant_(module.bias, 0)
    
    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Forward pass.
        
        Args:
            x: Input tensor of shape (batch_size, input_size)
            
        Returns:
            Tuple of (logits, probabilities)
        """
        # Project input to hidden dimension
        x = self.input_projection(x)  # (batch_size, hidden_dim)
        
        # Add sequence dimension for transformer
        x = x.unsqueeze(1)  # (batch_size, 1, hidden_dim)
        
        # Apply transformer
        x = self.transformer_encoder(x)  # (batch_size, 1, hidden_dim)
        
        # Take sequence output
        x = x.squeeze(1)  # (batch_size, hidden_dim)
        
        # Classification
        logits = self.classifier(x)  # (batch_size, num_classes)
        probabilities = F.softmax(logits, dim=1)
        
        return logits, probabilities


class SimpleDNNAnomalyDetector(nn.Module):
    """
    Simpler DNN alternative for faster training/inference.
    """
    
    def __init__(
        self,
        input_size: int,
        num_classes: int,
        hidden_dims: list = None,
        dropout: float = 0.2
    ):
        """Initialize the model."""
        super(SimpleDNNAnomalyDetector, self).__init__()
        
        if hidden_dims is None:
            hidden_dims = [256, 128, 64]
        
        layers = []
        prev_dim = input_size
        
        for hidden_dim in hidden_dims:
            layers.extend([
                nn.Linear(prev_dim, hidden_dim),
                nn.BatchNorm1d(hidden_dim),
                nn.ReLU(),
                nn.Dropout(dropout)
            ])
            prev_dim = hidden_dim
        
        layers.append(nn.Linear(prev_dim, num_classes))
        
        self.model = nn.Sequential(*layers)
        self._init_weights()
    
    def _init_weights(self) -> None:
        """Initialize weights."""
        for module in self.modules():
            if isinstance(module, nn.Linear):
                nn.init.kaiming_normal_(module.weight, nonlinearity='relu')
                if module.bias is not None:
                    nn.init.constant_(module.bias, 0)
    
    def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """Forward pass."""
        logits = self.model(x)
        probabilities = F.softmax(logits, dim=1)
        return logits, probabilities