"""
Training script for anomaly detection model.
"""

import os
import sys
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)
import numpy as np
import json
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, Tuple

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from preprocessor import DataPreprocessor
from model import TransformerAnomalyDetector, SimpleDNNAnomalyDetector


class AnomalyDetectionTrainer:
    """Trainer for anomaly detection model."""
    
    def __init__(
        self,
        model_type: str = "dnn",
        device: str = None,
        models_path: str = "./data/models"
    ):
        """
        Initialize trainer.
        
        Args:
            model_type: "transformer" or "dnn"
            device: "cuda" or "cpu"
            models_path: Path to save models
        """
        self.model_type = model_type
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.models_path = Path(models_path)
        self.models_path.mkdir(parents=True, exist_ok=True)
        
        self.model = None
        self.optimizer = None
        self.criterion = nn.CrossEntropyLoss()
        self.preprocessor = DataPreprocessor()
        self.history = {'train_loss': [], 'val_loss': [], 'train_acc': [], 'val_acc': []}
    
    def build_model(self, input_size: int, num_classes: int) -> None:
        """Build model architecture."""
        if self.model_type == "transformer":
            self.model = TransformerAnomalyDetector(
                input_size=input_size,
                num_classes=num_classes,
                hidden_dim=128,
                num_layers=2,
                num_heads=4,
                dropout=0.1
            )
        elif self.model_type == "dnn":
            self.model = SimpleDNNAnomalyDetector(
                input_size=input_size,
                num_classes=num_classes,
                hidden_dims=[256, 128, 64],
                dropout=0.2
            )
        else:
            raise ValueError(f"Unknown model type: {self.model_type}")
        
        self.model.to(self.device)
        print(f"Model built: {self.model_type}")
        print(f"Device: {self.device}")
        print(f"Model parameters: {sum(p.numel() for p in self.model.parameters()):,}")
    
    def setup_training(self, learning_rate: float = 0.001) -> None:
        """Setup optimizer and loss function."""
        self.optimizer = optim.Adam(self.model.parameters(), lr=learning_rate)
        print(f"Optimizer: Adam, LR: {learning_rate}")
    
    def train_epoch(self, train_loader: DataLoader) -> Tuple[float, float]:
        """Train one epoch."""
        self.model.train()
        total_loss = 0
        all_preds = []
        all_labels = []
        
        for batch_idx, (X_batch, y_batch) in enumerate(train_loader):
            X_batch = X_batch.to(self.device)
            y_batch = y_batch.to(self.device)
            
            # Forward pass
            logits, _ = self.model(X_batch)
            loss = self.criterion(logits, y_batch)
            
            # Backward pass
            self.optimizer.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
            self.optimizer.step()
            
            # Metrics
            total_loss += loss.item()
            preds = torch.argmax(logits, dim=1).cpu().numpy()
            all_preds.extend(preds)
            all_labels.extend(y_batch.cpu().numpy())
            
            if (batch_idx + 1) % 10 == 0:
                print(f"  Batch {batch_idx + 1}, Loss: {loss.item():.4f}")
        
        avg_loss = total_loss / len(train_loader)
        accuracy = accuracy_score(all_labels, all_preds)
        
        return avg_loss, accuracy
    
    def evaluate(self, val_loader: DataLoader) -> Tuple[float, float, Dict]:
        """Evaluate model on validation set."""
        self.model.eval()
        total_loss = 0
        all_preds = []
        all_labels = []
        
        with torch.no_grad():
            for X_batch, y_batch in val_loader:
                X_batch = X_batch.to(self.device)
                y_batch = y_batch.to(self.device)
                
                logits, _ = self.model(X_batch)
                loss = self.criterion(logits, y_batch)
                
                total_loss += loss.item()
                preds = torch.argmax(logits, dim=1).cpu().numpy()
                all_preds.extend(preds)
                all_labels.extend(y_batch.cpu().numpy())
        
        avg_loss = total_loss / len(val_loader)
        accuracy = accuracy_score(all_labels, all_preds)
        
        metrics = {
            'precision': precision_score(all_labels, all_preds, average='weighted', zero_division=0),
            'recall': recall_score(all_labels, all_preds, average='weighted', zero_division=0),
            'f1': f1_score(all_labels, all_preds, average='weighted', zero_division=0),
        }
        
        return avg_loss, accuracy, metrics
    
    def train(
        self,
        X_train: np.ndarray,
        X_test: np.ndarray,
        y_train: np.ndarray,
        y_test: np.ndarray,
        epochs: int = 50,
        batch_size: int = 32,
        learning_rate: float = 0.001
    ) -> Dict:
        """
        Train the model.
        
        Args:
            X_train, X_test, y_train, y_test: Training and test data
            epochs: Number of training epochs
            batch_size: Batch size
            learning_rate: Learning rate
            
        Returns:
            Training history and final metrics
        """
        # Build model
        self.build_model(X_train.shape[1], len(np.unique(y_train)))
        self.setup_training(learning_rate)
        
        # Create dataloaders
        train_dataset = TensorDataset(
            torch.FloatTensor(X_train),
            torch.LongTensor(y_train)
        )
        test_dataset = TensorDataset(
            torch.FloatTensor(X_test),
            torch.LongTensor(y_test)
        )
        
        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
        test_loader = DataLoader(test_dataset, batch_size=batch_size)
        
        # Training loop
        best_val_acc = 0
        patience = 10
        patience_counter = 0
        
        print(f"\nStarting training for {epochs} epochs...")
        for epoch in range(epochs):
            print(f"\nEpoch {epoch + 1}/{epochs}")
            
            # Train
            train_loss, train_acc = self.train_epoch(train_loader)
            
            # Evaluate
            val_loss, val_acc, metrics = self.evaluate(test_loader)
            
            self.history['train_loss'].append(train_loss)
            self.history['val_loss'].append(val_loss)
            self.history['train_acc'].append(train_acc)
            self.history['val_acc'].append(val_acc)
            
            print(f"  Train Loss: {train_loss:.4f}, Train Acc: {train_acc:.4f}")
            print(f"  Val Loss: {val_loss:.4f}, Val Acc: {val_acc:.4f}")
            print(f"  Precision: {metrics['precision']:.4f}, Recall: {metrics['recall']:.4f}, F1: {metrics['f1']:.4f}")
            
            # Early stopping
            if val_acc > best_val_acc:
                best_val_acc = val_acc
                patience_counter = 0
                self.save_model("best_model.pt")
            else:
                patience_counter += 1
                if patience_counter >= patience:
                    print(f"\nEarly stopping at epoch {epoch + 1}")
                    break
        
        # Final evaluation
        self.model.eval()
        with torch.no_grad():
            test_dataset_full = TensorDataset(
                torch.FloatTensor(X_test),
                torch.LongTensor(y_test)
            )
            test_loader_full = DataLoader(test_dataset_full, batch_size=batch_size)
            
            all_preds = []
            all_labels = []
            
            for X_batch, y_batch in test_loader_full:
                X_batch = X_batch.to(self.device)
                logits, _ = self.model(X_batch)
                preds = torch.argmax(logits, dim=1).cpu().numpy()
                all_preds.extend(preds)
                all_labels.extend(y_batch.numpy())
        
        # Final metrics
        final_metrics = {
            'accuracy': accuracy_score(all_labels, all_preds),
            'precision': precision_score(all_labels, all_preds, average='weighted', zero_division=0),
            'recall': recall_score(all_labels, all_preds, average='weighted', zero_division=0),
            'f1': f1_score(all_labels, all_preds, average='weighted', zero_division=0),
            'confusion_matrix': confusion_matrix(all_labels, all_preds).tolist(),
            'classification_report': classification_report(all_labels, all_preds, output_dict=True)
        }
        
        print("\n" + "="*50)
        print("FINAL TEST METRICS")
        print("="*50)
        print(f"Accuracy: {final_metrics['accuracy']:.4f}")
        print(f"Precision: {final_metrics['precision']:.4f}")
        print(f"Recall: {final_metrics['recall']:.4f}")
        print(f"F1-Score: {final_metrics['f1']:.4f}")
        
        return final_metrics
    
    def save_model(self, filename: str = "anomaly_detector.pt") -> str:
        """Save model."""
        filepath = self.models_path / filename
        torch.save(self.model.state_dict(), filepath)
        print(f"Model saved to {filepath}")
        return str(filepath)
    
    def load_model(self, filepath: str) -> None:
        """Load model."""
        if not self.model:
            raise ValueError("Model not built. Call build_model first.")
        self.model.load_state_dict(torch.load(filepath, map_location=self.device))
        print(f"Model loaded from {filepath}")


def main():
    """Main training function."""
    parser = argparse.ArgumentParser(description="Train anomaly detection model")
    parser.add_argument("--dataset", type=str, required=True, help="Path to dataset CSV")
    parser.add_argument("--model-type", type=str, default="dnn", choices=["dnn", "transformer"])
    parser.add_argument("--epochs", type=int, default=10)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--learning-rate", type=float, default=0.001)
    parser.add_argument("--models-path", type=str, default="./data/models")
    
    args = parser.parse_args()
    
    # Ensure the models directory exists
    os.makedirs(args.models_path, exist_ok=True)
    
    print("Preprocessing data...")
    preprocessor = DataPreprocessor(test_size=0.2)
    
    X_train, X_test, y_train, y_test, metadata = preprocessor.prepare_data(
        args.dataset,
        target_col='Label', 
        categorical_cols=[] 
    )
    
    # Save preprocessor
    preprocessor.save_preprocessor(os.path.join(args.models_path, "preprocessor.pkl"))
    
    # Save metadata
    with open(os.path.join(args.models_path, "metadata.json"), 'w') as f:
        json.dump(metadata, f, indent=2)
    
    # Train model
    trainer = AnomalyDetectionTrainer(
        model_type=args.model_type,
        models_path=args.models_path
    )
    
    metrics = trainer.train(
        X_train, X_test, y_train, y_test,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate
    )
    
    # Save final metrics
    with open(os.path.join(args.models_path, "metrics.json"), 'w') as f:
        json.dump(metrics, f, indent=2)
    
    trainer.save_model("final_model.pt")


if __name__ == "__main__":
    main()