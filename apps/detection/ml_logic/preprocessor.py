"""
Data preprocessing for network intrusion detection.
Handles normalization, encoding, and feature engineering.
"""

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from typing import Tuple, Dict, Any
import pickle
import os


class DataPreprocessor:
    """Preprocesses network intrusion dataset for ML model."""

    def __init__(self, test_size: float = 0.2, random_state: int = 42):
        """
        Initialize preprocessor.
        
        Args:
            test_size: Proportion of dataset for testing
            random_state: Random seed for reproducibility
        """
        self.test_size = test_size
        self.random_state = random_state
        self.scaler = StandardScaler()
        self.label_encoders: Dict[str, LabelEncoder] = {}
        self.feature_names = None
        self.class_encoder = LabelEncoder()
        
    def load_data(self, filepath: str) -> pd.DataFrame:
        """
        Load intrusion dataset.
        
        Args:
            filepath: Path to CSV file
            
        Returns:
            DataFrame with loaded data
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Dataset not found: {filepath}")
        
        df = pd.read_csv(filepath)
        print(f"Loaded dataset: {df.shape[0]} samples, {df.shape[1]} features")
        return df

    def handle_missing_values(self, df: pd.DataFrame) -> pd.DataFrame:
        """Handle missing values in dataset."""
        missing_count = df.isnull().sum().sum()
        if missing_count > 0:
            print(f"Handling {missing_count} missing values")
            df = df.fillna(df.mean(numeric_only=True))
        return df

    def encode_categorical_features(
        self, 
        df: pd.DataFrame, 
        categorical_cols: list,
        fit: bool = True
    ) -> pd.DataFrame:
        """
        Encode categorical features using LabelEncoder.
        
        Args:
            df: DataFrame to encode
            categorical_cols: List of categorical column names
            fit: Whether to fit new encoders (True for training, False for inference)
            
        Returns:
            DataFrame with encoded features
        """
        df_encoded = df.copy()
        
        for col in categorical_cols:
            if col in df_encoded.columns:
                if fit:
                    self.label_encoders[col] = LabelEncoder()
                    df_encoded[col] = self.label_encoders[col].fit_transform(
                        df_encoded[col].astype(str)
                    )
                else:
                    if col not in self.label_encoders:
                        raise ValueError(f"Encoder for {col} not fitted")
                    df_encoded[col] = self.label_encoders[col].transform(
                        df_encoded[col].astype(str)
                    )
        
        return df_encoded

    def normalize_numeric_features(
        self,
        X: np.ndarray,
        fit: bool = True
    ) -> np.ndarray:
        """
        Normalize numeric features using StandardScaler.
        
        Args:
            X: Feature matrix to normalize
            fit: Whether to fit scaler (True for training, False for inference)
            
        Returns:
            Normalized feature matrix
        """
        if fit:
            X_normalized = self.scaler.fit_transform(X)
        else:
            X_normalized = self.scaler.transform(X)
        
        return X_normalized

    def prepare_data(
        self,
        filepath: str,
        target_col: str = "label",
        categorical_cols: list = None
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, Dict[str, Any]]:
        """
        Complete preprocessing pipeline.
        
        Args:
            filepath: Path to dataset
            target_col: Name of target column
            categorical_cols: List of categorical column names
            
        Returns:
            Tuple of (X_train, X_test, y_train, y_test, metadata)
        """
        # Default categorical columns for NSL-KDD or similar datasets
        if categorical_cols is None:
            categorical_cols = ['protocol_type', 'service', 'flag']
        
        # Load data
        df = self.load_data(filepath)
        
        # Handle missing values
        df = self.handle_missing_values(df)
        
        # Separate features and target
        if target_col not in df.columns:
            raise ValueError(f"Target column '{target_col}' not found in dataset")
        
        X = df.drop(columns=[target_col])
        y = df[target_col]
        
        # Store feature names
        self.feature_names = X.columns.tolist()
        
        # Encode categorical features
        X = self.encode_categorical_features(X, categorical_cols, fit=True)
        
        # Encode target labels
        y_encoded = self.class_encoder.fit_transform(y)
        
        # Get unique classes
        classes = self.class_encoder.classes_
        print(f"Classes: {classes}")
        
        # Normalize features
        X_normalized = self.normalize_numeric_features(X.values, fit=True)
        
        # Train-test split
        X_train, X_test, y_train, y_test = train_test_split(
            X_normalized,
            y_encoded,
            test_size=self.test_size,
            random_state=self.random_state,
            stratify=y_encoded
        )
        
        metadata = {
            'feature_names': self.feature_names,
            'n_features': len(self.feature_names),
            'n_classes': len(classes),
            'classes': classes.tolist(),
            'categorical_columns': categorical_cols,
            'train_samples': X_train.shape[0],
            'test_samples': X_test.shape[0],
        }
        
        print(f"Training samples: {X_train.shape[0]}, Test samples: {X_test.shape[0]}")
        
        return X_train, X_test, y_train, y_test, metadata

    def save_preprocessor(self, filepath: str) -> None:
        """Save preprocessor state for inference."""
        state = {
            'scaler': self.scaler,
            'label_encoders': self.label_encoders,
            'class_encoder': self.class_encoder,
            'feature_names': self.feature_names,
        }
        with open(filepath, 'wb') as f:
            pickle.dump(state, f)
        print(f"Preprocessor saved to {filepath}")

    def load_preprocessor(self, filepath: str) -> None:
        """Load preprocessor state for inference."""
        with open(filepath, 'rb') as f:
            state = pickle.load(f)
        
        self.scaler = state['scaler']
        self.label_encoders = state['label_encoders']
        self.class_encoder = state['class_encoder']
        self.feature_names = state['feature_names']
        print(f"Preprocessor loaded from {filepath}")

    def preprocess_inference_data(
        self,
        data: Dict[str, Any],
        categorical_cols: list = None
    ) -> np.ndarray:
        """
        Preprocess single record for inference.
        
        Args:
            data: Dictionary with feature values
            categorical_cols: List of categorical column names
            
        Returns:
            Preprocessed feature vector
        """
        if categorical_cols is None:
            categorical_cols = ['protocol_type', 'service', 'flag']
        
        # Create DataFrame from dict
        df = pd.DataFrame([data])
        
        # Encode categorical features
        df = self.encode_categorical_features(df, categorical_cols, fit=False)
        
        # Normalize
        X = self.normalize_numeric_features(df.values, fit=False)
        
        return X[0]