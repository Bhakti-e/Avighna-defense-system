"""
Enhanced ML Models for DOME
===========================
Combines multiple ML approaches for superior threat detection:
- Isolation Forest (existing)
- Autoencoder for behavioral anomaly detection
- LSTM for temporal pattern analysis
- Ensemble voting for final decision
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.model_selection import train_test_split
import joblib
import logging
from typing import Dict, Any, List, Tuple, Optional
import time

# Try to import TensorFlow/Keras, but make it optional
try:
    import tensorflow as tf
    import keras
    from keras import layers
    HAS_KERAS = True
except ImportError:
    HAS_KERAS = False
    print("WARNING: TensorFlow/Keras not available - using basic ML only")

logger = logging.getLogger(__name__)

class EnhancedMLEngine:
    """
    Multi-model ML engine for advanced threat detection
    Combines unsupervised and deep learning approaches
    """
    
    def __init__(self):
        self.isolation_forest = None
        self.autoencoder = None
        self.lstm_model = None
        self.scaler = StandardScaler()
        self.autoencoder_scaler = MinMaxScaler()
        self.features = ['failed_logins', 'connections', 'bytes_out', 'forensics_score']
        self.is_trained = False
        
        # Model weights for ensemble
        self.model_weights = {
            'isolation_forest': 0.3,
            'autoencoder': 0.4,
            'lstm': 0.3
        }
        
        # Load existing models if available
        self._load_models()
    
    def _load_models(self):
        """Load pre-trained models"""
        try:
            # Try to load enhanced models first
            try:
                if_bundle = joblib.load("backend/enhanced_if_model.joblib")
                self.isolation_forest = if_bundle.get("model")
                self.scaler = if_bundle.get("scaler", StandardScaler())
                loaded_features = if_bundle.get("features", [])
                
                # Check if features match
                if loaded_features == self.features:
                    logger.info("Loaded existing Enhanced Isolation Forest model")
                else:
                    logger.warning(f"Feature mismatch: expected {self.features}, got {loaded_features}")
                    raise ValueError("Feature mismatch")
                    
            except:
                # Try to load old 3-feature model and adapt it
                logger.info("Attempting to load legacy 3-feature model...")
                if_bundle = joblib.load("backend/if_model.joblib")
                old_model = if_bundle.get("model")
                old_scaler = if_bundle.get("scaler", StandardScaler())
                
                # Check if old model expects 3 features
                if hasattr(old_scaler, 'n_features_in_') and old_scaler.n_features_in_ == 3:
                    logger.info("Legacy 3-feature model detected, retraining with 4 features...")
                    self._train_default_models()
                    return
                else:
                    self.isolation_forest = old_model
                    self.scaler = old_scaler
                    logger.info("Loaded existing Isolation Forest model")
            
            # Load Autoencoder
            try:
                self.autoencoder = keras.models.load_model("backend/autoencoder_model.h5")
                self.autoencoder_scaler = joblib.load("backend/autoencoder_scaler.joblib")
                logger.info("Loaded existing Autoencoder model")
            except:
                logger.info("No existing Autoencoder model found")
            
            # Load LSTM
            try:
                self.lstm_model = keras.models.load_model("backend/lstm_model.h5")
                logger.info("Loaded existing LSTM model")
            except:
                logger.info("No existing LSTM model found")
                
            self.is_trained = True
            
        except Exception as e:
            logger.warning(f"Could not load existing models: {e}")
            self._train_default_models()
    
    def _train_default_models(self):
        """Train models with synthetic data for demo"""
        logger.info("Training enhanced ML models with synthetic data...")
        
        # Generate synthetic training data
        X_train = self._generate_synthetic_data(5000)
        
        # Train Isolation Forest
        self._train_isolation_forest(X_train)
        
        # Train Autoencoder
        self._train_autoencoder(X_train)
        
        # Train LSTM (requires sequence data)
        self._train_lstm(X_train)
        
        self.is_trained = True
        logger.info("Enhanced ML models trained successfully")
    
    def _generate_synthetic_data(self, n_samples: int) -> np.ndarray:
        """Generate synthetic network telemetry data"""
        np.random.seed(42)
        
        # Normal behavior patterns
        normal_data = []
        for _ in range(int(n_samples * 0.8)):  # 80% normal
            failed_logins = np.random.poisson(0.5)  # Low failure rate
            connections = np.random.normal(5, 2)    # Normal connection count
            bytes_out = np.random.lognormal(10, 1)  # Log-normal data transfer
            forensics_score = np.random.normal(10, 5)  # Low forensics score
            
            normal_data.append([
                max(0, failed_logins),
                max(1, connections),
                max(100, bytes_out),
                max(0, forensics_score)
            ])
        
        # Anomalous behavior patterns
        anomaly_data = []
        for _ in range(int(n_samples * 0.2)):  # 20% anomalies
            failed_logins = np.random.poisson(8)   # High failure rate
            connections = np.random.normal(25, 10) # High connection count
            bytes_out = np.random.lognormal(15, 2) # High data transfer
            forensics_score = np.random.normal(60, 20)  # High forensics score
            
            anomaly_data.append([
                max(0, failed_logins),
                max(1, connections),
                max(100, bytes_out),
                max(0, forensics_score)
            ])
        
        # Combine and shuffle
        all_data = normal_data + anomaly_data
        np.random.shuffle(all_data)
        
        return np.array(all_data)
    
    def _train_isolation_forest(self, X_train: np.ndarray):
        """Train Isolation Forest model"""
        try:
            # Scale features
            X_scaled = self.scaler.fit_transform(X_train)
            
            # Train Isolation Forest
            self.isolation_forest = IsolationForest(
                n_estimators=200,
                contamination=0.1,
                random_state=42,
                n_jobs=-1
            )
            self.isolation_forest.fit(X_scaled)
            
            # Save model
            bundle = {
                "model": self.isolation_forest,
                "scaler": self.scaler,
                "features": self.features
            }
            joblib.dump(bundle, "backend/enhanced_if_model.joblib")
            
            logger.info("Isolation Forest trained and saved")
            
        except Exception as e:
            logger.error(f"Failed to train Isolation Forest: {e}")
    
    def _train_autoencoder(self, X_train: np.ndarray):
        """Train Autoencoder for anomaly detection"""
        try:
            # Scale features for autoencoder (0-1 range)
            X_scaled = self.autoencoder_scaler.fit_transform(X_train)
            
            # Build autoencoder architecture
            input_dim = X_scaled.shape[1]
            
            # Encoder
            input_layer = keras.Input(shape=(input_dim,))
            encoded = layers.Dense(8, activation='relu')(input_layer)
            encoded = layers.Dense(4, activation='relu')(encoded)
            encoded = layers.Dense(2, activation='relu')(encoded)  # Bottleneck
            
            # Decoder
            decoded = layers.Dense(4, activation='relu')(encoded)
            decoded = layers.Dense(8, activation='relu')(decoded)
            decoded = layers.Dense(input_dim, activation='sigmoid')(decoded)
            
            # Create and compile autoencoder
            self.autoencoder = keras.Model(input_layer, decoded)
            self.autoencoder.compile(
                optimizer='adam',
                loss='mse',
                metrics=['mae']
            )
            
            # Train autoencoder (only on normal data for unsupervised learning)
            normal_indices = np.where(X_train[:, 3] < 30)[0]  # Low forensics score = normal
            X_normal = X_scaled[normal_indices]
            
            self.autoencoder.fit(
                X_normal, X_normal,
                epochs=50,
                batch_size=32,
                validation_split=0.2,
                verbose=0
            )
            
            # Save model and scaler
            self.autoencoder.save("backend/autoencoder_model.h5")
            joblib.dump(self.autoencoder_scaler, "backend/autoencoder_scaler.joblib")
            
            logger.info("Autoencoder trained and saved")
            
        except Exception as e:
            logger.error(f"Failed to train Autoencoder: {e}")
    
    def _train_lstm(self, X_train: np.ndarray):
        """Train LSTM for temporal pattern analysis"""
        try:
            # Create sequences for LSTM (sliding window)
            sequence_length = 5
            X_sequences, y_sequences = self._create_sequences(X_train, sequence_length)
            
            if len(X_sequences) == 0:
                logger.warning("Not enough data for LSTM training")
                return
            
            # Build LSTM model
            model = keras.Sequential([
                layers.LSTM(32, return_sequences=True, input_shape=(sequence_length, X_train.shape[1])),
                layers.Dropout(0.2),
                layers.LSTM(16, return_sequences=False),
                layers.Dropout(0.2),
                layers.Dense(8, activation='relu'),
                layers.Dense(1, activation='sigmoid')  # Anomaly probability
            ])
            
            model.compile(
                optimizer='adam',
                loss='binary_crossentropy',
                metrics=['accuracy']
            )
            
            # Create labels (1 for anomaly, 0 for normal)
            y_labels = (y_sequences[:, 3] > 30).astype(int)  # High forensics score = anomaly
            
            # Train LSTM
            model.fit(
                X_sequences, y_labels,
                epochs=30,
                batch_size=16,
                validation_split=0.2,
                verbose=0
            )
            
            self.lstm_model = model
            model.save("backend/lstm_model.h5")
            
            logger.info("LSTM model trained and saved")
            
        except Exception as e:
            logger.error(f"Failed to train LSTM: {e}")
    
    def _create_sequences(self, data: np.ndarray, sequence_length: int) -> Tuple[np.ndarray, np.ndarray]:
        """Create sequences for LSTM training"""
        X_sequences = []
        y_sequences = []
        
        for i in range(len(data) - sequence_length):
            X_sequences.append(data[i:i+sequence_length])
            y_sequences.append(data[i+sequence_length])
        
        return np.array(X_sequences), np.array(y_sequences)
    
    def predict_anomaly(self, telemetry: Dict[str, Any], forensics_score: float = 0.0) -> Dict[str, Any]:
        """
        Enhanced anomaly prediction using ensemble of models
        """
        try:
            # Prepare input features
            features = [
                telemetry.get('failed_logins', 0),
                telemetry.get('connections', 0) if isinstance(telemetry.get('connections'), int) 
                else len(telemetry.get('connections', [])),
                telemetry.get('bytes_out', 0),
                forensics_score
            ]
            
            X = np.array([features])
            
            # Get predictions from each model
            predictions = {}
            
            # 1. Isolation Forest
            if self.isolation_forest:
                try:
                    X_scaled = self.scaler.transform(X)
                    if_score = self.isolation_forest.decision_function(X_scaled)[0]
                    # Convert to 0-1 anomaly score (higher = more anomalous)
                    if_anomaly = max(0.0, min(1.0, (1.0 - ((if_score + 0.5) / 1.5))))
                    predictions['isolation_forest'] = if_anomaly
                except Exception as e:
                    logger.warning(f"Isolation Forest prediction failed: {e}")
                    # If feature mismatch, retrain models
                    if "features" in str(e).lower():
                        logger.info("Feature mismatch detected, retraining models...")
                        self._train_default_models()
                        # Retry prediction
                        try:
                            X_scaled = self.scaler.transform(X)
                            if_score = self.isolation_forest.decision_function(X_scaled)[0]
                            if_anomaly = max(0.0, min(1.0, (1.0 - ((if_score + 0.5) / 1.5))))
                            predictions['isolation_forest'] = if_anomaly
                        except:
                            logger.error("Isolation Forest still failing after retrain")
            
            # 2. Autoencoder
            if self.autoencoder:
                try:
                    X_ae_scaled = self.autoencoder_scaler.transform(X)
                    reconstruction = self.autoencoder.predict(X_ae_scaled, verbose=0)
                    mse = np.mean((X_ae_scaled - reconstruction) ** 2)
                    # Normalize MSE to 0-1 range
                    ae_anomaly = min(1.0, mse * 10)  # Scale factor for demo
                    predictions['autoencoder'] = ae_anomaly
                except Exception as e:
                    logger.warning(f"Autoencoder prediction failed: {e}")
            
            # 3. LSTM (requires sequence, use current value for demo)
            if self.lstm_model:
                try:
                    # For demo, create a simple sequence by repeating current values
                    lstm_input = np.tile(X, (5, 1)).reshape(1, 5, len(features))
                    lstm_anomaly = self.lstm_model.predict(lstm_input, verbose=0)[0][0]
                    predictions['lstm'] = float(lstm_anomaly)
                except Exception as e:
                    logger.warning(f"LSTM prediction failed: {e}")
            
            # Ensemble prediction (weighted average)
            if predictions:
                ensemble_score = 0.0
                total_weight = 0.0
                
                for model_name, score in predictions.items():
                    weight = self.model_weights.get(model_name, 0.33)
                    ensemble_score += score * weight
                    total_weight += weight
                
                if total_weight > 0:
                    ensemble_score /= total_weight
                
                # Add forensics boost
                forensics_boost = min(0.3, forensics_score / 100.0)
                final_score = min(1.0, ensemble_score + forensics_boost)
                
                return {
                    'anomaly_score': final_score,
                    'model_predictions': predictions,
                    'forensics_score': forensics_score,
                    'ensemble_confidence': len(predictions) / 3.0,  # Max 3 models
                    'model_agreement': self._calculate_agreement(predictions)
                }
            else:
                # Fallback to forensics-only scoring
                return {
                    'anomaly_score': min(1.0, forensics_score / 100.0),
                    'model_predictions': {},
                    'forensics_score': forensics_score,
                    'ensemble_confidence': 0.5,
                    'model_agreement': 1.0
                }
                
        except Exception as e:
            logger.error(f"Enhanced ML prediction failed: {e}")
            return {
                'anomaly_score': 0.5,  # Default to medium risk
                'model_predictions': {},
                'forensics_score': forensics_score,
                'ensemble_confidence': 0.0,
                'model_agreement': 0.0,
                'error': str(e)
            }
    
    def _calculate_agreement(self, predictions: Dict[str, float]) -> float:
        """Calculate agreement between model predictions"""
        if len(predictions) < 2:
            return 1.0
        
        scores = list(predictions.values())
        mean_score = np.mean(scores)
        variance = np.var(scores)
        
        # High agreement = low variance
        agreement = max(0.0, 1.0 - (variance * 4))  # Scale factor
        return agreement

# Global enhanced ML engine
enhanced_ml_engine = EnhancedMLEngine()