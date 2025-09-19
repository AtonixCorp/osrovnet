"""
ML-based Threat Detection Services
"""
from __future__ import annotations
try:
    import numpy as np
    import pandas as pd
    _ML_AVAILABLE = True
except Exception:
    # Allow Django checks to run on systems without ML dependencies installed.
    np = None
    pd = None
    _ML_AVAILABLE = False
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
from django.utils import timezone
from django.conf import settings
try:
    import joblib
except Exception:
    joblib = None
import logging
import os

# ML Libraries
if _ML_AVAILABLE:
    from sklearn.ensemble import IsolationForest
    from sklearn.svm import OneClassSVM
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import classification_report, confusion_matrix
    import tensorflow as tf
    from tensorflow.keras.models import Sequential
    from tensorflow.keras.layers import LSTM, Dense, Dropout
    from tensorflow.keras.optimizers import Adam
else:
    IsolationForest = None
    OneClassSVM = None
    StandardScaler = None
    classification_report = None
    confusion_matrix = None
    tf = None
    Sequential = None
    LSTM = None
    Dense = None
    Dropout = None
    Adam = None

from .models import (
    AnomalyDetectionModel, BehavioralProfile, AnomalyDetection,
    MLTrainingDataset, ThreatHuntingCampaign, InsiderThreatIndicator
)
from network_security.models import NetworkTraffic, DiscoveredHost
from threat_intelligence.models import ThreatMatch

logger = logging.getLogger('osrovnet.security_analytics')

class MLThreatDetector:
    """
    Machine Learning-based threat detection engine
    """
    
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.feature_extractors = {
            'network_traffic': self._extract_network_features,
            'user_behavior': self._extract_user_features,
            'behavioral_analysis': self._extract_behavioral_features,
        }
    
    def train_isolation_forest(self, dataset_id: int, contamination: float = 0.1) -> AnomalyDetectionModel:
        """
        Train an Isolation Forest model for anomaly detection
        """
        try:
            dataset = MLTrainingDataset.objects.get(id=dataset_id)
            
            # Load and prepare data
            data = self._load_training_data(dataset)
            X_train = self._preprocess_data(data, dataset.preprocessing_config)
            
            # Initialize and train model
            model = IsolationForest(
                contamination=contamination,
                random_state=42,
                n_estimators=100,
                max_samples='auto',
                bootstrap=False
            )
            
            if _ML_AVAILABLE and IsolationForest is not None:
                model.fit(X_train)
            else:
                # Fallback: compute simple statistics and store them in-memory
                logger.warning("ML libraries not available: using in-memory fallback for Isolation Forest")
                # compute column-wise mean/std
                try:
                    stats = {
                        'mean': X_train.mean().to_dict() if hasattr(X_train, 'mean') else {},
                        'std': X_train.std().to_dict() if hasattr(X_train, 'std') else {}
                    }
                except Exception:
                    stats = {'mean': {}, 'std': {}}
            
            # Evaluate model
            y_pred = model.predict(X_train)
            anomaly_scores = model.decision_function(X_train)
            
            # Save model
            model_path = ''
            if _ML_AVAILABLE and joblib is not None:
                model_path = f"models/isolation_forest_{dataset_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.joblib"
                os.makedirs(os.path.dirname(model_path), exist_ok=True)
                joblib.dump(model, model_path)
            
            # Create model record
            ml_model = AnomalyDetectionModel.objects.create(
                name=f"Isolation Forest - {dataset.name}",
                model_type='isolation_forest',
                description=f"Trained on {dataset.name} with contamination={contamination}",
                status='active',
                model_file=model_path,
                feature_columns=list(X_train.columns) if hasattr(X_train, 'columns') else [],
                training_data_size=len(X_train),
                hyperparameters={
                    'contamination': contamination,
                    'n_estimators': 100,
                    'max_samples': 'auto'
                },
                last_trained=timezone.now()
            )

            # If we used fallback stats, store them in self.models so detect can use them
            if not (_ML_AVAILABLE and IsolationForest is not None):
                self.models[ml_model.id] = {'type': 'fallback_iforest', 'stats': stats, 'contamination': contamination}
            else:
                self.models[ml_model.id] = model
            
            logger.info(f"Trained Isolation Forest model {ml_model.id} on {len(X_train)} samples")
            return ml_model
            
        except Exception as e:
            logger.error(f"Failed to train Isolation Forest: {str(e)}")
            raise
    
    def train_lstm_autoencoder(self, dataset_id: int, sequence_length: int = 10) -> AnomalyDetectionModel:
        """
        Train an LSTM Autoencoder for sequence-based anomaly detection
        """
        try:
            dataset = MLTrainingDataset.objects.get(id=dataset_id)
            
            # Load and prepare data
            data = self._load_training_data(dataset)
            X_train = self._preprocess_data(data, dataset.preprocessing_config)
            
            # Create sequences
            X_sequences = self._create_sequences(X_train, sequence_length)
            
            # Build LSTM Autoencoder
            input_dim = X_sequences.shape[2]
            
            model = Sequential([
                LSTM(50, activation='relu', input_shape=(sequence_length, input_dim), return_sequences=True),
                LSTM(25, activation='relu', return_sequences=False),
                Dropout(0.2),
                Dense(25, activation='relu'),
                Dense(50, activation='relu'),
                Dense(input_dim * sequence_length, activation='sigmoid'),
                tf.keras.layers.Reshape((sequence_length, input_dim))
            ])
            
            model.compile(optimizer=Adam(learning_rate=0.001), loss='mse')
            
            # Train model
            history = model.fit(
                X_sequences, X_sequences,
                epochs=50,
                batch_size=32,
                validation_split=0.2,
                verbose=0
            )
            
            # Save model
            model_path = f"models/lstm_autoencoder_{dataset_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.h5"
            model.save(model_path)
            
            # Create model record
            ml_model = AnomalyDetectionModel.objects.create(
                name=f"LSTM Autoencoder - {dataset.name}",
                model_type='lstm_autoencoder',
                description=f"Trained on {dataset.name} with sequence_length={sequence_length}",
                status='active',
                model_file=model_path,
                feature_columns=list(X_train.columns) if hasattr(X_train, 'columns') else [],
                training_data_size=len(X_sequences),
                hyperparameters={
                    'sequence_length': sequence_length,
                    'lstm_units': [50, 25],
                    'epochs': 50,
                    'batch_size': 32
                },
                last_trained=timezone.now()
            )
            
            self.models[ml_model.id] = model
            
            logger.info(f"Trained LSTM Autoencoder model {ml_model.id} on {len(X_sequences)} sequences")
            return ml_model
            
        except Exception as e:
            logger.error(f"Failed to train LSTM Autoencoder: {str(e)}")
            raise
    
    def detect_anomalies(self, model_id: int, data: pd.DataFrame) -> List[Dict]:
        """
        Detect anomalies using a trained model
        """
        try:
            ml_model = AnomalyDetectionModel.objects.get(id=model_id)
            
            # Preprocess data
            X = self._preprocess_data(data, {})

            anomalies = []

            # If we have an in-memory fallback model
            mem_model = self.models.get(model_id)
            if isinstance(mem_model, dict) and mem_model.get('type') == 'fallback_iforest':
                stats = mem_model.get('stats', {})
                # compute z-score per numeric column
                try:
                    numeric = X.select_dtypes(include=[np.number]) if hasattr(X, 'select_dtypes') else X
                    if hasattr(numeric, 'values'):
                        means = numeric.mean()
                        stds = numeric.std().replace(0, 1)
                        z = (numeric - means) / stds
                        for i in range(len(z)):
                            row = z.iloc[i] if hasattr(z, 'iloc') else z[i]
                            max_z = float(row.abs().max()) if hasattr(row, 'abs') else float(max(abs(x) for x in row))
                            if max_z > 3.0:
                                anomalies.append({
                                    'index': i,
                                    'anomaly_score': max_z,
                                    'confidence': min(1.0, max_z / 5.0),
                                    'features': X.iloc[i].to_dict() if hasattr(X, 'iloc') else X[i]
                                })
                except Exception as e:
                    logger.error(f"Fallback detection error: {e}")
                    return []

                logger.info(f"Fallback detected {len(anomalies)} anomalies using model {model_id}")
                return anomalies

            # Otherwise, attempt to load persistent model if not loaded
            if model_id not in self.models:
                # if model_file is missing or empty, use simple fallback detection
                if not ml_model.model_file:
                    # compute z-score fallback directly
                    try:
                        numeric = X.select_dtypes(include=[np.number]) if hasattr(X, 'select_dtypes') else X
                        if hasattr(numeric, 'values'):
                            means = numeric.mean()
                            stds = numeric.std().replace(0, 1)
                            z = (numeric - means) / stds
                            for i in range(len(z)):
                                row = z.iloc[i] if hasattr(z, 'iloc') else z[i]
                                max_z = float(row.abs().max()) if hasattr(row, 'abs') else float(max(abs(x) for x in row))
                                if max_z > 3.0:
                                    anomalies.append({
                                        'index': i,
                                        'anomaly_score': max_z,
                                        'confidence': min(1.0, max_z / 5.0),
                                        'features': X.iloc[i].to_dict() if hasattr(X, 'iloc') else X[i]
                                    })
                    except Exception as e:
                        logger.error(f"Fallback detection error: {e}")
                        return []

                    logger.info(f"Fallback (no model file) detected {len(anomalies)} anomalies using model {model_id}")
                    return anomalies

                # Try loading from file
                try:
                    if ml_model.model_type == 'lstm_autoencoder':
                        self.models[model_id] = tf.keras.models.load_model(ml_model.model_file)
                    else:
                        self.models[model_id] = joblib.load(ml_model.model_file)
                except Exception as e:
                    logger.error(f"Failed to load model file for model {model_id}: {e}")
                    return []

            model = self.models[model_id]

            if ml_model.model_type == 'isolation_forest':
                try:
                    predictions = model.predict(X)
                    scores = model.decision_function(X)

                    for i, (pred, score) in enumerate(zip(predictions, scores)):
                        if pred == -1:  # Anomaly
                            anomalies.append({
                                'index': i,
                                'anomaly_score': float(score),
                                'confidence': float(abs(score)),
                                'features': X.iloc[i].to_dict() if hasattr(X, 'iloc') else X[i].tolist()
                            })
                except Exception as e:
                    logger.error(f"Isolation forest detection failed: {e}")

            elif ml_model.model_type == 'lstm_autoencoder':
                try:
                    # Create sequences
                    sequence_length = ml_model.hyperparameters.get('sequence_length', 10)
                    X_sequences = self._create_sequences(X, sequence_length)

                    # Predict and calculate reconstruction error
                    predictions = model.predict(X_sequences)
                    mse = np.mean(np.power(X_sequences - predictions, 2), axis=(1, 2))

                    # Use 95th percentile as threshold
                    threshold = np.percentile(mse, 95)

                    for i, error in enumerate(mse):
                        if error > threshold:
                            anomalies.append({
                                'index': i,
                                'anomaly_score': float(error),
                                'confidence': float(error / threshold),
                                'threshold': float(threshold),
                                'features': X_sequences[i].tolist() if len(X_sequences) > i else []
                            })
                except Exception as e:
                    logger.error(f"LSTM detection failed: {e}")

            logger.info(f"Detected {len(anomalies)} anomalies using model {model_id}")
            return anomalies
            
        except Exception as e:
            logger.error(f"Failed to detect anomalies: {str(e)}")
            return []
    
    def analyze_behavioral_patterns(self, entity_type: str, entity_id: str) -> Dict:
        """
        Analyze behavioral patterns for an entity
        """
        try:
            # Get or create behavioral profile
            profile, created = BehavioralProfile.objects.get_or_create(
                entity_type=entity_type,
                entity_id=entity_id,
                defaults={'entity_name': entity_id}
            )
            
            # Extract features based on entity type
            if entity_type == 'user':
                features = self._extract_user_behavioral_features(entity_id)
            elif entity_type == 'host':
                features = self._extract_host_behavioral_features(entity_id)
            else:
                features = {}
            
            # Update profile
            if features:
                profile.last_activity = timezone.now()
                profile.metadata.update(features)
                profile.save()
            
            # Calculate risk score
            risk_score = self._calculate_behavioral_risk_score(profile)
            profile.risk_score = risk_score
            profile.save()
            
            return {
                'profile_id': profile.id,
                'risk_score': risk_score,
                'features': features,
                'baseline_established': profile.baseline_established
            }
            
        except Exception as e:
            logger.error(f"Failed to analyze behavioral patterns: {str(e)}")
            return {}
    
    def detect_insider_threats(self, days_back: int = 7) -> List[Dict]:
        """
        Detect potential insider threat indicators
        """
        try:
            cutoff_date = timezone.now() - timedelta(days=days_back)
            
            # Get high-risk behavioral profiles
            high_risk_profiles = BehavioralProfile.objects.filter(
                risk_score__gte=7.0,
                last_activity__gte=cutoff_date
            )
            
            insider_threats = []
            
            for profile in high_risk_profiles:
                # Analyze for insider threat indicators
                indicators = self._analyze_insider_threat_indicators(profile)
                
                for indicator in indicators:
                    # Create insider threat indicator record
                    threat_indicator = InsiderThreatIndicator.objects.create(
                        behavioral_profile=profile,
                        indicator_type=indicator['type'],
                        risk_level=indicator['risk_level'],
                        description=indicator['description'],
                        evidence=indicator['evidence'],
                        risk_score=indicator['risk_score'],
                        confidence=indicator['confidence'],
                        first_observed=indicator['first_observed'],
                        last_observed=indicator['last_observed']
                    )
                    
                    insider_threats.append({
                        'indicator_id': threat_indicator.id,
                        'entity_type': profile.entity_type,
                        'entity_id': profile.entity_id,
                        'indicator_type': indicator['type'],
                        'risk_level': indicator['risk_level'],
                        'risk_score': indicator['risk_score'],
                        'description': indicator['description']
                    })
            
            logger.info(f"Detected {len(insider_threats)} insider threat indicators")
            return insider_threats
            
        except Exception as e:
            logger.error(f"Failed to detect insider threats: {str(e)}")
            return []
    
    def detect_lateral_movement(self) -> List[Dict]:
        """
        Detect lateral movement patterns in network traffic
        """
        try:
            # Get recent network traffic
            recent_traffic = NetworkTraffic.objects.filter(
                timestamp__gte=timezone.now() - timedelta(hours=24)
            )
            
            # Group by source IP
            source_ips = {}
            for traffic in recent_traffic:
                if traffic.source_ip not in source_ips:
                    source_ips[traffic.source_ip] = []
                source_ips[traffic.source_ip].append(traffic)
            
            lateral_movements = []
            
            for source_ip, traffic_list in source_ips.items():
                # Analyze for lateral movement patterns
                destinations = set([t.destination_ip for t in traffic_list])
                
                # Check for unusual number of destinations
                if len(destinations) > 10:  # Threshold for suspicious activity
                    # Analyze timing patterns
                    timestamps = [t.timestamp for t in traffic_list]
                    time_span = max(timestamps) - min(timestamps)
                    
                    if time_span.total_seconds() < 3600:  # Within 1 hour
                        # Check for privilege escalation indicators
                        privileged_ports = [22, 23, 80, 443, 445, 3389]
                        privileged_access = any(
                            t.destination_port in privileged_ports 
                            for t in traffic_list
                        )
                        
                        if privileged_access:
                            lateral_movements.append({
                                'source_ip': source_ip,
                                'destination_count': len(destinations),
                                'time_span_minutes': time_span.total_seconds() / 60,
                                'privileged_access': privileged_access,
                                'destinations': list(destinations)[:10],  # Limit list size
                                'risk_score': min(len(destinations) / 5.0, 10.0)
                            })
            
            logger.info(f"Detected {len(lateral_movements)} potential lateral movement patterns")
            return lateral_movements
            
        except Exception as e:
            logger.error(f"Failed to detect lateral movement: {str(e)}")
            return []
    
    def _load_training_data(self, dataset: MLTrainingDataset) -> pd.DataFrame:
        """Load training data from dataset"""
        # This would load from the actual file path
        # For now, return sample data
        return pd.DataFrame()
    
    def _preprocess_data(self, data: pd.DataFrame, config: Dict) -> pd.DataFrame:
        """Preprocess data for ML models"""
        # Implement data preprocessing logic
        return data
    
    def _create_sequences(self, data: pd.DataFrame, sequence_length: int) -> np.ndarray:
        """Create sequences for LSTM models"""
        # Implement sequence creation logic
        sequences = []
        for i in range(len(data) - sequence_length + 1):
            sequences.append(data.iloc[i:i+sequence_length].values)
        return np.array(sequences)
    
    def _extract_network_features(self, data: Dict) -> List[float]:
        """Extract network traffic features"""
        return []
    
    def _extract_user_features(self, data: Dict) -> List[float]:
        """Extract user behavior features"""
        return []
    
    def _extract_behavioral_features(self, data: Dict) -> List[float]:
        """Extract behavioral analysis features"""
        return []
    
    def _extract_user_behavioral_features(self, user_id: str) -> Dict:
        """Extract behavioral features for a user"""
        return {}
    
    def _extract_host_behavioral_features(self, host_ip: str) -> Dict:
        """Extract behavioral features for a host"""
        return {}
    
    def _calculate_behavioral_risk_score(self, profile: BehavioralProfile) -> float:
        """Calculate risk score for behavioral profile"""
        return 0.0
    
    def _analyze_insider_threat_indicators(self, profile: BehavioralProfile) -> List[Dict]:
        """Analyze for insider threat indicators"""
        return []

# Singleton instance
ml_threat_detector = MLThreatDetector()