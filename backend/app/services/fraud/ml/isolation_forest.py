from typing import List, Dict, Tuple, Any
import numpy as np
from sklearn.ensemble import IsolationForest
from sqlalchemy.orm import Session
from app.models.transaction import Transaction
from app.core.config import settings


class IsolationForestAnomalyDetector:
    def __init__(self):
        pass

    def evaluate_anomaly(
        self, 
        transaction: Transaction, 
        db: Session, 
        history: List[Transaction]
    ) -> Tuple[float, float, Dict[str, float]]:
        """
        Fits a local Isolation Forest on customer transaction history
        and predicts the anomaly score for the current transaction.
        
        Returns:
            ml_anomaly_score: float (0.0 - 100.0, higher means more anomalous)
            confidence: float (0.0 - 1.0)
            feature_contributions: dict of feature names to percentage contributions
        """
        # Cold start check: dynamically load min history from config settings
        if len(history) < settings.FRAUD_ML_MIN_HISTORY:
            # Baseline anomaly score with very low confidence based on transaction amount scale
            amount = float(transaction.amount)
            if amount >= 50000.0:
                base_score = 60.0
            elif amount >= 5000.0:
                base_score = 40.0
            else:
                base_score = 15.0
                
            confidence = len(history) / 10.0
            contributions = {"amount": 0.5, "time_of_day": 0.3, "device_frequency": 0.2}
            return base_score, confidence, contributions

        try:
            # 1. Feature Engineering
            # We encode amount, hour, day of week, device usage frequency, and city usage frequency
            history_amounts = [float(h.amount) for h in history]
            history_hours = [float(h.created_at.hour) for h in history]
            history_days = [float(h.created_at.weekday()) for h in history]
            
            # Helper to calculate frequency of attributes in history
            def get_freq(val: Any, list_vals: List[Any]) -> float:
                if not list_vals:
                    return 0.0
                return sum(1 for v in list_vals if str(v).lower() == str(val).lower()) / len(list_vals)

            X_train = []
            for tx in history:
                device_freq = get_freq(tx.device_id, [h.device_id for h in history])
                city_freq = get_freq(tx.city, [h.city for h in history])
                
                row = [
                    float(tx.amount),
                    float(tx.created_at.hour),
                    float(tx.created_at.weekday()),
                    float(device_freq),
                    float(city_freq)
                ]
                X_train.append(row)

            # Fit Isolation Forest
            X_train = np.array(X_train)
            clf = IsolationForest(
                n_estimators=50,
                contamination=0.1,
                random_state=42
            )
            clf.fit(X_train)

            # 2. Score Current Transaction
            cur_device_freq = get_freq(transaction.device_id, [h.device_id for h in history])
            cur_city_freq = get_freq(transaction.city, [h.city for h in history])

            X_curr = np.array([[
                float(transaction.amount),
                float(transaction.created_at.hour),
                float(transaction.created_at.weekday()),
                float(cur_device_freq),
                float(cur_city_freq)
            ]])

            # decision_function returns negative values for anomalies, positive for normal
            raw_score = clf.decision_function(X_curr)[0]
            
            # Map raw_score in [-0.5, 0.5] to a 0-100 anomaly scale
            # If raw_score < 0 (anomalous), ml_score in [50, 100]
            # If raw_score >= 0 (normal), ml_score in [0, 50]
            if raw_score < 0:
                ml_score = 50.0 + min((abs(raw_score) / 0.4) * 50.0, 50.0)
            else:
                ml_score = max(0.0, 50.0 - (raw_score / 0.4) * 50.0)

            # 3. Calculate Feature Contributions (Feature Importance explanation)
            # We measure how many standard deviations the current feature is from historical mean
            means = np.mean(X_train, axis=0)
            stds = np.std(X_train, axis=0)
            
            # Avoid division by zero
            stds = np.where(stds == 0, 1e-5, stds)
            
            z_scores = np.abs((X_curr[0] - means) / stds)
            total_z = sum(z_scores)
            
            if total_z > 0:
                raw_contributions = z_scores / total_z
            else:
                raw_contributions = np.array([0.2, 0.2, 0.2, 0.2, 0.2])

            features = ["amount", "time_of_day", "day_of_week", "device_frequency", "city_frequency"]
            contributions = {features[i]: float(raw_contributions[i]) for i in range(len(features))}

            # Confidence increases with historical sample size
            confidence = min(len(history) / 15.0, 1.0)

            return float(round(ml_score, 1)), float(round(confidence, 2)), contributions

        except Exception as e:
            # Fallback in case of numpy/sklearn errors
            import logging
            logging.getLogger("uvicorn.error").error(f"Error in Isolation Forest scoring: {e}")
            return 25.0, 0.2, {"amount": 0.5, "time_of_day": 0.3, "device_frequency": 0.2}
