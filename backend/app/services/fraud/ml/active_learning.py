import os
import joblib
import numpy as np
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from sklearn.ensemble import RandomForestClassifier
from app.models.analyst_decision import AnalystDecision
from app.models.transaction import Transaction
from app.models.fraud_evaluation import FraudEvaluation
from app.models.enums import TransactionStatus


# Fixed vocabulary of rule names to build a one-hot rule trigger vector
RULE_VOCABULARY = [
    "AVERAGE_AMOUNT_EXCEEDED", "PERCENTILE_AMOUNT_EXCEEDED", "NEW_DEVICE", "NEW_CITY", "NEW_IP",
    "FIRST_INTERNATIONAL_TRANSACTION", "UNUSUAL_HOUR", "NEW_PAYMENT_METHOD", "NEW_MERCHANT_CATEGORY",
    "BLACKLISTED_RECEIVER", "BLACKLISTED_IP", "BLACKLISTED_DEVICE", "RECEIVER_UNDER_INVESTIGATION",
    "HIGH_VELOCITY_LIMIT", "SHARED_DEVICE_SUSPICIOUS", "IMPOSSIBLE_TRAVEL", "LARGE_AMOUNT_AND_NEW_DEVICE",
    "NEW_CITY_AND_INTERNATIONAL", "SHARED_DEVICE_AND_BLACKLIST_RECEIVER", "MULTIPLE_UNUSUAL_BEHAVIORS"
]

MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
MODEL_PATH = os.path.join(MODEL_DIR, "supervised_model.joblib")


class ActiveLearningRetrainer:
    def __init__(self):
        self.min_training_samples = 10  # Minimum total labeled feedback to train

    def get_feature_vector(self, tx: Transaction, evaluation: FraudEvaluation, db: Session) -> List[float]:
        """
        Encodes a transaction and its evaluation results into a flat feature vector.
        """
        # Fetch history up to this transaction's creation time to calculate frequencies
        history = (
            db.query(Transaction)
            .filter(
                Transaction.sender_id == tx.sender_id,
                Transaction.status == TransactionStatus.APPROVED,
                Transaction.created_at < tx.created_at
            )
            .all()
        )

        def get_freq(val: Any, list_vals: List[Any]) -> float:
            if not list_vals:
                return 0.0
            return sum(1 for v in list_vals if str(v).lower() == str(val).lower()) / len(list_vals)

        history_devices = [h.device_id for h in history]
        history_cities = [h.city for h in history]

        device_freq = get_freq(tx.device_id, history_devices)
        city_freq = get_freq(tx.city, history_cities)

        # Baseline numeric features
        features = [
            float(tx.amount),
            float(tx.created_at.hour),
            float(tx.created_at.weekday()),
            float(device_freq),
            float(city_freq)
        ]

        # Triggered rules binary vector (1.0 if triggered, 0.0 if not)
        triggered_rules_dict = {
            r.get("rule_name"): r.get("triggered", False)
            for r in (evaluation.triggered_rules if evaluation else [])
        }

        for rule in RULE_VOCABULARY:
            features.append(1.0 if triggered_rules_dict.get(rule, False) else 0.0)

        return features

    def trigger_retraining(self) -> bool:
        """
        Retrains the supervised Random Forest model using manual analyst overrides.
        Saves the trained model to disk.
        """
        from app.database.database import SessionLocal
        db = SessionLocal()
        try:
            # Fetch all analyst feedback decisions
            decisions = db.query(AnalystDecision).all()
            
            # Check if we have enough labeled samples to establish a classification boundary
            if len(decisions) < self.min_training_samples:
                import logging
                logging.getLogger("uvicorn.error").info(
                    f"Skipping active learning retraining: Labeled decisions count ({len(decisions)}) is below minimum ({self.min_training_samples})"
                )
                return False

            X = []
            y = []

            for dec in decisions:
                tx = dec.transaction
                eval_record = db.query(FraudEvaluation).filter(FraudEvaluation.transaction_id == tx.id).first()
                
                if not tx or not eval_record:
                    continue

                # Encode features
                features = self.get_feature_vector(tx, eval_record, db)
                X.append(features)

                # Map manual action label:
                # - CONFIRMED_FRAUD -> 1 (Fraud)
                # - APPROVED / FALSE_POSITIVE -> 0 (Safe)
                label = 1 if dec.decision == "CONFIRMED_FRAUD" else 0
                y.append(label)

            if len(set(y)) < 2:
                # We need at least one class of each (Fraud and Safe) to train a classification boundary
                import logging
                logging.getLogger("uvicorn.error").info("Skipping active learning retraining: Training requires both fraud and safe manual decisions.")
                return False

            # Fit model
            X = np.array(X)
            y = np.array(y)

            clf = RandomForestClassifier(n_estimators=50, random_state=42)
            clf.fit(X, y)

            # Ensure directory exists
            os.makedirs(MODEL_DIR, exist_ok=True)
            
            # Save model
            joblib.dump({
                "model": clf,
                "sample_count": len(decisions)
            }, MODEL_PATH)

            import logging
            logging.getLogger("uvicorn.error").info(f"Active learning model retrained successfully! Saved model using {len(decisions)} labeled decisions.")
            return True
        except Exception as e:
            import logging
            logging.getLogger("uvicorn.error").error(f"Error in active learning retraining background task: {e}")
            return False
        finally:
            db.close()


active_learning_retrainer = ActiveLearningRetrainer()
