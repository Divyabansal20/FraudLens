import os
import unittest
import joblib
from datetime import datetime, timedelta
from unittest.mock import patch
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.database import Base
from app.models.user import User
from app.models.transaction import Transaction
from app.models.enums import TransactionStatus
from app.models.fraud_evaluation import FraudEvaluation
from app.models.analyst_decision import AnalystDecision

# Import engine components
from app.services.fraud.ml.active_learning import active_learning_retrainer, MODEL_PATH, MODEL_DIR
from app.services.fraud.orchestrator import fraud_orchestrator


class TestActiveLearningPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Configure in-memory SQLite
        cls.engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
        Base.metadata.create_all(bind=cls.engine)
        cls.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=cls.engine)

    def setUp(self):
        self.connection = self.engine.connect()
        self.trans = self.connection.begin()
        self.db = self.SessionLocal(bind=self.connection)
        
        # Clean up any existing model files from previous runs
        if os.path.exists(MODEL_PATH):
            try:
                os.remove(MODEL_PATH)
            except OSError:
                pass

        # Seed mock users
        self.customer = User(
            name="Rahul Sharma",
            email="customer_test@fraudlens.com",
            password="hashedpassword",
            role="customer"
        )
        self.analyst = User(
            name="Malhotra Test",
            email="analyst_test@fraudlens.com",
            password="hashedpassword",
            role="analyst"
        )
        self.db.add(self.customer)
        self.db.add(self.analyst)
        self.db.commit()
        self.customer_id = self.customer.id
        self.analyst_id = self.analyst.id

    def tearDown(self):
        self.db.close()
        self.trans.rollback()
        self.connection.close()
        
        # Clean up the test model file
        if os.path.exists(MODEL_PATH):
            try:
                os.remove(MODEL_PATH)
            except OSError:
                pass

    @patch("app.database.database.SessionLocal")
    def test_active_learning_retraining_trigger(self, mock_session_local):
        # Configure the mocked session creator to return our test db session
        mock_session_local.return_value = self.db

        # Retraining should skip if there are less than 10 decisions
        success = active_learning_retrainer.trigger_retraining()
        self.assertFalse(success)
        self.assertFalse(os.path.exists(MODEL_PATH))

        # Seed 10 transactions with analyst decisions (5 FRAUD, 5 SAFE)
        base_time = datetime.utcnow() - timedelta(days=5)
        for i in range(10):
            # Create transaction
            tx = Transaction(
                sender_id=self.customer_id,
                receiver_name="Amit Patel" if i % 2 == 0 else "Fraudulent Org",
                amount=150.00 + (i * 20.0),
                payment_method="UPI",
                device_id=f"Device_{i}",
                city="Delhi",
                ip_address="192.168.1.5",
                country="IN",
                status=TransactionStatus.BLOCKED if i % 2 == 0 else TransactionStatus.APPROVED,
                created_at=base_time + timedelta(hours=i * 2)
            )
            self.db.add(tx)
            self.db.flush()

            # Create evaluation record
            eval_record = FraudEvaluation(
                transaction_id=tx.id,
                rule_engine_score=40.0 if i % 2 == 0 else 0.0,
                ml_anomaly_score=15.0,
                graph_risk_score=90.0 if i % 2 == 0 else 0.0,
                aggregated_score=60.0 if i % 2 == 0 else 10.0,
                confidence=0.5,
                triggered_rules=[
                    {"rule_name": "NEW_DEVICE", "triggered": True, "severity": "MEDIUM", "score_contribution": 20.0}
                ] if i % 2 == 0 else [],
                ml_details={},
                graph_details={},
                customer_explanation="Reviewing",
                analyst_explanation="Reviewing"
            )
            self.db.add(eval_record)
            self.db.flush()

            # Create Analyst Decision (Approve vs. Confirm Fraud)
            decision = AnalystDecision(
                transaction_id=tx.id,
                analyst_id=self.analyst_id,
                prediction="FRAUD" if i % 2 == 0 else "SAFE",
                decision="CONFIRMED_FRAUD" if i % 2 == 0 else "FALSE_POSITIVE",
                notes=f"Test note {i}",
                created_at=datetime.utcnow()
            )
            self.db.add(decision)

        self.db.commit()

        # Retrain now that we have 10 balanced samples
        success = active_learning_retrainer.trigger_retraining()
        self.assertTrue(success)
        self.assertTrue(os.path.exists(MODEL_PATH))

        # Check saved joblib contents
        saved_data = joblib.load(MODEL_PATH)
        self.assertEqual(saved_data["sample_count"], 10)
        self.assertIsNotNone(saved_data["model"])

        # Test prediction integration (orchestrator should blend scores)
        # Create a new test transaction
        test_tx = Transaction(
            sender_id=self.customer_id,
            receiver_name="Amit Patel",
            amount=50000.0,  # Matches the fallback trigger
            payment_method="UPI",
            device_id="Device_A",
            city="Delhi",
            ip_address="192.168.1.5",
            country="IN",
            status=TransactionStatus.PROCESSING,
            created_at=datetime.utcnow()
        )
        self.db.add(test_tx)
        self.db.commit()

        # Run orchestrator
        evaluation = fraud_orchestrator.evaluate_transaction(self.db, test_tx)
        
        # The ML score should be blended. Since the model exists, it loaded and computed it successfully.
        self.assertIsNotNone(evaluation.ml_anomaly_score)
        print(f"Blended ML Anomaly Score in test: {evaluation.ml_anomaly_score}")


if __name__ == "__main__":
    unittest.main()
