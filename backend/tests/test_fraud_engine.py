from datetime import datetime, timedelta
import unittest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from app.database.database import Base
from app.models.user import User
from app.models.transaction import Transaction
from app.models.blacklist import BlacklistedEntity
from app.models.fraud_evaluation import FraudEvaluation
from app.models.analyst_decision import AnalystDecision
from app.models.enums import TransactionStatus

# Import engine components
from app.services.fraud.orchestrator import FraudOrchestrator
from app.services.fraud.rule_engine.base_rule import RuleEvaluationResult
from app.services.fraud.rule_engine.rule_engine import RuleEngine
from app.services.fraud.ml.isolation_forest import IsolationForestAnomalyDetector
from app.services.fraud.graph.graph_detector import GraphFraudDetector
from app.services.fraud.risk_aggregator import RiskAggregator
from app.services.fraud.decision_engine import DecisionEngine


class TestFraudDetectionEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Configure in-memory SQLite for testing to ensure isolated and fast execution
        cls.engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
        Base.metadata.create_all(bind=cls.engine)
        cls.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=cls.engine)

    def setUp(self):
        # Establish connection and start transaction for rollback isolation
        self.connection = self.engine.connect()
        self.trans = self.connection.begin()
        self.db = self.SessionLocal(bind=self.connection)
        
        # Seed basic users (rolled back automatically in tearDown)
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

        # Seed global blacklists
        self.blacklist_receiver = BlacklistedEntity(
            entity_type="receiver",
            entity_value="Bad Actor Corp",
            reason="Confirmed phishing receiver",
            is_active=True
        )
        self.blacklist_ip = BlacklistedEntity(
            entity_type="ip",
            entity_value="198.51.100.99",
            reason="Phishing IP",
            is_active=True
        )
        self.db.add(self.blacklist_receiver)
        self.db.add(self.blacklist_ip)
        self.db.commit()

        # Instantiate fraud pipeline components
        self.orchestrator = FraudOrchestrator()
        self.rule_engine = RuleEngine()
        self.ml_detector = IsolationForestAnomalyDetector()
        self.graph_detector = GraphFraudDetector()
        self.risk_aggregator = RiskAggregator()
        self.decision_engine = DecisionEngine()

    def tearDown(self):
        # Close session, rollback everything to keep tables clean
        self.db.close()
        self.trans.rollback()
        self.connection.close()

    def test_rule_engine_cold_start(self):
        """
        Verify rule engine behaves correctly when there is zero historical transaction history.
        """
        new_tx = Transaction(
            sender_id=self.customer.id,
            receiver_name="Amit Patel",
            amount=2500.00,
            payment_method="UPI",
            device_id="Device_S24",
            city="Delhi",
            ip_address="192.168.1.5",
            country="IN",
            status=TransactionStatus.PROCESSING,
            created_at=datetime.utcnow()
        )
        self.db.add(new_tx)
        self.db.commit()

        # Run rules: average amount, percentile amount, new device, etc. shouldn't trigger
        rule_results, score = self.rule_engine.run_all_rules(new_tx, self.db, [])
        
        # Capped score should be 0 because no personalized rules can trigger on cold start
        self.assertEqual(score, 0.0)
        
        # Verify specific rules outputting "triggered=False"
        triggered_names = [r.rule_name for r in rule_results if r.triggered]
        self.assertNotIn("AVERAGE_AMOUNT_EXCEEDED", triggered_names)
        self.assertNotIn("NEW_DEVICE", triggered_names)

    def test_rule_engine_triggers_personalized_anomalies(self):
        """
        Seed a normal transaction history and verify that personalized rules flag deviations.
        """
        # Seed normal history: 6 small Delhi transactions
        history = []
        base_time = datetime.utcnow() - timedelta(days=5)
        for i in range(6):
            tx = Transaction(
                sender_id=self.customer.id,
                receiver_name="Amit Patel",
                amount=100.00, # average ₹100
                payment_method="UPI",
                device_id="Device_Trusted_1",
                city="Delhi",
                ip_address="192.168.1.5",
                country="IN",
                status=TransactionStatus.APPROVED,
                created_at=base_time + timedelta(hours=i * 2)
            )
            self.db.add(tx)
            history.append(tx)
        self.db.commit()

        # Now construct an anomalous transaction (Amount > 5x avg, New device, New city, New country)
        anomalous_tx = Transaction(
            sender_id=self.customer.id,
            receiver_name="Amit Patel",
            amount=1000.00, # 10x average
            payment_method="UPI",
            device_id="Device_Brand_New",
            city="Mumbai",
            ip_address="192.168.1.5",
            country="US", # new country
            status=TransactionStatus.PROCESSING,
            created_at=datetime.utcnow()
        )
        self.db.add(anomalous_tx)
        self.db.commit()

        # Run Rule Engine
        rule_results, score = self.rule_engine.run_all_rules(anomalous_tx, self.db, history)
        
        triggered_names = [r.rule_name for r in rule_results if r.triggered]
        
        # Should trigger: Average Amount, Percentile, New Device, New City, First International, and contextual rules
        self.assertIn("AVERAGE_AMOUNT_EXCEEDED", triggered_names)
        self.assertIn("PERCENTILE_AMOUNT_EXCEEDED", triggered_names)
        self.assertIn("NEW_DEVICE", triggered_names)
        self.assertIn("NEW_CITY", triggered_names)
        self.assertIn("FIRST_INTERNATIONAL_TRANSACTION", triggered_names)
        self.assertIn("LARGE_AMOUNT_AND_NEW_DEVICE", triggered_names)
        self.assertIn("NEW_CITY_AND_INTERNATIONAL", triggered_names)
        self.assertIn("MULTIPLE_UNUSUAL_BEHAVIORS", triggered_names)
        
        # Total score should be capped at 100
        self.assertEqual(score, 100.0)

    def test_global_blacklist_rules(self):
        """
        Verify that global blacklist items trigger immediate critical flags.
        """
        # Transaction sent to blacklisted receiver
        black_tx = Transaction(
            sender_id=self.customer.id,
            receiver_name="Bad Actor Corp",
            amount=500.00,
            payment_method="UPI",
            device_id="Device_Trusted_1",
            city="Delhi",
            ip_address="192.168.1.5",
            country="IN",
            status=TransactionStatus.PROCESSING,
            created_at=datetime.utcnow()
        )
        self.db.add(black_tx)
        self.db.commit()

        rule_results, score = self.rule_engine.run_all_rules(black_tx, self.db, [])
        triggered_names = [r.rule_name for r in rule_results if r.triggered]
        
        self.assertIn("BLACKLISTED_RECEIVER", triggered_names)
        # Verify Critical severity contribution
        crit_contrib = next(r for r in rule_results if r.rule_name == "BLACKLISTED_RECEIVER")
        self.assertEqual(crit_contrib.severity, "CRITICAL")
        self.assertEqual(crit_contrib.score_contribution, 90.0)

    def test_impossible_travel_calculation(self):
        """
        Verify velocity calculations for physically impossible travel between cities.
        """
        # Last transaction: Delhi, 10 minutes ago
        last_tx = Transaction(
            sender_id=self.customer.id,
            receiver_name="Amit Patel",
            amount=200.00,
            payment_method="UPI",
            device_id="Device_S24",
            city="Delhi",
            ip_address="192.168.1.5",
            country="IN",
            status=TransactionStatus.APPROVED,
            created_at=datetime.utcnow() - timedelta(minutes=10)
        )
        self.db.add(last_tx)
        self.db.commit()

        # Current transaction: Mumbai (distance is ~1150 km)
        curr_tx = Transaction(
            sender_id=self.customer.id,
            receiver_name="Amit Patel",
            amount=200.00,
            payment_method="UPI",
            device_id="Device_S24",
            city="Mumbai",
            ip_address="192.168.1.5",
            country="IN",
            status=TransactionStatus.PROCESSING,
            created_at=datetime.utcnow()
        )
        self.db.add(curr_tx)
        self.db.commit()

        rule_results, score = self.rule_engine.run_all_rules(curr_tx, self.db, [last_tx])
        triggered_names = [r.rule_name for r in rule_results if r.triggered]
        
        # Should flag impossible travel since Delhi to Mumbai in 10 mins requires ~6900 km/h
        self.assertIn("IMPOSSIBLE_TRAVEL", triggered_names)

    def test_isolation_forest_ml_engine(self):
        """
        Verify that Isolation Forest fits on historical data and scores anomaly.
        """
        import random
        random.seed(42)  # Seed for reproducibility
        
        history = []
        base_time = datetime.utcnow() - timedelta(days=15)
        # Seed 25 transactions to establish a stable ML training boundary
        for i in range(25):
            tx = Transaction(
                sender_id=self.customer.id,
                receiver_name="Amit Patel",
                amount=100.00 + (i * 5.0) + random.uniform(-10.0, 10.0),
                payment_method="UPI",
                device_id="Device_A",
                city="Delhi",
                ip_address="192.168.1.5",
                country="IN",
                status=TransactionStatus.APPROVED,
                created_at=base_time + timedelta(hours=i * 6)  # varies hour and weekday
            )
            self.db.add(tx)
            history.append(tx)
        self.db.commit()

        # Test case A: Similar transaction -> low anomaly score
        normal_tx = Transaction(
            sender_id=self.customer.id,
            receiver_name="Amit Patel",
            amount=150.00,
            payment_method="UPI",
            device_id="Device_A",
            city="Delhi",
            ip_address="192.168.1.5",
            country="IN",
            status=TransactionStatus.PROCESSING,
            created_at=datetime.utcnow()
        )
        score_normal, conf_normal, contrib_normal = self.ml_detector.evaluate_anomaly(normal_tx, self.db, history)
        
        # Test case B: Drastic deviation (₹50,000, new device) -> high anomaly score
        anomaly_tx = Transaction(
            sender_id=self.customer.id,
            receiver_name="Amit Patel",
            amount=50000.00,
            payment_method="UPI",
            device_id="Device_New_X",
            city="Delhi",
            ip_address="192.168.1.5",
            country="IN",
            status=TransactionStatus.PROCESSING,
            created_at=datetime.utcnow()
        )
        score_anom, conf_anom, contrib_anom = self.ml_detector.evaluate_anomaly(anomaly_tx, self.db, history)
        
        # Assert anomaly score behaves as expected
        self.assertTrue(score_anom > score_normal)
        self.assertTrue(contrib_anom["amount"] > 0.0)

    def test_graph_network_distance_analysis(self):
        """
        Verify that Graph Fraud Detector identifies paths to blacklisted entities.
        """
        # Create a transaction linking Customer (A) to Device (X)
        tx1 = Transaction(
            sender_id=self.customer.id,
            receiver_name="Amit Patel",
            amount=100.00,
            payment_method="UPI",
            device_id="Shared_Device_9",
            city="Delhi",
            ip_address="192.168.1.5",
            country="IN",
            status=TransactionStatus.APPROVED,
            created_at=datetime.utcnow() - timedelta(days=2)
        )
        # Create a blocked transaction associated with another user (B) using the same device (X)
        tx2 = Transaction(
            sender_id=99, # different user
            receiver_name="Fraud mule",
            amount=1000.00,
            payment_method="NetBanking",
            device_id="Shared_Device_9",
            city="Mumbai",
            ip_address="192.168.1.99",
            country="IN",
            status=TransactionStatus.BLOCKED, # BLOCKED
            created_at=datetime.utcnow() - timedelta(days=1)
        )
        self.db.add(tx1)
        self.db.add(tx2)
        self.db.commit()

        # Current transaction for our customer (A)
        curr_tx = Transaction(
            sender_id=self.customer.id,
            receiver_name="Amit Patel",
            amount=150.00,
            payment_method="UPI",
            device_id="Shared_Device_9",
            city="Delhi",
            ip_address="192.168.1.5",
            country="IN",
            status=TransactionStatus.PROCESSING,
            created_at=datetime.utcnow()
        )
        self.db.add(curr_tx)
        self.db.commit()

        # Evaluate graph
        risk_score, patterns, connected_accts = self.graph_detector.evaluate_network(curr_tx, self.db)
        
        # Risk score should be 95 because the customer is directly connected to a device used in blocked fraud
        self.assertEqual(risk_score, 95.0)
        self.assertIn(99, connected_accts)

    def test_end_to_end_decision_routing(self):
        """
        Verify that decision engine maps aggregated risk scores to APPROVED, REVIEW, and BLOCKED.
        """
        # Test Case 1: Safe parameters
        status1, cust_exp1, analyst_exp1 = self.decision_engine.make_decision(
            aggregated_score=15.0,
            triggered_rules=[],
            ml_score=10.0,
            ml_contributions={"amount": 0.2},
            graph_score=0.0,
            graph_patterns=[]
        )
        self.assertEqual(status1, TransactionStatus.APPROVED)

        # Test Case 2: Intermediate risk (REVIEW)
        rule_res = [
            RuleEvaluationResult(
                rule_name="NEW_DEVICE",
                triggered=True,
                reason="New Device",
                severity="MEDIUM",
                score_contribution=20.0
            )
        ]
        status2, cust_exp2, analyst_exp2 = self.decision_engine.make_decision(
            aggregated_score=45.0,
            triggered_rules=rule_res,
            ml_score=55.0,
            ml_contributions={"device_frequency": 0.8},
            graph_score=30.0,
            graph_patterns=["2 hops to blacklist"]
        )
        self.assertEqual(status2, TransactionStatus.REVIEW)
        self.assertIn("verification", cust_exp2) # customer explanation mentions verification
        self.assertIn("NEW_DEVICE", analyst_exp2) # analyst gets details

        # Test Case 3: Extreme risk (BLOCKED)
        status3, cust_exp3, analyst_exp3 = self.decision_engine.make_decision(
            aggregated_score=85.0,
            triggered_rules=rule_res,
            ml_score=90.0,
            ml_contributions={"amount": 0.9},
            graph_score=90.0,
            graph_patterns=["Direct path to blacklist"]
        )
        self.assertEqual(status3, TransactionStatus.BLOCKED)
        self.assertIn("blocked", cust_exp3)


if __name__ == "__main__":
    unittest.main()
