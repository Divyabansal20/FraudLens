from sqlalchemy.orm import Session
from app.models.transaction import Transaction
from app.models.enums import TransactionStatus
from app.models.fraud_evaluation import FraudEvaluation
from app.services.fraud.rule_engine.rule_engine import RuleEngine
from app.services.fraud.ml.isolation_forest import IsolationForestAnomalyDetector
from app.services.fraud.graph.graph_detector import GraphFraudDetector
from app.services.fraud.risk_aggregator import RiskAggregator
from app.services.fraud.decision_engine import DecisionEngine


class FraudOrchestrator:
    def __init__(self):
        self.rule_engine = RuleEngine()
        self.ml_detector = IsolationForestAnomalyDetector()
        self.graph_detector = GraphFraudDetector()
        self.risk_aggregator = RiskAggregator()
        self.decision_engine = DecisionEngine()

    def evaluate_transaction(self, db: Session, transaction: Transaction) -> FraudEvaluation:
        # 1. Fetch User historical transaction profile (only successfully APPROVED ones to avoid poisoning profile)
        history = (
            db.query(Transaction)
            .filter(
                Transaction.sender_id == transaction.sender_id,
                Transaction.status == TransactionStatus.APPROVED,
                Transaction.id != transaction.id
            )
            .order_by(Transaction.created_at.desc())
            .all()
        )

        # 2. Run Rule Engine (20% weight)
        rule_results, rule_score = self.rule_engine.run_all_rules(transaction, db, history)

        # 3. Run ML Engine (40% weight)
        ml_score, ml_confidence, ml_contributions = self.ml_detector.evaluate_anomaly(transaction, db, history)

        # 4. Run Graph Engine (40% weight)
        graph_score, graph_patterns, connected_accounts = self.graph_detector.evaluate_network(transaction, db)

        # Serialize triggered rules and details to dict format
        serialized_rules = [r.model_dump() for r in rule_results]

        # Active Learning Retraining Model Check (hybrid ML scoring)
        import os
        import joblib
        from app.services.fraud.ml.active_learning import MODEL_PATH, active_learning_retrainer
        
        if os.path.exists(MODEL_PATH):
            try:
                saved_data = joblib.load(MODEL_PATH)
                clf = saved_data["model"]
                sample_count = saved_data["sample_count"]
                
                # Mock evaluation record to pass triggered rules
                dummy_eval = type('DummyEval', (object,), {'triggered_rules': serialized_rules})
                features = active_learning_retrainer.get_feature_vector(transaction, dummy_eval, db)
                
                # Predict probability of class 1 (Fraud)
                supervised_score = float(clf.predict_proba([features])[0][1] * 100.0)
                
                # Blending coefficient: alpha scales with sample size, capped at 0.60
                alpha = min(0.60, sample_count * 0.05)
                ml_score = (1 - alpha) * ml_score + alpha * supervised_score
                ml_score = float(round(ml_score, 1))
            except Exception as e:
                import logging
                logging.getLogger("uvicorn.error").error(f"Error applying active learning model: {e}")

        # 5. Run Risk Assessment Engine
        agg_score, agg_confidence = self.risk_aggregator.aggregate_scores(
            rule_score=rule_score,
            ml_score=ml_score,
            graph_score=graph_score,
            ml_confidence=ml_confidence
        )

        # 6. Run Decision Engine
        status, cust_exp, analyst_exp = self.decision_engine.make_decision(
            aggregated_score=agg_score,
            triggered_rules=rule_results,
            ml_score=ml_score,
            ml_contributions=ml_contributions,
            graph_score=graph_score,
            graph_patterns=graph_patterns
        )

        # 7. AI/LLM Explanation generation
        from app.services.llm.explainer import gemini_explainer
        llm_cust_exp, llm_analyst_exp = gemini_explainer.generate_explanations(
            transaction=transaction,
            triggered_rules=serialized_rules,
            ml_score=ml_score,
            graph_score=graph_score,
            aggregated_score=agg_score,
            decision_status=status.value
        )
        if llm_cust_exp and llm_analyst_exp:
            cust_exp = llm_cust_exp
            analyst_exp = llm_analyst_exp

        # Update the transaction's status
        transaction.status = status

        # 7. Construct FraudEvaluation DB Model
        evaluation = FraudEvaluation(
            transaction_id=transaction.id,
            rule_engine_score=rule_score,
            ml_anomaly_score=ml_score,
            graph_risk_score=graph_score,
            aggregated_score=agg_score,
            confidence=agg_confidence,
            triggered_rules=serialized_rules,
            ml_details={
                "anomaly_score": ml_score,
                "confidence": ml_confidence,
                "feature_contributions": ml_contributions
            },
            graph_details={
                "risk_score": graph_score,
                "detected_patterns": graph_patterns,
                "connected_fraud_accounts": connected_accounts
            },
            customer_explanation=cust_exp,
            analyst_explanation=analyst_exp
        )

        return evaluation


# Singleton instance
fraud_orchestrator = FraudOrchestrator()
