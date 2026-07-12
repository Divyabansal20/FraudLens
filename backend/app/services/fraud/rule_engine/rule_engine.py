from typing import List, Tuple
from sqlalchemy.orm import Session
from app.models.transaction import Transaction
from app.services.fraud.rule_engine.base_rule import BaseRule, RuleEvaluationResult
from app.services.fraud.rule_engine.rules.personalized_rules import (
    AverageAmountRule,
    PercentileAmountRule,
    NewDeviceRule,
    NewCityRule,
    NewIPRule,
    FirstInternationalRule,
    UnusualHourRule,
    NewPaymentMethodRule,
    NewMerchantCategoryRule,
)
from app.services.fraud.rule_engine.rules.global_rules import (
    BlacklistReceiverRule,
    BlacklistIPRule,
    BlacklistDeviceRule,
    ReceiverInvestigationRule,
    VelocityRule,
    SharedDeviceRule,
    ImpossibleTravelRule,
)
from app.services.fraud.rule_engine.rules.contextual_rules import (
    LargeAmountNewDeviceRule,
    NewCityInternationalRule,
    SharedDeviceBlacklistReceiverRule,
    MultiAnomalyRule,
)


class RuleEngine:
    def __init__(self):
        # Register rules
        self.rules: List[BaseRule] = [
            # Personalized Rules
            AverageAmountRule(),
            PercentileAmountRule(),
            NewDeviceRule(),
            NewCityRule(),
            NewIPRule(),
            FirstInternationalRule(),
            UnusualHourRule(),
            NewPaymentMethodRule(),
            NewMerchantCategoryRule(),
            
            # Global Rules
            BlacklistReceiverRule(),
            BlacklistIPRule(),
            BlacklistDeviceRule(),
            ReceiverInvestigationRule(),
            VelocityRule(),
            SharedDeviceRule(),
            ImpossibleTravelRule(),
            
            # Contextual Rules
            LargeAmountNewDeviceRule(),
            NewCityInternationalRule(),
            SharedDeviceBlacklistReceiverRule(),
        ]
        
        # Keep multi anomaly rule separate to run last
        self.multi_anomaly_rule = MultiAnomalyRule()

    def run_all_rules(
        self, 
        transaction: Transaction, 
        db: Session, 
        history: List[Transaction]
    ) -> Tuple[List[RuleEvaluationResult], float]:
        triggered_results: List[RuleEvaluationResult] = []
        individual_triggered_count = 0

        # 1. Run all standard rules
        for rule in self.rules:
            try:
                res = rule.evaluate(transaction, db, history)
                triggered_results.append(res)
                if res.triggered:
                    individual_triggered_count += 1
            except Exception as e:
                # Log rule execution failures but don't crash the engine
                import logging
                logging.getLogger("uvicorn.error").error(f"Error evaluating rule {rule.name}: {e}")
                triggered_results.append(
                    RuleEvaluationResult(
                        rule_name=rule.name,
                        triggered=False,
                        reason=f"Failed to evaluate: {str(e)}",
                        severity=rule.severity,
                        score_contribution=0.0
                    )
                )

        # 2. Run Multi-Anomaly Rule dynamically based on other triggers
        if individual_triggered_count >= 3:
            multi_res = RuleEvaluationResult(
                rule_name=self.multi_anomaly_rule.name,
                triggered=True,
                reason=f"Critical risk threshold crossed: {individual_triggered_count} distinct anomalies detected for this transaction",
                severity=self.multi_anomaly_rule.severity,
                score_contribution=self.multi_anomaly_rule.score
            )
            triggered_results.append(multi_res)
        else:
            triggered_results.append(
                RuleEvaluationResult(
                    rule_name=self.multi_anomaly_rule.name,
                    triggered=False,
                    reason=f"Anomalous trigger count ({individual_triggered_count}) below threshold of 3",
                    severity=self.multi_anomaly_rule.severity,
                    score_contribution=0.0
                )
            )

        # 3. Sum up the score contributions and cap at 100
        total_score = sum(r.score_contribution for r in triggered_results if r.triggered)
        capped_score = min(total_score, 100.0)

        return triggered_results, capped_score
