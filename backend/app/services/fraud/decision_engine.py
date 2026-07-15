from typing import List, Dict, Tuple, Any
from app.models.enums import TransactionStatus
from app.services.fraud.rule_engine.base_rule import RuleEvaluationResult
from app.core.config import settings


class DecisionEngine:
    def __init__(self):
        # Risk threshold limits loaded dynamically from settings
        self.review_threshold = settings.FRAUD_REVIEW_THRESHOLD
        self.blocked_threshold = settings.FRAUD_BLOCKED_THRESHOLD

    def make_decision(
        self,
        aggregated_score: float,
        triggered_rules: List[RuleEvaluationResult],
        ml_score: float,
        ml_contributions: Dict[str, float],
        graph_score: float,
        graph_patterns: List[str]
    ) -> Tuple[TransactionStatus, str, str]:
        """
        Determines the final transaction status based on aggregated risk score:
        - Score < 40: APPROVED
        - 40 <= Score < 80: REVIEW
        - Score >= 80: BLOCKED
        
        Generates distinct explanation formats for Customer and Analyst.
        
        Returns:
            status: TransactionStatus
            customer_explanation: str
            analyst_explanation: str
        """
        # 1. Determine Status
        if aggregated_score >= self.blocked_threshold:
            status = TransactionStatus.BLOCKED
        elif aggregated_score >= self.review_threshold:
            status = TransactionStatus.REVIEW
        else:
            status = TransactionStatus.APPROVED

        # 2. Get active triggered rules
        active_rules = [r for r in triggered_rules if r.triggered]

        # 3. Generate Customer Explanation (high-level, security-oriented, non-technical)
        customer_explanation = self._generate_customer_explanation(status, active_rules)

        # 4. Generate Analyst Explanation (detailed metrics, rules triggers, ML and Graph results)
        analyst_explanation = self._generate_analyst_explanation(
            status,
            aggregated_score,
            active_rules,
            ml_score,
            ml_contributions,
            graph_score,
            graph_patterns
        )

        return status, customer_explanation, analyst_explanation

    def _generate_customer_explanation(self, status: TransactionStatus, active_rules: List[RuleEvaluationResult]) -> str:
        if status == TransactionStatus.APPROVED:
            return "Transaction verified and approved successfully."
            
        elif status == TransactionStatus.REVIEW:
            # Look at general trigger descriptors to compile a friendly explanation
            reasons = []
            for r in active_rules:
                if r.rule_name == "NEW_DEVICE":
                    reasons.append("a new device")
                elif r.rule_name == "NEW_CITY":
                    reasons.append("an unusual location")
                elif r.rule_name == "UNUSUAL_HOUR":
                    reasons.append("an unusual time of day")
                elif r.rule_name == "FIRST_INTERNATIONAL_TRANSACTION":
                    reasons.append("an international location")
                elif r.rule_name == "PERCENTILE_AMOUNT_EXCEEDED" or r.rule_name == "AVERAGE_AMOUNT_EXCEEDED":
                    reasons.append("an atypical transfer amount")

            if not reasons:
                return "This transaction is temporarily held under review by our security system for verification."
                
            reasons_str = " and ".join(reasons[:3])
            return f"This transaction is temporarily held for verification because it originated from {reasons_str}. Our security team is verifying the payment."
            
        else:  # BLOCKED
            # Check critical rule triggers
            is_blacklisted = any(r.rule_name in ["BLACKLISTED_RECEIVER", "BLACKLISTED_IP", "BLACKLISTED_DEVICE", "SHARED_DEVICE_BLACKLIST_RECEIVER"] for r in active_rules)
            if is_blacklisted:
                return "This transaction was blocked because it was sent to or associated with an account, device, or IP address flagged on our security blacklist."
                
            # Compile customer-friendly reasons
            reasons = []
            for r in active_rules:
                if r.rule_name == "LARGE_AMOUNT_NEW_DEVICE":
                    reasons.append("a high payment amount on an unrecognized device")
                elif r.rule_name == "VELOCITY":
                    reasons.append("too many rapid transactions in a short timeframe")
                elif r.rule_name == "IMPOSSIBLE_TRAVEL":
                    reasons.append("impossible movement across locations in a short timeframe")
                elif r.rule_name == "MULTI_ANOMALY":
                    reasons.append("multiple behavioral deviations detected simultaneously")
                elif r.rule_name in ["PERCENTILE_AMOUNT_EXCEEDED", "AVERAGE_AMOUNT_EXCEEDED"]:
                    reasons.append("a transfer amount significantly higher than your typical average")
                elif r.rule_name == "NEW_DEVICE":
                    reasons.append("an unrecognized device footprint")
                elif r.rule_name == "NEW_CITY":
                    reasons.append("an unusual login location")
                elif r.rule_name == "UNUSUAL_HOUR":
                    reasons.append("an atypical payment hour")

            if reasons:
                reasons_str = ", ".join(reasons[:3])
                return f"This transaction was blocked by our automated security systems due to: {reasons_str}. If you believe this is an error, please contact support."

            return "This transaction was blocked by our automated security systems due to multiple high-risk indicators. If you believe this is an error, please contact support."

    def _generate_analyst_explanation(
        self,
        status: TransactionStatus,
        aggregated_score: float,
        active_rules: List[RuleEvaluationResult],
        ml_score: float,
        ml_contributions: Dict[str, float],
        graph_score: float,
        graph_patterns: List[str]
    ) -> str:
        explanation_lines = [
            f"=== DECISION: {status.value} (Risk Score: {aggregated_score:.1f}/100) ===",
            ""
        ]

        # Triggered Rules summary
        explanation_lines.append("--- TRIGGERED BUSINESS RULES ---")
        if not active_rules:
            explanation_lines.append("No rules triggered.")
        for r in active_rules:
            explanation_lines.append(f"- [{r.severity}] {r.rule_name} (Contribution: +{r.score_contribution:.0f})")
            explanation_lines.append(f"  Reason: {r.reason}")
        explanation_lines.append("")

        # ML anomaly forest summary
        explanation_lines.append("--- ML ANOMALY DETECTION (Isolation Forest) ---")
        explanation_lines.append(f"Anomaly Score: {ml_score:.1f}/100")
        explanation_lines.append("Top Feature Contributions:")
        # Sort contributions descending
        sorted_contrib = sorted(ml_contributions.items(), key=lambda item: item[1], reverse=True)
        for feat, val in sorted_contrib:
            explanation_lines.append(f"  * {feat}: {val * 100:.1f}%")
        explanation_lines.append("")

        # Graph Engine summary
        explanation_lines.append("--- GRAPH RELATION ENGINE (NetworkX) ---")
        explanation_lines.append(f"Network Risk Score: {graph_score:.1f}/100")
        if graph_patterns:
            explanation_lines.append("Detected Network Patterns:")
            for pat in graph_patterns:
                explanation_lines.append(f"  * {pat}")
        else:
            explanation_lines.append("No suspicious network paths or shared structures found.")
        explanation_lines.append("")

        explanation_lines.append("--- EVIDENCE SUMMARY ---")
        if status == TransactionStatus.APPROVED:
            explanation_lines.append("Safe transaction: cumulative scores are within normal limits.")
        elif status == TransactionStatus.REVIEW:
            explanation_lines.append("Uncertain risk: requires analyst verification (routing to review queue).")
        else:
            explanation_lines.append("Critical risk: automatic block issued based on definitive indicators.")

        return "\n".join(explanation_lines)
