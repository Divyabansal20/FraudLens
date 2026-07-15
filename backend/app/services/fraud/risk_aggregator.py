from typing import Tuple
from app.core.config import settings


class RiskAggregator:
    def __init__(self):
        # Configurable weights loaded dynamically from settings
        self.rule_weight = settings.FRAUD_RULE_WEIGHT
        self.ml_weight = settings.FRAUD_ML_WEIGHT
        self.graph_weight = settings.FRAUD_GRAPH_WEIGHT

    def aggregate_scores(
        self, 
        rule_score: float, 
        ml_score: float, 
        graph_score: float,
        ml_confidence: float,
        behavior_drift_score: float = 0.0,
        graph_confidence: float = 0.8
    ) -> Tuple[float, float]:
        """
        Combines scores from the four fraud engines:
        Risk = (0.2 * Rule) + (0.3 * ML) + (0.3 * Graph) + (0.2 * Behavior)
        
        Calculates aggregated confidence.
        
        Returns:
            aggregated_score: float (0.0 - 100.0)
            confidence: float (0.0 - 1.0)
        """
        # Calculate weighted sum
        aggregated_score = (
            (0.20 * rule_score) +
            (0.30 * ml_score) +
            (0.30 * graph_score) +
            (0.20 * behavior_drift_score)
        )
        
        # Rule engine is deterministic (1.0), behavior is 0.9
        rule_confidence = 1.0
        behavior_confidence = 0.9
        
        # Combined confidence
        aggregated_confidence = (
            (0.20 * rule_confidence) +
            (0.30 * ml_confidence) +
            (0.30 * graph_confidence) +
            (0.20 * behavior_confidence)
        )

        return float(round(aggregated_score, 1)), float(round(aggregated_confidence, 2))
