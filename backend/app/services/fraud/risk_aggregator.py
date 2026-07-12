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
        graph_confidence: float = 0.8
    ) -> Tuple[float, float]:
        """
        Combines scores from the three fraud engines:
        Risk = (0.2 * Rule) + (0.4 * ML) + (0.4 * Graph)
        
        Calculates aggregated confidence.
        
        Returns:
            aggregated_score: float (0.0 - 100.0)
            confidence: float (0.0 - 1.0)
        """
        # Calculate weighted sum
        aggregated_score = (
            (self.rule_weight * rule_score) +
            (self.ml_weight * ml_score) +
            (self.graph_weight * graph_score)
        )
        
        # Rule engine is deterministic, so its confidence is 1.0
        rule_confidence = 1.0
        
        # Combined confidence
        aggregated_confidence = (
            (self.rule_weight * rule_confidence) +
            (self.ml_weight * ml_confidence) +
            (self.graph_weight * graph_confidence)
        )

        return float(round(aggregated_score, 1)), float(round(aggregated_confidence, 2))
