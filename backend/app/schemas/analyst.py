from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, field_validator
from app.models.enums import TransactionStatus


class AnalystDecisionRequest(BaseModel):
    decision: str  # 'APPROVE', 'CONFIRMED_FRAUD', 'FALSE_POSITIVE'
    notes: Optional[str] = None

    @field_validator("decision")
    @classmethod
    def validate_decision(cls, v: str) -> str:
        upper_v = v.upper()
        allowed = ["APPROVE", "CONFIRMED_FRAUD", "FALSE_POSITIVE"]
        if upper_v not in allowed:
            raise ValueError(f"Decision must be one of {allowed}")
        return upper_v


class FraudEvaluationResponse(BaseModel):
    id: int
    transaction_id: int
    rule_engine_score: float
    ml_anomaly_score: float
    graph_risk_score: float
    aggregated_score: float
    confidence: float
    triggered_rules: List[Dict[str, Any]]
    ml_details: Dict[str, Any]
    graph_details: Dict[str, Any]
    customer_explanation: Optional[str]
    analyst_explanation: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class AnalystTransactionListItem(BaseModel):
    id: int
    sender_id: int
    receiver_name: str
    amount: float
    payment_method: str
    device_id: str
    city: str
    ip_address: Optional[str]
    merchant_category: Optional[str]
    country: Optional[str]
    status: TransactionStatus
    created_at: datetime
    aggregated_score: Optional[float] = None
    confidence: Optional[float] = None
    customer_explanation: Optional[str] = None

    class Config:
        from_attributes = True
