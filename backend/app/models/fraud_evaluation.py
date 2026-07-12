from datetime import datetime
from sqlalchemy import DateTime, ForeignKey, Float, JSON, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.database import Base
from app.models.transaction import Transaction


class FraudEvaluation(Base):
    __tablename__ = "fraud_evaluations"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    
    transaction_id: Mapped[int] = mapped_column(
        ForeignKey("transactions.id"), 
        unique=True, 
        nullable=False
    )
    
    rule_engine_score: Mapped[float] = mapped_column(
        Float, 
        default=0.0
    )
    
    ml_anomaly_score: Mapped[float] = mapped_column(
        Float, 
        default=0.0
    )
    
    graph_risk_score: Mapped[float] = mapped_column(
        Float, 
        default=0.0
    )
    
    aggregated_score: Mapped[float] = mapped_column(
        Float, 
        default=0.0
    )
    
    confidence: Mapped[float] = mapped_column(
        Float, 
        default=0.0
    )
    
    triggered_rules: Mapped[dict] = mapped_column(
        JSON, 
        default=list
    )
    
    ml_details: Mapped[dict] = mapped_column(
        JSON, 
        default=dict
    )
    
    graph_details: Mapped[dict] = mapped_column(
        JSON, 
        default=dict
    )
    
    customer_explanation: Mapped[str] = mapped_column(
        Text, 
        nullable=True
    )
    
    analyst_explanation: Mapped[str] = mapped_column(
        Text, 
        nullable=True
    )
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime, 
        default=datetime.utcnow
    )

    # Relationship to transaction
    transaction = relationship(Transaction, backref="fraud_evaluation")
