from datetime import datetime
from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.database import Base
from app.models.transaction import Transaction


class AnalystDecision(Base):
    __tablename__ = "analyst_decisions"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    
    transaction_id: Mapped[int] = mapped_column(
        ForeignKey("transactions.id"), 
        unique=True, 
        nullable=False
    )
    
    analyst_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"), 
        nullable=False
    )
    
    prediction: Mapped[str] = mapped_column(
        String(50)
    )  # e.g., 'FRAUD' or 'SAFE' (predicted status before decision)
    
    decision: Mapped[str] = mapped_column(
        String(50)
    )  # e.g., 'APPROVED', 'CONFIRMED_FRAUD', 'FALSE_POSITIVE'
    
    notes: Mapped[str] = mapped_column(
        Text, 
        nullable=True
    )
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime, 
        default=datetime.utcnow
    )

    # Relationships
    transaction = relationship(Transaction, backref="analyst_decision")
    analyst = relationship("User")
