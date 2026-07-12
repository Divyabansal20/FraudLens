from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Enum, ForeignKey, Numeric, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.database import Base
from app.models.enums import TransactionStatus


class Transaction(Base):
    __tablename__ = "transactions"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)

    sender_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"),
        nullable=False,
    )

    receiver_name: Mapped[str] = mapped_column(String(100))

    amount: Mapped[float] = mapped_column(
        Numeric(10, 2)
    )

    payment_method: Mapped[str] = mapped_column(
        String(50)
    )

    device_id: Mapped[str] = mapped_column(
        String(100)
    )

    city: Mapped[str] = mapped_column(
        String(100)
    )

    ip_address: Mapped[Optional[str]] = mapped_column(
        String(45),
        nullable=True,
    )

    merchant_category: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
    )

    country: Mapped[Optional[str]] = mapped_column(
        String(2),
        nullable=True,
    )

    status: Mapped[TransactionStatus] = mapped_column(
        Enum(TransactionStatus),
        default=TransactionStatus.PROCESSING,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )

    @property
    def customer_explanation(self) -> Optional[str]:
        if getattr(self, "fraud_evaluation", None):
            if isinstance(self.fraud_evaluation, list) and len(self.fraud_evaluation) > 0:
                return self.fraud_evaluation[0].customer_explanation
            elif not isinstance(self.fraud_evaluation, list):
                return self.fraud_evaluation.customer_explanation
        return None