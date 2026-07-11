from datetime import datetime

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

    status: Mapped[TransactionStatus] = mapped_column(
        Enum(TransactionStatus),
        default=TransactionStatus.PENDING,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )