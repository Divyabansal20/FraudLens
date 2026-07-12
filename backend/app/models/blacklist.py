from datetime import datetime
from sqlalchemy import DateTime, String, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from app.database.database import Base


class BlacklistedEntity(Base):
    __tablename__ = "blacklisted_entities"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    
    entity_type: Mapped[str] = mapped_column(
        String(50), 
        index=True
    )  # 'receiver', 'ip', 'device'
    
    entity_value: Mapped[str] = mapped_column(
        String(255), 
        index=True
    )
    
    reason: Mapped[str] = mapped_column(
        String(255), 
        nullable=True
    )
    
    is_active: Mapped[bool] = mapped_column(
        Boolean, 
        default=True
    )
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime, 
        default=datetime.utcnow
    )
