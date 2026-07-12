from datetime import datetime
from typing import Optional

from pydantic import BaseModel

from app.models.enums import TransactionStatus


class TransactionCreate(BaseModel):
    receiver_name: str
    amount: float
    payment_method: str
    device_id: str
    city: str
    ip_address: Optional[str] = None
    merchant_category: Optional[str] = None
    country: Optional[str] = None


class TransactionResponse(BaseModel):
    id: int
    sender_id: int
    receiver_name: str
    amount: float
    payment_method: str
    device_id: str
    city: str
    ip_address: Optional[str] = None
    merchant_category: Optional[str] = None
    country: Optional[str] = None
    status: TransactionStatus
    created_at: datetime
    customer_explanation: Optional[str] = None

    model_config = {
        "from_attributes": True
    }