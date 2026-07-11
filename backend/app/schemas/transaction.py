from datetime import datetime

from pydantic import BaseModel

from app.models.enums import TransactionStatus


class TransactionCreate(BaseModel):
    receiver_name: str
    amount: float
    payment_method: str
    device_id: str
    city: str


class TransactionResponse(BaseModel):
    id: int
    sender_id: int
    receiver_name: str
    amount: float
    payment_method: str
    device_id: str
    city: str
    status: TransactionStatus
    created_at: datetime

    model_config = {
        "from_attributes": True
    }