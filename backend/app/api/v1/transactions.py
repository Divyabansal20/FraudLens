from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.security import get_current_user
from app.database.database import get_db
from app.schemas.transaction import (
    TransactionCreate,
    TransactionResponse,
)
from app.services.transaction_service import (
    create_transaction,
    get_user_transactions,
)

router = APIRouter(
    prefix="/transactions",
    tags=["Transactions"],
)


@router.post(
    "/",
    response_model=TransactionResponse,
)
def create_new_transaction(
    transaction: TransactionCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return create_transaction(
        db,
        transaction,
        current_user.id,
    )


@router.get(
    "/",
    response_model=List[TransactionResponse],
)
def get_transactions(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    return get_user_transactions(
        db,
        current_user.id,
    )