from sqlalchemy.orm import Session

from app.models.transaction import Transaction
from app.schemas.transaction import TransactionCreate


def create_transaction(
    db: Session,
    transaction: TransactionCreate,
    sender_id: int,
):
    new_transaction = Transaction(
        sender_id=sender_id,
        receiver_name=transaction.receiver_name,
        amount=transaction.amount,
        payment_method=transaction.payment_method,
        device_id=transaction.device_id,
        city=transaction.city,
    )

    db.add(new_transaction)
    db.commit()
    db.refresh(new_transaction)

    return new_transaction


def get_user_transactions(
    db: Session,
    sender_id: int,
):
    return (
        db.query(Transaction)
        .filter(Transaction.sender_id == sender_id)
        .all()
    )