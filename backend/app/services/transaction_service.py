from sqlalchemy.orm import Session

from app.models.transaction import Transaction
from app.models.enums import TransactionStatus
from app.schemas.transaction import TransactionCreate
from app.services.fraud.orchestrator import fraud_orchestrator


def create_transaction(
    db: Session,
    transaction: TransactionCreate,
    sender_id: int,
):
    # 1. Initialize and store transaction as PROCESSING
    new_transaction = Transaction(
        sender_id=sender_id,
        receiver_name=transaction.receiver_name,
        amount=transaction.amount,
        payment_method=transaction.payment_method,
        device_id=transaction.device_id,
        city=transaction.city,
        ip_address=transaction.ip_address,
        merchant_category=transaction.merchant_category,
        country=transaction.country,
        status=TransactionStatus.PROCESSING,
    )

    db.add(new_transaction)
    db.commit()
    db.refresh(new_transaction)

    try:
        # 2. Evaluate using multi-stage Fraud Orchestrator
        evaluation = fraud_orchestrator.evaluate_transaction(db, new_transaction)
        
        # 3. Save the fraud evaluation results
        db.add(evaluation)
        db.commit()
        db.refresh(new_transaction)
    except Exception as e:
        # Fallback safeguard: if the fraud engine fails, hold the transaction for REVIEW rather than failing the transaction
        import logging
        logging.getLogger("uvicorn.error").error(f"Critical error in fraud orchestration pipeline: {e}")
        new_transaction.status = TransactionStatus.REVIEW
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
        .order_by(Transaction.created_at.desc())
        .all()
    )