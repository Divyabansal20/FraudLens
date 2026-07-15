from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session

from app.core.dependencies import require_role
from app.database.database import get_db
from app.models.transaction import Transaction
from app.models.enums import TransactionStatus
from app.models.fraud_evaluation import FraudEvaluation
from app.models.analyst_decision import AnalystDecision
from app.schemas.analyst import (
    AnalystDecisionRequest,
    FraudEvaluationResponse,
    AnalystTransactionListItem,
)
from app.services.fraud.ml.active_learning import active_learning_retrainer

router = APIRouter(
    prefix="/analyst",
    tags=["Fraud Analyst"],
)


@router.get("/dashboard")
def analyst_dashboard(
    current_user=Depends(require_role("analyst")),
):
    return {
        "message": "Welcome Fraud Analyst",
        "analyst": current_user.name,
    }


@router.get(
    "/queue",
    response_model=List[AnalystTransactionListItem],
)
def get_review_queue(
    db: Session = Depends(get_db),
    current_user=Depends(require_role("analyst")),
):
    """
    Retrieve all transactions currently held in the REVIEW queue.
    """
    results = (
        db.query(Transaction, FraudEvaluation)
        .outerjoin(FraudEvaluation, Transaction.id == FraudEvaluation.transaction_id)
        .filter(Transaction.status == TransactionStatus.REVIEW)
        .order_by(Transaction.created_at.desc())
        .all()
    )

    items = []
    for tx, eval_data in results:
        items.append(
            AnalystTransactionListItem(
                id=tx.id,
                sender_id=tx.sender_id,
                receiver_name=tx.receiver_name,
                amount=float(tx.amount),
                payment_method=tx.payment_method,
                device_id=tx.device_id,
                city=tx.city,
                ip_address=tx.ip_address,
                merchant_category=tx.merchant_category,
                country=tx.country,
                status=tx.status,
                created_at=tx.created_at,
                aggregated_score=eval_data.aggregated_score if eval_data else None,
                confidence=eval_data.confidence if eval_data else None,
                customer_explanation=eval_data.customer_explanation if eval_data else None,
            )
        )
    return items


@router.get(
    "/blocked",
    response_model=List[AnalystTransactionListItem],
)
def get_blocked_queue(
    db: Session = Depends(get_db),
    current_user=Depends(require_role("analyst")),
):
    """
    Retrieve all transactions that have been automatically or manually BLOCKED.
    """
    results = (
        db.query(Transaction, FraudEvaluation)
        .outerjoin(FraudEvaluation, Transaction.id == FraudEvaluation.transaction_id)
        .filter(Transaction.status == TransactionStatus.BLOCKED)
        .order_by(Transaction.created_at.desc())
        .all()
    )

    items = []
    for tx, eval_data in results:
        items.append(
            AnalystTransactionListItem(
                id=tx.id,
                sender_id=tx.sender_id,
                receiver_name=tx.receiver_name,
                amount=float(tx.amount),
                payment_method=tx.payment_method,
                device_id=tx.device_id,
                city=tx.city,
                ip_address=tx.ip_address,
                merchant_category=tx.merchant_category,
                country=tx.country,
                status=tx.status,
                created_at=tx.created_at,
                aggregated_score=eval_data.aggregated_score if eval_data else None,
                confidence=eval_data.confidence if eval_data else None,
                customer_explanation=eval_data.customer_explanation if eval_data else None,
            )
        )
    return items


@router.get(
    "/transactions/{transaction_id}/evaluate",
    response_model=FraudEvaluationResponse,
)
def get_transaction_evaluation(
    transaction_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("analyst")),
):
    """
    Retrieve the detailed multi-engine evaluation details for a transaction.
    Recalculates the graph relationship network on the fly to ensure
    it reflects the latest active threat paths and updates the DB record.
    """
    tx = db.query(Transaction).filter(Transaction.id == transaction_id).first()
    if not tx:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Transaction ID {transaction_id} not found",
        )

    evaluation = (
        db.query(FraudEvaluation)
        .filter(FraudEvaluation.transaction_id == transaction_id)
        .first()
    )

    if not evaluation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evaluation not found for transaction ID {transaction_id}",
        )

    # Re-evaluate the relationship network graph dynamically on the fly
    from app.services.fraud.graph.graph_detector import GraphFraudDetector
    from app.services.fraud.behavior_profile import BehaviorProfileEngine
    from app.services.fraud.investigator_assistant import AIInvestigatorAssistant
    
    graph_detector = GraphFraudDetector()
    behavior_profile = BehaviorProfileEngine()
    ai_assistant = AIInvestigatorAssistant()
    
    graph_score, graph_patterns, connected_accounts = graph_detector.evaluate_network(tx, db)
    behavior_drift = behavior_profile.evaluate_behavior(tx, db)
    ai_summary, ai_recommendation = ai_assistant.generate_investigation_report(tx, behavior_drift, db)
    
    # Update evaluation details
    evaluation.graph_risk_score = graph_score
    evaluation.graph_details = {
        "risk_score": graph_score,
        "detected_patterns": graph_patterns,
        "connected_fraud_accounts": connected_accounts
    }
    evaluation.behavior_drift_score = behavior_drift
    evaluation.ai_investigation_summary = ai_summary
    evaluation.ai_recommendation = ai_recommendation
    
    # Re-calculate aggregated score using the updated weights
    evaluation.aggregated_score = round(
        (evaluation.rule_engine_score * 0.20) +
        (evaluation.ml_anomaly_score * 0.30) +
        (graph_score * 0.30) +
        (behavior_drift * 0.20),
        2
    )
    
    # Commit changes back to the database to ensure the cached DB values are corrected
    db.add(evaluation)
    db.commit()
    db.refresh(evaluation)

    return evaluation


@router.post(
    "/transactions/{transaction_id}/decision",
)
def resolve_transaction(
    transaction_id: int,
    payload: AnalystDecisionRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user=Depends(require_role("analyst")),
):
    """
    Resolve a pending review or blocked transaction. Updates transaction status
    and logs feedback for active learning model retraining.
    """
    # 1. Fetch transaction
    tx = db.query(Transaction).filter(Transaction.id == transaction_id).first()
    if not tx:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Transaction ID {transaction_id} not found",
        )

    # 2. Determine previous prediction class (FRAUD vs SAFE)
    # Statuses of REVIEW or BLOCKED represent system-flagged risk (predicted FRAUD)
    system_predicted_fraud = tx.status in [TransactionStatus.REVIEW, TransactionStatus.BLOCKED]
    prediction_label = "FRAUD" if system_predicted_fraud else "SAFE"

    # 3. Apply decision to transaction status
    decision_upper = payload.decision.upper()
    if decision_upper == "APPROVE" or decision_upper == "FALSE_POSITIVE":
        tx.status = TransactionStatus.APPROVED
    elif decision_upper == "CONFIRMED_FRAUD":
        tx.status = TransactionStatus.BLOCKED

    # 4. Record analyst decision in database
    existing_decision = db.query(AnalystDecision).filter(AnalystDecision.transaction_id == transaction_id).first()
    if existing_decision:
        existing_decision.analyst_id = current_user.id
        existing_decision.prediction = prediction_label
        existing_decision.decision = decision_upper
        existing_decision.notes = payload.notes
        existing_decision.created_at = datetime.utcnow()
    else:
        new_decision = AnalystDecision(
            transaction_id=transaction_id,
            analyst_id=current_user.id,
            prediction=prediction_label,
            decision=decision_upper,
            notes=payload.notes
        )
        db.add(new_decision)

    db.commit()
    db.refresh(tx)

    # Queue active learning retraining background task
    background_tasks.add_task(active_learning_retrainer.trigger_retraining)

    return {
        "message": f"Transaction resolved successfully as {decision_upper}",
        "transaction_id": tx.id,
        "new_status": tx.status.value,
        "prediction_feedback": prediction_label,
        "decision_logged": decision_upper
    }