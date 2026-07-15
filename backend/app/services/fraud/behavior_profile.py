from sqlalchemy.orm import Session
from app.models.transaction import Transaction
from app.models.enums import TransactionStatus
import numpy as np


class BehaviorProfileEngine:
    def __init__(self):
        pass

    def evaluate_behavior(self, transaction: Transaction, db: Session) -> float:
        """
        Evaluates how anomalous the transaction is compared to the sender's history.
        Looks at amount, location, device, and category.
        Returns behavior drift score (0.0 to 100.0).
        """
        # Fetch sender's last 30 successful (APPROVED) historical transactions
        history = (
            db.query(Transaction)
            .filter(
                Transaction.sender_id == transaction.sender_id,
                Transaction.status == TransactionStatus.APPROVED,
                Transaction.id != transaction.id
            )
            .order_by(Transaction.created_at.desc())
            .limit(30)
            .all()
        )

        if not history:
            # First transaction or no history - neutral behavior drift
            return 0.0

        # Compile profiles
        amounts = [t.amount for t in history]
        avg_amount = float(np.mean(amounts))
        std_amount = float(np.std(amounts)) if len(amounts) > 1 else 1.0

        cities = {t.city.lower() for t in history if t.city}
        devices = {t.device_id.lower() for t in history if t.device_id}
        categories = {t.merchant_category.lower() for t in history if t.merchant_category}

        # Calculate deviation indices
        # 1. Amount Drift (Z-Score)
        z_score = abs(float(transaction.amount) - avg_amount) / (std_amount if std_amount > 0 else 1.0)
        # Scale Z-Score so a Z-score of 3.5 (highly anomalous) maps to 100% drift
        amount_drift = min((z_score / 3.5) * 100.0, 100.0)

        # 2. Location (City) Drift
        city_drift = 100.0 if (transaction.city and transaction.city.lower() not in cities) else 0.0

        # 3. Device Drift
        device_drift = 100.0 if (transaction.device_id and transaction.device_id.lower() not in devices) else 0.0

        # 4. Merchant Category Drift
        category_drift = 100.0 if (transaction.merchant_category and transaction.merchant_category.lower() not in categories) else 0.0

        # Weight distribution: Amount (40%), Device (30%), Location (20%), Category (10%)
        weighted_drift = (
            (amount_drift * 0.40) +
            (device_drift * 0.30) +
            (city_drift * 0.20) +
            (category_drift * 0.10)
        )

        return float(round(weighted_drift, 1))
