from typing import List, Dict
from sqlalchemy.orm import Session
from app.models.transaction import Transaction
from app.models.blacklist import BlacklistedEntity
from app.services.fraud.rule_engine.base_rule import BaseRule, RuleEvaluationResult


class LargeAmountNewDeviceRule(BaseRule):
    @property
    def name(self) -> str:
        return "LARGE_AMOUNT_AND_NEW_DEVICE"

    @property
    def description(self) -> str:
        return "High risk combination: Transaction amount is anomalous AND initiated from a new device"

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def score(self) -> float:
        return 60.0

    def evaluate(self, transaction: Transaction, db: Session, history: List[Transaction]) -> RuleEvaluationResult:
        # We can evaluate this by checking if the device is new AND the amount is anomalous
        # To avoid duplicate logic, we can pass triggered results or compute it simply.
        # Let's write it in a way that checks if this device is new for the user,
        # and if the amount is > user's 95th percentile or > 5x average.
        if not history:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=False,
                reason="Cold start: No prior transactions to establish profile",
                severity=self.severity,
                score_contribution=0.0
            )

        known_devices = {h.device_id for h in history if h.device_id}
        is_new_device = transaction.device_id not in known_devices

        if not is_new_device:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=False,
                reason="Device is already trusted",
                severity=self.severity,
                score_contribution=0.0
            )

        # Check if amount is above 95th percentile or 5x average
        amounts = [float(h.amount) for h in history]
        avg_amount = sum(amounts) / len(history)
        
        from app.services.fraud.rule_engine.rules.personalized_rules import calculate_percentile
        pct_95 = calculate_percentile(amounts, 95.0) if len(history) >= 5 else float('inf')

        tx_amount = float(transaction.amount)
        is_large = tx_amount > (avg_amount * 5.0) or tx_amount > pct_95

        if is_new_device and is_large:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=True,
                reason=f"Anomalous amount (₹{tx_amount:.2f}) sent from a brand new device '{transaction.device_id}'",
                severity=self.severity,
                score_contribution=self.score
            )

        return RuleEvaluationResult(
            rule_name=self.name,
            triggered=False,
            reason="Not a combined large amount and new device scenario",
            severity=self.severity,
            score_contribution=0.0
        )


class NewCityInternationalRule(BaseRule):
    @property
    def name(self) -> str:
        return "NEW_CITY_AND_INTERNATIONAL"

    @property
    def description(self) -> str:
        return "High risk combination: Transaction initiated in a new city AND a new country"

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def score(self) -> float:
        return 50.0

    def evaluate(self, transaction: Transaction, db: Session, history: List[Transaction]) -> RuleEvaluationResult:
        if not history:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=False,
                reason="Cold start: No history to establish geo profile",
                severity=self.severity,
                score_contribution=0.0
            )

        if not transaction.country or not transaction.city:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=False,
                reason="Missing city or country details",
                severity=self.severity,
                score_contribution=0.0
            )

        known_countries = {h.country for h in history if h.country}
        known_cities = {h.city.lower() for h in history if h.city}

        is_new_country = transaction.country not in known_countries
        is_new_city = transaction.city.lower() not in known_cities

        if is_new_country and is_new_city:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=True,
                reason=f"Transaction executed in a new country '{transaction.country}' and new city '{transaction.city}' simultaneously",
                severity=self.severity,
                score_contribution=self.score
            )

        return RuleEvaluationResult(
            rule_name=self.name,
            triggered=False,
            reason="Not a combined new city and new country scenario",
            severity=self.severity,
            score_contribution=0.0
        )


class SharedDeviceBlacklistReceiverRule(BaseRule):
    @property
    def name(self) -> str:
        return "SHARED_DEVICE_AND_BLACKLIST_RECEIVER"

    @property
    def description(self) -> str:
        return "Critical risk combination: Shared device sending funds to a blacklisted receiver"

    @property
    def severity(self) -> str:
        return "CRITICAL"

    @property
    def score(self) -> float:
        return 100.0

    def evaluate(self, transaction: Transaction, db: Session, history: List[Transaction]) -> RuleEvaluationResult:
        if not transaction.device_id or not transaction.receiver_name:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=False,
                reason="Missing device ID or receiver name",
                severity=self.severity,
                score_contribution=0.0
            )

        # Check if receiver is blacklisted
        from sqlalchemy import func
        blacklisted = db.query(BlacklistedEntity).filter(
            BlacklistedEntity.entity_type == "receiver",
            func.lower(BlacklistedEntity.entity_value) == transaction.receiver_name.lower(),
            BlacklistedEntity.is_active == True
        ).first()

        if not blacklisted:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=False,
                reason="Receiver is not blacklisted",
                severity=self.severity,
                score_contribution=0.0
            )

        # Check if device is shared across distinct accounts
        from datetime import datetime, timedelta
        time_limit = datetime.utcnow() - timedelta(days=30)
        distinct_users = db.query(func.count(func.distinct(Transaction.sender_id))).filter(
            Transaction.device_id == transaction.device_id,
            Transaction.created_at >= time_limit
        ).scalar()

        is_shared_device = (distinct_users and distinct_users >= 2)  # relaxed threshold for contextual compounding

        if is_shared_device and blacklisted:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=True,
                reason=f"Shared device '{transaction.device_id}' (used by {distinct_users} accounts) was used to transact with blacklisted receiver '{transaction.receiver_name}'",
                severity=self.severity,
                score_contribution=self.score
            )

        return RuleEvaluationResult(
            rule_name=self.name,
            triggered=False,
            reason="Not a combined shared device and blacklisted receiver scenario",
            severity=self.severity,
            score_contribution=0.0
        )


class MultiAnomalyRule(BaseRule):
    @property
    def name(self) -> str:
        return "MULTIPLE_UNUSUAL_BEHAVIORS"

    @property
    def description(self) -> str:
        return "High risk indicator: 3 or more individual rules triggered for this transaction"

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def score(self) -> float:
        return 50.0

    # Custom evaluate which can accept pre-triggered results
    def evaluate(self, transaction: Transaction, db: Session, history: List[Transaction]) -> RuleEvaluationResult:
        # Note: Handled dynamically by the Orchestrator/Engine rather than running rules recursively inside evaluate.
        # By default, returns triggered=False here, but the engine will override it when aggregating.
        return RuleEvaluationResult(
            rule_name=self.name,
            triggered=False,
            reason="Evaluated dynamically by orchestrator",
            severity=self.severity,
            score_contribution=0.0
        )
