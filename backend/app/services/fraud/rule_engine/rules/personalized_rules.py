import math
from typing import List
from sqlalchemy.orm import Session
from app.models.transaction import Transaction
from app.services.fraud.rule_engine.base_rule import BaseRule, RuleEvaluationResult


def calculate_percentile(values: List[float], pct: float) -> float:
    if not values:
        return 0.0
    sorted_val = sorted(values)
    k = (len(sorted_val) - 1) * (pct / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_val[int(k)]
    d0 = sorted_val[int(f)] * (c - k)
    d1 = sorted_val[int(c)] * (k - f)
    return d0 + d1


class AverageAmountRule(BaseRule):
    @property
    def name(self) -> str:
        return "AVERAGE_AMOUNT_EXCEEDED"

    @property
    def description(self) -> str:
        return "Transaction amount is more than 5 times the user's historical average"

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
                reason="Insufficient history to establish an average",
                severity=self.severity,
                score_contribution=0.0
            )

        tx_amount = float(transaction.amount)
        avg_amount = sum(float(h.amount) for h in history) / len(history)
        threshold = avg_amount * 5.0

        if tx_amount > threshold:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=True,
                reason=f"Transaction amount (₹{tx_amount:.2f}) exceeds 5x user's historical average (₹{avg_amount:.2f}, limit: ₹{threshold:.2f})",
                severity=self.severity,
                score_contribution=self.score
            )

        return RuleEvaluationResult(
            rule_name=self.name,
            triggered=False,
            reason=f"Transaction amount (₹{tx_amount:.2f}) is below 5x user's average (₹{avg_amount:.2f})",
            severity=self.severity,
            score_contribution=0.0
        )


class PercentileAmountRule(BaseRule):
    @property
    def name(self) -> str:
        return "PERCENTILE_AMOUNT_EXCEEDED"

    @property
    def description(self) -> str:
        return "Transaction amount exceeds the 95th percentile of the user's history"

    @property
    def severity(self) -> str:
        return "MEDIUM"

    @property
    def score(self) -> float:
        return 30.0

    def evaluate(self, transaction: Transaction, db: Session, history: List[Transaction]) -> RuleEvaluationResult:
        if len(history) < 5:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=False,
                reason=f"Insufficient history (size: {len(history)}) to establish a reliable 95th percentile profile",
                severity=self.severity,
                score_contribution=0.0
            )

        amounts = [float(h.amount) for h in history]
        pct_95 = calculate_percentile(amounts, 95.0)
        tx_amount = float(transaction.amount)

        if tx_amount > pct_95:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=True,
                reason=f"Transaction amount (₹{tx_amount:.2f}) is above the user's 95th percentile (₹{pct_95:.2f})",
                severity=self.severity,
                score_contribution=self.score
            )

        return RuleEvaluationResult(
            rule_name=self.name,
            triggered=False,
            reason=f"Transaction amount (₹{tx_amount:.2f}) is within the user's historical 95th percentile (₹{pct_95:.2f})",
            severity=self.severity,
            score_contribution=0.0
        )


class NewDeviceRule(BaseRule):
    @property
    def name(self) -> str:
        return "NEW_DEVICE"

    @property
    def description(self) -> str:
        return "Transaction initiated from a device never used by this user before"

    @property
    def severity(self) -> str:
        return "MEDIUM"

    @property
    def score(self) -> float:
        return 20.0

    def evaluate(self, transaction: Transaction, db: Session, history: List[Transaction]) -> RuleEvaluationResult:
        if not history:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=False,
                reason="Cold start: No prior transactions to compare device ID",
                severity=self.severity,
                score_contribution=0.0
            )

        known_devices = {h.device_id for h in history if h.device_id}
        if transaction.device_id not in known_devices:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=True,
                reason=f"Device ID '{transaction.device_id}' has not been used by this user before",
                severity=self.severity,
                score_contribution=self.score
            )

        return RuleEvaluationResult(
            rule_name=self.name,
            triggered=False,
            reason="Device ID has been used before",
            severity=self.severity,
            score_contribution=0.0
        )


class NewCityRule(BaseRule):
    @property
    def name(self) -> str:
        return "NEW_CITY"

    @property
    def description(self) -> str:
        return "Transaction initiated from a city never visited by this user before"

    @property
    def severity(self) -> str:
        return "MEDIUM"

    @property
    def score(self) -> float:
        return 20.0

    def evaluate(self, transaction: Transaction, db: Session, history: List[Transaction]) -> RuleEvaluationResult:
        if not history:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=False,
                reason="Cold start: No prior transactions to compare city",
                severity=self.severity,
                score_contribution=0.0
            )

        known_cities = {h.city.lower() for h in history if h.city}
        if not transaction.city or transaction.city.lower() not in known_cities:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=True,
                reason=f"City '{transaction.city}' has not been recorded in this user's history",
                severity=self.severity,
                score_contribution=self.score
            )

        return RuleEvaluationResult(
            rule_name=self.name,
            triggered=False,
            reason="City has been used before",
            severity=self.severity,
            score_contribution=0.0
        )


class NewIPRule(BaseRule):
    @property
    def name(self) -> str:
        return "NEW_IP"

    @property
    def description(self) -> str:
        return "Transaction initiated from an IP address never used by this user before"

    @property
    def severity(self) -> str:
        return "MEDIUM"

    @property
    def score(self) -> float:
        return 20.0

    def evaluate(self, transaction: Transaction, db: Session, history: List[Transaction]) -> RuleEvaluationResult:
        if not history:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=False,
                reason="Cold start: No prior transactions to compare IP address",
                severity=self.severity,
                score_contribution=0.0
            )

        known_ips = {h.ip_address for h in history if h.ip_address}
        if not transaction.ip_address or transaction.ip_address not in known_ips:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=True,
                reason=f"IP address '{transaction.ip_address}' is new for this user",
                severity=self.severity,
                score_contribution=self.score
            )

        return RuleEvaluationResult(
            rule_name=self.name,
            triggered=False,
            reason="IP address has been used before",
            severity=self.severity,
            score_contribution=0.0
        )


class FirstInternationalRule(BaseRule):
    @property
    def name(self) -> str:
        return "FIRST_INTERNATIONAL_TRANSACTION"

    @property
    def description(self) -> str:
        return "First transaction executed in a foreign country relative to historical baseline"

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def score(self) -> float:
        return 40.0

    def evaluate(self, transaction: Transaction, db: Session, history: List[Transaction]) -> RuleEvaluationResult:
        if not history:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=False,
                reason="Cold start: No prior transactions to establish country baseline",
                severity=self.severity,
                score_contribution=0.0
            )

        if not transaction.country:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=False,
                reason="Country code is missing",
                severity=self.severity,
                score_contribution=0.0
            )

        known_countries = {h.country for h in history if h.country}
        
        # If the country is not the primary historical country, and we've never transacted in it before
        if transaction.country not in known_countries:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=True,
                reason=f"Transaction country '{transaction.country}' is new (previous known countries: {known_countries})",
                severity=self.severity,
                score_contribution=self.score
            )

        return RuleEvaluationResult(
            rule_name=self.name,
            triggered=False,
            reason="Country has been used before",
            severity=self.severity,
            score_contribution=0.0
        )


class UnusualHourRule(BaseRule):
    @property
    def name(self) -> str:
        return "UNUSUAL_HOUR"

    @property
    def description(self) -> str:
        return "Transaction occurred during sleep hours (11 PM - 6 AM) without historical night activity"

    @property
    def severity(self) -> str:
        return "LOW"

    @property
    def score(self) -> float:
        return 10.0

    def evaluate(self, transaction: Transaction, db: Session, history: List[Transaction]) -> RuleEvaluationResult:
        # Sleep hours window: 11 PM to 6 AM (inclusive)
        hour = transaction.created_at.hour
        is_sleep_hour = (hour >= 23 or hour <= 6)
        
        if not is_sleep_hour:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=False,
                reason=f"Transaction hour ({hour}:00) is outside sleep hour window (23:00 - 06:00)",
                severity=self.severity,
                score_contribution=0.0
            )

        if len(history) < 3:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=False,
                reason="Insufficient history (size < 3) to verify if night transactions are typical",
                severity=self.severity,
                score_contribution=0.0
            )

        # Check if they have ever transacted during sleep hours historically
        night_history = [h for h in history if (h.created_at.hour >= 23 or h.created_at.hour <= 6)]
        
        if not night_history:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=True,
                reason=f"Transaction occurred at {hour}:00, which is during sleep hours, and the user has no history of night transactions",
                severity=self.severity,
                score_contribution=self.score
            )

        return RuleEvaluationResult(
            rule_name=self.name,
            triggered=False,
            reason=f"Transaction occurred at night, but user has history of night transactions (count: {len(night_history)})",
            severity=self.severity,
            score_contribution=0.0
        )


class NewPaymentMethodRule(BaseRule):
    @property
    def name(self) -> str:
        return "NEW_PAYMENT_METHOD"

    @property
    def description(self) -> str:
        return "Payment method used has not been observed in this user's history"

    @property
    def severity(self) -> str:
        return "LOW"

    @property
    def score(self) -> float:
        return 10.0

    def evaluate(self, transaction: Transaction, db: Session, history: List[Transaction]) -> RuleEvaluationResult:
        if not history:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=False,
                reason="Cold start: No prior transactions to establish payment method baseline",
                severity=self.severity,
                score_contribution=0.0
            )

        known_methods = {h.payment_method.lower() for h in history if h.payment_method}
        if not transaction.payment_method or transaction.payment_method.lower() not in known_methods:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=True,
                reason=f"Payment method '{transaction.payment_method}' is new for this user",
                severity=self.severity,
                score_contribution=self.score
            )

        return RuleEvaluationResult(
            rule_name=self.name,
            triggered=False,
            reason="Payment method has been used before",
            severity=self.severity,
            score_contribution=0.0
        )


class NewMerchantCategoryRule(BaseRule):
    @property
    def name(self) -> str:
        return "NEW_MERCHANT_CATEGORY"

    @property
    def description(self) -> str:
        return "Merchant category visited has not been observed in this user's history"

    @property
    def severity(self) -> str:
        return "LOW"

    @property
    def score(self) -> float:
        return 10.0

    def evaluate(self, transaction: Transaction, db: Session, history: List[Transaction]) -> RuleEvaluationResult:
        if not history:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=False,
                reason="Cold start: No prior transactions to establish merchant category baseline",
                severity=self.severity,
                score_contribution=0.0
            )

        known_categories = {h.merchant_category.lower() for h in history if h.merchant_category}
        if not transaction.merchant_category or transaction.merchant_category.lower() not in known_categories:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=True,
                reason=f"Merchant category '{transaction.merchant_category}' has not been transacted with by this user before",
                severity=self.severity,
                score_contribution=self.score
            )

        return RuleEvaluationResult(
            rule_name=self.name,
            triggered=False,
            reason="Merchant category has been visited before",
            severity=self.severity,
            score_contribution=0.0
        )
