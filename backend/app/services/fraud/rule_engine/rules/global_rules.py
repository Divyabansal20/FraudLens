from datetime import datetime, timedelta
import math
from typing import List
from sqlalchemy import func
from sqlalchemy.orm import Session
from app.models.transaction import Transaction
from app.models.blacklist import BlacklistedEntity
from app.services.fraud.rule_engine.base_rule import BaseRule, RuleEvaluationResult


# City coordinates for Impossible Travel calculation (Haversine distance)
CITY_COORDINATES = {
    "delhi": (28.6139, 77.2090),
    "mumbai": (19.0760, 72.8777),
    "bangalore": (12.9716, 77.5946),
    "kolkata": (22.5726, 88.3639),
    "chennai": (13.0827, 80.2707),
    "hyderabad": (17.3850, 78.4867),
    "pune": (18.5204, 73.8567),
    "ahmedabad": (23.0225, 72.5714),
    "new york": (40.7128, -74.0060),
    "london": (51.5074, -0.1278),
    "tokyo": (35.6762, 139.6503),
    "singapore": (1.3521, 103.8198),
}


def calculate_haversine_distance(coord1, coord2):
    lat1, lon1 = coord1
    lat2, lon2 = coord2
    R = 6371.0  # Earth's radius in km

    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)

    a = math.sin(dlat / 2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    return R * c


class BlacklistReceiverRule(BaseRule):
    @property
    def name(self) -> str:
        return "BLACKLISTED_RECEIVER"

    @property
    def description(self) -> str:
        return "Transaction receiver is on the global fraud blacklist"

    @property
    def severity(self) -> str:
        return "CRITICAL"

    @property
    def score(self) -> float:
        return 90.0

    def evaluate(self, transaction: Transaction, db: Session, history: List[Transaction]) -> RuleEvaluationResult:
        if not transaction.receiver_name:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=False,
                reason="Receiver name is empty",
                severity=self.severity,
                score_contribution=0.0
            )

        blacklisted = db.query(BlacklistedEntity).filter(
            BlacklistedEntity.entity_type == "receiver",
            func.lower(BlacklistedEntity.entity_value) == transaction.receiver_name.lower(),
            BlacklistedEntity.is_active == True
        ).first()

        if blacklisted:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=True,
                reason=f"Receiver '{transaction.receiver_name}' is blacklisted: {blacklisted.reason}",
                severity=self.severity,
                score_contribution=self.score
            )

        return RuleEvaluationResult(
            rule_name=self.name,
            triggered=False,
            reason="Receiver is not blacklisted",
            severity=self.severity,
            score_contribution=0.0
        )


class BlacklistIPRule(BaseRule):
    @property
    def name(self) -> str:
        return "BLACKLISTED_IP"

    @property
    def description(self) -> str:
        return "Transaction IP address is on the global fraud blacklist"

    @property
    def severity(self) -> str:
        return "CRITICAL"

    @property
    def score(self) -> float:
        return 95.0

    def evaluate(self, transaction: Transaction, db: Session, history: List[Transaction]) -> RuleEvaluationResult:
        if not transaction.ip_address:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=False,
                reason="IP address is empty",
                severity=self.severity,
                score_contribution=0.0
            )

        blacklisted = db.query(BlacklistedEntity).filter(
            BlacklistedEntity.entity_type == "ip",
            BlacklistedEntity.entity_value == transaction.ip_address,
            BlacklistedEntity.is_active == True
        ).first()

        if blacklisted:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=True,
                reason=f"IP address '{transaction.ip_address}' is blacklisted: {blacklisted.reason}",
                severity=self.severity,
                score_contribution=self.score
            )

        return RuleEvaluationResult(
            rule_name=self.name,
            triggered=False,
            reason="IP address is not blacklisted",
            severity=self.severity,
            score_contribution=0.0
        )


class BlacklistDeviceRule(BaseRule):
    @property
    def name(self) -> str:
        return "BLACKLISTED_DEVICE"

    @property
    def description(self) -> str:
        return "Transaction device is on the global fraud blacklist"

    @property
    def severity(self) -> str:
        return "CRITICAL"

    @property
    def score(self) -> float:
        return 95.0

    def evaluate(self, transaction: Transaction, db: Session, history: List[Transaction]) -> RuleEvaluationResult:
        if not transaction.device_id:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=False,
                reason="Device ID is empty",
                severity=self.severity,
                score_contribution=0.0
            )

        blacklisted = db.query(BlacklistedEntity).filter(
            BlacklistedEntity.entity_type == "device",
            BlacklistedEntity.entity_value == transaction.device_id,
            BlacklistedEntity.is_active == True
        ).first()

        if blacklisted:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=True,
                reason=f"Device ID '{transaction.device_id}' is blacklisted: {blacklisted.reason}",
                severity=self.severity,
                score_contribution=self.score
            )

        return RuleEvaluationResult(
            rule_name=self.name,
            triggered=False,
            reason="Device ID is not blacklisted",
            severity=self.severity,
            score_contribution=0.0
        )


class ReceiverInvestigationRule(BaseRule):
    @property
    def name(self) -> str:
        return "RECEIVER_UNDER_INVESTIGATION"

    @property
    def description(self) -> str:
        return "Transaction receiver is currently flagged as under active investigation"

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def score(self) -> float:
        return 50.0

    def evaluate(self, transaction: Transaction, db: Session, history: List[Transaction]) -> RuleEvaluationResult:
        if not transaction.receiver_name:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=False,
                reason="Receiver name is empty",
                severity=self.severity,
                score_contribution=0.0
            )

        # A receiver is under investigation if they are in the blacklist table with active=True,
        # and the reason text mentions 'investigation' or 'mule' or 'laundering'.
        under_investigation = db.query(BlacklistedEntity).filter(
            BlacklistedEntity.entity_type == "receiver",
            func.lower(BlacklistedEntity.entity_value) == transaction.receiver_name.lower(),
            BlacklistedEntity.is_active == True,
            func.lower(BlacklistedEntity.reason).like("%investigation%")
        ).first()

        if under_investigation:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=True,
                reason=f"Receiver '{transaction.receiver_name}' is under investigation: {under_investigation.reason}",
                severity=self.severity,
                score_contribution=self.score
            )

        return RuleEvaluationResult(
            rule_name=self.name,
            triggered=False,
            reason="Receiver is not under active investigation",
            severity=self.severity,
            score_contribution=0.0
        )


class VelocityRule(BaseRule):
    @property
    def name(self) -> str:
        return "HIGH_VELOCITY_LIMIT"

    @property
    def description(self) -> str:
        return "User has initiated more than 3 transactions in the last 5 minutes"

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def score(self) -> float:
        return 45.0

    def evaluate(self, transaction: Transaction, db: Session, history: List[Transaction]) -> RuleEvaluationResult:
        time_limit = datetime.utcnow() - timedelta(minutes=5)
        
        # Count transactions for the same sender within the last 5 minutes
        recent_tx_count = db.query(Transaction).filter(
            Transaction.sender_id == transaction.sender_id,
            Transaction.created_at >= time_limit
        ).count()

        # Since the current transaction might already be stored in database or is currently processing,
        # we trigger if count > 3. (Or if this is pre-save, recent_tx_count represents prior transactions, trigger if count >= 3).
        # Let's check: if we allow 3 transactions, the 4th triggers the rule. So if recent_tx_count >= 3 (excluding current if pre-save)
        # If the current is already in DB, count will include it. Let's make it trigger if recent_tx_count >= 3.
        if recent_tx_count >= 3:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=True,
                reason=f"High frequency: {recent_tx_count} transactions initiated by user in the last 5 minutes",
                severity=self.severity,
                score_contribution=self.score
            )

        return RuleEvaluationResult(
            rule_name=self.name,
            triggered=False,
            reason=f"Transaction velocity is normal (count: {recent_tx_count} in last 5 minutes)",
            severity=self.severity,
            score_contribution=0.0
        )


class SharedDeviceRule(BaseRule):
    @property
    def name(self) -> str:
        return "SHARED_DEVICE_SUSPICIOUS"

    @property
    def description(self) -> str:
        return "Device ID is shared across 3 or more distinct user accounts in the last 30 days"

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def score(self) -> float:
        return 40.0

    def evaluate(self, transaction: Transaction, db: Session, history: List[Transaction]) -> RuleEvaluationResult:
        if not transaction.device_id:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=False,
                reason="Device ID is empty",
                severity=self.severity,
                score_contribution=0.0
            )

        time_limit = datetime.utcnow() - timedelta(days=30)
        
        # Query distinct senders who used this device
        distinct_users = db.query(func.count(func.distinct(Transaction.sender_id))).filter(
            Transaction.device_id == transaction.device_id,
            Transaction.created_at >= time_limit
        ).scalar()

        # Include the current sender (if not already counted)
        # If distinct_users >= 3, trigger
        if distinct_users >= 3:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=True,
                reason=f"Device ID '{transaction.device_id}' is shared across {distinct_users} distinct user accounts in the last 30 days",
                severity=self.severity,
                score_contribution=self.score
            )

        return RuleEvaluationResult(
            rule_name=self.name,
            triggered=False,
            reason=f"Device is shared with {distinct_users} users (below threshold of 3)",
            severity=self.severity,
            score_contribution=0.0
        )


class ImpossibleTravelRule(BaseRule):
    @property
    def name(self) -> str:
        return "IMPOSSIBLE_TRAVEL"

    @property
    def description(self) -> str:
        return "Velocity between consecutive transactions implies physically impossible travel"

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def score(self) -> float:
        return 55.0

    def evaluate(self, transaction: Transaction, db: Session, history: List[Transaction]) -> RuleEvaluationResult:
        if not transaction.city:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=False,
                reason="City name is empty",
                severity=self.severity,
                score_contribution=0.0
            )

        # Get user's last transaction (excluding the current one)
        last_tx = db.query(Transaction).filter(
            Transaction.sender_id == transaction.sender_id,
            Transaction.id != transaction.id
        ).order_by(Transaction.created_at.desc()).first()

        if not last_tx or not last_tx.city:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=False,
                reason="No prior transactions found to calculate speed",
                severity=self.severity,
                score_contribution=0.0
            )

        if last_tx.city.lower() == transaction.city.lower():
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=False,
                reason="Transaction in the same city as the previous one",
                severity=self.severity,
                score_contribution=0.0
            )

        # Find coordinates
        coord1 = CITY_COORDINATES.get(last_tx.city.lower())
        coord2 = CITY_COORDINATES.get(transaction.city.lower())

        if not coord1 or not coord2:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=False,
                reason=f"Coordinates unavailable for '{last_tx.city}' or '{transaction.city}'",
                severity=self.severity,
                score_contribution=0.0
            )

        # Calculate distance
        distance = calculate_haversine_distance(coord1, coord2)
        
        # Calculate time difference in hours
        time_diff = (transaction.created_at - last_tx.created_at).total_seconds() / 3600.0
        
        if time_diff <= 0:
            # Transactions too close in time or simultaneous
            time_diff = 0.01  # avoid division by zero

        # Speed in km/h
        speed = distance / time_diff

        # If speed > 900 km/h (speed of commercial aircraft)
        if speed > 900.0:
            return RuleEvaluationResult(
                rule_name=self.name,
                triggered=True,
                reason=f"Travel from {last_tx.city} to {transaction.city} ({distance:.2f} km) in {time_diff * 60:.1f} mins implies speed of {speed:.1f} km/h (limit: 900 km/h)",
                severity=self.severity,
                score_contribution=self.score
            )

        return RuleEvaluationResult(
            rule_name=self.name,
            triggered=False,
            reason=f"Travel from {last_tx.city} to {transaction.city} ({distance:.2f} km) in {time_diff:.2f} hours implies normal speed of {speed:.1f} km/h",
            severity=self.severity,
            score_contribution=0.0
        )
