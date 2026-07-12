from enum import Enum


class TransactionStatus(str, Enum):
    PROCESSING = "PROCESSING"
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REVIEW = "REVIEW"
    BLOCKED = "BLOCKED"