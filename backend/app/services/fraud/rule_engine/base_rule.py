from abc import ABC, abstractmethod
from typing import List
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.models.transaction import Transaction


class RuleEvaluationResult(BaseModel):
    rule_name: str
    triggered: bool
    reason: str
    severity: str
    score_contribution: float


class BaseRule(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        pass

    @property
    @abstractmethod
    def severity(self) -> str:
        """LOW, MEDIUM, HIGH, CRITICAL"""
        pass

    @property
    @abstractmethod
    def score(self) -> float:
        """Score contribution when triggered"""
        pass

    @abstractmethod
    def evaluate(
        self, 
        transaction: Transaction, 
        db: Session, 
        history: List[Transaction]
    ) -> RuleEvaluationResult:
        pass
