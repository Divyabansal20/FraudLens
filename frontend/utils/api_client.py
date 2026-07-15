import requests
import os
from typing import Dict, Any, List, Optional

class FraudLensAPIClient:
    def __init__(self, base_url: Optional[str] = None):
        if not base_url:
            backend_env = os.getenv("BACKEND_API_URL")
            if backend_env:
                base_url = backend_env.rstrip("/")
                if not base_url.endswith("/api/v1"):
                    base_url = f"{base_url}/api/v1"
            else:
                base_url = "http://127.0.0.1:8000/api/v1"
        self.base_url = base_url

    def _get_headers(self, token: Optional[str] = None) -> Dict[str, str]:
        headers = {"accept": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def register(self, name: str, email: str, password: str, role: str = "customer") -> Dict[str, Any]:
        """
        Register a new user (customer or analyst).
        """
        url = f"{self.base_url.replace('/api/v1', '')}/api/v1/users/"
        payload = {
            "name": name,
            "email": email,
            "password": password,
            "role": role
        }
        response = requests.post(url, json=payload)
        response.raise_for_status()
        return response.json()

    def login(self, username: str, password: str) -> Dict[str, Any]:
        """
        Log in and fetch the access token.
        """
        url = f"{self.base_url}/auth/login"
        # OAuth2 password flow expects form data
        data = {
            "grant_type": "password",
            "username": username,
            "password": password,
            "scope": ""
        }
        response = requests.post(url, data=data)
        response.raise_for_status()
        return response.json()

    def get_profile(self, token: str) -> Dict[str, Any]:
        """
        Retrieve current authenticated user profile.
        """
        url = f"{self.base_url}/profile/me"
        response = requests.get(url, headers=self._get_headers(token))
        response.raise_for_status()
        return response.json()

    def get_transactions(self, token: str) -> List[Dict[str, Any]]:
        """
        Retrieve current customer's transaction history.
        """
        url = f"{self.base_url}/transactions/"
        response = requests.get(url, headers=self._get_headers(token))
        response.raise_for_status()
        return response.json()

    def create_transaction(self, token: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Submit a new payment transaction.
        """
        url = f"{self.base_url}/transactions/"
        response = requests.post(url, json=payload, headers=self._get_headers(token))
        # We don't raise_for_status here so we can read 400/403/500 validation errors gracefully in UI
        return response

    def get_analyst_queue(self, token: str) -> List[Dict[str, Any]]:
        """
        Retrieve pending transactions in REVIEW status.
        """
        url = f"{self.base_url}/analyst/queue"
        response = requests.get(url, headers=self._get_headers(token))
        response.raise_for_status()
        return response.json()

    def get_analyst_blocked(self, token: str) -> List[Dict[str, Any]]:
        """
        Retrieve historically BLOCKED transactions.
        """
        url = f"{self.base_url}/analyst/blocked"
        response = requests.get(url, headers=self._get_headers(token))
        response.raise_for_status()
        return response.json()

    def get_transaction_evaluation(self, token: str, transaction_id: int) -> Dict[str, Any]:
        """
        Retrieve multi-engine risk evaluation audit details.
        """
        url = f"{self.base_url}/analyst/transactions/{transaction_id}/evaluate"
        response = requests.get(url, headers=self._get_headers(token))
        response.raise_for_status()
        return response.json()

    def submit_decision(self, token: str, transaction_id: int, decision: str, notes: str) -> Dict[str, Any]:
        """
        Submit analyst resolution overrides (Approve, Confirm Fraud, False Positive).
        """
        url = f"{self.base_url}/analyst/transactions/{transaction_id}/decision"
        payload = {
            "decision": decision,
            "notes": notes
        }
        response = requests.post(url, json=payload, headers=self._get_headers(token))
        response.raise_for_status()
        return response.json()

api_client = FraudLensAPIClient()
