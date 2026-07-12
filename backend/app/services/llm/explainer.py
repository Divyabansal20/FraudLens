import json
import urllib.request
import urllib.error
from typing import Tuple, List, Dict, Any
from app.core.config import settings
from app.models.transaction import Transaction


class GeminiExplainer:
    def __init__(self):
        self.api_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"

    def generate_explanations(
        self,
        transaction: Transaction,
        triggered_rules: List[Dict[str, Any]],
        ml_score: float,
        graph_score: float,
        aggregated_score: float,
        decision_status: str
    ) -> Tuple[str, str]:
        """
        Uses Gemini to generate natural language explanations for customer & analyst.
        Returns:
            (customer_explanation, analyst_explanation)
            Or (None, None) if key is missing or call fails.
        """
        api_key = settings.GEMINI_API_KEY
        if not api_key:
            return None, None

        # Build list of active triggered rules for context
        rule_details = []
        for r in triggered_rules:
            if r.get("triggered", False):
                rule_details.append(
                    f"- [{r.get('severity', 'UNKNOWN')}] {r.get('rule_name')}: {r.get('reason')} (+{r.get('score_contribution')} score contribution)"
                )
        rules_text = "\n".join(rule_details) if rule_details else "None"

        # Construct unified context prompt
        prompt = f"""
You are the core AI explanation engine for FraudLens, a production payment fraud detection platform.
Analyze the following payment evaluation data and generate two separate natural language explanations:

TRANSACTION DETAILS:
- Transaction ID: {transaction.id}
- Sender User ID: {transaction.sender_id}
- Receiver: {transaction.receiver_name}
- Amount: INR {transaction.amount:.2f}
- Method: {transaction.payment_method}
- Device: {transaction.device_id}
- City: {transaction.city}
- IP Address: {transaction.ip_address}
- Merchant Category: {transaction.merchant_category}
- Country: {transaction.country}
- Created At: {transaction.created_at}

DETECTION METRICS:
- Triggered Business Rules: 
{rules_text}
- Machine Learning Anomaly Score: {ml_score}/100
- Graph Relationship Score: {graph_score}/100
- Final Aggregated Risk Score: {aggregated_score}/100
- Final System Decision: {decision_status}

YOUR TASKS:
1. Generate a CUSTOMER EXPLANATION:
- Must be friendly, clear, reassuring, and easy to understand for a normal consumer.
- Do not mention raw risk scores, machine learning terminology, graph weights, or developer rules.
- If APPROVED: Confirm their payment is secure and has completed.
- If REVIEW: Explain that the transaction is under a temporary standard security review for their safety and will be resolved shortly.
- If BLOCKED: Explain that the transaction was declined due to security verification steps (e.g. from an unrecognized device or suspicious pattern).

2. Generate an ANALYST EXPLANATION:
- Must be highly technical, objective, and detailed for fraud investigators.
- Provide a summary of the evidence, highlighting rule triggers, ML anomaly indicators, and relationship links.
- Keep it structured and action-oriented to help them make a fast override decision (Approve/Reject).

Return the output strictly in the following JSON format:
{{
  "customer_explanation": "Your customer explanation text",
  "analyst_explanation": "Your analyst explanation text"
}}
"""

        try:
            # Prepare payload
            payload = {
                "contents": [
                    {
                        "parts": [
                            {"text": prompt}
                        ]
                    }
                ],
                "generationConfig": {
                    "responseMimeType": "application/json"
                }
            }
            
            req_data = json.dumps(payload).encode("utf-8")
            url_with_key = f"{self.api_url}?key={api_key}"
            
            # Send HTTP Request
            req = urllib.request.Request(
                url_with_key,
                data=req_data,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            
            with urllib.request.urlopen(req, timeout=10) as response:
                resp_data = json.loads(response.read().decode("utf-8"))
                
                # Parse Gemini response candidate text
                candidate_text = resp_data["candidates"][0]["content"]["parts"][0]["text"]
                explanation_json = json.loads(candidate_text.strip())
                
                cust_text = explanation_json.get("customer_explanation")
                analyst_text = explanation_json.get("analyst_explanation")
                
                if cust_text and analyst_text:
                    return cust_text, analyst_text
                    
        except Exception as e:
            # Silence and fall back to templates
            import logging
            logging.getLogger("uvicorn.error").warning(f"Failed to generate Gemini explanations: {e}")
            
        return None, None


gemini_explainer = GeminiExplainer()
