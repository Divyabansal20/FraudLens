import json
import urllib.request
import urllib.error
from sqlalchemy.orm import Session
from app.models.transaction import Transaction
from app.models.fraud_evaluation import FraudEvaluation
from app.models.enums import TransactionStatus
from app.core.config import settings


class AIInvestigatorAssistant:
    def __init__(self):
        self.api_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"

    def generate_investigation_report(self, transaction: Transaction, drift_score: float, db: Session) -> tuple[str, str]:
        """
        Retrieves historical precedent fraud cases sharing similar attributes (RAG concept)
        and prompts Gemini to synthesize an investigator briefing and action recommendation.
        """
        # Find precedent blocked fraud transactions
        similar_cases = (
            db.query(Transaction)
            .filter(
                Transaction.status == TransactionStatus.BLOCKED,
                Transaction.id != transaction.id
            )
            .order_by(Transaction.created_at.desc())
            .limit(10)
            .all()
        )

        matched_cases = []
        for case in similar_cases:
            matches = []
            if case.device_id and transaction.device_id and case.device_id.lower() == transaction.device_id.lower():
                matches.append(f"Same Device ({transaction.device_id})")
            if case.receiver_name and transaction.receiver_name and case.receiver_name.lower() == transaction.receiver_name.lower():
                matches.append(f"Same Receiver ({transaction.receiver_name})")
            if case.city and transaction.city and case.city.lower() == transaction.city.lower():
                matches.append(f"Same City ({transaction.city})")
            if transaction.amount > 0 and abs(case.amount - transaction.amount) / transaction.amount <= 0.25:
                matches.append(f"Similar Amount (₹{case.amount:,.2f})")

            if len(matches) >= 1:
                eval_record = db.query(FraudEvaluation).filter(FraudEvaluation.transaction_id == case.id).first()
                audit_findings = eval_record.analyst_explanation if (eval_record and eval_record.analyst_explanation) else "Flagged automatically by security rules."
                matched_cases.append({
                    "id": case.id,
                    "amount": case.amount,
                    "device": case.device_id,
                    "city": case.city,
                    "receiver": case.receiver_name,
                    "matches": ", ".join(matches),
                    "audit_findings": audit_findings
                })

        # Keep top 3 most similar matches
        matched_cases = matched_cases[:3]

        # Assemble RAG Context
        if matched_cases:
            rag_context = ""
            for idx, c in enumerate(matched_cases, 1):
                rag_context += (
                    f"--- Historical Fraud Case {idx} ---\n"
                    f"- Case ID: #{c['id']}\n"
                    f"- Amount: ₹{c['amount']:,.2f}\n"
                    f"- Device ID: {c['device']}\n"
                    f"- City Location: {c['city']}\n"
                    f"- Receiver: {c['receiver']}\n"
                    f"- Shared Signatures: {c['matches']}\n"
                    f"- Precedent Findings: {c['audit_findings']}\n\n"
                )
        else:
            rag_context = "No direct matching historical fraud cases found in the repository."

        prompt = f"""
You are an expert fraud intelligence copilot. Synthesize an investigation briefing for the incoming transaction.

--- Current Case Details ---
Transaction ID: #{transaction.id}
Sender ID: {transaction.sender_id}
Receiver: {transaction.receiver_name}
Amount: ₹{transaction.amount:,.2f}
Device: {transaction.device_id}
City: {transaction.city}
IP: {transaction.ip_address}
Behavior Drift (Lifestyle Deviation): {drift_score}%

--- Historical Precedents (RAG Context) ---
{rag_context}

Provide the output strictly in the following JSON format:
{{
  "investigation_summary": "A professional, analyst-oriented summary detailing the evidence, the deviation, and similar characteristics with historical cases (maximum 4 bullet points formatted in standard markdown list).",
  "recommendation": "A concise recommended action (e.g. 'Temporarily Hold Transaction' or 'Confirm Fraud & Block') followed by a 1-sentence reason."
}}
"""

        api_key = settings.GEMINI_API_KEY
        if api_key:
            try:
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
                
                req = urllib.request.Request(
                    url_with_key,
                    data=req_data,
                    headers={"Content-Type": "application/json"},
                    method="POST"
                )
                
                with urllib.request.urlopen(req, timeout=10) as response:
                    resp_data = json.loads(response.read().decode("utf-8"))
                    candidate_text = resp_data["candidates"][0]["content"]["parts"][0]["text"]
                    result_json = json.loads(candidate_text.strip())
                    
                    summary = result_json.get("investigation_summary")
                    rec = result_json.get("recommendation")
                    
                    if summary and rec:
                        return summary, rec
            except Exception as e:
                import logging
                logging.getLogger("uvicorn.error").warning(f"Failed to generate Gemini investigation report: {e}")

        # Local deterministic template fallback
        summary = (
            f"- Transaction shows a behavior drift of **{drift_score}%** compared to historical transaction profiles.\n"
            f"- Current amount of ₹{transaction.amount:,.2f} is a deviation from typical spend limits.\n"
        )
        if matched_cases:
            summary += f"- Found matches in **{len(matched_cases)}** historical confirmed fraud cases: sharing " + ", ".join(matched_cases[0]["matches"].split(", "))
            recommendation = "Temporarily Hold Transaction. High correlation with previous account takeover profiles."
        else:
            recommendation = "Hold Transaction for customer verification due to high behavior deviation."

        return summary, recommendation
