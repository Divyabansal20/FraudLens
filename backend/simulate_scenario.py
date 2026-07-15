import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.abspath('.'))

# Pre-import models to register them in SQLAlchemy mapper
from app.models.user import User
from app.models.transaction import Transaction
from app.models.fraud_evaluation import FraudEvaluation
from app.models.enums import TransactionStatus
from app.database.database import SessionLocal, engine
from app.core.security import hash_password
from app.services.fraud.orchestrator import fraud_orchestrator


def run_scenario():
    db = SessionLocal()
    try:
        print("Starting Real-World Scenario Simulation...")

        # 1. Create Simulation Users
        users_info = [
            ("Vikram Malhotra", "vikram@example.com", "corporate"),
            ("Sneha Rao", "sneha@example.com", "steady_utility"),
            ("Aman Verma", "aman@example.com", "high_value")
        ]
        
        users = {}
        for name, email, label in users_info:
            user = db.query(User).filter(User.email == email).first()
            if not user:
                user = User(
                    name=name,
                    email=email,
                    password=hash_password("password123"),
                    role="customer"
                )
                db.add(user)
                db.commit()
                db.refresh(user)
                print(f"Created user: {name} ({email})")
            else:
                print(f"User already exists: {name}")
            users[label] = user

        # 2. Clear old evaluations and transactions for these users to make a clean run
        user_ids = [u.id for u in users.values()]
        db.query(FraudEvaluation).filter(
            FraudEvaluation.transaction_id.in_(
                db.query(Transaction.id).filter(Transaction.sender_id.in_(user_ids))
            )
        ).delete(synchronize_session=False)
        db.commit()
        
        db.query(Transaction).filter(Transaction.sender_id.in_(user_ids)).delete(synchronize_session=False)
        db.commit()
        print("Cleaned up old simulation transactions.")

        base_time = datetime.utcnow() - timedelta(days=2)

        # 3. Vikram Malhotra's Timeline (Account Takeover Fraud Target)
        vikram = users["corporate"]
        vikram_txs = [
            # Day 1, 10:00 AM - Safe internet payment
            {
                "receiver_name": "Airtel Broadband",
                "amount": 3500.0,
                "payment_method": "NetBanking",
                "device_id": "Lenovo_ThinkPad_X1",
                "city": "Bangalore",
                "ip_address": "103.56.28.12",
                "merchant_category": "utilities",
                "time_offset": timedelta(days=0, hours=10)
            },
            # Day 1, 2:30 PM - Safe travel purchase
            {
                "receiver_name": "Indigo Airlines",
                "amount": 8000.0,
                "payment_method": "UPI",
                "device_id": "Lenovo_ThinkPad_X1",
                "city": "Bangalore",
                "ip_address": "103.56.28.12",
                "merchant_category": "entertainment",
                "time_offset": timedelta(days=0, hours=14, minutes=30)
            },
            # Day 2, 9:00 AM - Safe morning coffee
            {
                "receiver_name": "Starbucks Coffee",
                "amount": 1500.0,
                "payment_method": "UPI",
                "device_id": "Samsung_S23_Vikram",
                "city": "Bangalore",
                "ip_address": "103.56.28.12",
                "merchant_category": "retail",
                "time_offset": timedelta(days=1, hours=9)
            },
            # Day 2, 9:02 AM - SUDDEN ACCOUNT TAKEOVER (Impossible travel + Hacker device + Manoj Kumar receiver)
            {
                "receiver_name": "Manoj Kumar",
                "amount": 95000.0,
                "payment_method": "UPI",
                "device_id": "Atacker_macbook_pro",
                "city": "Delhi",
                "ip_address": "203.0.113.88",
                "merchant_category": "retail",
                "time_offset": timedelta(days=1, hours=9, minutes=2)
            }
        ]

        # 4. Sneha Rao's Timeline (Device Hijacking Fraud Target)
        sneha = users["steady_utility"]
        sneha_txs = [
            # Day 1, 8:00 PM - Standard payment
            {
                "receiver_name": "Tata Power",
                "amount": 1200.0,
                "payment_method": "UPI",
                "device_id": "iPhone_15_Pro",
                "city": "Mumbai",
                "ip_address": "120.45.67.89",
                "merchant_category": "utilities",
                "time_offset": timedelta(days=0, hours=20)
            },
            # Day 2, 7:00 PM - Standard grocery
            {
                "receiver_name": "Nature's Basket",
                "amount": 850.0,
                "payment_method": "UPI",
                "device_id": "iPhone_15_Pro",
                "city": "Mumbai",
                "ip_address": "120.45.67.89",
                "merchant_category": "retail",
                "time_offset": timedelta(days=1, hours=19)
            },
            # Day 3, 2:15 AM - COMPROMISED DEVICE HIJACK (Blacklisted device + Blacklisted receiver)
            {
                "receiver_name": "Fraudulent Account XYZ",
                "amount": 45000.0,
                "payment_method": "NetBanking",
                "device_id": "compromised_device_99",
                "city": "Mumbai",
                "ip_address": "120.45.67.89",
                "merchant_category": "entertainment",
                "time_offset": timedelta(days=2, hours=2, minutes=15)
            }
        ]

        # 5. Aman Verma's Timeline (Legitimate High-Value Buyer - Not Fraud)
        aman = users["high_value"]
        aman_txs = [
            # Day 1, 12:00 PM - Large safe shopping
            {
                "receiver_name": "Reliance Digital",
                "amount": 45000.0,
                "payment_method": "NetBanking",
                "device_id": "iPhone_14",
                "city": "Pune",
                "ip_address": "144.56.78.90",
                "merchant_category": "retail",
                "time_offset": timedelta(days=0, hours=12)
            },
            # Day 2, 4:00 PM - Grocery
            {
                "receiver_name": "More Retail",
                "amount": 3000.0,
                "payment_method": "UPI",
                "device_id": "iPhone_14",
                "city": "Pune",
                "ip_address": "144.56.78.90",
                "merchant_category": "retail",
                "time_offset": timedelta(days=1, hours=16)
            },
            # Day 3, 11:30 AM - Large laptop purchase (legit)
            {
                "receiver_name": "Croma Electronics",
                "amount": 75000.0,
                "payment_method": "NetBanking",
                "device_id": "iPhone_14",
                "city": "Pune",
                "ip_address": "144.56.78.90",
                "merchant_category": "retail",
                "time_offset": timedelta(days=2, hours=11, minutes=30)
            }
        ]

        # Function to insert and evaluate transactions in timeline sequence
        all_tx_definitions = []
        for d in vikram_txs:
            all_tx_definitions.append((vikram, d))
        for d in sneha_txs:
            all_tx_definitions.append((sneha, d))
        for d in aman_txs:
            all_tx_definitions.append((aman, d))

        # Sort timeline by time offset to compile profile correctly sequentially
        all_tx_definitions.sort(key=lambda x: x[1]["time_offset"])

        print("\nFeeding transactions sequentially into the engine...")
        for user, tx_def in all_tx_definitions:
            tx = Transaction(
                sender_id=user.id,
                receiver_name=tx_def["receiver_name"],
                amount=tx_def["amount"],
                payment_method=tx_def["payment_method"],
                device_id=tx_def["device_id"],
                city=tx_def["city"],
                ip_address=tx_def["ip_address"],
                merchant_category=tx_def["merchant_category"],
                country="IN",
                status=TransactionStatus.APPROVED,  # Temporary
                created_at=base_time + tx_def["time_offset"]
            )
            db.add(tx)
            db.commit()
            db.refresh(tx)

            # Evaluate transaction using Orchestrator (Rules, ML, Graph, Behavior Profile, RAG Copilot)
            eval_record = fraud_orchestrator.evaluate_transaction(db, tx)
            db.add(eval_record)
            db.commit()
            db.refresh(eval_record)

            print(f"ID #{tx.id} | User: {user.name} | Amount: INR {tx.amount:,} | Status: {tx.status.value} | Risk Score: {eval_record.aggregated_score}")

        print("\nReal-World Scenario Seeded Successfully!")
    except Exception as e:
        db.rollback()
        print(f"Error during simulation: {e}")
    finally:
        db.close()


if __name__ == "__main__":
    run_scenario()
