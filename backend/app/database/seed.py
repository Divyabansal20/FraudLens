from datetime import datetime, timedelta
import random
from sqlalchemy.orm import Session
from app.database.database import SessionLocal, engine
from app.models.user import User
from app.models.transaction import Transaction
from app.models.blacklist import BlacklistedEntity
from app.models.enums import TransactionStatus
from app.core.security import hash_password


def seed_database():
    db = SessionLocal()
    try:
        print("Seeding database...")
        
        # 1. Create Users if they don't exist
        customer = db.query(User).filter(User.email == "customer@fraudlens.com").first()
        if not customer:
            customer = User(
                name="Rahul Sharma",
                email="customer@fraudlens.com",
                password=hash_password("password123"),
                role="customer"
            )
            db.add(customer)
            db.commit()
            db.refresh(customer)
            print("Created customer user: customer@fraudlens.com")
        else:
            print("Customer user already exists.")

        analyst = db.query(User).filter(User.email == "analyst@fraudlens.com").first()
        if not analyst:
            analyst = User(
                name="Inspector Malhotra",
                email="analyst@fraudlens.com",
                password=hash_password("password123"),
                role="analyst"
            )
            db.add(analyst)
            db.commit()
            print("Created analyst user: analyst@fraudlens.com")
        else:
            print("Analyst user already exists.")

        # 2. Create Blacklisted Entities
        blacklist_items = [
            ("receiver", "Blacklisted Receiver Corp", "Associated with phishing mule accounts"),
            ("receiver", "Fraudulent Account XYZ", "Known money laundering destination"),
            ("ip", "198.51.100.42", "IP flagged for brute-force attacks"),
            ("device", "compromised_device_99", "Device ID spoofed in multiple carding runs")
        ]
        for ent_type, ent_val, reason in blacklist_items:
            existing = db.query(BlacklistedEntity).filter(
                BlacklistedEntity.entity_type == ent_type,
                BlacklistedEntity.entity_value == ent_val
            ).first()
            if not existing:
                be = BlacklistedEntity(
                    entity_type=ent_type,
                    entity_value=ent_val,
                    reason=reason,
                    is_active=True
                )
                db.add(be)
                print(f"Added blacklist: {ent_type} -> {ent_val}")
        db.commit()

        # 3. Create Transaction History for customer to establish profile
        tx_count = db.query(Transaction).filter(Transaction.sender_id == customer.id).count()
        if tx_count < 10:
            print(f"Found {tx_count} transactions. Seeding 15 mock historical transactions to build user profile...")
            
            # Base variables for user profiling
            start_date = datetime.utcnow() - timedelta(days=30)
            
            # Generate 15 transactions
            for i in range(15):
                # Distribute times over the last 30 days, during active hours (9 AM - 9 PM)
                days_ago = random.uniform(1, 30)
                hour = random.randint(9, 21)
                minute = random.randint(0, 59)
                tx_time = start_date + timedelta(days=30 - days_ago)
                tx_time = tx_time.replace(hour=hour, minute=minute)
                
                # Amounts between ₹1,000 and ₹4,000 (Average around ₹2,500)
                amount = round(random.uniform(1000.0, 4000.0), 2)
                
                # Standard locations, devices, IP, etc.
                tx = Transaction(
                    sender_id=customer.id,
                    receiver_name=random.choice(["Amit Patel", "Priya Singh", "Supermarket Retail", "Electric Utility"]),
                    amount=amount,
                    payment_method=random.choice(["UPI", "NetBanking"]),
                    device_id="Samsung_S24_D998",
                    city="Delhi",
                    ip_address="192.168.1.10",
                    merchant_category=random.choice(["retail", "utilities", "entertainment"]),
                    country="IN",
                    status=TransactionStatus.APPROVED,
                    created_at=tx_time
                )
                db.add(tx)
            db.commit()
            print("Successfully seeded historical transactions.")
        else:
            print("User already has sufficient transaction history.")

        print("Database seeding completed successfully!")
    except Exception as e:
        db.rollback()
        print(f"Error seeding database: {e}")
    finally:
        db.close()


if __name__ == "__main__":
    seed_database()
