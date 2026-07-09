from sqlalchemy.orm import Session

from app.models.user import User
from app.schemas.user import UserCreate


def create_user(db: Session, user: UserCreate):
    new_user = User(
        name=user.name,
        email=user.email,
        password=user.password,
        role=user.role,
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


def get_all_users(db: Session):
    return db.query(User).all()