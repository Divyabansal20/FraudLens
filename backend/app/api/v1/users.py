from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.schemas.user import UserCreate, UserResponse
from app.services.user_service import create_user, get_all_users

router = APIRouter(
    prefix="/users",
    tags=["Users"]
)


@router.post("/", response_model=UserResponse)
def create_new_user(
    user: UserCreate,
    db: Session = Depends(get_db)
):
    return create_user(db, user)


@router.get("/", response_model=List[UserResponse])
def read_users(
    db: Session = Depends(get_db)
):
    return get_all_users(db)