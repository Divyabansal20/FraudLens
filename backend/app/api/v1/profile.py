from fastapi import APIRouter, Depends

from app.core.security import get_current_user

router = APIRouter(
    prefix="/profile",
    tags=["Profile"],
)


@router.get("/me")
def get_profile(
    current_user=Depends(get_current_user),
):
    return {
        "id": current_user.id,
        "name": current_user.name,
        "email": current_user.email,
        "role": current_user.role,
    }