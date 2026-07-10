from fastapi import APIRouter, Depends

from app.core.dependencies import require_role

router = APIRouter(
    prefix="/analyst",
    tags=["Fraud Analyst"],
)


@router.get("/dashboard")
def analyst_dashboard(
    current_user=Depends(
        require_role("analyst")
    ),
):
    return {
        "message": "Welcome Fraud Analyst",
        "analyst": current_user.name,
    }