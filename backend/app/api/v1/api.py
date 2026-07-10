from fastapi import APIRouter

from app.api.v1.users import router as users_router
from app.api.v1.auth import router as auth_router
from app.api.v1.profile import router as profile_router
from app.api.v1.analyst import router as analyst_router


api_router = APIRouter(prefix="/api/v1")

api_router.include_router(users_router)

api_router.include_router(auth_router)
api_router.include_router(profile_router)
api_router.include_router(analyst_router)