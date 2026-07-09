from fastapi import FastAPI
from sqlalchemy import text

from app.api.v1.api import api_router
from app.core.config import settings
from app.database.database import engine
from app.core.exceptions import register_exception_handlers

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="AI Powered Fraud Detection Platform",
)

register_exception_handlers(app)

app.include_router(api_router)

@app.on_event("startup")
def startup():
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
        print("Database connected successfully!")


@app.get("/")
def root():
    return {
        "message": "Welcome to FraudLens!",
        "version": settings.APP_VERSION,
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "application": settings.APP_NAME,
    }