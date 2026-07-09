from fastapi import FastAPI
from sqlalchemy import text

from app.core.config import settings
from app.database.database import engine

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="AI Powered Fraud Detection Platform"
)


@app.on_event("startup")
def startup():
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
        print("Database connected successfully!")


@app.get("/")
def root():
    return {
        "message": "Welcome to FraudLens!",
        "version": settings.APP_VERSION
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "application": settings.APP_NAME
    }