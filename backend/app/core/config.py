from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str
    APP_VERSION: str
    DEBUG: bool

    DATABASE_URL: str

    SECRET_KEY: str
    ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int

    REDIS_URL: str

    # Fraud Detection Engine configuration settings
    FRAUD_RULE_WEIGHT: float = 0.25
    FRAUD_ML_WEIGHT: float = 0.40
    FRAUD_GRAPH_WEIGHT: float = 0.35
    FRAUD_REVIEW_THRESHOLD: float = 38.0
    FRAUD_BLOCKED_THRESHOLD: float = 80.0
    FRAUD_ML_MIN_HISTORY: int = 5
    GEMINI_API_KEY: str = ""

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True
    )


settings = Settings()