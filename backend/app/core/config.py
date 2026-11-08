from functools import lru_cache
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration loaded from environment variables."""

    # Project Information
    PROJECT_NAME: str = "AI-Assisted Security Assessment and Vulnerability Analysis Platform"
    API_V1_PREFIX: str = "/api/v1"

    # Database
    POSTGRES_DB: str = "secassess"
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = "postgres"
    DATABASE_URL: str = "postgresql+psycopg://postgres:postgres@localhost:5432/secassess"

    # Security & JWT
    JWT_SECRET: str = "supersecretjwtkeyforuniversityprojecttestingonly12345"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 1440

    # CORS
    CORS_ORIGINS: str = "http://localhost:5173,http://127.0.0.1:5173"

    # External Integrations
    ZAP_API_KEY: str = ""
    ANTHROPIC_API_KEY: str = ""

    # Seeding
    SEED_ADMIN_EMAIL: str = "admin@secassess.local"
    SEED_ADMIN_PASSWORD: str = "AdminSecurePassword123!"
    SEED_ASSESSOR_EMAIL: str = "assessor@secassess.local"
    SEED_ASSESSOR_PASSWORD: str = "AssessorSecurePassword123!"

    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def cors_origins_list(self) -> List[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
