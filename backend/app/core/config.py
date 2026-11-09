from functools import lru_cache
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration loaded from environment variables."""

    # Project Information
    PROJECT_NAME: str = "AI-Assisted Security Assessment and Vulnerability Analysis Platform"
    API_V1_PREFIX: str = "/api/v1"
    ENVIRONMENT: str = "development"

    # Database
    POSTGRES_DB: str = "secassess"
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = "postgres"
    DATABASE_URL: str = "postgresql+psycopg://postgres:postgres@localhost:5432/secassess"

    # Security & JWT
    JWT_SECRET: str = "supersecretjwtkeyforuniversityprojecttestingonly12345"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 1440
    LOGIN_MAX_ATTEMPTS: int = 5
    LOCKOUT_MINUTES: int = 15
    DEFAULT_JWT_SECRET: str = "supersecretjwtkeyforuniversityprojecttestingonly12345"

    # Verification & Risk Rating
    MIN_VERIFICATION_NOTE_LENGTH: int = 10
    MIN_JUSTIFICATION_LENGTH: int = 10

    # Evidence Uploads
    UPLOAD_DIR: str = "uploads"
    MAX_UPLOAD_BYTES: int = 5 * 1024 * 1024  # 5 MB default

    # CORS
    CORS_ORIGINS: str = "http://localhost:5173,http://127.0.0.1:5173"

    # External Integrations
    # Docker uses the Compose service name; host-run backends can override with localhost.
    ZAP_API_URL: str = "http://zap:8080"
    ZAP_API_KEY: str = ""
    ZAP_ALLOW_ACTIVE_SCAN: bool = False
    ZAP_SPIDER_MAX_DEPTH: int = 2
    ZAP_SPIDER_MAX_DURATION_MINS: int = 2
    ANTHROPIC_API_KEY: str = ""

    # Google Gemini AI Integration
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-2.5-flash"
    AI_ENABLED: bool = False
    AI_TIMEOUT_SECONDS: int = 30
    AI_MAX_RETRIES: int = 2
    AI_MAX_INPUT_CHARS: int = 30000
    AI_MAX_OUTPUT_TOKENS: int = 2048
    AI_TEMPERATURE: float = 0.2
    AI_MAX_CALLS_PER_ASSESSMENT: int = 20
    AI_MAX_CALLS_PER_USER_PER_HOUR: int = 10
    AI_REDACT_INTERNAL_IPS: bool = False
    AI_EVIDENCE_MAX_CHARS: int = 2500

    # Tool Executables & Scan Configuration
    NMAP_PATH: str = "nmap"
    DIG_PATH: str = "dig"
    NSLOOKUP_PATH: str = "nslookup"
    CURL_PATH: str = "curl"
    TESTSSL_PATH: str = "testssl.sh"
    SCAN_TIMEOUT_SECONDS: int = 120
    MAX_CONCURRENT_SCANS: int = 2

    # Web Assessment Specifics
    WEB_RATE_LIMIT_DELAY_MS: int = 250
    WEB_MAX_REQUESTS_CAP: int = 100
    WEB_GLOBAL_TIMEOUT_SECONDS: int = 300
    WEB_REQUEST_TIMEOUT_SECONDS: int = 10
    WEB_MAX_BODY_SIZE_BYTES: int = 200000
    CHECK_SESSION_FIXATION: bool = False
    TEST_USER_EMAIL: str = "testuser@secassess.local"
    TEST_USER_PASSWORD: str = "TestPassword123!"

    # Seeding
    SEED_ADMIN_EMAIL: str = "admin@secassess.local"
    SEED_ADMIN_PASSWORD: str = "AdminSecurePassword123!"
    SEED_ASSESSOR_EMAIL: str = "assessor@secassess.local"
    SEED_ASSESSOR_PASSWORD: str = "AssessorSecurePassword123!"

    # Reporting and Exports Configuration (Phase 6)
    REPORT_DIR: str = "reports_storage"
    REPORT_FORMAT_PRIMARY: str = "docx"
    LIBREOFFICE_PATH: str = "soffice"
    REPORT_MAX_EXCERPT_CHARS: int = 1500
    REPORT_MAX_IMAGES: int = 20
    REPORT_MAX_IMAGE_WIDTH_PX: int = 1200
    REPORT_MAX_TOTAL_MB: int = 50
    REPORT_CLASSIFICATION: str = "Confidential: Academic Assessment"
    REPORT_GROUP_NAME: str = "Security Assessment Group"
    REPORT_COURSE: str = "Cybersecurity Assessment Capstone"
    REPORT_MEMBERS: str = "Lead Assessor, Security Analyst"
    DASHBOARD_TOP_FINDINGS: int = 5
    DASHBOARD_RECENT_ACTIVITY: int = 10

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
