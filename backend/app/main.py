from contextlib import asynccontextmanager
from typing import Dict, Any
from fastapi import FastAPI, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.database import get_db
from app.core.logging import setup_logging, logger

# Import all module routers
from app.modules.auth.router import router as auth_router
from app.modules.audit.router import router as audit_router
from app.modules.targets.router import router as targets_router
from app.modules.assessments.router import router as assessments_router
from app.modules.scans.router import router as scans_router
from app.modules.recon.router import router as recon_router
from app.modules.web_assessment.router import router as web_assessment_router
from app.modules.findings.router import router as findings_router
from app.modules.ai_analysis.router import router as ai_analysis_router
from app.modules.verification.router import router as verification_router
from app.modules.reporting.router import router as reporting_router
from app.modules.dashboard.router import router as dashboard_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup and shutdown routines."""
    setup_logging()
    logger.info("Starting up %s", settings.PROJECT_NAME)
    yield
    logger.info("Shutting down %s", settings.PROJECT_NAME)


def create_app() -> FastAPI:
    """FastAPI application factory."""
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # Configure CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Health check endpoint under /api/v1/health
    @app.get(f"{settings.API_V1_PREFIX}/health", tags=["system"], status_code=status.HTTP_200_OK)
    def health_check(db: Session = Depends(get_db)) -> Dict[str, Any]:
        """Health check endpoint validating application and database connectivity."""
        db_status = "error"
        try:
            result = db.execute(text("SELECT 1")).scalar()
            if result == 1:
                db_status = "ok"
        except Exception as exc:
            logger.error("Health check database error: %s", exc)
            db_status = f"unhealthy: {str(exc)}"

        return {
            "status": "ok" if db_status == "ok" else "degraded",
            "database": db_status,
            "version": "0.1.0",
        }

    # Mount module routers under /api/v1
    prefix = settings.API_V1_PREFIX
    app.include_router(auth_router, prefix=prefix)
    app.include_router(audit_router, prefix=prefix)
    app.include_router(targets_router, prefix=prefix)
    app.include_router(assessments_router, prefix=prefix)
    app.include_router(scans_router, prefix=prefix)
    app.include_router(recon_router, prefix=prefix)
    app.include_router(web_assessment_router, prefix=prefix)
    app.include_router(findings_router, prefix=prefix)
    app.include_router(ai_analysis_router, prefix=prefix)
    app.include_router(verification_router, prefix=prefix)
    app.include_router(reporting_router, prefix=prefix)
    app.include_router(dashboard_router, prefix=prefix)

    return app


app = create_app()
