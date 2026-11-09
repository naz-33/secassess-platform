"""Idempotent database seeding script."""
import sys
import os

# Ensure backend root is on sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from sqlalchemy import select
from app.core.config import settings
from app.core.database import SessionLocal
from app.core.security import get_password_hash
from app.core.logging import setup_logging, logger
from app.modules.auth.models import User, UserRole
from app.modules.targets.models import Target, ScopeItem


def seed_database() -> None:
    setup_logging()
    logger.info("Starting database seeding...")
    db = SessionLocal()

    try:
        # 1. Seed Admin User
        admin_email = settings.SEED_ADMIN_EMAIL
        admin_user = db.execute(select(User).where(User.email == admin_email)).scalar_one_or_none()
        if not admin_user:
            admin_user = User(
                name="Security Administrator",
                email=admin_email,
                password_hash=get_password_hash(settings.SEED_ADMIN_PASSWORD),
                role=UserRole.ADMIN,
            )
            db.add(admin_user)
            logger.info("Created admin user: %s", admin_email)
        else:
            logger.info("Admin user '%s' already exists, skipping.", admin_email)

        # 2. Seed Assessor User
        assessor_email = settings.SEED_ASSESSOR_EMAIL
        assessor_user = db.execute(select(User).where(User.email == assessor_email)).scalar_one_or_none()
        if not assessor_user:
            assessor_user = User(
                name="Lead Security Assessor",
                email=assessor_email,
                password_hash=get_password_hash(settings.SEED_ASSESSOR_PASSWORD),
                role=UserRole.ASSESSOR,
            )
            db.add(assessor_user)
            logger.info("Created assessor user: %s", assessor_email)
        else:
            logger.info("Assessor user '%s' already exists, skipping.", assessor_email)

        # 3. Seed Example Target (OWASP Juice Shop)
        target_name = "OWASP Juice Shop"
        target = db.execute(select(Target).where(Target.name == target_name)).scalar_one_or_none()
        if not target:
            target = Target(
                name=target_name,
                base_url="http://juice-shop:3000",
                description="Intentionally vulnerable web application for security assessment practice.",
                authorization_note="Authorized for academic lab testing within designated environment boundaries.",
            )
            db.add(target)
            db.flush()  # to obtain target.id

            scope_item = ScopeItem(
                target_id=target.id,
                asset="http://juice-shop:3000",
                in_scope=True,
                notes="Primary application target in Docker compose network",
            )
            db.add(scope_item)
            logger.info("Created target '%s' with default scope item.", target_name)
        else:
            logger.info("Target '%s' already exists, skipping.", target_name)

        db.commit()
        logger.info("Database seeding completed successfully.")
    except Exception as exc:
        db.rollback()
        logger.error("Error during seeding: %s", exc)
        raise
    finally:
        db.close()


if __name__ == "__main__":
    seed_database()

