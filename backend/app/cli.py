import argparse
import sys
from app.core.config import settings
from app.core.database import SessionLocal
from app.modules.auth.models import UserRole
from app.modules.auth.schemas import UserCreate
from app.modules.auth.service import AuthService


def create_admin(name: str, email: str, password: str) -> None:
    """Create an administrator account."""
    db = SessionLocal()
    try:
        service = AuthService(db)
        existing = service.repository.get_by_email(email)
        if existing:
            if existing.role != UserRole.ADMIN:
                existing.role = UserRole.ADMIN
                service.repository.update(existing)
                print(f"User '{email}' already exists. Promoted role to admin.")
            else:
                print(f"Admin user '{email}' already exists.")
            return

        user_in = UserCreate(
            name=name,
            email=email,
            password=password,
            role=UserRole.ADMIN,
        )
        created = service.register_user(user_in, creator=None)
        print(f"Successfully created admin user: {created.email} (ID: {created.id})")
    except Exception as e:
        print(f"Error creating admin: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        db.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Security Assessment Platform CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    admin_parser = subparsers.add_parser("create-admin", help="Bootstrap initial admin user")
    admin_parser.add_argument("--name", default="System Administrator", help="Admin user full name")
    admin_parser.add_argument("--email", default=settings.SEED_ADMIN_EMAIL, help="Admin user email")
    admin_parser.add_argument("--password", default=settings.SEED_ADMIN_PASSWORD, help="Admin user password")

    args = parser.parse_args()

    if args.command == "create-admin":
        create_admin(name=args.name, email=args.email, password=args.password)


if __name__ == "__main__":
    main()

