import sys
import os
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

# Ensure backend root is on sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app.main import app
from app.core.database import SessionLocal
from app.core.security import get_password_hash, create_access_token
from app.modules.auth.models import User, UserRole

ADMIN_USER_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
ASSESSOR_USER_ID = uuid.UUID("00000000-0000-0000-0000-000000000002")
VIEWER_USER_ID = uuid.UUID("00000000-0000-0000-0000-000000000003")


def _get_or_create_test_user(user_id: uuid.UUID, email: str, name: str, role: UserRole) -> User:
    db = SessionLocal()
    try:
        user = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
        if not user:
            # Check by email as fallback
            user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
            if not user:
                user = User(
                    id=user_id,
                    name=name,
                    email=email,
                    password_hash=get_password_hash("TestPassword123!"),
                    role=role,
                    is_active=True,
                    failed_login_count=0,
                    locked_until=None,
                )
                db.add(user)
                db.commit()
                db.refresh(user)
            else:
                user.role = role
                user.is_active = True
                user.locked_until = None
                user.failed_login_count = 0
                db.commit()
                db.refresh(user)
        else:
            user.role = role
            user.is_active = True
            user.locked_until = None
            user.failed_login_count = 0
            db.commit()
            db.refresh(user)
        return user
    finally:
        db.close()


@pytest.fixture(scope="session")
def admin_user():
    return _get_or_create_test_user(
        user_id=ADMIN_USER_ID,
        email="test_admin@secassess.local",
        name="Test Administrator",
        role=UserRole.ADMIN,
    )


@pytest.fixture(scope="session")
def assessor_user():
    return _get_or_create_test_user(
        user_id=ASSESSOR_USER_ID,
        email="test_assessor@secassess.local",
        name="Test Assessor",
        role=UserRole.ASSESSOR,
    )


@pytest.fixture(scope="session")
def viewer_user():
    return _get_or_create_test_user(
        user_id=VIEWER_USER_ID,
        email="test_viewer@secassess.local",
        name="Test Viewer",
        role=UserRole.VIEWER,
    )


@pytest.fixture(scope="session")
def admin_token(admin_user):
    return create_access_token(subject=str(admin_user.id), role=admin_user.role.value)


@pytest.fixture(scope="session")
def assessor_token(assessor_user):
    return create_access_token(subject=str(assessor_user.id), role=assessor_user.role.value)


@pytest.fixture(scope="session")
def viewer_token(viewer_user):
    return create_access_token(subject=str(viewer_user.id), role=viewer_user.role.value)


@pytest.fixture(scope="session")
def admin_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture(scope="session")
def assessor_headers(assessor_token):
    return {"Authorization": f"Bearer {assessor_token}"}


@pytest.fixture(scope="session")
def viewer_headers(viewer_token):
    return {"Authorization": f"Bearer {viewer_token}"}


@pytest.fixture(scope="session")
def client(assessor_token):
    """
    Default test client with authenticated assessor session.
    Preserves seamless execution of Phase 1-3 tests with valid assessor privileges.
    """
    with TestClient(app) as test_client:
        test_client.headers["Authorization"] = f"Bearer {assessor_token}"
        yield test_client


@pytest.fixture(scope="session")
def assessor_client(assessor_token):
    """Client with assessor credentials."""
    with TestClient(app) as test_client:
        test_client.headers["Authorization"] = f"Bearer {assessor_token}"
        yield test_client


@pytest.fixture(scope="session")
def unauth_client():
    """Unauthenticated client for testing 401 Unauthorized enforcement."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="session")
def admin_client(admin_token):
    """Client with administrator credentials."""
    with TestClient(app) as test_client:
        test_client.headers["Authorization"] = f"Bearer {admin_token}"
        yield test_client


@pytest.fixture(scope="session")
def viewer_client(viewer_token):
    """Client with viewer (read-only) credentials."""
    with TestClient(app) as test_client:
        test_client.headers["Authorization"] = f"Bearer {viewer_token}"
        yield test_client
