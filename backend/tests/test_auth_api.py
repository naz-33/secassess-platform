import uuid
from datetime import datetime, timezone, timedelta
import jwt
import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.security import get_password_hash, create_access_token
from app.modules.auth.models import User, UserRole


def test_password_hashing_and_no_plaintext():
    """Ensure password hashing is one-way, salted, and plaintext is not stored."""
    plain = "SuperSecureSecret123!"
    hashed = get_password_hash(plain)
    assert hashed != plain
    assert hashed.startswith("$2b$") or hashed.startswith("$2a$")

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == "test_admin@secassess.local").first()
        assert user is not None
        assert user.password_hash != "TestPassword123!"
        assert not user.password_hash.startswith("TestPassword")
    finally:
        db.close()


def test_login_success(unauth_client: TestClient, assessor_user):
    """Test login with valid credentials yields JWT token and user info."""
    res = unauth_client.post(
        "/api/v1/auth/login",
        json={"email": assessor_user.email, "password": "TestPassword123!"},
    )
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["email"] == assessor_user.email
    assert data["user"]["role"] == "assessor"


def test_login_generic_error_on_invalid_credentials(unauth_client: TestClient):
    """Wrong password or unknown email must return generic 401 without enumeration."""
    # Unknown user
    res1 = unauth_client.post(
        "/api/v1/auth/login",
        json={"email": "nonexistent@secassess.local", "password": "SomePassword123!"},
    )
    assert res1.status_code == 401
    assert "invalid email or password" in res1.json()["detail"].lower()

    # Known user, wrong password
    res2 = unauth_client.post(
        "/api/v1/auth/login",
        json={"email": "test_assessor@secassess.local", "password": "IncorrectPassword123!"},
    )
    assert res2.status_code == 401
    assert "invalid email or password" in res2.json()["detail"].lower()


def test_brute_force_lockout(unauth_client: TestClient):
    """After N failed logins, account must be temporarily locked."""
    # Create dedicated user for brute-force test
    email = f"brute_{uuid.uuid4().hex[:6]}@secassess.local"
    db = SessionLocal()
    try:
        user = User(
            name="Brute User",
            email=email,
            password_hash=get_password_hash("CorrectPassword123!"),
            role=UserRole.ASSESSOR,
            is_active=True,
            failed_login_count=0,
            locked_until=None,
        )
        db.add(user)
        db.commit()
    finally:
        db.close()

    # Attempt failed logins up to limit
    for _ in range(settings.LOGIN_MAX_ATTEMPTS):
        res = unauth_client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "WrongPassword123!"},
        )
        assert res.status_code == 401

    # Next attempt must trigger lockout message
    locked_res = unauth_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "CorrectPassword123!"},
    )
    assert locked_res.status_code == 401
    assert "locked" in locked_res.json()["detail"].lower()


def test_token_expiry_and_tampered_token_rejected(unauth_client: TestClient, assessor_user):
    """Expired tokens and tokens with invalid signatures must be rejected."""
    # 1. Expired token
    expired_token = create_access_token(
        subject=str(assessor_user.id),
        role=assessor_user.role.value,
        expires_delta=timedelta(seconds=-10),
    )
    res_exp = unauth_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert res_exp.status_code == 401

    # 2. Tampered token (signed with different key)
    tampered_token = jwt.encode(
        {"sub": str(assessor_user.id), "exp": datetime.now(timezone.utc) + timedelta(minutes=10)},
        "wrong-secret-key-12345678901234567890",
        algorithm="HS256",
    )
    res_tampered = unauth_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {tampered_token}"},
    )
    assert res_tampered.status_code == 401


def test_inactive_user_rejected(unauth_client: TestClient):
    """Deactivated user account cannot log in or authenticate."""
    email = f"inactive_{uuid.uuid4().hex[:6]}@secassess.local"
    db = SessionLocal()
    try:
        user = User(
            name="Inactive User",
            email=email,
            password_hash=get_password_hash("ValidPassword123!"),
            role=UserRole.ASSESSOR,
            is_active=False,
        )
        db.add(user)
        db.commit()
    finally:
        db.close()

    res = unauth_client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "ValidPassword123!"},
    )
    assert res.status_code in (401, 403)


def test_weak_password_rejected(admin_client: TestClient):
    """Passwords shorter than 12 characters must be rejected upon user creation."""
    res = admin_client.post(
        "/api/v1/users",
        json={
            "name": "Weak Pass User",
            "email": f"weak_{uuid.uuid4().hex[:6]}@secassess.local",
            "password": "short",  # < 12 chars
            "role": "assessor",
        },
    )
    assert res.status_code == 422

