
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models import User, UserCredential
from app.services.authentication import (
    hash_password,
    create_access_token,
)

# Separate in-memory database for testing
test_engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

TestSession = sessionmaker(
    bind=test_engine,
    autoflush=False,
    expire_on_commit=False,
)

TEST_PASSWORD = "TestPassword123!Secure"


def override_get_db():
    with TestSession() as db:
        yield db


@pytest.fixture
def client():
    Base.metadata.create_all(bind=test_engine)

    with TestSession() as db:
        users = [
            User(
                id="DOC001",
                name="Demo Doctor",
                role="DOCTOR",
                on_shift=True,
                location="HOSPITAL",
                registered_device="WS001",
            ),
            User(
                id="NUR001",
                name="Demo Nurse",
                role="NURSE",
                on_shift=True,
                location="HOSPITAL",
                registered_device="WS002",
            ),
            User(
                id="ADM001",
                name="Demo Administrator",
                role="ADMIN",
                on_shift=True,
                location="HOSPITAL",
                registered_device="WS004",
            ),
        ]

        db.add_all(users)
        db.flush()

        for user in users:
            db.add(
                UserCredential(
                    user_id=user.id,
                    password_hash=hash_password(TEST_PASSWORD),
                    active=True,
                )
            )

        db.commit()

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)


def login(client, user_id, password=TEST_PASSWORD):
    response = client.post(
        "/auth/login",
        json={
            "user_id": user_id,
            "password": password,
        },
    )
    return response


def headers_for(client, user_id):
    response = login(client, user_id)
    assert response.status_code == 200

    token = response.json()["access_token"]

    return {
        "Authorization": f"Bearer {token}"
    }


def test_valid_login(client):
    response = login(client, "DOC001")

    assert response.status_code == 200
    assert "access_token" in response.json()


def test_invalid_login(client):
    response = login(
        client,
        "DOC001",
        "IncorrectPassword123!",
    )

    assert response.status_code == 401


def test_access_without_token(client):
    response = client.post(
        "/access/evaluate",
        json={
            "case_id": "CASE001",
            "purpose": "TREATMENT",
            "access_device": "WS001",
        },
    )

    assert response.status_code == 401


def test_doctor_cannot_view_audit_history(client):
    response = client.get(
        "/access/history",
        headers=headers_for(client, "DOC001"),
    )

    assert response.status_code == 403


def test_admin_can_view_audit_history(client):
    response = client.get(
        "/access/history",
        headers=headers_for(client, "ADM001"),
    )

    assert response.status_code == 200
