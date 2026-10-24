
import pytest

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models import (
    User,
    UserCredential,
    EmergencyCase,
    CaseAssignment,
    TelemetryRecord,
    AccessLog,
)
from app.services.authentication import hash_password


TEST_PASSWORD = "TestPassword123!Secure"

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
                name="Test Doctor",
                role="DOCTOR",
                on_shift=True,
                location="HOSPITAL",
                registered_device="WS001",
            ),
            User(
                id="NUR001",
                name="Test Nurse",
                role="NURSE",
                on_shift=True,
                location="HOSPITAL",
                registered_device="WS002",
            ),
            User(
                id="ADM001",
                name="Test Administrator",
                role="ADMIN",
                on_shift=True,
                location="HOSPITAL",
                registered_device="WS004",
            ),
        ]
        db.add_all(users)

        db.add_all([
            EmergencyCase(
                id="CASE001",
                severity="HIGH",
                active=True,
            ),
            EmergencyCase(
                id="CASE002",
                severity="CRITICAL",
                active=True,
            ),
        ])

        db.flush()

        for user in users:
            db.add(
                UserCredential(
                    user_id=user.id,
                    password_hash=hash_password(TEST_PASSWORD),
                    active=True,
                )
            )

        db.add(
            CaseAssignment(
                user_id="DOC001",
                case_id="CASE001",
            )
        )

        db.add_all([
            TelemetryRecord(
                case_id="CASE001",
                device_id="AMB001",
                packet_id="pkt_001",
                heart_rate=82,
                spo2=98.0,
                systolic_bp=120,
                diastolic_bp=80,
                respiratory_rate=18,
                c3_status="ACCEPT",
            ),
            TelemetryRecord(
                case_id="CASE001",
                device_id="AMB001",
                packet_id="pkt_002",
                heart_rate=110,
                spo2=92.0,
                systolic_bp=140,
                diastolic_bp=90,
                respiratory_rate=24,
                c3_status="FLAG",
            ),
            TelemetryRecord(
                case_id="CASE001",
                device_id="AMB001",
                packet_id="pkt_003",
                heart_rate=90,
                spo2=97.0,
                systolic_bp=125,
                diastolic_bp=82,
                respiratory_rate=20,
                c3_status="DISCARD",
            ),
        ])

        db.commit()

    app.dependency_overrides[get_db] = override_get_db

    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=test_engine)


def headers_for(client, user_id):
    response = client.post(
        "/auth/login",
        json={
            "user_id": user_id,
            "password": TEST_PASSWORD,
        },
    )
    assert response.status_code == 200

    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def get_telemetry(client, user_id, device):
    return client.get(
        "/telemetry/cases/CASE001",
        params={"access_device": device},
        headers=headers_for(client, user_id),
    )


def test_unauthenticated_access_denied(client):
    response = client.get(
        "/telemetry/cases/CASE001",
        params={"access_device": "WS001"},
    )
    assert response.status_code == 401


def test_assigned_doctor_can_view_telemetry(client):
    response = get_telemetry(client, "DOC001", "WS001")

    assert response.status_code == 200

    records = response.json()
    assert len(records) == 2

    statuses = {record["c3_status"] for record in records}
    assert statuses == {"ACCEPT", "FLAG"}

    assert all(
        record["case_id"] == "CASE001"
        for record in records
    )


def test_unassigned_nurse_denied(client):
    response = get_telemetry(client, "NUR001", "WS002")
    assert response.status_code == 403


def test_unregistered_workstation_denied(client):
    response = get_telemetry(client, "DOC001", "UNKNOWN")
    assert response.status_code == 403


def test_admin_cannot_view_patient_telemetry(client):
    response = get_telemetry(client, "ADM001", "WS004")
    assert response.status_code == 403


def test_unknown_case_returns_404(client):
    response = client.get(
        "/telemetry/cases/UNKNOWN",
        params={"access_device": "WS001"},
        headers=headers_for(client, "DOC001"),
    )
    assert response.status_code == 404


def test_successful_access_is_audited(client):
    response = get_telemetry(client, "DOC001", "WS001")
    assert response.status_code == 200

    with TestSession() as db:
        log = db.scalar(
            select(AccessLog)
            .where(AccessLog.user_id == "DOC001")
            .where(AccessLog.case_id == "CASE001")
        )

        assert log is not None
        assert log.decision == "ALLOW"


def test_denied_access_is_audited(client):
    response = get_telemetry(client, "NUR001", "WS002")
    assert response.status_code == 403

    with TestSession() as db:
        log = db.scalar(
            select(AccessLog)
            .where(AccessLog.user_id == "NUR001")
            .where(AccessLog.case_id == "CASE001")
        )

        assert log is not None
        assert log.decision == "DENY"

