
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def evaluate(user, case, purpose, device):
    response = client.post(
        "/access/evaluate",
        json={
            "user_id": user,
            "case_id": case,
            "purpose": purpose,
            "access_device": device,
        },
    )
    assert response.status_code == 200
    return response.json()


def test_authorized_doctor():
    result = evaluate(
        "DOC001", "CASE001", "TREATMENT", "WS001"
    )
    assert result["decision"] == "ALLOW"
    assert result["risk_score"] == 0.0


def test_unassigned_nurse_denied():
    result = evaluate(
        "NUR001", "CASE002", "TREATMENT", "WS002"
    )
    assert result["decision"] == "DENY"


def test_emergency_requires_break_glass():
    result = evaluate(
        "DOC001", "CASE002", "EMERGENCY", "WS001"
    )
    assert result["decision"] == "BREAK_GLASS_REQUIRED"


def test_admin_denied():
    result = evaluate(
        "ADM001", "CASE001", "TREATMENT", "WS004"
    )
    assert result["decision"] == "DENY"


def test_unregistered_device_denied():
    result = evaluate(
        "DOC001", "CASE001", "TREATMENT", "UNKNOWN"
    )
    assert result["decision"] == "DENY"


def test_unknown_user():
    response = client.post(
        "/access/evaluate",
        json={
            "user_id": "UNKNOWN",
            "case_id": "CASE001",
            "purpose": "TREATMENT",
            "access_device": "WS001",
        },
    )
    assert response.status_code == 404


def test_access_log_created():
    result = evaluate(
        "DOC001", "CASE001", "TREATMENT", "WS001"
    )

    response = client.get("/access/history")
    assert response.status_code == 200

    log_ids = [item["id"] for item in response.json()]
    assert result["log_id"] in log_ids
