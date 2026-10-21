
from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import Base, engine, get_db, SessionLocal
from app.models import (
    User, EmergencyCase, CaseAssignment, AccessLog
)
from app.schemas import AccessRequest, AccessResponse
from app.services.risk_engine import calculate_ars
from app.services.policy_engine import evaluate_policy

app = FastAPI(
    title="VitalPath Component 4",
    description="Context-Aware Emergency Access Control Prototype",
    version="0.1.0",
)


def seed_database():
    """Create synthetic demonstration data once."""
    with SessionLocal() as db:
        if db.scalar(select(User.id).limit(1)) is not None:
            return

        db.add_all([
            User(
                id="DOC001", name="Demo Doctor",
                role="DOCTOR", on_shift=True,
                location="HOSPITAL",
                registered_device="WS001",
            ),
            User(
                id="NUR001", name="Demo Nurse",
                role="NURSE", on_shift=True,
                location="HOSPITAL",
                registered_device="WS002",
            ),
            User(
                id="SPC001", name="Demo Specialist",
                role="SPECIALIST", on_shift=True,
                location="HOSPITAL",
                registered_device="WS003",
            ),
            User(
                id="ADM001", name="Demo Administrator",
                role="ADMIN", on_shift=True,
                location="HOSPITAL",
                registered_device="WS004",
            ),
        ])

        db.add_all([
            EmergencyCase(
                id="CASE001", severity="HIGH", active=True
            ),
            EmergencyCase(
                id="CASE002", severity="CRITICAL", active=True
            ),
        ])

        db.add_all([
            CaseAssignment(
                user_id="DOC001", case_id="CASE001"
            ),
            CaseAssignment(
                user_id="NUR001", case_id="CASE001"
            ),
            CaseAssignment(
                user_id="SPC001", case_id="CASE001"
            ),
        ])

        db.commit()


Base.metadata.create_all(bind=engine)
seed_database()


@app.get("/")
def home():
    return {
        "system": "VitalPath Component 4",
        "status": "running",
        "version": "0.1.0",
    }


@app.post("/access/evaluate", response_model=AccessResponse)
def evaluate_access(
    request: AccessRequest,
    db: Session = Depends(get_db),
):
    user = db.get(User, request.user_id)
    if user is None:
        raise HTTPException(
            status_code=404, detail="Unknown user"
        )

    case = db.get(EmergencyCase, request.case_id)
    if case is None:
        raise HTTPException(
            status_code=404, detail="Unknown case"
        )

    assignment = db.scalar(
        select(CaseAssignment).where(
            CaseAssignment.user_id == user.id,
            CaseAssignment.case_id == case.id,
        )
    )
    assigned = assignment is not None

    score, factors = calculate_ars(
        user, case, assigned, request
    )

    decision, reasons = evaluate_policy(
        user, case, assigned, request, score
    )

    log = AccessLog(
        user_id=user.id,
        case_id=case.id,
        purpose=request.purpose,
        risk_score=score,
        decision=decision,
        reason="; ".join(reasons),
    )

    db.add(log)
    db.commit()
    db.refresh(log)

    return AccessResponse(
        user_id=user.id,
        case_id=case.id,
        role=user.role,
        case_assigned=assigned,
        risk_score=score,
        decision=decision,
        reasons=reasons,
        log_id=log.id,
    )


@app.get("/access/history")
def access_history(db: Session = Depends(get_db)):
    logs = db.scalars(
        select(AccessLog).order_by(AccessLog.id.desc())
    ).all()

    return [
        {
            "id": log.id,
            "user_id": log.user_id,
            "case_id": log.case_id,
            "purpose": log.purpose,
            "risk_score": log.risk_score,
            "decision": log.decision,
            "reason": log.reason,
            "created_at": log.created_at,
        }
        for log in logs
    ]
