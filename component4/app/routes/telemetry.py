
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import (
    AccessLog,
    CaseAssignment,
    EmergencyCase,
    TelemetryRecord,
    User,
)
from app.schemas import AccessRequest, TelemetryResponse
from app.services.authentication import get_current_user
from app.services.policy_engine import evaluate_policy
from app.services.risk_engine import calculate_ars

router = APIRouter(prefix="/telemetry", tags=["Telemetry"])


@router.get(
    "/cases/{case_id}",
    response_model=list[TelemetryResponse],
)
def get_case_telemetry(
    case_id: str,
    access_device: str = Query(min_length=1),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    case = db.get(EmergencyCase, case_id)

    if case is None:
        raise HTTPException(
            status_code=404,
            detail="Unknown emergency case",
        )

    assignment = db.scalar(
        select(CaseAssignment).where(
            CaseAssignment.user_id == user.id,
            CaseAssignment.case_id == case.id,
        )
    )

    assigned = assignment is not None

    request = AccessRequest(
        case_id=case_id,
        purpose="TREATMENT",
        access_device=access_device,
    )

    score, factors = calculate_ars(
        user, case, assigned, request
    )

    decision, reasons = evaluate_policy(
        user, case, assigned, request, score
    )

    log = AccessLog(
        user_id=user.id,
        case_id=case.id,
        purpose="TREATMENT",
        risk_score=score,
        decision=decision,
        reason="; ".join(reasons),
    )

    db.add(log)
    db.commit()

    if decision != "ALLOW":
        raise HTTPException(
            status_code=403,
            detail={
                "decision": decision,
                "reasons": reasons,
            },
        )

    records = db.scalars(
        select(TelemetryRecord)
        .where(TelemetryRecord.case_id == case.id)
        .where(TelemetryRecord.c3_status.in_(
            ["ACCEPT", "FLAG"]
        ))
        .order_by(TelemetryRecord.id.desc())
        .limit(100)
    ).all()

    return records
