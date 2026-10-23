
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, DateTime, Float, ForeignKey,
    Integer, String
)
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def utc_now():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String)
    role: Mapped[str] = mapped_column(String)
    on_shift: Mapped[bool] = mapped_column(Boolean)
    location: Mapped[str] = mapped_column(String)
    registered_device: Mapped[str] = mapped_column(String)


class EmergencyCase(Base):
    __tablename__ = "emergency_cases"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    severity: Mapped[str] = mapped_column(String)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class CaseAssignment(Base):
    __tablename__ = "case_assignments"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True
    )
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id")
    )
    case_id: Mapped[str] = mapped_column(
        ForeignKey("emergency_cases.id")
    )


class AccessLog(Base):
    __tablename__ = "access_logs"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True
    )
    user_id: Mapped[str] = mapped_column(String)
    case_id: Mapped[str] = mapped_column(String)
    purpose: Mapped[str] = mapped_column(String)
    risk_score: Mapped[float] = mapped_column(Float)
    decision: Mapped[str] = mapped_column(String)
    reason: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now
    )

class UserCredential(Base):
    __tablename__ = "user_credentials"

    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id"),
        primary_key=True,
    )
    password_hash: Mapped[str] = mapped_column(
        String, nullable=False
    )
    active: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )

class TelemetryRecord(Base):
    __tablename__ = "telemetry_records"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True
    )
    case_id: Mapped[str] = mapped_column(
        ForeignKey("emergency_cases.id"), nullable=False
    )
    device_id: Mapped[str] = mapped_column(String, nullable=False)
    sequence_number: Mapped[int] = mapped_column(Integer, nullable=False)
    heart_rate: Mapped[int] = mapped_column(Integer, nullable=False)
    spo2: Mapped[float] = mapped_column(Float, nullable=False)
    systolic_bp: Mapped[int] = mapped_column(Integer, nullable=False)
    diastolic_bp: Mapped[int] = mapped_column(Integer, nullable=False)
    respiratory_rate: Mapped[int] = mapped_column(Integer, nullable=False)
    c3_status: Mapped[str] = mapped_column(String, nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now
    )

