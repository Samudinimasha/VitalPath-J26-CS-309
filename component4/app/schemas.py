
from typing import Literal

from pydantic import BaseModel, Field


class AccessRequest(BaseModel):
    user_id: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    purpose: Literal[
        "TREATMENT",
        "CONSULTATION",
        "EMERGENCY",
        "ADMINISTRATION",
    ]
    access_device: str = Field(min_length=1)


class AccessResponse(BaseModel):
    user_id: str
    case_id: str
    role: str
    case_assigned: bool
    risk_score: float
    decision: Literal[
        "ALLOW",
        "LIMITED_ACCESS",
        "DENY",
        "BREAK_GLASS_REQUIRED",
    ]
    reasons: list[str]
    log_id: int
