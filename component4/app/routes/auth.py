
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.schemas import LoginRequest, TokenResponse
from app.services.authentication import (
    authenticate_user,
    create_access_token,
    get_current_user,
)

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


@router.post("/login", response_model=TokenResponse)
def login(
    request: LoginRequest,
    db: Session = Depends(get_db),
):
    user = authenticate_user(
        db,
        request.user_id,
        request.password,
    )

    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
        )

    token = create_access_token(user.id)

    return TokenResponse(access_token=token)


@router.get("/me")
def current_user(
    user: User = Depends(get_current_user),
):
    return {
        "user_id": user.id,
        "name": user.name,
        "role": user.role,
        "on_shift": user.on_shift,
        "location": user.location,
        "registered_device": user.registered_device,
    }
