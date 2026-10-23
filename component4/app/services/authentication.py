
import os
from datetime import datetime, timedelta, timezone

import jwt
from dotenv import load_dotenv
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import InvalidTokenError
from pwdlib import PasswordHash
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, UserCredential

load_dotenv()

SECRET_KEY = os.getenv("VITALPATH_JWT_SECRET")
ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 30

password_hasher = PasswordHash.recommended()
bearer_scheme = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(
    plain_password: str,
    stored_hash: str,
) -> bool:
    return password_hasher.verify(
        plain_password, stored_hash
    )


def authenticate_user(
    db: Session,
    user_id: str,
    password: str,
):
    credential = db.get(UserCredential, user_id)

    if credential is None or not credential.active:
        return None

    if not verify_password(
        password, credential.password_hash
    ):
        return None

    return db.get(User, user_id)


def create_access_token(user_id: str) -> str:
    if not SECRET_KEY:
        raise RuntimeError(
            "VITALPATH_JWT_SECRET is not configured"
        )

    now = datetime.now(timezone.utc)

    payload = {
        "sub": user_id,
        "iat": now,
        "exp": now + timedelta(
            minutes=TOKEN_EXPIRE_MINUTES
        ),
        "iss": "vitalpath-c4",
    }

    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = (
        Depends(bearer_scheme)
    ),
    db: Session = Depends(get_db),
) -> User:

    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing authentication",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if credentials is None:
        raise unauthorized

    if not SECRET_KEY:
        raise HTTPException(
            status_code=503,
            detail="Authentication not configured",
        )

    try:
        payload = jwt.decode(
            credentials.credentials,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            issuer="vitalpath-c4",
            options={"require": ["sub", "iat", "exp", "iss"]},
        )
        user_id = payload.get("sub")

        if not isinstance(user_id, str):
            raise unauthorized

    except InvalidTokenError:
        raise unauthorized

    credential = db.get(UserCredential, user_id)
    user = db.get(User, user_id)

    if (
        user is None
        or credential is None
        or not credential.active
    ):
        raise unauthorized

    return user
