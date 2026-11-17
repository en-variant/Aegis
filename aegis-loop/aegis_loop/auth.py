import hashlib
import hmac
import os
import secrets
from typing import Any

from fastapi import HTTPException, Request, Response
from psycopg.errors import UniqueViolation

from aegis_loop import database

SESSION_COOKIE = "aegis_session"
PASSWORD_ITERATIONS = 600_000
SESSION_HOURS = 12


def _password_hash(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def issue_session(response: Response, user_id: str) -> None:
    token = secrets.token_urlsafe(32)
    database.create_session(_token_hash(token), user_id)
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_HOURS * 60 * 60,
        httponly=True,
        secure=os.environ.get("AEGIS_SECURE_COOKIES") == "1",
        samesite="strict",
        path="/",
    )


def register_user(email: str, password: str) -> dict[str, Any]:
    normalized_email = email.strip().casefold()
    if len(normalized_email) > 254 or normalized_email.count("@") != 1:
        raise HTTPException(status_code=422, detail="A valid email is required")
    if len(password) < 12:
        raise HTTPException(
            status_code=422,
            detail="Password must be at least 12 characters",
        )
    salt = secrets.token_bytes(16)
    try:
        return database.create_user(
            normalized_email,
            salt,
            _password_hash(password, salt),
        )
    except UniqueViolation as exc:
        raise HTTPException(
            status_code=409,
            detail="An account with this email already exists",
        ) from exc


def login_user(email: str, password: str) -> dict[str, Any]:
    user = database.get_user_by_email(email.strip().casefold())
    if user is None or not hmac.compare_digest(
        _password_hash(password, user["password_salt"]),
        user["password_hash"],
    ):
        raise HTTPException(status_code=401, detail="Email or password is incorrect")
    return user


def current_user(request: Request) -> dict[str, Any]:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(status_code=401, detail="Sign in to continue")
    user = database.get_session_user(_token_hash(token))
    if user is None:
        raise HTTPException(status_code=401, detail="Session expired; sign in again")
    return user


def logout(request: Request, response: Response) -> None:
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        database.delete_session(_token_hash(token))
    response.delete_cookie(
        SESSION_COOKIE,
        httponly=True,
        secure=os.environ.get("AEGIS_SECURE_COOKIES") == "1",
        samesite="strict",
        path="/",
    )
