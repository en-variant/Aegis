from __future__ import annotations

import secrets
from pathlib import Path
from typing import Annotated, Any

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from agent.identity import AuthenticatedUser, authenticate_user
from agent.loop import run_agent

ROOT = Path(__file__).resolve().parent
SESSION_COOKIE = "victim_session"
SESSIONS: dict[str, AuthenticatedUser] = {}
LOCAL_ORIGINS = {"http://127.0.0.1:8002", "http://localhost:8002"}

app = FastAPI(title="Synthetic Finance Victim", version="0.1.0")
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["127.0.0.1", "localhost", "testserver"],
)
app.mount("/assets", StaticFiles(directory=ROOT / "web"), name="victim-assets")


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=32)
    password: str = Field(min_length=1, max_length=256, repr=False)


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)


def current_victim_user(request: Request) -> AuthenticatedUser:
    session_id = request.cookies.get(SESSION_COOKIE)
    user = SESSIONS.get(session_id or "")
    if user is None:
        raise HTTPException(status_code=401, detail="Sign in to the Victim app first")
    return user


CurrentVictimUser = Annotated[AuthenticatedUser, Depends(current_victim_user)]


@app.middleware("http")
async def require_local_browser_origin(request: Request, call_next):
    origin = request.headers.get("origin")
    if request.method in {"POST", "DELETE"} and origin and origin not in LOCAL_ORIGINS:
        return JSONResponse(
            status_code=403,
            content={"detail": "Local browser origin required"},
        )
    return await call_next(request)


@app.get("/")
def victim_dashboard() -> FileResponse:
    return FileResponse(ROOT / "web" / "index.html")


@app.post("/api/login")
def login(request: LoginRequest, response: Response) -> dict[str, str]:
    user = authenticate_user(request.username.strip(), request.password)
    if user is None:
        raise HTTPException(status_code=401, detail="Username or password is incorrect")
    session_id = secrets.token_urlsafe(32)
    SESSIONS[session_id] = user
    response.set_cookie(
        SESSION_COOKIE,
        session_id,
        httponly=True,
        secure=False,
        samesite="strict",
        path="/",
        max_age=12 * 60 * 60,
    )
    return {"id": user.user_id, "role": user.role}


@app.get("/api/me")
def who_am_i(user: CurrentVictimUser) -> dict[str, str]:
    return {"id": user.user_id, "role": user.role}


@app.post("/api/logout")
def logout(request: Request, response: Response) -> dict[str, str]:
    session_id = request.cookies.get(SESSION_COOKIE)
    if session_id:
        SESSIONS.pop(session_id, None)
    response.delete_cookie(
        SESSION_COOKIE,
        httponly=True,
        secure=False,
        samesite="strict",
        path="/",
    )
    return {"status": "signed_out"}


@app.post("/api/chat")
def chat(request: ChatRequest, user: CurrentVictimUser) -> dict[str, Any]:
    try:
        answer, tool_calls = run_agent(request.message, user=user)
    except (httpx.HTTPError, RuntimeError):
        raise HTTPException(
            status_code=502,
            detail=(
                "The local model or Aegis identity integration is unavailable. "
                "No unapproved tool action was run."
            ),
        ) from None
    return {"answer": answer, "tool_calls": tool_calls}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("victim_api:app", host="127.0.0.1", port=8002, reload=False)
