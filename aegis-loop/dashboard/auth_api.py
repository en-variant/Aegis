from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field

from aegis_loop import auth

router = APIRouter(prefix="/api/auth", tags=["authentication"])
CurrentUser = Annotated[dict[str, Any], Depends(auth.current_user)]


class Credentials(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=1024)


def _public_user(user: dict[str, Any]) -> dict[str, str]:
    return {"id": str(user["id"]), "email": user["email"]}


@router.post("/register")
def register(credentials: Credentials, response: Response) -> dict[str, str]:
    user = auth.register_user(credentials.email, credentials.password)
    auth.issue_session(response, str(user["id"]))
    return _public_user(user)


@router.post("/login")
def login(credentials: Credentials, response: Response) -> dict[str, str]:
    user = auth.login_user(credentials.email, credentials.password)
    auth.issue_session(response, str(user["id"]))
    return _public_user(user)


@router.post("/logout")
def logout(request: Request, response: Response) -> dict[str, str]:
    auth.logout(request, response)
    return {"status": "signed out"}


@router.get("/me")
def me(user: CurrentUser) -> dict[str, str]:
    return _public_user(user)
