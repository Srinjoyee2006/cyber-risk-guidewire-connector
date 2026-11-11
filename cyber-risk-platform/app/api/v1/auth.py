"""
CyberRisk-Guidewire-Connector (CRGC)
Authentication API Endpoints
Provides OAuth2/JWT token issuance and current user inspection.
"""

import logging
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field

from config.settings import Settings, get_settings
from app.core.security import (
    authenticate_user,
    create_access_token,
    get_current_user,
    UserProfile,
)

logger = logging.getLogger("crgc.api.auth")

router = APIRouter(prefix="/auth", tags=["Authentication & Access Control"])


class LoginRequest(BaseModel):
    username: str = Field(..., description="User login identifier")
    password: str = Field(..., description="Plaintext password")


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserProfile


def _issue_token_response(username: str, password: str, settings: Settings) -> TokenResponse:
    user = authenticate_user(username, password, settings=settings)
    if not user:
        logger.warning("Failed login attempt for username '%s'", username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(
        data={
            "sub": user.username,
            "role": user.role,
            "full_name": user.full_name,
        },
        settings=settings,
    )
    logger.info("Successfully authenticated user '%s' (%s)", user.username, user.role)
    return TokenResponse(access_token=token, user=user)


@router.post(
    "/token",
    response_model=TokenResponse,
    summary="OAuth2 Password Flow Token Endpoint",
    description="Authenticates form-encoded OAuth2 credentials and returns a signed HMAC-SHA256 JWT access token.",
)
async def login_oauth2_form(
    form_data: OAuth2PasswordRequestForm = Depends(),
    settings: Settings = Depends(get_settings),
) -> TokenResponse:
    return _issue_token_response(form_data.username, form_data.password, settings)


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="JSON Login Endpoint",
    description="Authenticates JSON credentials and returns a signed HMAC-SHA256 JWT access token.",
)
async def login_json(
    payload: LoginRequest,
    settings: Settings = Depends(get_settings),
) -> TokenResponse:
    return _issue_token_response(payload.username, payload.password, settings)


@router.get(
    "/me",
    response_model=UserProfile,
    summary="Get Authenticated User Profile",
    description="Returns the profile and role of the currently authenticated user.",
)
async def get_my_profile(
    current_user: UserProfile = Depends(get_current_user),
) -> UserProfile:
    return current_user
