"""Auth router (50_ §2.4): login -> short-lived JWT.

Human auth is OIDC/SAML SSO in production (SSO is the enterprise paywall);
local password login exists only for dev. Machine auth (GitHub App tokens, GUARD
SDK API keys) does NOT go through here — those authenticate per-request in
deps.get_principal.
"""

from __future__ import annotations

from fastapi import APIRouter

from control_plane.api.schemas import LoginRequest, TokenResponse

router = APIRouter(prefix="/v1/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest) -> TokenResponse:
    """Exchange credentials (dev) or an SSO assertion for a short-lived JWT.

    TODO(stage-1): dev path — verify argon2 password hash; SSO path — validate
    the IdP assertion and mint a short-lived JWT carrying (user_id, org_id, role).
    Write an `audit_log` "auth.login" row (50_ §2.2).
    """
    raise NotImplementedError("login not implemented (scaffold) — 50_ §2.4")


@router.post("/logout")
async def logout() -> dict:
    """TODO(stage-1): revoke the refresh token at the IdP; audit-log the event."""
    raise NotImplementedError("logout not implemented (scaffold)")
