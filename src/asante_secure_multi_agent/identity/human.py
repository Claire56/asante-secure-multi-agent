"""Human authentication for the Asante operator-facing HTTP boundary.

Phase 4 removes caller-supplied operator IDs from request bodies. FastAPI now
accepts OAuth-style Bearer access tokens, validates them, and derives the human
principal from verified token claims. Ruhusa receives only that trusted
principal identifier as the root of the delegation chain.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Annotated, Protocol

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import InvalidTokenError, PyJWKClient
from jwt.exceptions import PyJWTError

DEFAULT_AUTH_MODE = "dev"
DEFAULT_DEV_ISSUER = "https://dev.asante.local"
DEFAULT_AUDIENCE = "asante-secure-multi-agent"
# Local learning only. Production/JWKS mode never uses this shared secret.
DEFAULT_DEV_JWT_SECRET = "asante-local-development-only-change-me"

_REQUIRED_ACCESS_TOKEN_CLAIMS = (
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "jti",
    "client_id",
)


@dataclass(frozen=True)
class AuthenticatedHuman:
    """Canonical human identity derived from a validated access token."""

    principal_id: str
    subject: str
    issuer: str
    audiences: tuple[str, ...]
    client_id: str
    scopes: frozenset[str]


class AccessTokenVerifier(Protocol):
    """Boundary implemented by local-dev and external-JWKS token verifiers."""

    def verify(self, token: str) -> AuthenticatedHuman:
        """Validate ``token`` and return canonical authenticated identity."""


def _audiences(value: object) -> tuple[str, ...]:
    """Normalize a validated JWT ``aud`` claim into an immutable tuple."""
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return tuple(value)
    raise InvalidTokenError("invalid aud claim")


def _scopes(value: object) -> frozenset[str]:
    """Normalize the optional OAuth scope claim."""
    if value is None:
        return frozenset()
    if isinstance(value, str):
        return frozenset(item for item in value.split() if item)
    raise InvalidTokenError("invalid scope claim")


def _authenticated_human(claims: dict[str, object]) -> AuthenticatedHuman:
    """Build a collision-resistant principal from the validated iss/sub pair."""
    issuer = claims["iss"]
    subject = claims["sub"]
    client_id = claims["client_id"]
    if not isinstance(issuer, str) or not issuer:
        raise InvalidTokenError("invalid iss claim")
    if not isinstance(subject, str) or not subject:
        raise InvalidTokenError("invalid sub claim")
    if not isinstance(client_id, str) or not client_id:
        raise InvalidTokenError("invalid client_id claim")

    return AuthenticatedHuman(
        principal_id=f"oauth:{issuer}#{subject}",
        subject=subject,
        issuer=issuer,
        audiences=_audiences(claims["aud"]),
        client_id=client_id,
        scopes=_scopes(claims.get("scope")),
    )


def _require_access_token_type(token: str) -> None:
    """Reject ID tokens or ambiguous JWTs at the resource-server boundary."""
    header = jwt.get_unverified_header(token)
    token_type = header.get("typ")
    if token_type not in {"at+jwt", "application/at+jwt"}:
        raise InvalidTokenError("expected OAuth access-token JWT type at+jwt")


@dataclass(frozen=True)
class DevHmacAccessTokenVerifier:
    """HS256 verifier used only for local development and deterministic tests."""

    secret: str = DEFAULT_DEV_JWT_SECRET
    issuer: str = DEFAULT_DEV_ISSUER
    audience: str = DEFAULT_AUDIENCE

    def verify(self, token: str) -> AuthenticatedHuman:
        """Verify signature, issuer, audience, lifetime, and required claims."""
        _require_access_token_type(token)
        claims = jwt.decode(
            token,
            self.secret,
            algorithms=["HS256"],
            issuer=self.issuer,
            audience=self.audience,
            options={"require": list(_REQUIRED_ACCESS_TOKEN_CLAIMS)},
        )
        return _authenticated_human(claims)


class JwksAccessTokenVerifier:
    """Validate asymmetric JWT access tokens against an external JWKS endpoint.

    This is suitable for an OIDC/OAuth authorization server such as Entra ID,
    Auth0, Okta, or another provider once issuer/audience/JWKS configuration is
    supplied. The application validates access tokens as a resource server; it
    does not accept an ID token as authorization for API calls.
    """

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks_url: str,
        algorithms: tuple[str, ...] = ("RS256",),
    ) -> None:
        self.issuer = issuer
        self.audience = audience
        self.algorithms = algorithms
        self._jwks_client = PyJWKClient(jwks_url)

    def verify(self, token: str) -> AuthenticatedHuman:
        """Resolve the signing key from JWKS and validate the access token."""
        _require_access_token_type(token)
        signing_key = self._jwks_client.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=list(self.algorithms),
            issuer=self.issuer,
            audience=self.audience,
            options={"require": list(_REQUIRED_ACCESS_TOKEN_CLAIMS)},
        )
        return _authenticated_human(claims)


def build_access_token_verifier() -> AccessTokenVerifier:
    """Build the configured resource-server verifier.

    ``ASANTE_AUTH_MODE=dev`` uses a local HS256 token only for learning and
    testing. ``ASANTE_AUTH_MODE=jwks`` validates externally issued asymmetric
    access tokens and requires explicit issuer/audience/JWKS settings.
    """
    mode = os.getenv("ASANTE_AUTH_MODE", DEFAULT_AUTH_MODE).strip().lower()
    if mode == "dev":
        return DevHmacAccessTokenVerifier(
            secret=os.getenv("ASANTE_DEV_JWT_SECRET", DEFAULT_DEV_JWT_SECRET),
            issuer=os.getenv("ASANTE_AUTH_ISSUER", DEFAULT_DEV_ISSUER),
            audience=os.getenv("ASANTE_AUTH_AUDIENCE", DEFAULT_AUDIENCE),
        )
    if mode == "jwks":
        issuer = os.getenv("ASANTE_AUTH_ISSUER")
        audience = os.getenv("ASANTE_AUTH_AUDIENCE")
        jwks_url = os.getenv("ASANTE_AUTH_JWKS_URL")
        missing = [
            name
            for name, value in (
                ("ASANTE_AUTH_ISSUER", issuer),
                ("ASANTE_AUTH_AUDIENCE", audience),
                ("ASANTE_AUTH_JWKS_URL", jwks_url),
            )
            if not value
        ]
        if missing:
            raise RuntimeError(f"JWKS auth mode requires: {', '.join(missing)}")
        algorithms = tuple(
            item.strip()
            for item in os.getenv("ASANTE_AUTH_ALGORITHMS", "RS256").split(",")
            if item.strip()
        )
        if not algorithms:
            raise RuntimeError("ASANTE_AUTH_ALGORITHMS must contain at least one algorithm")
        return JwksAccessTokenVerifier(
            issuer=issuer,
            audience=audience,
            jwks_url=jwks_url,
            algorithms=algorithms,
        )
    raise RuntimeError("ASANTE_AUTH_MODE must be 'dev' or 'jwks'")


@lru_cache(maxsize=1)
def get_access_token_verifier() -> AccessTokenVerifier:
    """Return one process-local verifier so JWKS clients can reuse key caches."""
    return build_access_token_verifier()


_bearer = HTTPBearer(auto_error=False)
BearerCredentials = Annotated[
    HTTPAuthorizationCredentials | None,
    Depends(_bearer),
]


def require_authenticated_human(
    credentials: BearerCredentials,
) -> AuthenticatedHuman:
    """FastAPI dependency that authenticates the human initiating the task."""
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer access token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        return get_access_token_verifier().verify(credentials.credentials)
    except PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
