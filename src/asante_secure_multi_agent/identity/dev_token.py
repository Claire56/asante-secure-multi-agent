"""Generate a local OAuth-style JWT access token for Phase 4 testing.

Usage:
    uv run python -m asante_secure_multi_agent.identity.dev_token claire
"""

from __future__ import annotations

import argparse
import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt

from .human import (
    DEFAULT_AUDIENCE,
    DEFAULT_DEV_ISSUER,
    DEFAULT_DEV_JWT_SECRET,
)


def create_dev_access_token(
    subject: str,
    *,
    lifetime_minutes: int = 30,
    client_id: str = "asante-local-cli",
    scope: str = "asante:operate",
    issuer: str | None = None,
    audience: str | None = None,
    secret: str | None = None,
) -> str:
    """Create a signed development access token with RFC 9068-style claims."""
    if not subject:
        raise ValueError("subject is required")
    now = datetime.now(UTC)
    issuer_value = issuer or os.getenv("ASANTE_AUTH_ISSUER", DEFAULT_DEV_ISSUER)
    audience_value = audience or os.getenv("ASANTE_AUTH_AUDIENCE", DEFAULT_AUDIENCE)
    secret_value = secret or os.getenv("ASANTE_DEV_JWT_SECRET", DEFAULT_DEV_JWT_SECRET)
    claims = {
        "iss": issuer_value,
        "sub": subject,
        "aud": audience_value,
        "exp": now + timedelta(minutes=lifetime_minutes),
        "iat": now,
        "jti": uuid4().hex,
        "client_id": client_id,
        "scope": scope,
    }
    return jwt.encode(
        claims,
        secret_value,
        algorithm="HS256",
        headers={"typ": "at+jwt"},
    )


def main() -> None:
    """CLI entrypoint for minting a local token outside the API service."""
    parser = argparse.ArgumentParser(description="Create a local Asante Phase 4 access token")
    parser.add_argument("subject", help="human subject, for example claire")
    parser.add_argument("--minutes", type=int, default=30, help="token lifetime")
    args = parser.parse_args()
    print(create_dev_access_token(args.subject, lifetime_minutes=args.minutes))


if __name__ == "__main__":
    main()
