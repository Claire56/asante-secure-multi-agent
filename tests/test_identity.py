"""Phase 4 tests for authenticated human and trusted workload identity."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
import pytest
from jwt import InvalidTokenError

from asante_secure_multi_agent.api_models import DemoCreditRequest, RunRequest
from asante_secure_multi_agent.identity import (
    GUEST_SUPPORT_WORKLOAD,
    SUPERVISOR_WORKLOAD,
    DevHmacAccessTokenVerifier,
    StaticSpiffeWorkloadIdentityProvider,
)
from asante_secure_multi_agent.identity.dev_token import create_dev_access_token


def test_valid_access_token_derives_canonical_human_principal() -> None:
    """The API root identity comes from verified iss/sub, not a request field."""
    token = create_dev_access_token(
        "claire",
        issuer="https://dev.asante.local",
        audience="asante-secure-multi-agent",
        secret="asante-local-development-only-change-me",
    )
    human = DevHmacAccessTokenVerifier().verify(token)

    assert human.subject == "claire"
    assert human.issuer == "https://dev.asante.local"
    assert human.principal_id == "oauth:https://dev.asante.local#claire"
    assert "asante-secure-multi-agent" in human.audiences


def test_access_token_with_wrong_audience_is_rejected() -> None:
    """A token for another API cannot establish Asante operator identity."""
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "iss": "https://dev.asante.local",
            "sub": "claire",
            "aud": "some-other-api",
            "exp": now + timedelta(minutes=5),
            "iat": now,
            "jti": uuid4().hex,
            "client_id": "test-client",
        },
        "asante-local-development-only-change-me",
        algorithm="HS256",
        headers={"typ": "at+jwt"},
    )

    with pytest.raises(InvalidTokenError):
        DevHmacAccessTokenVerifier().verify(token)


def test_id_token_or_ambiguous_jwt_type_is_rejected() -> None:
    """The resource server must not accept an ID token as an API access token."""
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "iss": "https://dev.asante.local",
            "sub": "claire",
            "aud": "asante-secure-multi-agent",
            "exp": now + timedelta(minutes=5),
            "iat": now,
            "jti": uuid4().hex,
            "client_id": "test-client",
        },
        "asante-local-development-only-change-me",
        algorithm="HS256",
        headers={"typ": "JWT"},
    )

    with pytest.raises(InvalidTokenError):
        DevHmacAccessTokenVerifier().verify(token)


def test_operator_identity_is_not_model_or_request_body_input() -> None:
    """Phase 4 removes operator_id from both operator-facing request schemas."""
    run_properties = RunRequest.model_json_schema()["properties"]
    demo_properties = DemoCreditRequest.model_json_schema()["properties"]

    assert set(run_properties) == {"message"}
    assert set(demo_properties) == {"reservation_id", "amount", "reason"}
    assert "operator_id" not in run_properties
    assert "operator_id" not in demo_properties


def test_workload_provider_assigns_distinct_spiffe_ids() -> None:
    """Trusted runtime identities are SPIFFE names rather than model labels."""
    provider = StaticSpiffeWorkloadIdentityProvider("asante.jamiiz.io")
    supervisor = provider.require(SUPERVISOR_WORKLOAD)
    guest_support = provider.require(GUEST_SUPPORT_WORKLOAD)

    assert supervisor.principal_id == "spiffe://asante.jamiiz.io/agents/supervisor"
    assert guest_support.principal_id == "spiffe://asante.jamiiz.io/agents/guest-support"
    assert supervisor.principal_id != guest_support.principal_id


def test_authenticated_human_becomes_delegation_root() -> None:
    """The verified human identity is preserved as the root grantor."""
    from ruhusa import TaskContext

    from asante_secure_multi_agent.security import (
        build_security_runtime,
        issue_guest_support_delegation,
    )

    human = DevHmacAccessTokenVerifier().verify(
        create_dev_access_token(
            "claire",
            issuer="https://dev.asante.local",
            audience="asante-secure-multi-agent",
            secret="asante-local-development-only-change-me",
        )
    )
    security = build_security_runtime()
    task = TaskContext(
        task_id=f"task-identity-{uuid4().hex}",
        initiated_by=human.principal_id,
        purpose="guest service recovery",
        expires_at=datetime.now(UTC) + timedelta(minutes=30),
    )

    root, child = issue_guest_support_delegation(security, task)

    assert root.grantor_id == human.principal_id
    assert root.grantee_id.startswith("spiffe://")
    assert child.grantor_id == root.grantee_id
    assert child.grantee_id.startswith("spiffe://")


def test_missing_bearer_credentials_are_rejected() -> None:
    """Operator-facing endpoints must not fall back to anonymous identity."""
    from fastapi import HTTPException

    from asante_secure_multi_agent.identity.human import require_authenticated_human

    with pytest.raises(HTTPException) as exc_info:
        require_authenticated_human(None)

    assert exc_info.value.status_code == 401


def test_bearer_credentials_resolve_authenticated_human(monkeypatch) -> None:
    """A valid Bearer token is converted into the canonical human principal."""
    from fastapi.security import HTTPAuthorizationCredentials

    from asante_secure_multi_agent.identity.human import (
        get_access_token_verifier,
        require_authenticated_human,
    )

    monkeypatch.setenv("ASANTE_AUTH_MODE", "dev")
    monkeypatch.setenv("ASANTE_AUTH_ISSUER", "https://dev.asante.local")
    monkeypatch.setenv("ASANTE_AUTH_AUDIENCE", "asante-secure-multi-agent")
    monkeypatch.setenv(
        "ASANTE_DEV_JWT_SECRET",
        "asante-local-development-only-change-me",
    )
    get_access_token_verifier.cache_clear()
    token = create_dev_access_token(
        "claire",
        issuer="https://dev.asante.local",
        audience="asante-secure-multi-agent",
        secret="asante-local-development-only-change-me",
    )
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    human = require_authenticated_human(credentials)

    assert human.principal_id == "oauth:https://dev.asante.local#claire"
    get_access_token_verifier.cache_clear()
