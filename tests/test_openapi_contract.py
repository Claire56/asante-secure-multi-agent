"""Regression tests for the public FastAPI/OpenAPI contract."""

from __future__ import annotations

from asante_secure_multi_agent.main import app


def _schema() -> dict[str, object]:
    return app.openapi()


def test_openapi_has_intentional_tags_and_description() -> None:
    schema = _schema()

    assert schema["info"]["title"] == "Asante Secure Multi-Agent Application"
    assert schema["info"]["version"] == "0.7.0"
    assert "Ruhusa" in schema["info"]["description"]
    assert "authorization-aware caching" in schema["info"]["description"].lower()

    tags = {item["name"] for item in schema["tags"]}
    assert tags == {"Service", "Identity", "Agents", "Demo / Diagnostics"}


def test_bearer_security_scheme_is_documented() -> None:
    schema = _schema()
    schemes = schema["components"]["securitySchemes"]

    bearer = next(value for value in schemes.values() if value.get("scheme") == "bearer")
    assert bearer["type"] == "http"


def test_agent_run_has_typed_response_and_auth_error() -> None:
    operation = _schema()["paths"]["/agent/run"]["post"]

    success = operation["responses"]["200"]["content"]["application/json"]["schema"]
    assert success["$ref"].endswith("/AgentRunResponse")
    assert "401" in operation["responses"]
    assert operation["tags"] == ["Agents"]


def test_reservation_docs_expose_domain_outcomes_without_authority_fields() -> None:
    schema = _schema()
    operation = schema["paths"]["/demo/reservations/{reservation_id}"]["get"]
    response = operation["responses"]["200"]["content"]["application/json"]["schema"]

    assert "anyOf" in response
    refs = {item["$ref"].rsplit("/", 1)[-1] for item in response["anyOf"]}
    assert refs == {
        "ReservationFoundResponse",
        "ReservationNotFoundResponse",
        "ReservationBlockedResponse",
    }

    run_request = schema["components"]["schemas"]["RunRequest"]["properties"]
    demo_credit = schema["components"]["schemas"]["DemoCreditRequest"]["properties"]
    assert "operator_id" not in run_request
    assert "operator_id" not in demo_credit
    assert "principal_id" not in run_request
    assert "grant_id" not in run_request


def test_service_metadata_documents_redoc_discovery() -> None:
    response = _schema()["components"]["schemas"]["ServiceInfoResponse"]["properties"]

    assert "docs" in response
    assert "redoc" in response
    assert "mcp" in response
