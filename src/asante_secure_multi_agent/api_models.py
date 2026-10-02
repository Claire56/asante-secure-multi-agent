"""Operator-facing API contracts.

Identity is intentionally absent from request bodies. The human principal is derived
exclusively from the authenticated Bearer access token at the HTTP boundary.

These models also make the generated OpenAPI/ReDoc surface explicit. The application
returns security outcomes as business-domain responses (for example ``blocked``) while
HTTP 401 remains reserved for authentication failures.
"""

from typing import Literal

from pydantic import BaseModel, Field


class RunRequest(BaseModel):
    """Natural-language operator request for the multi-agent runtime."""

    message: str = Field(
        min_length=1,
        description="Natural-language request for the supervisor agent, e.g. a "
        "reservation lookup or a service-recovery credit.",
    )


class DemoCreditRequest(BaseModel):
    """Direct business arguments for the Ruhusa diagnostic control path."""

    reservation_id: str = Field(
        min_length=1,
        description="Reservation to credit, e.g. R-3001, R-3002, or R-3003.",
    )
    amount: float = Field(
        gt=0,
        description="Credit amount in USD. Guest support is delegated up to $25; "
        "larger amounts are denied by Ruhusa.",
    )
    reason: str = Field(min_length=1, description="Service-recovery reason for the credit.")


class ErrorResponse(BaseModel):
    """Standard FastAPI error body used for documented authentication failures."""

    detail: str = Field(examples=["Bearer access token required"])


class ServiceInfoResponse(BaseModel):
    """Public service metadata and discovery links."""

    name: str
    phase: int
    status: Literal["running"]
    docs: str
    redoc: str
    health: str
    whoami: str
    mcp: str
    auth: str
    workload_identity: str
    observability: str
    release_gate: str
    caching: str
    otel_exporter: str


class HealthResponse(BaseModel):
    """Liveness status."""

    status: Literal["ok"]


class WhoAmIResponse(BaseModel):
    """Canonical human identity derived from the validated access token."""

    principal_id: str = Field(
        description="Collision-resistant principal derived from validated issuer + subject.",
        examples=["oauth:https://dev.asante.local#claire"],
    )
    subject: str = Field(examples=["claire"])
    issuer: str = Field(examples=["https://dev.asante.local"])
    audiences: list[str] = Field(examples=[["asante-secure-multi-agent"]])
    client_id: str = Field(examples=["asante-local-cli"])
    scopes: list[str] = Field(examples=[["asante:operate"]])
    trace_id: str = Field(
        description="OpenTelemetry trace identifier for request correlation.",
        examples=["4fed3c7e83ab990b624a33ffb153aba9"],
    )


class AgentRunResponse(BaseModel):
    """Completed multi-agent workflow result."""

    task_id: str = Field(description="Trusted task identifier bound to delegated authority.")
    trace_id: str = Field(description="OpenTelemetry trace identifier for correlation.")
    initiated_by: str = Field(
        description="Canonical authenticated human principal that initiated the task."
    )
    last_agent: str = Field(
        description="Agent that produced the final response.",
        examples=["Asante Guest Support Agent"],
    )
    output: str = Field(description="Final natural-language agent response.")


class CreditRecord(BaseModel):
    """One credit persisted in the in-memory demonstration ledger."""

    reservation_id: str
    amount: float
    reason: str
    status: Literal["issued"]


class CreditIssuedResponse(BaseModel):
    """Authorized guest-credit action that reached the protected side effect."""

    task_id: str
    trace_id: str
    initiated_by: str
    reservation_id: str
    amount: float
    reason: str
    status: Literal["issued"]
    deduplicated: bool = Field(
        description="True when provider-side idempotency returned an existing result."
    )
    effect: Literal["allow"]
    policy_id: str | None = Field(
        default=None,
        examples=["guest-support-small-credit"],
    )


class CreditBlockedResponse(BaseModel):
    """Credit request stopped by delegated authority or policy before side effect."""

    task_id: str
    trace_id: str
    initiated_by: str
    status: Literal["blocked"]
    effect: Literal["deny", "require_approval"]
    reason: str


class ReservationRecord(BaseModel):
    """Protected reservation representation returned after live authorization."""

    reservation_id: str = Field(examples=["R-3001"])
    guest_name: str = Field(examples=["Amina N."])
    property: str = Field(examples=["Bandini"])
    status: str = Field(examples=["confirmed"])
    check_in: str = Field(examples=["2026-10-02"])
    check_out: str = Field(examples=["2026-10-05"])


class ReservationFoundResponse(BaseModel):
    """Authorized reservation read that returned protected data."""

    task_id: str
    trace_id: str
    initiated_by: str
    status: Literal["found"]
    effect: Literal["allow"]
    policy_id: str | None = None
    cache: Literal["hit", "miss"]
    reservation: ReservationRecord


class ReservationNotFoundResponse(BaseModel):
    """Authorized reservation read for a resource the provider did not contain."""

    task_id: str
    trace_id: str
    initiated_by: str
    status: Literal["not_found"]
    effect: Literal["allow"]
    policy_id: str | None = None
    cache: Literal["miss"]


class ReservationBlockedResponse(BaseModel):
    """Reservation disclosure blocked before the cache or provider was consulted."""

    task_id: str
    trace_id: str
    initiated_by: str
    status: Literal["blocked"]
    effect: Literal["deny", "require_approval"]
    reason: str
