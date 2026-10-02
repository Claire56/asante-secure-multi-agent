"""HTTP entrypoint for the Asante secure property-operations application.

Phase 9 introduces manager-style least-privilege specialist agents. The Operations
Supervisor remains responsible for the final answer and invokes Reservations, Property
Operations, Guest Support, and Service Recovery as bounded agent tools. Each specialist
has its own SPIFFE identity, filtered MCP tool surface, delegated scope, and Ruhusa policy.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import uuid4

from agents import Runner
from agents.tracing import add_trace_processor
from fastapi import Body, Depends, FastAPI, HTTPException, Path
from opentelemetry.trace import Status, StatusCode
from ruhusa import TaskContext

from asante_secure_multi_agent.agents import (
    build_guest_support_agent,
    build_property_operations_agent,
    build_reservations_agent,
    build_service_recovery_agent,
    build_supervisor_agent,
)
from asante_secure_multi_agent.api_models import (
    AgentRunResponse,
    ApprovalDecisionRequest,
    ApprovalExecutionResponse,
    ApprovalRecordResponse,
    CreditBlockedResponse,
    CreditIssuedResponse,
    CreditRecord,
    DemoCreditRequest,
    ErrorResponse,
    GuestMessageRecord,
    HealthResponse,
    ReservationBlockedResponse,
    ReservationFoundResponse,
    ReservationNotFoundResponse,
    RunRequest,
    ServiceInfoResponse,
    WhoAmIResponse,
    WorkOrderRecord,
)
from asante_secure_multi_agent.approvals import ApprovalStateError, SQLiteApprovalStore
from asante_secure_multi_agent.cache import InMemoryCacheStore
from asante_secure_multi_agent.context import AsanteRunContext
from asante_secure_multi_agent.identity import AuthenticatedHuman, require_authenticated_human
from asante_secure_multi_agent.mcp import (
    TrustedTaskRegistry,
    build_guest_operations_mcp_server,
    build_guest_support_mcp_client,
    build_property_operations_mcp_client,
    build_reservations_mcp_client,
    build_service_recovery_mcp_client,
)
from asante_secure_multi_agent.openapi_examples import (
    AGENT_RUN_REQUEST_EXAMPLES,
    AGENT_RUN_RESPONSES,
    APPROVAL_DECISION_EXAMPLES,
    DEMO_CREDIT_REQUEST_EXAMPLES,
    DEMO_CREDIT_RESPONSES,
    DEMO_RESERVATION_RESPONSES,
    RESERVATION_ID_EXAMPLES,
    UNAUTHORIZED_RESPONSE,
)
from asante_secure_multi_agent.reliability import credit_retry_policy_from_env
from asante_secure_multi_agent.security import (
    build_security_runtime,
    issue_approval_executor_delegation,
    issue_guest_support_message_delegation,
    issue_property_operations_delegation,
    issue_reservations_delegation,
    issue_service_recovery_credit_request_delegation,
    issue_service_recovery_delegation,
)
from asante_secure_multi_agent.telemetry import (
    OpenAIAgentsOpenTelemetryProcessor,
    configure_telemetry,
    current_trace_id,
    get_tracer,
    instrument_fastapi,
)
from asante_secure_multi_agent.tools import (
    ApprovedCreditExecutor,
    GuestCreditLedger,
    GuestMessageOutbox,
    InMemoryReservationProvider,
    MaintenanceWorkOrderStore,
    SecuredGuestCreditTool,
    SecuredGuestOperationsTool,
    SecuredReservationTool,
)

APP_DESCRIPTION = """
Asante Secure Multi-Agent is the secure property-operations backend for **Asante Stays**.
It combines authenticated human operators with a manager-style Operations Supervisor and four
least-privilege specialist agents.

The API demonstrates a complete trust chain:

1. **Human authentication** with OAuth-style Bearer access tokens.
2. **Distinct workload identity** using trusted SPIFFE IDs for Supervisor, Reservations,
   Property Operations, Guest Support, Service Recovery, and the Approval Executor.
3. **Task-bound delegated authority** enforced by Ruhusa per specialist capability.
4. **Filtered MCP tool surfaces** so each specialist sees only its own business tools.
5. **Server-side workload checks + Ruhusa policy** so prompt roles are never the security boundary.
6. **Execution fencing and live revalidation** before protected side effects or disclosure.
7. **OpenTelemetry** traces and security/reliability metrics.
8. **Bounded retry + idempotency** for protected credit writes.
9. **Authorization-aware caching** where every cache hit is preceded by fresh authorization.
10. **Durable human approval** for larger credits, executed by a separate trusted workload.
11. **Deterministic release gates** for attack, reliability, disclosure, and
    specialist-boundary regressions.

### Least-privilege specialists

* **Reservations** may read protected reservation data.
* **Property Operations** may create maintenance work orders.
* **Guest Support** may send operational guest messages.
* **Service Recovery** may issue small credits or request human approval.

The Supervisor coordinates these specialists as bounded agent tools and owns the final response,
but it does not inherit their business capabilities. A specialist result also does not become
authority for another specialist.

### Approval separation of duties

Service Recovery may *request* a service-recovery credit above $25 (up to $100), but it cannot
approve that request. Approval decisions require an authenticated human token containing
`asante:approve`; execution then runs through a separate trusted workload and distinct Ruhusa
action.

### Security semantics

Ruhusa denials are represented as domain responses such as `status=blocked`; they are not HTTP
authentication errors. HTTP `401` is reserved for missing, invalid, or expired Bearer credentials.
Approval endpoints additionally return `403` (missing `asante:approve`), `404` (unknown approval),
and `409` (invalid state transition).

> A cache hit may save an external reservation read, but it may never save the authorization check.
"""

OPENAPI_TAGS = [
    {
        "name": "Service",
        "description": "Service discovery and liveness endpoints.",
    },
    {
        "name": "Identity",
        "description": "Inspect the canonical human identity derived from a validated token.",
    },
    {
        "name": "Agents",
        "description": "Run the authenticated multi-agent workflow through MCP and Ruhusa.",
    },
    {
        "name": "Operations",
        "description": "Maintenance work orders, guest messages, and the human approval inbox.",
    },
    {
        "name": "Demo / Diagnostics",
        "description": (
            "Direct authenticated control paths for exercising Ruhusa, reliability, and cache "
            "behavior without relying on model orchestration."
        ),
    },
]

APPROVAL_RESPONSES = {
    **UNAUTHORIZED_RESPONSE,
    403: {"model": ErrorResponse, "description": "asante:approve scope is required."},
    404: {"model": ErrorResponse, "description": "Approval request was not found."},
    409: {"model": ErrorResponse, "description": "Approval state transition is invalid."},
}

telemetry = configure_telemetry()
tracer = get_tracer()
add_trace_processor(OpenAIAgentsOpenTelemetryProcessor(tracer))

security = build_security_runtime()
ledger = GuestCreditLedger()
credit_tool = SecuredGuestCreditTool(
    security,
    ledger,
    retry_policy=credit_retry_policy_from_env(),
)
reservation_cache = InMemoryCacheStore()
reservation_provider = InMemoryReservationProvider()
reservation_tool = SecuredReservationTool(
    security,
    reservation_provider,
    reservation_cache,
)
approvals = SQLiteApprovalStore(os.getenv("ASANTE_APPROVAL_DB_PATH", ".asante/approvals.db"))
maintenance_store = MaintenanceWorkOrderStore()
message_outbox = GuestMessageOutbox()
operations_tool = SecuredGuestOperationsTool(
    security,
    maintenance_store,
    message_outbox,
    approvals,
)
approved_credit_executor = ApprovedCreditExecutor(security, ledger, approvals)
trusted_tasks = TrustedTaskRegistry()

AuthenticatedOperator = Annotated[
    AuthenticatedHuman,
    Depends(require_authenticated_human),
]

guest_operations_mcp = build_guest_operations_mcp_server(
    credit_tool,
    trusted_tasks,
    reservation_tool,
    operations_tool,
)
mcp_http_app = guest_operations_mcp.streamable_http_app(
    json_response=True,
    streamable_http_path="/",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Run MCP session management and flush durable/runtime resources on shutdown."""
    try:
        async with guest_operations_mcp.session_manager.run():
            yield
    finally:
        approvals.close()
        telemetry.shutdown()


app = FastAPI(
    title="Asante Secure Multi-Agent Application",
    summary="Secure AI property operations for Asante Stays.",
    description=APP_DESCRIPTION,
    version="0.9.0",
    openapi_tags=OPENAPI_TAGS,
    contact={
        "name": "Jamiiz AI Systems",
        "url": "https://ai.jamiiz.io",
    },
    license_info={"name": "Apache-2.0"},
    lifespan=lifespan,
)
app.mount("/mcp", mcp_http_app)
instrument_fastapi(app, telemetry)


@app.get(
    "/",
    response_model=ServiceInfoResponse,
    tags=["Service"],
    summary="Discover service capabilities",
)
async def root() -> dict[str, object]:
    """Return versioned service metadata and local API discovery links."""
    return {
        "name": "Asante Secure Multi-Agent Application",
        "phase": 9,
        "status": "running",
        "docs": "/docs",
        "redoc": "/redoc",
        "health": "/health",
        "whoami": "/auth/whoami",
        "mcp": "/mcp/",
        "operations": {
            "approvals": "/operations/approvals",
            "maintenance": "/operations/work-orders",
            "messages": "/operations/messages",
        },
        "specialists": {
            "reservations": "reservation.read",
            "property_operations": "maintenance.create",
            "guest_support": "guest.message.send",
            "service_recovery": "guest.credit.issue / guest.credit.request",
        },
        "auth": "Bearer JWT access token",
        "workload_identity": "SPIFFE IDs",
        "observability": "OpenTelemetry",
        "release_gate": "deterministic security + reliability + cache-disclosure evals",
        "caching": "authorization-aware reservation reads",
        "human_approval": "SQLite-backed durable approval workflow",
        "otel_exporter": telemetry.exporter,
    }


@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["Service"],
    summary="Check service liveness",
)
def health() -> dict[str, str]:
    """Return the lightweight liveness probe excluded from tracing noise."""
    return {"status": "ok"}


@app.get(
    "/auth/whoami",
    response_model=WhoAmIResponse,
    responses=UNAUTHORIZED_RESPONSE,
    tags=["Identity"],
    summary="Inspect the authenticated human principal",
)
def whoami(
    operator: AuthenticatedOperator,
) -> dict[str, object]:
    """Show trusted identity claims after Bearer-token validation.

    The principal used by Ruhusa is derived from the validated `iss` + `sub` claims;
    callers cannot provide or override it in a request body.
    """
    return {
        "principal_id": operator.principal_id,
        "subject": operator.subject,
        "issuer": operator.issuer,
        "audiences": list(operator.audiences),
        "client_id": operator.client_id,
        "scopes": sorted(operator.scopes),
        "trace_id": current_trace_id(),
    }


@app.post(
    "/agent/run",
    response_model=AgentRunResponse,
    responses=AGENT_RUN_RESPONSES,
    tags=["Agents"],
    summary="Run the secure Asante property-operations workflow",
)
async def run_agent(
    request: Annotated[RunRequest, Body(openapi_examples=AGENT_RUN_REQUEST_EXAMPLES)],
    operator: AuthenticatedOperator,
) -> dict[str, object]:
    """Run authenticated human -> agents -> MCP -> Ruhusa in one OTel trace.

    Agent handoff does not create authority. Before the model runs, the application creates
    task-bound delegation chains rooted in the authenticated human principal. MCP tools then
    resolve those canonical chains server-side and Ruhusa independently authorizes each
    protected action.
    """
    with tracer.start_as_current_span(
        "asante.agent.run",
        attributes={
            "asante.workflow": "property_operations",
            "asante.identity.kind": "authenticated_human",
            "asante.delegation.depth": 2,
            "asante.mcp.transport": "streamable_http",
        },
    ) as span:
        task = TaskContext(
            task_id=uuid4().hex,
            initiated_by=operator.principal_id,
            purpose="Asante property operations",
            expires_at=datetime.now(UTC) + timedelta(minutes=30),
        )
        context = AsanteRunContext(
            task=task,
            reservations_delegation=issue_reservations_delegation(security, task),
            property_operations_delegation=issue_property_operations_delegation(security, task),
            guest_support_message_delegation=issue_guest_support_message_delegation(security, task),
            service_recovery_delegation=issue_service_recovery_delegation(security, task),
            service_recovery_credit_request_delegation=(
                issue_service_recovery_credit_request_delegation(security, task)
            ),
        )
        trusted_tasks.register(context)

        try:
            async with (
                build_reservations_mcp_client() as reservations_mcp,
                build_property_operations_mcp_client() as property_operations_mcp,
                build_guest_support_mcp_client() as guest_support_mcp,
                build_service_recovery_mcp_client() as service_recovery_mcp,
            ):
                reservations_agent = build_reservations_agent(reservations_mcp)
                property_operations_agent = build_property_operations_agent(property_operations_mcp)
                guest_support_agent = build_guest_support_agent(guest_support_mcp)
                service_recovery_agent = build_service_recovery_agent(service_recovery_mcp)
                supervisor_agent = build_supervisor_agent(
                    reservations_agent,
                    property_operations_agent,
                    guest_support_agent,
                    service_recovery_agent,
                )
                result = await Runner.run(
                    supervisor_agent,
                    request.message,
                    context=context,
                )
        except Exception as exc:
            span.set_status(Status(StatusCode.ERROR))
            span.set_attribute("error.type", type(exc).__name__)
            raise
        finally:
            trusted_tasks.unregister(task.task_id)

        span.set_attribute("asante.agent.last", result.last_agent.name)
        return {
            "task_id": task.task_id,
            "trace_id": current_trace_id(),
            "initiated_by": operator.principal_id,
            "last_agent": result.last_agent.name,
            "output": str(result.final_output),
        }


@app.get(
    "/demo/credits",
    response_model=list[CreditRecord],
    responses=UNAUTHORIZED_RESPONSE,
    tags=["Demo / Diagnostics"],
    summary="Inspect issued demo credits",
)
def list_demo_credits(
    _operator: AuthenticatedOperator,
) -> list[dict[str, object]]:
    """Inspect credits that actually reached the protected in-memory side effect."""
    return ledger.credits


@app.post(
    "/demo/credits",
    response_model=CreditIssuedResponse | CreditBlockedResponse,
    responses=DEMO_CREDIT_RESPONSES,
    tags=["Demo / Diagnostics"],
    summary="Issue a credit directly through Ruhusa (no LLM)",
)
async def dev_issue_credit(
    request: Annotated[DemoCreditRequest, Body(openapi_examples=DEMO_CREDIT_REQUEST_EXAMPLES)],
    operator: AuthenticatedOperator,
) -> dict[str, object]:
    """Exercise authenticated-human -> Ruhusa without LLM or MCP orchestration.

    This endpoint bypasses model reasoning so authorization, revalidation, idempotency,
    retry, and side-effect behavior can be diagnosed independently. A blocked Ruhusa
    decision is returned as a normal domain response and produces no credit side effect.
    """
    with tracer.start_as_current_span(
        "asante.credit.direct",
        attributes={
            "asante.workflow": "direct_guest_credit_test",
            "asante.identity.kind": "authenticated_human",
            "asante.delegation.depth": 2,
        },
    ):
        task = TaskContext(
            task_id=uuid4().hex,
            initiated_by=operator.principal_id,
            purpose="direct guest credit test",
            expires_at=datetime.now(UTC) + timedelta(minutes=30),
        )
        delegation_chain = issue_service_recovery_delegation(security, task)

        result = credit_tool.issue_credit(
            reservation_id=request.reservation_id,
            amount=request.amount,
            reason=request.reason,
            task=task,
            delegation_chain=delegation_chain,
        )
        return {
            "task_id": task.task_id,
            "trace_id": current_trace_id(),
            "initiated_by": operator.principal_id,
            **result,
        }


@app.get(
    "/demo/reservations/{reservation_id}",
    response_model=(
        ReservationFoundResponse | ReservationNotFoundResponse | ReservationBlockedResponse
    ),
    responses=DEMO_RESERVATION_RESPONSES,
    tags=["Demo / Diagnostics"],
    summary="Read a reservation through Ruhusa and the cache (no LLM)",
)
def dev_get_reservation(
    reservation_id: Annotated[
        str,
        Path(description="Seeded reservation ID", openapi_examples=RESERVATION_ID_EXAMPLES),
    ],
    operator: AuthenticatedOperator,
) -> dict[str, object]:
    """Read protected reservation data through Ruhusa and the authorization-aware cache.

    Ruhusa admission and execution-time revalidation happen before every cache lookup.
    Therefore a cached value cannot be disclosed after the relevant delegated authority is
    revoked. `not_found` is returned as a successful authorized domain result rather than an
    HTTP 404 because the security decision succeeded even though the provider had no record.
    """
    with tracer.start_as_current_span(
        "asante.reservation.direct",
        attributes={
            "asante.workflow": "direct_reservation_read_test",
            "asante.identity.kind": "authenticated_human",
            "asante.delegation.depth": 2,
        },
    ):
        task = TaskContext(
            task_id=uuid4().hex,
            initiated_by=operator.principal_id,
            purpose="direct reservation read test",
            expires_at=datetime.now(UTC) + timedelta(minutes=30),
        )
        delegation_chain = issue_reservations_delegation(security, task)
        result = reservation_tool.get_reservation(
            reservation_id=reservation_id,
            task=task,
            delegation_chain=delegation_chain,
        )
        return {
            "task_id": task.task_id,
            "trace_id": current_trace_id(),
            "initiated_by": operator.principal_id,
            **result,
        }


@app.get(
    "/operations/work-orders",
    response_model=list[WorkOrderRecord],
    responses=UNAUTHORIZED_RESPONSE,
    tags=["Operations"],
    summary="List maintenance work orders",
)
def list_work_orders(_operator: AuthenticatedOperator) -> list[dict[str, object]]:
    """Return maintenance work orders for the operations dashboard."""
    return maintenance_store.work_orders


@app.get(
    "/operations/messages",
    response_model=list[GuestMessageRecord],
    responses=UNAUTHORIZED_RESPONSE,
    tags=["Operations"],
    summary="List outbound guest messages",
)
def list_guest_messages(_operator: AuthenticatedOperator) -> list[dict[str, object]]:
    """Return outbound guest messages for the operations dashboard."""
    return message_outbox.messages


@app.get(
    "/operations/approvals",
    response_model=list[ApprovalRecordResponse],
    responses=UNAUTHORIZED_RESPONSE,
    tags=["Operations"],
    summary="List durable human approval requests",
)
def list_approvals(_operator: AuthenticatedOperator) -> list[dict[str, object]]:
    """Return durable approval requests newest first."""
    return [record.to_dict() for record in approvals.list_requests()]


def _require_approval_scope(operator: AuthenticatedHuman) -> None:
    """Require explicit manager approval authority from the validated token."""
    if "asante:approve" not in operator.scopes:
        raise HTTPException(
            status_code=403,
            detail="asante:approve scope required for human approval decisions",
        )


@app.post(
    "/operations/approvals/{approval_id}/approve",
    response_model=ApprovalExecutionResponse,
    responses=APPROVAL_RESPONSES,
    tags=["Operations"],
    summary="Approve and execute a pending guest credit",
)
def approve_credit_request(
    approval_id: str,
    request: Annotated[ApprovalDecisionRequest, Body(openapi_examples=APPROVAL_DECISION_EXAMPLES)],
    operator: AuthenticatedOperator,
) -> dict[str, object]:
    """Record human approval and execute the credit through a separate trusted workload."""
    _require_approval_scope(operator)
    try:
        record = approvals.require(approval_id)
        if record.status == "executed":
            return {
                "approval": record.to_dict(),
                "execution": {**(record.execution_result or {}), "deduplicated": True},
                "trace_id": current_trace_id(),
            }
        record = approvals.decide(
            approval_id,
            approved=True,
            decided_by=operator.principal_id,
            note=request.note,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ApprovalStateError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    task = TaskContext(
        task_id=uuid4().hex,
        initiated_by=operator.principal_id,
        purpose=f"execute approved guest credit {approval_id}",
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
    )
    result = approved_credit_executor.execute(
        approval=record,
        task=task,
        delegation_chain=issue_approval_executor_delegation(security, task),
    )
    refreshed = approvals.require(approval_id)
    return {
        "approval": refreshed.to_dict(),
        "execution": result,
        "trace_id": current_trace_id(),
    }


@app.post(
    "/operations/approvals/{approval_id}/deny",
    response_model=ApprovalRecordResponse,
    responses=APPROVAL_RESPONSES,
    tags=["Operations"],
    summary="Deny a pending guest credit",
)
def deny_credit_request(
    approval_id: str,
    request: Annotated[ApprovalDecisionRequest, Body(openapi_examples=APPROVAL_DECISION_EXAMPLES)],
    operator: AuthenticatedOperator,
) -> dict[str, object]:
    """Persist a human denial; no credit execution occurs."""
    _require_approval_scope(operator)
    try:
        record = approvals.decide(
            approval_id,
            approved=False,
            decided_by=operator.principal_id,
            note=request.note,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ApprovalStateError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return record.to_dict()
