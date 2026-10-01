"""HTTP entrypoint for the Asante secure multi-agent application.

Phase 7 adds authorization-aware reservation caching on top of the trusted
identity -> delegation -> agent -> MCP -> Ruhusa -> execution path. Every cache
lookup is preceded by live Ruhusa authorization and revalidation, so stale cached
data cannot bypass revocation or task-bound authority.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import uuid4

from agents import Runner
from agents.tracing import add_trace_processor
from fastapi import Body, Depends, FastAPI, Path
from opentelemetry.trace import Status, StatusCode
from ruhusa import TaskContext

from asante_secure_multi_agent.agents import build_guest_support_agent, build_supervisor_agent
from asante_secure_multi_agent.api_models import DemoCreditRequest, RunRequest
from asante_secure_multi_agent.cache import InMemoryCacheStore
from asante_secure_multi_agent.context import AsanteRunContext
from asante_secure_multi_agent.identity import AuthenticatedHuman, require_authenticated_human
from asante_secure_multi_agent.mcp import (
    TrustedTaskRegistry,
    build_guest_operations_mcp_client,
    build_guest_operations_mcp_server,
)
from asante_secure_multi_agent.openapi_examples import (
    AGENT_RUN_REQUEST_EXAMPLES,
    AGENT_RUN_RESPONSES,
    DEMO_CREDIT_REQUEST_EXAMPLES,
    DEMO_CREDIT_RESPONSES,
    DEMO_RESERVATION_RESPONSES,
    RESERVATION_ID_EXAMPLES,
    UNAUTHORIZED_RESPONSE,
)
from asante_secure_multi_agent.reliability import credit_retry_policy_from_env
from asante_secure_multi_agent.security import (
    build_security_runtime,
    issue_guest_support_delegation,
    issue_guest_support_reservation_delegation,
)
from asante_secure_multi_agent.telemetry import (
    OpenAIAgentsOpenTelemetryProcessor,
    configure_telemetry,
    current_trace_id,
    get_tracer,
    instrument_fastapi,
)
from asante_secure_multi_agent.tools import (
    GuestCreditLedger,
    InMemoryReservationProvider,
    SecuredGuestCreditTool,
    SecuredReservationTool,
)

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
trusted_tasks = TrustedTaskRegistry()

AuthenticatedOperator = Annotated[
    AuthenticatedHuman,
    Depends(require_authenticated_human),
]

guest_operations_mcp = build_guest_operations_mcp_server(
    credit_tool,
    trusted_tasks,
    reservation_tool,
)
mcp_http_app = guest_operations_mcp.streamable_http_app(
    json_response=True,
    streamable_http_path="/",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Run the MCP session manager and flush telemetry during shutdown."""
    try:
        async with guest_operations_mcp.session_manager.run():
            yield
    finally:
        telemetry.shutdown()


app = FastAPI(
    title="Asante Secure Multi-Agent Application",
    version="0.7.0",
    lifespan=lifespan,
)
app.mount("/mcp", mcp_http_app)
instrument_fastapi(app, telemetry)


@app.get("/")
async def root() -> dict[str, object]:
    """Return service metadata and discovery links for local development."""
    return {
        "name": "Asante Secure Multi-Agent Application",
        "phase": 7,
        "status": "running",
        "docs": "/docs",
        "health": "/health",
        "whoami": "/auth/whoami",
        "mcp": "/mcp/",
        "auth": "Bearer JWT access token",
        "workload_identity": "SPIFFE IDs",
        "observability": "OpenTelemetry",
        "release_gate": "deterministic security + reliability + cache-disclosure evals",
        "caching": "authorization-aware reservation reads",
        "otel_exporter": telemetry.exporter,
    }


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness probe excluded from tracing to reduce observability noise."""
    return {"status": "ok"}


@app.get("/auth/whoami", responses=UNAUTHORIZED_RESPONSE)
def whoami(
    operator: AuthenticatedOperator,
) -> dict[str, object]:
    """Show the canonical human identity derived from the validated token."""
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
    summary="Send a message to the agent graph",
    responses=AGENT_RUN_RESPONSES,
)
async def run_agent(
    request: Annotated[RunRequest, Body(openapi_examples=AGENT_RUN_REQUEST_EXAMPLES)],
    operator: AuthenticatedOperator,
) -> dict[str, object]:
    """Run authenticated human -> agents -> MCP -> Ruhusa with one OTel trace."""
    with tracer.start_as_current_span(
        "asante.agent.run",
        attributes={
            "asante.workflow": "guest_service_recovery",
            "asante.identity.kind": "authenticated_human",
            "asante.delegation.depth": 2,
            "asante.mcp.transport": "streamable_http",
        },
    ) as span:
        task = TaskContext(
            task_id=uuid4().hex,
            initiated_by=operator.principal_id,
            purpose="guest service recovery",
            expires_at=datetime.now(UTC) + timedelta(minutes=30),
        )
        delegation_chain = issue_guest_support_delegation(security, task)
        reservation_delegation_chain = issue_guest_support_reservation_delegation(security, task)
        context = AsanteRunContext(
            task=task,
            guest_support_delegation=delegation_chain,
            guest_support_reservation_delegation=reservation_delegation_chain,
        )
        trusted_tasks.register(context)

        try:
            async with build_guest_operations_mcp_client() as mcp_server:
                guest_support_agent = build_guest_support_agent(mcp_server)
                supervisor_agent = build_supervisor_agent(guest_support_agent)
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
            "output": result.final_output,
        }


@app.get("/demo/credits", summary="List issued demo credits", responses=UNAUTHORIZED_RESPONSE)
def list_demo_credits(
    _operator: AuthenticatedOperator,
) -> list[dict[str, object]]:
    """Inspect the demo ledger after authenticating the requesting operator."""
    return ledger.credits


@app.post(
    "/demo/credits",
    summary="Issue a credit directly through Ruhusa (no LLM)",
    responses=DEMO_CREDIT_RESPONSES,
)
async def dev_issue_credit(
    request: Annotated[DemoCreditRequest, Body(openapi_examples=DEMO_CREDIT_REQUEST_EXAMPLES)],
    operator: AuthenticatedOperator,
) -> dict[str, object]:
    """Exercise authenticated-human -> Ruhusa directly with OTel visibility."""
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
        delegation_chain = issue_guest_support_delegation(security, task)

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
    summary="Read a reservation through Ruhusa and the cache (no LLM)",
    responses=DEMO_RESERVATION_RESPONSES,
)
def dev_get_reservation(
    reservation_id: Annotated[
        str,
        Path(description="Seeded reservation ID", openapi_examples=RESERVATION_ID_EXAMPLES),
    ],
    operator: AuthenticatedOperator,
) -> dict[str, object]:
    """Exercise the secured reservation-read/cache path without the LLM or MCP."""
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
        delegation_chain = issue_guest_support_reservation_delegation(security, task)
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
