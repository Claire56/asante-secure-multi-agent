"""HTTP entrypoint for the Asante secure multi-agent application.

Phase 5 adds vendor-neutral OpenTelemetry around the trusted identity ->
delegation -> agent -> MCP -> Ruhusa -> execution path. Human/workload identity
and authorization behavior remain unchanged; telemetry observes those boundaries
without becoming part of the security decision.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import uuid4

from agents import Runner
from agents.tracing import add_trace_processor
from fastapi import Depends, FastAPI
from opentelemetry.trace import Status, StatusCode
from ruhusa import TaskContext

from asante_secure_multi_agent.agents import build_guest_support_agent, build_supervisor_agent
from asante_secure_multi_agent.api_models import DemoCreditRequest, RunRequest
from asante_secure_multi_agent.context import AsanteRunContext
from asante_secure_multi_agent.identity import AuthenticatedHuman, require_authenticated_human
from asante_secure_multi_agent.mcp import (
    TrustedTaskRegistry,
    build_guest_operations_mcp_client,
    build_guest_operations_mcp_server,
)
from asante_secure_multi_agent.security import (
    build_security_runtime,
    issue_guest_support_delegation,
)
from asante_secure_multi_agent.telemetry import (
    OpenAIAgentsOpenTelemetryProcessor,
    configure_telemetry,
    current_trace_id,
    get_tracer,
    instrument_fastapi,
)
from asante_secure_multi_agent.tools import GuestCreditLedger, SecuredGuestCreditTool

telemetry = configure_telemetry()
tracer = get_tracer()
add_trace_processor(OpenAIAgentsOpenTelemetryProcessor(tracer))

security = build_security_runtime()
ledger = GuestCreditLedger()
credit_tool = SecuredGuestCreditTool(security, ledger)
trusted_tasks = TrustedTaskRegistry()

AuthenticatedOperator = Annotated[
    AuthenticatedHuman,
    Depends(require_authenticated_human),
]

guest_operations_mcp = build_guest_operations_mcp_server(credit_tool, trusted_tasks)
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
    version="0.5.0",
    lifespan=lifespan,
)
app.mount("/mcp", mcp_http_app)
instrument_fastapi(app, telemetry)


@app.get("/")
async def root() -> dict[str, object]:
    """Return service metadata and discovery links for local development."""
    return {
        "name": "Asante Secure Multi-Agent Application",
        "phase": 5,
        "status": "running",
        "docs": "/docs",
        "health": "/health",
        "whoami": "/auth/whoami",
        "mcp": "/mcp/",
        "auth": "Bearer JWT access token",
        "workload_identity": "SPIFFE IDs",
        "observability": "OpenTelemetry",
        "otel_exporter": telemetry.exporter,
    }


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness probe excluded from tracing to reduce observability noise."""
    return {"status": "ok"}


@app.get("/auth/whoami")
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


@app.post("/agent/run")
async def run_agent(
    request: RunRequest,
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
        context = AsanteRunContext(
            task=task,
            guest_support_delegation=delegation_chain,
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


@app.get("/demo/credits")
def list_demo_credits(
    _operator: AuthenticatedOperator,
) -> list[dict[str, object]]:
    """Inspect the demo ledger after authenticating the requesting operator."""
    return ledger.credits


@app.post("/demo/credits")
async def dev_issue_credit(
    request: DemoCreditRequest,
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
