"""HTTP entrypoint for the Asante secure multi-agent application.

Phase 4 adds a trusted identity boundary in front of the existing agent -> MCP ->
Ruhusa path. Human identity comes from a validated Bearer access token. Agent
workload identities come from trusted runtime configuration and are represented
as SPIFFE IDs. Ruhusa remains the authorization boundary, not the authenticator.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import uuid4

from agents import Runner
from fastapi import Depends, FastAPI
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
from asante_secure_multi_agent.tools import GuestCreditLedger, SecuredGuestCreditTool

security = build_security_runtime()
ledger = GuestCreditLedger()
credit_tool = SecuredGuestCreditTool(security, ledger)
trusted_tasks = TrustedTaskRegistry()

guest_operations_mcp = build_guest_operations_mcp_server(credit_tool, trusted_tasks)
mcp_http_app = guest_operations_mcp.streamable_http_app(
    json_response=True,
    streamable_http_path="/",
)

AuthenticatedOperator = Annotated[
    AuthenticatedHuman,
    Depends(require_authenticated_human),
]


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Run the MCP session manager inside the parent FastAPI application."""
    async with guest_operations_mcp.session_manager.run():
        yield


app = FastAPI(
    title="Asante Secure Multi-Agent Application",
    version="0.4.0",
    lifespan=lifespan,
)
app.mount("/mcp", mcp_http_app)


@app.get("/")
async def root() -> dict[str, object]:
    """Return service metadata and discovery links for local development."""
    return {
        "name": "Asante Secure Multi-Agent Application",
        "phase": 4,
        "status": "running",
        "docs": "/docs",
        "health": "/health",
        "whoami": "/auth/whoami",
        "mcp": "/mcp/",
        "auth": "Bearer JWT access token",
        "workload_identity": "SPIFFE IDs",
    }


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness probe used by local tooling and later deployment checks."""
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
        "scopes": list(operator.scopes),
    }


@app.post("/agent/run")
async def run_agent(
    request: RunRequest,
    operator: AuthenticatedOperator,
) -> dict[str, object]:
    """Run authenticated human -> Supervisor -> Guest Support -> MCP -> Ruhusa.

    The human principal is derived from a verified Bearer token. No operator ID
    from the request body is trusted. That canonical principal becomes the root
    authority source in the Ruhusa task/delegation chain.
    """
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
    finally:
        trusted_tasks.unregister(task.task_id)

    return {
        "task_id": task.task_id,
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
    """Exercise authenticated-human -> Ruhusa directly, bypassing LLM and MCP."""
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
        "initiated_by": operator.principal_id,
        **result,
    }
