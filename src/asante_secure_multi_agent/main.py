"""HTTP entrypoint for the Asante secure multi-agent application.

FastAPI owns the operator-facing REST API and mounts a Streamable HTTP MCP
server at ``/mcp``. The agent reaches business actions through MCP; Ruhusa sits
behind the MCP tool and remains the authorization/execution boundary.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from agents import Runner
from fastapi import FastAPI
from pydantic import BaseModel, Field
from ruhusa import TaskContext

from asante_secure_multi_agent.agents import build_guest_support_agent, build_supervisor_agent
from asante_secure_multi_agent.context import AsanteRunContext
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

# Shared process-local security and fake external system. Phase 3 intentionally
# keeps these in memory so the new learning target is the MCP trust boundary.
security = build_security_runtime()
ledger = GuestCreditLedger()
credit_tool = SecuredGuestCreditTool(security, ledger)
trusted_tasks = TrustedTaskRegistry()

# The MCP server exposes business tools, not authority-management tools. Its
# issue_guest_credit implementation resolves trusted state from ``trusted_tasks``
# before entering the existing Ruhusa authorization/execution path.
guest_operations_mcp = build_guest_operations_mcp_server(credit_tool, trusted_tasks)
mcp_http_app = guest_operations_mcp.streamable_http_app(
    json_response=True,
    streamable_http_path="/",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Run the MCP session manager inside the parent FastAPI application."""
    async with guest_operations_mcp.session_manager.run():
        yield


app = FastAPI(
    title="Asante Secure Multi-Agent Application",
    version="0.3.0",
    lifespan=lifespan,
)
app.mount("/mcp", mcp_http_app)


class RunRequest(BaseModel):
    """Operator prompt plus the identity that initiated the task.

    ``operator_id`` becomes the root of the Ruhusa delegation chain. It is still
    self-supplied at the HTTP boundary in Phase 3; authenticated operator identity
    is the next milestone.
    """

    message: str = Field(min_length=1)
    operator_id: str = "user:asante-operator"


class DemoCreditRequest(BaseModel):
    """Direct credit request used to test Ruhusa without the LLM or MCP."""

    reservation_id: str = Field(min_length=1)
    amount: float = Field(gt=0)
    reason: str = Field(min_length=1)
    operator_id: str = "user:asante-operator"


@app.get("/")
async def root() -> dict[str, object]:
    """Return service metadata and discovery links for local development."""
    return {
        "name": "Asante Secure Multi-Agent Application",
        "phase": 3,
        "status": "running",
        "docs": "/docs",
        "health": "/health",
        "mcp": "/mcp",
    }


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness probe used by local tooling and later deployment checks."""
    return {"status": "ok"}


@app.post("/agent/run")
async def run_agent(request: RunRequest) -> dict[str, object]:
    """Run one operator request through Supervisor -> Guest Support -> MCP.

    Trusted infrastructure creates the Ruhusa delegation chain and registers it
    server-side before the model runs. OpenAI's MCP client injects only the task
    reference into per-call ``_meta``. The MCP server uses that reference to
    recover canonical task/delegation state; those security objects never come
    from model-visible MCP tool arguments.
    """
    task = TaskContext(
        task_id=uuid4().hex,
        initiated_by=request.operator_id,
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
        "last_agent": result.last_agent.name,
        "output": result.final_output,
    }


@app.get("/demo/credits")
def list_demo_credits() -> list[dict[str, object]]:
    """Inspect credits written to the in-memory ledger after secured executions."""
    return ledger.credits


@app.post("/demo/credits")
async def dev_issue_credit(request: DemoCreditRequest) -> dict[str, object]:
    """Exercise Ruhusa directly, bypassing both the LLM and MCP layers.

    This stays useful in Phase 3 as a diagnostic control path: if this succeeds
    while ``/agent/run`` fails, the problem is above the Ruhusa/business layer.
    """
    task = TaskContext(
        task_id=uuid4().hex,
        initiated_by=request.operator_id,
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
        **result,
    }
