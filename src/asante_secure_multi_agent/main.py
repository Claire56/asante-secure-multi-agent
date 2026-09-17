"""HTTP entrypoint for the Asante secure multi-agent application.

This module wires the OpenAI Agents SDK supervisor to FastAPI. Authorization is
not enforced here; Ruhusa sits inside the guest-credit tool so every side effect
still goes through policy, trusted provenance, delegated authority, and
execution fencing.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from agents import Runner
from fastapi import FastAPI
from pydantic import BaseModel, Field
from ruhusa import TaskContext

from asante_secure_multi_agent.agents import build_guest_support_agent, build_supervisor_agent
from asante_secure_multi_agent.context import AsanteRunContext
from asante_secure_multi_agent.security import (
    build_security_runtime,
    issue_guest_support_delegation,
)
from asante_secure_multi_agent.tools import GuestCreditLedger, SecuredGuestCreditTool

app = FastAPI(title="Asante Secure Multi-Agent Application", version="0.2.0")

# Shared process-local runtime. Phase 2 keeps persistence in memory so we can
# isolate and prove delegation semantics before adding external identity or a DB.
security = build_security_runtime()
ledger = GuestCreditLedger()
credit_tool = SecuredGuestCreditTool(security, ledger)
guest_support_agent = build_guest_support_agent(credit_tool)
supervisor_agent = build_supervisor_agent(guest_support_agent)


class RunRequest(BaseModel):
    """Operator prompt plus the identity that initiated the task.

    ``operator_id`` becomes the root of the Ruhusa delegation chain. It is still
    self-supplied at the HTTP boundary in Phase 2; authenticated operator identity
    is a later milestone.
    """

    message: str = Field(min_length=1)
    operator_id: str = "user:asante-operator"


@app.get("/")
async def root():
    """Return service metadata and discovery links for local development."""
    return {
        "name": "Asante Secure Multi-Agent Application",
        "phase": 2,
        "status": "running",
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness probe used by local tooling and later deployment checks."""
    return {"status": "ok"}


@app.post("/agent/run")
async def run_agent(request: RunRequest) -> dict[str, object]:
    """Run one operator request through the supervisor with delegated authority.

    A unique task is created per request. Trusted application infrastructure then
    registers a human -> supervisor -> guest-support delegation chain before the
    model runs. The SDK can hand work to Guest Support, but only Ruhusa determines
    whether that delegated authority is sufficient for a proposed side effect.
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

    result = await Runner.run(
        supervisor_agent,
        request.message,
        context=context,
    )
    return {
        "task_id": task.task_id,
        "last_agent": result.last_agent.name,
        "output": result.final_output,
    }


@app.get("/demo/credits")
def list_demo_credits() -> list[dict[str, object]]:
    """Inspect credits written to the in-memory ledger after agent runs."""
    return ledger.credits
