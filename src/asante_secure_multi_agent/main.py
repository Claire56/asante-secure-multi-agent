"""HTTP entrypoint for the Asante secure multi-agent application.

This module wires the OpenAI Agents SDK supervisor to FastAPI. Authorization is
not enforced here; Ruhusa sits inside the guest-credit tool so every side effect
still goes through the same policy, provenance, and execution-fencing path.
"""

from __future__ import annotations

from uuid import uuid4

from agents import Runner
from fastapi import FastAPI
from pydantic import BaseModel, Field

from asante_secure_multi_agent.agents import build_guest_support_agent, build_supervisor_agent
from asante_secure_multi_agent.security import build_security_runtime
from asante_secure_multi_agent.tools import GuestCreditLedger, SecuredGuestCreditTool

app = FastAPI(title="Asante Secure Multi-Agent Application", version="0.1.0")

# Shared process-local runtime. Phase 1 keeps these in memory so the
# authorization lifecycle can be proven before a real PMS or identity provider.
security = build_security_runtime()
ledger = GuestCreditLedger()
credit_tool = SecuredGuestCreditTool(security, ledger)
guest_support_agent = build_guest_support_agent(credit_tool)
supervisor_agent = build_supervisor_agent(guest_support_agent)


class RunRequest(BaseModel):
    """Operator prompt plus the identity that initiated the task.

    ``operator_id`` becomes Ruhusa task provenance (``initiated_by``). It is not
    authenticated yet; that is a later milestone.
    """

    message: str = Field(min_length=1)
    operator_id: str = "user:asante-operator"


@app.get("/")
async def root():
    """Return service metadata and discovery links for local development."""
    return {
        "name": "Asante Secure Multi-Agent Application",
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
    """Run one operator request through the supervisor agent.

    A unique ``task_id`` is generated per request so Ruhusa can bind tool
    invocations to this operator task rather than a long-lived session.
    """
    task_id = uuid4().hex
    result = await Runner.run(
        supervisor_agent,
        request.message,
        context={"task_id": task_id, "initiated_by": request.operator_id},
    )
    return {
        "task_id": task_id,
        "last_agent": result.last_agent.name,
        "output": result.final_output,
    }


@app.get("/demo/credits")
def list_demo_credits() -> list[dict[str, object]]:
    """Inspect credits written to the in-memory ledger after agent runs."""
    return ledger.credits
