from __future__ import annotations

from uuid import uuid4

from agents import Runner
from fastapi import FastAPI
from pydantic import BaseModel, Field

from asante_secure_multi_agent.agents import build_guest_support_agent, build_supervisor_agent
from asante_secure_multi_agent.security import build_security_runtime
from asante_secure_multi_agent.tools import GuestCreditLedger, SecuredGuestCreditTool

app = FastAPI(title="Asante Secure Multi-Agent Application", version="0.1.0")

security = build_security_runtime()
ledger = GuestCreditLedger()
credit_tool = SecuredGuestCreditTool(security, ledger)
guest_support_agent = build_guest_support_agent(credit_tool)
supervisor_agent = build_supervisor_agent(guest_support_agent)


class RunRequest(BaseModel):
    message: str = Field(min_length=1)
    operator_id: str = "user:asante-operator"

@app.get("/")
async def root():
    return {
        "name": "Asante Secure Multi-Agent Application",
        "status": "running",
        "docs": "/docs",
        "health": "/health",
    }

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/agent/run")
async def run_agent(request: RunRequest) -> dict[str, object]:
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
    return ledger.credits
