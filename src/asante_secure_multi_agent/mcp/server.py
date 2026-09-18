"""MCP tool surface for Asante guest operations with OTel propagation."""

from __future__ import annotations

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from opentelemetry import propagate
from opentelemetry.trace import Status, StatusCode

from asante_secure_multi_agent.telemetry import get_tracer
from asante_secure_multi_agent.telemetry.metrics import record_mcp_call
from asante_secure_multi_agent.tools import SecuredGuestCreditTool

from .client import ASANTE_TASK_META_KEY
from .registry import TrustedTaskNotFoundError, TrustedTaskRegistry

_tracer = get_tracer()


def issue_guest_credit_for_trusted_task(
    *,
    credit_tool: SecuredGuestCreditTool,
    task_registry: TrustedTaskRegistry,
    task_id: str,
    reservation_id: str,
    amount: float,
    reason: str,
) -> dict[str, object]:
    """Resolve canonical authority and execute the Ruhusa-secured credit path."""
    run_context = task_registry.require(task_id)
    return credit_tool.issue_credit(
        reservation_id=reservation_id,
        amount=amount,
        reason=reason,
        task=run_context.task,
        delegation_chain=run_context.guest_support_delegation,
    )


def _mcp_meta(ctx: Context) -> dict[str, object]:
    """Return inbound MCP metadata used for trusted lookup and trace propagation."""
    return dict(ctx.request_context.meta or {})


def _task_id_from_meta(meta: dict[str, object]) -> str:
    """Extract the hidden task reference from inbound MCP request metadata."""
    task_id = meta.get(ASANTE_TASK_META_KEY)
    if not isinstance(task_id, str) or not task_id:
        raise ToolError("missing trusted Asante task context")
    return task_id


def _task_id_from_mcp_context(ctx: Context) -> str:
    """Backward-compatible helper retained for the Phase 3 regression tests."""
    return _task_id_from_meta(_mcp_meta(ctx))


def build_guest_operations_mcp_server(
    credit_tool: SecuredGuestCreditTool,
    task_registry: TrustedTaskRegistry,
) -> MCPServer:
    """Build the Streamable HTTP MCP server consumed by Guest Support."""
    server = MCPServer(
        "Asante Guest Operations MCP",
        instructions=(
            "Asante guest-operation tools. Tool calls are subject to Ruhusa "
            "delegated authorization and execution-time revalidation."
        ),
    )

    @server.tool(name="issue_guest_credit", structured_output=True)
    async def issue_guest_credit(
        reservation_id: str,
        amount: float,
        reason: str,
        ctx: Context,
    ) -> dict[str, object]:
        """Issue a credit using hidden canonical authority and propagated OTel context."""
        meta = _mcp_meta(ctx)
        task_id = _task_id_from_meta(meta)
        parent_context = propagate.extract(meta)

        with _tracer.start_as_current_span(
            "asante.mcp.issue_guest_credit",
            context=parent_context,
            attributes={
                "mcp.tool.name": "issue_guest_credit",
                "asante.action": "guest.credit.issue",
                "asante.resource.kind": "reservation",
            },
        ) as span:
            try:
                result = issue_guest_credit_for_trusted_task(
                    credit_tool=credit_tool,
                    task_registry=task_registry,
                    task_id=task_id,
                    reservation_id=reservation_id,
                    amount=amount,
                    reason=reason,
                )
            except TrustedTaskNotFoundError as exc:
                span.set_status(Status(StatusCode.ERROR))
                span.set_attribute("error.type", "trusted_task_unavailable")
                record_mcp_call(outcome="error")
                raise ToolError("trusted Asante task context is unavailable") from exc

            outcome = str(result.get("status", "unknown"))
            span.set_attribute("asante.mcp.outcome", outcome)
            record_mcp_call(outcome=outcome)
            return result

    return server
