"""MCP tool surface for Asante guest operations.

The MCP server exposes business capabilities to agents, but it does not become
an authorization oracle for the model. It resolves trusted task/delegation state
server-side and invokes the same Ruhusa-secured application service used by the
direct development endpoint.
"""

from __future__ import annotations

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from asante_secure_multi_agent.tools import SecuredGuestCreditTool

from .client import ASANTE_TASK_META_KEY
from .registry import TrustedTaskNotFoundError, TrustedTaskRegistry


def issue_guest_credit_for_trusted_task(
    *,
    credit_tool: SecuredGuestCreditTool,
    task_registry: TrustedTaskRegistry,
    task_id: str,
    reservation_id: str,
    amount: float,
    reason: str,
) -> dict[str, object]:
    """Resolve canonical authority and execute the Ruhusa-secured credit path.

    ``task_id`` is only a lookup reference. The TaskContext and DelegationGrant
    objects used for authorization are taken from trusted server-side state.
    """
    run_context = task_registry.require(task_id)
    return credit_tool.issue_credit(
        reservation_id=reservation_id,
        amount=amount,
        reason=reason,
        task=run_context.task,
        delegation_chain=run_context.guest_support_delegation,
    )


def _task_id_from_mcp_context(ctx: Context) -> str:
    """Extract the hidden task reference from inbound MCP request metadata."""
    meta = ctx.request_context.meta or {}
    task_id = meta.get(ASANTE_TASK_META_KEY)
    if not isinstance(task_id, str) or not task_id:
        raise ToolError("missing trusted Asante task context")
    return task_id


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
        """Issue a service-recovery credit to an Asante guest reservation.

        The caller supplies only business arguments. Trusted task and delegated
        authority are resolved from MCP request metadata plus server-side state.
        """
        task_id = _task_id_from_mcp_context(ctx)
        try:
            return issue_guest_credit_for_trusted_task(
                credit_tool=credit_tool,
                task_registry=task_registry,
                task_id=task_id,
                reservation_id=reservation_id,
                amount=amount,
                reason=reason,
            )
        except TrustedTaskNotFoundError as exc:
            # Fail closed without revealing whether another task ID exists.
            raise ToolError("trusted Asante task context is unavailable") from exc

    return server
