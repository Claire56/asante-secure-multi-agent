"""MCP tool surface for Asante guest operations with OTel propagation."""

from __future__ import annotations

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from opentelemetry import propagate
from opentelemetry.trace import Status, StatusCode

from asante_secure_multi_agent.telemetry import get_tracer
from asante_secure_multi_agent.telemetry.metrics import record_mcp_call
from asante_secure_multi_agent.tools import (
    SecuredGuestCreditTool,
    SecuredGuestOperationsTool,
    SecuredReservationTool,
)

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


def get_reservation_for_trusted_task(
    *,
    reservation_tool: SecuredReservationTool,
    task_registry: TrustedTaskRegistry,
    task_id: str,
    reservation_id: str,
) -> dict[str, object]:
    """Resolve canonical authority and execute the secured reservation-read path."""
    run_context = task_registry.require(task_id)
    return reservation_tool.get_reservation(
        reservation_id=reservation_id,
        task=run_context.task,
        delegation_chain=(
            run_context.guest_support_reservation_delegation
            if run_context.guest_support_reservation_delegation is not None
            else run_context.guest_support_delegation
        ),
    )


def create_maintenance_for_trusted_task(
    *,
    operations_tool: SecuredGuestOperationsTool,
    task_registry: TrustedTaskRegistry,
    task_id: str,
    reservation_id: str,
    category: str,
    urgency: str,
    description: str,
) -> dict[str, object]:
    """Create a work order from trusted task-bound service authority."""
    run_context = task_registry.require(task_id)
    chain = run_context.guest_support_service_delegation
    if chain is None:
        raise TrustedTaskNotFoundError("guest service delegation is unavailable")
    return operations_tool.create_maintenance_request(
        reservation_id=reservation_id,
        category=category,
        urgency=urgency,
        description=description,
        task=run_context.task,
        delegation_chain=chain,
    )


def send_guest_message_for_trusted_task(
    *,
    operations_tool: SecuredGuestOperationsTool,
    task_registry: TrustedTaskRegistry,
    task_id: str,
    reservation_id: str,
    message: str,
) -> dict[str, object]:
    """Send a guest update from trusted task-bound service authority."""
    run_context = task_registry.require(task_id)
    chain = run_context.guest_support_service_delegation
    if chain is None:
        raise TrustedTaskNotFoundError("guest service delegation is unavailable")
    return operations_tool.send_guest_message(
        reservation_id=reservation_id,
        message=message,
        task=run_context.task,
        delegation_chain=chain,
    )


def request_guest_credit_for_trusted_task(
    *,
    operations_tool: SecuredGuestOperationsTool,
    task_registry: TrustedTaskRegistry,
    task_id: str,
    reservation_id: str,
    amount: float,
    reason: str,
) -> dict[str, object]:
    """Create a durable approval request without granting execution authority."""
    run_context = task_registry.require(task_id)
    chain = run_context.guest_support_credit_request_delegation
    if chain is None:
        raise TrustedTaskNotFoundError("credit-request delegation is unavailable")
    return operations_tool.request_guest_credit(
        reservation_id=reservation_id,
        amount=amount,
        reason=reason,
        task=run_context.task,
        delegation_chain=chain,
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
    """Backward-compatible helper retained for MCP boundary regression tests."""
    return _task_id_from_meta(_mcp_meta(ctx))


def build_guest_operations_mcp_server(
    credit_tool: SecuredGuestCreditTool,
    task_registry: TrustedTaskRegistry,
    reservation_tool: SecuredReservationTool | None = None,
    operations_tool: SecuredGuestOperationsTool | None = None,
) -> MCPServer:
    """Build the Streamable HTTP MCP server consumed by Guest Support."""
    server = MCPServer(
        "Asante Guest Operations MCP",
        instructions=(
            "Asante guest-operation tools. Tool calls are subject to Ruhusa "
            "delegated authorization and execution-time revalidation. Cached "
            "reservation results never bypass authorization, and larger credits "
            "must use the approval-request tool rather than bypassing limits."
        ),
    )

    @server.tool(name="issue_guest_credit", structured_output=True)
    async def issue_guest_credit(
        reservation_id: str,
        amount: float,
        reason: str,
        ctx: Context,
    ) -> dict[str, object]:
        """Issue a small credit using hidden canonical authority."""
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
                record_mcp_call(outcome="error", tool_name="issue_guest_credit")
                raise ToolError("trusted Asante task context is unavailable") from exc
            outcome = str(result.get("status", "unknown"))
            span.set_attribute("asante.mcp.outcome", outcome)
            record_mcp_call(outcome=outcome, tool_name="issue_guest_credit")
            return result

    if reservation_tool is not None:

        @server.tool(name="get_reservation", structured_output=True)
        async def get_reservation(
            reservation_id: str,
            ctx: Context,
        ) -> dict[str, object]:
            """Read reservation data only after live Ruhusa authorization."""
            meta = _mcp_meta(ctx)
            task_id = _task_id_from_meta(meta)
            parent_context = propagate.extract(meta)
            with _tracer.start_as_current_span(
                "asante.mcp.get_reservation",
                context=parent_context,
                attributes={
                    "mcp.tool.name": "get_reservation",
                    "asante.action": "reservation.read",
                    "asante.resource.kind": "reservation",
                },
            ) as span:
                try:
                    result = get_reservation_for_trusted_task(
                        reservation_tool=reservation_tool,
                        task_registry=task_registry,
                        task_id=task_id,
                        reservation_id=reservation_id,
                    )
                except TrustedTaskNotFoundError as exc:
                    span.set_status(Status(StatusCode.ERROR))
                    span.set_attribute("error.type", "trusted_task_unavailable")
                    record_mcp_call(outcome="error", tool_name="get_reservation")
                    raise ToolError("trusted Asante task context is unavailable") from exc
                outcome = str(result.get("cache", result.get("status", "unknown")))
                span.set_attribute("asante.mcp.outcome", outcome)
                record_mcp_call(outcome=outcome, tool_name="get_reservation")
                return result

    if operations_tool is not None:

        @server.tool(name="create_maintenance_request", structured_output=True)
        async def create_maintenance_request(
            reservation_id: str,
            category: str,
            urgency: str,
            description: str,
            ctx: Context,
        ) -> dict[str, object]:
            """Create an authorized maintenance work order for a reservation."""
            meta = _mcp_meta(ctx)
            task_id = _task_id_from_meta(meta)
            parent_context = propagate.extract(meta)
            with _tracer.start_as_current_span(
                "asante.mcp.create_maintenance_request",
                context=parent_context,
                attributes={
                    "mcp.tool.name": "create_maintenance_request",
                    "asante.action": "maintenance.create",
                },
            ):
                try:
                    result = create_maintenance_for_trusted_task(
                        operations_tool=operations_tool,
                        task_registry=task_registry,
                        task_id=task_id,
                        reservation_id=reservation_id,
                        category=category,
                        urgency=urgency,
                        description=description,
                    )
                except TrustedTaskNotFoundError as exc:
                    record_mcp_call(outcome="error", tool_name="create_maintenance_request")
                    raise ToolError("trusted Asante task context is unavailable") from exc
                outcome = str(result.get("status", "unknown"))
                record_mcp_call(outcome=outcome, tool_name="create_maintenance_request")
                return result

        @server.tool(name="send_guest_message", structured_output=True)
        async def send_guest_message(
            reservation_id: str,
            message: str,
            ctx: Context,
        ) -> dict[str, object]:
            """Send an authorized operational update to the guest."""
            meta = _mcp_meta(ctx)
            task_id = _task_id_from_meta(meta)
            parent_context = propagate.extract(meta)
            with _tracer.start_as_current_span(
                "asante.mcp.send_guest_message",
                context=parent_context,
                attributes={
                    "mcp.tool.name": "send_guest_message",
                    "asante.action": "guest.message.send",
                },
            ):
                try:
                    result = send_guest_message_for_trusted_task(
                        operations_tool=operations_tool,
                        task_registry=task_registry,
                        task_id=task_id,
                        reservation_id=reservation_id,
                        message=message,
                    )
                except TrustedTaskNotFoundError as exc:
                    record_mcp_call(outcome="error", tool_name="send_guest_message")
                    raise ToolError("trusted Asante task context is unavailable") from exc
                outcome = str(result.get("status", "unknown"))
                record_mcp_call(outcome=outcome, tool_name="send_guest_message")
                return result

        @server.tool(name="request_guest_credit", structured_output=True)
        async def request_guest_credit(
            reservation_id: str,
            amount: float,
            reason: str,
            ctx: Context,
        ) -> dict[str, object]:
            """Create a durable human-approval request for a larger credit."""
            meta = _mcp_meta(ctx)
            task_id = _task_id_from_meta(meta)
            parent_context = propagate.extract(meta)
            with _tracer.start_as_current_span(
                "asante.mcp.request_guest_credit",
                context=parent_context,
                attributes={
                    "mcp.tool.name": "request_guest_credit",
                    "asante.action": "guest.credit.request",
                },
            ):
                try:
                    result = request_guest_credit_for_trusted_task(
                        operations_tool=operations_tool,
                        task_registry=task_registry,
                        task_id=task_id,
                        reservation_id=reservation_id,
                        amount=amount,
                        reason=reason,
                    )
                except TrustedTaskNotFoundError as exc:
                    record_mcp_call(outcome="error", tool_name="request_guest_credit")
                    raise ToolError("trusted Asante task context is unavailable") from exc
                outcome = str(result.get("status", "unknown"))
                record_mcp_call(outcome=outcome, tool_name="request_guest_credit")
                return result

    return server
