"""Least-privilege OpenAI Agents SDK clients for the Asante MCP server."""

from __future__ import annotations

import os
from collections.abc import Callable

from agents.mcp import (
    MCPServerStreamableHttp,
    MCPToolMetaContext,
    create_static_tool_filter,
)

from asante_secure_multi_agent.context import AsanteRunContext
from asante_secure_multi_agent.identity import (
    GUEST_SUPPORT_WORKLOAD,
    PROPERTY_OPERATIONS_WORKLOAD,
    RESERVATIONS_WORKLOAD,
    SERVICE_RECOVERY_WORKLOAD,
)
from asante_secure_multi_agent.reliability import mcp_reliability_config_from_env
from asante_secure_multi_agent.telemetry import inject_current_trace_headers

ASANTE_TASK_META_KEY = "asante/task_id"
ASANTE_WORKLOAD_META_KEY = "asante/workload"
DEFAULT_ASANTE_MCP_URL = "http://127.0.0.1:8000/mcp/"


def _resolve_specialist_meta(
    workload: str,
) -> Callable[[MCPToolMetaContext], dict[str, str] | None]:
    """Create a trusted metadata resolver bound to one specialist workload."""

    def resolve(context: MCPToolMetaContext) -> dict[str, str] | None:
        run_context = context.run_context.context
        if not isinstance(run_context, AsanteRunContext):
            return None
        return inject_current_trace_headers(
            {
                ASANTE_TASK_META_KEY: run_context.task.task_id,
                ASANTE_WORKLOAD_META_KEY: workload,
            }
        )

    return resolve


def resolve_asante_mcp_meta(context: MCPToolMetaContext) -> dict[str, str] | None:
    """Backward-compatible metadata resolver for the Guest Support workload."""
    return _resolve_specialist_meta(GUEST_SUPPORT_WORKLOAD)(context)


def _build_specialist_mcp_client(
    *,
    name: str,
    workload: str,
    allowed_tools: list[str],
    url: str | None = None,
) -> MCPServerStreamableHttp:
    reliability = mcp_reliability_config_from_env()
    return MCPServerStreamableHttp(
        name=name,
        params={
            "url": url or os.getenv("ASANTE_MCP_URL", DEFAULT_ASANTE_MCP_URL),
            "headers": inject_current_trace_headers(),
            "timeout": reliability.timeout_seconds,
        },
        cache_tools_list=True,
        max_retry_attempts=reliability.max_retry_attempts,
        use_structured_content=True,
        tool_filter=create_static_tool_filter(allowed_tool_names=allowed_tools),
        tool_meta_resolver=_resolve_specialist_meta(workload),
    )


def build_reservations_mcp_client(url: str | None = None) -> MCPServerStreamableHttp:
    """Expose only reservation-read capability to the Reservations specialist."""
    return _build_specialist_mcp_client(
        name="Asante Reservations MCP",
        workload=RESERVATIONS_WORKLOAD,
        allowed_tools=["get_reservation"],
        url=url,
    )


def build_property_operations_mcp_client(url: str | None = None) -> MCPServerStreamableHttp:
    """Expose only maintenance creation to the Property Operations specialist."""
    return _build_specialist_mcp_client(
        name="Asante Property Operations MCP",
        workload=PROPERTY_OPERATIONS_WORKLOAD,
        allowed_tools=["create_maintenance_request"],
        url=url,
    )


def build_guest_support_mcp_client(url: str | None = None) -> MCPServerStreamableHttp:
    """Expose only outbound guest messaging to the Guest Support specialist."""
    return _build_specialist_mcp_client(
        name="Asante Guest Support MCP",
        workload=GUEST_SUPPORT_WORKLOAD,
        allowed_tools=["send_guest_message"],
        url=url,
    )


def build_service_recovery_mcp_client(url: str | None = None) -> MCPServerStreamableHttp:
    """Expose only credit issue/request capabilities to Service Recovery."""
    return _build_specialist_mcp_client(
        name="Asante Service Recovery MCP",
        workload=SERVICE_RECOVERY_WORKLOAD,
        allowed_tools=["issue_guest_credit", "request_guest_credit"],
        url=url,
    )


def build_guest_operations_mcp_client(url: str | None = None) -> MCPServerStreamableHttp:
    """Legacy Phase 8 client; new code should use specialist-specific clients."""
    return _build_specialist_mcp_client(
        name="Asante Guest Operations MCP",
        workload=GUEST_SUPPORT_WORKLOAD,
        allowed_tools=[
            "get_reservation",
            "create_maintenance_request",
            "send_guest_message",
            "issue_guest_credit",
            "request_guest_credit",
        ],
        url=url,
    )
