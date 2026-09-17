"""OpenAI Agents SDK client configuration for the Asante MCP server."""

from __future__ import annotations

import os

from agents.mcp import MCPServerStreamableHttp, MCPToolMetaContext

from asante_secure_multi_agent.context import AsanteRunContext

ASANTE_TASK_META_KEY = "asante/task_id"
DEFAULT_ASANTE_MCP_URL = "http://127.0.0.1:8000/mcp"


def resolve_asante_mcp_meta(context: MCPToolMetaContext) -> dict[str, str] | None:
    """Attach trusted run metadata to each MCP tool call.

    The value is application metadata, not a model-visible tool argument. The MCP
    server treats it only as a lookup reference; canonical task/delegation state
    still comes from ``TrustedTaskRegistry``.
    """
    run_context = context.run_context.context
    if not isinstance(run_context, AsanteRunContext):
        return None
    return {ASANTE_TASK_META_KEY: run_context.task.task_id}


def build_guest_operations_mcp_client(
    url: str | None = None,
) -> MCPServerStreamableHttp:
    """Create the local Streamable HTTP MCP client used by Guest Support."""
    return MCPServerStreamableHttp(
        name="Asante Guest Operations MCP",
        params={
            "url": url or os.getenv("ASANTE_MCP_URL", DEFAULT_ASANTE_MCP_URL),
            "timeout": 10,
        },
        cache_tools_list=True,
        max_retry_attempts=1,
        use_structured_content=True,
        tool_meta_resolver=resolve_asante_mcp_meta,
    )
