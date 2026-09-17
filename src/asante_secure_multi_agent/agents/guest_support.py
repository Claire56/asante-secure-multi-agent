"""Guest-support specialist whose business actions are exposed through MCP.

Phase 3 moved the credit surface from a local ``function_tool`` to MCP. The agent discovers
and calls ``issue_guest_credit`` from the Asante Guest Operations MCP server;
Ruhusa remains behind that MCP boundary and independently decides whether the
side effect may execute.
"""

from __future__ import annotations

from agents import Agent
from agents.mcp import MCPServerStreamableHttp


def build_guest_support_agent(mcp_server: MCPServerStreamableHttp) -> Agent:
    """Create Guest Support using the secured Asante MCP tool surface."""
    return Agent(
        name="Asante Guest Support Agent",
        handoff_description="Handles guest support and service-recovery requests.",
        instructions=(
            "You handle Asante guest-support requests. Use the MCP tools for real actions. "
            "Never claim a credit was issued unless the MCP tool returns status='issued'. "
            "A handoff does not give you unlimited authority: Ruhusa validates the canonical "
            "delegation chain behind the MCP server. If an action is blocked or requires "
            "approval, explain that outcome and do not alter the amount or retry to bypass it."
        ),
        mcp_servers=[mcp_server],
        mcp_config={
            "convert_schemas_to_strict": True,
            "include_server_in_tool_names": True,
        },
    )
