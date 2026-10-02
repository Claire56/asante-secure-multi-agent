"""Runtime specialist boundaries exercised through real MCP calls.

``test_specialist_agents.py`` proves Ruhusa denies a tool when it is handed the wrong
specialist's delegation chain. At runtime, however, the MCP server always binds each
tool to its own specialist's chain, so the barriers that actually stop a specialist
from invoking another specialist's tool are:

1. the client-side static tool filter (the model never sees the tool), and
2. the server-side workload check on the trusted ``_meta`` label.

These tests exercise both barriers directly, so a regression in either fails CI.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable

import pytest
from mcp.client.client import Client
from test_mcp_boundary import _trusted_context

from asante_secure_multi_agent.approvals import SQLiteApprovalStore
from asante_secure_multi_agent.cache import InMemoryCacheStore
from asante_secure_multi_agent.identity import (
    GUEST_SUPPORT_WORKLOAD,
    PROPERTY_OPERATIONS_WORKLOAD,
    RESERVATIONS_WORKLOAD,
    SERVICE_RECOVERY_WORKLOAD,
)
from asante_secure_multi_agent.mcp import (
    ASANTE_TASK_META_KEY,
    ASANTE_WORKLOAD_META_KEY,
    TrustedTaskRegistry,
    build_guest_operations_mcp_server,
    build_guest_support_mcp_client,
    build_property_operations_mcp_client,
    build_reservations_mcp_client,
    build_service_recovery_mcp_client,
)
from asante_secure_multi_agent.tools import (
    GuestMessageOutbox,
    InMemoryReservationProvider,
    MaintenanceWorkOrderStore,
    SecuredGuestOperationsTool,
    SecuredReservationTool,
)

SPECIALISTS = (
    RESERVATIONS_WORKLOAD,
    PROPERTY_OPERATIONS_WORKLOAD,
    GUEST_SUPPORT_WORKLOAD,
    SERVICE_RECOVERY_WORKLOAD,
)

# tool name -> (owning workload, valid arguments)
TOOLS: dict[str, tuple[str, dict[str, object]]] = {
    "get_reservation": (RESERVATIONS_WORKLOAD, {"reservation_id": "R-3001"}),
    "create_maintenance_request": (
        PROPERTY_OPERATIONS_WORKLOAD,
        {
            "reservation_id": "R-3001",
            "category": "plumbing",
            "urgency": "high",
            "description": "No hot water",
        },
    ),
    "send_guest_message": (
        GUEST_SUPPORT_WORKLOAD,
        {"reservation_id": "R-3001", "message": "A technician is on the way."},
    ),
    "issue_guest_credit": (
        SERVICE_RECOVERY_WORKLOAD,
        {"reservation_id": "R-3001", "amount": 20.0, "reason": "No hot water"},
    ),
    "request_guest_credit": (
        SERVICE_RECOVERY_WORKLOAD,
        {"reservation_id": "R-3001", "amount": 75.0, "reason": "No hot water"},
    ),
}

CROSS_AGENT_ATTEMPTS = [
    (tool, caller)
    for tool, (owner, _) in TOOLS.items()
    for caller in SPECIALISTS
    if caller != owner
]


class _Harness:
    """One MCP server wired to fresh providers so side effects can be counted."""

    def __init__(self) -> None:
        context, credit_tool, ledger = _trusted_context()
        security = credit_tool.security
        self.ledger = ledger
        self.task_id = context.task.task_id
        self.provider = InMemoryReservationProvider()
        self.maintenance = MaintenanceWorkOrderStore()
        self.messages = GuestMessageOutbox()
        self.approvals = SQLiteApprovalStore(":memory:")
        registry = TrustedTaskRegistry()
        registry.register(context)
        self.server = build_guest_operations_mcp_server(
            credit_tool,
            registry,
            SecuredReservationTool(security, self.provider, InMemoryCacheStore()),
            SecuredGuestOperationsTool(security, self.maintenance, self.messages, self.approvals),
        )

    def side_effects(self) -> int:
        return (
            self.provider.calls
            + len(self.maintenance.work_orders)
            + len(self.messages.messages)
            + len(self.ledger.credits)
            + len(self.approvals.list_requests())
        )

    def call(self, tool: str, meta: dict[str, str]):
        async def run():
            async with Client(self.server) as client:
                return await client.call_tool(tool, TOOLS[tool][1], meta=meta)

        return asyncio.run(run())


@pytest.mark.parametrize(("tool", "caller"), CROSS_AGENT_ATTEMPTS)
def test_server_rejects_tool_called_by_another_specialist(tool: str, caller: str) -> None:
    harness = _Harness()

    result = harness.call(
        tool,
        {ASANTE_TASK_META_KEY: harness.task_id, ASANTE_WORKLOAD_META_KEY: caller},
    )

    assert result.is_error
    assert "not available to workload" in str(result.content)
    assert harness.side_effects() == 0
    harness.approvals.close()


@pytest.mark.parametrize("tool", sorted(TOOLS))
def test_server_rejects_call_without_workload_label(tool: str) -> None:
    harness = _Harness()

    result = harness.call(tool, {ASANTE_TASK_META_KEY: harness.task_id})

    assert result.is_error
    assert harness.side_effects() == 0
    harness.approvals.close()


@pytest.mark.parametrize("tool", sorted(TOOLS))
def test_owning_specialist_can_call_its_tool(tool: str) -> None:
    """Positive control: the rejections above are about the caller, not the tool."""
    harness = _Harness()
    owner = TOOLS[tool][0]

    result = harness.call(
        tool,
        {ASANTE_TASK_META_KEY: harness.task_id, ASANTE_WORKLOAD_META_KEY: owner},
    )

    assert not result.is_error, result.content
    assert harness.side_effects() >= 1
    harness.approvals.close()


@pytest.mark.parametrize(
    ("build_client", "expected_tools"),
    [
        (build_reservations_mcp_client, {"get_reservation"}),
        (build_property_operations_mcp_client, {"create_maintenance_request"}),
        (build_guest_support_mcp_client, {"send_guest_message"}),
        (
            build_service_recovery_mcp_client,
            {"issue_guest_credit", "request_guest_credit"},
        ),
    ],
)
def test_specialist_client_exposes_only_its_own_tools(
    build_client: Callable, expected_tools: set[str]
) -> None:
    tool_filter = build_client().tool_filter

    assert set(tool_filter["allowed_tool_names"]) == expected_tools
    assert not tool_filter.get("blocked_tool_names")


def test_specialist_tool_filters_are_disjoint_and_cover_every_server_tool() -> None:
    filters = [
        set(build().tool_filter["allowed_tool_names"])
        for build in (
            build_reservations_mcp_client,
            build_property_operations_mcp_client,
            build_guest_support_mcp_client,
            build_service_recovery_mcp_client,
        )
    ]
    harness = _Harness()
    server_tools = {tool.name for tool in asyncio.run(harness.server.list_tools())}

    assert sum(len(f) for f in filters) == len(set().union(*filters))
    assert set().union(*filters) == server_tools == set(TOOLS)
    harness.approvals.close()
