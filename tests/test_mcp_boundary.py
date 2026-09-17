"""Phase 3 tests for the MCP trust boundary around Ruhusa-secured tools."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from ruhusa import TaskContext

from asante_secure_multi_agent.context import AsanteRunContext
from asante_secure_multi_agent.mcp import (
    ASANTE_TASK_META_KEY,
    TrustedTaskNotFoundError,
    TrustedTaskRegistry,
    build_guest_operations_mcp_server,
    issue_guest_credit_for_trusted_task,
    resolve_asante_mcp_meta,
)
from asante_secure_multi_agent.security import (
    build_security_runtime,
    issue_guest_support_delegation,
)
from asante_secure_multi_agent.tools import GuestCreditLedger, SecuredGuestCreditTool


def _trusted_context() -> tuple[AsanteRunContext, SecuredGuestCreditTool, GuestCreditLedger]:
    """Create canonical task authority plus the secured service under test."""
    security = build_security_runtime()
    ledger = GuestCreditLedger()
    credit_tool = SecuredGuestCreditTool(security, ledger)
    task = TaskContext(
        task_id=f"task-mcp-{uuid4().hex}",
        initiated_by="user:claire",
        purpose="guest service recovery",
        expires_at=datetime.now(UTC) + timedelta(minutes=30),
    )
    context = AsanteRunContext(
        task=task,
        guest_support_delegation=issue_guest_support_delegation(security, task),
    )
    return context, credit_tool, ledger


def test_registry_resolves_only_registered_canonical_task_state() -> None:
    """The MCP layer fails closed when no trusted task state exists."""
    registry = TrustedTaskRegistry()
    context, _, _ = _trusted_context()

    with pytest.raises(TrustedTaskNotFoundError):
        registry.require(context.task.task_id)

    registry.register(context)
    assert registry.require(context.task.task_id) is context

    registry.unregister(context.task.task_id)
    with pytest.raises(TrustedTaskNotFoundError):
        registry.require(context.task.task_id)


def test_mcp_meta_resolver_injects_task_reference_outside_tool_arguments() -> None:
    """The Agents SDK metadata resolver carries only a hidden task reference."""
    context, _, _ = _trusted_context()
    fake_meta_context = SimpleNamespace(
        run_context=SimpleNamespace(context=context),
    )

    meta = resolve_asante_mcp_meta(fake_meta_context)

    assert meta == {ASANTE_TASK_META_KEY: context.task.task_id}


def test_mcp_tool_schema_does_not_expose_task_or_grant_authority_to_model() -> None:
    """Security context must not appear in the model-visible MCP input schema."""
    context, credit_tool, _ = _trusted_context()
    registry = TrustedTaskRegistry()
    registry.register(context)
    server = build_guest_operations_mcp_server(credit_tool, registry)

    tools = asyncio.run(server.list_tools())
    tool = next(item for item in tools if item.name == "issue_guest_credit")
    properties = tool.input_schema.get("properties", {})

    assert set(properties) == {"reservation_id", "amount", "reason"}
    assert "task_id" not in properties
    assert "delegation_chain" not in properties
    assert "principal_id" not in properties


def test_mcp_boundary_executes_using_server_side_canonical_authority() -> None:
    """A valid hidden task reference resolves authority and reaches Ruhusa."""
    context, credit_tool, ledger = _trusted_context()
    registry = TrustedTaskRegistry()
    registry.register(context)

    result = issue_guest_credit_for_trusted_task(
        credit_tool=credit_tool,
        task_registry=registry,
        task_id=context.task.task_id,
        reservation_id="R-MCP-1001",
        amount=20.0,
        reason="Wi-Fi outage",
    )

    assert result["status"] == "issued"
    assert result["effect"] == "allow"
    assert len(ledger.credits) == 1


def test_mcp_boundary_preserves_delegation_limit() -> None:
    """Moving the action behind MCP cannot expand Guest Support authority."""
    context, credit_tool, ledger = _trusted_context()
    registry = TrustedTaskRegistry()
    registry.register(context)

    result = issue_guest_credit_for_trusted_task(
        credit_tool=credit_tool,
        task_registry=registry,
        task_id=context.task.task_id,
        reservation_id="R-MCP-1002",
        amount=40.0,
        reason="Extended Wi-Fi outage",
    )

    assert result["status"] == "blocked"
    assert result["effect"] == "deny"
    assert ledger.credits == []
