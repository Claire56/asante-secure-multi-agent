"""Phase 9 specialist-aware product workflow tests."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

from ruhusa import TaskContext

from asante_secure_multi_agent.approvals import SQLiteApprovalStore
from asante_secure_multi_agent.context import AsanteRunContext
from asante_secure_multi_agent.mcp import TrustedTaskRegistry, build_guest_operations_mcp_server
from asante_secure_multi_agent.security import (
    build_security_runtime,
    issue_approval_executor_delegation,
    issue_guest_support_message_delegation,
    issue_property_operations_delegation,
    issue_reservations_delegation,
    issue_service_recovery_credit_request_delegation,
    issue_service_recovery_delegation,
)
from asante_secure_multi_agent.tools import (
    ApprovedCreditExecutor,
    GuestCreditLedger,
    GuestMessageOutbox,
    MaintenanceWorkOrderStore,
    SecuredGuestCreditTool,
    SecuredGuestOperationsTool,
)


def _task(prefix: str = "ops") -> TaskContext:
    return TaskContext(
        task_id=f"{prefix}-{uuid4().hex}",
        initiated_by="oauth:https://dev.asante.local#claire",
        purpose="property operations test",
        expires_at=datetime.now(UTC) + timedelta(minutes=30),
    )


def _operations_fixture():
    security = build_security_runtime()
    maintenance = MaintenanceWorkOrderStore()
    messages = GuestMessageOutbox()
    approvals = SQLiteApprovalStore(":memory:")
    tool = SecuredGuestOperationsTool(security, maintenance, messages, approvals)
    return security, maintenance, messages, approvals, tool


def test_maintenance_request_is_authorized_and_persisted() -> None:
    security, maintenance, _, approvals, tool = _operations_fixture()
    task = _task()
    result = tool.create_maintenance_request(
        reservation_id="R-3001",
        category="plumbing",
        urgency="high",
        description="Guest reports no hot water for two hours",
        task=task,
        delegation_chain=issue_property_operations_delegation(security, task),
    )

    assert result["status"] == "open"
    assert result["effect"] == "allow"
    assert len(maintenance.work_orders) == 1
    approvals.close()


def test_guest_message_is_authorized_and_idempotent_within_task() -> None:
    security, _, messages, approvals, tool = _operations_fixture()
    task = _task()
    chain = issue_guest_support_message_delegation(security, task)

    first = tool.send_guest_message(
        reservation_id="R-3001",
        message="We have created an urgent maintenance request and will update you shortly.",
        task=task,
        delegation_chain=chain,
    )
    second = tool.send_guest_message(
        reservation_id="R-3001",
        message="We have created an urgent maintenance request and will update you shortly.",
        task=task,
        delegation_chain=chain,
    )

    assert first["status"] == "sent"
    assert first["deduplicated"] is False
    assert second["deduplicated"] is True
    assert len(messages.messages) == 1
    approvals.close()


def test_larger_credit_creates_approval_without_credit_side_effect() -> None:
    security, _, _, approvals, operations_tool = _operations_fixture()
    ledger = GuestCreditLedger()
    task = _task("approval-request")

    result = operations_tool.request_guest_credit(
        reservation_id="R-3001",
        amount=75.0,
        reason="Extended hot-water outage",
        task=task,
        delegation_chain=issue_service_recovery_credit_request_delegation(security, task),
    )

    assert result["status"] == "approval_pending"
    assert result["effect"] == "allow"
    assert ledger.credits == []
    record = approvals.require(str(result["approval_id"]))
    assert record.status == "pending"
    assert record.amount == 75.0
    approvals.close()


def test_repeated_credit_request_in_one_task_reuses_the_approval() -> None:
    """A retried request must not create a second approvable (and executable) credit."""
    security, _, _, approvals, operations_tool = _operations_fixture()
    task = _task("approval-dedup")

    def request() -> dict[str, object]:
        return operations_tool.request_guest_credit(
            reservation_id="R-3001",
            amount=75.0,
            reason="Extended hot-water outage",
            task=task,
            delegation_chain=issue_service_recovery_credit_request_delegation(security, task),
        )

    first = request()
    second = request()

    assert first["deduplicated"] is False
    assert second["deduplicated"] is True
    assert second["approval_id"] == first["approval_id"]
    assert second["status"] == "approval_pending"
    assert len(approvals.list_requests()) == 1

    other_task = _task("approval-dedup-other")
    third = operations_tool.request_guest_credit(
        reservation_id="R-3001",
        amount=75.0,
        reason="Extended hot-water outage",
        task=other_task,
        delegation_chain=issue_service_recovery_credit_request_delegation(security, other_task),
    )
    assert third["approval_id"] != first["approval_id"]
    assert len(approvals.list_requests()) == 2
    approvals.close()


def test_credit_request_above_human_approval_limit_is_denied() -> None:
    security, _, _, approvals, operations_tool = _operations_fixture()
    task = _task("oversized-request")
    result = operations_tool.request_guest_credit(
        reservation_id="R-3001",
        amount=150.0,
        reason="Oversized requested credit",
        task=task,
        delegation_chain=issue_service_recovery_credit_request_delegation(security, task),
    )

    assert result["status"] == "blocked"
    assert approvals.list_requests() == []
    approvals.close()


def test_human_approval_executes_credit_once() -> None:
    security, _, _, approvals, operations_tool = _operations_fixture()
    ledger = GuestCreditLedger()
    executor = ApprovedCreditExecutor(security, ledger, approvals)
    request_task = _task("request")
    requested = operations_tool.request_guest_credit(
        reservation_id="R-3001",
        amount=75.0,
        reason="Extended service outage",
        task=request_task,
        delegation_chain=issue_service_recovery_credit_request_delegation(security, request_task),
    )
    approval_id = str(requested["approval_id"])
    approved = approvals.decide(
        approval_id,
        approved=True,
        decided_by="oauth:https://dev.asante.local#manager",
        note="Approved after reviewing outage duration",
    )

    execution_task = TaskContext(
        task_id=f"execute-{uuid4().hex}",
        initiated_by="oauth:https://dev.asante.local#manager",
        purpose="execute approved credit",
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
    )
    first = executor.execute(
        approval=approved,
        task=execution_task,
        delegation_chain=issue_approval_executor_delegation(security, execution_task),
    )
    second = executor.execute(
        approval=approvals.require(approval_id),
        task=execution_task,
        delegation_chain=issue_approval_executor_delegation(security, execution_task),
    )

    assert first["status"] == "issued"
    assert len(ledger.credits) == 1
    assert approvals.require(approval_id).status == "executed"
    assert second["deduplicated"] is True
    assert len(ledger.credits) == 1
    approvals.close()


def test_human_denial_never_executes_credit() -> None:
    security, _, _, approvals, operations_tool = _operations_fixture()
    ledger = GuestCreditLedger()
    executor = ApprovedCreditExecutor(security, ledger, approvals)
    request_task = _task("deny-request")
    requested = operations_tool.request_guest_credit(
        reservation_id="R-3001",
        amount=60.0,
        reason="Service complaint",
        task=request_task,
        delegation_chain=issue_service_recovery_credit_request_delegation(security, request_task),
    )
    record = approvals.decide(
        str(requested["approval_id"]),
        approved=False,
        decided_by="oauth:https://dev.asante.local#manager",
    )
    execution_task = _task("denied-execution")
    result = executor.execute(
        approval=record,
        task=execution_task,
        delegation_chain=issue_approval_executor_delegation(security, execution_task),
    )

    assert result["status"] == "blocked"
    assert ledger.credits == []
    approvals.close()


def test_approval_record_survives_store_reopen() -> None:
    with TemporaryDirectory() as directory:
        path = Path(directory) / "approvals.db"
        store = SQLiteApprovalStore(path)
        record = store.create_credit_request(
            task_id="task-1",
            requested_by="oauth:https://dev.asante.local#claire",
            reservation_id="R-3001",
            amount=75.0,
            reason="Extended outage",
            policy_id="service-recovery-credit-request",
        )
        store.close()

        reopened = SQLiteApprovalStore(path)
        persisted = reopened.require(record.approval_id)
        assert persisted.status == "pending"
        assert persisted.reservation_id == "R-3001"
        reopened.close()


def test_mcp_product_tool_schemas_hide_authority() -> None:
    security, maintenance, messages, approvals, operations_tool = _operations_fixture()
    task = _task("mcp-product")
    context = AsanteRunContext(
        task=task,
        reservations_delegation=issue_reservations_delegation(security, task),
        property_operations_delegation=issue_property_operations_delegation(security, task),
        guest_support_message_delegation=issue_guest_support_message_delegation(security, task),
        service_recovery_delegation=issue_service_recovery_delegation(security, task),
        service_recovery_credit_request_delegation=(
            issue_service_recovery_credit_request_delegation(security, task)
        ),
    )
    registry = TrustedTaskRegistry()
    registry.register(context)
    server = build_guest_operations_mcp_server(
        SecuredGuestCreditTool(security, GuestCreditLedger()),
        registry,
        operations_tool=operations_tool,
    )

    tools = asyncio.run(server.list_tools())
    schemas = {tool.name: set(tool.input_schema.get("properties", {})) for tool in tools}

    assert schemas["create_maintenance_request"] == {
        "reservation_id",
        "category",
        "urgency",
        "description",
    }
    assert schemas["send_guest_message"] == {"reservation_id", "message"}
    assert schemas["request_guest_credit"] == {"reservation_id", "amount", "reason"}
    forbidden = {"task_id", "delegation_chain", "principal_id", "grant_id", "approval_verified"}
    assert all(not fields & forbidden for fields in schemas.values())
    assert maintenance.work_orders == []
    assert messages.messages == []
    approvals.close()
