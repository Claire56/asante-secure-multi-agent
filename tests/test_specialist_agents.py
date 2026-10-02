"""Phase 9 least-privilege specialist-agent regressions."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ruhusa import TaskContext

from asante_secure_multi_agent.agents import (
    build_guest_support_agent,
    build_property_operations_agent,
    build_reservations_agent,
    build_service_recovery_agent,
    build_supervisor_agent,
)
from asante_secure_multi_agent.approvals import SQLiteApprovalStore
from asante_secure_multi_agent.cache import InMemoryCacheStore
from asante_secure_multi_agent.mcp import (
    build_guest_support_mcp_client,
    build_property_operations_mcp_client,
    build_reservations_mcp_client,
    build_service_recovery_mcp_client,
)
from asante_secure_multi_agent.security import (
    build_security_runtime,
    issue_guest_support_message_delegation,
    issue_property_operations_delegation,
    issue_reservations_delegation,
    issue_service_recovery_delegation,
)
from asante_secure_multi_agent.tools import (
    GuestCreditLedger,
    GuestMessageOutbox,
    InMemoryReservationProvider,
    MaintenanceWorkOrderStore,
    SecuredGuestCreditTool,
    SecuredGuestOperationsTool,
    SecuredReservationTool,
)


def _task(prefix: str) -> TaskContext:
    return TaskContext(
        task_id=f"{prefix}-{datetime.now(UTC).timestamp()}",
        initiated_by="oauth:https://dev.asante.local#specialist-test",
        purpose="least-privilege specialist test",
        expires_at=datetime.now(UTC) + timedelta(minutes=30),
    )


def _blocked(operation) -> dict[str, object]:
    try:
        result = operation()
    except Exception:  # noqa: BLE001 - fail-closed exception is acceptable in this regression.
        return {"status": "blocked", "effect": "deny"}
    return result


def _operations_fixture():
    security = build_security_runtime()
    approvals = SQLiteApprovalStore(":memory:")
    maintenance = MaintenanceWorkOrderStore()
    messages = GuestMessageOutbox()
    operations = SecuredGuestOperationsTool(
        security,
        maintenance,
        messages,
        approvals,
    )
    return security, approvals, maintenance, messages, operations


def test_supervisor_exposes_four_bounded_specialist_agent_tools() -> None:
    reservations = build_reservations_agent(build_reservations_mcp_client())
    property_operations = build_property_operations_agent(build_property_operations_mcp_client())
    guest_support = build_guest_support_agent(build_guest_support_mcp_client())
    service_recovery = build_service_recovery_agent(build_service_recovery_mcp_client())

    supervisor = build_supervisor_agent(
        reservations,
        property_operations,
        guest_support,
        service_recovery,
    )

    assert {tool.name for tool in supervisor.tools} == {
        "consult_reservations",
        "dispatch_property_operations",
        "contact_guest_support",
        "handle_service_recovery",
    }


def test_guest_support_cannot_create_maintenance_work_order() -> None:
    security, approvals, maintenance, _, operations = _operations_fixture()
    task = _task("guest-support-maintenance")
    result = _blocked(
        lambda: operations.create_maintenance_request(
            reservation_id="R-3001",
            category="plumbing",
            urgency="high",
            description="Attempted through the wrong specialist authority",
            task=task,
            delegation_chain=issue_guest_support_message_delegation(security, task),
        )
    )

    assert result.get("status") == "blocked"
    assert maintenance.work_orders == []
    approvals.close()


def test_property_operations_cannot_send_guest_message() -> None:
    security, approvals, _, messages, operations = _operations_fixture()
    task = _task("property-ops-message")
    result = _blocked(
        lambda: operations.send_guest_message(
            reservation_id="R-3001",
            message="Attempted through the wrong specialist authority",
            task=task,
            delegation_chain=issue_property_operations_delegation(security, task),
        )
    )

    assert result.get("status") == "blocked"
    assert messages.messages == []
    approvals.close()


def test_reservations_cannot_issue_guest_credit() -> None:
    security = build_security_runtime()
    ledger = GuestCreditLedger()
    tool = SecuredGuestCreditTool(security, ledger)
    task = _task("reservations-credit")
    result = _blocked(
        lambda: tool.issue_credit(
            reservation_id="R-3001",
            amount=20.0,
            reason="Attempted through the wrong specialist authority",
            task=task,
            delegation_chain=issue_reservations_delegation(security, task),
        )
    )

    assert result.get("status") == "blocked"
    assert ledger.credits == []


def test_service_recovery_cannot_read_reservation() -> None:
    security = build_security_runtime()
    provider = InMemoryReservationProvider()
    cache = InMemoryCacheStore()
    tool = SecuredReservationTool(security, provider, cache)
    task = _task("recovery-reservation")
    result = _blocked(
        lambda: tool.get_reservation(
            reservation_id="R-3001",
            task=task,
            delegation_chain=issue_service_recovery_delegation(security, task),
        )
    )

    assert result.get("status") == "blocked"
    assert provider.calls == 0
    assert cache.get_calls == 0
