"""Phase 7 authorization-aware cache security and behavior tests."""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from ruhusa import TaskContext

from asante_secure_multi_agent.cache import (
    InMemoryCacheStore,
    build_reservation_cache_key,
)
from asante_secure_multi_agent.context import AsanteRunContext
from asante_secure_multi_agent.mcp import TrustedTaskRegistry, build_guest_operations_mcp_server
from asante_secure_multi_agent.security import (
    build_security_runtime,
    issue_guest_support_message_delegation,
    issue_property_operations_delegation,
    issue_reservations_delegation,
    issue_service_recovery_credit_request_delegation,
    issue_service_recovery_delegation,
)
from asante_secure_multi_agent.tools import (
    GuestCreditLedger,
    InMemoryReservationProvider,
    SecuredGuestCreditTool,
    SecuredReservationTool,
)


def _task(prefix: str = "cache") -> TaskContext:
    return TaskContext(
        task_id=f"{prefix}-{uuid4().hex}",
        initiated_by="oauth:https://dev.asante.local#claire",
        purpose="authorization-aware cache test",
        expires_at=datetime.now(UTC) + timedelta(minutes=30),
    )


def _secured_reader(*, ttl: float = 300.0):
    security = build_security_runtime()
    cache = InMemoryCacheStore()
    provider = InMemoryReservationProvider()
    tool = SecuredReservationTool(
        security,
        provider,
        cache,
        cache_ttl_seconds=ttl,
    )
    task = _task()
    chain = issue_reservations_delegation(security, task)
    return security, cache, provider, tool, task, chain


def test_first_authorized_read_misses_then_repeat_hits_cache() -> None:
    security, cache, provider, tool, task, chain = _secured_reader()
    del security

    first = tool.get_reservation(
        reservation_id="R-3001",
        task=task,
        delegation_chain=chain,
    )
    second = tool.get_reservation(
        reservation_id="R-3001",
        task=task,
        delegation_chain=chain,
    )

    assert first["status"] == "found"
    assert first["cache"] == "miss"
    assert second["status"] == "found"
    assert second["cache"] == "hit"
    assert provider.calls == 1
    assert cache.size == 1


def test_different_reservation_is_a_cache_miss() -> None:
    _, cache, provider, tool, task, chain = _secured_reader()

    first = tool.get_reservation(
        reservation_id="R-3001",
        task=task,
        delegation_chain=chain,
    )
    second = tool.get_reservation(
        reservation_id="R-3002",
        task=task,
        delegation_chain=chain,
    )

    assert first["cache"] == "miss"
    assert second["cache"] == "miss"
    assert provider.calls == 2
    assert cache.size == 2


def test_revoked_grant_cannot_disclose_previously_cached_reservation() -> None:
    security, cache, provider, tool, task, chain = _secured_reader()

    first = tool.get_reservation(
        reservation_id="R-3001",
        task=task,
        delegation_chain=chain,
    )
    assert first["cache"] == "miss"
    assert cache.size == 1
    assert provider.calls == 1

    security.authorizer.revoke_grant(
        chain[-1].grant_id,
        reason="operator withdrew reservations authority",
    )

    blocked = tool.get_reservation(
        reservation_id="R-3001",
        task=task,
        delegation_chain=chain,
    )

    assert blocked["status"] == "blocked"
    assert blocked["effect"] == "deny"
    assert "reservation" not in blocked
    assert provider.calls == 1
    assert cache.get_calls == 1
    # The sensitive value is still physically cached; live authorization is what blocks it.
    assert cache.size == 1


def test_cross_task_replay_cannot_reach_cached_data() -> None:
    security, cache, provider, tool, original_task, original_chain = _secured_reader()

    first = tool.get_reservation(
        reservation_id="R-3001",
        task=original_task,
        delegation_chain=original_chain,
    )
    assert first["cache"] == "miss"
    assert cache.size == 1

    replay_task = _task("replay")
    try:
        result = tool.get_reservation(
            reservation_id="R-3001",
            task=replay_task,
            delegation_chain=original_chain,
        )
    except Exception:  # noqa: BLE001 - Ruhusa may fail closed by exception or DENY.
        result = {"status": "blocked", "effect": "deny"}

    assert result["status"] == "blocked"
    assert "reservation" not in result
    assert provider.calls == 1
    assert cache.get_calls == 1
    assert cache.size == 1
    del security


def test_expired_cache_entry_refreshes_from_provider() -> None:
    _, _, provider, tool, task, chain = _secured_reader(ttl=0.01)

    first = tool.get_reservation(
        reservation_id="R-3001",
        task=task,
        delegation_chain=chain,
    )
    time.sleep(0.02)
    second = tool.get_reservation(
        reservation_id="R-3001",
        task=task,
        delegation_chain=chain,
    )

    assert first["cache"] == "miss"
    assert second["cache"] == "miss"
    assert provider.calls == 2


def test_cache_schema_version_change_produces_different_key() -> None:
    v1 = build_reservation_cache_key("R-3001", schema_version="reservation-read-v1")
    v2 = build_reservation_cache_key("R-3001", schema_version="reservation-read-v2")

    assert v1 != v2
    assert "R-3001" not in v1
    assert "R-3001" not in v2


def test_mcp_reservation_schema_hides_authority() -> None:
    security = build_security_runtime()
    task = _task("mcp-cache")
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
    reservation_tool = SecuredReservationTool(
        security,
        InMemoryReservationProvider(),
        InMemoryCacheStore(),
    )
    server = build_guest_operations_mcp_server(
        SecuredGuestCreditTool(security, GuestCreditLedger()),
        registry,
        reservation_tool,
    )

    tools = asyncio.run(server.list_tools())
    tool = next(item for item in tools if item.name == "get_reservation")
    properties = set(tool.input_schema.get("properties", {}))

    assert properties == {"reservation_id"}
    assert not properties & {"task_id", "delegation_chain", "principal_id", "grant_id", "cache_key"}
