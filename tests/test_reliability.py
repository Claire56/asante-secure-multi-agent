"""Phase 6 unit tests for bounded retry and server-side idempotency."""

from __future__ import annotations

import pytest

from asante_secure_multi_agent.reliability import (
    RetryPolicy,
    TransientCreditProviderError,
    UnknownOutcomeCreditProviderError,
    build_credit_idempotency_key,
    credit_retry_policy_from_env,
    execute_with_bounded_retry,
    mcp_reliability_config_from_env,
)
from asante_secure_multi_agent.tools import GuestCreditLedger


def test_credit_idempotency_key_is_stable_and_task_bound() -> None:
    first = build_credit_idempotency_key(
        task_id="task-1",
        reservation_id="R-1",
        amount=20.0,
    )
    retry = build_credit_idempotency_key(
        task_id="task-1",
        reservation_id="R-1",
        amount=20,
    )
    other_task = build_credit_idempotency_key(
        task_id="task-2",
        reservation_id="R-1",
        amount=20.0,
    )

    assert first == retry
    assert first != other_task


def test_ledger_deduplicates_same_server_derived_operation() -> None:
    ledger = GuestCreditLedger()
    key = build_credit_idempotency_key(
        task_id="task-1",
        reservation_id="R-1",
        amount=20.0,
    )

    first = ledger.issue(
        reservation_id="R-1",
        amount=20.0,
        reason="Wi-Fi outage",
        idempotency_key=key,
    )
    second = ledger.issue(
        reservation_id="R-1",
        amount=20.0,
        reason="Retry with equivalent side effect",
        idempotency_key=key,
    )

    assert first["deduplicated"] is False
    assert second["deduplicated"] is True
    assert len(ledger.credits) == 1


def test_bounded_retry_retries_only_transient_failures() -> None:
    attempts = 0

    def operation() -> str:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise TransientCreditProviderError("known transient")
        return "ok"

    result = execute_with_bounded_retry(
        operation,
        policy=RetryPolicy(max_attempts=2, initial_backoff_seconds=0),
    )

    assert result == "ok"
    assert attempts == 2


def test_unknown_outcome_is_never_retried() -> None:
    attempts = 0

    def operation() -> None:
        nonlocal attempts
        attempts += 1
        raise UnknownOutcomeCreditProviderError("uncertain outcome")

    with pytest.raises(UnknownOutcomeCreditProviderError):
        execute_with_bounded_retry(
            operation,
            policy=RetryPolicy(max_attempts=4, initial_backoff_seconds=0),
        )

    assert attempts == 1


def test_reliability_environment_settings_are_bounded(monkeypatch) -> None:
    monkeypatch.setenv("ASANTE_CREDIT_MAX_ATTEMPTS", "3")
    monkeypatch.setenv("ASANTE_MCP_TIMEOUT_SECONDS", "15")
    monkeypatch.setenv("ASANTE_MCP_MAX_RETRIES", "2")

    credit = credit_retry_policy_from_env()
    mcp = mcp_reliability_config_from_env()

    assert credit.max_attempts == 3
    assert mcp.timeout_seconds == 15.0
    assert mcp.max_retry_attempts == 2

    monkeypatch.setenv("ASANTE_CREDIT_MAX_ATTEMPTS", "99")
    with pytest.raises(ValueError):
        credit_retry_policy_from_env()
