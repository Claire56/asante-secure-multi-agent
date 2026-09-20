"""Bounded retry and idempotency helpers for protected credit execution.

Phase 6 keeps retries outside Ruhusa's authorization decision. Authorization is
still performed before execution and immediately revalidated before the side
effect. This module only governs how a *known-safe-to-retry* provider failure is
handled after that security boundary has admitted the action.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol


class CreditProvider(Protocol):
    """Minimal external credit-provider contract used by the secured tool."""

    def issue(
        self,
        *,
        reservation_id: str,
        amount: float,
        reason: str,
        idempotency_key: str | None = None,
    ) -> dict[str, object]: ...


class TransientCreditProviderError(RuntimeError):
    """Known pre-execution/transient failure that is safe to retry."""


class UnknownOutcomeCreditProviderError(RuntimeError):
    """Failure where the caller cannot know whether the provider executed."""


@dataclass(frozen=True)
class RetryPolicy:
    """Small deterministic retry budget for known transient provider failures."""

    max_attempts: int = 2
    initial_backoff_seconds: float = 0.05
    max_backoff_seconds: float = 0.2

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        if self.initial_backoff_seconds < 0:
            raise ValueError("initial_backoff_seconds cannot be negative")
        if self.max_backoff_seconds < 0:
            raise ValueError("max_backoff_seconds cannot be negative")


def build_credit_idempotency_key(
    *,
    task_id: str,
    reservation_id: str,
    amount: float,
) -> str:
    """Derive a server-side key for one logical credit within one trusted task.

    The key is intentionally not model supplied. The human/agent can retry the
    same logical action, but cannot choose a key that aliases another task.
    """
    canonical = f"guest.credit.issue\n{task_id}\n{reservation_id}\n{amount:.2f}"
    return "credit:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def execute_with_bounded_retry[T](
    operation: Callable[[], T],
    *,
    policy: RetryPolicy,
    on_retry: Callable[[int], None] | None = None,
) -> T:
    """Retry only explicit transient errors; never retry unknown outcomes."""
    for attempt in range(1, policy.max_attempts + 1):
        try:
            return operation()
        except TransientCreditProviderError:
            if attempt >= policy.max_attempts:
                raise
            if on_retry is not None:
                on_retry(attempt)
            backoff = min(
                policy.initial_backoff_seconds * (2 ** (attempt - 1)),
                policy.max_backoff_seconds,
            )
            if backoff > 0:
                time.sleep(backoff)

    raise AssertionError("retry loop exited unexpectedly")
