"""Low-cardinality security, execution, and cache metrics."""

from __future__ import annotations

from time import perf_counter

from .runtime import get_meter

_meter = get_meter()
_authorization_decisions = _meter.create_counter(
    "asante.authorization.decisions",
    unit="1",
    description="Ruhusa authorization outcomes observed by the application.",
)
_authorization_duration = _meter.create_histogram(
    "asante.authorization.duration",
    unit="s",
    description="Time spent in Ruhusa authorization/revalidation phases.",
)
_mcp_calls = _meter.create_counter(
    "asante.mcp.tool.calls",
    unit="1",
    description="Asante MCP tool calls by outcome.",
)
_credit_executions = _meter.create_counter(
    "asante.credit.executions",
    unit="1",
    description="Guest-credit protected side-effect outcomes.",
)
_credit_retries = _meter.create_counter(
    "asante.credit.retries",
    unit="1",
    description="Known-safe transient credit-provider retries.",
)
_credit_deduplications = _meter.create_counter(
    "asante.credit.idempotency_deduplications",
    unit="1",
    description="Repeated logical credit operations suppressed by idempotency.",
)
_cache_lookups = _meter.create_counter(
    "asante.cache.lookups",
    unit="1",
    description="Authorization-aware application-cache lookups by result.",
)
_cache_denied_before_lookup = _meter.create_counter(
    "asante.cache.denied_before_lookup",
    unit="1",
    description="Reservation reads denied before sensitive cache access.",
)
_operation_executions = _meter.create_counter(
    "asante.operations.executions",
    unit="1",
    description="Guest operations such as maintenance, messaging, and approval requests.",
)


def monotonic_time() -> float:
    """Return a monotonic timestamp used for duration measurements."""
    return perf_counter()


def record_authorization(
    *,
    effect: str,
    phase: str,
    duration_seconds: float,
    action: str = "guest.credit.issue",
) -> None:
    """Record one Ruhusa decision without user, resource, or prompt data."""
    attrs = {
        "asante.action": action,
        "asante.authorization.effect": effect,
        "asante.authorization.phase": phase,
    }
    _authorization_decisions.add(1, attrs)
    _authorization_duration.record(duration_seconds, attrs)


def record_mcp_call(*, outcome: str, tool_name: str = "issue_guest_credit") -> None:
    """Record one MCP tool-call outcome using a low-cardinality tool name."""
    _mcp_calls.add(
        1,
        {
            "mcp.tool.name": tool_name,
            "asante.outcome": outcome,
        },
    )


def record_cache_lookup(*, hit: bool, expired: bool = False) -> None:
    """Record cache behavior without business identifiers or cached values."""
    outcome = "hit" if hit else "expired" if expired else "miss"
    _cache_lookups.add(
        1,
        {
            "asante.cache.kind": "reservation",
            "asante.cache.outcome": outcome,
        },
    )


def record_cache_denied_before_lookup(*, phase: str) -> None:
    """Record a Ruhusa denial that prevented cache access entirely."""
    _cache_denied_before_lookup.add(
        1,
        {
            "asante.cache.kind": "reservation",
            "asante.authorization.phase": phase,
        },
    )


def record_credit_execution(*, outcome: str) -> None:
    """Record one protected credit side-effect outcome."""
    _credit_executions.add(
        1,
        {
            "asante.action": "guest.credit.issue",
            "asante.outcome": outcome,
        },
    )


def record_credit_retry(*, attempt: int) -> None:
    """Record a bounded retry without high-cardinality business identifiers."""
    _credit_retries.add(
        1,
        {
            "asante.action": "guest.credit.issue",
            "asante.retry.attempt": attempt,
        },
    )


def record_credit_deduplication() -> None:
    """Record one idempotency suppression event."""
    _credit_deduplications.add(
        1,
        {"asante.action": "guest.credit.issue"},
    )


def record_operation_execution(*, action: str, outcome: str) -> None:
    """Record one protected guest-operation outcome."""
    _operation_executions.add(
        1,
        {
            "asante.action": action,
            "asante.outcome": outcome,
        },
    )
