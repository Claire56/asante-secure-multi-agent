"""Low-cardinality security and execution metrics for Phase 5."""

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


def monotonic_time() -> float:
    """Return a monotonic timestamp used for duration measurements."""
    return perf_counter()


def record_authorization(*, effect: str, phase: str, duration_seconds: float) -> None:
    """Record one Ruhusa decision without user, reservation, or prompt data."""
    attrs = {
        "asante.action": "guest.credit.issue",
        "asante.authorization.effect": effect,
        "asante.authorization.phase": phase,
    }
    _authorization_decisions.add(1, attrs)
    _authorization_duration.record(duration_seconds, attrs)


def record_mcp_call(*, outcome: str) -> None:
    """Record one MCP credit-tool call outcome."""
    _mcp_calls.add(
        1,
        {
            "mcp.tool.name": "issue_guest_credit",
            "asante.outcome": outcome,
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
