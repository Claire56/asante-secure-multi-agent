"""Environment-backed reliability configuration with bounded values."""

from __future__ import annotations

import os
from dataclasses import dataclass

from .credit import RetryPolicy


@dataclass(frozen=True)
class McpReliabilityConfig:
    """Timeout and retry budget for the local Streamable HTTP MCP client."""

    timeout_seconds: float = 10.0
    max_retry_attempts: int = 1


def _float_env(name: str, default: float, *, minimum: float, maximum: float) -> float:
    raw = os.getenv(name)
    value = default if raw is None else float(raw)
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _int_env(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = os.getenv(name)
    value = default if raw is None else int(raw)
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def credit_retry_policy_from_env() -> RetryPolicy:
    """Build a bounded provider retry policy from local/deployment settings."""
    return RetryPolicy(
        max_attempts=_int_env(
            "ASANTE_CREDIT_MAX_ATTEMPTS",
            2,
            minimum=1,
            maximum=4,
        ),
        initial_backoff_seconds=_float_env(
            "ASANTE_CREDIT_RETRY_BACKOFF_SECONDS",
            0.05,
            minimum=0.0,
            maximum=2.0,
        ),
        max_backoff_seconds=_float_env(
            "ASANTE_CREDIT_RETRY_MAX_BACKOFF_SECONDS",
            0.2,
            minimum=0.0,
            maximum=5.0,
        ),
    )


def mcp_reliability_config_from_env() -> McpReliabilityConfig:
    """Build bounded MCP transport settings from the environment."""
    return McpReliabilityConfig(
        timeout_seconds=_float_env(
            "ASANTE_MCP_TIMEOUT_SECONDS",
            10.0,
            minimum=1.0,
            maximum=60.0,
        ),
        max_retry_attempts=_int_env(
            "ASANTE_MCP_MAX_RETRIES",
            1,
            minimum=0,
            maximum=3,
        ),
    )
