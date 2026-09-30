"""Small cache abstraction used by the Phase 7 authorization-aware read path."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from time import monotonic
from typing import Protocol


@dataclass(frozen=True)
class CacheLookup:
    """Result of one cache lookup without exposing business identifiers."""

    hit: bool
    value: dict[str, object] | None = None
    age_seconds: float = 0.0
    expired: bool = False


class CacheStore(Protocol):
    """Minimal cache contract so Redis can replace the in-memory store later."""

    def get(self, key: str) -> CacheLookup: ...

    def put(self, key: str, value: dict[str, object], *, ttl_seconds: float) -> None: ...

    def delete(self, key: str) -> None: ...

    def clear(self) -> None: ...


@dataclass
class _CacheEntry:
    value: dict[str, object]
    created_at: float
    expires_at: float


class InMemoryCacheStore:
    """Process-local TTL cache used to prove authorization/cache invariants."""

    def __init__(self) -> None:
        self._entries: dict[str, _CacheEntry] = {}
        self._get_calls = 0

    @property
    def size(self) -> int:
        """Return the number of currently stored entries for diagnostics/tests."""
        return len(self._entries)

    @property
    def get_calls(self) -> int:
        """Return cache-lookup count for deterministic security diagnostics."""
        return self._get_calls

    def get(self, key: str) -> CacheLookup:
        """Return a defensive copy of a live entry, evicting expired entries."""
        self._get_calls += 1
        entry = self._entries.get(key)
        if entry is None:
            return CacheLookup(hit=False)

        now = monotonic()
        age = max(0.0, now - entry.created_at)
        if now >= entry.expires_at:
            self._entries.pop(key, None)
            return CacheLookup(hit=False, age_seconds=age, expired=True)

        return CacheLookup(
            hit=True,
            value=deepcopy(entry.value),
            age_seconds=age,
        )

    def put(self, key: str, value: dict[str, object], *, ttl_seconds: float) -> None:
        """Store one value for a bounded TTL."""
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be greater than zero")
        now = monotonic()
        self._entries[key] = _CacheEntry(
            value=deepcopy(value),
            created_at=now,
            expires_at=now + ttl_seconds,
        )

    def delete(self, key: str) -> None:
        """Delete one cache entry if present."""
        self._entries.pop(key, None)

    def clear(self) -> None:
        """Clear all cache entries."""
        self._entries.clear()
