"""Stable opaque cache-key derivation for authorized reservation reads."""

from __future__ import annotations

import hashlib

RESERVATION_CACHE_SCHEMA_VERSION = "reservation-read-v1"


def build_reservation_cache_key(
    reservation_id: str,
    *,
    schema_version: str = RESERVATION_CACHE_SCHEMA_VERSION,
) -> str:
    """Build an opaque key from stable resource semantics, not task/grant IDs.

    Authorization is re-evaluated before every cache lookup. Therefore revocation
    safety does not depend on encoding an ephemeral task or grant into the key.
    """
    canonical = f"{schema_version}\nreservation.read\nreservation:{reservation_id}"
    return "reservation:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
