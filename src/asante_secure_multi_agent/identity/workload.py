"""Trusted workload identity abstraction for Asante agents and services.

Phase 9 assigns a distinct SPIFFE ID to every specialist agent so prompt-level
roles and authorization identities stay separate. The current agents and MCP
server still share one process, so trusted runtime code assigns canonical
identities. When components are split into separate workloads, this provider is
the seam where SPIRE/SVID verification replaces static assignment.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlparse

SUPERVISOR_WORKLOAD = "supervisor"
GUEST_SUPPORT_WORKLOAD = "guest-support"
PROPERTY_OPERATIONS_WORKLOAD = "property-operations"
RESERVATIONS_WORKLOAD = "reservations"
SERVICE_RECOVERY_WORKLOAD = "service-recovery"
APPROVAL_EXECUTOR_WORKLOAD = "approval-executor"
DEFAULT_SPIFFE_TRUST_DOMAIN = "asante.jamiiz.io"


@dataclass(frozen=True)
class WorkloadIdentity:
    """Canonical identity assigned to a trusted application workload."""

    workload: str
    principal_id: str


class WorkloadIdentityProvider(Protocol):
    """Resolve trusted runtime workload names to canonical principal IDs."""

    def require(self, workload: str) -> WorkloadIdentity:
        """Return canonical identity or fail closed for an unknown workload."""


def _spiffe_id(trust_domain: str, path: str) -> str:
    """Construct and minimally validate a SPIFFE ID URI."""
    value = f"spiffe://{trust_domain}/{path.lstrip('/')}"
    parsed = urlparse(value)
    if parsed.scheme != "spiffe" or not parsed.netloc or not parsed.path:
        raise ValueError("invalid SPIFFE identity")
    if parsed.query or parsed.fragment:
        raise ValueError("SPIFFE identity cannot contain query or fragment")
    return value


class StaticSpiffeWorkloadIdentityProvider:
    """Trusted in-process SPIFFE-ID assignment used until workloads are split."""

    def __init__(self, trust_domain: str | None = None) -> None:
        domain = trust_domain or os.getenv(
            "ASANTE_SPIFFE_TRUST_DOMAIN",
            DEFAULT_SPIFFE_TRUST_DOMAIN,
        )
        self._identities = {
            SUPERVISOR_WORKLOAD: WorkloadIdentity(
                workload=SUPERVISOR_WORKLOAD,
                principal_id=_spiffe_id(domain, "agents/supervisor"),
            ),
            GUEST_SUPPORT_WORKLOAD: WorkloadIdentity(
                workload=GUEST_SUPPORT_WORKLOAD,
                principal_id=_spiffe_id(domain, "agents/guest-support"),
            ),
            PROPERTY_OPERATIONS_WORKLOAD: WorkloadIdentity(
                workload=PROPERTY_OPERATIONS_WORKLOAD,
                principal_id=_spiffe_id(domain, "agents/property-operations"),
            ),
            RESERVATIONS_WORKLOAD: WorkloadIdentity(
                workload=RESERVATIONS_WORKLOAD,
                principal_id=_spiffe_id(domain, "agents/reservations"),
            ),
            SERVICE_RECOVERY_WORKLOAD: WorkloadIdentity(
                workload=SERVICE_RECOVERY_WORKLOAD,
                principal_id=_spiffe_id(domain, "agents/service-recovery"),
            ),
            APPROVAL_EXECUTOR_WORKLOAD: WorkloadIdentity(
                workload=APPROVAL_EXECUTOR_WORKLOAD,
                principal_id=_spiffe_id(domain, "services/approval-executor"),
            ),
        }

    def require(self, workload: str) -> WorkloadIdentity:
        """Return the trusted identity; unknown workloads fail closed."""
        try:
            return self._identities[workload]
        except KeyError as exc:
            raise LookupError(f"unknown trusted workload: {workload}") from exc
