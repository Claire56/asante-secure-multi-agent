"""Human and workload identity boundaries for the Asante application."""

from .human import (
    AuthenticatedHuman,
    DevHmacAccessTokenVerifier,
    JwksAccessTokenVerifier,
    require_authenticated_human,
)
from .workload import (
    GUEST_SUPPORT_WORKLOAD,
    SUPERVISOR_WORKLOAD,
    StaticSpiffeWorkloadIdentityProvider,
    WorkloadIdentity,
    WorkloadIdentityProvider,
)

__all__ = [
    "GUEST_SUPPORT_WORKLOAD",
    "SUPERVISOR_WORKLOAD",
    "AuthenticatedHuman",
    "DevHmacAccessTokenVerifier",
    "JwksAccessTokenVerifier",
    "StaticSpiffeWorkloadIdentityProvider",
    "WorkloadIdentity",
    "WorkloadIdentityProvider",
    "require_authenticated_human",
]
