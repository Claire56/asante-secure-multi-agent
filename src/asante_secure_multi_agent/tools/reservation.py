"""Ruhusa-secured reservation reads with authorization-aware caching."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Protocol

from opentelemetry.trace import Status, StatusCode
from ruhusa import DecisionEffect, DelegationGrant, Principal, TaskContext

from asante_secure_multi_agent.cache import CacheStore, build_reservation_cache_key
from asante_secure_multi_agent.identity import RESERVATIONS_WORKLOAD, SUPERVISOR_WORKLOAD
from asante_secure_multi_agent.security.runtime import (
    RESERVATION_TOOL_ID,
    RESERVATION_TOOL_IMPLEMENTATION,
    AsanteSecurityRuntime,
)
from asante_secure_multi_agent.telemetry import get_tracer
from asante_secure_multi_agent.telemetry.metrics import (
    monotonic_time,
    record_authorization,
    record_cache_denied_before_lookup,
    record_cache_lookup,
)

_tracer = get_tracer()


class ReservationProvider(Protocol):
    """Minimal reservation-provider contract used by the secured read tool."""

    def get_reservation(self, reservation_id: str) -> dict[str, object] | None: ...


@dataclass
class InMemoryReservationProvider:
    """Fake external reservation system with a provider-call counter."""

    reservations: dict[str, dict[str, object]] = field(
        default_factory=lambda: {
            "R-3001": {
                "reservation_id": "R-3001",
                "guest_name": "Amina N.",
                "property": "Bandini",
                "status": "confirmed",
                "check_in": "2026-10-02",
                "check_out": "2026-10-05",
            },
            "R-3002": {
                "reservation_id": "R-3002",
                "guest_name": "Jordan K.",
                "property": "Bandini",
                "status": "confirmed",
                "check_in": "2026-10-06",
                "check_out": "2026-10-09",
            },
            "R-3003": {
                "reservation_id": "R-3003",
                "guest_name": "Maya T.",
                "property": "Bandini",
                "status": "completed",
                "check_in": "2026-09-12",
                "check_out": "2026-09-15",
            },
        }
    )
    calls: int = 0

    def get_reservation(self, reservation_id: str) -> dict[str, object] | None:
        """Return a defensive copy and count external-provider reads."""
        self.calls += 1
        value = self.reservations.get(reservation_id)
        return deepcopy(value) if value is not None else None


class SecuredReservationTool:
    """Release reservation data only after live Ruhusa authorization succeeds."""

    def __init__(
        self,
        security: AsanteSecurityRuntime,
        provider: ReservationProvider,
        cache: CacheStore,
        *,
        cache_ttl_seconds: float = 300.0,
    ) -> None:
        if cache_ttl_seconds <= 0:
            raise ValueError("cache_ttl_seconds must be greater than zero")
        self.security = security
        self.provider = provider
        self.cache = cache
        self.cache_ttl_seconds = cache_ttl_seconds

    def get_reservation(
        self,
        *,
        reservation_id: str,
        task: TaskContext,
        delegation_chain: tuple[DelegationGrant, ...],
    ) -> dict[str, object]:
        """Authorize first; only then inspect cache or external reservation data."""
        with _tracer.start_as_current_span(
            "asante.reservation.secured_read",
            attributes={
                "asante.action": "reservation.read",
                "asante.resource.kind": "reservation",
                "asante.delegation.depth": len(delegation_chain),
            },
        ) as execution_span:
            supervisor_id = self.security.workload_identities.require(
                SUPERVISOR_WORKLOAD
            ).principal_id
            reservations_id = self.security.workload_identities.require(
                RESERVATIONS_WORKLOAD
            ).principal_id
            principal = Principal(principal_id=reservations_id, principal_type="agent")
            now = datetime.now(UTC)
            invocation_expiry = min(task.expires_at, now + timedelta(minutes=5))

            prepared = self.security.invocation_factory.create(
                invoking_principal_id=supervisor_id,
                executing_principal=principal,
                task=task,
                action="reservation.read",
                resource=f"reservation:{reservation_id}",
                arguments={},
                expires_at=invocation_expiry,
                tool_id=RESERVATION_TOOL_ID,
                implementation_id=RESERVATION_TOOL_IMPLEMENTATION,
                delegation_chain=delegation_chain,
            )

            started = monotonic_time()
            with _tracer.start_as_current_span(
                "ruhusa.authorization.admission",
                attributes={"asante.action": "reservation.read"},
            ) as admission_span:
                admission = self.security.execution_controller.begin(prepared.request)
                admission_effect = admission.authorization.effect.value
                admission_span.set_attribute("asante.authorization.effect", admission_effect)
                if admission.authorization.policy_id:
                    admission_span.set_attribute(
                        "asante.authorization.policy_id",
                        admission.authorization.policy_id,
                    )
            record_authorization(
                action="reservation.read",
                effect=admission_effect,
                phase="admission",
                duration_seconds=monotonic_time() - started,
            )

            if not admission.allowed:
                execution_span.set_attribute("asante.execution.outcome", "blocked")
                record_cache_denied_before_lookup(phase="admission")
                return {
                    "status": "blocked",
                    "effect": admission_effect,
                    "reason": admission.authorization.reason,
                }

            permit = admission.permit
            if permit is None:
                execution_span.set_status(Status(StatusCode.ERROR))
                execution_span.set_attribute("error.type", "missing_execution_permit")
                return {
                    "status": "blocked",
                    "effect": "deny",
                    "reason": "missing execution permit",
                }

            started = monotonic_time()
            with _tracer.start_as_current_span(
                "ruhusa.authorization.revalidation",
                attributes={"asante.action": "reservation.read"},
            ) as live_span:
                live = self.security.execution_controller.revalidate_before_execution(
                    prepared.request,
                    permit,
                )
                live_effect = live.authorization.effect.value
                live_span.set_attribute("asante.authorization.effect", live_effect)
                if live.authorization.policy_id:
                    live_span.set_attribute(
                        "asante.authorization.policy_id",
                        live.authorization.policy_id,
                    )
            record_authorization(
                action="reservation.read",
                effect=live_effect,
                phase="revalidation",
                duration_seconds=monotonic_time() - started,
            )

            if not live.allowed:
                execution_span.set_attribute("asante.execution.outcome", "blocked")
                record_cache_denied_before_lookup(phase="revalidation")
                return {
                    "status": "blocked",
                    "effect": live_effect,
                    "reason": live.authorization.reason,
                }

            cache_key = build_reservation_cache_key(reservation_id)
            with _tracer.start_as_current_span(
                "asante.cache.lookup",
                attributes={"asante.cache.kind": "reservation"},
            ) as cache_span:
                lookup = self.cache.get(cache_key)
                cache_span.set_attribute("asante.cache.hit", lookup.hit)
                cache_span.set_attribute("asante.cache.expired", lookup.expired)
                cache_span.set_attribute("asante.cache.age_ms", lookup.age_seconds * 1000.0)
            record_cache_lookup(hit=lookup.hit, expired=lookup.expired)

            if lookup.hit and lookup.value is not None:
                completed = self.security.execution_controller.complete(permit)
                if not completed:
                    raise RuntimeError(
                        "reservation disclosed but execution lifecycle did not complete"
                    )
                execution_span.set_attribute("asante.execution.outcome", "cache_hit")
                return {
                    "status": "found",
                    "effect": DecisionEffect.ALLOW.value,
                    "policy_id": live.authorization.policy_id,
                    "cache": "hit",
                    "reservation": lookup.value,
                }

            with _tracer.start_as_current_span(
                "asante.reservation.provider_read",
                attributes={"asante.external.system": "in_memory_reservation_provider"},
            ):
                reservation = self.provider.get_reservation(reservation_id)

            if reservation is None:
                completed = self.security.execution_controller.complete(permit)
                if not completed:
                    raise RuntimeError("reservation read lifecycle could not complete")
                execution_span.set_attribute("asante.execution.outcome", "not_found")
                return {
                    "status": "not_found",
                    "effect": DecisionEffect.ALLOW.value,
                    "policy_id": live.authorization.policy_id,
                    "cache": "miss",
                }

            self.cache.put(cache_key, reservation, ttl_seconds=self.cache_ttl_seconds)
            completed = self.security.execution_controller.complete(permit)
            if not completed:
                raise RuntimeError("reservation disclosed but execution lifecycle did not complete")

            execution_span.set_attribute("asante.execution.outcome", "cache_miss")
            return {
                "status": "found",
                "effect": DecisionEffect.ALLOW.value,
                "policy_id": live.authorization.policy_id,
                "cache": "miss",
                "reservation": reservation,
            }
