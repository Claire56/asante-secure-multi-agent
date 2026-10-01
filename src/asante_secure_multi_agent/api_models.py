"""Operator-facing request models.

Identity is intentionally absent from these schemas. Phase 4 derives the human
principal exclusively from the authenticated Bearer token at the HTTP boundary.
"""

from pydantic import BaseModel, Field


class RunRequest(BaseModel):
    """Natural-language operator request for the multi-agent runtime."""

    message: str = Field(
        min_length=1,
        description="Natural-language request for the supervisor agent, e.g. a "
        "reservation lookup or a service-recovery credit.",
    )


class DemoCreditRequest(BaseModel):
    """Direct business arguments for the Ruhusa diagnostic control path."""

    reservation_id: str = Field(
        min_length=1,
        description="Reservation to credit, e.g. R-3001, R-3002, or R-3003.",
    )
    amount: float = Field(
        gt=0,
        description="Credit amount in USD. Guest support is delegated up to $25; "
        "larger amounts are denied by Ruhusa.",
    )
    reason: str = Field(min_length=1, description="Service-recovery reason for the credit.")
