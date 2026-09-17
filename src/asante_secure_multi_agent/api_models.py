"""Operator-facing request models.

Identity is intentionally absent from these schemas. Phase 4 derives the human
principal exclusively from the authenticated Bearer token at the HTTP boundary.
"""

from pydantic import BaseModel, Field


class RunRequest(BaseModel):
    """Natural-language operator request for the multi-agent runtime."""

    message: str = Field(min_length=1)


class DemoCreditRequest(BaseModel):
    """Direct business arguments for the Ruhusa diagnostic control path."""

    reservation_id: str = Field(min_length=1)
    amount: float = Field(gt=0)
    reason: str = Field(min_length=1)
