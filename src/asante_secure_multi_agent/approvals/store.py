"""Durable approval records for Asante human-in-the-loop operations.

Approval state is persisted separately from the model/runtime so a process restart
cannot silently erase a pending or completed human decision. SQLite is used for
the local reference implementation; production deployments can replace this
store behind the same interface.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Literal
from uuid import uuid4

ApprovalStatus = Literal["pending", "approved", "denied", "executed"]


@dataclass(frozen=True)
class ApprovalRecord:
    """One durable human approval request and its decision/execution state."""

    approval_id: str
    action: str
    task_id: str
    requested_by: str
    reservation_id: str
    amount: float
    reason: str
    policy_id: str | None
    status: ApprovalStatus
    created_at: str
    decided_at: str | None = None
    decided_by: str | None = None
    decision_note: str | None = None
    executed_at: str | None = None
    execution_result: dict[str, object] | None = None

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-friendly representation for API/MCP responses."""
        return {
            "approval_id": self.approval_id,
            "action": self.action,
            "task_id": self.task_id,
            "requested_by": self.requested_by,
            "reservation_id": self.reservation_id,
            "amount": self.amount,
            "reason": self.reason,
            "policy_id": self.policy_id,
            "status": self.status,
            "created_at": self.created_at,
            "decided_at": self.decided_at,
            "decided_by": self.decided_by,
            "decision_note": self.decision_note,
            "executed_at": self.executed_at,
            "execution_result": self.execution_result,
        }


class ApprovalStateError(RuntimeError):
    """Raised when an approval transition violates the state machine."""


class SQLiteApprovalStore:
    """Small durable SQLite approval store with explicit state transitions."""

    def __init__(self, path: str | Path = ".asante/approvals.db") -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._connection = sqlite3.connect(self.path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._initialize()

    def _initialize(self) -> None:
        with self._connection:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS approval_requests (
                    approval_id TEXT PRIMARY KEY,
                    action TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    requested_by TEXT NOT NULL,
                    reservation_id TEXT NOT NULL,
                    amount REAL NOT NULL,
                    reason TEXT NOT NULL,
                    policy_id TEXT,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    decided_at TEXT,
                    decided_by TEXT,
                    decision_note TEXT,
                    executed_at TEXT,
                    execution_result_json TEXT
                )
                """
            )

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        self._connection.close()

    def create_credit_request(
        self,
        *,
        task_id: str,
        requested_by: str,
        reservation_id: str,
        amount: float,
        reason: str,
        policy_id: str | None,
    ) -> ApprovalRecord:
        """Persist a pending request for a human-approved guest credit.

        Requests are idempotent per task: repeating the same reservation and amount
        within one task returns the existing record (whatever its state) instead of
        creating a second approval that could be approved and executed separately.
        """
        with self._lock:
            existing = self.find_credit_request(
                task_id=task_id, reservation_id=reservation_id, amount=amount
            )
            if existing is not None:
                return existing
            return self._insert_credit_request(
                task_id=task_id,
                requested_by=requested_by,
                reservation_id=reservation_id,
                amount=amount,
                reason=reason,
                policy_id=policy_id,
            )

    def find_credit_request(
        self,
        *,
        task_id: str,
        reservation_id: str,
        amount: float,
    ) -> ApprovalRecord | None:
        """Return the credit request already recorded for this task, if any."""
        with self._lock:
            row = self._connection.execute(
                """
                SELECT * FROM approval_requests
                WHERE action = 'guest.credit.issue.approved'
                  AND task_id = ? AND reservation_id = ? AND amount = ?
                ORDER BY created_at ASC
                LIMIT 1
                """,
                (task_id, reservation_id, float(amount)),
            ).fetchone()
        return self._from_row(row) if row is not None else None

    def _insert_credit_request(
        self,
        *,
        task_id: str,
        requested_by: str,
        reservation_id: str,
        amount: float,
        reason: str,
        policy_id: str | None,
    ) -> ApprovalRecord:
        now = datetime.now(UTC).isoformat()
        record = ApprovalRecord(
            approval_id=f"approval:{uuid4().hex}",
            action="guest.credit.issue.approved",
            task_id=task_id,
            requested_by=requested_by,
            reservation_id=reservation_id,
            amount=float(amount),
            reason=reason,
            policy_id=policy_id,
            status="pending",
            created_at=now,
        )
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO approval_requests (
                    approval_id, action, task_id, requested_by, reservation_id,
                    amount, reason, policy_id, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.approval_id,
                    record.action,
                    record.task_id,
                    record.requested_by,
                    record.reservation_id,
                    record.amount,
                    record.reason,
                    record.policy_id,
                    record.status,
                    record.created_at,
                ),
            )
        return record

    def get(self, approval_id: str) -> ApprovalRecord | None:
        """Return an approval record or ``None`` when it does not exist."""
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM approval_requests WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
        return self._from_row(row) if row is not None else None

    def require(self, approval_id: str) -> ApprovalRecord:
        """Return an approval record or fail for an unknown identifier."""
        record = self.get(approval_id)
        if record is None:
            raise LookupError(f"unknown approval request: {approval_id}")
        return record

    def list_requests(self, *, status: ApprovalStatus | None = None) -> list[ApprovalRecord]:
        """List approvals newest first, optionally filtered by state."""
        with self._lock:
            if status is None:
                rows = self._connection.execute(
                    "SELECT * FROM approval_requests ORDER BY created_at DESC"
                ).fetchall()
            else:
                rows = self._connection.execute(
                    "SELECT * FROM approval_requests WHERE status = ? ORDER BY created_at DESC",
                    (status,),
                ).fetchall()
        return [self._from_row(row) for row in rows]

    def decide(
        self,
        approval_id: str,
        *,
        approved: bool,
        decided_by: str,
        note: str | None = None,
    ) -> ApprovalRecord:
        """Transition a pending request to approved or denied."""
        with self._lock:
            current = self.require(approval_id)
            target: ApprovalStatus = "approved" if approved else "denied"
            if current.status == target:
                return current
            if current.status != "pending":
                raise ApprovalStateError(
                    f"approval {approval_id} is {current.status}; expected pending"
                )
            decided_at = datetime.now(UTC).isoformat()
            with self._connection:
                self._connection.execute(
                    """
                    UPDATE approval_requests
                    SET status = ?, decided_at = ?, decided_by = ?, decision_note = ?
                    WHERE approval_id = ?
                    """,
                    (target, decided_at, decided_by, note, approval_id),
                )
        return self.require(approval_id)

    def mark_executed(
        self,
        approval_id: str,
        *,
        result: dict[str, object],
    ) -> ApprovalRecord:
        """Mark an approved request executed and persist the provider result."""
        with self._lock:
            current = self.require(approval_id)
            if current.status == "executed":
                return current
            if current.status != "approved":
                raise ApprovalStateError(
                    f"approval {approval_id} is {current.status}; expected approved"
                )
            executed_at = datetime.now(UTC).isoformat()
            with self._connection:
                self._connection.execute(
                    """
                    UPDATE approval_requests
                    SET status = 'executed', executed_at = ?, execution_result_json = ?
                    WHERE approval_id = ?
                    """,
                    (executed_at, json.dumps(result, sort_keys=True), approval_id),
                )
        return self.require(approval_id)

    @staticmethod
    def _from_row(row: sqlite3.Row) -> ApprovalRecord:
        payload = row["execution_result_json"]
        execution_result = json.loads(payload) if payload else None
        return ApprovalRecord(
            approval_id=row["approval_id"],
            action=row["action"],
            task_id=row["task_id"],
            requested_by=row["requested_by"],
            reservation_id=row["reservation_id"],
            amount=float(row["amount"]),
            reason=row["reason"],
            policy_id=row["policy_id"],
            status=row["status"],
            created_at=row["created_at"],
            decided_at=row["decided_at"],
            decided_by=row["decided_by"],
            decision_note=row["decision_note"],
            executed_at=row["executed_at"],
            execution_result=execution_result,
        )
