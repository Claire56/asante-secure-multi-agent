from datetime import UTC, datetime, timedelta

from ruhusa import TaskContext

from asante_secure_multi_agent.security import build_security_runtime
from asante_secure_multi_agent.tools import GuestCreditLedger, SecuredGuestCreditTool


def _task() -> TaskContext:
    return TaskContext(
        task_id="task-test-credit",
        initiated_by="user:claire",
        purpose="guest service recovery",
        expires_at=datetime.now(UTC) + timedelta(minutes=30),
    )


def test_guest_support_can_issue_small_credit() -> None:
    ledger = GuestCreditLedger()
    tool = SecuredGuestCreditTool(build_security_runtime(), ledger)

    result = tool.issue_credit(
        reservation_id="R-1001",
        amount=20.0,
        reason="Wi-Fi outage",
        task=_task(),
    )

    assert result["status"] == "issued"
    assert result["effect"] == "allow"
    assert result["policy_id"] == "guest-support-small-credit"
    assert len(ledger.credits) == 1


def test_credit_above_25_requires_approval_and_does_not_execute() -> None:
    ledger = GuestCreditLedger()
    tool = SecuredGuestCreditTool(build_security_runtime(), ledger)

    result = tool.issue_credit(
        reservation_id="R-1001",
        amount=75.0,
        reason="Extended Wi-Fi outage",
        task=_task(),
    )

    assert result["status"] == "blocked"
    assert result["effect"] == "require_approval"
    assert ledger.credits == []


def test_credit_above_100_is_default_deny() -> None:
    ledger = GuestCreditLedger()
    tool = SecuredGuestCreditTool(build_security_runtime(), ledger)

    result = tool.issue_credit(
        reservation_id="R-1001",
        amount=150.0,
        reason="Requested oversized credit",
        task=_task(),
    )

    assert result["status"] == "blocked"
    assert result["effect"] == "deny"
    assert ledger.credits == []
