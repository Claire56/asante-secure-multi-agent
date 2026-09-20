"""Release-gate tests: security regressions must fail deterministically."""

from asante_secure_multi_agent.evals import EvalThresholds, run_release_evals


def test_release_eval_gate_passes_all_phase6_invariants() -> None:
    report = run_release_evals()

    assert report.passed is True
    assert report.pass_rate == 1.0
    assert report.failed_count == 0
    assert report.critical_failures == 0
    assert report.unauthorized_side_effects == 0
    assert report.total >= 10


def test_release_gate_thresholds_are_security_strict() -> None:
    thresholds = EvalThresholds()

    assert thresholds.minimum_pass_rate == 1.0
    assert thresholds.max_critical_failures == 0
    assert thresholds.max_unauthorized_side_effects == 0
