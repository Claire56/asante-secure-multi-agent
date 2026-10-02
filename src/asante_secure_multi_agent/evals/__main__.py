"""CLI entrypoint for the Phase 9 release gate."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .runner import run_release_evals, write_report


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Asante deterministic release evals.")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("eval-report.json"),
        help="Path for the JSON eval report.",
    )
    args = parser.parse_args()

    report = run_release_evals()
    write_report(report, args.output)
    print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
