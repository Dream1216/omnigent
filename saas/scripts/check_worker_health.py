"""Content-blind local health probe for the production scheduler worker."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping, Sequence

from saas.production.worker import (
    ProductionWorkerConfigError,
    ProductionWorkerHealthError,
    assert_production_worker_health,
    load_production_worker_health_policy,
    load_production_worker_health_state,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        choices=("startup", "readiness", "liveness"),
        required=True,
        help="Probe contract to evaluate",
    )
    return parser


def check_worker_health(
    *,
    mode: str,
    environ: Mapping[str, str] | None = None,
    now_unix_ns: int | None = None,
) -> None:
    """Load and evaluate one exact local health state."""

    policy = load_production_worker_health_policy(environ)
    state = load_production_worker_health_state(policy.state_path)
    assert_production_worker_health(
        state,
        policy,
        mode=mode,
        now_unix_ns=now_unix_ns,
    )


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    now_unix_ns: int | None = None,
) -> int:
    args = build_parser().parse_args(argv)
    try:
        check_worker_health(
            mode=args.mode,
            environ=environ,
            now_unix_ns=now_unix_ns,
        )
    except (ProductionWorkerConfigError, ProductionWorkerHealthError):
        print("production worker health probe failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["build_parser", "check_worker_health", "main"]
