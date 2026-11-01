"""Validate Casdoor identity evidence and measured live session convergence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from saas.production.identity_readiness import load_identity_evidence, validate_identity_readiness


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--product-revision")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-ready", action="store_true")
    args = parser.parse_args(argv)
    if args.require_ready and not args.product_revision:
        parser.error("--require-ready requires --product-revision")
    repo = Path(__file__).resolve().parents[2]
    try:
        policy = json.loads((repo / "saas/production/identity-policy.json").read_bytes())
        report = validate_identity_readiness(
            repo,
            policy,
            load_identity_evidence(repo, policy),
            expected_product_revision=args.product_revision,
        )
    except (OSError, ValueError):
        print("identity evidence could not be validated")
        return 1
    raw = json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(raw, encoding="utf-8")
    print(raw, end="")
    return int(
        report["status"] != "pass"
        or (args.require_ready and report["production_readiness"] != "ready")
    )


if __name__ == "__main__":
    raise SystemExit(main())
