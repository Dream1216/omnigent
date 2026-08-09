"""Verify cryptographic admission of every production evidence document."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from saas.production.admission import validate_evidence_admission


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--product-revision")
    parser.add_argument("--output")
    parser.add_argument("--require-ready", action="store_true")
    args = parser.parse_args()
    if args.require_ready and not args.product_revision:
        parser.error("--require-ready requires --product-revision")
    repo = Path(__file__).resolve().parents[2]
    try:
        policy = json.loads(
            (repo / "saas/production/evidence-admission-policy.json").read_text(encoding="utf-8")
        )
        report = validate_evidence_admission(
            repo,
            policy,
            expected_product_revision=args.product_revision,
        )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.error(str(error))
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = repo / args.output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    if report["status"] != "pass":
        return 1
    return 1 if args.require_ready and report["production_readiness"] != "ready" else 0


if __name__ == "__main__":
    raise SystemExit(main())
