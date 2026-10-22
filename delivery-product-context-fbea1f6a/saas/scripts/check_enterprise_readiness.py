"""Validate production enterprise identity and governance acceptance evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from saas.production.business import load_business_evidence, validate_business_readiness


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", default="saas/production/enterprise-policy.json")
    parser.add_argument("--product-revision")
    parser.add_argument("--output")
    parser.add_argument("--require-ready", action="store_true")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    policy = json.loads((repo / args.policy).read_text(encoding="utf-8"))
    try:
        records = load_business_evidence(repo, policy)
    except ValueError as error:
        parser.error(str(error))
    report = validate_business_readiness(
        repo, policy, records, expected_product_revision=args.product_revision
    )
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
