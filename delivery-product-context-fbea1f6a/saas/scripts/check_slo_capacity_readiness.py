"""Validate the P5 production SLO and capacity evidence contract."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from saas.production.slo_capacity import (
    load_slo_capacity_evidence,
    validate_slo_capacity_readiness,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", default="saas/production/slo-capacity-policy.json")
    parser.add_argument("--product-revision")
    parser.add_argument("--output")
    parser.add_argument(
        "--require-ready",
        action="store_true",
        help="fail when active dashboards and current production evidence are absent",
    )
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    policy = json.loads((repo / args.policy).read_text(encoding="utf-8"))
    records = load_slo_capacity_evidence(repo, policy)
    report = validate_slo_capacity_readiness(
        repo,
        policy,
        records,
        expected_product_revision=args.product_revision,
    )
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = repo / args.output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    if report["status"] != "pass":
        return 1
    if args.require_ready and report["production_readiness"] != "ready":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
