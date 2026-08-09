"""Derive all aggregate production gates from authoritative evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from saas.production.readiness import validate_production_readiness


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--product-revision")
    parser.add_argument("--output")
    parser.add_argument("--require-ready", action="store_true")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    try:
        report = validate_production_readiness(
            repo, expected_product_revision=args.product_revision
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
