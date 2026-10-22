"""Run the P5 disposable PostgreSQL logical backup and restore contract."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path

from saas.production.postgresql_restore import run_logical_restore_contract


def _git_revision(repo: Path) -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--admin-url",
        default=os.environ.get("OMNIGENT_SAAS_TEST_POSTGRES_URL"),
        help="PostgreSQL admin URL; defaults to OMNIGENT_SAAS_TEST_POSTGRES_URL",
    )
    parser.add_argument("--product-revision")
    parser.add_argument(
        "--allow-disposable-databases",
        action="store_true",
        help="authorize creation and force-drop of two generated test databases",
    )
    parser.add_argument("--output")
    args = parser.parse_args()
    if not args.admin_url:
        parser.error("--admin-url or OMNIGENT_SAAS_TEST_POSTGRES_URL is required")
    repo = Path(__file__).resolve().parents[2]
    report = run_logical_restore_contract(
        repo,
        args.admin_url,
        product_revision=args.product_revision or _git_revision(repo),
        allow_disposable_databases=args.allow_disposable_databases,
    )
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = repo / args.output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
