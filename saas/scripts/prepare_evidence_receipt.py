"""Prepare canonical production-evidence receipt bytes for external HSM signing."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from saas.production.admission import prepare_evidence_admission_receipt
from saas.production.readiness import validate_candidate_revision


def _parse_time(value: str) -> datetime:
    if not value.endswith("Z"):
        raise argparse.ArgumentTypeError("timestamp must be UTC and end with Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise argparse.ArgumentTypeError("timestamp must be ISO 8601") from error
    return parsed.astimezone(UTC)


def _safe_output(repo: Path, value: str) -> Path:
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("output must be repository-relative")
    output = repo / relative
    current = output.parent
    while current != repo:
        if current.is_symlink():
            raise ValueError("output parent cannot use symbolic links")
        current = current.parent
    if output.is_symlink():
        raise ValueError("output cannot be a symbolic link")
    output.parent.mkdir(parents=True, exist_ok=True)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-kind", required=True)
    parser.add_argument("--evidence-path", required=True)
    parser.add_argument("--product-revision", required=True)
    parser.add_argument("--signer-key-id", required=True)
    parser.add_argument("--receipt-id", required=True)
    parser.add_argument("--issued-at", required=True, type=_parse_time)
    parser.add_argument("--expires-at", required=True, type=_parse_time)
    parser.add_argument("--workflow-identity", required=True)
    parser.add_argument("--output")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    try:
        lineage = validate_candidate_revision(args.product_revision, repo)
        if lineage["status"] != "pass" or lineage["production_readiness"] != "ready":
            failures = [*lineage.get("violations", []), *lineage.get("blockers", [])]
            raise ValueError("candidate lineage is not ready: " + "; ".join(failures))
        policy = json.loads(
            (repo / "saas/production/evidence-admission-policy.json").read_text(encoding="utf-8")
        )
        preparation = prepare_evidence_admission_receipt(
            repo,
            policy,
            evidence_kind=args.evidence_kind,
            evidence_path=args.evidence_path,
            product_revision=args.product_revision,
            signer_key_id=args.signer_key_id,
            receipt_id=args.receipt_id,
            issued_at=args.issued_at,
            expires_at=args.expires_at,
        )
        if preparation["receipt"]["workflow_identity"] != args.workflow_identity:
            raise ValueError("runtime workflow identity does not match the trusted signer key")
        rendered = json.dumps(preparation, indent=2, sort_keys=True) + "\n"
        if args.output:
            _safe_output(repo, args.output).write_text(rendered, encoding="utf-8")
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.error(str(error))
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
