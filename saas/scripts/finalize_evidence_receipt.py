"""Finalize and verify a production-evidence receipt signed outside the repository."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from saas.production.admission import finalize_evidence_admission_receipt
from saas.scripts.prepare_evidence_receipt import _safe_output


def _regular_repo_input(repo: Path, value: str, *, label: str) -> Path:
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"{label} must be a regular repository-relative file")
    candidate = repo / relative
    if candidate.is_symlink() or not candidate.is_file():
        raise ValueError(f"{label} must be a regular repository-relative file")
    try:
        candidate.resolve().relative_to(repo.resolve())
    except (OSError, ValueError) as error:
        raise ValueError(f"{label} must be a regular repository-relative file") from error
    current = candidate.parent
    while current != repo:
        if current.is_symlink():
            raise ValueError(f"{label} must not traverse symbolic links")
        current = current.parent
    return candidate


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preparation", required=True)
    signature = parser.add_mutually_exclusive_group(required=True)
    signature.add_argument("--signature-file")
    signature.add_argument("--signature-stdin", action="store_true")
    parser.add_argument("--output")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    try:
        preparation_path = _regular_repo_input(repo, args.preparation, label="preparation")
        preparation = json.loads(preparation_path.read_text(encoding="utf-8"))
        if not isinstance(preparation, dict):
            raise ValueError("preparation must contain a JSON object")
        if args.signature_stdin:
            signature_base64 = sys.stdin.read()
        else:
            signature_path = _regular_repo_input(repo, args.signature_file, label="signature")
            signature_base64 = signature_path.read_text(encoding="ascii")
        if signature_base64.endswith("\n"):
            signature_base64 = signature_base64[:-1]
        if any(character.isspace() for character in signature_base64):
            raise ValueError("signature must not contain embedded whitespace")
        policy = json.loads(
            (repo / "saas/production/evidence-admission-policy.json").read_text(encoding="utf-8")
        )
        receipt = finalize_evidence_admission_receipt(
            repo,
            policy,
            preparation,
            signature_base64=signature_base64,
        )
        rendered = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        if args.output:
            _safe_output(repo, args.output).write_text(rendered, encoding="utf-8")
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        parser.error(str(error))
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
