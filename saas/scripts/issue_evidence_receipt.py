"""Prepare or finalize an HSM-signed receipt from one exact JSON request."""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from saas.production.admission import (
    finalize_evidence_admission_receipt,
    prepare_evidence_admission_receipt,
)
from saas.production.readiness import validate_candidate_revision
from saas.scripts.prepare_evidence_receipt import _safe_output

_REQUEST_FIELDS = {
    "action",
    "evidence_kind",
    "evidence_path",
    "signer_key_id",
    "receipt_id",
    "issued_at",
    "expires_at",
    "signature_base64",
}


def _time(value: object, *, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{label} must be a UTC ISO 8601 timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ValueError(f"{label} must be an ISO 8601 timestamp") from error
    return parsed.astimezone(UTC)


def _text(request: Mapping[str, Any], field: str) -> str:
    value = request.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} is required")
    return value


def issue_evidence_receipt(
    repo: Path,
    policy: Mapping[str, Any],
    request: Mapping[str, Any],
    *,
    product_revision: str,
    workflow_identity: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Regenerate exact signing bytes and optionally bind an external signature."""

    if set(request) != _REQUEST_FIELDS:
        raise ValueError("receipt request fields do not match the schema")
    action = request.get("action")
    if action not in {"prepare", "finalize"}:
        raise ValueError("receipt request action must be prepare or finalize")
    signature = request.get("signature_base64")
    if action == "prepare" and signature not in {None, ""}:
        raise ValueError("prepare request must not contain a signature")
    if action == "finalize" and (not isinstance(signature, str) or not signature):
        raise ValueError("finalize request requires signature_base64")
    preparation = prepare_evidence_admission_receipt(
        repo,
        policy,
        evidence_kind=_text(request, "evidence_kind"),
        evidence_path=_text(request, "evidence_path"),
        product_revision=product_revision,
        signer_key_id=_text(request, "signer_key_id"),
        receipt_id=_text(request, "receipt_id"),
        issued_at=_time(request.get("issued_at"), label="issued_at"),
        expires_at=_time(request.get("expires_at"), label="expires_at"),
        now=now,
    )
    if preparation["receipt"]["workflow_identity"] != workflow_identity:
        raise ValueError("runtime workflow identity does not match the trusted signer key")
    result: dict[str, Any] = {"preparation": preparation, "receipt": None}
    if action == "finalize":
        if not isinstance(signature, str):
            raise ValueError("finalize request requires signature_base64")
        result["receipt"] = finalize_evidence_admission_receipt(
            repo,
            policy,
            preparation,
            signature_base64=signature,
            now=now,
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request-json", required=True)
    parser.add_argument("--product-revision", required=True)
    parser.add_argument("--workflow-identity", required=True)
    parser.add_argument("--output-directory", default="artifacts/evidence-receipt")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    try:
        request = json.loads(args.request_json)
        if not isinstance(request, dict):
            raise ValueError("receipt request must contain a JSON object")
        lineage = validate_candidate_revision(args.product_revision, repo)
        if lineage["status"] != "pass" or lineage["production_readiness"] != "ready":
            failures = [*lineage.get("violations", []), *lineage.get("blockers", [])]
            raise ValueError("candidate lineage is not ready: " + "; ".join(failures))
        policy = json.loads(
            (repo / "saas/production/evidence-admission-policy.json").read_text(encoding="utf-8")
        )
        result = issue_evidence_receipt(
            repo,
            policy,
            request,
            product_revision=args.product_revision,
            workflow_identity=args.workflow_identity,
        )
        directory = Path(args.output_directory)
        if directory.is_absolute() or ".." in directory.parts or directory == Path("."):
            raise ValueError("output directory must be safe and repository-relative")
        preparation = json.dumps(result["preparation"], indent=2, sort_keys=True) + "\n"
        _safe_output(repo, (directory / "receipt-preparation.json").as_posix()).write_text(
            preparation, encoding="utf-8"
        )
        if result["receipt"] is not None:
            receipt = json.dumps(result["receipt"], indent=2, sort_keys=True) + "\n"
            _safe_output(repo, (directory / "receipt.json").as_posix()).write_text(
                receipt, encoding="utf-8"
            )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.error(str(error))
    print(preparation, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
