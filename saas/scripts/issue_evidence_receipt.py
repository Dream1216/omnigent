"""Prepare or finalize an HSM-signed receipt from one exact JSON request."""

from __future__ import annotations

import argparse
import hashlib
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
_REPORT_FIELDS = (
    "action",
    "evidence_kind",
    "evidence_path",
    "signer_key_id",
    "receipt_id",
)


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


def process_evidence_receipt_request(
    repo: Path,
    request_json: str,
    *,
    product_revision: str,
    workflow_identity: str,
    policy: Mapping[str, Any] | None = None,
    enforce_lineage: bool = True,
    now: datetime | None = None,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Return a redacted diagnostic report even when issuance fails closed."""

    current = (now or datetime.now(UTC)).astimezone(UTC)
    report: dict[str, Any] = {
        "schema_version": 1,
        "contract": "omnigent-production-evidence-receipt-issuance-v1",
        "generated_at": current.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "status": "fail",
        "action": None,
        "product_revision": product_revision,
        "workflow_identity": workflow_identity,
        "request_sha256": hashlib.sha256(request_json.encode("utf-8")).hexdigest(),
        "evidence_kind": None,
        "evidence_path": None,
        "signer_key_id": None,
        "receipt_id": None,
        "signature_present": False,
        "signature_payload_sha256": None,
        "receipt_emitted": False,
        "violations": [],
    }
    result: dict[str, Any] | None = None
    try:
        request = json.loads(request_json)
        if not isinstance(request, dict):
            raise ValueError("receipt request must contain a JSON object")
        for field in _REPORT_FIELDS:
            value = request.get(field)
            report[field] = value if isinstance(value, str) else None
        report["signature_present"] = bool(request.get("signature_base64"))
        if enforce_lineage:
            lineage = validate_candidate_revision(product_revision, repo)
            if lineage["status"] != "pass" or lineage["production_readiness"] != "ready":
                failures = [*lineage.get("violations", []), *lineage.get("blockers", [])]
                raise ValueError("candidate lineage is not ready: " + "; ".join(failures))
        if policy is None:
            loaded_policy = json.loads(
                (repo / "saas/production/evidence-admission-policy.json").read_text(
                    encoding="utf-8"
                )
            )
        else:
            loaded_policy = policy
        result = issue_evidence_receipt(
            repo,
            loaded_policy,
            request,
            product_revision=product_revision,
            workflow_identity=workflow_identity,
            now=current,
        )
        report["status"] = "pass"
        report["signature_payload_sha256"] = result["preparation"]["signature_payload_sha256"]
        report["receipt_emitted"] = result["receipt"] is not None
    except (OSError, ValueError, json.JSONDecodeError) as error:
        report["violations"] = [str(error)]
    return report, result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request-json", required=True)
    parser.add_argument("--product-revision", required=True)
    parser.add_argument("--workflow-identity", required=True)
    parser.add_argument("--output-directory", default="artifacts/evidence-receipt")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    directory = Path(args.output_directory)
    if directory.is_absolute() or ".." in directory.parts or directory == Path("."):
        parser.error("output directory must be safe and repository-relative")
    report, result = process_evidence_receipt_request(
        repo,
        args.request_json,
        product_revision=args.product_revision,
        workflow_identity=args.workflow_identity,
    )
    try:
        if result is not None:
            preparation = json.dumps(result["preparation"], indent=2, sort_keys=True) + "\n"
            _safe_output(repo, (directory / "receipt-preparation.json").as_posix()).write_text(
                preparation, encoding="utf-8"
            )
            if result["receipt"] is not None:
                receipt = json.dumps(result["receipt"], indent=2, sort_keys=True) + "\n"
                _safe_output(repo, (directory / "receipt.json").as_posix()).write_text(
                    receipt, encoding="utf-8"
                )
        rendered_report = json.dumps(report, indent=2, sort_keys=True) + "\n"
        _safe_output(repo, (directory / "receipt-issuance-report.json").as_posix()).write_text(
            rendered_report, encoding="utf-8"
        )
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(rendered_report, end="")
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
