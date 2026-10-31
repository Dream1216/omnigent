"""Collect native human approval into a candidate-bound canonical review exception."""

from __future__ import annotations

import argparse
import hashlib
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from saas.production.readiness import validate_candidate_revision
from saas.production.review_exception import (
    MODE,
    RECORD_DIRECTORY,
    RELEASE_ID,
    WORKFLOW_IDENTITY,
    _load_policy,
    _object,
    _time,
    canonical_review_record,
    governed_review_record,
    native_review_facts,
)
from saas.scripts.prepare_evidence_receipt import _safe_output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--product-revision", required=True)
    parser.add_argument("--evidence-revision", required=True)
    parser.add_argument("--workflow-run", type=int)
    parser.add_argument("--authorization-request-json")
    parser.add_argument("--workflow-identity")
    parser.add_argument(
        "--output", default="artifacts/review-exception/review-exception-authorization.json"
    )
    parser.add_argument("--attestor-commitment")
    parser.add_argument("--expires-at")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    try:
        lineage = validate_candidate_revision(args.product_revision, repo)
        if lineage["status"] != "pass" or lineage["production_readiness"] != "ready":
            raise ValueError(
                "review exception preparation requires a clean immutable candidate lineage"
            )
        policy = _load_policy(repo)
        for ancestor, descendant in (
            (args.product_revision, args.evidence_revision),
            (args.evidence_revision, "HEAD"),
        ):
            if subprocess.run(
                ["git", "-C", str(repo), "merge-base", "--is-ancestor", ancestor, descendant],
                capture_output=True,
                check=False,
            ).returncode:
                raise ValueError("authorization must bind the current immutable candidate lineage")
        if args.authorization_request_json is not None:
            request = _object(args.authorization_request_json.encode())
            if (
                set(request) != {"attestor_commitment", "expires_at"}
                or args.workflow_identity != WORKFLOW_IDENTITY
            ):
                raise ValueError("authorization request fields or workflow identity are invalid")
            commitment = request["attestor_commitment"]
            expiry = request["expires_at"]
            import re

            if (
                not isinstance(commitment, str)
                or re.fullmatch(r"[0-9a-f]{64}", commitment) is None
            ):
                raise ValueError("authorization requires one exact owner commitment")
            if not datetime.now(UTC) < _time(expiry) <= _time(policy["expires_at"]):
                raise ValueError("authorization expiry is outside the approved release window")
            document = {
                "schema_version": 1,
                "release_id": RELEASE_ID,
                "mode": MODE,
                "product_revision": args.product_revision,
                "evidence_revision": args.evidence_revision,
                "attestor_commitment": commitment,
                "expires_at": expiry,
                "revision_contract": policy["revision_contract"],
                "authorization_reference_sha256": policy["authorization_reference_sha256"],
                "workflow_identity": WORKFLOW_IDENTITY,
            }
            with _safe_output(repo, args.output).open("xb") as output:
                output.write(canonical_review_record(document))
            return 0
        if (
            args.workflow_run is None
            or args.attestor_commitment is None
            or args.expires_at is None
        ):
            raise ValueError(
                "record collection requires workflow run, owner commitment and expiry"
            )
        facts = native_review_facts(args.workflow_run)
        if (
            facts["product_revision"] != args.product_revision
            or facts["attestor_commitment"] != args.attestor_commitment
            or facts["expires_at"] != args.expires_at
            or not datetime.now(UTC) < _time(args.expires_at)
        ):
            raise ValueError(
                "native approved authorization does not bind this product owner or expiry"
            )
        if facts["workflow_head_sha"] != args.evidence_revision:
            raise ValueError("workflow is not the exact evidence revision")
        document = {
            "schema_version": 1,
            "release_id": RELEASE_ID,
            "mode": MODE,
            "governance_classification": "degraded",
            "product_revision": args.product_revision,
            "evidence_revision": args.evidence_revision,
            "revision_contract": policy["revision_contract"],
            "authorized_login": policy["authorized_login"],
            "authorized_github_user_id": policy["authorized_github_user_id"],
            "attestor_commitment": args.attestor_commitment,
            "issued_at": datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "expires_at": args.expires_at,
            "authorization_reference_sha256": policy["authorization_reference_sha256"],
            "domains": sorted(policy["domain_roles"]),
            "native_approval": {
                key: value for key, value in facts.items() if key != "completed_at"
            },
        }
        relative = f"{RECORD_DIRECTORY}/{RELEASE_ID}-{args.product_revision}.json"
        target = _safe_output(repo, relative)
        payload = canonical_review_record(document)
        with target.open("xb") as output:
            output.write(payload)
        if governed_review_record(repo, relative) is None:
            target.unlink()
            raise ValueError(
                "record scope, timestamps or commitment do not match the release policy"
            )
        print(f"{relative} sha256:{hashlib.sha256(payload).hexdigest()}")
    except (OSError, ValueError, KeyError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
