"""Provision the credential-free repository mirrors consumed by one Runner."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from saas.production.repository_mirror import provision_repository_mirrors


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="omnigent-saas-provision-runner-repositories",
        description="Provision an immutable, credential-free Runner repository mirror set.",
    )
    parser.add_argument(
        "--spec",
        required=True,
        type=Path,
        help="Owner-only canonical repository provisioning spec.",
    )
    parser.add_argument(
        "--expected-binding-key",
        action="append",
        choices=("primary",),
        required=True,
        help="Exact isolated-Beta repository binding key; pass primary once.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Emit exactly one canonical secret-free status object."""

    arguments = _parser().parse_args(argv)
    try:
        expected_binding_keys = tuple(arguments.expected_binding_key)
        if expected_binding_keys != ("primary",):
            raise ValueError("isolated Beta requires exactly one primary binding")
        receipt = provision_repository_mirrors(
            arguments.spec,
            expected_binding_keys=expected_binding_keys,
            expected_credential_files={
                "primary": Path("/provisioning-private/credentials/primary.credential")
            },
        )
    except Exception:  # noqa: BLE001 - transport and credential details must stay sealed.
        result = {
            "code": "runner_repository_provisioning_failed",
            "schema_version": 1,
            "status": "fail",
        }
        print(json.dumps(result, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
        return 1
    result = {
        "bindings_sha256": receipt.bindings_sha256,
        "receipt_sha256": receipt.receipt_sha256,
        "schema_version": 1,
        "spec_sha256": receipt.spec_sha256,
        "status": "pass",
    }
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["main"]
