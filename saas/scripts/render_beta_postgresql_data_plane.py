"""Render the pinned Beta PostgreSQL data-plane bundle without network access."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from saas.production.beta_postgresql_data_plane import (
    render_beta_postgresql_data_plane,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="omnigent-saas-render-beta-postgresql-data-plane",
        description=(
            "Verify pinned local upstream manifests and render a secret-free Beta "
            "PostgreSQL GitOps bundle."
        ),
    )
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--cert-manager-manifest", required=True, type=Path)
    parser.add_argument("--operator-manifest", required=True, type=Path)
    parser.add_argument("--plugin-manifest", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Emit one canonical, secret-free status record."""

    arguments = _parser().parse_args(argv)
    try:
        receipt = render_beta_postgresql_data_plane(
            arguments.spec,
            cert_manager_manifest=arguments.cert_manager_manifest,
            operator_manifest=arguments.operator_manifest,
            plugin_manifest=arguments.plugin_manifest,
            output_directory=arguments.output_directory,
        )
    except Exception:  # noqa: BLE001 - release paths and source details stay sealed.
        status = {
            "code": "beta_postgresql_data_plane_render_failed",
            "schema_version": 1,
            "status": "fail",
        }
        print(json.dumps(status, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
        return 1
    status = {
        "bundle_sha256": receipt.bundle_sha256,
        "receipt_sha256": receipt.receipt_sha256,
        "schema_version": 1,
        "spec_sha256": receipt.spec_sha256,
        "status": "pass",
    }
    print(json.dumps(status, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["main"]
