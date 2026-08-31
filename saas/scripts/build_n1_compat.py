"""Deterministically materialize the pinned N-1 security-compat source tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

_BASE_COMMIT = "9451a64c1affa06630b9105bf39b56bb89feba3b"
_CONTRACT = "p0s3-n1-outbox-security-compat-v1"
_MANIFEST_FIELDS = {
    "schema_version",
    "contract_version",
    "base_commit",
    "patch_file",
    "patch_sha256",
    "dockerfile_sha256",
    "dockerignore_sha256",
    "build_requirements_sha256",
    "allowed_paths",
    "patched_tree_hash",
    "required_schema_revision",
    "launcher_module",
    "worker_module",
    "artifact_admission",
    "schema_change_policy",
}


def _run(root: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        raise RuntimeError("N-1 compatibility source materialization failed") from None
    return result.stdout.rstrip("\n")


def _load_manifest(repository: Path) -> dict[str, Any]:
    path = repository / "saas/n1_compat/manifest.json"
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise RuntimeError("N-1 compatibility manifest is invalid") from None
    if not isinstance(manifest, dict) or set(manifest) != _MANIFEST_FIELDS:
        raise RuntimeError("N-1 compatibility manifest is invalid") from None
    return manifest


def _validate_manifest(repository: Path, manifest: Mapping[str, Any]) -> Path:
    allowed = manifest.get("allowed_paths")
    if (
        manifest.get("schema_version") != 1
        or manifest.get("contract_version") != _CONTRACT
        or manifest.get("base_commit") != _BASE_COMMIT
        or manifest.get("required_schema_revision") != "p0s000000003"
        or manifest.get("launcher_module") != "saas.n1_outbox_launcher"
        or manifest.get("worker_module") != "saas.outbox_worker"
        or manifest.get("artifact_admission") != "external-signed-receipt-required"
        or manifest.get("schema_change_policy")
        != {
            "outbox_ddl_requires_worker_drain": True,
            "catalog_recheck_before_restart": True,
        }
        or not isinstance(allowed, list)
        or allowed != sorted(set(allowed))
        or any(not isinstance(path, str) or not path.startswith("saas/") for path in allowed)
    ):
        raise RuntimeError("N-1 compatibility manifest is invalid") from None
    patch_relative = manifest.get("patch_file")
    if patch_relative != "saas/n1_compat/9451a64c1.patch":
        raise RuntimeError("N-1 compatibility manifest is invalid") from None
    patch = repository / patch_relative
    try:
        digest = hashlib.sha256(patch.read_bytes()).hexdigest()
    except OSError:
        raise RuntimeError("N-1 compatibility patch is unavailable") from None
    if digest != manifest.get("patch_sha256"):
        raise RuntimeError("N-1 compatibility patch digest mismatch") from None
    for filename, field in (
        ("Dockerfile", "dockerfile_sha256"),
        ("Dockerfile.dockerignore", "dockerignore_sha256"),
        ("build-requirements.txt", "build_requirements_sha256"),
    ):
        try:
            observed = hashlib.sha256(
                (repository / "saas/n1_compat" / filename).read_bytes()
            ).hexdigest()
        except OSError:
            raise RuntimeError("N-1 compatibility build input is unavailable") from None
        if observed != manifest.get(field):
            raise RuntimeError("N-1 compatibility build input digest mismatch") from None
    return patch


def _changed_paths(root: Path) -> set[str]:
    lines = _run(root, "status", "--porcelain=v1", "--untracked-files=all").splitlines()
    return {line[3:] for line in lines if len(line) > 3}


def _verify_contract(root: Path) -> None:
    outbox = (root / "saas/control_plane/outbox.py").read_text(encoding="utf-8")
    worker = (root / "saas/outbox_worker.py").read_text(encoding="utf-8")
    launcher = (root / "saas/n1_outbox_launcher.py").read_text(encoding="utf-8")
    admission = (root / "saas/n1_outbox_compat_admission.py").read_text(encoding="utf-8")
    n1_dockerfile = (root / "saas/n1_compat/Dockerfile").read_text(encoding="utf-8")
    from_lines = re.findall(r"(?mi)^FROM\s+.*$", n1_dockerfile)
    copies = re.findall(r"(?mi)^COPY\s+--from=([^\s]+)\s+([^\n]+)$", n1_dockerfile)
    requirements = (root / "saas/n1_compat/build-requirements.txt").read_text(encoding="utf-8")
    forbidden = ("str(error)", "logger.exception", "exc_info=True")
    if (
        any(token in outbox or token in worker for token in forbidden)
        or 'last_error="n1_compat_delivery_error"' not in outbox
        or 'raise RuntimeError("outbox_failure_release_failed") from None' not in outbox
        or "hide_parameters=True" not in worker
        or "hide_parameters=True" not in launcher
        or "self._logger.error(" not in worker
        or "dsn_coordinate_fingerprint(database_url)" not in worker
        or "dsn_coordinate_fingerprint(database_url)" not in launcher
        or "outbox_schema" not in admission
        or "_OUTBOX_SCHEMA_SIGNATURE" not in admission
        or "_N1_COLUMN_ACLS" not in admission
        or "_N1_EFFECTIVE_COLUMN_ACLS" not in admission
        or "effective_allowed_column_acls" not in admission
        or "forbidden_column_acl" not in admission
        or "forbidden_relation_acl" not in admission
        or "direct_catalog_authority" not in admission
        or "non_system_schema_ownership" not in admission
        or "executable_security_definers" not in admission
        or "effective_database_temp" not in admission
        or "ORDER BY relation.relname, rewrite.rulename" not in admission
        or "verify_dispatcher_database_role(engine)" in worker.split("def main()", 1)[-1]
        or 'os.environ.get(_DATABASE_URL_ENV, "")' not in launcher
        or "OMNIGENT_SAAS_N1_COMPAT_DATABASE_URL" in launcher
        or "os.execve(" not in launcher
        or '[sys.executable, "-I", "-m", "saas.outbox_worker"]' not in launcher
        or "url.password" in admission
        or "database_url.encode" in admission
        or from_lines
        != [
            "FROM ${UV_IMAGE} AS uv-bin",
            "FROM ${PYTHON_IMAGE} AS n1-compat-builder",
            "FROM ${PYTHON_IMAGE} AS n1-compat-runtime",
        ]
        or copies
        != [("uv-bin", "/uv /usr/local/bin/uv"), ("n1-compat-builder", "/opt/venv /opt/venv")]
        or "COPY --from=runtime" in n1_dockerfile
        or "RUN --mount" in n1_dockerfile
        or "setuptools==83.0.0" not in requirements
        or "hatchling==1.27.0" not in requirements
        or "pathspec==1.1.1" not in requirements
        or "pluggy==1.6.0" not in requirements
        or "trove-classifiers==2026.6.1.19" not in requirements
        or "packaging==26.3" not in requirements
        or "--require-hashes" not in n1_dockerfile
        or "--no-build-isolation" not in n1_dockerfile
        or "FROM ${UV_IMAGE} AS uv-bin" not in n1_dockerfile
        or "uv:0.12.1@sha256:cf4eedcaa816" not in n1_dockerfile
        or "FROM ${PYTHON_IMAGE} AS n1-compat-builder" not in n1_dockerfile
        or "OMNIGENT_SKIP_WEB_UI=true" not in n1_dockerfile
        or "COPY pyproject.toml setup.py uv.lock README.md ./" not in n1_dockerfile
        or "sed -i '/^\\[tool\\.uv\\.workspace\\]$/,/^$/d' pyproject.toml" not in n1_dockerfile
        or "/usr/local/bin/uv pip install --python /opt/venv/bin/python" not in n1_dockerfile
        or "/usr/local/bin/uv sync --frozen --active --package omnigent" not in n1_dockerfile
        or "--no-dev --no-editable --no-cache" not in n1_dockerfile
        or '[ "${installed}" = "3.3.4" ]' not in n1_dockerfile
        or "import saas.n1_outbox_launcher as l, saas.outbox_worker as w" not in n1_dockerfile
        or 'p=Path("/opt/venv").resolve()' not in n1_dockerfile
        or "Path(m.__file__).resolve().is_relative_to(p)" not in n1_dockerfile
        or "FROM ${PYTHON_IMAGE} AS n1-compat-runtime" not in n1_dockerfile
        or "COPY --from=n1-compat-builder /opt/venv /opt/venv" not in n1_dockerfile
        or 'CMD ["python", "-I", "-m", "saas.n1_outbox_launcher"]' not in n1_dockerfile
        or "ai.omnigent.saas.n1.base-commit=${N1_BASE_COMMIT}" not in n1_dockerfile
        or "ai.omnigent.saas.n1.patch-source-revision=${SOURCE_REVISION}" not in n1_dockerfile
        or "ai.omnigent.saas.n1.patch-sha256=${N1_PATCH_SHA256}" not in n1_dockerfile
        or "ai.omnigent.saas.n1.patched-tree-hash=${N1_PATCHED_TREE_HASH}" not in n1_dockerfile
        or "ai.omnigent.saas.n1.schema-revision=${CONTROL_PLANE_SCHEMA_REVISION}"
        not in n1_dockerfile
        or "ai.omnigent.saas.n1.contract-version=${N1_CONTRACT_VERSION}" not in n1_dockerfile
        or "apt-get" in n1_dockerfile
        or "FROM runtime AS n1-compat-runtime" in n1_dockerfile
        or "server-builder" in n1_dockerfile
        or "web-builder" in n1_dockerfile
        or "RUN pip install" in n1_dockerfile
        or "COPY --from=n1-compat-builder /build" in n1_dockerfile
    ):
        raise RuntimeError("N-1 compatibility security contract is incomplete") from None


def _prepare_output_directory(output_directory: Path) -> Path:
    """Create or validate a new, empty, non-symlink materialization target."""

    output_directory = output_directory.absolute()
    if output_directory.is_symlink():
        raise RuntimeError("N-1 compatibility output directory is unsafe") from None
    if output_directory.exists():
        if not output_directory.is_dir():
            raise RuntimeError("N-1 compatibility output directory is unsafe") from None
        try:
            if next(output_directory.iterdir(), None) is not None:
                raise RuntimeError("N-1 compatibility output directory is not empty") from None
        except OSError:
            raise RuntimeError("N-1 compatibility output directory is unsafe") from None
    else:
        try:
            output_directory.mkdir(parents=True, exist_ok=False)
        except OSError:
            raise RuntimeError("N-1 compatibility output directory is unavailable") from None
    return output_directory.resolve()


def _copy_indexed_source(root: Path, output_directory: Path) -> None:
    """Export the already verified Git index without repository metadata."""

    prefix = f"{output_directory}{os.sep}"
    _run(root, "checkout-index", "--all", f"--prefix={prefix}")
    if (output_directory / ".git").exists():
        raise RuntimeError("N-1 compatibility output contains repository metadata") from None


@contextmanager
def materialize_n1_compat(repository: Path) -> Iterator[tuple[Path, dict[str, Any]]]:
    """Yield a verified temporary checkout of the patched fixed base."""

    repository = repository.resolve()
    manifest = _load_manifest(repository)
    patch = _validate_manifest(repository, manifest)
    with tempfile.TemporaryDirectory(prefix="omnigent-n1-compat-") as directory:
        root = Path(directory) / "source"
        _run(repository, "clone", "--shared", "--no-checkout", str(repository), str(root))
        _run(root, "checkout", "--detach", _BASE_COMMIT)
        if _run(root, "rev-parse", "HEAD") != _BASE_COMMIT:
            raise RuntimeError("N-1 compatibility base revision mismatch") from None
        _run(root, "apply", "--check", str(patch))
        _run(root, "apply", str(patch))
        allowed_paths = set(manifest["allowed_paths"])
        if _changed_paths(root) != allowed_paths:
            raise RuntimeError("N-1 compatibility patch path boundary violated") from None
        _verify_contract(root)
        _run(root, "add", "--all")
        tree_hash = f"git-sha1:{_run(root, 'write-tree')}"
        if tree_hash != manifest.get("patched_tree_hash"):
            raise RuntimeError("N-1 compatibility patched tree mismatch") from None
        yield root, manifest


def build_n1_compat(
    repository: Path,
    *,
    output_directory: Path | None = None,
) -> dict[str, Any]:
    """Apply and verify the fixed patch, returning content-blind build facts."""

    prepared_output = (
        _prepare_output_directory(output_directory) if output_directory is not None else None
    )
    with materialize_n1_compat(repository) as (root, manifest):
        if prepared_output is not None:
            _copy_indexed_source(root, prepared_output)
        return {
            "base_commit": manifest["base_commit"],
            "contract_version": manifest["contract_version"],
            "materialized_source": (str(prepared_output) if prepared_output is not None else None),
            "patch_sha256": manifest["patch_sha256"],
            "patched_tree_hash": manifest["patched_tree_hash"],
            "required_schema_revision": manifest["required_schema_revision"],
            "schema_change_policy": manifest["schema_change_policy"],
            "status": "verified",
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--repository",
        default=str(Path(__file__).resolve().parents[2]),
        help="local Omnigent Git repository containing the fixed base commit",
    )
    parser.add_argument(
        "--output-directory",
        help="new or empty directory that will receive the verified source without .git",
    )
    arguments = parser.parse_args(argv)
    report = build_n1_compat(
        Path(arguments.repository),
        output_directory=(
            Path(arguments.output_directory) if arguments.output_directory else None
        ),
    )
    sys.stdout.write(json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
