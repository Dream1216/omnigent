from __future__ import annotations

from pathlib import Path

import pytest

from saas.scripts.finalize_artifact_receipt_revision import (
    finalize_manifest,
    validate_pending_manifest,
)

_SENTINEL = "sha256:" + ("0" * 64)
_REVISION = "sha256:" + ("1" * 64)


def _pending_manifest(tmp_path: Path) -> Path:
    path = tmp_path / "kubernetes.production.yaml"
    path.write_text(
        "apiVersion: v1\n"
        "kind: ConfigMap\n"
        "data:\n"
        f"      OMNIGENT_SAAS_ARTIFACT_ADMISSION_RECEIPT_REVISION: {_SENTINEL}\n"
        "---\n"
        "spec:\n"
        "  template:\n"
        "    metadata:\n"
        "      annotations:\n"
        f"            omnigent.io/artifact-admission-receipt-revision: {_SENTINEL}\n",
        encoding="utf-8",
    )
    return path


def test_finalizer_replaces_only_two_exact_receipt_fields_atomically(tmp_path: Path) -> None:
    path = _pending_manifest(tmp_path)
    path.chmod(0o640)

    validate_pending_manifest(path)
    finalize_manifest(path, _REVISION)

    text = path.read_text(encoding="utf-8")
    assert _SENTINEL not in text
    assert text.count(_REVISION) == 2
    assert path.stat().st_mode & 0o777 == 0o640


def test_finalizer_rejects_other_unresolved_template_sentinel(tmp_path: Path) -> None:
    path = _pending_manifest(tmp_path)
    path.write_text(path.read_text(encoding="utf-8") + "  image: replace.image\n")

    with pytest.raises(ValueError, match="outside the two pending receipt fields"):
        validate_pending_manifest(path)


@pytest.mark.parametrize("revision", [_SENTINEL, "sha256:ABC", "1" * 64])
def test_finalizer_rejects_invalid_or_zero_revision(tmp_path: Path, revision: str) -> None:
    with pytest.raises(ValueError, match="nonzero sha256"):
        finalize_manifest(_pending_manifest(tmp_path), revision)


def test_finalizer_rejects_rerun_after_receipt_is_bound(tmp_path: Path) -> None:
    path = _pending_manifest(tmp_path)
    finalize_manifest(path, _REVISION)

    with pytest.raises(ValueError, match="must occur exactly once"):
        finalize_manifest(path, _REVISION)
