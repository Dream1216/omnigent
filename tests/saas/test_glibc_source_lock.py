from __future__ import annotations

import hashlib
import json
from pathlib import Path

SUPPLY_CHAIN = Path(__file__).resolve().parents[2] / "saas/supply_chain"


def test_glibc_lock_requires_signed_dsc_and_nonproduction_scope() -> None:
    lock = json.loads((SUPPLY_CHAIN / "debian13-glibc-source-lock.json").read_text())
    assert lock["production_admission"] is False
    assert lock["codename"] == "trixie"
    assert "--require-valid-signature" in lock["extraction_contract"]
    assert "--require-strong-checksums" in lock["extraction_contract"]
    assert lock["source_authentication"]["primary_fingerprint"] == (
        "77462642A9EF94FD0F77196DBA9C78061DDD8C9B"
    )
    assert {item["role"] for item in lock["artifacts"]} == {
        "dsc",
        "upstream",
        "debian",
        "keyring",
        "reviewed-backport",
    }


def test_reviewed_glibc_patch_preserves_upstream_deletions() -> None:
    lock = json.loads((SUPPLY_CHAIN / "debian13-glibc-source-lock.json").read_text())
    material = next(item for item in lock["artifacts"] if item["role"] == "reviewed-backport")
    data = (SUPPLY_CHAIN / "glibc-source-build" / material["name"]).read_bytes()
    assert len(data) == material["size"]
    assert hashlib.sha256(data).hexdigest() == material["sha256"]
    assert f"Backport-Of: {material['upstream_commit']}".encode() in data
    deleted = [
        line[1:]
        for line in data.splitlines(keepends=True)
        if line.startswith(b"-") and not line.startswith((b"---", b"-- "))
    ]
    assert len(deleted) == material["removed_lines"] == 95
    assert hashlib.sha256(b"".join(deleted)).hexdigest() == material["removed_lines_sha256"]
