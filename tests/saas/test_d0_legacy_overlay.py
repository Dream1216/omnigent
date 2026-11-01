"""Filesystem/RECORD boundaries after fixed material validation; no image authority."""

from __future__ import annotations

import csv
import hashlib
import io
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from saas.scripts import export_d0_legacy_overlay as overlay


@pytest.fixture
def installed_base(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    prefix = tmp_path / "base"
    site = prefix / "lib/python3.12/site-packages"
    module = "saas/production/postgresql_migration.py"
    new = "omnigent/db/migrations/versions/new_fixed.py"
    old_revision, revision, epoch = "1" * 40, "2" * 40, 1234

    def identity(value):
        return (
            f'from __future__ import annotations\nCOMMIT_SHA: str = "{value}"\n'
            f"BUILD_TIME_EPOCH: int = {epoch}\n"
        ).encode()

    metadata = overlay.recipe.RECORD.removesuffix("RECORD") + "METADATA"
    before = {
        module: b"original source",
        overlay.recipe.BUILD_INFO: identity(old_revision),
        metadata: b"Name: omnigent\nVersion: 0.18.0.dev20261006\n",
        "other/unchanged.bin": b"immutable dependency",
        "other/UI.html": b"immutable UI",
    }
    for name, content in before.items():
        path = site / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    record = io.StringIO(newline="")
    rows = [
        [name, "retained-original-hash", str(len(content))] for name, content in before.items()
    ]
    rows += [
        ["../../../bin/omni", "retained-entrypoint-hash", "42"],
        [overlay.recipe.RECORD, "", ""],
    ]
    csv.writer(record, lineterminator="\n").writerows(rows)
    (site / overlay.recipe.RECORD).write_text(record.getvalue())
    payload = {
        module: b"fixed source",
        new: b"fixed migration",
        overlay.recipe.BUILD_INFO: identity(revision),
    }
    manifest = {
        "legacy_runtime_version": "0.18.0.dev20261006",
        "base_product_revision": old_revision,
        "files": {
            module: {"original_sha256": hashlib.sha256(before[module]).hexdigest()},
            new: {"original_sha256": None},
        },
    }
    distribution = SimpleNamespace(
        version="0.18.0.dev20261006", locate_file=lambda name: site / name
    )
    monkeypatch.setattr(overlay, "sys", SimpleNamespace(prefix=str(prefix)))
    monkeypatch.setattr(
        overlay,
        "importlib",
        SimpleNamespace(metadata=SimpleNamespace(distribution=lambda name: distribution)),
    )
    monkeypatch.setattr(overlay, "read_payload", lambda *args: (dict(payload), before, manifest))

    def run(output):
        return overlay.export(tmp_path, tmp_path, tmp_path, tmp_path, revision, epoch, output)

    return SimpleNamespace(
        prefix=prefix, site=site, run=run, payload=payload, module=module, rows=rows
    )


def snapshot(root):
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def test_export_preserves_installed_UI_dependencies_and_installer_RECORD_rows(
    installed_base, tmp_path
):
    base = installed_base
    before = snapshot(base.prefix)
    output = tmp_path / "overlay"
    receipt = base.run(output)
    assert snapshot(base.prefix) == before
    assert len(receipt["files"]) == len(base.payload) + 1
    shutil.copytree(output, base.prefix, dirs_exist_ok=True)
    after = snapshot(base.prefix)
    changed = {name for name in after if name not in before or before[name] != after[name]}
    relative = base.site.relative_to(base.prefix)
    assert changed == {
        (relative / name).as_posix() for name in (*base.payload, overlay.recipe.RECORD)
    }
    rows = {
        row[0]: row
        for row in csv.reader(io.StringIO((base.site / overlay.recipe.RECORD).read_text()))
    }
    for row in base.rows:
        if row[0] not in base.payload and row[0] != overlay.recipe.RECORD:
            assert rows[row[0]] == row


@pytest.mark.parametrize(
    "fault", ["source", "metadata", "symlink", "bytecode", "duplicate_record"]
)
def test_invalid_base_is_refused_before_any_overlay_output(installed_base, tmp_path, fault):
    base = installed_base
    target = base.site / base.module
    if fault == "source":
        target.write_bytes(b"foreign base source")
    elif fault == "metadata":
        (base.site / (overlay.recipe.RECORD.removesuffix("RECORD") + "METADATA")).write_bytes(
            b"foreign metadata"
        )
    elif fault == "symlink":
        external = tmp_path / "outside.py"
        external.write_bytes(target.read_bytes())
        target.unlink()
        target.symlink_to(external)
    elif fault == "bytecode":
        bytecode = target.parent / "__pycache__" / (target.stem + ".cpython-312.pyc")
        bytecode.parent.mkdir()
        bytecode.write_bytes(b"stale bytecode")
    else:
        record = base.site / overlay.recipe.RECORD
        record.write_text(record.read_text() + "other/unchanged.bin,duplicate,42\n")
    output = tmp_path / "refused"
    before = snapshot(base.prefix)
    with pytest.raises(ValueError):
        base.run(output)
    assert not output.exists()
    assert snapshot(base.prefix) == before


def test_build_identity_rejects_executable_code():
    with pytest.raises(ValueError):
        overlay.build_identity(b"raise RuntimeError('untrusted identity')")


@pytest.mark.parametrize("form", ["full", "headers", "dependency", "version", "description"])
def test_image_readme_omission_cannot_hide_dependency_or_metadata_changes(form):
    headers = b"Name: omnigent\nVersion: 0.18.0.dev20261006\nRequires-Dist: pillow<14,>=13.0.0\n"
    original = headers + b"\nExact signed README body\n"
    actual = original if form == "full" else headers
    if form == "dependency":
        actual = actual.replace(b"pillow<14,>=13.0.0", b"pillow<13,>=12.2")
    elif form == "version":
        actual = actual.replace(b"0.18.0", b"0.17.0")
    elif form == "description":
        actual += b"\nDifferent description\n"
    if form in {"full", "headers"}:
        overlay.require_original_dependency_metadata(actual, original)
    else:
        with pytest.raises(ValueError, match="installed dependency metadata differs"):
            overlay.require_original_dependency_metadata(actual, original)
