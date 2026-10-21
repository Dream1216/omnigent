"""Prepare a fixed signed-wheel backport without changing schema or Runner grants."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Any

BASE = "f4404d47f705c7a3c0745c38ccd1a9be125c31ad"
CONTRACT = "f440-runner-management-restart-v1"
MODULE = "saas/production/postgresql_migration.py"
WHEEL = "5ea5c280800e6fa342f2422a6974862dc6399cf241c05b8988e0d3fc2c8fed72"
RUNTIME = (
    "ghcr.io/dream1216/omnigent-saas-server@"
    "sha256:2555fafc4527912705014f5a2e84ad9db4632afb18b317daeb07a433fb9bdbc2"
)
UI = (
    "ghcr.io/dream1216/omnigent-saas-server@"
    "sha256:d40b0cf4c226eb1a8743f7ffe5fbf4f8d9380e556d0330ef70ce9c6bbb13313c"
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_manifest(repository: Path) -> dict[str, Any]:
    root = repository / "saas/core_f440_compat"
    value = json.loads((root / "manifest.json").read_text())
    if (
        value.get("schema_version") != 1
        or value.get("contract") != CONTRACT
        or value.get("base_product_revision") != BASE
        or value.get("module_path") != MODULE
        or value.get("original_wheel_sha256") != WHEEL
        or value.get("runtime_base_image") != RUNTIME
        or value.get("ui_source_image") != UI
        or value.get("required_schema_revision") != "p0s000000015"
        or value.get("database_mutation") is not False
        or value.get("runner_permissions_changed") is not False
        or value.get("production_authority") is not False
        or digest((root / "postgresql_migration.patch").read_bytes()) != value.get("patch_sha256")
    ):
        raise ValueError("fixed f440 core compatibility materials differ")
    return value


def patched_module(repository: Path) -> tuple[bytes, dict[str, Any]]:
    manifest = load_manifest(repository)
    original = subprocess.check_output(["git", "show", BASE + ":" + MODULE], cwd=repository)
    if digest(original) != manifest["original_module_sha256"]:
        raise ValueError("f440 original module differs")
    with tempfile.TemporaryDirectory(prefix="omnigent-f440-core-") as directory:
        root = Path(directory)
        path = root / MODULE
        path.parent.mkdir(parents=True)
        path.write_bytes(original)
        patch = repository / "saas/core_f440_compat/postgresql_migration.patch"
        subprocess.run(
            ["git", "apply", "--unidiff-zero", "--check", str(patch)], cwd=root, check=True
        )
        subprocess.run(["git", "apply", "--unidiff-zero", str(patch)], cwd=root, check=True)
        files = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
        if files != {MODULE}:
            raise ValueError("compatibility patch changes unapproved paths")
        changed = path.read_bytes()
    if digest(changed) != manifest["patched_module_sha256"]:
        raise ValueError("patched f440 module differs")
    compile(changed, MODULE, "exec")
    return changed, manifest


def prepare(repository: Path, wheel: Path, output: Path) -> dict[str, Any]:
    changed, manifest = patched_module(repository)
    if wheel.is_symlink() or not wheel.is_file() or digest(wheel.read_bytes()) != WHEEL:
        raise ValueError("original signed f440 wheel bytes differ")
    with zipfile.ZipFile(wheel) as bundle:
        if digest(bundle.read(MODULE)) != manifest["original_module_sha256"]:
            raise ValueError("original wheel does not contain the source-pinned f440 module")
    output.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(wheel, output / wheel.name)
    (output / "postgresql_migration.py").write_bytes(changed)
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    for name in ("bind_runtime_build_revision.py", "normalize_host_cli_tree.py"):
        shutil.copyfile(repository / "saas/scripts" / name, output / name)
    tests = output / "tests/saas/fixtures"
    tests.mkdir(parents=True)
    for name in (
        "tests/__init__.py",
        "tests/saas/__init__.py",
        "tests/saas/test_production_migration_replay.py",
        "tests/saas/fixtures/production_preview_authority.sql",
    ):
        data = subprocess.check_output(["git", "show", BASE + ":" + name], cwd=repository)
        (output / name).write_bytes(data)
    shutil.copyfile(
        repository / "saas/core_f440_compat/test_revoked_runner_startup.py",
        output / "tests/saas/test_revoked_runner_startup.py",
    )
    return {
        "status": "pass",
        "contract": CONTRACT,
        "materials": manifest,
        "files": {
            p.relative_to(output).as_posix(): digest(p.read_bytes())
            for p in sorted(output.rglob("*"))
            if p.is_file()
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = prepare(args.repository.resolve(), args.wheel.resolve(), args.output.resolve())
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
