"""Materialize a bounded unsigned D0/T legacy wheel; never grant release authority."""

from __future__ import annotations

import argparse
import ast
import base64
import csv
import hashlib
import io
import json
import re
import stat
import subprocess
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

MANIFEST_SHA256 = "b9cb2f0090dcd6295296edd110cf895835ff7b5276dac34f82c334c613b2ef88"
ROOT = "saas/d0_legacy_compat"
MODULE = "saas/production/postgresql_migration.py"
BASELINE = "saas/upstream-baseline.json"
BUILD_INFO = "omnigent/_build_info.py"
RECORD = "omnigent-0.18.0.dev20261006.dist-info/RECORD"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(value: object, message: str) -> None:
    if not value:
        raise ValueError(message)


def load_manifest(repository: Path) -> dict:
    raw = (repository / ROOT / "manifest.json").read_bytes()
    require(digest(raw) == MANIFEST_SHA256, "fixed D0 compatibility manifest differs")
    manifest = json.loads(raw)
    patch = (repository / ROOT / "M3659-D0-T.patch").read_bytes()
    require(digest(patch) == manifest["patch_sha256"], "fixed D0 compatibility patch differs")
    return manifest


def wheel_members(wheel: Path, manifest: dict) -> tuple[dict, dict]:
    require(
        wheel.is_file()
        and not wheel.is_symlink()
        and digest(wheel.read_bytes()) == manifest["original_wheel_sha256"],
        "original signed M3659 wheel differs",
    )
    with zipfile.ZipFile(wheel) as bundle:
        infos = bundle.infolist()
        names = [info.filename for info in infos]
        require(len(names) == len(set(names)), "duplicate wheel member")
        for info in infos:
            path = PurePosixPath(info.filename)
            require(
                not path.is_absolute()
                and ".." not in path.parts
                and "\\" not in info.filename
                and stat.S_IFMT(info.external_attr >> 16) != stat.S_IFLNK,
                "unsafe wheel member",
            )
        return {info.filename: bundle.read(info) for info in infos}, {
            info.filename: info for info in infos
        }


def materialize(repository: Path, wheel: Path) -> tuple[dict, dict, dict]:
    manifest = load_manifest(repository)
    members, infos = wheel_members(wheel, manifest)
    expected = manifest["files"]
    with tempfile.TemporaryDirectory(prefix="omnigent-d0-compat-") as temporary:
        root = Path(temporary)
        for name, pins in expected.items():
            if pins["original_sha256"] is None:
                require(name not in members, "unexpected preexisting migration")
                continue
            require(digest(members[name]) == pins["original_sha256"], "base module differs")
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(members[name])
        patch = repository / ROOT / "M3659-D0-T.patch"
        for arguments in (("--check",), ()):
            subprocess.run(
                ["git", "apply", "--unidiff-zero", *arguments, str(patch)], cwd=root, check=True
            )
        changed = {
            p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()
        }
    require(set(changed) == set(expected), "compatibility patch expands allowed paths")
    for name, content in changed.items():
        require(digest(content) == expected[name]["patched_sha256"], "patched bytes differ")
        if name.endswith(".py"):
            compile(content, name, "exec")

    # Catalog constants may grow; every existing function/class must retain its
    # original implementation. No verifier, query or permission code is patched.
    def implementations(content):
        return [
            ast.dump(node, include_attributes=False)
            for node in ast.parse(content).body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        ]

    require(
        implementations(members[MODULE]) == implementations(changed[MODULE]),
        "legacy verifier implementation changed",
    )
    before, after = json.loads(members[BASELINE]), json.loads(changed[BASELINE])
    require(after.pop("official_schema_heads") == ["d0a1f879a01d"], "D0 head differs")
    before.pop("official_schema_heads")
    require(before == after, "legacy baseline expands scope")
    members.update(changed)
    return members, infos, manifest


def write_wheel(members: dict, infos: dict, target: Path, revision: str, epoch: int) -> None:
    require(
        bool(re.fullmatch(r"[0-9a-f]{40}", revision)) and epoch >= 0,
        "immutable product coordinates required",
    )
    members = dict(members)
    members[BUILD_INFO] = (
        '"""Auto-generated for an immutable Omnigent runtime image; do not edit."""\n'
        "from __future__ import annotations\n\n"
        f"BUILD_TIME_EPOCH: int = {epoch}\nCOMMIT_SHA: str = {revision!r}\n"
    ).encode()
    record = io.StringIO(newline="")
    writer = csv.writer(record, lineterminator="\n")
    for name, content in sorted(members.items()):
        if name != RECORD:
            encoded = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=")
            writer.writerow((name, "sha256=" + encoded.decode(), len(content)))
    writer.writerow((RECORD, "", ""))
    members[RECORD] = record.getvalue().encode()
    with zipfile.ZipFile(target, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
        for name, content in sorted(members.items()):
            info = infos.get(name)
            if info is None:
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
            bundle.writestr(info, content)


def prepare(repository: Path, wheel: Path, output: Path, revision: str) -> dict:
    manifest = load_manifest(repository)
    require(
        subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repository).decode().strip()
        == revision,
        "exact recipe source revision required",
    )
    for name in ("manifest.json", "M3659-D0-T.patch"):
        path = ROOT + "/" + name
        committed = subprocess.check_output(["git", "show", revision + ":" + path], cwd=repository)
        require(committed == (repository / path).read_bytes(), "uncommitted recipe refused")
    builder = "saas/scripts/prepare_d0_legacy_compat.py"
    committed_builder = subprocess.check_output(
        ["git", "show", revision + ":" + builder], cwd=repository
    )
    require(committed_builder == Path(__file__).read_bytes(), "uncommitted builder refused")
    epoch = int(
        subprocess.check_output(["git", "show", "-s", "--format=%ct", revision], cwd=repository)
    )
    members, infos, manifest = materialize(repository, wheel)
    output.mkdir(parents=True, exist_ok=False)
    target = output / wheel.name
    write_wheel(members, infos, target, revision, epoch)
    receipt = {
        "status": "unsigned_materialization_only",
        "source_revision": revision,
        "source_date_epoch": epoch,
        "materials": manifest,
        "wheel_sha256": digest(target.read_bytes()),
        "production_authority": False,
        "image_or_rollback_qualification": False,
    }
    (output / "materialization.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    args = parser.parse_args()
    print(
        json.dumps(
            prepare(
                args.repository.resolve(),
                args.wheel.resolve(),
                args.output.resolve(),
                args.source_revision,
            ),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
