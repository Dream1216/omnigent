"""Export only the fixed legacy compatibility files over a verified installed base."""

from __future__ import annotations

import argparse
import ast
import base64
import csv
import importlib.metadata
import importlib.util
import io
import json
import os
import sys
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "_fixed_d0_recipe", Path(__file__).with_name("prepare_d0_legacy_compat.py")
)
assert _SPEC is not None and _SPEC.loader is not None
recipe = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(recipe)


def build_identity(content: bytes) -> dict:
    values = {}
    for node in ast.parse(content).body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            recipe.require(isinstance(node.value.value, str), "invalid build identity expression")
        elif isinstance(node, ast.ImportFrom):
            recipe.require(
                node.module == "__future__"
                and len(node.names) == 1
                and node.names[0].name == "annotations"
                and node.names[0].asname is None,
                "invalid build identity import",
            )
        else:
            if not (
                isinstance(node, ast.AnnAssign)
                and isinstance(node.target, ast.Name)
                and node.target.id in {"COMMIT_SHA", "BUILD_TIME_EPOCH"}
                and isinstance(node.annotation, ast.Name)
                and node.annotation.id in {"str", "int"}
                and node.target.id not in values
                and node.value is not None
            ):
                raise ValueError("invalid build identity declaration")
            values[node.target.id] = ast.literal_eval(node.value)
    recipe.require(
        set(values) == {"COMMIT_SHA", "BUILD_TIME_EPOCH"}
        and type(values["COMMIT_SHA"]) is str
        and type(values["BUILD_TIME_EPOCH"]) is int
        and values["BUILD_TIME_EPOCH"] >= 0,
        "incomplete build identity",
    )
    return values


def read_payload(repository, original_wheel, patched_wheel, materialization, revision, epoch):
    manifest = recipe.load_manifest(repository)
    receipt = json.loads(materialization.read_text())
    recipe.require(
        receipt["status"] == "unsigned_materialization_only"
        and receipt["materials"] == manifest
        and receipt["source_revision"] == revision
        and receipt["source_date_epoch"] == epoch
        and receipt["production_authority"] is False
        and receipt["image_or_rollback_qualification"] is False,
        "materialization is not this fixed source contract",
    )
    original, _ = recipe.wheel_members(original_wheel, manifest)
    patched, _ = recipe.wheel_members(
        patched_wheel, {"original_wheel_sha256": receipt["wheel_sha256"]}
    )
    changed = {
        name
        for name, content in patched.items()
        if name not in original or original[name] != content
    }
    recipe.require(set(original) <= set(patched), "original wheel member removed")
    recipe.require(
        changed == set(manifest["files"]) | {recipe.BUILD_INFO, recipe.RECORD},
        "patched wheel expands fixed payload",
    )
    for name, pins in manifest["files"].items():
        recipe.require(
            recipe.digest(patched[name]) == pins["patched_sha256"], "fixed payload bytes differ"
        )
    recipe.require(
        build_identity(patched[recipe.BUILD_INFO])
        == {"COMMIT_SHA": revision, "BUILD_TIME_EPOCH": epoch},
        "patched product identity differs",
    )
    return {name: patched[name] for name in changed if name != recipe.RECORD}, original, manifest


def export(repository, original_wheel, patched_wheel, materialization, revision, epoch, output):
    payload, original, manifest = read_payload(
        repository, original_wheel, patched_wheel, materialization, revision, epoch
    )
    prefix = Path(sys.prefix).resolve()
    distribution = importlib.metadata.distribution("omnigent")
    recipe.require(
        distribution.version == manifest["legacy_runtime_version"],
        "installed legacy version differs",
    )
    site = Path(str(distribution.locate_file(""))).resolve()
    record = Path(str(distribution.locate_file(recipe.RECORD)))
    recipe.require(
        site.is_relative_to(prefix)
        and record.is_file()
        and not record.is_symlink()
        and record.resolve() == site / recipe.RECORD,
        "installed distribution escapes runtime prefix",
    )
    metadata = recipe.RECORD.removesuffix("RECORD") + "METADATA"
    for name in (*payload, metadata):
        target = site / name
        recipe.require(
            target.resolve() == target and target.is_relative_to(site),
            "installed payload path escapes runtime prefix",
        )
    recipe.require(
        build_identity((site / recipe.BUILD_INFO).read_bytes())["COMMIT_SHA"]
        == manifest["base_product_revision"],
        "installed base product differs",
    )
    recipe.require(
        (site / metadata).read_bytes() == original[metadata],
        "installed dependency metadata differs",
    )
    for name, pins in manifest["files"].items():
        target = site / name
        recipe.require(
            target.resolve().is_relative_to(site) and not target.is_symlink(),
            "installed payload path escapes runtime prefix",
        )
        if pins["original_sha256"] is None:
            recipe.require(not target.exists(), "unexpected base migration already exists")
        else:
            recipe.require(
                target.is_file() and recipe.digest(target.read_bytes()) == pins["original_sha256"],
                "installed base source differs",
            )
    for name in payload:
        target = site / name
        recipe.require(
            not list(target.parent.glob("__pycache__/" + target.stem + ".*.pyc")),
            "cached base bytecode requires separate qualification",
        )
    rows = list(csv.reader(io.StringIO(record.read_text())))
    recipe.require(all(len(row) == 3 for row in rows), "invalid installed RECORD")
    records = {row[0]: row for row in rows}
    recipe.require(len(records) == len(rows), "duplicate installed RECORD member")
    for name, content in payload.items():
        encoded = base64.urlsafe_b64encode(bytes.fromhex(recipe.digest(content))).rstrip(b"=")
        records[name] = [name, "sha256=" + encoded.decode(), str(len(content))]
    records[recipe.RECORD] = [recipe.RECORD, "", ""]
    updated = io.StringIO(newline="")
    csv.writer(updated, lineterminator="\n").writerows(records[name] for name in sorted(records))
    payload[recipe.RECORD] = updated.getvalue().encode()
    output = output.resolve()
    recipe.require(
        not output.is_relative_to(prefix) and not output.exists(),
        "fresh external overlay output required",
    )
    output.mkdir(parents=True)
    exported = {}
    for name, content in payload.items():
        relative = (site / name).relative_to(prefix)
        target = output / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        target.chmod(0o644)
        os.utime(target, (epoch, epoch))
        exported[relative.as_posix()] = recipe.digest(content)
    for directory in sorted((p for p in output.rglob("*") if p.is_dir()), reverse=True):
        directory.chmod(0o755)
        os.utime(directory, (epoch, epoch))
    output.chmod(0o755)
    os.utime(output, (epoch, epoch))
    return {
        "status": "fixed_overlay_exported",
        "source_revision": revision,
        "base_product_revision": manifest["base_product_revision"],
        "files": exported,
        "installed_base_mutated": False,
        "dependency_changes": False,
        "production_or_image_qualification": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--original-wheel", type=Path, required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--materialization", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--source-date-epoch", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(
        json.dumps(
            export(
                args.repository.resolve(),
                args.original_wheel.resolve(),
                args.wheel.resolve(),
                args.materialization.resolve(),
                args.source_revision,
                args.source_date_epoch,
                args.output,
            ),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
