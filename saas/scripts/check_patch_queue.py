"""Replay every downstream patch against the pinned official revision."""

from __future__ import annotations

import argparse
import json
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Any


def _run(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=check,
        capture_output=True,
        text=True,
    )


def _patch_paths(patch: Path) -> tuple[str, ...]:
    paths: set[str] = set()
    for line in patch.read_text(encoding="utf-8").splitlines():
        if line.startswith("diff --git a/"):
            parts = line.split(" ", 3)
            if len(parts) == 4 and parts[3].startswith("b/"):
                paths.add(parts[3].removeprefix("b/"))
    return tuple(sorted(paths))


def check_patch_queue(repo: Path) -> dict[str, Any]:
    manifest = json.loads((repo / "saas/upstream-baseline.json").read_text(encoding="utf-8"))
    baseline = str(manifest["upstream_revision"])
    patch_directory = repo / str(manifest["patch_queue_directory"])
    patches = sorted(patch_directory.glob("*.patch"))
    ledger = (patch_directory / "README.md").read_text(encoding="utf-8")
    official_deltas = set(
        filter(
            None,
            _run(repo, "diff", "--name-only", baseline, "--", "omnigent").stdout.splitlines(),
        )
    )
    official_deltas.update(
        filter(
            None,
            _run(
                repo,
                "ls-files",
                "--others",
                "--exclude-standard",
                "--",
                "omnigent",
            ).stdout.splitlines(),
        )
    )
    covered_paths: set[str] = set()
    results: list[dict[str, object]] = []
    violations: list[str] = []

    with tempfile.TemporaryDirectory(prefix="omnigent-patch-replay-") as temp_name:
        temp_root = Path(temp_name)
        archive_path = temp_root / "upstream.tar"
        checkout = temp_root / "checkout"
        checkout.mkdir()
        _run(repo, "archive", "--format=tar", f"--output={archive_path}", baseline)
        with tarfile.open(archive_path) as archive:
            archive.extractall(checkout, filter="data")

        for patch in patches:
            paths = _patch_paths(patch)
            covered_paths.update(paths)
            if patch.name not in ledger:
                violations.append(f"patch ledger is missing {patch.name}")
            checked = _run(
                checkout,
                "apply",
                "--check",
                str(patch),
                check=False,
            )
            applied = checked.returncode == 0
            results.append(
                {
                    "patch": patch.name,
                    "paths": list(paths),
                    "applies": applied,
                    "error": checked.stderr.strip() if not applied else "",
                }
            )
            if not applied:
                violations.append(f"patch does not apply to replay state: {patch.name}")
                break
            _run(checkout, "apply", str(patch))

    missing_patch_paths = sorted(official_deltas - covered_paths)
    stale_patch_paths = sorted(covered_paths - official_deltas)
    if missing_patch_paths:
        violations.append(f"official source changes lack patches: {missing_patch_paths}")
    if stale_patch_paths:
        violations.append(f"patches do not match product source changes: {stale_patch_paths}")
    return {
        "status": "pass" if not violations else "fail",
        "upstream_revision": baseline,
        "patch_count": len(patches),
        "official_source_paths": sorted(official_deltas),
        "covered_paths": sorted(covered_paths),
        "patches": results,
        "violations": violations,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", help="optional JSON evidence path")
    args = parser.parse_args()
    repo = Path(_run(Path.cwd(), "rev-parse", "--show-toplevel").stdout.strip())
    report = check_patch_queue(repo)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = repo / args.output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
