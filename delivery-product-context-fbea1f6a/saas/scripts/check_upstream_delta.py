"""Enforce the downstream source-intrusion budget against a pinned upstream."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import tomllib


@dataclass(frozen=True, slots=True)
class FileDelta:
    """Line-level change summary for one repository path."""

    path: str
    added: int
    deleted: int


def _is_under(path: str, prefixes: tuple[str, ...]) -> bool:
    return any(path == prefix.rstrip("/") or path.startswith(prefix) for prefix in prefixes)


def evaluate_delta(
    deltas: list[FileDelta],
    manifest: dict[str, Any],
    *,
    active_patch_count: int,
    reverse_dependencies: list[str],
    lineage_ok: bool,
    version_ok: bool,
) -> dict[str, Any]:
    """Evaluate a prepared delta without invoking Git, enabling unit tests."""

    budgets = manifest["source_intrusion_budget"]
    downstream_prefixes = tuple(manifest["downstream_owned_prefixes"])
    forbidden_prefixes = tuple(manifest["forbidden_upstream_prefixes"])

    upstream_deltas = [d for d in deltas if not _is_under(d.path, downstream_prefixes)]
    forbidden_files = sorted(
        d.path for d in upstream_deltas if _is_under(d.path, forbidden_prefixes)
    )
    total_added = sum(delta.added for delta in deltas)
    downstream_added = sum(
        delta.added for delta in deltas if _is_under(delta.path, downstream_prefixes)
    )
    isolated_ratio = 1.0 if total_added == 0 else downstream_added / total_added
    upstream_net_added = max(0, sum(delta.added - delta.deleted for delta in upstream_deltas))

    metrics = {
        "active_patch_count": active_patch_count,
        "direct_upstream_file_count": len(upstream_deltas),
        "forbidden_upstream_files": forbidden_files,
        "isolated_custom_code_ratio": round(isolated_ratio, 4),
        "reverse_dependencies": sorted(reverse_dependencies),
        "upstream_net_added_loc": upstream_net_added,
    }
    violations: list[str] = []
    if not lineage_ok:
        violations.append("upstream baseline is not an ancestor of the product revision")
    if not version_ok:
        violations.append("manifest upstream_version does not match pyproject.toml")
    if metrics["direct_upstream_file_count"] > budgets["max_direct_upstream_files"]:
        violations.append("direct upstream file budget exceeded")
    if upstream_net_added > budgets["max_upstream_net_added_loc"]:
        violations.append("upstream net-added LOC budget exceeded")
    if active_patch_count > budgets["max_active_patches"]:
        violations.append("active patch queue budget exceeded")
    if isolated_ratio < budgets["min_isolated_custom_code_ratio"]:
        violations.append("isolated custom-code ratio is below budget")
    if forbidden_files:
        violations.append("forbidden Agent/Harness/Native Bridge paths were modified")
    if reverse_dependencies:
        violations.append("official code imports downstream SaaS packages")

    return {
        "status": "pass" if not violations else "fail",
        "metrics": metrics,
        "budgets": budgets,
        "violations": violations,
        "files": [asdict(delta) for delta in sorted(deltas, key=lambda item: item.path)],
    }


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout


def _count_untracked_lines(path: Path) -> int:
    data = path.read_bytes()
    if b"\0" in data:
        return 0
    return len(data.splitlines())


def collect_deltas(repo: Path, baseline_revision: str) -> list[FileDelta]:
    """Collect committed, staged, unstaged, and untracked changes."""

    deltas: dict[str, FileDelta] = {}
    raw = _git(repo, "diff", "--numstat", "--no-renames", baseline_revision, "--", ".")
    for line in raw.splitlines():
        added_raw, deleted_raw, path = line.split("\t", 2)
        added = 0 if added_raw == "-" else int(added_raw)
        deleted = 0 if deleted_raw == "-" else int(deleted_raw)
        deltas[path] = FileDelta(path, added, deleted)

    untracked = _git(repo, "ls-files", "--others", "--exclude-standard", "-z")
    for path in filter(None, untracked.split("\0")):
        if path not in deltas:
            deltas[path] = FileDelta(path, _count_untracked_lines(repo / path), 0)
    return list(deltas.values())


_PYTHON_REVERSE_DEPENDENCY = re.compile(
    r"^\s*(?:from|import)\s+(?:saas|omnigent_saas)(?:\.|\s|$)", re.MULTILINE
)
_JS_REVERSE_DEPENDENCY = re.compile(r"(?:from\s+|require\()['\"](?:saas|omnigent_saas)(?:/|['\"])")


def scan_reverse_dependencies(repo: Path, upstream_paths: list[str]) -> list[str]:
    """Find official source files that import downstream-owned packages."""

    findings: list[str] = []
    for path in upstream_paths:
        source = repo / path
        if not source.is_file() or source.suffix not in {".js", ".jsx", ".py", ".ts", ".tsx"}:
            continue
        text = source.read_text(encoding="utf-8", errors="replace")
        pattern = _PYTHON_REVERSE_DEPENDENCY if source.suffix == ".py" else _JS_REVERSE_DEPENDENCY
        if pattern.search(text):
            findings.append(path)
    return findings


def _load_manifest(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_project_version(repo: Path) -> str:
    with (repo / "pyproject.toml").open("rb") as handle:
        return str(tomllib.load(handle)["project"]["version"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest", default="saas/upstream-baseline.json", help="baseline manifest path"
    )
    parser.add_argument("--output", help="optional JSON report path")
    args = parser.parse_args()

    repo = Path(_git(Path.cwd(), "rev-parse", "--show-toplevel").strip())
    manifest_path = repo / args.manifest
    manifest = _load_manifest(manifest_path)
    baseline = str(manifest["upstream_revision"])
    product_revision = _git(repo, "rev-parse", "HEAD").strip()

    lineage = (
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", baseline, "HEAD"], cwd=repo, check=False
        ).returncode
        == 0
    )
    deltas = collect_deltas(repo, baseline)
    downstream_prefixes = tuple(manifest["downstream_owned_prefixes"])
    upstream_paths = [
        delta.path for delta in deltas if not _is_under(delta.path, downstream_prefixes)
    ]
    reverse_dependencies = scan_reverse_dependencies(repo, upstream_paths)
    patch_dir = repo / str(manifest["patch_queue_directory"])
    active_patch_count = sum(1 for _ in patch_dir.glob("*.patch")) if patch_dir.exists() else 0
    version_ok = _read_project_version(repo) == manifest["upstream_version"]

    report = evaluate_delta(
        deltas,
        manifest,
        active_patch_count=active_patch_count,
        reverse_dependencies=reverse_dependencies,
        lineage_ok=lineage,
        version_ok=version_ok,
    )
    report["upstream_revision"] = baseline
    report["product_revision"] = product_revision
    report["adapter_contract_version"] = manifest["adapter_contract_version"]
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = repo / args.output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    sys.stdout.write(rendered)
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
