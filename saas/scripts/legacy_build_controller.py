"""Read trusted legacy profiles and stage fresh unprivileged build artifacts.

This entry point does not grant signing or production admission. Complete
source CI, native PostgreSQL and independent signed readback remain separate.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import shutil
import subprocess
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

import tomllib

from saas.scripts.legacy_artifact_download import download_artifact_bytes
from saas.scripts.legacy_native_evidence import api
from saas.scripts.legacy_pr_candidate import (
    collect_native_pr_oci,
    load_transfer_profile,
)
from saas.scripts.oci_promotion import extract_artifact, require
from saas.scripts.protected_legacy_initial_build import (
    BASELINES,
    REPOSITORY,
    load_profile,
    verify_build_artifact,
    verify_pr_tree,
    verify_source_delta,
    verify_wheel,
)

STATIC_WHEEL_PATHS = (
    "omnigent/server/static/web-ui/index.html",
    "saas/login_ui/static/login.html",
    "saas/login_ui/static/signup.html",
    "saas/login_ui/static/signup-verify.html",
    "saas/login_ui/static/signup-status.html",
    "saas/login_ui/static/script-hashes.json",
    "saas/login_ui/static/LICENSE-Manrope.txt",
)


def load_original_inputs(control: Path, profile: dict[str, Any]) -> dict[str, Any]:
    """Original artifact coordinates must come from the reviewed control tree."""
    path = control / "saas/supply_chain/legacy-security-original-inputs.json"
    require(path.is_file() and not path.is_symlink(), "missing reviewed original inputs")
    store = json.loads(path.read_text())
    require(
        set(store) == {"schema_version", "inputs"}
        and type(store["schema_version"]) is int
        and store["schema_version"] == 1
        and isinstance(store["inputs"], dict),
        "original input store differs",
    )
    selected = store["inputs"].get(profile["component"])
    require(
        isinstance(selected, dict)
        and set(selected) == {"component", "product_revision", "product_tree", "original_pr_oci"}
        and all(
            selected[key] == profile[key]
            for key in ("component", "product_revision", "product_tree")
        ),
        "original artifact has no reviewed exact-product binding",
    )
    original = selected["original_pr_oci"]
    require(
        isinstance(original, dict)
        and set(original)
        == {"run_id", "attempt", "artifact_id", "zip_size", "zip_sha256", "seal_sha256"}
        and all(
            type(original[key]) is int and original[key] > 0
            for key in ("run_id", "attempt", "artifact_id", "zip_size")
        )
        and all(
            isinstance(original[key], str)
            and re.fullmatch(r"[0-9a-f]{64}", original[key]) is not None
            for key in ("zip_sha256", "seal_sha256")
        ),
        "reviewed original OCI coordinates differ",
    )
    return original


def control_context(control: Path, revision: str) -> None:
    """Require the native dispatch context and the exact clean control checkout."""
    require(
        isinstance(revision, str) and re.fullmatch(r"[0-9a-f]{40}", revision) is not None,
        "control revision must be immutable",
    )
    require(
        os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
        and os.environ.get("GITHUB_REF") == "refs/heads/main"
        and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and os.environ.get("GITHUB_SHA") == revision,
        "legacy build requires the protected native main context",
    )

    def git(*args: str) -> str:
        return subprocess.check_output(["git", *args], cwd=control, text=True).strip()

    require(git("rev-parse", "HEAD") == revision, "control checkout revision differs")
    require(
        not git("status", "--porcelain=v1", "--untracked-files=all"),
        "control checkout contains unsealed inputs",
    )


def select_product(control: Path, component: str, control_revision: str) -> dict[str, str]:
    control_context(control, control_revision)
    profile = load_profile(control, component)
    load_transfer_profile(control, component)
    return {
        "component": component,
        "product_revision": profile["product_revision"],
        "product_tree": profile["product_tree"],
        "source_date_epoch": str(profile["source_date_epoch"]),
        "control_revision": control_revision,
        "profile_sha256": hashlib.sha256(json.dumps(profile, sort_keys=True).encode()).hexdigest(),
    }


def original_required_wheel_paths(product: Path, profile: dict[str, Any]) -> tuple[str, ...]:
    """Read the product's original literal manifest without importing its code."""
    body = subprocess.check_output(
        [
            "git",
            "cat-file",
            "blob",
            profile["product_revision"] + ":saas/scripts/check_wheel_contents.py",
        ],
        cwd=product,
    )
    require(len(body) <= 262144, "original wheel manifest exceeds its parser bound")
    found = []
    for node in ast.parse(body).body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "REQUIRED_WHEEL_PATHS"
            for target in node.targets
        ):
            found.append(ast.literal_eval(node.value))
    require(
        len(found) == 1 and isinstance(found[0], (tuple, list)) and 0 < len(found[0]) <= 2048,
        "original wheel manifest is missing or ambiguous",
    )
    paths = found[0]
    require(
        all(
            isinstance(path, str)
            and bool(path)
            and len(path) < 512
            and not PurePosixPath(path).is_absolute()
            and ".." not in PurePosixPath(path).parts
            for path in paths
        )
        and len(paths) == len(set(paths)),
        "unsafe original wheel manifest",
    )
    return tuple(paths)


def write_build_constraints(product: Path, profile: dict[str, Any], destination: Path) -> str:
    """Use the reviewed product lock's setuptools artifacts for its build backend."""
    verify_source_delta(product, profile)

    def git_file(path: str) -> bytes:
        return subprocess.check_output(
            ["git", "cat-file", "blob", profile["product_revision"] + ":" + path],
            cwd=product,
        )

    project = tomllib.loads(git_file("pyproject.toml").decode())
    require(
        project.get("build-system")
        == {"requires": ["setuptools>=68.0"], "build-backend": "setuptools.build_meta"},
        "legacy build backend differs from the original contract",
    )
    locked = tomllib.loads(git_file("uv.lock").decode())
    packages = [row for row in locked.get("package", []) if row.get("name") == "setuptools"]
    require(len(packages) == 1, "build backend has no unique reviewed lock entry")
    package = packages[0]
    require(
        re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", package.get("version", "")) is not None
        and package.get("source") == {"registry": "https://pypi.org/simple"},
        "build backend registry or version differs",
    )
    wheels = package.get("wheels", [])
    require(isinstance(wheels, list) and bool(wheels), "build backend has no locked wheel")
    hashes = []
    for item in [*wheels, package.get("sdist", {})]:
        require(
            isinstance(item.get("url"), str)
            and item["url"].startswith("https://files.pythonhosted.org/")
            and re.fullmatch(r"sha256:[0-9a-f]{64}", item.get("hash", "")) is not None,
            "build backend lacks a reviewed artifact hash",
        )
        hashes.append(item["hash"])
    line = (
        f"setuptools=={package['version']} "
        + " ".join(f"--hash={value}" for value in sorted(set(hashes)))
        + "\n"
    )
    with destination.open("x") as output:
        output.write(line)
    return hashlib.sha256(line.encode()).hexdigest()


def wheel_source_facts(
    product: Path, wheel: Path, profile: dict[str, Any], control_revision: str
) -> dict[str, Any]:
    """Recompute source and payload facts instead of trusting wheel-owned JSON."""
    verify_source_delta(product, profile)
    require(
        wheel.name == f"omnigent-{profile['application_version']}-py3-none-any.whl",
        "new wheel filename differs from the original product distribution",
    )
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    verify_wheel(wheel, profile, digest)
    required = original_required_wheel_paths(product, profile)
    with zipfile.ZipFile(wheel) as bundle:
        names = set(bundle.namelist())
        require(
            set(required) | set(STATIC_WHEEL_PATHS) <= names,
            "new wheel omits original SaaS or generated UI artifacts",
        )
        require(
            all(bundle.getinfo(path).file_size > 0 for path in STATIC_WHEEL_PATHS),
            "new wheel contains empty generated UI artifacts",
        )
        require(
            any(
                name.startswith("omnigent/server/static/web-ui/assets/") and name.endswith(".js")
                for name in names
            )
            and any(
                name.startswith("saas/login_ui/static/_next/static/") and name.endswith(".js")
                for name in names
            ),
            "new wheel lacks generated SPA or login chunks",
        )
    return {
        "schema_version": 1,
        "kind": "fresh_legacy_product_wheel/v1",
        "component": profile["component"],
        "product_revision": profile["product_revision"],
        "product_tree": profile["product_tree"],
        "application_version": profile["application_version"],
        "source_date_epoch": profile["source_date_epoch"],
        "control_revision": control_revision,
        "wheel_filename": wheel.name,
        "wheel_sha256": digest,
        "original_required_paths_sha256": hashlib.sha256(
            json.dumps(required, separators=(",", ":")).encode()
        ).hexdigest(),
        "original_required_path_count": len(required),
        "required_generated_static_paths": list(STATIC_WHEEL_PATHS),
    }


def stage_wheel(
    product: Path,
    dist: Path,
    destination: Path,
    profile: dict[str, Any],
    control_revision: str,
) -> dict[str, Any]:
    wheels = list(dist.glob("*.whl"))
    require(len(wheels) == 1, "fresh wheel build must produce exactly one wheel")
    facts = wheel_source_facts(product, wheels[0], profile, control_revision)
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    target = destination / wheels[0].name
    shutil.copyfile(wheels[0], target, follow_symlinks=False)
    require(
        hashlib.sha256(target.read_bytes()).hexdigest() == facts["wheel_sha256"],
        "fresh wheel changed while staging",
    )
    (destination / "wheel-source.json").write_text(
        json.dumps(facts, sort_keys=True, indent=2) + "\n"
    )
    (destination / "SHA256SUMS").write_text(f"{facts['wheel_sha256']}  {target.name}\n")
    return facts


def verify_wheel_bundle(
    archive: Path,
    destination: Path,
    *,
    product: Path,
    profile: dict[str, Any],
    control_revision: str,
    zip_sha256: str,
) -> dict[str, Any]:
    filename = f"omnigent-{profile['application_version']}-py3-none-any.whl"
    expected = {filename, "wheel-source.json", "SHA256SUMS"}
    with zipfile.ZipFile(archive) as bundle:
        names = bundle.namelist()
        require(
            len(names) == len(expected) and set(names) == expected,
            "fresh wheel artifact has unexpected or missing payloads",
        )
        require(
            bundle.getinfo("wheel-source.json").file_size <= 1048576
            and bundle.getinfo("SHA256SUMS").file_size <= 1024,
            "fresh wheel manifest exceeds its parser bound",
        )
    extract_artifact(archive, destination, zip_sha256=zip_sha256)
    facts = wheel_source_facts(product, destination / filename, profile, control_revision)
    require(
        json.loads((destination / "wheel-source.json").read_text()) == facts
        and (destination / "SHA256SUMS").read_text() == f"{facts['wheel_sha256']}  {filename}\n",
        "fresh wheel artifact facts differ from actual source or bytes",
    )
    return facts


def download_original_oci(
    control: Path,
    component: str,
    *,
    run_id: int,
    attempt: int,
    artifact_id: int,
    zip_size: int,
    zip_sha256: str,
    seal_sha256: str,
    destination: Path,
) -> dict[str, Any]:
    result = collect_native_pr_oci(
        control,
        component,
        run_id=run_id,
        attempt=attempt,
        artifact_id=artifact_id,
        zip_size=zip_size,
        zip_sha256=zip_sha256,
        seal_sha256=seal_sha256,
        destination=destination,
    )
    download_artifact_bytes(
        artifact_id,
        destination / "original-oci.zip",
        expected_size=zip_size,
        expected_sha256=zip_sha256,
    )
    refreshed = api(f"repos/{REPOSITORY}/actions/artifacts/{artifact_id}")
    require(
        all(
            refreshed.get(key) == result["native_artifact"].get(key)
            for key in (
                "id",
                "name",
                "size_in_bytes",
                "digest",
                "expired",
                "workflow_run",
            )
        ),
        "original OCI artifact changed during native download",
    )
    latest = api(f"repos/{REPOSITORY}/actions/runs/{run_id}")
    require(
        all(
            latest.get(key) == result["native_run"].get(key)
            for key in (
                "id",
                "run_attempt",
                "head_sha",
                "event",
                "path",
                "status",
                "conclusion",
            )
        ),
        "original OCI run changed during native download",
    )
    transfer = load_transfer_profile(control, component)
    pull = api(f"repos/{REPOSITORY}/pulls/{transfer['pull_number']}")
    verify_pr_tree(
        pull,
        result["native_merge_commit"],
        load_profile(control, component),
        number=transfer["pull_number"],
        base_ref=transfer["base_ref"],
    )
    return result


def download_fresh_wheel(
    profile: dict[str, Any],
    *,
    control_revision: str,
    run_id: int,
    attempt: int,
    job_id: int,
    actor: str,
    artifact_id: int,
    zip_size: int,
    zip_sha256: str,
    destination: Path,
) -> dict[str, Any]:
    require(
        all(type(value) is int and value > 0 for value in (run_id, attempt, job_id, artifact_id)),
        "invalid fresh control wheel coordinates",
    )
    run = api(f"repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}")
    job = api(f"repos/{REPOSITORY}/actions/jobs/{job_id}")
    metadata = api(f"repos/{REPOSITORY}/actions/artifacts/{artifact_id}")
    verify_build_artifact(
        metadata,
        run,
        job,
        profile=profile,
        artifact_id=artifact_id,
        zip_size=zip_size,
        zip_sha256=zip_sha256,
        control_revision=control_revision,
        run_id=run_id,
        attempt=attempt,
        actor=actor,
    )
    latest = api(f"repos/{REPOSITORY}/actions/runs/{run_id}")
    require(
        all(
            latest.get(key) == run.get(key)
            for key in ("id", "run_attempt", "head_sha", "event", "path")
        ),
        "fresh wheel belongs to an obsolete control run attempt",
    )
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    download_artifact_bytes(
        artifact_id,
        destination / "fresh-wheel.zip",
        expected_size=zip_size,
        expected_sha256=zip_sha256,
    )
    final_run = api(f"repos/{REPOSITORY}/actions/runs/{run_id}")
    final_metadata = api(f"repos/{REPOSITORY}/actions/artifacts/{artifact_id}")
    require(
        all(
            final_run.get(key) == run.get(key)
            for key in ("id", "run_attempt", "head_sha", "event", "path")
        )
        and final_run.get("status") in {"in_progress", "completed"}
        and final_run.get("conclusion") in {None, "success"},
        "fresh control wheel run changed or failed during native download",
    )
    verify_build_artifact(
        final_metadata,
        final_run,
        job,
        profile=profile,
        artifact_id=artifact_id,
        zip_size=zip_size,
        zip_sha256=zip_sha256,
        control_revision=control_revision,
        run_id=run_id,
        attempt=attempt,
        actor=actor,
    )
    return {"native_run": run, "native_build_job": job, "native_artifact": metadata}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=(
            "select",
            "verify-source",
            "build-constraints",
            "stage-wheel",
            "collect-original",
        ),
    )
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--component", choices=tuple(BASELINES), required=True)
    parser.add_argument("--control-revision", required=True)
    parser.add_argument("--product", type=Path)
    parser.add_argument("--dist", type=Path)
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    selected = select_product(args.control, args.component, args.control_revision)
    profile = load_profile(args.control, args.component)
    if args.command == "verify-source":
        require(args.product is not None, "product checkout required")
        verify_source_delta(args.product, profile)
    elif args.command == "build-constraints":
        require(
            args.product is not None and args.destination is not None,
            "build constraint source and output required",
        )
        selected["build_constraints_sha256"] = write_build_constraints(
            args.product, profile, args.destination
        )
    elif args.command == "stage-wheel":
        require(
            args.product is not None and args.dist is not None and args.destination is not None,
            "fresh wheel staging paths are required",
        )
        facts = stage_wheel(
            args.product, args.dist, args.destination, profile, args.control_revision
        )
        selected["wheel_sha256"] = facts["wheel_sha256"]
    elif args.command == "collect-original":
        require(args.destination is not None, "original artifact destination required")
        original = load_original_inputs(args.control, profile)
        observation = download_original_oci(
            args.control, args.component, **original, destination=args.destination
        )
        selected["original_oci_sha256"] = observation["native_artifact"]["digest"].removeprefix(
            "sha256:"
        )
    if args.github_output is not None:
        require(
            all(
                re.fullmatch(r"[a-z][a-z0-9_]*", key) and "\n" not in value and "\r" not in value
                for key, value in selected.items()
            ),
            "unsafe native workflow output",
        )
        with args.github_output.open("a") as output:
            output.write("".join(f"{key}={value}\n" for key, value in selected.items()))
    print(json.dumps(selected, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
