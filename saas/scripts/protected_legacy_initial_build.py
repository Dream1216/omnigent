"""Bind a reviewed legacy product to a separate protected signing workflow."""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import re
import subprocess
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import Any

from saas.scripts.oci_promotion import require
from saas.scripts.resume_oci_promotion import (
    BUILD_TYPE,
    PREDICATE_TYPE,
    verify_predicate,
)

REPOSITORY = "Dream1216/omnigent"
WORKFLOW = ".github/workflows/saas-legacy-security-build.yml"
BASELINES = {
    "Core": "dc1e9a9735d4c996b74e601ed7f4ecb49e83f9ec",
    "Gateway": "3319b59a5d75a411f339b294cbe6b4133bfb851a",
    "Model": "7cea09404d49fc965ce053e51803688a5be5fe53",
}
_SHA = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_MATERIAL_PATHS = {
    "deploy/docker/Dockerfile",
    "pyproject.toml",
    "uv.lock",
    "uv.toml",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    "package.json",
    "saas/supply_chain/wolfi-runtime-lock.json",
    "saas/supply_chain/npm-122-security-lock.json",
    "saas/scripts/check_image_supply_chain.py",
    "web/electron/package.json",
}
_BUDGET_PATH = "saas/upstream-baseline.json"
_REVIEWED_METADATA_PAIRS = {
    "examples/extensions/hello-page/web/package.json": (
        "218492253404367267272bbeb5fce096159810968eaf0f4530dc6e281dba4a4d",
        "b79ebecfa481ec57998b62bfea810d687d7842b0ce53244a7b93cf3397c2d7b5",
    ),
    "saas/login_web/package.json": (
        "5ef3e3eada263c74d2baf0909b96dc86c57d1cc9925118e41f2829934084fef3",
        "9f56b3f8f75e38f417bc057324db6df5b64f15da7ab0f164c557ea24ee349daa",
    ),
    "saas/login_web/package-lock.json": (
        "e4bb8521c9417275d318b1b83d372605f1aea5f7e2d9d1b578a6d3e3b0d3004d",
        "6abffaeef7fab5b1395af1fef49adb25477d3f9546a3a636e20ba42732650f28",
    ),
}
_REVIEWED_TEST_PAIRS = {
    "web/src/shell/archiveUndoToast.test.tsx": (
        "16b284c4c03ae0e5a3face82f108d12262aedc8e3c4308e6a337daf5cfda9f71",
        "efbb6d3978d0d3856f44d489d9e5f7a88bbe969018721b713589f058665caca8",
    ),
}
_REVIEWED_BLOB_PAIRS = {**_REVIEWED_METADATA_PAIRS, **_REVIEWED_TEST_PAIRS}
_MODEL_REVIEWED_BLOB_PAIRS = {
    "dev/benchmarks/omnigent/environment.py": (
        "10be2cc22023e83d50fb460d759a9439691bb0dc6261892e27cc6ccd2d356f68",
        "41668cbecb3623933e2ba87441326f431636d77fcfdf340c3e655720bc19438b",
    ),
    "tests/benchmarks/test_benchmark_smoke.py": (
        "075ef6f5f291732fd6c27a54aeb2c5fc31079f331a498cbb3dcaeab9f0c108d3",
        "df62611701eb78c9b143213f1e2d826418c3bc3a48b6bda8d429a5169b481c65",
    ),
}


def validate_profile(profile: dict[str, Any], component: str) -> None:
    """Validate a profile read exclusively from the trusted control checkout."""
    require(component in BASELINES, "unknown legacy component")
    require(
        set(profile) - {"budget_file_cap"}
        == {
            "schema_version",
            "repository",
            "component",
            "baseline_revision",
            "product_revision",
            "product_tree",
            "source_date_epoch",
            "source_delta",
            "application_version",
        },
        "legacy profile fields differ",
    )
    require(
        type(profile["schema_version"]) is int
        and profile["schema_version"] == 1
        and profile["repository"] == REPOSITORY
        and profile["component"] == component
        and profile["baseline_revision"] == BASELINES[component],
        "legacy profile is not the reviewed original product",
    )
    for key in ("product_revision", "product_tree"):
        require(
            isinstance(profile[key], str) and _SHA.fullmatch(profile[key]) is not None,
            "legacy product must use complete immutable Git coordinates",
        )
    require(
        profile["product_revision"] != profile["baseline_revision"],
        "new hotfix cannot reuse the original product SHA",
    )
    require(
        profile["application_version"] == "0.18.0.dev20261006",
        "legacy application version changed",
    )
    require(
        type(profile["source_date_epoch"]) is int and profile["source_date_epoch"] >= 0,
        "invalid legacy source epoch",
    )
    delta = profile["source_delta"]
    require(isinstance(delta, list) and bool(delta), "empty legacy security delta")
    has_budget = any(isinstance(row, dict) and row.get("path") == _BUDGET_PATH for row in delta)
    require(
        has_budget == ("budget_file_cap" in profile),
        "budget change lacks exact control approval",
    )
    if has_budget:
        require(
            type(profile["budget_file_cap"]) is int
            and profile["budget_file_cap"] == (169 if component == "Model" else 167),
            "legacy budget differs from reviewed file cap",
        )
    reviewed_blob_pairs = {
        **_REVIEWED_BLOB_PAIRS,
        **(_MODEL_REVIEWED_BLOB_PAIRS if component == "Model" else {}),
    }
    paths: set[str] = set()
    for row in delta:
        require(
            isinstance(row, dict) and set(row) == {"path", "before", "after"},
            "legacy source delta fields differ",
        )
        path = row["path"]
        require(
            isinstance(path, str)
            and bool(path)
            and not PurePosixPath(path).is_absolute()
            and ".." not in PurePosixPath(path).parts
            and path not in paths,
            "unsafe or duplicate legacy source path",
        )
        require(
            path in _MATERIAL_PATHS
            or path in reviewed_blob_pairs
            or path == _BUDGET_PATH
            or path.startswith((".github/", "tests/")),
            "legacy patch changes application or schema code",
        )
        require(
            path not in _MODEL_REVIEWED_BLOB_PAIRS or (component == "Model" and has_budget),
            "reader-close source paths require the reviewed Model budget",
        )
        paths.add(path)
        for side in ("before", "after"):
            value = row[side]
            require(
                isinstance(value, dict)
                and set(value) == {"mode", "sha256"}
                and isinstance(value["mode"], str)
                and value["mode"] in {"100644", "100755"}
                and isinstance(value["sha256"], str)
                and _SHA256.fullmatch(value["sha256"]) is not None,
                "invalid legacy source blob binding",
            )
            if path in {_BUDGET_PATH, "web/electron/package.json"} or path in (
                reviewed_blob_pairs
            ):
                require(value["mode"] == "100644", "source metadata mode changed")
        if path in reviewed_blob_pairs:
            require(
                tuple(row[side]["sha256"] for side in ("before", "after"))
                == reviewed_blob_pairs[path],
                "source metadata differs from the exact reviewed byte transition",
            )

    if has_budget and component == "Model":
        require(
            set(_MODEL_REVIEWED_BLOB_PAIRS) <= paths,
            "reviewed Model reader-close source paths are incomplete",
        )


def load_profile(control: Path, component: str) -> dict[str, Any]:
    """Missing, empty or unknown profiles deny; artifacts cannot supply profiles."""
    path = control / "saas/supply_chain/legacy-security-build-profiles.json"
    require(path.is_file() and not path.is_symlink(), "missing reviewed legacy profiles")
    data = json.loads(path.read_text())
    require(
        set(data) == {"schema_version", "profiles"}
        and data["schema_version"] == 1
        and isinstance(data["profiles"], dict),
        "legacy profile store differs",
    )
    require(component in data["profiles"], "legacy product has no approved profile")
    profile = data["profiles"][component]
    require(isinstance(profile, dict), "legacy profile must be an object")
    validate_profile(profile, component)
    return profile


def verify_source_delta(repository: Path, profile: dict[str, Any]) -> None:
    """Read Git objects without running the product or accepting working-tree files."""
    validate_profile(profile, profile["component"])

    def git(*args: str) -> bytes:
        return subprocess.check_output(["git", *args], cwd=repository)

    base, product = profile["baseline_revision"], profile["product_revision"]
    require(
        git("rev-parse", "HEAD").decode().strip() == product,
        "product checkout differs from reviewed source",
    )
    require(
        not git("status", "--porcelain=v1", "--untracked-files=all", "-z"),
        "product checkout contains unsealed working-tree inputs",
    )
    require(
        git("rev-parse", product + "^{tree}").decode().strip() == profile["product_tree"],
        "product tree differs",
    )
    require(
        int(git("show", "-s", "--format=%ct", product)) == profile["source_date_epoch"],
        "product source epoch differs from its immutable commit",
    )
    require(
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", base, product],
            cwd=repository,
            capture_output=True,
        ).returncode
        == 0,
        "legacy source is not descended from its own original product",
    )
    actual = set(
        filter(
            None,
            git("diff", "--name-only", "--no-renames", "-z", base, product, "--")
            .decode()
            .split("\0"),
        )
    )
    require(
        actual == {row["path"] for row in profile["source_delta"]},
        "legacy security delta omits or adds paths",
    )
    for row in profile["source_delta"]:
        for side, revision in (("before", base), ("after", product)):
            tree = git("ls-tree", revision, "--", row["path"]).decode().split()
            require(
                len(tree) >= 3 and tree[0] == row[side]["mode"] and tree[1] == "blob",
                "legacy source mode or file type differs",
            )
            body = git("cat-file", "blob", revision + ":" + row["path"])
            require(
                hashlib.sha256(body).hexdigest() == row[side]["sha256"],
                "legacy source blob differs",
            )
        if row["path"] in {_BUDGET_PATH, "web/electron/package.json"} or row["path"] in (
            _REVIEWED_METADATA_PAIRS
        ):
            verify_metadata_delta(
                row["path"],
                git("cat-file", "blob", base + ":" + row["path"]),
                git("cat-file", "blob", product + ":" + row["path"]),
                profile,
            )


def verify_metadata_delta(path: str, before: bytes, after: bytes, profile: dict[str, Any]) -> None:
    """Bind exact reviewed metadata bytes and the original narrow field transitions."""

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, "duplicate source metadata field")
            result[key] = value
        return result

    original, changed = (
        json.loads(body, object_pairs_hook=unique_object) for body in (before, after)
    )
    require(
        isinstance(original, dict) and isinstance(changed, dict),
        "source metadata is not an object",
    )
    if path in _REVIEWED_METADATA_PAIRS:
        require(
            (hashlib.sha256(before).hexdigest(), hashlib.sha256(after).hexdigest())
            == _REVIEWED_METADATA_PAIRS[path],
            "source metadata differs from the exact reviewed byte transition",
        )
        return
    expected = copy.deepcopy(original)
    if path == _BUDGET_PATH:
        require(
            (
                profile.get("budget_file_cap") == 167
                if profile.get("component") != "Model"
                else type(profile.get("budget_file_cap")) is int
                and profile["budget_file_cap"] == 169
            )
            and original.get("source_intrusion_budget", {}).get("max_direct_upstream_files")
            == 150,
            "legacy budget original or approved cap differs",
        )
        expected["source_intrusion_budget"]["max_direct_upstream_files"] = profile[
            "budget_file_cap"
        ]
    else:
        require(
            path == "web/electron/package.json"
            and original.get("devDependencies", {}).get("electron") == "^42.10.0",
            "unreviewed Electron manifest transition",
        )
        expected["devDependencies"]["electron"] = "^42.11.16"
    require(
        changed == expected,
        "source metadata changes fields outside the exact reviewed transition",
    )


def verify_pr_tree(
    pull: dict[str, Any],
    commit: dict[str, Any],
    profile: dict[str, Any],
    *,
    number: int,
    base_ref: str,
) -> str:
    """Bind native PR records to a frozen base and an equivalent merge tree.

    Source equivalence alone does not prove original workflow bytes, actual
    checkout step logs, complete matrices or exact-product dynamic identity
    tests. Those remain separate mandatory checks.
    """
    validate_profile(profile, profile["component"])
    require(
        type(number) is int
        and number > 0
        and isinstance(base_ref, str)
        and bool(base_ref)
        and base_ref != "main",
        "missing reviewed isolated validation PR coordinate",
    )
    require(
        pull.get("number") == number
        and pull.get("state") == "open"
        and pull.get("draft") is False
        and pull.get("head", {}).get("sha") == profile["product_revision"]
        and pull.get("head", {}).get("repo", {}).get("full_name") == REPOSITORY
        and pull.get("base", {}).get("sha") == profile["baseline_revision"]
        and pull.get("base", {}).get("ref") == base_ref
        and pull.get("base", {}).get("repo", {}).get("full_name") == REPOSITORY,
        "validation PR base, head or repository differs",
    )
    merge = pull.get("merge_commit_sha")
    require(
        isinstance(merge, str)
        and _SHA.fullmatch(merge) is not None
        and merge != profile["product_revision"]
        and commit.get("sha") == merge
        and commit.get("tree", {}).get("sha") == profile["product_tree"],
        "actual PR merge commit does not have the exact product tree",
    )
    parents = commit.get("parents")
    require(
        isinstance(parents, list)
        and len(parents) == 2
        and all(isinstance(row, dict) for row in parents)
        and [row.get("sha") for row in parents]
        == [profile["baseline_revision"], profile["product_revision"]],
        "actual PR merge parents differ from the frozen base and product",
    )
    return merge


def verify_native_pr_tree(profile: dict[str, Any], *, number: int, base_ref: str) -> str:
    """Read source coordinates directly through authenticated GitHub APIs."""
    require(type(number) is int and number > 0, "invalid validation PR number")
    validate_profile(profile, profile["component"])

    def api(endpoint: str) -> dict[str, Any]:
        value = json.loads(subprocess.check_output(["gh", "api", endpoint], text=True))
        require(isinstance(value, dict), "native source API did not return an object")
        return value

    pull = api(f"repos/{REPOSITORY}/pulls/{number}")
    merge = pull.get("merge_commit_sha")
    require(
        isinstance(merge, str) and _SHA.fullmatch(merge) is not None,
        "validation PR has no immutable test merge commit",
    )
    commit = api(f"repos/{REPOSITORY}/git/commits/{merge}")
    verified = verify_pr_tree(pull, commit, profile, number=number, base_ref=base_ref)
    refreshed = api(f"repos/{REPOSITORY}/pulls/{number}")
    require(
        verify_pr_tree(refreshed, commit, profile, number=number, base_ref=base_ref) == verified,
        "validation PR moved during source observation",
    )
    return verified


def verify_build_artifact(
    metadata: dict[str, Any],
    run: dict[str, Any],
    job: dict[str, Any],
    *,
    profile: dict[str, Any],
    artifact_id: int,
    zip_size: int,
    zip_sha256: str,
    control_revision: str,
    run_id: int,
    attempt: int,
    actor: str,
) -> None:
    """Bind authenticated GitHub API records to the control run, never product SHA."""
    validate_profile(profile, profile["component"])
    require(
        _SHA.fullmatch(control_revision) is not None and type(attempt) is int and attempt > 0,
        "invalid control run coordinate",
    )
    require(
        run.get("id") == run_id
        and run.get("run_attempt") == attempt
        and run.get("head_sha") == control_revision
        and run.get("head_branch") == "main"
        and run.get("event") == "workflow_dispatch"
        and run.get("path") == WORKFLOW
        and run.get("repository", {}).get("full_name") == REPOSITORY,
        "legacy build run differs from protected control",
    )
    require(
        isinstance(actor, str)
        and bool(actor)
        and run.get("actor", {}).get("login") == actor
        and run.get("triggering_actor", {}).get("login") == actor,
        "legacy build actor differs from the native workflow actor",
    )
    require(
        job.get("run_id") == run_id
        and job.get("run_attempt") == attempt
        and job.get("name") == "build-initial"
        and job.get("status") == "completed"
        and job.get("conclusion") == "success"
        and job.get("runner_group_name") == "GitHub Actions"
        and "ubuntu-latest" in job.get("labels", []),
        "original unprivileged hosted build job is not successful",
    )
    # The existing generic promotion helper cannot represent component and attempt.
    expected_name = (
        f"legacy-initial-{profile['component']}-{profile['product_revision']}-"
        f"{control_revision}-{run_id}-{attempt}"
    )
    require(
        type(zip_size) is int
        and zip_size > 0
        and metadata.get("id") == artifact_id
        and metadata.get("name") == expected_name
        and metadata.get("expired") is False
        and metadata.get("size_in_bytes") == zip_size
        and metadata.get("digest") == "sha256:" + zip_sha256
        and metadata.get("workflow_run", {}).get("id") == run_id
        and metadata.get("workflow_run", {}).get("head_sha") == control_revision,
        "legacy artifact does not bind the exact role, attempt and original bytes",
    )


def verify_wheel(path: Path, profile: dict[str, Any], expected_sha256: str) -> None:
    """Inspect immutable wheel metadata without importing or executing its code."""
    validate_profile(profile, profile["component"])
    require(path.is_file() and not path.is_symlink(), "missing regular new product wheel")
    require(
        hashlib.sha256(path.read_bytes()).hexdigest() == expected_sha256,
        "new product wheel digest differs",
    )
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), "duplicate wheel members")
        require(
            all(
                not PurePosixPath(n).is_absolute() and ".." not in PurePosixPath(n).parts
                for n in names
            ),
            "unsafe wheel member",
        )
        metadata_paths = [n for n in names if n.endswith(".dist-info/METADATA")]
        require(len(metadata_paths) == 1, "wheel distribution identity is ambiguous")
        require(
            archive.getinfo(metadata_paths[0]).file_size <= 1048576
            and archive.getinfo("omnigent/_build_info.py").file_size <= 65536,
            "wheel identity metadata exceeds its bounded parser input",
        )
        metadata = BytesParser().parsebytes(archive.read(metadata_paths[0]))
        require(
            metadata["Name"] == "omnigent"
            and metadata["Version"] == profile["application_version"],
            "new product wheel distribution differs",
        )
        body = ast.parse(archive.read("omnigent/_build_info.py").decode())
        constants = {}
        for node in body.body:
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                name, value = node.target.id, node.value
            elif (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
            ):
                name, value = node.targets[0].id, node.value
            else:
                continue
            if name in {"COMMIT_SHA", "BUILD_TIME_EPOCH"}:
                require(
                    name not in constants and isinstance(value, ast.Constant),
                    "wheel build identity must be a unique literal",
                )
                constants[name] = value.value
        require(
            constants
            == {
                "COMMIT_SHA": profile["product_revision"],
                "BUILD_TIME_EPOCH": profile["source_date_epoch"],
            },
            "old or mismatched wheel source identity",
        )


def provenance(
    profile: dict[str, Any],
    *,
    control_revision: str,
    run_id: int,
    attempt: int,
    artifact_id: int,
    zip_sha256: str,
    seal_sha256: str,
    wheel_sha256: str,
) -> dict[str, Any]:
    """Use supported workflow SLSA with explicit product and control dependencies."""
    validate_profile(profile, profile["component"])
    require(
        _SHA.fullmatch(control_revision) is not None
        and control_revision != profile["product_revision"],
        "control/product identity conflation",
    )
    require(
        all(type(v) is int and v > 0 for v in (run_id, attempt, artifact_id)),
        "invalid original build coordinates",
    )
    require(
        all(_SHA256.fullmatch(v) is not None for v in (zip_sha256, seal_sha256, wheel_sha256)),
        "invalid artifact digest",
    )
    repository = "https://github.com/" + REPOSITORY
    return {
        "buildDefinition": {
            "buildType": BUILD_TYPE,
            "externalParameters": {
                "workflow": {
                    "path": WORKFLOW,
                    "ref": "refs/heads/main",
                    "repository": repository,
                },
                "legacy_security_profile": profile,
                "candidate_seal_sha256": seal_sha256,
                "wheel_sha256": wheel_sha256,
                "rebuild_in_publisher": False,
            },
            "resolvedDependencies": [
                {
                    "uri": f"git+{repository}@refs/heads/main",
                    "digest": {"gitCommit": control_revision},
                },
                {
                    "uri": f"git+{repository}@{profile['product_revision']}",
                    "digest": {
                        "gitCommit": profile["product_revision"],
                        "gitTree": profile["product_tree"],
                    },
                },
                {
                    "uri": f"{repository}/actions/artifacts/{artifact_id}",
                    "digest": {"sha256": zip_sha256},
                },
            ],
        },
        "runDetails": {
            "builder": {"id": f"{repository}/{WORKFLOW}@refs/heads/main"},
            "metadata": {"invocationId": f"{repository}/actions/runs/{run_id}/attempts/{attempt}"},
        },
    }


def verify_native_attestation(
    subject: str,
    *,
    digest: str,
    profile: dict[str, Any],
    control_revision: str,
    run_id: int,
    attempt: int,
    artifact_id: int,
    zip_sha256: str,
    seal_sha256: str,
    wheel_sha256: str,
) -> None:
    """Obtain native cryptographic verification directly; reject artifact-owned JSON."""
    require(
        isinstance(subject, str) and bool(subject) and not subject.startswith("-"),
        "native attestation subject must not be a CLI option",
    )
    predicate = provenance(
        profile,
        control_revision=control_revision,
        run_id=run_id,
        attempt=attempt,
        artifact_id=artifact_id,
        zip_sha256=zip_sha256,
        seal_sha256=seal_sha256,
        wheel_sha256=wheel_sha256,
    )
    verify_native_statement(
        subject,
        digest=digest,
        predicate=predicate,
        control_revision=control_revision,
        run_id=run_id,
        attempt=attempt,
    )


def verify_native_statement(
    subject: str,
    *,
    digest: str,
    predicate: dict[str, Any],
    control_revision: str,
    run_id: int,
    attempt: int,
) -> None:
    """Compare a caller-constructed typed predicate with native verified claims."""
    require(
        isinstance(subject, str) and bool(subject) and not subject.startswith("-"),
        "native attestation subject must not be a CLI option",
    )
    require(
        isinstance(control_revision, str)
        and _SHA.fullmatch(control_revision) is not None
        and type(run_id) is int
        and run_id > 0
        and type(attempt) is int
        and attempt > 0,
        "invalid protected native statement coordinate",
    )
    require(
        re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is not None,
        "invalid subject digest",
    )
    command = [
        "gh",
        "attestation",
        "verify",
        subject,
        "--repo",
        REPOSITORY,
        "--signer-workflow",
        REPOSITORY + "/" + WORKFLOW,
        "--source-ref",
        "refs/heads/main",
        "--source-digest",
        control_revision,
        "--deny-self-hosted-runners",
        "--predicate-type",
        PREDICATE_TYPE,
        "--format",
        "json",
    ]
    entries = json.loads(subprocess.check_output(command, text=True))
    require(isinstance(entries, list), "native attestation output must be a list")
    repository = "https://github.com/" + REPOSITORY
    claims = {
        "issuer": "https://token.actions.githubusercontent.com",
        "sourceRepositoryURI": repository,
        "sourceRepositoryRef": "refs/heads/main",
        "sourceRepositoryDigest": control_revision,
        "buildSignerDigest": control_revision,
        "buildConfigDigest": control_revision,
        "runnerEnvironment": "github-hosted",
        "subjectAlternativeName": f"{repository}/{WORKFLOW}@refs/heads/main",
        "runInvocationURI": f"{repository}/actions/runs/{run_id}/attempts/{attempt}",
    }
    matched = []
    for entry in entries:
        try:
            result = entry["verificationResult"]
            if result["statement"].get("predicate") == predicate:
                verify_predicate(
                    [entry],
                    subject=digest,
                    predicate=predicate,
                    predicate_type=PREDICATE_TYPE,
                    claims=claims,
                )
                matched.append(entry)
        except (KeyError, TypeError, ValueError):
            continue
    require(
        len(matched) == 1,
        "exactly one native-verified control/product statement required",
    )
