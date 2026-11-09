"""Select release work and resume native candidates without rebuilding OCI."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any

CONFIG = Path(".github/release-pipeline.json")
SHA = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
GATES = {
    "check_control_plane_migration_cli",
    "check_patch_queue",
    "check_upstream_delta",
    "check_production_baseline",
    "check_image_supply_chain",
    "check_recovery_readiness",
    "run_production_admission",
}


def require(value: Any, message: str) -> None:
    if not value:
        raise ValueError(message)


def config(repo: Path) -> dict[str, Any]:
    value = json.loads((repo / CONFIG).read_text())
    require(value.get("schema_version") == 1, "unsupported release pipeline schema")
    require(value.get("repository") == "Dream1216/omnigent", "unexpected release repository")
    require(
        value.get("release_policy") == "saas/supply_chain/release-policy.json",
        "unexpected release policy",
    )
    for key in ("image_inputs", "non_image_inputs"):
        require(
            isinstance(value.get(key), list) and bool(value[key]), "missing input classification"
        )
        require(
            all(
                isinstance(p, str) and p and not p.startswith("/") and ".." not in p.split("/")
                for p in value[key]
            ),
            "unsafe input classification",
        )
    require(
        set(value["automatic_build_events"]) <= {"pull_request", "push"}, "invalid build event"
    )
    require(
        all(
            isinstance(commands, list) and commands and set(commands) <= GATES
            for commands in value["gates"].values()
        ),
        "unregistered release gate",
    )
    return value


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def matches(path: str, prefixes: list[str]) -> bool:
    return any(path.startswith(p) if p.endswith("/") else path == p for p in prefixes)


def input_digest(repo: Path, revision: str, settings: dict[str, Any]) -> str:
    require(SHA.fullmatch(revision), "a full product revision is required")
    rows = subprocess.check_output(["git", "-C", str(repo), "ls-tree", "-r", "-z", revision])
    selected = []
    for row in rows.split(b"\0"):
        if row:
            _, path = row.split(b"\t", 1)
            if matches(path.decode(), settings["image_inputs"]):
                selected.append(row)
    require(selected, "image input tree is empty")
    return hashlib.sha256(b"\0".join(selected)).hexdigest()


def plan(
    repo: Path, *, revision: str, base: str | None, event: str, reuse_run: int = 0
) -> dict[str, Any]:
    settings = config(repo)
    require(SHA.fullmatch(revision), "a full product revision is required")
    require(reuse_run >= 0, "candidate run must be nonnegative")
    require(
        not reuse_run or event == "workflow_dispatch",
        "candidate reuse requires an explicit release",
    )
    changed: list[str] = []
    runtime_changed = True
    if base:
        require(SHA.fullmatch(base), "a full base revision is required")
        changed = git(repo, "diff", "--name-only", "--no-renames", base, revision).splitlines()
        runtime_changed = input_digest(repo, base, settings) != input_digest(
            repo, revision, settings
        )
        runtime_changed |= any(
            not matches(p, settings["image_inputs"] + settings["non_image_inputs"])
            for p in changed
        )
    build = not reuse_run and (
        event == "workflow_dispatch"
        or (event in settings["automatic_build_events"] and runtime_changed)
    )
    return {
        "schema_version": 1,
        "product_revision": revision,
        "base_revision": base,
        "image_inputs_sha256": input_digest(repo, revision, settings),
        "candidate_required": build,
        "candidate_run_id": reuse_run,
        "runtime_changed": runtime_changed,
        "changed_paths": changed,
        "reason": "reuse-native-candidate"
        if reuse_run
        else "build"
        if build
        else "validation-only",
        "production_authority": False,
        "release_requirements": release_requirements(repo, settings),
    }


def release_requirements(repo: Path, settings: dict[str, Any]) -> dict[str, Any]:
    """Project the authoritative policy into the plan instead of inventing defaults."""
    policy = json.loads((repo / settings["release_policy"]).read_text())
    return {
        "policy_sha256": hashlib.sha256(
            (repo / settings["release_policy"]).read_bytes()
        ).hexdigest(),
        "repeat_builds": policy["reproducibility"]["repeat_builds"],
        "platforms": {image["name"]: image["platforms"] for image in policy["images"]},
        "maximum_scanner_database_age_hours": policy["vulnerability_policy"][
            "maximum_scanner_database_age_hours"
        ],
        "minimum_canary_observation_seconds": policy["promotion"][
            "minimum_canary_observation_seconds"
        ],
        "maximum_n_minus_one_rollback_seconds": policy["promotion"][
            "maximum_n_minus_one_rollback_seconds"
        ],
    }


def api(endpoint: str) -> dict[str, Any]:
    return json.loads(subprocess.check_output(["gh", "api", endpoint], text=True))


def resolve_candidate(repo: Path, *, revision: str, run_id: int) -> dict[str, str]:
    settings = config(repo)
    require(SHA.fullmatch(revision) and run_id > 0, "exact candidate coordinates required")
    root = f"repos/{settings['repository']}/actions"
    run = api(f"{root}/runs/{run_id}")
    require(
        run.get("id") == run_id
        and run.get("head_sha") == revision
        and run.get("head_branch") == "main"
        and run.get("path") == settings["candidate_workflow"]
        and run.get("event") in {"push", "workflow_dispatch"}
        and run.get("status") == "completed"
        and run.get("repository", {}).get("full_name") == settings["repository"],
        "candidate is not the exact completed protected producer",
    )
    attempt = run.get("run_attempt")
    require(type(attempt) is int and attempt > 0, "missing native attempt")
    jobs = api(f"{root}/runs/{run_id}/attempts/{attempt}/jobs?per_page=100")
    rows = jobs.get("jobs", [])
    require(jobs.get("total_count") == len(rows), "incomplete candidate job inventory")
    builders = [j for j in rows if j.get("name") == "build-candidate"]
    require(
        len(builders) == 1
        and builders[0].get("conclusion") == "success"
        and builders[0].get("run_id") == run_id,
        "original candidate build did not succeed",
    )
    artifacts = api(f"{root}/runs/{run_id}/artifacts?per_page=100")
    rows = artifacts.get("artifacts", [])
    require(artifacts.get("total_count") == len(rows), "incomplete artifact inventory")

    def artifact(name: str) -> dict[str, Any]:
        found = [a for a in rows if a.get("name") == f"{name}-{revision}"]
        require(len(found) == 1, "candidate artifact is missing or ambiguous")
        a = found[0]
        require(
            a.get("expired") is False
            and DIGEST.fullmatch(a.get("digest", ""))
            and a.get("workflow_run", {}).get("id") == run_id
            and a.get("workflow_run", {}).get("head_sha") == revision,
            "candidate artifact identity differs",
        )
        return a

    oci = artifact("saas-oci-promotion")
    report = artifact("saas-image-candidate")
    limit = settings["artifact_limits"]["report_bytes"]
    require(0 < report.get("size_in_bytes", 0) <= limit, "candidate report exceeds its bound")
    with subprocess.Popen(
        ["gh", "api", f"{root}/artifacts/{report['id']}/zip"], stdout=subprocess.PIPE
    ) as process:
        assert process.stdout is not None
        body = process.stdout.read(limit + 1)
        if len(body) > limit:
            process.kill()
        require(
            process.wait() == 0 and len(body) == report["size_in_bytes"],
            "candidate report download is incomplete",
        )
    require(
        "sha256:" + hashlib.sha256(body).hexdigest() == report["digest"],
        "candidate report archive digest differs",
    )
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        members = [
            i for i in archive.infolist() if Path(i.filename).name == "oci-promotion-manifest.json"
        ]
        require(
            len(members) == 1 and members[0].file_size <= 1024 * 1024,
            "candidate seal is missing or ambiguous",
        )
        manifest_bytes = archive.read(members[0])
    manifest = json.loads(manifest_bytes)
    require(
        manifest.get("product_revision") == revision
        and manifest.get("evidence_kind") == "immutable_oci_promotion_candidate",
        "candidate seal source differs",
    )
    return {
        "oci-artifact-id": str(oci["id"]),
        "oci-artifact-sha256": oci["digest"].removeprefix("sha256:"),
        "manifest-sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "candidate-run-id": str(run_id),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "resolve", "gate"))
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--revision")
    parser.add_argument("--base")
    parser.add_argument("--event", default=os.environ.get("GITHUB_EVENT_NAME", "local"))
    parser.add_argument("--candidate-run-id", type=int, default=0)
    parser.add_argument("--stage")
    parser.add_argument("--output", type=Path)
    args, forwarded = parser.parse_known_args()
    if args.command == "gate":
        commands = config(args.repo)["gates"]
        require(args.stage in commands, "unknown configured release gate")
        require(
            not forwarded or args.stage in {"production", "recovery"},
            "source gate takes no extra arguments",
        )
        for module in commands[args.stage]:
            subprocess.run(
                [sys.executable, "-m", f"saas.scripts.{module}", *forwarded],
                cwd=args.repo,
                check=True,
            )
        return 0
    require(not forwarded, "unexpected pipeline arguments")
    if args.command == "resolve":
        value = resolve_candidate(args.repo, revision=args.revision, run_id=args.candidate_run_id)
    else:
        value = plan(
            args.repo,
            revision=args.revision,
            base=args.base,
            event=args.event,
            reuse_run=args.candidate_run_id,
        )
    rendered = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered)
    if target := os.environ.get("GITHUB_OUTPUT"):
        with Path(target).open("a") as stream:
            for key, item in value.items():
                if isinstance(item, (str, bool, int)):
                    text = json.dumps(item) if not isinstance(item, str) else item
                    require("\n" not in text and "\r" not in text, "multiline workflow output")
                    stream.write(f"{key.replace('_', '-')}={text}\n")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
