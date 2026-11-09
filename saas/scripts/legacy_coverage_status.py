"""Post native coverage results against exact, reviewed frozen-version references."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
import tomllib
import zipfile
from decimal import Decimal
from pathlib import Path

from saas.scripts.legacy_artifact_download import download_artifact_bytes
from saas.scripts.legacy_check_history import latest_statuses
from saas.scripts.legacy_domain_native import _latest_matches_attempt
from saas.scripts.legacy_native_evidence import api
from saas.scripts.legacy_pytest_results import verify_pytest_artifact_identity
from saas.scripts.legacy_source_ci import _job_pages, _load_contract, verify_job_set
from saas.scripts.oci_promotion import require
from saas.scripts.protected_legacy_initial_build import REPOSITORY, load_profile

# This one upgrade's reviewed source-CI predecessors, never a moving branch,
# arbitrary input baseline, or a replacement baseline for 0.21/main.
REFERENCES = {
    "Core": (
        "cee6a057062844689cfa7e54c3d79bf5cb779729",
        "62b5598cdba624987921cd7c865152564b3e59f4",
        {"Coverage": 40673558223, "Coverage (ui)": 40673558209},
    ),
    "Gateway": (
        "8756f81d699a9b1cd64bc93702b0c06cc38c3fdc",
        "b6363d1b99fa9f190589471a21c89f89057e6b88",
        {"Coverage": 40673580252, "Coverage (ui)": 40673580069},
    ),
    "Model": (
        "f16e62a63cdb1802076b7712af630342daa56586",
        "538eacfab39402307d0b477ba5efc0eddc8007b1",
        {"Coverage": 40673594571, "Coverage (ui)": 40673594588},
    ),
    "Compatibility018": (
        "4e11681dd3809febeb42cb5d752d423b5f751f82",
        "ba024657ad464ddf022c8ad8bb41610aef949b46",
        {"Coverage": 41401723690},
    ),
}
TOLERANCE = Decimal("0.5")
_WORKFLOW = ".github/workflows/code-coverage.yml"
_CURRENT_C2 = (
    "27503d14973b751a2031c6febf12a581b42b06d1",
    "a02ea9f17664bd0290eb5025f864672c0025075c",
)
_CURRENT_C2_PRODUCERS = (
    "8751d7628bc5438ad915ade51649a069b438a2c3dd9b5ae9b95d7fd812a134b5",
    "ea4fde43ab964d47e77d6c9279e36bd9ce74b82ba684835d1b0b2d5c61af1b42",
)
_CURRENT_C2_V8_SETUP = (
    b"      - name: Verify exact parity V8 download\n"
    b"        if: steps.sidecar-cache.outputs.cache-hit != 'true'\n"
    b"        uses: ./saas/actions/setup-pinned-parity-v8\n"
    b"        timeout-minutes: 3\n"
)


def _same_coverage_producer(source, reference, path, current, original):
    if current == original:
        return True
    return (
        source == _CURRENT_C2[0]
        and reference == REFERENCES["Compatibility018"][1]
        and path == ".github/workflows/ci.yml"
        and tuple(hashlib.sha256(body).hexdigest() for body in (current, original))
        == _CURRENT_C2_PRODUCERS
        and current.count(_CURRENT_C2_V8_SETUP) == 1
        and current.replace(_CURRENT_C2_V8_SETUP, b"", 1) == original
    )


def require_native_main_writer(root: Path) -> None:
    """Only the protected existing coverage workflow can write a status."""
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    require(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
        and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and os.environ.get("GITHUB_REF") == "refs/heads/main"
        and os.environ.get("GITHUB_WORKFLOW_REF") == f"{REPOSITORY}/{_WORKFLOW}@refs/heads/main"
        and os.environ.get("GITHUB_SHA") == revision,
        "coverage status writer requires the exact native protected-main checkout",
    )


def _coverage(source, specification, run_id, attempt, destination, *, current):
    run = api(f"repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}")
    require(
        _latest_matches_attempt(api(f"repos/{REPOSITORY}/actions/runs/{run_id}"), run),
        "coverage producer is not the latest original attempt",
    )
    jobs = _job_pages(run_id, attempt)
    if current:
        verify_job_set(run, jobs, specification, source)
    require(
        run.get("head_sha") == source
        and run.get("id") == run_id
        and run.get("run_attempt") == attempt
        and run.get("event") == "pull_request"
        and run.get("repository", {}).get("full_name") == REPOSITORY
        and run.get("path") == specification["path"]
        and run.get("status") == "completed"
        and run.get("conclusion") == "success",
        "coverage producer is not a successful exact-source original PR workflow",
    )
    ui = specification["path"] == ".github/workflows/web-tests.yml"
    upload_name = "Upload UI coverage summary" if ui else "Upload coverage summary"
    matching = [job for job in jobs if any(s["name"] == upload_name for s in job.get("steps", []))]
    require(len(matching) == 1, "coverage upload job is missing or ambiguous")
    job = matching[0]
    steps = [step for step in job["steps"] if step["name"] == upload_name]
    require(len(steps) == 1, "coverage upload step is ambiguous")
    upload = {key: steps[0][key] for key in ("number", "name")}
    name = ("ui-coverage-summary-" if ui else "coverage-summary-") + str(run_id)
    endpoint = f"repos/{REPOSITORY}/actions/runs/{run_id}/artifacts?per_page=100"
    inventory = api(endpoint)
    require(
        inventory.get("total_count") == len(inventory.get("artifacts", [])) <= 100,
        "coverage artifact inventory is incomplete",
    )
    matches = [row for row in inventory["artifacts"] if row["name"] == name]
    require(len(matches) == 1, "coverage original artifact is missing or ambiguous")
    artifact = matches[0]
    require(
        0 < artifact["size_in_bytes"] <= 1024 * 1024, "coverage summary exceeds its input bound"
    )
    archive = destination / f"coverage-{artifact['id']}.zip"
    download_artifact_bytes(
        artifact["id"],
        archive,
        expected_size=artifact["size_in_bytes"],
        expected_sha256=artifact["digest"].removeprefix("sha256:"),
    )
    verify_pytest_artifact_identity(
        artifact,
        run,
        job,
        revision=source,
        artifact_name=name,
        upload_step=upload,
        archive=archive,
    )
    with zipfile.ZipFile(archive) as bundle:
        require(
            bundle.namelist().count("total.txt") == 1, "coverage total is missing or duplicated"
        )
        item = bundle.getinfo("total.txt")
        require(0 < item.file_size < 64, "coverage total exceeds its text bound")
        body = bundle.read(item)
    text = body.decode().strip()
    require(
        re.fullmatch(r"(?:100(?:\.0+)?|[0-9]{1,2}(?:\.[0-9]+)?)", text) is not None,
        "coverage total is not a bounded percentage",
    )
    require(
        api(f"repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}") == run
        and _latest_matches_attempt(api(f"repos/{REPOSITORY}/actions/runs/{run_id}"), run)
        and _job_pages(run_id, attempt) == jobs
        and api(endpoint) == inventory,
        "native coverage producer or original artifact changed",
    )
    return Decimal(text), {
        "source": source,
        "run_id": run_id,
        "attempt": attempt,
        "job_id": job["id"],
        "artifact_id": artifact["id"],
        "artifact_sha256": artifact["digest"],
        "total_sha256": hashlib.sha256(body).hexdigest(),
    }


def compare_originals(root: Path, component: str, destination: Path):
    require(component in REFERENCES, "unreviewed legacy coverage component")
    source, reference, contexts = REFERENCES[component]
    profile = load_profile(root, component)
    identity = _load_contract(root, profile)
    if component == "Compatibility018" and profile["product_revision"] == _CURRENT_C2[0]:
        require(
            profile.get("product_tree") == _CURRENT_C2[1], "legacy coverage source tree changed"
        )
        source = _CURRENT_C2[0]
    require(profile["product_revision"] == source, "legacy coverage source changed")
    projects = [
        tomllib.loads(
            subprocess.check_output(["git", "show", rev + ":pyproject.toml"], cwd=root, text=True)
        )
        for rev in (source, reference)
    ]
    require(
        all(p["project"]["version"] == "0.18.0.dev20261006" for p in projects)
        and projects[0]["tool"]["coverage"] == projects[1]["tool"]["coverage"]
        and projects[0]["tool"]["pytest"] == projects[1]["tool"]["pytest"],
        "legacy coverage version, configuration or pytest selection changed",
    )
    if "Coverage (ui)" in contexts:
        for path in ("web/vite.config.ts", "web/package.json", "pnpm-lock.yaml"):
            originals = [
                subprocess.check_output(["git", "show", rev + ":" + path], cwd=root)
                for rev in (source, reference)
            ]
            require(
                originals[0] == originals[1], "legacy UI coverage configuration or lock changed"
            )
    results = []
    for context, reference_run in contexts.items():
        path = (
            ".github/workflows/ci.yml"
            if context == "Coverage"
            else ".github/workflows/web-tests.yml"
        )
        specification = next(row for row in identity["workflows"] if row["path"] == path)
        # The coverage producer and its test selection must be identical.
        workflow_bytes = [
            subprocess.check_output(["git", "show", rev + ":" + path], cwd=root)
            for rev in (source, reference)
        ]
        require(
            _same_coverage_producer(source, reference, path, *workflow_bytes),
            "legacy coverage producer or selection changed",
        )
        before, original = _coverage(
            reference, specification, reference_run, 1, destination, current=False
        )
        after, current = _coverage(
            source,
            specification,
            specification["run_id"],
            specification["attempt"],
            destination,
            current=True,
        )
        results.append(
            {
                "context": context,
                "reference_percent": str(before),
                "current_percent": str(after),
                "tolerance_percent": str(TOLERANCE),
                "passed": after + TOLERANCE >= before,
                "reference": original,
                "current": current,
            }
        )
    return source, results


def status_payload(component, row):
    """Report the actual same-version comparison; a real drop remains failure."""
    return {
        "state": "success" if row["passed"] else "failure",
        "context": row["context"],
        "target_url": f"https://github.com/{REPOSITORY}/actions/runs/{row['current']['run_id']}",
        "description": (
            f"{'UI coverage' if row['context'] == 'Coverage (ui)' else 'Coverage'} "
            f"{row['current_percent']}% (frozen {component} "
            f"baseline {row['reference_percent']}%; tol 0.5%)"
        ),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--component", choices=REFERENCES, required=True)
    parser.add_argument("--post", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    if args.post:
        require_native_main_writer(root)
    with tempfile.TemporaryDirectory(prefix="legacy-coverage-") as temporary:
        source, results = compare_originals(root, args.component, Path(temporary))
    # Finish every original comparison before any write. Never post to main.
    if args.post:
        statuses = api(f"repos/{REPOSITORY}/commits/{source}/statuses?per_page=100")
        latest = {row["context"]: row for row in latest_statuses({"statuses": statuses})}
        for row in results:
            existing = latest.get(row["context"], {})
            require(
                existing.get("creator", {}).get("id") == 41898282
                and existing.get("target_url")
                == status_payload(args.component, row)["target_url"],
                "legacy coverage status has another provider or producing run",
            )
        for row in results:
            payload = status_payload(args.component, row)
            subprocess.run(
                [
                    "gh",
                    "api",
                    "-X",
                    "POST",
                    f"repos/{REPOSITORY}/statuses/{source}",
                    "--input",
                    "-",
                ],
                input=json.dumps(payload),
                text=True,
                stdout=subprocess.DEVNULL,
                check=True,
            )
    print(
        json.dumps(
            {
                "component": args.component,
                "source": source,
                "comparisons": results,
                "statuses_written": args.post,
                "Main_baseline_changed": False,
            }
        )
    )
    return 0 if all(row["passed"] for row in results) else 2


if __name__ == "__main__":
    raise SystemExit(main())
