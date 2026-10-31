"""Read exact native control-run PG jobs and their original test artifacts."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import zipfile
from pathlib import Path
from typing import Any

from saas.scripts.legacy_artifact_download import download_artifact_bytes
from saas.scripts.legacy_build_controller import control_context
from saas.scripts.legacy_check_history import _pages
from saas.scripts.legacy_native_evidence import api, preserve_native_evidence
from saas.scripts.legacy_pg_contract import PG_IMAGES, _verify_pg_source, verify_pg_results
from saas.scripts.legacy_pytest_results import (
    pytest_log_inventory,
    read_junit_member,
    verify_job_artifact_identity,
    verify_test_results,
)
from saas.scripts.legacy_source_ci import _job_pages, checkout_commit, download_job_log
from saas.scripts.oci_promotion import require
from saas.scripts.protected_legacy_initial_build import (
    BASELINES,
    REPOSITORY,
    WORKFLOW,
    load_profile,
)

_PREFIX = f"repos/{REPOSITORY}"
_PG_STEPS = (
    "Checkout exact main PG verifier",
    "Set up Python",
    "Select registered PG product",
    "Checkout exact PG product",
    "Verify complete component PG input fingerprints",
    "Set up uv",
    "Install locked product contract dependencies without build hooks",
    "Capture actual disposable PostgreSQL version",
    "Execute original exact-source PostgreSQL contracts",
    "Reverify source and exact PostgreSQL result inventory",
    "Retain exact-source PG evidence",
)
_MEMBERS = {
    "legacy-pg-source.json",
    "legacy-pg-version.txt",
    "legacy-pg.xml",
    "legacy-pg-result.json",
}


def verify_control_run(
    run: dict[str, Any], *, revision: str, run_id: int, attempt: int, actor: str
) -> None:
    require(
        re.fullmatch(r"[0-9a-f]{40}", revision) is not None
        and type(run_id) is int
        and run_id > 0
        and type(attempt) is int
        and attempt > 0
        and isinstance(actor, str)
        and bool(actor),
        "invalid immutable native control coordinates",
    )
    require(
        run.get("id") == run_id
        and run.get("run_attempt") == attempt
        and run.get("head_sha") == revision
        and run.get("head_branch") == "main"
        and run.get("event") == "workflow_dispatch"
        and run.get("path") == WORKFLOW
        and run.get("repository", {}).get("full_name") == REPOSITORY
        and run.get("head_repository", {}).get("full_name") == REPOSITORY
        and run.get("actor", {}).get("login") == actor
        and run.get("triggering_actor", {}).get("login") == actor
        and run.get("status") in {"in_progress", "completed"}
        and (
            (run["status"] == "in_progress" and run.get("conclusion") is None)
            or (run["status"] == "completed" and run.get("conclusion") == "success")
        ),
        "native run is not the current successful-or-active protected control",
    )


def verify_pg_job(
    job: dict[str, Any], *, major: int, run_id: int, attempt: int, control_revision: str
) -> dict[str, dict[str, Any]]:
    require(
        job.get("name") == f"legacy-pg ({major})"
        and job.get("run_id") == run_id
        and job.get("run_attempt") == attempt
        and job.get("head_sha") == control_revision
        and job.get("status") == "completed"
        and job.get("conclusion") == "success"
        and job.get("runner_group_name") == "GitHub Actions"
        and "ubuntu-latest" in job.get("labels", []),
        "PG matrix job is not the exact successful native hosted job",
    )
    result = {}
    numbers = []
    for name in _PG_STEPS:
        matches = [row for row in job.get("steps", []) if row.get("name") == name]
        require(
            len(matches) == 1
            and matches[0].get("status") == "completed"
            and matches[0].get("conclusion") == "success"
            and type(matches[0].get("number")) is int,
            "original PG execution step is missing, ambiguous or unsuccessful",
        )
        result[name] = matches[0]
        numbers.append(matches[0]["number"])
    require(numbers == sorted(set(numbers)) and numbers[0] > 0, "native PG steps are out of order")
    return result


def verify_pg_archive(archive: Path, *, source: dict[str, Any], major: int) -> dict[str, Any]:
    with zipfile.ZipFile(archive) as bundle:
        require(
            len(bundle.namelist()) == len(_MEMBERS) and set(bundle.namelist()) == _MEMBERS,
            "PG artifact has missing, duplicate or extra members",
        )
    payloads = {name: read_junit_member(archive, name) for name in _MEMBERS}
    require(
        json.loads(payloads["legacy-pg-source.json"]) == source,
        "original PG source receipt differs from actual input fingerprints",
    )
    result = verify_pg_results(
        payloads["legacy-pg.xml"],
        major=major,
        observed_version=payloads["legacy-pg-version.txt"].decode(),
    )
    expected = {**source, "result": result}
    require(
        json.loads(payloads["legacy-pg-result.json"]) == expected,
        "PG result receipt differs from actual XML/version/source",
    )
    return result


def collect_pg_receipts(
    control: Path,
    product: Path,
    component: str,
    control_revision: str,
    *,
    run_id: int,
    attempt: int,
    actor: str,
    destination: Path,
) -> dict[str, Any]:
    return _collect_pg_receipts(
        control,
        product,
        component,
        control_revision,
        run_id=run_id,
        attempt=attempt,
        actor=actor,
        destination=destination,
        context_verifier=control_context,
    )


def _collect_pg_receipts(
    control: Path,
    product: Path,
    component: str,
    control_revision: str,
    *,
    run_id: int,
    attempt: int,
    actor: str,
    destination: Path,
    context_verifier,
) -> dict[str, Any]:
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    with preserve_native_evidence(
        destination / "native-api", evidence_root=destination
    ) as evidence:
        context_verifier(control, control_revision)
        profile = load_profile(control, component)
        source = _verify_pg_source(
            control, product, component, control_revision, context_verifier=context_verifier
        )
        run = api(f"{_PREFIX}/actions/runs/{run_id}/attempts/{attempt}")
        verify_control_run(
            run, revision=control_revision, run_id=run_id, attempt=attempt, actor=actor
        )
        latest = api(f"{_PREFIX}/actions/runs/{run_id}")
        verify_control_run(
            latest, revision=control_revision, run_id=run_id, attempt=attempt, actor=actor
        )
        workflow = api(f"{_PREFIX}/contents/{WORKFLOW}?ref={control_revision}")
        require(
            workflow.get("path") == WORKFLOW and workflow.get("encoding") == "base64",
            "native control workflow identity differs",
        )
        native_bytes = base64.b64decode("".join(workflow["content"].split()), validate=True)
        local_bytes = (control / WORKFLOW).read_bytes()
        require(
            native_bytes == local_bytes and workflow.get("size") == len(native_bytes),
            "native control workflow bytes differ from trusted checkout",
        )
        jobs = _job_pages(run_id, attempt)
        artifacts = _pages(f"{_PREFIX}/actions/runs/{run_id}/artifacts", "artifacts")
        receipts = []
        selected_ids = {}
        for major in (16, 18):
            evidence.stage = f"PG{major}-native-job"
            matching_jobs = [job for job in jobs if job.get("name") == f"legacy-pg ({major})"]
            require(len(matching_jobs) == 1, "native PG matrix job is missing or duplicated")
            job = matching_jobs[0]
            selected_ids[major] = job["id"]
            steps = verify_pg_job(
                job, major=major, run_id=run_id, attempt=attempt, control_revision=control_revision
            )
            log_path = destination / f"job-{job['id']}.log"
            download_job_log(job["id"], log_path)
            log = log_path.read_text()
            require(
                checkout_commit(log, steps["Checkout exact main PG verifier"]) == control_revision
                and checkout_commit(log, steps["Checkout exact PG product"])
                == profile["product_revision"],
                "actual PG control/product checkout differs",
            )
            name = (
                f"legacy-pg-{component}-{major}-{profile['product_revision']}-"
                f"{control_revision}-{run_id}-{attempt}"
            )
            matched = [row for row in artifacts if row.get("name") == name]
            require(len(matched) == 1, "native PG artifact is missing or duplicated")
            metadata = api(f"{_PREFIX}/actions/artifacts/{matched[0]['id']}")
            require(metadata == matched[0], "native PG artifact changed since listing")
            require(
                isinstance(metadata.get("digest"), str)
                and re.fullmatch(r"sha256:[0-9a-f]{64}", metadata["digest"]) is not None
                and type(metadata.get("size_in_bytes")) is int
                and 0 < metadata["size_in_bytes"] <= 64 * 1024 * 1024,
                "native PG artifact digest/size is invalid",
            )
            archive = destination / f"pg-{major}.zip"
            download_artifact_bytes(
                metadata["id"],
                archive,
                expected_size=metadata["size_in_bytes"],
                expected_sha256=metadata["digest"][7:],
            )
            evidence.stage = f"PG{major}-original-ZIP-XML"
            verify_job_artifact_identity(
                metadata,
                run,
                job,
                revision=control_revision,
                artifact_name=name,
                upload_step=steps["Retain exact-source PG evidence"],
                archive=archive,
            )
            native_tests = pytest_log_inventory(
                log, steps["Execute original exact-source PostgreSQL contracts"]
            )
            parsed = verify_test_results(
                read_junit_member(archive, "legacy-pg.xml"),
                native_tests,
                approved_skips={},
                approved_reruns={},
            )
            major_source = {
                **source,
                "postgresql_major": major,
                "service_image": PG_IMAGES[major],
                "production_admission": False,
            }
            result = verify_pg_archive(archive, source=major_source, major=major)
            require(
                api(f"{_PREFIX}/actions/artifacts/{metadata['id']}") == metadata,
                "native PG artifact expired or changed during verification",
            )
            fresh_job = api(f"{_PREFIX}/actions/jobs/{job['id']}")
            require(fresh_job == job, "native PG job changed during result verification")
            receipts.append(
                {
                    "postgresql_major": major,
                    "job_id": job["id"],
                    "artifact_id": metadata["id"],
                    "original_ZIP_size": metadata["size_in_bytes"],
                    "original_ZIP_sha256": metadata["digest"][7:],
                    "native_log_sha256": hashlib.sha256(log_path.read_bytes()).hexdigest(),
                    "source": major_source,
                    "XML_result": result,
                    "native_pytest": parsed,
                }
            )
        evidence.stage = "final-control-run-and-source"
        final_run = api(f"{_PREFIX}/actions/runs/{run_id}")
        verify_control_run(
            final_run, revision=control_revision, run_id=run_id, attempt=attempt, actor=actor
        )
        final_jobs = _job_pages(run_id, attempt)
        for major, job_id in selected_ids.items():
            require(
                [job["id"] for job in final_jobs if job.get("name") == f"legacy-pg ({major})"]
                == [job_id],
                "native PG matrix changed during verification",
            )
        require(
            _verify_pg_source(
                control, product, component, control_revision, context_verifier=context_verifier
            )
            == source,
            "exact PG source inputs changed during native collection",
        )
        result = {
            "kind": "legacy_native_exact_product_PG_receipts/v1",
            "component": component,
            "control_revision": control_revision,
            "product_revision": profile["product_revision"],
            "product_tree": profile["product_tree"],
            "run_id": run_id,
            "attempt": attempt,
            "actor": actor,
            "workflow_sha256": hashlib.sha256(native_bytes).hexdigest(),
            "PG16_and_PG18": receipts,
            "native_PG_receipts_pass": True,
            "complete_source_image_signature_production_admission": False,
        }
        (destination / "native-PG-results.json").write_text(json.dumps(result, indent=2) + "\n")
        evidence.stage = "PG-receipts-verified-only"
        return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--product", type=Path, required=True)
    parser.add_argument("--component", choices=tuple(BASELINES), required=True)
    parser.add_argument("--control-revision", required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    require(
        os.environ.get("GITHUB_WORKFLOW_SHA") == args.control_revision
        and os.environ.get("GITHUB_WORKFLOW_REF") == f"{REPOSITORY}/{WORKFLOW}@refs/heads/main",
        "PG consumer requires the actual protected workflow source identity",
    )
    result = collect_pg_receipts(
        args.control,
        args.product,
        args.component,
        args.control_revision,
        run_id=int(os.environ["GITHUB_RUN_ID"]),
        attempt=int(os.environ["GITHUB_RUN_ATTEMPT"]),
        actor=os.environ["GITHUB_ACTOR"],
        destination=args.destination,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
