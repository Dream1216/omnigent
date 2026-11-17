"""Refresh vulnerability evidence for an explicitly registered signed OCI origin."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import NamedTuple
from urllib.parse import parse_qs, urlsplit

from saas.scripts.legacy_artifact_download import download_artifact_bytes
from saas.scripts.oci_promotion import (
    MANIFEST_NAME,
    extract_artifact,
    read_json,
    require,
    validate_scans,
    verify_candidate,
)
from saas.scripts.resume_oci_promotion import (
    api,
    build_certificate_claims,
    build_promotion_predicate,
    verify_predicate,
)
from saas.scripts.scan_oci_candidates import official_database_latest, scan_report

ORIGIN_FILE = Path(".github/actions/compat-smoke-m2c-evidence-renewal/origin.json")
WORKFLOW = ".github/workflows/saas-m2c-evidence-renewal.yml"
PRODUCT = "2c34fd412118b806156b42de767dc2315e25cbd1"
_FIXED_TREE = "0589ca4ed27b94691dae61db48dd84e4777401bc"
_FIXED_RUN = 43535964651
_EVIDENCE_KIND = "same_signed_M2c_current_scan_evidence"
_ORIGIN_FIELDS = {
    "schema_version",
    "repository",
    "product_revision",
    "product_tree",
    "run_id",
    "attempt",
    "workflow",
    "rebuilt",
    "source_date_epoch",
    "manifest_sha256",
    "images",
    "platforms",
    "required_jobs",
    "artifacts",
}


class FixedRelease(NamedTuple):
    product: str
    tree: str
    run: int
    origin_file: Path
    workflow: str
    evidence_kind: str


_FIXED_RELEASES = {
    "m2c": FixedRelease(PRODUCT, _FIXED_TREE, _FIXED_RUN, ORIGIN_FILE, WORKFLOW, _EVIDENCE_KIND),
    "main342": FixedRelease(
        "34201d054c563b1760e6990cdcaa8a71da097471",
        "25e90c8c4b284f1282b309bbe33bae388f8d5a98",
        43980645999,
        ORIGIN_FILE.with_name("main4cb-origin.json"),
        ".github/workflows/saas-m-current-evidence-renewal.yml",
        "same_signed_M342_current_scan_evidence",
    ),
}


def select_release(release: str) -> None:
    """Select only a committed fixed profile; no caller-supplied origin path."""
    global PRODUCT, _FIXED_TREE, _FIXED_RUN, ORIGIN_FILE, WORKFLOW, _EVIDENCE_KIND
    require(release in _FIXED_RELEASES, "unknown fixed renewal origin")
    profile = _FIXED_RELEASES[release]
    PRODUCT, _FIXED_TREE, _FIXED_RUN = profile.product, profile.tree, profile.run
    ORIGIN_FILE, WORKFLOW, _EVIDENCE_KIND = (
        profile.origin_file,
        profile.workflow,
        profile.evidence_kind,
    )


CURRENT_PRODUCT = "34201d054c563b1760e6990cdcaa8a71da097471"
CURRENT_TREE = "25e90c8c4b284f1282b309bbe33bae388f8d5a98"
CURRENT_SOURCE_RUN = 43957191521
SOURCE_REQUIRED_JOBS = {
    "verify-candidate-preflight": 133614979204,
    (
        "verify-production-migration-replay "
        "(postgres:18.6-trixie@sha256:4ef4dbc939d61acea57712655ddb4b4ab..."
    ): 133614979307,
    (
        "verify-production-migration-replay "
        "(postgres:16.14-bookworm@sha256:64154d0babcb1741988719e703419a..."
    ): 133614979426,
    "build-candidate": 133617883066,
}
CURRENT_PUBLISHER_RUN = 43980645999
_CURRENT_ORIGIN_Q_SHA256 = "adbdb36ffb8ba3f95455fe114f1a742a0276f6fb993f563659d062552cd5e5ca"
_CURRENT_SOURCE_QUALIFICATION_SHA256 = (
    "96006ad901c9069dc43dc0cdf6a6970b23959352685019482893d9e4a98b98f3"
)
_CURRENT_CORE_QUALIFICATION_SHA256 = (
    "487649b8ae9dfb27d379e6e651eb4f61bc4c90585e89424ea3b632839647fbcd"
)
_CURRENT_CORE_EXPIRY = "2026-11-17T21:10:21+00:00"
CURRENT_PATHS = frozenset(
    (
        ".github/actions/compat-smoke-m2c-evidence-renewal/renewal.py",
        ".github/actions/compat-smoke-m2c-evidence-renewal/test_renewal.py",
        ".github/actions/compat-smoke-m2c-evidence-renewal/main4cb-origin.json",
        ".github/workflows/saas-m-current-evidence-renewal.yml",
        ".github/workflows/saas-upstream-compat.yml",
    )
)
CURRENT_REGISTRY = ".github/actions/compat-smoke-m2c-evidence-renewal/main4cb-origin.json"


def origin() -> dict:
    value = read_json(ORIGIN_FILE)
    if _FIXED_RUN == CURRENT_PUBLISHER_RUN:
        require(
            value["product_revision"] == CURRENT_PRODUCT
            and value["product_tree"] == CURRENT_TREE
            and value["run_id"] == CURRENT_PUBLISHER_RUN
            and value["source_run_id"] == CURRENT_SOURCE_RUN
            and value["attempt"] == value["source_attempt"] == 1
            and value["workflow"] == ".github/workflows/saas-image-candidate.yml"
            and value["rebuilt"] is False,
            "fixed342 signed origin differs",
        )
        for key in ("source_qualification_sha256", "origin_q_sha256", "manifest_sha256"):
            require(
                re.fullmatch(r"[0-9a-f]{64}", str(value[key])) is not None,
                "actual342 first P1/q pins not materialized",
            )
        require(
            value["source_required_jobs"] == SOURCE_REQUIRED_JOBS
            and value["required_jobs"].keys() == {"publish-signed", "verify-published-source"}
            and all(
                type(j) is int and j > 0
                for rows in (value["source_required_jobs"], value["required_jobs"])
                for j in rows.values()
            ),
            "actual342 origin native jobs required",
        )
        require(
            value["origin_q_sha256"] == _CURRENT_ORIGIN_Q_SHA256
            and value["source_qualification_sha256"] == _CURRENT_SOURCE_QUALIFICATION_SHA256
            and value["original_main_ci"]["qualification_sha256"]
            == _CURRENT_CORE_QUALIFICATION_SHA256
            and value["original_main_ci"]["expires_at"] == _CURRENT_CORE_EXPIRY,
            "actual fixed342 original qualification/Main CI pins differ",
        )
        require(
            value["original_main_ci"]["product_revision"] == CURRENT_PRODUCT
            and value["original_main_ci"]["product_tree"] == CURRENT_TREE
            and value["original_main_ci"]["required_workflow_count"] == 6
            and value["original_environment_review"]["run"] == CURRENT_PUBLISHER_RUN
            and value["original_environment_review"]["environment"] == "production-image"
            and value["original_environment_review"]["no_rules_bypassed"] is True,
            "original342 Main CI or normal protected review differs",
        )
        caps = value["origin_hard_caps"]
        require(
            set(caps) == {"product_core", "source_created24", "publisher_created24"}
            and caps["product_core"] == value["original_main_ci"]["expires_at"],
            "all original nonsecurity clocks required",
        )
        for cap in caps.values():
            instant(cap)
        for role, run in (("oci", CURRENT_SOURCE_RUN), ("signed", CURRENT_PUBLISHER_RUN)):
            item = value["artifacts"][role]
            require(
                item["run_id"] == run
                and type(item["id"]) is int
                and item["id"] > 0
                and type(item["bytes"]) is int
                and item["bytes"] > 0
                and re.fullmatch(r"[0-9a-f]{64}", str(item["sha256"])),
                "actual342 immutable artifact pins required",
            )
        return value
    require(
        set(value) == _ORIGIN_FIELDS
        and value["product_revision"] == PRODUCT
        and value["product_tree"] == _FIXED_TREE
        and value["run_id"] == _FIXED_RUN
        and value["attempt"] == 1
        and value["workflow"] == ".github/workflows/saas-image-candidate.yml"
        and value["rebuilt"] is False,
        "fixed original signed M identity differs",
    )
    return value


def validate_controller_changes(changes: dict, registered: set) -> None:
    require(
        set(changes) == CURRENT_PATHS
        and set(changes) == registered
        and all(status == "M" for status in changes.values()),
        "fixed342 controller exact reviewed CI paths/statuses differ",
    )


def controller_budget(repo: Path, product_root: Path, policy: str) -> dict:
    # Reuse the original classifier's finite-diff principle, never a prefix skip.
    from saas.scripts import check_upstream_delta as guard
    from saas.scripts.fixed_main16_ci_promotion import _git

    require(
        _git(repo, "rev-parse", "HEAD") == policy and policy != CURRENT_PRODUCT,
        "actual distinct controller checkout required",
    )
    _git(repo, "merge-base", "--is-ancestor", CURRENT_PRODUCT, policy)
    require(not _git(repo, "diff", "HEAD", "--"), "tracked controller checkout changed")
    require(
        _git(product_root, "rev-parse", "HEAD") == CURRENT_PRODUCT
        and _git(product_root, "rev-parse", "HEAD^{tree}") == CURRENT_TREE
        and not _git(product_root, "status", "--porcelain"),
        "fixed product view differs",
    )
    registered = read_json(repo / CURRENT_REGISTRY)["controller_scope"]
    changes = {
        p: status
        for status, p in (
            row.split("\t")
            for row in _git(
                repo, "diff", "--no-renames", "--name-status", CURRENT_PRODUCT, policy
            ).splitlines()
        )
    }
    validate_controller_changes(changes, set(registered["postimages"]) | {CURRENT_REGISTRY})
    require(
        set(registered["postimages"]) == CURRENT_PATHS - {CURRENT_REGISTRY},
        "exact four controller code/workflow postimages required",
    )
    for path, expected in registered["postimages"].items():
        target = repo / path
        require(
            target.is_file()
            and not target.is_symlink()
            and digest(target) == expected["sha256"]
            and target.stat().st_size == expected["bytes"],
            "controller postimage differs",
        )
    authority = registered["authority"]
    require(
        authority["thread"] == "01a1db4c-a4d7-7693-96b6-af294b9aed8b"
        and authority["Source_handoff_sha256"]
        == "f6cc2d86c6bdb4d3d62fb1e24b3dabce4adbbd8c1279e5f529ee79d2a0172187"
        and authority["decision"] == "MAINTAINER_REGISTERED_EXACT_CI_ONLY_INCREMENT"
        and all(
            re.fullmatch(r"[0-9a-f]{64}", str(authority[k]))
            for k in ("registration_sha256", "independent_review_sha256")
        ),
        "Root exact registration and independent review not materialized",
    )
    manifest = read_json(product_root / ".github/workflows/saas-controller-source-budget.json")
    require(
        guard._ordinary_m_candidate_matches(product_root, manifest),
        "original fixed342 finite product scope failed",
    )
    baseline = manifest["upstream_revision"]
    _git(repo, "merge-base", "--is-ancestor", baseline, policy)
    deltas = guard.collect_deltas(repo, baseline)
    upstream = [
        d.path
        for d in deltas
        if not guard._is_under(d.path, tuple(manifest["downstream_owned_prefixes"]))
    ]
    report = guard.evaluate_delta(
        deltas,
        manifest,
        active_patch_count=len(list((repo / manifest["patch_queue_directory"]).glob("*.patch"))),
        reverse_dependencies=guard.scan_reverse_dependencies(repo, upstream),
        lineage_ok=True,
        version_ok=guard._read_project_version(repo) == manifest["upstream_version"],
        source_root=product_root,
    )
    require(report["status"] == "pass", "actual controller budget failed")
    report.update(
        product_revision=CURRENT_PRODUCT,
        product_tree=CURRENT_TREE,
        controller_revision=policy,
        controller_tree=_git(repo, "rev-parse", "HEAD^{tree}"),
        controller_scope=registered,
        product_guard_scope_sha256=digest(
            product_root / "saas/governance/ordinary-m-native-0142-source-scope.json"
        ),
    )
    return report


def verify_two_run_origin(
    run: dict, jobs: dict, tree: dict, artifacts: dict, producer: dict
) -> None:
    value = origin()
    for native, job_rows, identifier, event, expected in (
        (
            producer["run"],
            producer["jobs"],
            CURRENT_SOURCE_RUN,
            "push",
            value["source_required_jobs"],
        ),
        (run, jobs, CURRENT_PUBLISHER_RUN, "workflow_dispatch", value["required_jobs"]),
    ):
        require(
            native["id"] == identifier
            and native["head_sha"] == CURRENT_PRODUCT
            and native["run_attempt"] == 1
            and native["head_branch"] == "main"
            and native["event"] == event
            and native["path"] == value["workflow"]
            and native["status"] == "completed"
            and native["conclusion"] == "success"
            and native["repository"]["full_name"] == value["repository"],
            "fixed342 original source/publisher invocation differs",
        )
        by_name = {j["name"]: j for j in job_rows["jobs"]}
        for name, job_id in expected.items():
            j = by_name.get(name, {})
            require(
                j.get("id") == job_id
                and j["run_id"] == identifier
                and j["run_attempt"] == 1
                and j["status"] == "completed"
                and j["conclusion"] == "success"
                and j["runner_group_name"] == "GitHub Actions"
                and "ubuntu-24.04" in j["labels"],
                "original342 hosted job differs",
            )
    migrations = [
        j
        for j in producer["jobs"]["jobs"]
        if j["name"].startswith("verify-production-migration-replay (postgres:")
    ]
    require(
        len(migrations) == 2 and {j["id"] for j in migrations} == {133614979307, 133614979426},
        "both original PG16 and PG18 migration jobs required",
    )
    by_name = {j["name"]: j for j in jobs["jobs"]}
    require(
        all(
            by_name[name]["conclusion"] == "skipped"
            for name in (
                "build-candidate",
                "verify-candidate-preflight",
                "verify-production-migration-replay",
            )
        ),
        "publisher must retain original logical build/preflight/replay skips",
    )
    require(
        tree["sha"] == CURRENT_PRODUCT and tree["tree"]["sha"] == CURRENT_TREE,
        "fixed342 original product tree differs",
    )
    for role, rows in (("oci", producer["artifacts"]), ("signed", artifacts)):
        expected = value["artifacts"][role]
        item = next(a for a in rows["artifacts"] if a["id"] == expected["id"])
        require(
            item["name"] == expected["name"]
            and item["size_in_bytes"] == expected["bytes"]
            and item["digest"] == "sha256:" + expected["sha256"]
            and item["expired"] is False
            and item["workflow_run"]["id"] == expected["run_id"]
            and item["workflow_run"]["head_sha"] == CURRENT_PRODUCT,
            "fixed342 immutable split-origin artifact differs",
        )
    caps = value["origin_hard_caps"]
    require(
        instant(caps["source_created24"])
        == instant(producer["run"]["created_at"]) + timedelta(hours=24)
        and instant(caps["publisher_created24"])
        == instant(run["created_at"]) + timedelta(hours=24),
        "original source/publisher clocks cannot renew",
    )


def instant(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(parsed.utcoffset() == timedelta(0), "UTC timestamp required")
    return parsed


def verify_origin(
    run: dict, jobs: dict, tree: dict, artifacts: dict, producer: dict | None = None
) -> None:
    if _FIXED_RUN == CURRENT_PUBLISHER_RUN:
        require(producer is not None, "actual fixed342 push origin required")
        verify_two_run_origin(run, jobs, tree, artifacts, producer)
        return
    value = origin()
    require(
        run["id"] == value["run_id"]
        and run["run_attempt"] == value["attempt"]
        and run["head_sha"] == PRODUCT
        and run["head_branch"] == "main"
        and run["path"] == value["workflow"]
        and run["event"] == "workflow_dispatch"
        and run["status"] == "completed"
        and run["conclusion"] == "success"
        and run["repository"]["full_name"] == value["repository"]
        and tree["sha"] == PRODUCT
        and tree["tree"]["sha"] == value["product_tree"],
        "original native source or signing invocation differs",
    )
    by_id = {job["id"]: job for job in jobs["jobs"]}
    for job_id in value["required_jobs"]:
        job = by_id[job_id]
        require(
            job["run_id"] == value["run_id"]
            and job["run_attempt"] == value["attempt"]
            and job["status"] == "completed"
            and job["conclusion"] == "success"
            and job["runner_group_name"] == "GitHub Actions"
            and "ubuntu-24.04" in job["labels"],
            "original required hosted job differs",
        )
    actual = {item["id"]: item for item in artifacts["artifacts"]}
    for expected in value["artifacts"].values():
        item = actual[expected["id"]]
        require(
            item["name"] == expected["name"]
            and item["size_in_bytes"] == expected["bytes"]
            and item["digest"] == "sha256:" + expected["sha256"]
            and item["expired"] is False
            and item["workflow_run"]["id"] == value["run_id"]
            and item["workflow_run"]["head_sha"] == PRODUCT,
            "original immutable artifact differs or expired",
        )


def download_origin(destination: Path) -> None:
    value = origin()
    prefix = f"repos/{value['repository']}"
    native = {
        "run": api(f"{prefix}/actions/runs/{value['run_id']}/attempts/{value['attempt']}"),
        "jobs": api(
            f"{prefix}/actions/runs/{value['run_id']}/attempts/{value['attempt']}/jobs?per_page=100"
        ),
        "tree": api(f"{prefix}/git/commits/{PRODUCT}"),
        "artifacts": api(f"{prefix}/actions/runs/{value['run_id']}/artifacts?per_page=100"),
    }
    if _FIXED_RUN == CURRENT_PUBLISHER_RUN:
        source = f"{prefix}/actions/runs/{CURRENT_SOURCE_RUN}"
        native["producer"] = {
            "run": api(source + "/attempts/1"),
            "jobs": api(source + "/attempts/1/jobs?per_page=100"),
            "artifacts": api(source + "/artifacts?per_page=100"),
        }
    verify_origin(**native)
    destination.mkdir(parents=True, exist_ok=False)
    (destination / "native-origin.json").write_text(json.dumps(native, sort_keys=True) + "\n")
    for role, target in (("oci", "sealed"), ("signed", "signed-origin")):
        item = value["artifacts"][role]
        archive = destination / f"{role}.zip"
        download_artifact_bytes(
            item["id"], archive, expected_size=item["bytes"], expected_sha256=item["sha256"]
        )
        extract_artifact(archive, destination / target, zip_sha256=item["sha256"])
        archive.unlink()
    require(
        digest(destination / "sealed" / MANIFEST_NAME) == value["manifest_sha256"],
        "retained OCI seal differs",
    )
    if _FIXED_RUN == CURRENT_PUBLISHER_RUN:
        signed = destination / "signed-origin"
        facts = read_json(signed / "signed-release-candidate.json")
        proof = read_json(signed / "promotion-source.json")
        promotion = facts["promotion"]
        require(
            facts["product_revision"] == CURRENT_PRODUCT
            and promotion["rebuilt"] is False
            and promotion["source_run_id"] == proof["source_run_id"] == CURRENT_SOURCE_RUN
            and promotion["source_run_attempt"] == proof["source_run_attempt"] == 1
            and promotion["original_artifact_id"]
            == proof["artifact_id"]
            == value["artifacts"]["oci"]["id"]
            and promotion["original_artifact_sha256"]
            == proof["artifact_sha256"]
            == value["artifacts"]["oci"]["sha256"]
            and promotion["candidate_manifest_sha256"] == value["manifest_sha256"]
            and digest(signed / "promotion-source.json") == promotion["source_proof_sha256"],
            "fixed342 original signed-source/seal binding differs",
        )


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def promotion_predicate(policy: str, run: str, attempt: str) -> dict:
    value = origin()
    binding = {
        **value,
        "oci_artifact_id": value["artifacts"]["oci"]["id"],
        "oci_artifact_sha256": value["artifacts"]["oci"]["sha256"],
    }
    return build_promotion_predicate(binding, WORKFLOW, policy, run, attempt)


def verify_signature(entries: list, subject: str, *, policy: str, run: str, attempt: str) -> None:
    value = origin()
    verify_predicate(
        entries,
        subject="sha256:" + subject,
        predicate=promotion_predicate(policy, run, attempt),
        predicate_type="https://slsa.dev/provenance/v1",
        claims=build_certificate_claims(value["repository"], policy, WORKFLOW, run, attempt),
    )


def qualify(
    sealed: Path, scans: Path, *, policy: str, run: str, attempt: str, started: str
) -> dict:
    value = origin()
    require(
        re.fullmatch(r"[0-9a-f]{40}", policy) is not None
        and policy != PRODUCT
        and re.fullmatch(r"[1-9][0-9]*", run) is not None
        and re.fullmatch(r"[1-9][0-9]*", attempt) is not None,
        "actual distinct controller and invocation required",
    )
    current = datetime.now(UTC)
    beginning = instant(started)
    require(beginning <= current, "scan start cannot be in the future")
    manifest = read_json(sealed / MANIFEST_NAME)
    manifest = verify_candidate(
        sealed,
        manifest_sha256=value["manifest_sha256"],
        labels=manifest["labels"],
        source_date_epoch=value["source_date_epoch"],
        current_scan_root=scans,
    )
    require(
        manifest["product_revision"] == PRODUCT
        and {role: row["index_digest"] for role, row in manifest["images"].items()}
        == value["images"],
        "fresh evidence cannot change source or OCI subjects",
    )
    latest = official_database_latest()
    checked = datetime.now(UTC)
    summary = read_json(scans / "grype/candidate-scan-summary.json")
    require(
        all(
            row.get("database_age_disposition") is None
            and row.get("component_disposition") is None
            for row in summary["images"]
        ),
        "renewal accepts no age or component exception",
    )
    qualified = validate_scans(scans, manifest["images"], now=checked)
    require("temporary_database_age" not in qualified, "normal24 only")
    built = instant(summary["database_built_at"])
    expiry = min(built + timedelta(hours=24), checked + timedelta(hours=24))
    if "original_main_ci" in value:
        expiry = min(expiry, instant(value["original_main_ci"]["expires_at"]))
    if "origin_hard_caps" in value:
        expiry = min(expiry, *(instant(v) for v in value["origin_hard_caps"].values()))
    require(
        latest["status"] == "active"
        and instant(latest["built"]) == built
        and beginning <= checked < expiry
        and checked - built < timedelta(hours=24),
        "current official database or time bound differs",
    )
    reports = {}
    for role in ("server", "host"):
        for arch in ("amd64", "arm64"):
            coordinate = f"{role}-{arch}"
            path = scans / f"grype/{coordinate}-grype.json"
            raw = read_json(path)
            descriptor = raw["descriptor"]
            config = descriptor["configuration"]
            db = config["db"]
            require(
                scan_report(raw)["counts"] == {"Critical": 0, "High": 0}
                and raw.get("ignoredMatches", []) == []
                and config["fail-on-severity"] == "high"
                and db["validate-age"] is True
                and db["validate-by-hash-on-start"] is True
                and db["max-allowed-built-age"] == 86400000000000
                and descriptor["db"]["status"]["schemaVersion"] == latest["schemaVersion"]
                and parse_qs(urlsplit(descriptor["db"]["status"]["from"]).query).get("checksum")
                == [latest["checksum"]],
                "raw findings, official DB hash or normal24 policy differs",
            )
            reports[coordinate] = {
                "sha256": digest(path),
                "manifest_digest": manifest["images"][role]["facts"]["platforms"][f"linux/{arch}"][
                    "manifest_digest"
                ],
                "config_digest": manifest["images"][role]["facts"]["platforms"][f"linux/{arch}"][
                    "config_digest"
                ],
            }
    return {
        "schema_version": 1,
        "kind": _EVIDENCE_KIND,
        "origin": value,
        "signing_policy_revision": policy,
        "run_id": run,
        "run_attempt": attempt,
        "workflow": WORKFLOW,
        "scan_started_at": beginning.isoformat(),
        "scan_qualified_at": checked.isoformat(),
        "official_latest_checked_at": checked.isoformat(),
        "official_latest": latest,
        "database_built_at": built.isoformat(),
        "expires_at": expiry.isoformat(),
        "reports": reports,
        "scan_summary_sha256": qualified["summary_sha256"],
        "product_source_or_OCI_rebuilt": False,
        "production_deployment_receipt": None,
    }


def verify_current(payload: dict, scans: Path, *, policy: str, run: str, attempt: str) -> None:
    value = origin()
    now = datetime.now(UTC)
    require(
        payload["origin"] == value
        and payload["kind"] == _EVIDENCE_KIND
        and payload["signing_policy_revision"] == policy
        and payload["run_id"] == run
        and payload["run_attempt"] == attempt
        and payload["workflow"] == WORKFLOW
        and payload["product_source_or_OCI_rebuilt"] is False
        and payload["production_deployment_receipt"] is None
        and instant(payload["scan_started_at"]) <= instant(payload["scan_qualified_at"]) <= now
        and now
        < instant(payload["expires_at"])
        <= instant(payload["database_built_at"]) + timedelta(hours=24),
        "current signed evidence identity or hard expiry differs",
    )
    if "original_main_ci" in value:
        require(
            instant(payload["expires_at"]) <= instant(value["original_main_ci"]["expires_at"]),
            "new security evidence cannot renew original Main CI",
        )
    if "origin_hard_caps" in value:
        require(
            all(
                instant(payload["expires_at"]) <= instant(v)
                for v in value["origin_hard_caps"].values()
            ),
            "current evidence cannot renew original nonsecurity clocks",
        )
    manifest = read_json(scans / MANIFEST_NAME)
    require(digest(scans / MANIFEST_NAME) == value["manifest_sha256"], "independent seal differs")
    require(
        validate_scans(scans, manifest["images"], now=now)["summary_sha256"]
        == payload["scan_summary_sha256"],
        "independent current raw scan validation differs",
    )
    summary = read_json(scans / "grype/candidate-scan-summary.json")
    require(
        all(
            row.get("component_disposition") is None
            and row.get("database_age_disposition") is None
            for row in summary["images"]
        ),
        "independent renewal accepts no exception",
    )
    require(
        payload["official_latest"]["status"] == "active"
        and instant(payload["official_latest"]["built"]) == instant(payload["database_built_at"]),
        "independent official input binding differs",
    )
    for coordinate, reference in payload["reports"].items():
        raw = read_json(scans / f"grype/{coordinate}-grype.json")
        config = raw["descriptor"]["configuration"]
        db = config["db"]
        require(
            scan_report(raw)["counts"] == {"Critical": 0, "High": 0}
            and raw.get("ignoredMatches", []) == []
            and config["fail-on-severity"] == "high"
            and db["validate-age"] is True
            and db["validate-by-hash-on-start"] is True
            and db["max-allowed-built-age"] == 86400000000000
            and instant(raw["descriptor"]["db"]["status"]["built"])
            == instant(payload["database_built_at"])
            and parse_qs(urlsplit(raw["descriptor"]["db"]["status"]["from"]).query).get("checksum")
            == [payload["official_latest"]["checksum"]],
            "independent raw findings or normal official policy differs",
        )
        facts = value["platforms"][coordinate]
        require(
            reference["sha256"] == digest(scans / f"grype/{coordinate}-grype.json")
            and reference["manifest_digest"] == facts["manifest_digest"]
            and reference["config_digest"] == facts["config_digest"],
            "current exact four report subjects differ",
        )
    require(
        set(payload["reports"]) == set(value["platforms"]), "four current coordinates required"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument(
        "action",
        choices=(
            "origin",
            "qualify",
            "verify",
            "origin-signatures",
            "predicate",
            "controller-budget",
        ),
    )
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--scans", type=Path)
    parser.add_argument("--product-root", type=Path)
    parser.add_argument("--policy")
    parser.add_argument("--run")
    parser.add_argument("--attempt")
    parser.add_argument("--started")
    parser.add_argument("--release", choices=tuple(_FIXED_RELEASES), default="m2c")
    args = parser.parse_args()
    select_release(args.release)
    if args.action == "controller-budget":
        print(
            json.dumps(
                controller_budget(args.root, args.product_root, args.policy), sort_keys=True
            )
        )
        return
    if args.action == "origin":
        download_origin(args.root)
    elif args.action == "predicate":
        print(json.dumps(promotion_predicate(args.policy, args.run, args.attempt), sort_keys=True))
    elif args.action == "origin-signatures":
        value = origin()
        claims = build_certificate_claims(
            value["repository"],
            PRODUCT,
            value["workflow"],
            str(value["run_id"]),
            str(value["attempt"]),
        )
        for role, subject in value["images"].items():
            entries = json.loads((args.root / f"{role}-origin-signature.json").read_text())
            require(
                any(
                    all(
                        e["verificationResult"]["signature"]["certificate"].get(k) == v
                        for k, v in claims.items()
                    )
                    and e["verificationResult"]["statement"].get("predicateType")
                    == "https://slsa.dev/provenance/v1"
                    and any(
                        s.get("digest", {}).get("sha256") == subject.removeprefix("sha256:")
                        for s in e["verificationResult"]["statement"]["subject"]
                    )
                    for e in entries
                ),
                "original signed image must bind the actual original invocation",
            )
        print(json.dumps({"state": "EXACT_ORIGIN_IMAGE_SIGNATURES_PASS"}))
    elif args.action == "qualify":
        value = qualify(
            args.root,
            args.scans,
            policy=args.policy,
            run=args.run,
            attempt=args.attempt,
            started=args.started,
        )
        print(json.dumps(value, sort_keys=True))
    else:
        payload_path = args.root / "current-scan-evidence.json"
        payload = read_json(payload_path)
        verify_signature(
            json.loads((args.root / "current-signature.json").read_text()),
            digest(payload_path),
            policy=args.policy,
            run=args.run,
            attempt=args.attempt,
        )
        verify_current(payload, args.root, policy=args.policy, run=args.run, attempt=args.attempt)
        print(
            json.dumps(
                {
                    "state": "CURRENT_EVIDENCE_SIGNATURE_RAW_AND_CLOCK_PASS",
                    "payload_sha256": digest(payload_path),
                    "expires_at": payload["expires_at"],
                    "production_deployment_receipt": None,
                },
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    main()
