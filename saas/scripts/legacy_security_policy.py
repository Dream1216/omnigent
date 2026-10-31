"""Exact original OWNER security-policy completion; never a product scan."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, cast

from saas.scripts.legacy_native_evidence import api
from saas.scripts.oci_promotion import require

WORKFLOW = ".github/workflows/security-scan.yml"
MAIN = "2c5a9a45f1a576439fc9c5aa0a91022d461389ab"
_REVIEWED_MAIN_CHECKOUTS = {MAIN, "95ad31ca3a45b52ec7c071beeb4351f5e39a39fe"}
KIND = "legacy_original_OWNER_security_policy_decision/v1"
SOURCES = {
    WORKFLOW: "26a1962ee265653208068df49404b5a04f2e1d4d3fc651be4458e4c15f4763cd",
    ".github/scripts/security-scan/should-scan.sh": (
        "d3a62e9e1300a9263b1677806c942e0733155e433881c4864b5f12639b032b00"
    ),
    ".github/scripts/merge-ready/load-maintainers.sh": (
        "f6fe003317676e4f946c14bfbf578b6cafcbd83a3dea59d9f55a494b7bf9aa78"
    ),
}
ROOT = "repos/Dream1216/omnigent"
URL = "https://api.github.com/" + ROOT
_FIELDS = {
    "kind",
    "component",
    "product_revision",
    "product_tree",
    "baseline_revision",
    "validation_pr",
    "validation_base_ref",
    "workflow_sha256",
    "trusted_checkout_revision",
    "should_scan_sha256",
    "load_maintainers_sha256",
    "run_id",
    "attempt",
    "job_id",
    "check_id",
    "check_suite_id",
    "run_sha256",
    "job_sha256",
    "check_sha256",
    "job_log_sha256",
}
_NAMES = {
    1: "Set up job",
    2: "Check out scanner from main",
    3: "Load maintainers",
    4: "Trust gate",
    5: "Fetch PR diff",
    6: "Secret scan (added lines)",
    7: "Exfil scan (added lines)",
    8: "Sensitive-path guard",
    9: "Check out PR head for static analysis",
    10: "Workflow misuse lint",
    11: "Install uv",
    12: "OSV advisory scan (uv.lock)",
    13: "Semgrep (changed files, local rules)",
    14: "Explain the maintainer waiver (on failure)",
    28: "Post Check out scanner from main",
    29: "Complete job",
}
EXECUTION_STEPS = [{"number": n, "name": _NAMES[n]} for n in (3, 4)]


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


@dataclass(frozen=True)
class SecurityPolicyDecision:
    registration: dict[str, Any]
    receipt: dict[str, Any]


class SourceCIObservation(dict):
    def __init__(self, facts, proofs):
        super().__init__(facts)
        self.security_policy_decisions = tuple(proofs)


def validate_registration(profile, identity, specification):
    from saas.scripts.legacy_pr_candidate import VALIDATION_REFS

    row = specification.get("trusted_security_policy")
    require(
        isinstance(row, dict) and set(row) == _FIELDS,
        "original OWNER security-policy registration fields differ",
    )
    require(
        row["kind"] == KIND
        and row["component"] == profile["component"]
        and all(
            row[k] == profile[k] for k in ("product_revision", "product_tree", "baseline_revision")
        )
        and all(
            row[k] == identity[k]
            for k in ("validation_pr", "validation_base_ref", "product_revision", "product_tree")
        )
        and row["validation_base_ref"] == VALIDATION_REFS.get(profile["component"])
        and row["validation_base_ref"] != "main"
        and type(row["validation_pr"]) is int
        and row["validation_pr"] > 0,
        "original OWNER policy does not bind the exact frozen legacy source and PR",
    )
    require(
        specification["path"] == WORKFLOW
        and specification["name"] == "Security Scan"
        and specification["source_sha256"] == row["workflow_sha256"] == SOURCES[WORKFLOW]
        and row["trusted_checkout_revision"] in _REVIEWED_MAIN_CHECKOUTS
        and row["should_scan_sha256"] == SOURCES[".github/scripts/security-scan/should-scan.sh"]
        and row["load_maintainers_sha256"]
        == SOURCES[".github/scripts/merge-ready/load-maintainers.sh"]
        and specification["run_id"] == row["run_id"]
        and specification["attempt"] == row["attempt"]
        and specification["jobs"]
        == {
            "Security Scan": {
                "labels": ["ubuntu-latest"],
                "conclusion": "success",
                "checkouts": [
                    {"number": 2, "name": _NAMES[2], "revision": row["trusted_checkout_revision"]}
                ],
            }
        },
        "only the original fixed-main OWNER security workflow has this binding",
    )
    require(
        all(
            type(row[k]) is int and row[k] > 0
            for k in ("run_id", "attempt", "job_id", "check_id", "check_suite_id")
        )
        and all(
            isinstance(row[k], str) and re.fullmatch(r"[0-9a-f]{64}", row[k])
            for k in ("run_sha256", "job_sha256", "check_sha256", "job_log_sha256")
        ),
        "original OWNER native coordinates or object hashes differ",
    )
    return row


def _trust_output(log, step):
    from saas.scripts.legacy_source_ci import completed_step_lines

    lines = completed_step_lines(log, step)
    marker = "##[group]Run # Before this lands on main the scripts are absent there -- proceed"
    starts = [i for i, line in enumerate(lines) if line == marker]
    require(len(starts) == 1, "original OWNER command group is missing or ambiguous")
    start = starts[0]
    ends = [i for i in range(start + 1, len(lines)) if lines[i] == "##[endgroup]"]
    require(bool(ends), "original OWNER command group has no end")
    end = ends[0]
    require(
        not any(line.startswith("##[group]") for line in lines[start + 1 : end]),
        "original OWNER command group is nested",
    )
    group = lines[start + 1 : end]
    require(group.count("env:") == 1, "original OWNER environment frame differs")
    values, token_fields = {}, 0
    for line in group[group.index("env:") + 1 :]:
        if line.startswith("  GH_TOKEN: "):
            token_fields += 1
            continue
        match = re.fullmatch(r"  ([A-Z_]+): (.*)", line)
        require(
            match is not None and match[1] not in values,
            "original OWNER environment is malformed or duplicated",
        )
        match = cast(re.Match[str], match)
        values[match[1]] = match[2]
    require(
        token_fields == 1
        and set(values)
        == {
            "UV_INDEX_URL",
            "EVENT_NAME",
            "AUTHOR_ASSOCIATION",
            "PR_AUTHOR",
            "REPO",
            "PR",
            "MAINTAINERS",
        },
        "original OWNER environment is incomplete",
    )
    following = lines[end + 1 :]
    stop = next(
        (i for i, line in enumerate(following) if line.startswith("##[group]")), len(following)
    )
    output = following[:stop]
    require(
        [line for line in output if line.startswith("scan=")]
        == ["scan=false (trusted author (author_association=OWNER))"]
        and not any("##[error]" in line or "##[warning]" in line for line in output),
        "original OWNER decision is not actual successful post-group output",
    )
    return values


def verify_policy_decision(
    profile, identity, specification, pull, commit, run, jobs, check, raw_log
):
    from saas.scripts import legacy_source_ci as source

    row = validate_registration(profile, identity, specification)
    source.verify_pr_tree(
        pull,
        commit,
        profile,
        number=identity["validation_pr"],
        base_ref=identity["validation_base_ref"],
    )
    source.verify_run_pull_request(run, profile, identity["validation_pr"])
    source.verify_job_set(run, jobs, specification, profile["product_revision"])
    require(len(jobs) == 1, "original OWNER security native job set differs")
    job = jobs[0]
    require(
        run.get("id") == row["run_id"]
        and run.get("run_attempt") == row["attempt"]
        and run.get("check_suite_id") == row["check_suite_id"]
        and job.get("id") == row["job_id"]
        and check.get("id") == row["check_id"]
        and job.get("check_run_url") == f"{URL}/check-runs/{row['check_id']}"
        and check.get("app", {}).get("id") == 15368
        and check.get("check_suite", {}).get("id") == row["check_suite_id"]
        and check.get("head_sha") == profile["product_revision"]
        and check.get("name") == "Security Scan"
        and check.get("status") == "completed"
        and check.get("conclusion") == "success"
        and check.get("details_url")
        == f"https://github.com/Dream1216/omnigent/actions/runs/{row['run_id']}/job/{row['job_id']}",
        "original OWNER security native run/job/check/provider/source differs",
    )
    steps = job.get("steps", [])
    require(
        [(s.get("number"), s.get("name"), s.get("status"), s.get("conclusion")) for s in steps]
        == [
            (number, name, "completed", "skipped" if 5 <= number <= 14 else "success")
            for number, name in _NAMES.items()
        ],
        "original OWNER security executed/skipped step inventory differs",
    )
    lookup = {s["number"]: s for s in steps}
    require(
        source._instant(lookup[2]["completed_at"]) <= source._instant(lookup[3]["started_at"])
        and source._instant(lookup[3]["completed_at"]) <= source._instant(lookup[4]["started_at"]),
        "original OWNER security step windows overlap or reverse",
    )
    require(len(raw_log) <= 32 * 1024 * 1024, "original OWNER log exceeds bound")
    log = raw_log.decode("utf-8")
    require(
        source.checkout_commit(log, lookup[2]) == row["trusted_checkout_revision"],
        "original OWNER scanner checkout differs",
    )
    values = _trust_output(log, lookup[4])
    require(
        all(
            values[k] == v
            for k, v in {
                "UV_INDEX_URL": "https://pypi.org/simple",
                "EVENT_NAME": "pull_request",
                "AUTHOR_ASSOCIATION": "OWNER",
                "PR_AUTHOR": "Dream1216",
                "REPO": "Dream1216/omnigent",
                "PR": str(identity["validation_pr"]),
            }.items()
        )
        and pull.get("user", {}).get("login") == "Dream1216"
        and pull.get("author_association") == "OWNER",
        "original OWNER event environment or native PR author differs",
    )
    maintainers = source.completed_step_lines(log, lookup[3])
    require(
        [
            line
            for line in maintainers
            if line.startswith("Loaded maintainers from MAINTAINER@main:")
        ]
        == ["Loaded maintainers from MAINTAINER@main: " + values["MAINTAINERS"]]
        and bool(values["MAINTAINERS"]),
        "original OWNER maintainer observation differs",
    )
    require(
        digest(run) == row["run_sha256"]
        and digest(job) == row["job_sha256"]
        and digest(check) == row["check_sha256"]
        and hashlib.sha256(raw_log).hexdigest() == row["job_log_sha256"],
        "original OWNER native tuple changed from exact reviewed bytes",
    )
    receipt = {
        "kind": KIND,
        **{
            k: row[k]
            for k in (
                "component",
                "product_revision",
                "product_tree",
                "baseline_revision",
                "validation_pr",
                "validation_base_ref",
                "run_id",
                "attempt",
                "job_id",
                "check_id",
                "check_suite_id",
                "check_sha256",
            )
        },
        "trusted_checkout_revision": row["trusted_checkout_revision"],
        "registration_sha256": digest(row),
        "policy_result": "trusted-author-OWNER-not-scanned",
        "product_input_fetched": False,
        "scan_performed": False,
        "detectors_executed": False,
        "original_conclusion": "success",
        "original_skipped_steps": [{"number": n, "name": _NAMES[n]} for n in range(5, 15)],
        "production_admission": False,
    }
    return SecurityPolicyDecision(dict(row), receipt)


def collect_policy_decision(
    profile, identity, specification, pull, commit, run, jobs, log_path, destination
):
    from saas.scripts import legacy_source_ci as source
    from saas.scripts.legacy_domain_native import _native_file

    row = validate_registration(profile, identity, specification)
    for path, expected in SOURCES.items():
        require(
            hashlib.sha256(
                _native_file(path, row["trusted_checkout_revision"], read=api)
            ).hexdigest()
            == expected,
            "original OWNER trusted workflow or policy bytes changed",
        )
    check_endpoint = f"{ROOT}/check-runs/{row['check_id']}"
    check = api(check_endpoint)
    proof = verify_policy_decision(
        profile, identity, specification, pull, commit, run, jobs, check, log_path.read_bytes()
    )
    require(
        api(f"{ROOT}/actions/runs/{row['run_id']}/attempts/{row['attempt']}") == run
        and source._job_pages(row["run_id"], row["attempt"]) == jobs
        and api(check_endpoint) == check,
        "original OWNER native tuple changed during policy verification",
    )
    after = destination / f"security-policy-job-{row['job_id']}.after.log"
    source.download_job_log(row["job_id"], after)
    require(
        after.read_bytes() == log_path.read_bytes(),
        "original OWNER direct native log changed during verification",
    )
    return proof


def require_policy_observation(profile, identity, observation, snapshot):
    from saas.scripts.legacy_check_history import latest_check_runs

    expected = [s for s in identity["workflows"] if "trusted_security_policy" in s]
    proofs = getattr(observation, "security_policy_decisions", ())
    declared = [
        r.get("trusted_security_policy_decision")
        for r in observation["workflows"]
        if "trusted_security_policy_decision" in r
    ]
    if not expected:
        require(not proofs and not declared, "unregistered original OWNER policy proof")
        return ()
    require(
        isinstance(observation, SourceCIObservation)
        and len(proofs) == len(expected) == len(declared)
        and all(isinstance(p, SecurityPolicyDecision) for p in proofs)
        and [p.receipt for p in proofs] == declared,
        "source identity requires typed native OWNER policy evidence",
    )
    for spec, proof in zip(expected, proofs, strict=True):
        row = validate_registration(profile, identity, spec)
        require(
            proof.registration == row and proof.receipt["registration_sha256"] == digest(row),
            "original OWNER proof registration differs from current identity",
        )
        checks = [c for c in latest_check_runs(snapshot) if c["id"] == row["check_id"]]
        require(
            len(checks) == 1
            and checks[0].get("name") == "Security Scan"
            and checks[0].get("head_sha") == profile["product_revision"]
            and checks[0].get("app", {}).get("id") == 15368
            and checks[0].get("check_suite", {}).get("id") == row["check_suite_id"]
            and checks[0].get("status") == "completed"
            and checks[0].get("conclusion") == "success",
            "required all-App Security Scan check has no exact successful policy binding",
        )
    return proofs


def refresh_policy_observation(profile, identity, observation, snapshot, destination):
    from saas.scripts import legacy_source_ci as source

    proofs = require_policy_observation(profile, identity, observation, snapshot)
    if not proofs:
        return []
    destination.mkdir(mode=0o700)
    pull = api(f"{ROOT}/pulls/{identity['validation_pr']}")
    commit = api(f"{ROOT}/git/commits/{observation['merge_commit']}")
    for spec, proof in zip(
        [s for s in identity["workflows"] if "trusted_security_policy" in s], proofs, strict=True
    ):
        row = proof.registration
        run = api(f"{ROOT}/actions/runs/{row['run_id']}/attempts/{row['attempt']}")
        jobs = source._job_pages(row["run_id"], row["attempt"])
        log = destination / f"job-{row['job_id']}.log"
        source.download_job_log(row["job_id"], log)
        require(
            collect_policy_decision(
                profile, identity, spec, pull, commit, run, jobs, log, destination
            )
            == proof,
            "original OWNER policy proof changed during source qualification",
        )
    return [p.receipt for p in proofs]
