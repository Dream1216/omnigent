"""Discover native main-domain evidence without granting source-CI admission.

This reader is deliberately separate from the source qualifier. Even a complete
discovery receipt cannot enable the frozen-legacy domain rule or waive a check.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlencode

from saas.scripts import legacy_check_history as history
from saas.scripts import legacy_domain_native as domain
from saas.scripts import legacy_domain_non_execution as nonexecution
from saas.scripts.legacy_build_controller import control_context
from saas.scripts.legacy_native_evidence import api, preserve_native_evidence
from saas.scripts.legacy_source_ci import (
    _instant,
    _job_pages,
    _load_contract,
    checkout_commit,
    download_job_log,
)
from saas.scripts.oci_promotion import require
from saas.scripts.protected_legacy_initial_build import (
    BASELINES,
    REPOSITORY,
    load_profile,
    verify_pr_tree,
    verify_source_delta,
)

_SHA = domain._SHA
_STAMP = domain._STAMP
_EVENTS = domain._EVENTS
_ROOT = domain._ROOT
_REPO_URL = domain._REPO_URL
_pr_numbers = domain._pr_numbers
trigger_environment = domain.trigger_environment
trigger_identity = domain.trigger_identity


def load_qualification_policy(control: Path, profile: dict[str, Any]) -> dict[str, Any]:
    # CLI-only dependency; the discovery reader is also used by the qualifier.
    from saas.scripts.legacy_source_qualification import load_qualification_policy as load

    return load(control, profile)


def _run_shape(run: dict[str, Any], event: str, created: datetime) -> None:
    require(
        type(run.get("id")) is int
        and run["id"] > 0
        and type(run.get("run_attempt")) is int
        and 0 < run["run_attempt"] <= 10
        and type(run.get("workflow_id")) is int
        and run["workflow_id"] > 0
        and type(run.get("check_suite_id")) is int
        and run["check_suite_id"] > 0
        and run.get("path") == domain.MAIN_WORKFLOW
        and run.get("name") == "SaaS N-1 merge gate"
        and run.get("event") == event
        and run.get("repository", {}).get("full_name") == REPOSITORY
        and run.get("head_repository", {}).get("full_name") == REPOSITORY
        and isinstance(run.get("head_sha"), str)
        and _SHA.fullmatch(run["head_sha"]) is not None
        and _instant(run.get("created_at")) >= created,
        "native domain run identity, creation time or repository differs",
    )
    _pr_numbers(run.get("pull_requests"))


def _discovery_projection(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    fields = (
        "id",
        "run_attempt",
        "path",
        "event",
        "head_sha",
        "workflow_id",
        "check_suite_id",
        "created_at",
    )
    return sorted(
        [
            {
                **{field: row.get(field) for field in fields},
                "repository": row.get("repository", {}).get("full_name"),
                "head_repository": row.get("head_repository", {}).get("full_name"),
                "native_PR_numbers": sorted(_pr_numbers(row.get("pull_requests", []))),
            }
            for row in rows
        ],
        key=lambda row: row["id"],
    )


def _list_event(event: str, created: datetime, now: datetime) -> list[dict[str, Any]]:
    """Partition the API's 1000-result search cap with disjoint UTC seconds."""
    endpoint = f"{_ROOT}/actions/workflows/{Path(domain.MAIN_WORKFLOW).name}/runs"

    def query(window: str) -> str:
        return endpoint + "?" + urlencode({"event": event, "created": window})

    def count(window: str) -> dict[str, Any]:
        payload = api(query(window) + "&per_page=100&page=1")
        require(
            isinstance(payload, dict)
            and type(payload.get("total_count")) is int
            and 0 <= payload["total_count"] <= 10000,
            "domain native discovery total exceeds bound",
        )
        require(
            isinstance(payload.get("workflow_runs"), list)
            and len(payload["workflow_runs"]) <= 100
            and all(
                isinstance(row, dict) and type(row.get("id")) is int and row["id"] > 0
                for row in payload["workflow_runs"]
            ),
            "domain native first page is malformed",
        )
        return payload

    def stamp(value: datetime) -> str:
        return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")

    lower = created.astimezone(UTC).replace(microsecond=0)
    upper = now.astimezone(UTC).replace(microsecond=0)
    require(lower <= upper, "domain PR creation time is in the future")
    window = ">=" + stamp(lower)
    first = count(window)
    if first["total_count"] <= 1000:
        rows = history._pages(query(window), "workflow_runs")
    else:

        def partition(start: datetime, finish: datetime, depth: int) -> list[dict[str, Any]]:
            require(depth <= 32, "domain discovery partition bound exceeded")
            interval = stamp(start) + ".." + stamp(finish)
            payload = count(interval)
            if payload["total_count"] <= 1000:
                return history._pages(query(interval), "workflow_runs")
            require(start < finish, "more than 1000 domain runs share one native second")
            middle = start + timedelta(seconds=int((finish - start).total_seconds()) // 2)
            return partition(start, middle, depth + 1) + partition(
                middle + timedelta(seconds=1), finish, depth + 1
            )

        rows = partition(lower, upper, 0)
    final = count(window)
    require(
        first["total_count"] == final["total_count"] == len(rows)
        and _discovery_projection(first["workflow_runs"])
        == _discovery_projection(final["workflow_runs"]),
        "domain native discovery changed or is incomplete",
    )
    require(len({row["id"] for row in rows}) == len(rows), "domain discovery repeats run IDs")
    require(
        {row["id"] for row in first.get("workflow_runs", [])} <= {row["id"] for row in rows},
        "domain partition omitted native first-page runs",
    )
    for row in rows:
        _run_shape(row, event, created)
        require(_instant(row["created_at"]) <= now, "domain discovery contains a future run")
    return rows


def discover_runs(created: datetime) -> list[dict[str, Any]]:
    now = datetime.now(UTC)
    rows = [row for event in _EVENTS for row in _list_event(event, created, now)]
    require(
        len(rows) <= 10000 and len({row["id"] for row in rows}) == len(rows),
        "domain event discovery is duplicated or exceeds bound",
    )
    return sorted(rows, key=lambda row: row["id"])


def _coordinates(
    run: dict[str, Any], job: dict[str, Any], check: dict[str, Any]
) -> dict[str, int]:
    require(
        type(job.get("id")) is int
        and job["id"] > 0
        and job.get("run_id") == run["id"]
        and job.get("run_attempt") == run["run_attempt"]
        and job.get("head_sha") == run["head_sha"]
        and job.get("name") == "evaluate"
        and job.get("status") == check.get("status") == "completed"
        and job.get("conclusion") == check.get("conclusion")
        and job.get("conclusion") in {"success", "failure"}
        and job.get("runner_group_name") == "GitHub Actions"
        and job.get("labels") == ["ubuntu-latest"]
        and type(check.get("id")) is int
        and check["id"] > 0
        and job.get("check_run_url") == f"{_REPO_URL}/check-runs/{check['id']}"
        and check.get("name") == "evaluate"
        and check.get("head_sha") == run["head_sha"]
        and check.get("app", {}).get("id") == history.GITHUB_ACTIONS_APP_ID
        and check.get("check_suite", {}).get("id") == run["check_suite_id"],
        "domain native job/check/attachment/attempt/provider or execution differs",
    )
    return {
        "run_id": run["id"],
        "attempt": run["run_attempt"],
        "job_id": job["id"],
        "check_id": check["id"],
    }


def _one_step(job: dict[str, Any], name: str) -> dict[str, Any]:
    rows = [row for row in job.get("steps", []) if row.get("name") == name]
    require(len(rows) == 1, "domain executed step is missing or ambiguous")
    return rows[0]


def _inspect_run(
    run: dict[str, Any],
    profile: dict[str, Any],
    number: int,
    destination: Path,
    record: dict[str, Any],
    identity=None,
    non_execution_rules=(),
    observations=None,
    infrastructure_cancellation_rules=(),
) -> dict[str, Any]:
    numbers = _pr_numbers(run["pull_requests"])
    # PR numbers are stable associations; their mutable head SHA is never a source proof.
    if numbers and number not in numbers:
        return {
            **record,
            "classification": "other-pr",
            "native_PR_numbers": numbers,
            "association_basis": "native-PR-number",
            "technical_gate_waiver": False,
        }
    require(
        hashlib.sha256(domain._native_file(domain.MAIN_WORKFLOW, run["head_sha"])).hexdigest()
        == domain.MAIN_WORKFLOW_SHA256,
        "domain workflow bytes are not the reviewed original",
    )
    latest = api(f"{_ROOT}/actions/runs/{run['id']}")
    require(latest == run, "listed domain run differs from native latest run")
    for attempt in range(1, run["run_attempt"] + 1):
        observed = api(f"{_ROOT}/actions/runs/{run['id']}/attempts/{attempt}")
        _run_shape(observed, run["event"], _instant(run["created_at"]))
        require(
            observed["id"] == run["id"]
            and observed["run_attempt"] == attempt
            and all(
                observed[key] == run[key]
                for key in ("head_sha", "created_at", "workflow_id", "check_suite_id")
            )
            and observed.get("status") == "completed",
            "domain attempt identity or completion differs",
        )
        audit_rules = (*non_execution_rules, *infrastructure_cancellation_rules)
        if observed.get("conclusion") in {"cancelled", "skipped"} and audit_rules:
            rules = [
                row
                for row in audit_rules
                if (row["run_id"], row["attempt"]) == (run["id"], attempt)
            ]
            require(len(rules) == 1, "zero-execution attempt lacks one exact registration")
            if attempt == run["run_attempt"]:
                require(
                    domain._latest_matches_attempt(latest, observed),
                    "domain latest zero-execution attempt differs",
                )
            jobs = _job_pages(run["id"], attempt)
            proof = nonexecution.collect_observation(
                profile, identity, rules[0], observed, jobs, destination
            )
            cast(
                list[
                    nonexecution.ZeroExecutionObservation
                    | nonexecution.InfrastructureCancellationObservation
                ],
                observations,
            ).append(proof)
            field = (
                "non_execution_observations"
                if isinstance(proof, nonexecution.ZeroExecutionObservation)
                else "infrastructure_cancellation_observations"
            )
            record.setdefault(field, []).append(proof.receipt)
            continue
        require(
            observed.get("conclusion") in {"success", "failure"},
            "cancelled, skipped or incomplete domain attempts have no execution exemption",
        )
        if attempt == run["run_attempt"]:
            require(
                domain._latest_matches_attempt(latest, observed), "domain latest attempt differs"
            )
        jobs = _job_pages(run["id"], attempt)
        require(
            len(jobs) == 1 and jobs[0].get("name") == "evaluate", "domain native job set differs"
        )
        job = jobs[0]
        match = re.fullmatch(
            re.escape(_REPO_URL) + r"/check-runs/([1-9][0-9]*)", job.get("check_run_url", "")
        )
        require(match is not None, "domain check URL is not native")
        match = cast(re.Match[str], match)
        check = api(f"{_ROOT}/check-runs/{match[1]}")
        coordinate = _coordinates(observed, job, check)
        path = destination / f"run-{run['id']}-attempt-{attempt}-job-{job['id']}.log"
        download_job_log(job["id"], path)
        raw_log = path.read_bytes()
        log = raw_log.decode("utf-8")
        checkout = _one_step(job, "Check out trusted gate")
        resolve = _one_step(job, "Resolve current PR head")
        require(
            type(checkout.get("number")) is int
            and type(resolve.get("number")) is int
            and (checkout["number"], resolve["number"]) == (2, 3)
            and _instant(checkout.get("completed_at")) <= _instant(resolve.get("started_at")),
            "domain checkout and trigger step order differs",
        )
        control = checkout_commit(log, checkout)
        environment = trigger_environment(log, resolve)
        original_pr, source = trigger_identity(environment, run["event"])
        require(
            not numbers or original_pr in numbers,
            "native PR association contradicts original trigger",
        )
        classification = (
            "other-pr"
            if original_pr != number
            else "related"
            if source == profile["product_revision"]
            else "old-source"
        )
        record["attempts"].append(
            {
                **coordinate,
                "classification": classification,
                "original_PR": original_pr,
                "original_event_source_revision": source,
                "attachment_revision": observed["head_sha"],
                "trusted_checkout_revision": control,
                "trusted_gate_sha256": hashlib.sha256(
                    domain._native_file(domain._GATE, control)
                ).hexdigest(),
                "original_run_conclusion": observed.get("conclusion"),
                "original_job_conclusion": job.get("conclusion"),
                "run_sha256": domain.native_digest(observed),
                "job_sha256": domain.native_digest(job),
                "check_sha256": domain.native_digest(check),
                "job_log_sha256": hashlib.sha256(raw_log).hexdigest(),
                "technical_gate_waiver": False,
            }
        )
        require(
            api(f"{_ROOT}/actions/runs/{run['id']}/attempts/{attempt}") == observed
            and _job_pages(run["id"], attempt) == jobs
            and api(f"{_ROOT}/check-runs/{match[1]}") == check,
            "domain native attempt/job/check changed during discovery",
        )
    kinds = {row["classification"] for row in record["attempts"]}
    origins = {
        (row["original_PR"], row["original_event_source_revision"]) for row in record["attempts"]
    }
    if not record["attempts"] and record.get("infrastructure_cancellation_observations"):
        require(
            not record.get("non_execution_observations"), "domain audit execution kinds differ"
        )
        record["classification"] = "audited-infrastructure-cancellation"
    elif not record["attempts"] and record.get("non_execution_observations"):
        record["classification"] = "audited-nonexecution"
    else:
        require(len(kinds) == len(origins) == 1, "domain rerun original sources or PRs differ")
        record["classification"] = kinds.pop()
    require(
        api(f"{_ROOT}/actions/runs/{run['id']}") == latest,
        "domain latest run changed during discovery",
    )
    return record


def _key(row: dict[str, Any]) -> tuple[int, ...]:
    keys = ("run_id", "attempt", "job_id", "check_id")
    require(
        isinstance(row, dict) and all(type(row.get(key)) is int and row[key] > 0 for key in keys),
        "domain registration coordinate is malformed",
    )
    return tuple(row[key] for key in keys)


def _refresh_attempt(row: dict[str, Any], destination: Path) -> None:
    prefix = f"{_ROOT}/actions/runs/{row['run_id']}/attempts/{row['attempt']}"
    require(
        domain.native_digest(api(prefix)) == row["run_sha256"],
        "domain native attempt changed after complete enumeration",
    )
    jobs = _job_pages(row["run_id"], row["attempt"])
    require(
        len(jobs) == 1 and domain.native_digest(jobs[0]) == row["job_sha256"],
        "domain native job set changed after complete enumeration",
    )
    require(
        domain.native_digest(api(f"{_ROOT}/check-runs/{row['check_id']}")) == row["check_sha256"],
        "domain native check changed after complete enumeration",
    )
    path = (
        destination / f"run-{row['run_id']}-attempt-{row['attempt']}-job-{row['job_id']}.after.log"
    )
    download_job_log(row["job_id"], path)
    require(
        hashlib.sha256(path.read_bytes()).hexdigest() == row["job_log_sha256"],
        "domain native job log changed after complete enumeration",
    )


def discover_main_domain(
    profile: dict[str, Any],
    identity: dict[str, Any],
    rules: list[dict[str, Any]],
    destination: Path,
    non_execution_rules=None,
    infrastructure_cancellation_rules=None,
) -> dict[str, Any]:
    """Collect evidence only; complete means enumeration, never gate eligibility."""
    number = identity["validation_pr"]
    require(type(number) is int and number > 0, "domain validation PR is missing")
    pull = api(f"{_ROOT}/pulls/{number}")
    commit = api(f"{_ROOT}/git/commits/{pull.get('merge_commit_sha')}")
    verify_pr_tree(pull, commit, profile, number=number, base_ref=identity["validation_base_ref"])
    created = _instant(pull.get("created_at"))
    non_execution_rules = non_execution_rules or []
    nonexecution.validate_rules(non_execution_rules, profile, identity)
    infrastructure_cancellation_rules = infrastructure_cancellation_rules or []
    nonexecution.validate_infrastructure_rules(
        infrastructure_cancellation_rules, profile, identity
    )
    audit_rules = [*non_execution_rules, *infrastructure_cancellation_rules]
    registered_audits = {_key(row) for row in audit_rules}
    require(len(registered_audits) == len(audit_rules), "domain audit coordinate kinds overlap")
    observations = []
    registered = [_key(row) for row in rules]
    require(len(registered) == len(set(registered)), "domain registration is duplicated")
    before = discover_runs(created)
    records, blockers = [], []
    for run in before:
        record: dict[str, Any] = {
            "run_id": run["id"],
            "attachment_revision": run["head_sha"],
            "original_run_status": run.get("status"),
            "original_run_conclusion": run.get("conclusion"),
            "native_listing_sha256": domain.native_digest(run),
            "technical_gate_waiver": False,
            "attempts": [],
        }
        try:
            record = _inspect_run(
                run,
                profile,
                number,
                destination,
                record,
                identity,
                non_execution_rules,
                observations,
                infrastructure_cancellation_rules,
            )
        except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as error:
            record.update(classification="unassignable", reason=str(error))
            blockers.append({"run_id": run["id"], "reason": str(error)})
        records.append(record)
    for record in records:
        for row in record["attempts"]:
            try:
                _refresh_attempt(row, destination)
            except (
                ValueError,
                KeyError,
                TypeError,
                OSError,
                subprocess.CalledProcessError,
            ) as error:
                blockers.append(
                    {"run_id": row["run_id"], "attempt": row["attempt"], "reason": str(error)}
                )
    expected_audits = {_key(row): row for row in audit_rules}
    observed_audits = {_key(proof.receipt) for proof in observations}
    if observed_audits != registered_audits or len(observed_audits) != len(observations):
        blockers.append(
            {"reason": "native zero-execution and registered coordinates are not equal"}
        )
    for index, proof in enumerate(observations):
        row = proof.receipt
        try:
            run = api(f"{_ROOT}/actions/runs/{row['run_id']}/attempts/{row['attempt']}")
            jobs = _job_pages(row["run_id"], row["attempt"])
            refresh = destination / f"zero-refresh-{index}"
            refresh.mkdir(mode=0o700)
            require(
                nonexecution.collect_observation(
                    profile, identity, expected_audits[_key(row)], run, jobs, refresh
                )
                == proof,
                "native zero-execution proof changed after full enumeration",
            )
        except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as error:
            blockers.append(
                {"run_id": row["run_id"], "attempt": row["attempt"], "reason": str(error)}
            )
    after = discover_runs(created)
    # Other PR outcomes are observations, not gates on this product. The related
    # native attempt/job/check/log bytes were independently refreshed above.
    stable = _discovery_projection(before) == _discovery_projection(after)
    if not stable:
        blockers.append({"reason": "native workflow discovery sets changed"})
    final_pull = api(f"{_ROOT}/pulls/{number}")
    if final_pull != pull:
        blockers.append({"reason": "native PR changed during domain discovery"})
    related = [
        attempt
        for row in records
        for attempt in row["attempts"]
        if attempt["classification"] == "related"
    ]
    observed = {_key(row) for row in related}
    missing, orphaned = sorted(observed - set(registered)), sorted(set(registered) - observed)
    if missing or orphaned:
        blockers.append({"reason": "related native and registered coordinates are not equal"})
    require(len(observed) == len(related), "related native coordinates are duplicated")
    expected = {_key(row): row for row in rules}
    stale = []
    for row in related:
        rule = expected.get(_key(row))
        fields = (
            "run_sha256",
            "job_sha256",
            "check_sha256",
            "job_log_sha256",
            "trusted_checkout_revision",
            "trusted_gate_sha256",
        )
        if rule is not None and any(rule.get(field) != row[field] for field in fields):
            stale.append(_key(row))
    if stale:
        blockers.append(
            {"reason": "registered native proof bytes differ from discovered evidence"}
        )
    result = {
        "kind": "legacy_main_domain_discovery/v1",
        "scope": "evidence-only",
        "status": "incomplete-closed" if blockers else "complete-evidence-only",
        "complete_discovery": not blockers,
        "stable_discovery_sets": stable,
        "stability_scope": (
            "native run/attempt/workflow/attachment/PR-number identities; "
            "related proof bytes refreshed"
        ),
        "source_ci_pass": False,
        "admission_enabled": False,
        "production_admission": False,
        "domain_eligibility": False,
        "technical_gate_waiver": False,
        "validation_PR": number,
        "PR_created_at": pull["created_at"],
        "product_revision": profile["product_revision"],
        "product_tree": profile["product_tree"],
        "workflow": domain.MAIN_WORKFLOW,
        "events": list(_EVENTS),
        "discovery_before_sha256": domain.native_digest(before),
        "discovery_after_sha256": domain.native_digest(after),
        "native_identity_sha256": domain.native_digest(_discovery_projection(after)),
        "discovered_run_ids": [row["id"] for row in before],
        "records": records,
        "non_execution_observations": [
            proof.receipt
            for proof in observations
            if isinstance(proof, nonexecution.ZeroExecutionObservation)
        ],
        "infrastructure_cancellation_observations": [
            proof.receipt
            for proof in observations
            if isinstance(proof, nonexecution.InfrastructureCancellationObservation)
        ],
        "unregistered_related_coordinates": missing,
        "orphaned_registered_coordinates": orphaned,
        "changed_registered_proof_coordinates": stale,
        "blockers": blockers,
    }
    result = nonexecution.DomainDiscovery(result, observations)
    (destination / "domain-discovery.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--product", type=Path, required=True)
    parser.add_argument("--component", choices=tuple(BASELINES), required=True)
    parser.add_argument("--control-revision", required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    args.destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    with preserve_native_evidence(
        args.destination / "native-api", evidence_root=args.destination
    ) as evidence:
        control_context(args.control, args.control_revision)
        profile = load_profile(args.control, args.component)
        verify_source_delta(args.product, profile)
        identity = _load_contract(args.control, profile)
        policy = load_qualification_policy(args.control, profile)
        evidence.stage = "native-domain-discovery-no-admission"
        try:
            result = discover_main_domain(
                profile,
                identity,
                policy["domain_not_applicable"].get(domain.MAIN_WORKFLOW, []),
                args.destination,
                policy.get("domain_non_execution", {}).get(domain.MAIN_WORKFLOW, []),
                policy.get("domain_infrastructure_cancellation", {}).get(domain.MAIN_WORKFLOW, []),
            )
        except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as error:
            evidence.stage = "incomplete-closed"
            result = {
                "kind": "legacy_main_domain_discovery/v1",
                "scope": "evidence-only",
                "status": "incomplete-closed",
                "complete_discovery": False,
                "source_ci_pass": False,
                "admission_enabled": False,
                "domain_eligibility": False,
                "production_admission": False,
                "technical_gate_waiver": False,
                "blockers": [{"reason": str(error), "exception_type": type(error).__name__}],
            }
            (args.destination / "domain-discovery.json").write_text(
                json.dumps(result, indent=2) + "\n"
            )
        verify_source_delta(args.product, profile)
        print(json.dumps(result, sort_keys=True))
    # Discovery is not a source qualifier, including when its enumeration is complete.
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
