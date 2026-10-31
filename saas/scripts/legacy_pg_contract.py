"""Verify component-specific exact-source PG16 and PG18 contracts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

from saas.scripts.legacy_build_controller import control_context
from saas.scripts.legacy_pytest_results import inspect_junit
from saas.scripts.oci_promotion import require
from saas.scripts.protected_legacy_initial_build import (
    BASELINES,
    load_profile,
    verify_source_delta,
)

PG_IMAGES = {
    16: (
        "postgres:16.14-bookworm@sha256:"
        "64154d0babcb1741988719e703419af0382b19953706149f9872fbd0f438efa8"
    ),
    18: (
        "postgres:18.6-trixie@sha256:"
        "4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280"
    ),
}
COMMON_SELECTORS = (
    "tests/saas/test_control_plane_migration.py::"
    "test_real_postgresql_pinned_n1_outbox_compatibility_bridge",
    "tests/saas/test_n1_outbox_admission.py::"
    "test_real_postgresql_n1_compat_login_admission_and_roles_replay",
)
PG16_SELECTORS = (
    *COMMON_SELECTORS,
    "tests/saas/test_n1_outbox_admission.py::"
    "test_real_postgresql_roles_allow_exact_rollback_schema_and_reject_newer_marker_drift"
    "[p0s000000004]",
    "tests/saas/test_production_runner_postgresql.py::"
    "test_pg16_runner_direct_authority_is_fail_closed",
)
PG18_SELECTORS = ("tests/saas/test_n1_compat_patch.py", *COMMON_SELECTORS)
PATCH_CASE_NAMES = (
    "test_n1_compat_builder_applies_only_the_pinned_security_patch",
    "test_n1_compat_image_workflow_is_fixed_signed_and_production_blocked",
    "test_n1_compat_builder_materializes_deterministic_git_free_source",
    "test_n1_compat_hides_provider_db_and_dsn_secrets",
    "test_n1_compat_launcher_modules_ship_and_load_from_isolated_wheel",
)


def trusted_pg_paths(control: Path) -> tuple[str, ...]:
    """Read only path identities; never widen the generic Root hash slots."""
    policy = (control / ".github/actions/compat-smoke-saas-n1-gate/evaluate.sh").read_text()
    match = re.search(r"POSTGRESQL_N1_TRUSTED_INPUTS=\(\n(.*?)\n\)", policy, re.S)
    require(match is not None, "generic PG trusted-input path inventory missing")
    match = cast(re.Match[str], match)
    paths = []
    for line in match.group(1).splitlines():
        parsed = re.fullmatch(r'\s*"([^"|]+)\|[0-9a-f]{64}(?:,[0-9a-f]{64})?"\s*', line)
        require(parsed is not None, "generic PG trusted-input declaration is malformed")
        parsed = cast(re.Match[str], parsed)
        paths.append(parsed.group(1))
    require(len(paths) == len(set(paths)) == 21, "generic PG path inventory changed")
    return tuple(sorted(paths))


def verify_pg_source(
    control: Path, product: Path, component: str, control_revision: str
) -> dict[str, Any]:
    return _verify_pg_source(
        control, product, component, control_revision, context_verifier=control_context
    )


def _verify_pg_source(
    control: Path, product: Path, component: str, control_revision: str, *, context_verifier
) -> dict[str, Any]:
    context_verifier(control, control_revision)
    profile = load_profile(control, component)
    verify_source_delta(product, profile)
    path = control / "saas/supply_chain/legacy-security-pg-profiles.json"
    require(
        path.is_file() and not path.is_symlink(),
        "missing reviewed component PG profiles",
    )
    store = json.loads(path.read_text())
    require(
        set(store) == {"schema_version", "profiles"}
        and type(store["schema_version"]) is int
        and store["schema_version"] == 1
        and isinstance(store["profiles"], dict),
        "component PG profile store differs",
    )
    selected = store["profiles"].get(component)
    require(
        isinstance(selected, dict)
        and set(selected) == {"component", "product_revision", "product_tree", "trusted_inputs"}
        and all(
            selected[key] == profile[key]
            for key in ("component", "product_revision", "product_tree")
        )
        and isinstance(selected["trusted_inputs"], dict)
        and set(selected["trusted_inputs"]) == set(trusted_pg_paths(control)),
        "no complete exact-component PG input profile",
    )
    for source, expected in selected["trusted_inputs"].items():
        require(
            isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{64}", expected) is not None,
            "component PG input must bind exactly one SHA256",
        )
        body = subprocess.check_output(
            ["git", "cat-file", "blob", profile["product_revision"] + ":" + source],
            cwd=product,
        )
        require(
            hashlib.sha256(body).hexdigest() == expected,
            "exact-component PG input bytes differ",
        )
    return {
        "component": component,
        "product_revision": profile["product_revision"],
        "product_tree": profile["product_tree"],
        "control_revision": control_revision,
        "trusted_input_count": 21,
        "trusted_inputs_sha256": hashlib.sha256(
            json.dumps(selected["trusted_inputs"], sort_keys=True).encode()
        ).hexdigest(),
    }


def verify_disposable_database_url(value: str) -> None:
    parsed = urlsplit(value)
    require(
        parsed.scheme == "postgresql+psycopg"
        and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        and parsed.username == "postgres"
        and parsed.password == "postgres"
        and parsed.path == "/postgres"
        and parsed.port == 5432
        and not parsed.query
        and not parsed.fragment,
        "PG acceptance is restricted to the disposable native service",
    )


def expected_cases(major: int) -> set[tuple[str, str]]:
    require(major in PG_IMAGES, "unsupported PG acceptance major")
    cases: set[tuple[str, str]] = set()
    for selector in PG16_SELECTORS if major == 16 else COMMON_SELECTORS:
        path, name = selector.split("::", 1)
        cases.add((path.removesuffix(".py").replace("/", "."), name))
    if major == 18:
        cases.update(("tests.saas.test_n1_compat_patch", name) for name in PATCH_CASE_NAMES)
    return cases


def verify_pg_results(xml: bytes, *, major: int, observed_version: str) -> dict[str, Any]:
    require(
        isinstance(observed_version, str)
        and re.fullmatch(r"[0-9]+", observed_version.strip()) is not None
        and int(observed_version.strip()) // 10000 == major,
        "observed native PostgreSQL major differs",
    )
    results = inspect_junit(xml)
    observed = {(row["classname"], row["name"]) for row in results["cases"]}
    require(
        observed == expected_cases(major)
        and results["reported_tests"] == len(observed)
        and results["extra_reported_tests"] == 0
        and results["failed_cases"] == results["skipped_cases"] == 0
        and all(row["outcome"] == "passed" for row in results["cases"]),
        "exact original PG case inventory/outcomes differ",
    )
    return {
        "postgresql_major": major,
        "observed_server_version_num": int(observed_version.strip()),
        "service_image": PG_IMAGES[major],
        "tests": len(observed),
        "failures": 0,
        "errors": 0,
        "skipped": 0,
        "XML_sha256": hashlib.sha256(xml).hexdigest(),
        "scope": (
            "One local native-service test result; native run/j"
            "ob/control/product bindings and independent PG adm"
            "ission still required."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("verify-source", "verify-results"))
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--product", type=Path, required=True)
    parser.add_argument("--component", choices=tuple(BASELINES), required=True)
    parser.add_argument("--control-revision", required=True)
    parser.add_argument("--major", type=int, choices=(16, 18), required=True)
    parser.add_argument("--xml", type=Path)
    parser.add_argument("--version-file", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    verify_disposable_database_url(os.environ.get("OMNIGENT_SAAS_TEST_POSTGRES_URL", ""))
    result = verify_pg_source(args.control, args.product, args.component, args.control_revision)
    result["postgresql_major"] = args.major
    result["service_image"] = PG_IMAGES[args.major]
    if args.command == "verify-results":
        require(
            args.xml is not None and args.version_file is not None,
            "PG native result and version capture required",
        )
        result["result"] = verify_pg_results(
            args.xml.read_bytes(),
            major=args.major,
            observed_version=args.version_file.read_text(),
        )
    result["production_admission"] = False
    with args.output.open("x") as output:
        output.write(json.dumps(result, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
