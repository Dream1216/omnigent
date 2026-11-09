"""Retain exact original PG case sets and separately bind legacy inputs."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from tests.saas.test_legacy_source_qualification import scenario as scenario

ROOT = Path(__file__).resolve().parents[2]
key = "saas.scripts.legacy_pg_contract"
spec = importlib.util.spec_from_file_location(key, ROOT / "saas/scripts/legacy_pg_contract.py")
assert spec and spec.loader
pg = importlib.util.module_from_spec(spec)
sys.modules[key] = pg
spec.loader.exec_module(pg)


def result_xml(major, *, fault=None):
    cases = sorted(pg.expected_cases(major))
    if fault == "missing":
        cases.pop()
    root = ET.Element("testsuites")
    suite = ET.SubElement(
        root,
        "testsuite",
        tests=str(len(cases)),
        failures="1" if fault == "failure" else "0",
        errors="0",
        skipped="1" if fault == "skip" else "0",
    )
    for index, (classname, name) in enumerate(cases):
        case = ET.SubElement(suite, "testcase", classname=classname, name=name)
        if index == 0 and fault in {"skip", "failure"}:
            ET.SubElement(case, "skipped" if fault == "skip" else "failure", message="fault")
    return ET.tostring(root, encoding="utf-8")


@pytest.mark.parametrize("major", [16, 18])
def test_original_PG16_and_PG18_inventories_are_distinct_and_exact(major):
    result = pg.verify_pg_results(
        result_xml(major), major=major, observed_version=str(major * 10000 + 600)
    )
    assert result["tests"] == (4 if major == 16 else 7)
    direct = "test_pg16_runner_direct_authority_is_fail_closed"
    assert any(name == direct for _, name in pg.expected_cases(16))
    assert not any(name == direct for _, name in pg.expected_cases(18))


@pytest.mark.parametrize("fault", ["missing", "skip", "failure", "major"])
def test_PG_result_rejects_missing_skipped_failed_or_wrong_major(fault):
    with pytest.raises(ValueError):
        pg.verify_pg_results(
            result_xml(16, fault=fault),
            major=16,
            observed_version="180006" if fault == "major" else "160014",
        )


@pytest.mark.parametrize(
    "value",
    [
        "postgresql+psycopg://postgres:postgres@prod.example:5432/postgres",
        "postgresql+psycopg://postgres:postgres@localhost:5432/production",
        "postgresql+psycopg://postgres:postgres@localhost:5433/postgres",
        "postgresql+psycopg://other:other@localhost:5432/postgres",
    ],
)
def test_acceptance_URL_cannot_target_external_or_business_database(value):
    with pytest.raises(ValueError):
        pg.verify_disposable_database_url(value)
    pg.verify_disposable_database_url(
        "postgresql+psycopg://postgres:postgres@localhost:5432/postgres"
    )


@pytest.mark.parametrize("scenario", [{"pg_inputs": True}], indirect=True)
@pytest.mark.parametrize("fault", [None, "missing", "hash", "multiple_hashes"])
def test_component_profile_binds_all21_inputs_without_mutating_generic_hash_slots(
    scenario, monkeypatch, fault
):
    control, product = scenario["control"], scenario["product"]
    generic = control / ".github/actions/compat-smoke-saas-n1-gate/evaluate.sh"
    before = generic.read_bytes()
    profile_path = control / "saas/supply_chain/legacy-security-pg-profiles.json"
    if fault:
        store = json.loads(profile_path.read_text())
        inputs = store["profiles"]["Core"]["trusted_inputs"]
        first = next(iter(inputs))
        if fault == "missing":
            inputs.pop(first)
        if fault == "hash":
            inputs[first] = "0" * 64
        if fault == "multiple_hashes":
            inputs[first] += "," + "f" * 64
        profile_path.write_text(json.dumps(store))
        subprocess.run(["git", "add", "."], cwd=control, check=True)
        subprocess.run(
            ["git", "commit", "-qm", "bad declared input fixture"],
            cwd=control,
            check=True,
        )
        revision = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=control, text=True
        ).strip()
        monkeypatch.setenv("GITHUB_SHA", revision)
    else:
        revision = scenario["control_sha"]
    if fault:
        with pytest.raises(ValueError):
            pg.verify_pg_source(control, product, "Core", revision)
    else:
        result = pg.verify_pg_source(control, product, "Core", revision)
        assert (
            result["trusted_input_count"] == 21
            and result["product_revision"] == scenario["profile"]["product_revision"]
        )
    assert generic.read_bytes() == before


def test_default_PG_registry_remains_empty(scenario, monkeypatch):
    control = scenario["control"]
    profile_path = control / "saas/supply_chain/legacy-security-pg-profiles.json"
    profile_path.write_text(json.dumps({"schema_version": 1, "profiles": {}}) + "\n")
    assert json.loads(profile_path.read_text()) == {"schema_version": 1, "profiles": {}}
    subprocess.run(["git", "add", str(profile_path.relative_to(control))], cwd=control, check=True)
    subprocess.run(["git", "commit", "-qm", "empty PG registry fixture"], cwd=control, check=True)
    revision = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=control, text=True
    ).strip()
    monkeypatch.setenv("GITHUB_SHA", revision)
    with pytest.raises(ValueError, match="no complete exact-component PG input profile"):
        pg.verify_pg_source(control, scenario["product"], "Core", revision)


@pytest.mark.parametrize("scenario", [{"pg_inputs": True}], indirect=True)
@pytest.mark.parametrize("fault", [None, "missing", "hash", "multiple_hashes"])
def test_compatibility_PG_profile_reuses_exact_source_and21_path_contract(
    scenario, monkeypatch, fault
):
    control, product = scenario["control"], scenario["product"]
    generic = control / ".github/actions/compat-smoke-saas-n1-gate/evaluate.sh"
    before = generic.read_bytes()
    build_path = control / "saas/supply_chain/legacy-security-build-profiles.json"
    builds = json.loads(build_path.read_text())
    profile = copy.deepcopy(builds["profiles"]["Core"])
    profile["component"] = "Compatibility018"
    builds["profiles"]["Compatibility018"] = profile
    build_path.write_text(json.dumps(builds))
    digest = hashlib.sha256(
        json.dumps(profile, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()
    for function in (pg.load_profile, pg.verify_source_delta):
        monkeypatch.setitem(function.__globals__, "_COMPATIBILITY_PROFILE_SHA256", digest)
    path = control / "saas/supply_chain/legacy-security-pg-profiles.json"
    store = json.loads(path.read_text())
    selected = copy.deepcopy(store["profiles"]["Core"])
    selected["component"] = "Compatibility018"
    inputs = selected["trusted_inputs"]
    first = next(iter(inputs))
    if fault == "missing":
        inputs.pop(first)
    elif fault == "hash":
        inputs[first] = "0" * 64
    elif fault == "multiple_hashes":
        inputs[first] += "," + "f" * 64
    store["profiles"]["Compatibility018"] = selected
    path.write_text(json.dumps(store))
    subprocess.run(["git", "add", "."], cwd=control, check=True)
    subprocess.run(
        ["git", "commit", "-qm", "fixture owns reviewed compatibility PG registration"],
        cwd=control,
        check=True,
    )
    revision = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=control, text=True
    ).strip()
    monkeypatch.setenv("GITHUB_SHA", revision)
    if fault:
        with pytest.raises(ValueError):
            pg.verify_pg_source(control, product, "Compatibility018", revision)
    else:
        result = pg.verify_pg_source(control, product, "Compatibility018", revision)
        assert result["trusted_input_count"] == 21
        assert result["product_revision"] == profile["product_revision"]
    assert generic.read_bytes() == before


def test_registered_compatibility_PG_inputs_preserve_the_generic_path_inventory():
    store = json.loads((ROOT / "saas/supply_chain/legacy-security-pg-profiles.json").read_text())
    profile = store["profiles"]["Compatibility018"]
    assert profile["product_revision"] == "27503d14973b751a2031c6febf12a581b42b06d1"
    assert profile["product_tree"] == "a02ea9f17664bd0290eb5025f864672c0025075c"
    assert set(profile["trusted_inputs"]) == set(pg.trusted_pg_paths(ROOT))
    assert len(profile["trusted_inputs"]) == 21
    assert (
        hashlib.sha256(
            json.dumps(profile, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        == "1db6e44cf7bb4c690ad066cd1849831eaa95e0935f94dd174d083f5902640976"
    )
