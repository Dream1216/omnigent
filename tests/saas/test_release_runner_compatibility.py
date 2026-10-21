"""Keep P0 and R Runner admission contracts separate during an application rollback."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from uuid import uuid4

import pytest

from saas.production import postgresql_migration as migration
from saas.production.runner_control import RunnerControlError
from saas.production.runner_database_fleet import (
    RUNNER_DATABASE_FLEET_NAMESPACE_ENV,
    RunnerDatabaseFleetError,
    validate_runner_database_fleet_projection,
    verify_runner_database_fleet_release_facts,
)
from saas.production.runner_executor import (
    ProductionHostIsolationExecutor,
    _runner_agent_schema_contract,
    _verify_runner_agent_database_authority,
    runner_agent_database_authority_contract_sha256,
)
from tests.saas.test_production_runner_database_fleet import _context, _fleet, _projection

_P0 = "p0s000000015"
_R = "lm2r00000001"
_S = "lm2s00000001"
_T = "lm2t00000001"


def test_p0_runner_contract_retains_its_original_bytes() -> None:
    assert runner_agent_database_authority_contract_sha256() == (
        "0b33c0098f024b515a5f2860a24ceec077b597e04d573ac9bd69edcc9db2a07a"
    )


@pytest.mark.parametrize("head", [_R, _S, _T])
def test_r_runner_contract_pins_the_complete_new_function_set_and_digest(head) -> None:
    p0, old_functions, old_hashes = _runner_agent_schema_contract(_P0)
    r, new_functions, new_hashes = _runner_agent_schema_contract(head)
    assert (p0, r) == (_P0, head)
    assert set(new_functions) - set(old_functions) == {
        ("saas_interactive_recovery_owner_v1", "uuid, bigint, uuid, bigint, jsonb")
    }
    assert set(old_functions) < set(new_functions)
    assert old_hashes == dict.fromkeys(
        (16, 18), "43423586ac39ca5a08a415b36f37e93d7409deb5f03050238b0b876c4d33ca02"
    )
    assert new_hashes == dict.fromkeys(
        (16, 18), "7e5d534b22159804cc21f23893a2ba462a0af8674a3f535c58c83a3efd8cde67"
    )
    assert runner_agent_database_authority_contract_sha256(
        control_plane_schema_revision=head
    ) != runner_agent_database_authority_contract_sha256(control_plane_schema_revision=_P0)


@pytest.mark.parametrize("revision", ["lm2q00000001", "future", ""])
def test_runner_unknown_schema_is_rejected_before_a_database_connection(revision: str) -> None:
    with pytest.raises(RunnerControlError, match="schema"):
        _verify_runner_agent_database_authority(
            None,  # type: ignore[arg-type]
            runner_id=uuid4(),
            connection_generation=1,
            control_plane_schema_revision=revision,
        )


@pytest.mark.parametrize("installed", [_R, _S, _T])
def test_r_packaged_application_cannot_borrow_the_p0_contract(monkeypatch, installed) -> None:
    monkeypatch.setattr(migration, "_expected_head", lambda _kind: installed)
    assert _runner_agent_schema_contract(None)[0] == installed
    with pytest.raises(RunnerControlError, match="schema"):
        runner_agent_database_authority_contract_sha256(control_plane_schema_revision=_P0)


def test_fleet_projection_must_equal_the_explicit_release_schema() -> None:
    old = _projection()
    new = replace(old, schema_revision=_R)
    with pytest.raises(RunnerDatabaseFleetError, match="schema revision"):
        validate_runner_database_fleet_projection(
            fleet=_fleet(), context=_context(), projection=new
        )
    old_digest = validate_runner_database_fleet_projection(
        fleet=_fleet(), context=_context(), projection=old
    )
    new_digest = validate_runner_database_fleet_projection(
        fleet=_fleet(), context=_context(), projection=new, control_plane_schema_revision=_R
    )
    # The role graph is unchanged; the composed runtime contract binds the schema.
    assert old_digest == new_digest
    with pytest.raises(RunnerDatabaseFleetError, match="schema revision"):
        validate_runner_database_fleet_projection(
            fleet=_fleet(), context=_context(), projection=old, control_plane_schema_revision=_R
        )


@pytest.mark.parametrize("revision", [_P0, _R, _S, _T])
def test_fleet_release_facts_keep_official_and_control_plane_heads_distinct(revision) -> None:
    context = _context()
    source = {
        "OMNIGENT_SAAS_PRODUCT_REVISION": context.product_revision,
        "OMNIGENT_SAAS_SOURCE_SHA": context.product_revision,
        "OMNIGENT_SAAS_IMAGE_DIGEST": context.image_digest,
        "OMNIGENT_SAAS_RELEASE_INCARNATION": context.release_incarnation,
        "OMNIGENT_SAAS_OFFICIAL_SCHEMA_REVISION": context.schema_revision,
        "OMNIGENT_SAAS_CONTROL_PLANE_SCHEMA_REVISION": revision,
        RUNNER_DATABASE_FLEET_NAMESPACE_ENV: context.namespace,
    }
    assert verify_runner_database_fleet_release_facts(source, context) == revision
    source.pop("OMNIGENT_SAAS_CONTROL_PLANE_SCHEMA_REVISION")
    with pytest.raises(RunnerDatabaseFleetError, match="schema revision"):
        verify_runner_database_fleet_release_facts(source, context)


def test_legacy_host_rejects_interactive_work_before_loading_or_allocating(monkeypatch) -> None:
    executor = ProductionHostIsolationExecutor.__new__(ProductionHostIsolationExecutor)

    def unexpected_load(_lease):
        pytest.fail("legacy Host must not load or allocate an interactive Run")

    monkeypatch.setattr(executor, "_load_run", unexpected_load)
    lease = SimpleNamespace(
        execution_envelope=SimpleNamespace(execution_kind="omnigent.interactive.v1")
    )
    with pytest.raises(RunnerControlError) as rejected:
        executor._allocate_execution(lease)  # type: ignore[arg-type]
    assert rejected.value.code == "runner_execution_kind_unsupported"
