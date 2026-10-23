"""Private no-launch facts are not model credentials or physical Agent acceptance."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import timedelta
from uuid import uuid4

import pytest

from saas.production.interactive_recovery import (
    InteractiveRecoveryError,
    InteractiveRecoveryJournal,
    UnstartedInteractiveRecoveryRecord,
    physical_recovery_proof_sha256,
)


def _fact():
    return UnstartedInteractiveRecoveryRecord(
        run_id=uuid4(),
        runner_id=uuid4(),
        fence_token=1,
        connection_generation=1,
        product_revision="c" * 40,
        image_digest="sha256:" + "a" * 64,
        capability_token="x" * 43,
        certificate_sha256="b" * 64,
    )


def test_owner_only_unstarted_fact_survives_restart_without_a_runtime_or_runner(tmp_path):
    directory, fact = tmp_path / "private", _fact()
    journal = InteractiveRecoveryJournal(directory)
    try:
        assert journal.retain_unstarted(fact)
        assert journal.records() == [] and journal.unstarted_records() == [fact]
        with pytest.raises(InteractiveRecoveryError):
            journal.read(fact.run_id)
        stored = directory / f"{fact.run_id}.json"
        assert stored.stat().st_mode & 0o777 == 0o600
        assert directory.stat().st_mode & 0o777 == 0o700
        document = json.loads(stored.read_text())
        assert document["schema_version"] == 2 and document["record_type"] == "unstarted"
        assert {"runtime", "grant", "official_runner_id", "host_id"}.isdisjoint(document["record"])
        assert fact.capability_token not in repr(fact)
        proof = physical_recovery_proof_sha256(fact)
        assert len(proof) == 64
    finally:
        journal.close()
    restored = InteractiveRecoveryJournal(directory)
    try:
        found = restored.read_unstarted(fact.run_id)
        assert found == fact and physical_recovery_proof_sha256(found) == proof
        before = stored.read_bytes()
        assert not restored.retain_unstarted(
            replace(fact, updated_at=fact.updated_at + timedelta(seconds=1))
        )
        assert stored.read_bytes() == before
    finally:
        restored.close()


@pytest.mark.parametrize(
    "field,value",
    [
        ("fence_token", 2),
        ("runner_id", uuid4()),
        ("connection_generation", 2),
        ("capability_token", "y" * 43),
        ("certificate_sha256", "d" * 64),
        ("product_revision", "d" * 40),
        ("image_digest", "sha256:" + "d" * 64),
    ],
)
def test_unstarted_binding_cannot_be_replaced_or_rebound(tmp_path, field, value):
    journal, fact = InteractiveRecoveryJournal(tmp_path / "private"), _fact()
    try:
        assert journal.retain_unstarted(fact)
        with pytest.raises(InteractiveRecoveryError):
            journal.retain_unstarted(replace(fact, **{field: value}))
        assert journal.read_unstarted(fact.run_id) == fact
    finally:
        journal.close()


@pytest.mark.parametrize("corruption", ("version", "kind", "extra", "token", "uuid", "time"))
def test_unknown_or_corrupt_unstarted_journal_is_unavailable(tmp_path, corruption):
    directory, fact = tmp_path / "private", _fact()
    journal = InteractiveRecoveryJournal(directory)
    try:
        journal.retain_unstarted(fact)
        path = directory / f"{fact.run_id}.json"
        value = json.loads(path.read_text())
        if corruption == "version":
            value["schema_version"] = True
        elif corruption == "kind":
            value["record_type"] = "unknown"
        elif corruption == "extra":
            value["record"]["official_runner_id"] = "fabricated"
        elif corruption == "token":
            value["record"]["capability_token"] = None
        elif corruption == "uuid":
            value["record"]["run_id"] = "0" * 32
        else:
            value["record"]["updated_at"] = "2026-10-19T00:00:00"
        path.write_text(json.dumps(value))
        with pytest.raises(InteractiveRecoveryError):
            journal.read_unstarted(fact.run_id)
    finally:
        journal.close()
