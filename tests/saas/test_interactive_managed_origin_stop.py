"""Private origin-stop format contracts; constructed receipts are not live container proof."""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from uuid import UUID

import pytest

from saas.production.interactive_recovery import (
    InteractiveRecoveryError,
    ManagedPodTermination,
    ManagedTerminationReceipt,
    _decode,
    _encode,
    managed_retirement_proof_sha256,
    physical_recovery_proof_sha256,
)
from tests.saas.test_interactive_controller import controller_case as controller_case
from tests.saas.test_interactive_execution_http import interactive_http as interactive_http
from tests.saas.test_interactive_managed_reuse import _warm


async def _peer(c, *, known=True):
    w = await _warm(c)
    lease = await w.next_lease()
    active, _ = await c.executor._prepare_active(lease, cancellation=asyncio.Event())
    changes = (
        {}
        if known
        else {
            "host_id": None,
            "official_runner_id": None,
            "host_owner": None,
            "host_account_generation": None,
        }
    )
    c.executor._put(active, managed_origin_run_id=w.root.run_id, **changes)
    c.executor._put(active, phase="draining", outcome="orphaned")
    complete = replace(
        w.root,
        process_stopped=True,
        managed_termination=ManagedTerminationReceipt(
            secret_uid=w.root.managed_resources.token_secret_uid,
            secret_gone=True,
            pods=(ManagedPodTermination(str(UUID(int=3)), "owned-pod", "c" * 64),),
            quiescence_sha256="d" * 64,
            complete=True,
        ),
    )
    return w, active.record, complete


@pytest.mark.asyncio
@pytest.mark.parametrize("known", [False, True])
async def test_origin_stop_binds_complete_root_without_borrowing_model_authority(
    controller_case, known
):
    c = controller_case
    _, peer, complete = await _peer(c, known=known)
    c.journal.put(complete)
    stopped = replace(
        peer,
        phase="terminal",
        process_stopped=True,
        stop_kind="managed_origin",
        managed_origin_stop_sha256=managed_retirement_proof_sha256(complete),
    )
    c.journal.put(stopped)
    assert c.journal.read(peer.run_id) == stopped
    assert stopped.grant == peer.grant and stopped.grant.run_id != complete.grant.run_id
    assert stopped.managed_preparation is stopped.managed_resources is None
    assert stopped.managed_creation is stopped.managed_termination is None
    assert physical_recovery_proof_sha256(stopped) != physical_recovery_proof_sha256(complete)
    raw = _encode(stopped)
    assert json.loads(raw)["schema_version"] == 8 and _encode(_decode(raw)) == raw
    for version in range(1, 8):
        document = json.loads(raw)
        document["schema_version"] = version
        with pytest.raises(InteractiveRecoveryError):
            _decode(json.dumps(document).encode())
    for digest in (None, "f" * 64):
        with pytest.raises(InteractiveRecoveryError):
            c.journal.put(replace(stopped, managed_origin_stop_sha256=digest))
    assert len(c.inputs) == len(c.gateway_calls) == 1


@pytest.mark.asyncio
async def test_missing_incomplete_foreign_or_changed_root_cannot_confirm_origin_stop(
    controller_case,
):
    c = controller_case
    w, peer, complete = await _peer(c, known=False)
    for invalid in (
        w.root,
        replace(complete, process_stopped=False),
        replace(
            complete, managed_termination=replace(complete.managed_termination, complete=False)
        ),
    ):
        with pytest.raises(InteractiveRecoveryError):
            managed_retirement_proof_sha256(invalid)
    digest = managed_retirement_proof_sha256(complete)
    stopped = replace(
        peer,
        phase="terminal",
        process_stopped=True,
        stop_kind="managed_origin",
        managed_origin_stop_sha256=digest,
    )
    with pytest.raises(InteractiveRecoveryError):
        c.journal.put(stopped)
    c.journal.put(complete)
    with pytest.raises(InteractiveRecoveryError):
        c.journal.put(replace(stopped, certificate_sha256="e" * 64))
    c.journal.put(stopped)
    path = c.journal.root / f"{complete.run_id}.json"
    original = path.read_bytes()
    try:
        value = json.loads(original)
        value["record"]["managed_resources"]["workload_uid"] = str(UUID(int=9))
        path.write_text(json.dumps(value))
        with pytest.raises(InteractiveRecoveryError):
            c.journal.read(stopped.run_id)
    finally:
        path.write_bytes(original)
    assert c.journal.read(stopped.run_id) == stopped


@pytest.mark.asyncio
async def test_resource_receipt_does_not_change_an_existing_host_runner_ack_proof(controller_case):
    c = controller_case
    w, _, complete = await _peer(c)
    acknowledged = replace(w.root, process_stopped=True)
    c.journal.put(acknowledged)
    before = physical_recovery_proof_sha256(acknowledged)
    c.journal.put(complete)
    assert physical_recovery_proof_sha256(c.journal.read(complete.run_id)) == before
    assert managed_retirement_proof_sha256(complete) != before
