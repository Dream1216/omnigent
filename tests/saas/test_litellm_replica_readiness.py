from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import httpx
import pytest

from saas.control_plane.litellm_client import (
    LiteLLMManagementClient,
    LiteLLMManagementConfiguration,
)
from saas.production.litellm_configuration_attestation import (
    LiteLLMAttestationError,
    LiteLLMConfigurationAttestation,
)
from saas.production.litellm_replica_readiness import (
    READINESS_SCOPE,
    LiteLLMReplicaEndpoint,
    LiteLLMReplicaReadinessAuthority,
    LiteLLMReplicaReadinessError,
)
from tests.saas.test_model_protocol_probe import _fixture

_KEY = "isolated-provider-key-never-in-replica-evidence"
_MANAGEMENT = "isolated-management-key-never-in-replica-evidence"


def _endpoints():
    return tuple(
        LiteLLMReplicaEndpoint(
            f"replica-{index}",
            LiteLLMManagementConfiguration(
                base_url=f"https://replica-{index}.litellm.test", management_key=_MANAGEMENT
            ),
        )
        for index in range(2)
    )


class _Storage:
    def __init__(self, draft, now, *, change=None):
        self.draft, self.now, self.change, self.calls = draft, now, change, 0

    def attest(self, **arguments):
        self.calls += 1
        assert arguments["expected_api_key"] == _KEY
        if self.change == "before_error" or (self.change == "after_error" and self.calls == 2):
            raise LiteLLMAttestationError()
        return LiteLLMConfigurationAttestation(
            uuid4() if self.change == "binding" else self.draft.deployment_id,
            self.draft.credential_version_id,
            self.draft.configuration_sha256,
            "b" * 64 if self.change == "drift" and self.calls == 2 else "a" * 64,
            self.now
            + timedelta(
                seconds=-1 if self.change == "stale" else 1 if self.change == "future" else 0
            ),
        )


def _setup(*, handler=None, change=None):
    draft, _ = _fixture()
    now, requests = datetime.now(timezone.utc), []
    storage = _Storage(draft, now, change=change)

    async def manage(request):
        requests.append((request.method, request.url.host, request.url.path))
        assert request.headers["authorization"] == "Bearer " + _MANAGEMENT
        assert request.method == "GET" and request.url.path == "/model/info"
        row = {
            "model_name": draft.alias,
            "model_info": {"id": str(draft.deployment_id)},
            "litellm_params": {
                "model": "deepseek/" + draft.public_model_id,
                "api_base": "https://api.deepseek.com",
                "litellm_credential_name": "platform-approved-credential",
                "num_retries": 0,
                "max_retries": 0,
            },
        }
        if handler:
            return await handler(request, row)
        return httpx.Response(200, json={"data": [row]})

    authority = LiteLLMReplicaReadinessAuthority(
        _endpoints(),
        storage=storage,
        clock=lambda: now,
        client_factory=lambda config: LiteLLMManagementClient(
            config, transport=httpx.MockTransport(manage)
        ),
    )
    arguments = {
        "draft": draft,
        "credential_name": "platform-approved-credential",
        "expected_api_key": _KEY,
    }
    return authority, storage, requests, arguments, now


async def test_each_known_endpoint_and_storage_are_bound_without_inference_or_secret_evidence():
    authority, storage, requests, arguments, now = _setup()
    result = await authority.attest(**arguments)
    result.require_current(
        draft=arguments["draft"], inventory_sha256=authority.inventory_sha256, now=now
    )
    assert storage.calls == 2
    assert set(requests) == {
        ("GET", f"replica-{index}.litellm.test", "/model/info") for index in range(2)
    }
    assert result.scope == READINESS_SCOPE
    assert [row.replica_id for row in result.observations] == ["replica-0", "replica-1"]
    rendered = json.dumps(result.evidence())
    assert _KEY not in rendered and _MANAGEMENT not in rendered
    assert ".litellm.test" not in rendered
    assert _MANAGEMENT not in repr(_endpoints())
    assert len(result.evidence_sha256) == 64


@pytest.mark.parametrize(
    "change", ("before_error", "binding", "drift", "after_error", "stale", "future")
)
async def test_storage_failure_or_drift_never_yields_readiness(change):
    authority, storage, requests, arguments, _ = _setup(change=change)
    with pytest.raises(LiteLLMReplicaReadinessError) as error:
        await authority.attest(**arguments)
    assert _KEY not in str(error.value) and _MANAGEMENT not in str(error.value)
    assert len(requests) == (0 if change in {"before_error", "binding"} else 2)
    assert storage.calls == (1 if change in {"before_error", "binding"} else 2)


@pytest.mark.parametrize("change", ("missing", "wrong_id", "retry", "duplicate", "unavailable"))
async def test_one_unready_replica_rejects_the_whole_candidate(change):
    async def manage(request, row):
        if request.url.host == "replica-0.litellm.test":
            return httpx.Response(200, json={"data": [row]})
        if change == "unavailable":
            return httpx.Response(503, json={"error": _KEY})
        if change == "wrong_id":
            row["model_info"]["id"] = str(uuid4())
        if change == "retry":
            row["litellm_params"]["num_retries"] = 1
        rows = [] if change == "missing" else [row, row] if change == "duplicate" else [row]
        return httpx.Response(200, json={"data": rows})

    authority, storage, _, arguments, _ = _setup(handler=manage)
    with pytest.raises(LiteLLMReplicaReadinessError) as error:
        await authority.attest(**arguments)
    assert str(error.value) == "litellm_replica_readiness_unavailable"
    assert storage.calls == 1


@pytest.mark.parametrize(
    "change", ("stale", "future", "scope", "contract", "inventory", "duplicate", "naive")
)
async def test_receipt_cannot_be_reused_for_another_inventory_or_outside_freshness(change):
    authority, _, _, arguments, now = _setup()
    result = await authority.attest(**arguments)
    if change == "stale":
        now += timedelta(seconds=31)
    elif change == "future":
        now -= timedelta(seconds=1)
    elif change == "scope":
        result = replace(result, scope="hidden_replica_memory_verified")
    elif change == "contract":
        result = replace(result, contract="unapproved")
    elif change == "inventory":
        result = replace(result, inventory_sha256="b" * 64)
    elif change == "duplicate":
        result = replace(result, observations=(result.observations[0],) * 2)
    elif change == "naive":
        result = replace(result, completed_at=now.replace(tzinfo=None))
    with pytest.raises(LiteLLMReplicaReadinessError, match="stale_or_unbound"):
        result.require_current(
            draft=arguments["draft"], inventory_sha256=authority.inventory_sha256, now=now
        )


@pytest.mark.parametrize("change", ("one", "same_id", "same_endpoint", "trailing_slash"))
def test_endpoint_inventory_cannot_count_the_same_endpoint_twice(change):
    first, second = _endpoints()
    if change == "one":
        endpoints = (first,)
    elif change == "same_id":
        endpoints = (first, replace(second, replica_id=first.replica_id))
    else:
        endpoints = (
            first,
            replace(
                second,
                management=replace(
                    first.management,
                    base_url=first.management.base_url
                    + ("/" if change == "trailing_slash" else ""),
                ),
            ),
        )
    with pytest.raises(ValueError, match="replica_configuration_invalid"):
        LiteLLMReplicaReadinessAuthority(endpoints, storage=None)


async def test_failed_replica_cancels_other_endpoint_reads_before_returning():
    entered, cancelled = asyncio.Event(), asyncio.Event()

    async def manage(request, row):
        if request.url.host == "replica-0.litellm.test":
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()
        await entered.wait()
        return httpx.Response(200, json={"data": []})

    authority, storage, _, arguments, _ = _setup(handler=manage)
    with pytest.raises(LiteLLMReplicaReadinessError):
        await asyncio.wait_for(authority.attest(**arguments), timeout=2)
    assert cancelled.is_set() and storage.calls == 1
