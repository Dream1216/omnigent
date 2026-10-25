from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient

from saas.production.model_run_credentials import IssuedModelRunCredential
from saas.production.platform_model_relay import PlatformModelRelay


def _issued(run_id, now, number, *, fence=3):
    return IssuedModelRunCredential(
        "mrt_" + f"{number:064x}",
        datetime.fromtimestamp(now + 28800, timezone.utc),
        run_id,
        fence,
        number,
    )


def _run_relay(upstream, *, provider=None):
    now, run_id, count = [1000.0], uuid4(), []

    async def mint():
        count.append(len(count) + 1)
        return _issued(run_id, now[0], count[-1]) if provider is None else provider(run_id, now[0])

    relay = PlatformModelRelay.for_run(
        run_id=run_id,
        fence_token=3,
        credential_provider=mint,
        clock=lambda: now[0],
        client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(upstream)),
    )
    return relay, now, count


def test_run_relay_reads_the_new_opaque_bearer_without_changing_agent_capability():
    sent = []

    def upstream(request):
        sent.append(request.headers["Authorization"])
        return httpx.Response(200, stream=httpx.ByteStream(b"data: [DONE]\n\n"))

    relay, now, minted = _run_relay(upstream)
    with TestClient(relay.app) as client:
        capability = relay.capability
        for at in (1000, 1046, 1107):
            now[0] = at
            result = client.post(
                "/v1/responses",
                headers={"Authorization": "Bearer " + capability},
                json={"model": "allowed-model", "input": "Synthetic request"},
            )
            assert result.status_code == 200
            assert relay.capability == capability
        assert len(set(sent)) == 3
        assert all(token.startswith("Bearer mrt_") for token in sent)
        assert all(capability not in token for token in sent)
        assert len(minted) == 3


@pytest.mark.parametrize(
    "status,code,attempts",
    [
        (401, "platform_model_authentication_expired", 2),
        (401, "platform_model_authentication_invalid", 1),
        (403, "platform_model_run_authority_unavailable", 1),
        (429, "budget_exhausted", 1),
        (503, "platform_model_run_execution_unavailable", 1),
    ],
)
def test_run_relay_only_retries_one_explicit_pre_admission_expiry(status, code, attempts):
    sent = []

    def upstream(request):
        sent.append(request)
        return httpx.Response(status, json={"error": {"code": code}})

    relay, _now, _minted = _run_relay(upstream)
    with TestClient(relay.app) as client:
        result = client.post(
            "/v1/responses",
            headers={"Authorization": "Bearer " + relay.capability},
            json={"model": "allowed-model", "input": "Synthetic request"},
        )
    assert len(sent) == attempts
    if attempts == 2:
        assert result.status_code == 503 and b"codex login" not in result.content
        assert sent[0].content == sent[1].content
        assert sent[0].headers["Authorization"] != sent[1].headers["Authorization"]
    else:
        assert result.status_code == status


@pytest.mark.parametrize(
    "invalid", ["run", "fence", "expired", "short_lived", "oversized", "namespace"]
)
def test_run_relay_rejects_wrong_or_unusable_controller_credentials_before_egress(invalid):
    sent = []

    def provider(run_id, now):
        value = _issued(run_id, now, 1)
        changes = {
            "run": {"run_id": uuid4()},
            "fence": {"fence_token": 4},
            "expired": {"expires_at": datetime.fromtimestamp(now - 1, timezone.utc)},
            "short_lived": {"expires_at": datetime.fromtimestamp(now + 30, timezone.utc)},
            "oversized": {
                "expires_at": datetime.fromtimestamp(now, timezone.utc) + timedelta(days=1)
            },
            "namespace": {"value": "legacy-session-token"},
        }[invalid]
        return replace(value, **changes)

    relay, _now, _minted = _run_relay(lambda request: sent.append(request), provider=provider)
    with pytest.raises(Exception, match="会话认证恢复失败"), TestClient(relay.app):
        pass
    assert sent == []
