from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import sqlalchemy as sa

from saas.control_plane.db_models import OidcLoginTransaction
from saas.control_plane.lifecycle import LifecycleError
from saas.control_plane.oidc import OidcAuthorizationService
from saas.control_plane.oidc_keyring import OidcTransactionKeyring
from tests.saas.test_oidc_http_auth import _Harness, _start
from tests.saas.test_oidc_http_auth import oidc_harness as oidc_harness


def _replica(
    harness: _Harness, keys: dict[str, bytes], *, active: str = "rotated"
) -> OidcAuthorizationService:
    return OidcAuthorizationService(
        harness.sessions,
        harness.identities,
        {"test": harness.config},
        transaction_keyring=OidcTransactionKeyring(active, keys),
        http_transport=httpx.MockTransport(harness.provider.handle),
    )


def test_rotation_retains_old_pending_transactions_and_consumes_on_another_replica(
    oidc_harness: _Harness,
) -> None:
    callback, binding = _start(oidc_harness, subject="rotation", email="rotation@example.com")
    with pytest.raises(ValueError, match="retain keys"):
        _replica(oidc_harness, {"rotated": b"n" * 32})
    rotated = _replica(oidc_harness, {"legacy": b"o" * 32, "rotated": b"n" * 32})
    result = asyncio.run(rotated.complete("test", **callback, browser_binding=binding))
    assert result.user_id is not None
    started = rotated.begin("test")
    query = parse_qs(urlsplit(started.authorization_url).query)
    with oidc_harness.sessions() as db:
        ciphertext = db.scalar(
            sa.select(OidcLoginTransaction.code_verifier_ciphertext).where(
                OidcLoginTransaction.id == started.transaction_id
            )
        )
        assert ciphertext is not None and ciphertext.startswith("rotated.")
    final_replica = _replica(oidc_harness, {"rotated": b"n" * 32})
    next_callback = oidc_harness.provider.authorize(
        started.authorization_url, subject="rotation", email="rotation@example.com"
    )
    completed = asyncio.run(
        final_replica.complete("test", **next_callback, browser_binding=started.browser_binding)
    )
    assert completed.user_id == result.user_id
    assert next_callback["state"] == query["state"][0]


def test_expired_transactions_do_not_block_key_retirement(oidc_harness: _Harness) -> None:
    _start(oidc_harness, subject="expired-key", email="expired-key@example.com")
    with oidc_harness.sessions.begin() as db:
        db.execute(
            sa.update(OidcLoginTransaction).values(
                expires_at=datetime.now(timezone.utc) - timedelta(seconds=1)
            )
        )
    _replica(oidc_harness, {"rotated": b"n" * 32})


def test_key_identifier_is_authenticated_even_when_key_bytes_match() -> None:
    ring = OidcTransactionKeyring("v2", {"v2": b"a" * 32, "v3": b"a" * 32})
    ciphertext = ring.encrypt(b"secret-verifier", state_hash="b" * 64, nonce=b"c" * 12)
    assert ring.decrypt(ciphertext, state_hash="b" * 64) == b"secret-verifier"
    with pytest.raises(LifecycleError):
        ring.decrypt(ciphertext.replace("v2.", "v3.", 1), state_hash="b" * 64)
    with pytest.raises(LifecycleError):
        ring.decrypt(ciphertext, state_hash="d" * 64)


@pytest.mark.parametrize(
    "key_id,key", [("../../invalid", b"a" * 32), ("v2", b"a" * 31), ("v2", "a" * 32)]
)
def test_invalid_transaction_keys_fail_before_encrypting(key_id: str, key: bytes) -> None:
    with pytest.raises(ValueError):
        OidcTransactionKeyring(key_id, {key_id: key})
