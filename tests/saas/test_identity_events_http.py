from __future__ import annotations

import json

import pytest
import sqlalchemy as sa
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from saas.control_plane import IdentityEventInboxRecord, SaasBase
from saas.control_plane.identity_events_http import (
    IdentityEventIngressKeys,
    create_identity_event_router,
)
from saas.control_plane.identity_inbox import IdentityEventInboxService, IdentitySyncPolicy
from tests.saas.test_casdoor_identity_events import NOW, notification

HEADERS = {
    "X-Omnigent-Identity-Event-Key-Id": "current",
    "X-Omnigent-Identity-Event-Secret": "c" * 43,
    "Content-Type": "application/json",
}
PATH = "/saas/identity-events/casdoor"


@pytest.fixture
def ingress():
    engine = sa.create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    SaasBase.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    service = IdentityEventInboxService(
        sessions,
        policy=IdentitySyncPolicy(issuer="https://auth.example.test", organization="customers"),
    )
    app = FastAPI()
    app.include_router(
        create_identity_event_router(
            service,
            keys=IdentityEventIngressKeys({"current": "c" * 43, "previous": "p" * 43}),
            now=lambda: NOW,
        )
    )
    try:
        yield app, sessions
    finally:
        engine.dispose()


def count(sessions):
    with sessions() as db:
        return db.scalar(sa.select(sa.func.count()).select_from(IdentityEventInboxRecord))


def test_private_header_ingress_acknowledges_only_a_committed_normalized_inbox(ingress):
    app, sessions = ingress
    with TestClient(app, base_url="https://events.example.test") as client:
        first = client.post(PATH, content=notification(), headers=HEADERS)
        assert first.status_code == 200 and first.json()["status"] == "pending"
        assert first.headers["Cache-Control"] == "no-store" and count(sessions) == 1
        duplicate = client.post(PATH, content=notification(id=900), headers=HEADERS)
        assert (
            duplicate.json()["duplicate"]
            and duplicate.json()["receipt_id"] == first.json()["receipt_id"]
        )
        changed = client.post(
            PATH,
            content=notification(
                object=json.dumps({"owner": "customers", "name": "retargeted", "id": "another-id"})
            ),
            headers=HEADERS,
        )
        assert changed.status_code == 409 and count(sessions) == 1


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Cookie": "session=pretend-admin", "X-CSRF-Token": "pretend"},
        {**HEADERS, "X-Omnigent-Identity-Event-Key-Id": "unknown"},
        {**HEADERS, "X-Omnigent-Identity-Event-Secret": "wrong" * 10},
    ],
)
def test_cookies_csrf_and_unknown_or_wrong_private_keys_confer_no_authority(ingress, headers):
    app, sessions = ingress
    with TestClient(app, base_url="https://events.example.test") as client:
        result = client.post(PATH, content=notification(), headers=headers)
        assert result.status_code == 401 and count(sessions) == 0


def test_key_rotation_accepts_an_explicit_overlapping_previous_key(ingress):
    app, sessions = ingress
    with TestClient(app, base_url="https://events.example.test") as client:
        result = client.post(
            PATH,
            content=notification(),
            headers={
                **HEADERS,
                "X-Omnigent-Identity-Event-Key-Id": "previous",
                "X-Omnigent-Identity-Event-Secret": "p" * 43,
            },
        )
        assert result.status_code == 200 and count(sessions) == 1


def test_untrusted_forwarded_header_does_not_turn_plain_http_into_https(ingress):
    app, sessions = ingress
    with TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 1234)) as client:
        result = client.post(
            PATH, content=notification(), headers={**HEADERS, "X-Forwarded-Proto": "https"}
        )
        assert result.status_code == 403 and count(sessions) == 0


@pytest.mark.parametrize(
    ("body", "headers", "status"),
    [
        (b"x" * 65537, HEADERS, 413),
        (b"{}", {**HEADERS, "Content-Type": "text/plain"}, 415),
        (b"{}", {**HEADERS, "Content-Encoding": "gzip"}, 415),
        (b"{bad-json}", HEADERS, 400),
        (notification(response='{status:"error", msg:"wrong password"}'), HEADERS, 200),
        (notification(object=json.dumps({"owner": "foreign", "name": "one"})), HEADERS, 200),
    ],
    ids=["oversize", "media-type", "encoded", "invalid-json", "failed-operation", "foreign-scope"],
)
def test_invalid_and_irrelevant_events_never_create_inbox_rows(ingress, body, headers, status):
    app, sessions = ingress
    with TestClient(app, base_url="https://events.example.test") as client:
        result = client.post(PATH, content=body, headers=headers)
        assert result.status_code == status and count(sessions) == 0
        assert result.headers["Cache-Control"] == "no-store"


def test_failed_database_commit_is_not_acknowledged_or_exposed(ingress):
    app, sessions = ingress

    def fail(_session):
        raise RuntimeError("private-db-password-must-not-appear")

    sa.event.listen(sessions, "before_commit", fail)
    try:
        with TestClient(app, base_url="https://events.example.test") as client:
            result = client.post(PATH, content=notification(), headers=HEADERS)
            assert result.status_code == 503
            assert result.json() == {"error": "identity_event_unavailable"}
    finally:
        sa.event.remove(sessions, "before_commit", fail)
    assert count(sessions) == 0
