from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from time import monotonic
from uuid import uuid4

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from saas.control_plane.onboarding import (
    OnboardingError,
    RegistrationRateLimitSubjectKeyring,
    SharedRegistrationRateLimiter,
    SharedRegistrationRateLimitJanitor,
)

_POLICIES = {
    ("registration.request", "email"): (5, 900, 86400, 1_000_000),
    ("registration.request", "network"): (60, 900, 86400, 1_000_000),
    ("registration.resend", "email"): (3, 900, 86400, 1_000_000),
    ("registration.resend", "network"): (60, 900, 86400, 1_000_000),
    ("registration.verify", "registration"): (10, 900, 86400, 1_000_000),
    ("registration.verify", "network"): (120, 900, 86400, 1_000_000),
}
_CONSUME_SIGNATURE = (
    "public.saas_consume_registration_rate_limit(text,text,text,text,text,text,text,text)"
)
_PRUNE_SIGNATURE = "public.saas_prune_registration_rate_limits(text,text,integer)"
_STATUS_SIGNATURE = "public.saas_registration_rate_limit_status()"


def _postgres_url() -> str:
    value = os.environ.get("OMNIGENT_SAAS_TEST_POSTGRES_URL")
    if not value:
        pytest.skip(
            "OMNIGENT_SAAS_TEST_POSTGRES_URL is required for registration rate-limit acceptance"
        )
    return value


def _migration_config(connection: sa.Connection) -> Config:
    root = Path(__file__).resolve().parents[2]
    config = Config(root / "saas/control_plane/alembic.ini")
    config.set_main_option("script_location", str(root / "saas/control_plane/migrations"))
    config.attributes["connection"] = connection
    return config


@pytest.fixture(scope="module")
def rate_limit_postgresql_engine() -> Engine:
    root = Path(__file__).resolve().parents[2]
    engine = sa.create_engine(_postgres_url())
    with engine.begin() as connection:
        command.upgrade(_migration_config(connection), "head")
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
    try:
        yield engine
    finally:
        engine.dispose()


def _reset_rate_limits(engine: Engine) -> None:
    with engine.begin() as connection:
        connection.execute(sa.text("DELETE FROM public.saas_registration_rate_limits"))
        for (action, subject_kind), (
            limit_count,
            window_seconds,
            retention_seconds,
            max_rows,
        ) in _POLICIES.items():
            connection.execute(
                sa.text(
                    "UPDATE public.saas_registration_rate_limit_policies "
                    "SET limit_count = :limit_count, window_seconds = :window_seconds, "
                    "retention_seconds = :retention_seconds, max_rows = :max_rows, "
                    "current_rows = 0, policy_revision = 'registration-rate-limit-v1', "
                    "updated_at = pg_catalog.clock_timestamp() "
                    "WHERE action = :action AND subject_kind = :subject_kind"
                ),
                {
                    "action": action,
                    "subject_kind": subject_kind,
                    "limit_count": limit_count,
                    "window_seconds": window_seconds,
                    "retention_seconds": retention_seconds,
                    "max_rows": max_rows,
                },
            )


@pytest.fixture(autouse=True)
def clean_rate_limit_state(rate_limit_postgresql_engine: Engine) -> None:
    _reset_rate_limits(rate_limit_postgresql_engine)
    yield
    _reset_rate_limits(rate_limit_postgresql_engine)


def _role_sessions(engine: Engine, role: str) -> sessionmaker[Session]:
    sessions = sessionmaker(engine, expire_on_commit=False)

    @sa.event.listens_for(sessions, "after_begin")
    def _set_role(
        _session: Session,
        _transaction: object,
        connection: sa.Connection,
    ) -> None:
        connection.exec_driver_sql(f"SET LOCAL ROLE {role}")

    return sessions


def _keyring(
    *,
    active: str = "rate-test-active",
    previous: str | None = None,
    anchor: str | None = None,
    write: str | None = None,
    previous_writers_drained: bool = False,
) -> RegistrationRateLimitSubjectKeyring:
    keys = {active: b"a" * 32}
    if previous is not None:
        keys[previous] = b"p" * 32
    return RegistrationRateLimitSubjectKeyring(
        keys=keys,
        active_key_id=active,
        previous_key_id=previous,
        anchor_key_id=anchor,
        write_key_id=write,
        previous_writers_drained=previous_writers_drained,
    )


def _limiter(
    engine: Engine,
    keyring: RegistrationRateLimitSubjectKeyring | None = None,
) -> SharedRegistrationRateLimiter:
    return SharedRegistrationRateLimiter(
        _role_sessions(engine, "saas_registration"),
        subject_keyring=keyring or _keyring(),
    )


def _set_policy(
    engine: Engine,
    *,
    limit_count: int,
    max_rows: int = 1_000_000,
    window_seconds: int = 60,
    retention_seconds: int = 300,
) -> None:
    with engine.begin() as connection:
        connection.execute(
            sa.text(
                "UPDATE public.saas_registration_rate_limit_policies "
                "SET limit_count = :limit_count, window_seconds = :window_seconds, "
                "retention_seconds = :retention_seconds, max_rows = :max_rows, "
                "current_rows = 0, updated_at = pg_catalog.clock_timestamp() "
                "WHERE action = 'registration.request' AND subject_kind = 'email'"
            ),
            {
                "limit_count": limit_count,
                "window_seconds": window_seconds,
                "retention_seconds": retention_seconds,
                "max_rows": max_rows,
            },
        )


def _consume_result(limiter: SharedRegistrationRateLimiter, subject: str) -> str:
    try:
        limiter.require(
            action="registration.request",
            subject_kind="email",
            subject=subject,
        )
    except OnboardingError as error:
        return error.code
    return "allowed"


def test_catalog_seals_tables_and_security_definer_entrypoints(
    rate_limit_postgresql_engine: Engine,
) -> None:
    with rate_limit_postgresql_engine.begin() as connection:
        table_rows = {
            row.relname: row
            for row in connection.execute(
                sa.text(
                    "SELECT class.relname, class.relrowsecurity, class.relforcerowsecurity, "
                    "pg_catalog.pg_get_userbyid(class.relowner) AS owner "
                    "FROM pg_catalog.pg_class AS class "
                    "WHERE class.oid IN ("
                    "'public.saas_registration_rate_limit_policies'::pg_catalog.regclass, "
                    "'public.saas_registration_rate_limits'::pg_catalog.regclass)"
                )
            )
        }
        assert set(table_rows) == {
            "saas_registration_rate_limit_policies",
            "saas_registration_rate_limits",
        }
        assert all(row.relrowsecurity and row.relforcerowsecurity for row in table_rows.values())
        assert len({row.owner for row in table_rows.values()}) == 1
        table_owner = next(iter(table_rows.values())).owner
        policy_contracts = {
            (row.action, row.subject_kind): (
                row.limit_count,
                row.window_seconds,
                row.retention_seconds,
                row.max_rows,
            )
            for row in connection.execute(
                sa.text(
                    "SELECT action, subject_kind, limit_count, window_seconds, "
                    "retention_seconds, max_rows "
                    "FROM public.saas_registration_rate_limit_policies"
                )
            )
        }
        assert policy_contracts == _POLICIES

        policies = list(
            connection.execute(
                sa.text(
                    "SELECT policy.polname, "
                    "pg_catalog.pg_get_expr(policy.polqual, policy.polrelid) AS using_expr, "
                    "pg_catalog.pg_get_expr(policy.polwithcheck, policy.polrelid) AS check_expr "
                    "FROM pg_catalog.pg_policy AS policy "
                    "WHERE policy.polrelid IN ("
                    "'public.saas_registration_rate_limit_policies'::pg_catalog.regclass, "
                    "'public.saas_registration_rate_limits'::pg_catalog.regclass)"
                )
            ).mappings()
        )
        assert {row["polname"] for row in policies} == {
            "rls_registration_rate_limit_policies_owner",
            "rls_registration_rate_limits_owner",
        }
        for policy in policies:
            for expression in (policy["using_expr"], policy["check_expr"]):
                assert "relowner" in expression
                assert "pg_get_userbyid" in expression

        function_rows = {
            row.signature: row
            for row in connection.execute(
                sa.text(
                    "SELECT procedure.oid::pg_catalog.regprocedure::text AS signature, "
                    "pg_catalog.pg_get_userbyid(procedure.proowner) AS owner, "
                    "procedure.prosecdef, procedure.provolatile, procedure.proconfig "
                    "FROM pg_catalog.pg_proc AS procedure "
                    "WHERE procedure.oid IN (pg_catalog.to_regprocedure(:consume), "
                    "pg_catalog.to_regprocedure(:prune), pg_catalog.to_regprocedure(:status))"
                ),
                {
                    "consume": _CONSUME_SIGNATURE,
                    "prune": _PRUNE_SIGNATURE,
                    "status": _STATUS_SIGNATURE,
                },
            )
        }
        assert set(function_rows) == {
            "saas_consume_registration_rate_limit(text,text,text,text,text,text,text,text)",
            "saas_prune_registration_rate_limits(text,text,integer)",
            "saas_registration_rate_limit_status()",
        }
        for row in function_rows.values():
            assert row.owner == table_owner
            assert row.prosecdef is True
            assert row.provolatile == "v"
            assert "search_path=pg_catalog" in row.proconfig
        assert (
            "lock_timeout=250ms"
            in function_rows[
                "saas_consume_registration_rate_limit(text,text,text,text,text,text,text,text)"
            ].proconfig
        )
        assert (
            "lock_timeout=500ms"
            in function_rows["saas_prune_registration_rate_limits(text,text,integer)"].proconfig
        )

        for role in ("saas_registration", "saas_platform"):
            for table in table_rows:
                for privilege in (
                    "SELECT",
                    "INSERT",
                    "UPDATE",
                    "DELETE",
                    "TRUNCATE",
                    "REFERENCES",
                    "TRIGGER",
                ):
                    assert (
                        connection.scalar(
                            sa.text(
                                "SELECT pg_catalog.has_table_privilege(:role, :table, :privilege)"
                            ),
                            {"role": role, "table": f"public.{table}", "privilege": privilege},
                        )
                        is False
                    )
                for privilege in ("SELECT", "INSERT", "UPDATE", "REFERENCES"):
                    assert (
                        connection.scalar(
                            sa.text(
                                "SELECT pg_catalog.has_any_column_privilege("
                                ":role, :table, :privilege)"
                            ),
                            {
                                "role": role,
                                "table": f"public.{table}",
                                "privilege": privilege,
                            },
                        )
                        is False
                    )

        assert (
            connection.scalar(
                sa.text(
                    "SELECT pg_catalog.count(*) "
                    "FROM pg_catalog.pg_attribute AS attribute "
                    "CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) AS acl "
                    "WHERE attribute.attrelid IN ("
                    "'public.saas_registration_rate_limit_policies'::pg_catalog.regclass, "
                    "'public.saas_registration_rate_limits'::pg_catalog.regclass) "
                    "AND attribute.attnum > 0 AND NOT attribute.attisdropped "
                    "AND (acl.grantee = 0 OR acl.grantee IN ("
                    "SELECT role.oid FROM pg_catalog.pg_roles AS role "
                    "WHERE role.rolname IN ('saas_registration', 'saas_platform')))"
                )
            )
            == 0
        )

        expected_function_acl = {
            _CONSUME_SIGNATURE: {"saas_registration": True, "saas_platform": False},
            _PRUNE_SIGNATURE: {"saas_registration": False, "saas_platform": True},
            _STATUS_SIGNATURE: {"saas_registration": False, "saas_platform": True},
        }
        for signature, role_expectations in expected_function_acl.items():
            for role, expected in role_expectations.items():
                assert (
                    connection.scalar(
                        sa.text(
                            "SELECT pg_catalog.has_function_privilege("
                            ":role, :signature, 'EXECUTE')"
                        ),
                        {"role": role, "signature": signature},
                    )
                    is expected
                )
            assert (
                connection.scalar(
                    sa.text(
                        "SELECT pg_catalog.count(*) FROM pg_catalog.pg_proc AS procedure "
                        "CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE("
                        "procedure.proacl, "
                        "pg_catalog.acldefault('f', procedure.proowner))) AS acl "
                        "WHERE procedure.oid = pg_catalog.to_regprocedure(:signature) "
                        "AND acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'"
                    ),
                    {"signature": signature},
                )
                == 0
            )

    with pytest.raises(DBAPIError) as direct_counter:
        with rate_limit_postgresql_engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_registration")
            connection.execute(
                sa.text("SELECT pg_catalog.set_config(:name, :value, true)"),
                {
                    "name": "app.registration_rate_limit_subject_hash",
                    "value": "f" * 64,
                },
            )
            connection.execute(
                sa.text("SELECT count(*) FROM public.saas_registration_rate_limits")
            )
    assert direct_counter.value.orig.sqlstate == "42501"

    with pytest.raises(DBAPIError) as direct_policy:
        with rate_limit_postgresql_engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
            connection.execute(
                sa.text(
                    "UPDATE public.saas_registration_rate_limit_policies SET limit_count = 1000"
                )
            )
    assert direct_policy.value.orig.sqlstate == "42501"


def test_database_clock_and_hmac_only_storage(rate_limit_postgresql_engine: Engine) -> None:
    subject = f"clock-{uuid4()}@example.test"
    keyring = _keyring()
    aliases = keyring.aliases(
        action="registration.request",
        subject_kind="email",
        subject=subject,
    )
    with rate_limit_postgresql_engine.connect() as connection:
        before = connection.scalar(sa.text("SELECT pg_catalog.clock_timestamp()"))
    _limiter(rate_limit_postgresql_engine, keyring).require(
        action="registration.request",
        subject_kind="email",
        subject=subject,
    )
    with rate_limit_postgresql_engine.connect() as connection:
        after = connection.scalar(sa.text("SELECT pg_catalog.clock_timestamp()"))
        row = (
            connection.execute(
                sa.text(
                    "SELECT key_id, subject_hmac, window_started_at, created_at, updated_at, "
                    "expires_at, policy_revision "
                    "FROM public.saas_registration_rate_limits"
                )
            )
            .mappings()
            .one()
        )
        arguments = (
            connection.execute(
                sa.text(
                    "SELECT procedure.pronargs, procedure.proargnames "
                    "FROM pg_catalog.pg_proc AS procedure "
                    "WHERE procedure.oid = pg_catalog.to_regprocedure(:signature)"
                ),
                {"signature": _CONSUME_SIGNATURE},
            )
            .mappings()
            .one()
        )

    assert before <= row["window_started_at"] <= after
    assert before <= row["created_at"] <= after
    assert before <= row["updated_at"] <= after
    assert row["expires_at"] > row["window_started_at"]
    assert row["key_id"] == aliases.active_key_id
    assert row["subject_hmac"] == aliases.active_subject_hmac
    assert subject not in "|".join(str(value) for value in row.values())
    assert row["policy_revision"] == "registration-rate-limit-v1"
    assert arguments["pronargs"] == 8
    assert not {"now", "limit", "window"}.intersection(arguments["proargnames"])


def test_all_action_subject_policies_use_independent_hmac_buckets(
    rate_limit_postgresql_engine: Engine,
) -> None:
    limiter = _limiter(rate_limit_postgresql_engine)
    subject = "same-raw-test-subject"
    for action, subject_kind in _POLICIES:
        limiter.require(action=action, subject_kind=subject_kind, subject=subject)

    with rate_limit_postgresql_engine.connect() as connection:
        rows = list(
            connection.execute(
                sa.text(
                    "SELECT action, subject_kind, subject_hmac "
                    "FROM public.saas_registration_rate_limits "
                    "ORDER BY action, subject_kind"
                )
            )
        )
    assert {(row.action, row.subject_kind) for row in rows} == set(_POLICIES)
    assert len({row.subject_hmac for row in rows}) == len(_POLICIES)
    assert all(subject not in row.subject_hmac for row in rows)


def test_concurrent_same_subject_saturates_one_shared_quota(
    rate_limit_postgresql_engine: Engine,
) -> None:
    _set_policy(rate_limit_postgresql_engine, limit_count=5)
    limiter = _limiter(rate_limit_postgresql_engine)
    subject = f"concurrent-{uuid4()}@example.test"
    barrier = Barrier(12)

    def consume() -> str:
        barrier.wait()
        return _consume_result(limiter, subject)

    with ThreadPoolExecutor(max_workers=12) as workers:
        results = list(workers.map(lambda _index: consume(), range(12)))

    assert results.count("allowed") == 5
    assert results.count("registration_rate_limited") == 7
    assert set(results) == {"allowed", "registration_rate_limited"}
    with rate_limit_postgresql_engine.connect() as connection:
        counter = connection.execute(
            sa.text("SELECT request_count, version FROM public.saas_registration_rate_limits")
        ).one()
        current_rows = connection.scalar(
            sa.text(
                "SELECT current_rows FROM public.saas_registration_rate_limit_policies "
                "WHERE action = 'registration.request' AND subject_kind = 'email'"
            )
        )
    assert counter == (5, 12)
    assert current_rows == 1


def test_rotation_overlap_and_promotion_never_double_quota(
    rate_limit_postgresql_engine: Engine,
) -> None:
    _set_policy(rate_limit_postgresql_engine, limit_count=3)
    subject = f"rotation-{uuid4()}@example.test"
    old_keyring = RegistrationRateLimitSubjectKeyring(
        keys={"rate-old": b"p" * 32},
        active_key_id="rate-old",
    )
    old = _limiter(rate_limit_postgresql_engine, old_keyring)
    assert _consume_result(old, subject) == "allowed"
    assert _consume_result(old, subject) == "allowed"

    overlap_keyring = _keyring(active="rate-new", previous="rate-old")
    assert overlap_keyring.anchor_key_id == "rate-old"
    assert overlap_keyring.write_key_id == "rate-old"
    overlap = _limiter(rate_limit_postgresql_engine, overlap_keyring)
    assert _consume_result(overlap, subject) == "allowed"
    assert _consume_result(overlap, subject) == "registration_rate_limited"
    assert _consume_result(old, subject) == "registration_rate_limited"

    promoted_keyring = _keyring(
        active="rate-new",
        previous="rate-old",
        anchor="rate-old",
        write="rate-new",
        previous_writers_drained=True,
    )
    promoted = _limiter(rate_limit_postgresql_engine, promoted_keyring)
    assert _consume_result(promoted, subject) == "registration_rate_limited"
    new_only = _limiter(
        rate_limit_postgresql_engine,
        RegistrationRateLimitSubjectKeyring(
            keys={"rate-new": b"a" * 32},
            active_key_id="rate-new",
        ),
    )
    assert _consume_result(new_only, subject) == "registration_rate_limited"

    aliases = promoted_keyring.aliases(
        action="registration.request",
        subject_kind="email",
        subject=subject,
    )
    with rate_limit_postgresql_engine.connect() as connection:
        rows = list(
            connection.execute(
                sa.text(
                    "SELECT key_id, subject_hmac, request_count, version "
                    "FROM public.saas_registration_rate_limits"
                )
            )
        )
    assert rows == [("rate-new", aliases.active_subject_hmac, 3, 7)]


@pytest.mark.parametrize(
    "arguments",
    [
        {
            "active_key_id": "rate-new",
            "active_hmac": "a" * 64,
            "previous_key_id": "rate-old",
            "previous_hmac": "b" * 64,
            "anchor_key_id": "rate-new",
            "write_key_id": "rate-old",
        },
        {
            "active_key_id": "rate-new",
            "active_hmac": "a" * 64,
            "previous_key_id": None,
            "previous_hmac": None,
            "anchor_key_id": "rate-new",
            "write_key_id": "rate-old",
        },
    ],
)
def test_database_rejects_rotation_phase_bypass(
    rate_limit_postgresql_engine: Engine,
    arguments: dict[str, str | None],
) -> None:
    with pytest.raises(DBAPIError) as rejected:
        with rate_limit_postgresql_engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_registration")
            connection.execute(
                sa.text(
                    "SELECT * FROM public.saas_consume_registration_rate_limit("
                    "'registration.request', 'email', :active_key_id, :active_hmac, "
                    ":previous_key_id, :previous_hmac, :anchor_key_id, :write_key_id)"
                ),
                arguments,
            ).one()
    assert rejected.value.orig.sqlstate == "22023"
    with rate_limit_postgresql_engine.connect() as connection:
        assert (
            connection.scalar(sa.text("SELECT count(*) FROM public.saas_registration_rate_limits"))
            == 0
        )


def test_capacity_lock_allows_only_one_distinct_subject(
    rate_limit_postgresql_engine: Engine,
) -> None:
    _set_policy(rate_limit_postgresql_engine, limit_count=5, max_rows=1)
    limiter = _limiter(rate_limit_postgresql_engine)
    barrier = Barrier(2)
    subjects = [f"capacity-{uuid4()}@example.test" for _ in range(2)]

    def consume(subject: str) -> str:
        barrier.wait()
        return _consume_result(limiter, subject)

    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(consume, subjects))

    assert results.count("allowed") == 1
    assert results.count("registration_rate_limit_unavailable") == 1
    with rate_limit_postgresql_engine.connect() as connection:
        assert (
            connection.scalar(sa.text("SELECT count(*) FROM public.saas_registration_rate_limits"))
            == 1
        )
        assert (
            connection.scalar(
                sa.text(
                    "SELECT current_rows FROM public.saas_registration_rate_limit_policies "
                    "WHERE action = 'registration.request' AND subject_kind = 'email'"
                )
            )
            == 1
        )


def _insert_expired_rows(engine: Engine, count: int) -> None:
    with engine.begin() as connection:
        for index in range(count):
            connection.execute(
                sa.text(
                    "INSERT INTO public.saas_registration_rate_limits "
                    "(action, subject_kind, key_id, subject_hmac, window_started_at, "
                    "request_count, expires_at, policy_revision, version, created_at, "
                    "updated_at) VALUES ('registration.request', 'email', :key_id, :hmac, "
                    "pg_catalog.clock_timestamp() - interval '2 minutes', 1, "
                    "pg_catalog.clock_timestamp() - interval '1 minute', "
                    "'registration-rate-limit-v1', 1, "
                    "pg_catalog.clock_timestamp() - interval '2 minutes', "
                    "pg_catalog.clock_timestamp() - interval '2 minutes')"
                ),
                {"key_id": f"expired-{index}", "hmac": f"{index + 1:064x}"},
            )
        connection.execute(
            sa.text(
                "UPDATE public.saas_registration_rate_limit_policies "
                "SET current_rows = :count "
                "WHERE action = 'registration.request' AND subject_kind = 'email'"
            ),
            {"count": count},
        )


def test_ttl_prune_is_bounded_and_consumption_releases_expired_capacity(
    rate_limit_postgresql_engine: Engine,
) -> None:
    _insert_expired_rows(rate_limit_postgresql_engine, 3)
    janitor = SharedRegistrationRateLimitJanitor(
        _role_sessions(rate_limit_postgresql_engine, "saas_platform")
    )

    with pytest.raises(DBAPIError) as unbounded:
        with rate_limit_postgresql_engine.begin() as connection:
            connection.exec_driver_sql("SET LOCAL ROLE saas_platform")
            connection.execute(
                sa.text(
                    "SELECT public.saas_prune_registration_rate_limits("
                    "'registration.request', 'email', NULL)"
                )
            )
    assert unbounded.value.orig.sqlstate == "22023"

    assert janitor.prune(action="registration.request", subject_kind="email", batch_size=2) == 2
    with rate_limit_postgresql_engine.connect() as connection:
        assert (
            connection.scalar(sa.text("SELECT count(*) FROM public.saas_registration_rate_limits"))
            == 1
        )
        assert (
            connection.scalar(
                sa.text(
                    "SELECT current_rows FROM public.saas_registration_rate_limit_policies "
                    "WHERE action = 'registration.request' AND subject_kind = 'email'"
                )
            )
            == 1
        )
    assert janitor.prune(action="registration.request", subject_kind="email", batch_size=1000) == 1

    _set_policy(rate_limit_postgresql_engine, limit_count=5, max_rows=1)
    _insert_expired_rows(rate_limit_postgresql_engine, 1)
    assert (
        _consume_result(
            _limiter(rate_limit_postgresql_engine),
            f"opportunistic-prune-{uuid4()}@example.test",
        )
        == "allowed"
    )
    with rate_limit_postgresql_engine.connect() as connection:
        row = connection.execute(
            sa.text(
                "SELECT count(*), pg_catalog.bool_and(expires_at > pg_catalog.clock_timestamp()) "
                "FROM public.saas_registration_rate_limits"
            )
        ).one()
        current_rows = connection.scalar(
            sa.text(
                "SELECT current_rows FROM public.saas_registration_rate_limit_policies "
                "WHERE action = 'registration.request' AND subject_kind = 'email'"
            )
        )
    assert row == (1, True)
    assert current_rows == 1


def test_policy_lock_timeout_fails_closed(rate_limit_postgresql_engine: Engine) -> None:
    limiter = _limiter(rate_limit_postgresql_engine)
    blocker = rate_limit_postgresql_engine.connect()
    transaction = blocker.begin()
    try:
        blocker.execute(
            sa.text(
                "SELECT 1 FROM public.saas_registration_rate_limit_policies "
                "WHERE action = 'registration.request' AND subject_kind = 'email' FOR UPDATE"
            )
        )
        started = monotonic()
        with pytest.raises(OnboardingError) as denied:
            limiter.require(
                action="registration.request",
                subject_kind="email",
                subject=f"lock-timeout-{uuid4()}@example.test",
            )
        elapsed = monotonic() - started
    finally:
        transaction.rollback()
        blocker.close()

    assert denied.value.code == "registration_rate_limit_unavailable"
    assert 0.15 <= elapsed < 3.0
    with rate_limit_postgresql_engine.connect() as connection:
        assert (
            connection.scalar(sa.text("SELECT count(*) FROM public.saas_registration_rate_limits"))
            == 0
        )


def test_commit_failure_wins_over_pending_rate_limit(
    rate_limit_postgresql_engine: Engine,
) -> None:
    _set_policy(rate_limit_postgresql_engine, limit_count=1)
    limiter = _limiter(rate_limit_postgresql_engine)
    subject = f"commit-failure-{uuid4()}@example.test"
    assert _consume_result(limiter, subject) == "allowed"

    def fail_commit(_connection: sa.Connection) -> None:
        raise RuntimeError("injected registration rate-limit commit failure")

    sa.event.listen(rate_limit_postgresql_engine, "commit", fail_commit)
    try:
        with pytest.raises(OnboardingError) as denied:
            limiter.require(
                action="registration.request",
                subject_kind="email",
                subject=subject,
            )
    finally:
        sa.event.remove(rate_limit_postgresql_engine, "commit", fail_commit)

    assert denied.value.code == "registration_rate_limit_unavailable"
    assert isinstance(denied.value.__cause__, RuntimeError)
    with rate_limit_postgresql_engine.connect() as connection:
        counter = connection.execute(
            sa.text("SELECT request_count, version FROM public.saas_registration_rate_limits")
        ).one()
    assert counter == (1, 1)


def test_dynamic_owner_policy_survives_restore_owner_change(
    rate_limit_postgresql_engine: Engine,
) -> None:
    owner_role = f"registration_rate_owner_{uuid4().hex[:12]}"
    with rate_limit_postgresql_engine.connect() as connection:
        original_owner = str(connection.scalar(sa.text("SELECT current_user")))
    quoted_owner = rate_limit_postgresql_engine.dialect.identifier_preparer.quote(owner_role)
    quoted_original = rate_limit_postgresql_engine.dialect.identifier_preparer.quote(
        original_owner
    )
    ownership_changed = False
    try:
        with rate_limit_postgresql_engine.begin() as connection:
            connection.exec_driver_sql(
                f"CREATE ROLE {quoted_owner} NOLOGIN NOSUPERUSER NOCREATEDB "
                "NOCREATEROLE NOREPLICATION NOBYPASSRLS"
            )
            connection.exec_driver_sql(f"GRANT {quoted_owner} TO {quoted_original}")
            connection.exec_driver_sql(
                f"ALTER TABLE public.saas_registration_rate_limit_policies OWNER TO {quoted_owner}"
            )
            connection.exec_driver_sql(
                f"ALTER TABLE public.saas_registration_rate_limits OWNER TO {quoted_owner}"
            )
            connection.exec_driver_sql(
                f"ALTER FUNCTION {_CONSUME_SIGNATURE} OWNER TO {quoted_owner}"
            )
            connection.exec_driver_sql(
                f"ALTER FUNCTION {_PRUNE_SIGNATURE} OWNER TO {quoted_owner}"
            )
            connection.exec_driver_sql(
                f"ALTER FUNCTION {_STATUS_SIGNATURE} OWNER TO {quoted_owner}"
            )
        ownership_changed = True

        subject = f"owner-restore-{uuid4()}@example.test"
        assert _consume_result(_limiter(rate_limit_postgresql_engine), subject) == "allowed"
        with rate_limit_postgresql_engine.connect() as connection:
            owners = set(
                connection.execute(
                    sa.text(
                        "SELECT pg_catalog.pg_get_userbyid(class.relowner) "
                        "FROM pg_catalog.pg_class AS class WHERE class.oid IN ("
                        "'public.saas_registration_rate_limit_policies'::pg_catalog.regclass, "
                        "'public.saas_registration_rate_limits'::pg_catalog.regclass) "
                        "UNION SELECT pg_catalog.pg_get_userbyid(procedure.proowner) "
                        "FROM pg_catalog.pg_proc AS procedure WHERE procedure.oid IN ("
                        "pg_catalog.to_regprocedure(:consume), "
                        "pg_catalog.to_regprocedure(:prune), "
                        "pg_catalog.to_regprocedure(:status))"
                    ),
                    {
                        "consume": _CONSUME_SIGNATURE,
                        "prune": _PRUNE_SIGNATURE,
                        "status": _STATUS_SIGNATURE,
                    },
                ).scalars()
            )
        assert owners == {owner_role}
    finally:
        if ownership_changed:
            with rate_limit_postgresql_engine.begin() as connection:
                connection.exec_driver_sql(
                    f"ALTER FUNCTION {_STATUS_SIGNATURE} OWNER TO {quoted_original}"
                )
                connection.exec_driver_sql(
                    f"ALTER FUNCTION {_PRUNE_SIGNATURE} OWNER TO {quoted_original}"
                )
                connection.exec_driver_sql(
                    f"ALTER FUNCTION {_CONSUME_SIGNATURE} OWNER TO {quoted_original}"
                )
                connection.exec_driver_sql(
                    f"ALTER TABLE public.saas_registration_rate_limits OWNER TO {quoted_original}"
                )
                connection.exec_driver_sql(
                    "ALTER TABLE public.saas_registration_rate_limit_policies "
                    f"OWNER TO {quoted_original}"
                )
        with rate_limit_postgresql_engine.begin() as connection:
            connection.exec_driver_sql(f"DROP ROLE IF EXISTS {quoted_owner}")


def test_counter_evidence_blocks_downgrade_atomically_then_clean_round_trip_succeeds(
    rate_limit_postgresql_engine: Engine,
) -> None:
    root = Path(__file__).resolve().parents[2]
    assert (
        _consume_result(
            _limiter(rate_limit_postgresql_engine),
            f"downgrade-{uuid4()}@example.test",
        )
        == "allowed"
    )
    with rate_limit_postgresql_engine.begin() as connection:
        with pytest.raises(
            RuntimeError,
            match="cannot downgrade p0s000000005 with registration rate-limit counters",
        ):
            command.downgrade(_migration_config(connection), "p0s000000004")
        assert connection.scalar(sa.text("SELECT version_num FROM saas_alembic_version")) == (
            "p0s000000005"
        )
        assert (
            connection.scalar(
                sa.text(
                    "SELECT relforcerowsecurity FROM pg_catalog.pg_class "
                    "WHERE oid = 'public.saas_registration_rate_limits'::pg_catalog.regclass"
                )
            )
            is True
        )
        assert (
            connection.scalar(
                sa.text("SELECT pg_catalog.to_regprocedure(:signature) IS NOT NULL"),
                {"signature": _CONSUME_SIGNATURE},
            )
            is True
        )
        assert (
            connection.scalar(
                sa.text(
                    "SELECT pg_catalog.count(*) FROM information_schema.columns "
                    "WHERE table_schema = 'public' "
                    "AND table_name = 'saas_self_service_registrations' "
                    "AND column_name = 'deletion_manifest_id'"
                )
            )
            == 1
        )
        assert (
            connection.scalar(
                sa.text(
                    "SELECT pg_catalog.count(*) FROM pg_catalog.pg_trigger "
                    "WHERE tgrelid = "
                    "'public.saas_self_service_registrations'::pg_catalog.regclass "
                    "AND tgname = 'trg_self_service_registration_privacy_erasure' "
                    "AND NOT tgisinternal"
                )
            )
            == 1
        )

    with rate_limit_postgresql_engine.begin() as connection:
        connection.execute(sa.text("DELETE FROM public.saas_registration_rate_limits"))
        connection.execute(
            sa.text("UPDATE public.saas_registration_rate_limit_policies SET current_rows = 0")
        )
        command.downgrade(_migration_config(connection), "p0s000000004")
        assert (
            connection.scalar(
                sa.text(
                    "SELECT pg_catalog.to_regclass('public.saas_registration_rate_limits') IS NULL"
                )
            )
            is True
        )
        command.upgrade(_migration_config(connection), "head")
        connection.exec_driver_sql(
            (root / "saas/control_plane/postgresql_roles.sql").read_text(encoding="utf-8")
        )
        assert connection.scalar(sa.text("SELECT version_num FROM saas_alembic_version")) == (
            "p0s000000006"
        )
        assert (
            connection.scalar(
                sa.text("SELECT pg_catalog.to_regprocedure(:signature) IS NOT NULL"),
                {"signature": _CONSUME_SIGNATURE},
            )
            is True
        )
