"""Keep restore digests complete for R while preserving bounded legacy fixture hashes."""

from __future__ import annotations

import hashlib
import json

import pytest
import sqlalchemy as sa

from saas.production import postgresql_restore as restore

_P0 = "p0s000000015"
_R = "lm2r00000001"
_S = "lm2s00000001"
_T = "lm2t00000001"
_D = "dp1a00000001"
_R_TABLES = {
    "saas_model_connections",
    "saas_model_credential_versions",
    "saas_model_deployment_versions",
    "saas_model_gateway_evidence",
    "saas_model_projection_operations",
    "saas_model_projection_transitions",
    "saas_model_publication_commands",
    "saas_model_publication_disablements",
    "saas_model_publication_revocations",
    "saas_model_publication_versions",
    "saas_model_run_tokens",
    "saas_model_test_funding_policies",
    "saas_model_verification_budget_bindings",
    "saas_model_verification_commands",
    "saas_model_verification_receipts",
}


@pytest.fixture
def digest_connection():
    engine = sa.create_engine("sqlite://")
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql("ATTACH DATABASE ':memory:' AS public")
            yield connection
    finally:
        engine.dispose()


def _populate(connection, head):
    connection.exec_driver_sql("CREATE TABLE public.saas_alembic_version (version_num TEXT)")
    connection.execute(
        sa.text("INSERT INTO public.saas_alembic_version VALUES (:head)"), {"head": head}
    )
    for table in restore._digest_tables_for_schema(head):
        if table == "saas_alembic_version":
            continue
        connection.exec_driver_sql(
            f'CREATE TABLE public."{table}" (id TEXT PRIMARY KEY, value TEXT)'
        )
        connection.execute(
            sa.text(f'INSERT INTO public."{table}" VALUES (:id, :value)'),
            {"id": "fixture-1", "value": "synthetic-restore-evidence"},
        )


@pytest.mark.parametrize("head", [_R, _S, _T, _D])
def test_r_digest_adds_all_fifteen_new_tables_without_removing_legacy_scope(head):
    old = restore._digest_tables_for_schema(_P0)
    new = restore._digest_tables_for_schema(head)
    assert old == restore._SELECTED_HASH_TABLES
    assert new[: len(old)] == old
    assert set(new) - set(old) == _R_TABLES | (
        {"saas_development_preview_grants"} if head == _D else set()
    )
    assert len(new) == len(set(new)) == len(old) + 15 + (head == _D)


@pytest.mark.parametrize("head", [_P0, _R, _S, _T, _D])
def test_bounded_digest_preserves_the_existing_complete_canonical_bytes(digest_connection, head):
    _populate(digest_connection, head)
    digest, counts = restore._digest_on_connection(digest_connection)
    canonical = {}
    for table in restore._digest_tables_for_schema(head):
        canonical[table] = (
            [{"version_num": head}]
            if table == "saas_alembic_version"
            else [{"id": "fixture-1", "value": "synthetic-restore-evidence"}]
        )
    expected = hashlib.sha256(
        json.dumps(canonical, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()
    assert digest == expected and set(counts.values()) == {1}
    assert set(counts) == set(canonical)


@pytest.mark.parametrize("head", [_R, _S, _T, _D])
def test_r_evidence_change_changes_the_digest_even_if_legacy_rows_do_not_change(
    digest_connection, head
):
    _populate(digest_connection, head)
    before, counts = restore._digest_on_connection(digest_connection)
    digest_connection.exec_driver_sql(
        "UPDATE public.saas_model_gateway_evidence SET value='changed'"
    )
    after, after_counts = restore._digest_on_connection(digest_connection)
    assert before != after and counts == after_counts


def test_development_preview_revocation_changes_the_restore_digest(digest_connection):
    _populate(digest_connection, _D)
    before, counts = restore._digest_on_connection(digest_connection)
    digest_connection.exec_driver_sql(
        "UPDATE public.saas_development_preview_grants SET value='revoked'"
    )
    after, after_counts = restore._digest_on_connection(digest_connection)
    assert before != after and counts == after_counts


@pytest.mark.parametrize("heads", [["future"], ["lm2q00000001"], [], [_P0, _R]])
def test_unknown_or_ambiguous_schema_is_rejected_before_other_table_reads(
    digest_connection, heads
):
    digest_connection.exec_driver_sql(
        "CREATE TABLE public.saas_alembic_version (version_num TEXT)"
    )
    for head in heads:
        digest_connection.execute(
            sa.text("INSERT INTO public.saas_alembic_version VALUES (:head)"), {"head": head}
        )
    with pytest.raises(restore.PostgreSqlRestoreContractError, match="schema"):
        restore._digest_on_connection(digest_connection)


@pytest.mark.parametrize("head", [_R, _S, _T, _D])
def test_fixture_limit_is_not_a_silent_truncation(digest_connection, head):
    _populate(digest_connection, head)
    digest_connection.execute(
        sa.text("INSERT INTO public.users VALUES (:id, :value)"),
        [
            {"id": f"row-{index}", "value": "bounded"}
            for index in range(restore._MAX_DIGEST_ROWS_PER_TABLE)
        ],
    )
    with pytest.raises(restore.PostgreSqlRestoreContractError, match="fixture row bound"):
        restore._digest_on_connection(digest_connection)


@pytest.mark.parametrize("head", [_R, _S, _T, _D])
def test_missing_r_table_is_not_treated_as_an_empty_restored_table(digest_connection, head):
    _populate(digest_connection, head)
    digest_connection.exec_driver_sql("DROP TABLE public.saas_model_gateway_evidence")
    with pytest.raises(restore.PostgreSqlRestoreContractError, match="missing hash table"):
        restore._digest_on_connection(digest_connection)
