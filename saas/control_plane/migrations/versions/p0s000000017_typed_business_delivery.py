"""Add exact typed business delivery facts and native invalidation/audit sources.

Revision ID: p0s000000017
Revises: p0s000000016

Historical receipts are never dropped. Ordinary downgrade and an unknown archive
fail closed until the reviewed preserving driver supplies its verified phase.
"""

from __future__ import annotations

import hashlib

import sqlalchemy as sa
from alembic import op

revision = "p0s000000017"
down_revision = "p0s000000016"
branch_labels = None
depends_on = None

ROLES = ("saas_usage_consumer", "saas_audit_delivery", "saas_revocation_consumer")
TABLES = (
    "saas_usage_reconciliation_ingress",
    "saas_platform_audit_journal_deliveries",
    "saas_revocation_replica_applied",
)
OWNER_READ_TABLES = (
    "saas_usage_events",
    "saas_pricing_snapshots",
    "saas_platform_audit_events",
    "saas_global_users",
    "saas_service_accounts",
    "saas_api_credentials",
)
AUTH_TOPICS = (
    "authorization_user",
    "authorization_service_account",
    "authorization_api_credential",
)
TYPED_TOPICS = ("platform_audit", *AUTH_TOPICS)

TABLE_DDL = (
    (
        "CREATE TABLE saas_usage_reconciliation_ingress (\n        "
        "outbox_event_id UUID NOT NULL, \n        tenant_id UUID NOT NULL,"
        " \n        usage_event_id UUID NOT NULL, \n        pricing_snapshot_id "
        "UUID NOT NULL, \n        source_request_hash VARCHAR(64) NOT NULL,"
        " \n        facts_sha256 VARCHAR(64) NOT NULL, \n        facts JSON NOT "
        "NULL, \n        product_revision VARCHAR(40) NOT NULL, \n        "
        "source_created_at TIMESTAMP WITH TIME ZONE NOT NULL, \n        "
        "received_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, \n        "
        "PRIMARY KEY (outbox_event_id), \n        CONSTRAINT "
        "fk_usage_ingress_source FOREIGN KEY(tenant_id, usage_event_id) "
        "REFERENCES saas_usage_events (tenant_id, id) ON DELETE RESTRICT,"
        " \n        CONSTRAINT fk_usage_ingress_pricing FOREIGN KEY(tenant_id, "
        "pricing_snapshot_id) REFERENCES saas_pricing_snapshots (tenant_id, id)"
        " ON DELETE RESTRICT, \n        CONSTRAINT ck_usage_ingress_request "
        "CHECK (length(source_request_hash) = 64), \n        CONSTRAINT "
        "ck_usage_ingress_facts CHECK (length(facts_sha256) = 64), \n        "
        "CONSTRAINT ck_usage_ingress_product CHECK (length(product_revision) = "
        "40), \n        FOREIGN KEY(outbox_event_id) REFERENCES "
        "saas_control_plane_outbox (id) ON DELETE RESTRICT, \n        UNIQUE "
        "(usage_event_id)\n)"
    ),
    (
        "CREATE INDEX ix_usage_ingress_tenant_received ON "
        "saas_usage_reconciliation_ingress (tenant_id, received_at)"
    ),
    (
        "CREATE TABLE saas_platform_audit_journal_deliveries (\n        "
        "outbox_event_id UUID NOT NULL, \n        audit_event_id UUID NOT NULL,"
        " \n        audit_sequence INTEGER NOT NULL, \n        tenant_id UUID,"
        " \n        event_hash VARCHAR(64) NOT NULL, \n        journal_sha256 "
        "VARCHAR(64) NOT NULL, \n        storage_key VARCHAR(1024) NOT NULL,"
        " \n        storage_version VARCHAR(256) NOT NULL, \n        "
        "signing_key_id VARCHAR(256) NOT NULL, \n        product_revision "
        "VARCHAR(40) NOT NULL, \n        source_created_at TIMESTAMP WITH TIME "
        "ZONE NOT NULL, \n        received_at TIMESTAMP WITH TIME ZONE DEFAULT "
        "now() NOT NULL, \n        PRIMARY KEY (outbox_event_id), \n        "
        "CONSTRAINT ck_audit_journal_sequence CHECK (audit_sequence > 0),"
        " \n        CONSTRAINT ck_audit_journal_event_hash CHECK "
        "(length(event_hash) = 64), \n        CONSTRAINT ck_audit_journal_sha256"
        " CHECK (length(journal_sha256) = 64), \n        CONSTRAINT "
        "ck_audit_journal_version CHECK (length(storage_version) > 0),"
        " \n        CONSTRAINT ck_audit_journal_signer CHECK "
        "(length(signing_key_id) > 0), \n        CONSTRAINT "
        "ck_audit_journal_product CHECK (length(product_revision) = 40),"
        " \n        FOREIGN KEY(outbox_event_id) REFERENCES "
        "saas_control_plane_outbox (id) ON DELETE RESTRICT, \n        UNIQUE "
        "(audit_event_id), \n        FOREIGN KEY(audit_event_id) REFERENCES "
        "saas_platform_audit_events (id) ON DELETE RESTRICT, \n        UNIQUE "
        "(audit_sequence), \n        FOREIGN KEY(tenant_id) REFERENCES "
        "saas_tenants (id) ON DELETE RESTRICT\n)"
    ),
    (
        "CREATE TABLE saas_revocation_replica_applied (\n        outbox_event_id"
        " UUID NOT NULL, \n        replica_uid UUID NOT NULL, \n        "
        "process_boot_uid UUID NOT NULL, \n        listener_epoch_uid UUID NOT NULL, "
        "\n        product_revision VARCHAR(40) "
        "NOT NULL, \n        version_floor BIGINT NOT NULL, \n        "
        "applied_digest VARCHAR(64) NOT NULL, \n        source_created_at "
        "TIMESTAMP WITH TIME ZONE NOT NULL, \n        applied_at TIMESTAMP WITH "
        "TIME ZONE DEFAULT now() NOT NULL, \n        PRIMARY KEY "
        "(outbox_event_id, replica_uid, process_boot_uid, listener_epoch_uid, product_revision),"
        " \n        CONSTRAINT ck_revocation_applied_version CHECK "
        "(version_floor > 0), \n        CONSTRAINT ck_revocation_applied_digest "
        "CHECK (length(applied_digest) = 64), \n        CONSTRAINT "
        "ck_revocation_applied_product CHECK (length(product_revision) = 40),"
        " \n        FOREIGN KEY(outbox_event_id) REFERENCES "
        "saas_control_plane_outbox (id) ON DELETE RESTRICT\n)"
    ),
    (
        "CREATE INDEX ix_revocation_replica_applied ON "
        "saas_revocation_replica_applied (replica_uid, applied_at)"
    ),
)

NATIVE_SQL_SHA256 = "bb3fe5417a077e78d870298c81e081b142b27c70b69f20adca10d8dbc58d6e1d"


def _preflight():
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    rows = {
        r.rolname: r
        for r in bind.execute(
            sa.text(
                "SELECT rolname,rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolreplication,"
                "rolbypassrls,rolinherit,rolconnlimit,rolconfig FROM pg_catalog.pg_roles "
                "WHERE rolname IN ('saas_usage_consumer','saas_audit_delivery',"
                "'saas_revocation_consumer')"
            )
        )
    }
    for name in ROLES:
        row = rows.get(name)
        if row is None or tuple(row)[1:] != (
            False,
            False,
            False,
            False,
            False,
            False,
            True,
            -1,
            None,
        ):
            raise RuntimeError("typed delivery requires safe operator-owned NOLOGIN principals")
    if bind.execute(
        sa.text(
            "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m "
            "JOIN pg_catalog.pg_roles r ON r.oid=m.member WHERE r.rolname IN "
            "('saas_usage_consumer','saas_audit_delivery','saas_revocation_consumer'))"
        )
    ).scalar_one():
        raise RuntimeError("typed delivery base roles must not inherit other authorities")
    if bind.execute(
        sa.text(
            "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace "
            "WHERE nspname LIKE 'saas_delivery_archive_%')"
        )
    ).scalar_one():
        raise RuntimeError(
            "trusted preserving-driver archive verification is required before re-upgrade"
        )
    relations = (*OWNER_READ_TABLES, "saas_control_plane_outbox")
    for name in relations:
        if not bind.execute(
            sa.text(
                "SELECT c.relowner=(SELECT oid FROM pg_catalog.pg_roles "
                "WHERE rolname=current_user) AND c.relrowsecurity AND c.relforcerowsecurity "
                "FROM pg_catalog.pg_class c WHERE c.oid=to_regclass(:name)"
            ),
            {"name": "public." + name},
        ).scalar_one():
            raise RuntimeError("typed source functions require original owner and FORCE RLS")


def upgrade():
    _preflight()
    bind = op.get_bind()
    for statement in TABLE_DDL:
        if bind.dialect.name != "postgresql":
            statement = (
                statement.replace("UUID", "CHAR(32)")
                .replace("TIMESTAMP WITH TIME ZONE", "DATETIME")
                .replace("DEFAULT now()", "DEFAULT CURRENT_TIMESTAMP")
            )
        op.execute(statement)
    if bind.dialect.name == "postgresql":
        from saas.control_plane.migrations.typed_business_delivery import NATIVE_SQL

        native = NATIVE_SQL.encode("utf-8")
        if hashlib.sha256(native).hexdigest() != NATIVE_SQL_SHA256:
            raise RuntimeError("P17 native DDL does not match its frozen migration")
        # Compile literal percent signs in PL/pgSQL %ROWTYPE through SQLAlchemy.
        # No statement or parameter originates from an operator-supplied file.
        op.execute(sa.text(native.decode("utf-8")))


def downgrade():
    raise RuntimeError(
        "P17 downgrade requires reviewed preserving-driver archive; never DROP durable facts"
    )
