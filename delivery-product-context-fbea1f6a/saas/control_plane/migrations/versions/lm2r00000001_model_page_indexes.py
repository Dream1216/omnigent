"""Support deterministic, bounded model-management traversal.

Revision ID: lm2r00000001
Revises: lm2q00000001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "lm2r00000001"
down_revision = "lm2q00000001"
branch_labels = None
depends_on = None

_INDEXES = (
    ("ix_model_connection_page", "saas_model_connections", ("created_at", "id")),
    ("ix_model_deployment_page", "saas_model_deployment_versions", ("created_at", "id")),
    (
        "ix_model_projection_deployment_page",
        "saas_model_projection_operations",
        ("deployment_version_id", "action", "created_at", "id"),
    ),
    (
        "ix_model_projection_credential_state",
        "saas_model_projection_operations",
        ("credential_version_id", "status", "action", "id"),
    ),
    ("ix_model_publication_page", "saas_model_publication_versions", ("created_at", "id")),
    (
        "ix_model_publication_tenant_page",
        "saas_model_publication_versions",
        ("tenant_id", "created_at", "id"),
    ),
)

_RETIRED_INDEXES = (
    (
        "ix_model_budget_test_day",
        "saas_model_provider_budget_reservations",
        ("provider_id", "purpose", "usage_date"),
    ),
    ("ix_model_projection_status", "saas_model_projection_operations", ("status", "created_at")),
    ("ix_model_run_token_run", "saas_model_run_tokens", ("run_id", "fence_token")),
    (
        "ix_model_gateway_evidence_scope",
        "saas_model_gateway_evidence",
        ("tenant_id", "reservation_id", "created_at"),
    ),
)


def _begin_sqlite_transaction() -> None:
    bind = op.get_bind()
    if (
        bind.dialect.name == "sqlite"
        and getattr(bind.connection.driver_connection, "in_transaction", True) is False
    ):
        bind.exec_driver_sql("BEGIN")


def upgrade() -> None:
    _begin_sqlite_transaction()
    for name, table, columns in _INDEXES:
        op.create_index(name, table, list(columns))
    op.create_index(
        "ix_model_budget_admitted_test_day",
        "saas_model_provider_budget_reservations",
        ["provider_id", "purpose", "usage_date", "id"],
        postgresql_where=sa.text("admitted_microusd > 0"),
        sqlite_where=sa.text("admitted_microusd > 0"),
    )
    for name, table, _columns in _RETIRED_INDEXES:
        op.drop_index(name, table_name=table)
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "GRANT SELECT (id,created_at) ON public.saas_model_publication_versions TO saas_app"
        )


def downgrade() -> None:
    _begin_sqlite_transaction()
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "REVOKE SELECT (id,created_at) ON public.saas_model_publication_versions FROM saas_app"
        )
    for name, table, columns in _RETIRED_INDEXES:
        op.create_index(name, table, list(columns))
    op.drop_index(
        "ix_model_budget_admitted_test_day", table_name="saas_model_provider_budget_reservations"
    )
    for name, table, _columns in reversed(_INDEXES):
        op.drop_index(name, table_name=table)
