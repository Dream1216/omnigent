from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
from uuid import UUID, uuid4

import pytest
import sqlalchemy as sa

from saas.control_plane.model_routing_models import (
    ModelProjectionOperationRecord,
    ModelRunTokenRecord,
)
from saas.control_plane.platform_models import ModelGatewayEvidenceRecord
from tests.saas.test_model_connections import _fixture


@pytest.mark.parametrize(
    ("model", "retired"),
    (
        (ModelProjectionOperationRecord, "ix_model_projection_status"),
        (ModelRunTokenRecord, "ix_model_run_token_run"),
        (ModelGatewayEvidenceRecord, "ix_model_gateway_evidence_scope"),
    ),
)
def test_model_metadata_does_not_recreate_the_unused_or_redundant_index(model, retired):
    assert retired not in {index.name for index in model.__table__.indexes}


@pytest.mark.parametrize("kind", ("operation", "token", "evidence"))
def test_representative_lookups_keep_their_unique_index_without_retired_indexes(kind):
    _service, factory, actor, _cipher, client, _headers = _fixture()
    engine, at = factory.kw["bind"], datetime.now(timezone.utc)
    tenant, connection, credential = uuid4(), uuid4(), uuid4()
    phases = ("request", "in_flight", "uncertain", "settled", "released", "expired")
    try:
        with factory.begin() as db:
            for number in range(1, 151):
                identifier = UUID(int=number)
                if kind == "operation":
                    db.add(
                        ModelProjectionOperationRecord(
                            id=identifier,
                            connection_id=connection,
                            credential_version_id=credential,
                            deployment_version_id=None,
                            action="create_connection",
                            actor_principal_id=actor.principal_id,
                            idempotency_key=f"synthetic-{number}",
                            request_hash="a" * 64,
                            status="requested",
                            version=1,
                            created_at=at,
                            updated_at=at,
                        )
                    )
                elif kind == "token":
                    db.add(
                        ModelRunTokenRecord(
                            id=identifier,
                            token_hash=sha256(identifier.bytes).hexdigest(),
                            tenant_id=tenant,
                            space_id=uuid4(),
                            project_id=uuid4(),
                            actor_id=uuid4(),
                            run_id=identifier,
                            capability_id=uuid4(),
                            fence_token=7,
                            generation=0,
                            parent_id=None,
                            issued_at=at,
                            expires_at=at + timedelta(hours=8),
                        )
                    )
                else:
                    for version, phase in enumerate(phases, 1):
                        db.add(
                            ModelGatewayEvidenceRecord(
                                id=uuid4(),
                                tenant_id=tenant,
                                reservation_id=identifier,
                                phase=phase,
                                budget_version=version,
                                canonical_evidence="{}",
                                evidence_sha256=sha256(b"{}").hexdigest(),
                                created_at=at,
                            )
                        )
        target = UUID(int=75)
        if kind == "operation":
            model, columns, count = ModelProjectionOperationRecord, ("id",), 1
            query = sa.select(model.id).where(model.id == target)
        elif kind == "token":
            model, columns, count = ModelRunTokenRecord, ("run_id", "fence_token", "generation"), 1
            query = sa.select(model.id).where(
                model.run_id == target, model.fence_token == 7, model.generation == 0
            )
        else:
            model, columns, count = (
                ModelGatewayEvidenceRecord,
                ("reservation_id", "budget_version"),
                6,
            )
            query = (
                sa.select(model.id)
                .where(model.reservation_id == target, model.tenant_id == tenant)
                .order_by(model.budget_version)
            )
        statements = []

        def capture(_connection, _cursor, sql, parameters, _context, _many):
            statements.append((sql, parameters))

        sa.event.listen(engine, "before_cursor_execute", capture)
        try:
            with engine.connect() as db:
                assert len(db.execute(query).all()) == count
        finally:
            sa.event.remove(engine, "before_cursor_execute", capture)
        assert len(statements) == 1
        with engine.connect() as db:
            indexes = db.exec_driver_sql(f"PRAGMA index_list('{model.__tablename__}')").all()
            matching = [
                row[1]
                for row in indexes
                if tuple(
                    column[2] for column in db.exec_driver_sql(f"PRAGMA index_info('{row[1]}')")
                )
                == columns
            ]
            assert len(matching) == 1
            sql, parameters = statements[0]
            plan = db.exec_driver_sql("EXPLAIN QUERY PLAN " + sql, parameters).all()
        assert any("SEARCH" in row[-1] and matching[0] in row[-1] for row in plan)
        assert all("TEMP B-TREE" not in row[-1] for row in plan)
    finally:
        client.close()
        engine.dispose()
