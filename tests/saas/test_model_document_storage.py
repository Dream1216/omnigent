from __future__ import annotations

from hashlib import sha256

import pytest
import sqlalchemy as sa

from saas.control_plane.model_document_storage import (
    ModelDocumentStorage,
    decode_model_document,
    encode_model_document,
    model_document_format,
)
from saas.control_plane.model_routing_models import (
    ModelDeploymentVersionRecord,
    ModelPublicationVersionRecord,
    ModelVerificationCommandRecord,
    ModelVerificationReceiptRecord,
)
from saas.control_plane.platform_models import ModelGatewayEvidenceRecord

DOCUMENT_COLUMNS = [
    (ModelDeploymentVersionRecord, "canonical_configuration", 16376),
    (ModelVerificationCommandRecord, "canonical_price", 8192),
    (ModelVerificationReceiptRecord, "canonical_evidence", 8192),
    (ModelPublicationVersionRecord, "canonical_snapshot", 16376),
    (ModelPublicationVersionRecord, "canonical_readiness", 16376),
    (ModelGatewayEvidenceRecord, "canonical_evidence", 16376),
]


@pytest.fixture(params=DOCUMENT_COLUMNS, ids=lambda row: row[0].__tablename__ + "." + row[1])
def document_column(request):
    record, column, limit = request.param
    engine = sa.create_engine("sqlite+pysqlite://")
    table = sa.Table(
        "document_probe",
        sa.MetaData(),
        sa.Column("value", record.__table__.c[column].type.copy(), nullable=False),
    )
    table.metadata.create_all(engine)
    try:
        yield engine, table, limit
    finally:
        engine.dispose()


def test_each_document_column_is_binary_without_changing_canonical_bytes(document_column):
    engine, table, _limit = document_column
    value = '{"model":"合成候选","schema_version":1}'
    before = sha256(value.encode()).hexdigest()
    with engine.begin() as connection:
        connection.execute(table.insert().values(value=value))
        raw, storage = connection.exec_driver_sql(
            "SELECT value,typeof(value) FROM document_probe"
        ).one()
        assert storage == "blob"
        assert raw == b"OGMD\x01\x00\x00" + value.encode()
        decoded = connection.scalar(sa.select(table.c.value))
        assert decoded == value and sha256(decoded.encode()).hexdigest() == before


def test_each_document_column_enforces_stored_byte_cap_before_sql(document_column):
    engine, table, limit = document_column
    with engine.begin() as connection:
        connection.execute(table.insert().values(value="x" * limit))
        assert (
            len(connection.exec_driver_sql("SELECT value FROM document_probe").scalar()) <= 16383
        )
    with pytest.raises(sa.exc.StatementError, match="invalid model document storage"):
        with engine.begin() as connection:
            connection.execute(table.insert().values(value="密" * (limit // 3 + 1)))
    with engine.connect() as connection:
        assert connection.scalar(sa.select(sa.func.count()).select_from(table)) == 1


@pytest.mark.parametrize("limit", [0, -1, 16377, True, None, "8192"])
def test_caller_cannot_expand_the_physical_document_limit(limit):
    for operation in (
        lambda: ModelDocumentStorage(limit),
        lambda: encode_model_document("{}", max_payload_bytes=limit),
        lambda: decode_model_document(b"OGMD\x01\x00\x00{}", max_payload_bytes=limit),
    ):
        with pytest.raises(ValueError, match=r"^invalid model document storage$"):
            operation()


@pytest.mark.parametrize(
    "raw",
    [
        b"{}",
        "wrapped as text",
        None,
        b"OGMD\x02\x00\x00{}",
        b"OGMD\x01\x01\x00{}",
        b"OGMD\x01\x00\x01{}",
        b"OGMD\x01\x00\x00",
        b"OGMD\x01\x00\x00\xff",
        b"OGMD\x01\x00\x00" + b"x" * 16377,
    ],
)
def test_reader_rejects_unknown_encrypted_or_malformed_documents(raw):
    with pytest.raises(ValueError, match=r"^invalid model document storage$"):
        decode_model_document(raw)


def test_document_memoryview_roundtrip_does_not_normalize_public_hash_material():
    value = '{ "schema_version" : 1 }'
    assert decode_model_document(memoryview(encode_model_document(value))) == value
    with pytest.raises(ValueError, match=r"^invalid model document storage$"):
        encode_model_document("\ud800")


def test_raw_database_writer_cannot_store_an_unknown_document_variant():
    engine = sa.create_engine("sqlite+pysqlite://")
    table = sa.Table(
        "raw_probe",
        sa.MetaData(),
        sa.Column("value", ModelDocumentStorage()),
        *model_document_format("ck_raw_document_format", "value"),
    )
    try:
        table.metadata.create_all(engine)
        with pytest.raises(sa.exc.IntegrityError, match="ck_raw_document_format"):
            with engine.begin() as connection:
                connection.exec_driver_sql(
                    "INSERT INTO raw_probe(value) VALUES (?)", (b"OGMD\x01\x01\x00{}",)
                )
    finally:
        engine.dispose()
