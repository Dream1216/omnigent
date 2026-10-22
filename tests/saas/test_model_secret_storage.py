from __future__ import annotations

import pytest
import sqlalchemy as sa

from saas.control_plane.model_secret_storage import (
    MAX_STORED_SECRET_BYTES,
    ModelCiphertextStorage,
    decode_model_ciphertext,
    encode_model_ciphertext,
)


@pytest.mark.parametrize("value", ["ciphertext:opaque", "osvault:a2V5:vault:v1:opaque", "密文"])
def test_ciphertext_roundtrip_preserves_backend_payload(value):
    raw = encode_model_ciphertext(value)
    assert raw.startswith(b"OGSM\x01\x01\x01")
    assert decode_model_ciphertext(raw) == decode_model_ciphertext(memoryview(raw)) == value


def test_stored_byte_limit_includes_the_envelope_and_utf8_encoding():
    raw = encode_model_ciphertext("x" * (MAX_STORED_SECRET_BYTES - 7))
    assert len(raw) == MAX_STORED_SECRET_BYTES
    assert len(encode_model_ciphertext("密" * 5458)) == 16381
    for value in ("x" * (MAX_STORED_SECRET_BYTES - 6), "密" * 5459):
        with pytest.raises(ValueError, match=r"^invalid model secret storage$"):
            encode_model_ciphertext(value)


@pytest.mark.parametrize("value", ["", b"ciphertext", None, 1, "\ud800"])
def test_invalid_cipher_output_is_rejected_without_echoing_the_value(value):
    with pytest.raises(ValueError, match=r"^invalid model secret storage$"):
        encode_model_ciphertext(value)


@pytest.mark.parametrize(
    "raw",
    [
        b"ciphertext:unwrapped",
        b"OGSM\x01\x00\x01plaintext",
        b"OGSM\x02\x01\x01unknown-version",
        b"OGSM\x01\x01\x02unknown-scheme",
        b"OGSM\x01\x01\x01",
        b"OGSM\x01\x01\x01\xff",
        b"OGSM\x01\x01\x01" + b"x" * 16377,
        "OGSM wrapped as database text",
    ],
)
def test_reader_rejects_plaintext_unknown_and_malformed_envelopes(raw):
    with pytest.raises(ValueError, match=r"^invalid model secret storage$"):
        decode_model_ciphertext(raw)


def test_sqlalchemy_roundtrip_uses_binary_storage_and_keeps_the_python_contract():
    engine = sa.create_engine("sqlite+pysqlite://")
    metadata = sa.MetaData()
    table = sa.Table("cipher_probe", metadata, sa.Column("cipher", ModelCiphertextStorage()))
    try:
        metadata.create_all(engine)
        with engine.begin() as connection:
            connection.execute(table.insert().values(cipher="opaque-backend-envelope"))
            assert connection.scalar(sa.select(table.c.cipher)) == "opaque-backend-envelope"
            assert (
                connection.exec_driver_sql("SELECT typeof(cipher) FROM cipher_probe").scalar()
                == "blob"
            )
    finally:
        engine.dispose()
