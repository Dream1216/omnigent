"""Read-only storage attestation for the locked LiteLLM AES-GCM profile."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID

import sqlalchemy as sa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from omnigent.db.utils import make_named_managed_session_maker
from saas.control_plane.model_deployments import CompiledModelDeploymentDraft

ATTESTATION_CONTRACT = "litellm-1.105.1-aes-gcm-v1"
ATTESTATION_LOGIN = "omnigent_litellm_attestor"
ATTESTATION_ROLE = "omnigent_litellm_attestation_read"
_CIPHER_PREFIX = "v2:gcm:"
_DISABLED_FLAGS = frozenset(
    {
        "allow_client_keepalive_override",
        "use_in_pass_through",
        "use_litellm_proxy",
        "use_xai_oauth",
        "merge_reasoning_content_in_choices",
    }
)
_READ_COLUMNS = {
    "LiteLLM_ProxyModelTable": {
        "model_id",
        "model_name",
        "litellm_params",
        "model_info",
        "blocked",
    },
    "LiteLLM_CredentialsTable": {
        "credential_id",
        "credential_name",
        "credential_values",
        "credential_info",
    },
    "LiteLLM_Config": {"param_name", "param_value"},
}


class LiteLLMAttestationError(RuntimeError):
    """Never carry a raw row, ciphertext, key, DSN, or database exception."""

    def __init__(self, code: str = "litellm_configuration_drift") -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class LiteLLMConfigurationAttestation:
    deployment_id: UUID
    credential_version_id: UUID
    configuration_sha256: str
    stored_state_sha256: str
    observed_at: datetime
    contract: str = ATTESTATION_CONTRACT
    scope: str = "stored_model_credential_and_database_overlays"

    def evidence(self) -> dict[str, object]:
        return {
            "contract": self.contract,
            "scope": self.scope,
            "deployment_id": str(self.deployment_id),
            "credential_version_id": str(self.credential_version_id),
            "configuration_sha256": self.configuration_sha256,
            "stored_state_sha256": self.stored_state_sha256,
            "observed_at": self.observed_at.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class LiteLLMStoredConfiguration:
    models: Sequence[Mapping[str, object]] = field(repr=False)
    credentials: Sequence[Mapping[str, object]] = field(repr=False)
    settings: Sequence[Mapping[str, object]] = field(repr=False)


def _document(value: object) -> dict[str, object]:
    if isinstance(value, str):
        if len(value) > 65536:
            raise LiteLLMAttestationError()
        value = json.loads(value)
    if not isinstance(value, dict) or len(value) > 512:
        raise LiteLLMAttestationError()
    return value


def _key(salt_key: str) -> bytes:
    if (
        not isinstance(salt_key, str)
        or not 32 <= len(salt_key) <= 4096
        or not all(33 <= ord(char) <= 126 for char in salt_key)
    ):
        raise LiteLLMAttestationError("litellm_attestation_configuration_invalid")
    return hashlib.sha256(salt_key.encode("utf-8")).digest()


def _decrypt(value: object, key: bytes) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith(_CIPHER_PREFIX)
        or not 48 <= len(value) <= 16384
    ):
        raise LiteLLMAttestationError("litellm_attestation_cipher_unsupported")
    encoded = value.removeprefix(_CIPHER_PREFIX)
    sealed = base64.b64decode(encoded, altchars=b"-_", validate=True)
    if len(sealed) < 28:
        raise LiteLLMAttestationError()
    # This is the locked upstream wire format, not a platform encryption writer.
    return AESGCM(key).decrypt(sealed[:12], sealed[12:], None).decode("utf-8")


def attest_litellm_configuration(
    snapshot: LiteLLMStoredConfiguration,
    *,
    draft: CompiledModelDeploymentDraft,
    credential_name: str,
    expected_api_key: str,
    salt_key: str,
    provider_base_url: str = "https://api.deepseek.com",
) -> LiteLLMConfigurationAttestation:
    """Compare hidden values in trusted memory; retain only a ciphertext-state digest."""

    try:
        if (
            not isinstance(expected_api_key, str)
            or not 16 <= len(expected_api_key) <= 4096
            or not all(33 <= ord(char) <= 126 for char in expected_api_key)
            or re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", credential_name) is None
            or len(snapshot.models) != 1
            or len(snapshot.credentials) != 1
        ):
            raise LiteLLMAttestationError()
        # The locked server records this empty license baseline even with no auto-router.
        # It is not an editable runtime overlay; nonempty or unfamiliar rows are rejected.
        if len(snapshot.settings) > 1 or any(
            row.get("param_name") != "auto_router_tuning_baseline_v3"
            or _document(row.get("param_value")) != {}
            for row in snapshot.settings
        ):
            raise LiteLLMAttestationError("litellm_attestation_overlay_drift")
        key = _key(salt_key)
        model, credential = snapshot.models[0], snapshot.credentials[0]
        if (
            model.get("model_id") != str(draft.deployment_id)
            or model.get("model_name") != draft.alias
            or model.get("blocked") is not False
            or credential.get("credential_name") != credential_name
            or not isinstance(credential.get("credential_id"), str)
            or not credential["credential_id"]
        ):
            raise LiteLLMAttestationError("litellm_attestation_identity_drift")
        values = _document(credential["credential_values"])
        info = _document(credential["credential_info"])
        if set(values) != {"api_key"} or {
            name: value for name, value in info.items() if value is not None
        } != {"custom_llm_provider": "deepseek"}:
            raise LiteLLMAttestationError("litellm_attestation_credential_shape_drift")
        actual_key = _decrypt(values["api_key"], key)
        if not hmac.compare_digest(actual_key.encode("utf-8"), expected_api_key.encode("utf-8")):
            raise LiteLLMAttestationError()
        params = _document(model["litellm_params"])
        expected: dict[str, object] = {
            "model": "deepseek/" + draft.public_model_id,
            "api_base": provider_base_url,
            "litellm_credential_name": credential_name,
            "num_retries": 0,
            "max_retries": 0,
        }
        for name, value in expected.items():
            actual = params.get(name)
            if (
                isinstance(value, str)
                and isinstance(actual, str)
                and actual.startswith(_CIPHER_PREFIX)
            ):
                actual = _decrypt(actual, key)
            if actual != value or (
                name in {"num_retries", "max_retries"} and type(actual) is not int
            ):
                raise LiteLLMAttestationError("litellm_attestation_model_parameter_drift")
        if any(
            value is not None and not (name in _DISABLED_FLAGS and value is False)
            for name, value in params.items()
            if name not in expected
        ):
            raise LiteLLMAttestationError("litellm_attestation_model_override")
        metadata = _document(model["model_info"])
        if metadata.get("id") != str(draft.deployment_id) or any(
            value is not None
            and not (
                (name == "db_model" and value is False)
                or (name == "member_auto_router" and value is False)
            )
            for name, value in metadata.items()
            if name != "id"
        ):
            raise LiteLLMAttestationError("litellm_attestation_model_metadata_drift")
        canonical = json.dumps(
            {
                "model": dict(model),
                "credential": dict(credential),
                "settings": [dict(row) for row in snapshot.settings],
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        if len(canonical) > 131072:
            raise LiteLLMAttestationError()
        return LiteLLMConfigurationAttestation(
            deployment_id=draft.deployment_id,
            credential_version_id=draft.credential_version_id,
            configuration_sha256=draft.configuration_sha256,
            stored_state_sha256=hashlib.sha256(canonical).hexdigest(),
            observed_at=datetime.now(timezone.utc),
        )
    except LiteLLMAttestationError:
        raise
    except Exception:  # noqa: BLE001 - cryptography and driver details stay private.
        raise LiteLLMAttestationError() from None


class LiteLLMConfigurationAttestor:
    """Only the trusted projection process receives this read identity and salt."""

    def __init__(self, engine: sa.Engine, *, salt_key: str, expected_database: str) -> None:
        _key(salt_key)
        if engine.dialect.name != "postgresql" or not expected_database:
            raise LiteLLMAttestationError("litellm_attestation_configuration_invalid")
        self.engine, self._salt_key, self._database = engine, salt_key, expected_database
        self._session = make_named_managed_session_maker(
            engine, query_name_prefix="saas.litellm_attestation"
        )

    def validate_authority(self) -> None:
        try:
            with self._session("validate_read_only_storage_identity") as db:
                db.execute(sa.text("SET TRANSACTION READ ONLY"))
                row = db.execute(
                    sa.text(
                        "SELECT current_user, session_user, current_database(), rolcanlogin, "
                        "rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls, "
                        "current_setting('default_transaction_read_only') "
                        "FROM pg_roles WHERE rolname = current_user"
                    )
                ).one()
                if tuple(row) != (
                    ATTESTATION_LOGIN,
                    ATTESTATION_LOGIN,
                    self._database,
                    True,
                    False,
                    False,
                    False,
                    False,
                    False,
                    "on",
                ):
                    raise LiteLLMAttestationError("litellm_attestation_authority_invalid")
                edges = db.execute(
                    sa.text(
                        "SELECT base.rolname, membership.inherit_option, membership.set_option, "
                        "membership.admin_option, base.rolcanlogin, base.rolsuper, "
                        "base.rolcreaterole, base.rolcreatedb, "
                        "base.rolreplication, base.rolbypassrls "
                        "FROM pg_auth_members membership "
                        "JOIN pg_roles base ON base.oid=membership.roleid "
                        "WHERE membership.member="
                        "(SELECT oid FROM pg_roles WHERE rolname=current_user)"
                    )
                ).all()
                if [tuple(row) for row in edges] != [
                    (
                        ATTESTATION_ROLE,
                        True,
                        False,
                        False,
                        False,
                        False,
                        False,
                        False,
                        False,
                        False,
                    )
                ]:
                    raise LiteLLMAttestationError("litellm_attestation_authority_invalid")
                if db.scalar(
                    sa.text(
                        "SELECT has_database_privilege("
                        "current_user, current_database(), 'CREATE,TEMP') "
                        "OR has_schema_privilege(current_user, 'public', 'CREATE')"
                    )
                ):
                    raise LiteLLMAttestationError("litellm_attestation_authority_invalid")
                privileges = db.execute(
                    sa.text(
                        "SELECT relation.relname, attribute.attname, "
                        "has_column_privilege("
                        "current_user, relation.oid, attribute.attnum, 'SELECT'), "
                        "has_column_privilege(current_user, relation.oid, "
                        "attribute.attnum, 'INSERT,UPDATE,REFERENCES') "
                        "FROM pg_class relation JOIN pg_attribute attribute "
                        "ON attribute.attrelid=relation.oid "
                        "WHERE relation.relnamespace='public'::regnamespace "
                        "AND relation.relkind IN ('r','v','m','f','p') "
                        "AND attribute.attnum>0 AND NOT attribute.attisdropped"
                    )
                ).all()
                readable = set()
                for table, column, read, write in privileges:
                    if write or (read and column not in _READ_COLUMNS.get(table, set())):
                        raise LiteLLMAttestationError("litellm_attestation_authority_invalid")
                    if read:
                        readable.add((table, column))
                if readable != {
                    (table, column)
                    for table, columns in _READ_COLUMNS.items()
                    for column in columns
                }:
                    raise LiteLLMAttestationError("litellm_attestation_authority_invalid")
                if db.scalar(
                    sa.text(
                        "SELECT EXISTS (SELECT 1 FROM pg_class "
                        "WHERE relnamespace='public'::regnamespace "
                        "AND relkind IN ('r','v','m','f','p') AND "
                        "has_table_privilege(current_user, oid, "
                        "'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))"
                    )
                ):
                    raise LiteLLMAttestationError("litellm_attestation_authority_invalid")
        except LiteLLMAttestationError:
            raise
        except Exception:  # noqa: BLE001 - reject database errors without DSN context.
            raise LiteLLMAttestationError("litellm_attestation_authority_invalid") from None

    def attest(
        self,
        *,
        draft: CompiledModelDeploymentDraft,
        credential_name: str,
        expected_api_key: str,
        provider_base_url: str = "https://api.deepseek.com",
    ) -> LiteLLMConfigurationAttestation:
        try:
            with self._session("read_one_coherent_runtime_configuration") as db:
                db.connection(execution_options={"isolation_level": "REPEATABLE READ"})
                db.execute(sa.text("SET TRANSACTION READ ONLY"))
                db.execute(sa.text("SET LOCAL statement_timeout = '5000ms'"))
                models = (
                    db.execute(
                        sa.text(
                            "SELECT model_id, model_name, litellm_params, model_info, blocked "
                            'FROM public."LiteLLM_ProxyModelTable" '
                            "WHERE model_id=:id OR model_name=:alias LIMIT 2"
                        ),
                        {"id": str(draft.deployment_id), "alias": draft.alias},
                    )
                    .mappings()
                    .all()
                )
                credentials = (
                    db.execute(
                        sa.text(
                            "SELECT credential_id, credential_name, "
                            "credential_values, credential_info "
                            'FROM public."LiteLLM_CredentialsTable" '
                            "WHERE credential_name=:name LIMIT 2"
                        ),
                        {"name": credential_name},
                    )
                    .mappings()
                    .all()
                )
                settings = (
                    db.execute(
                        sa.text(
                            'SELECT param_name, param_value FROM public."LiteLLM_Config" LIMIT 33'
                        )
                    )
                    .mappings()
                    .all()
                )
                return attest_litellm_configuration(
                    LiteLLMStoredConfiguration(
                        [dict(row) for row in models],
                        [dict(row) for row in credentials],
                        [dict(row) for row in settings],
                    ),
                    draft=draft,
                    credential_name=credential_name,
                    expected_api_key=expected_api_key,
                    salt_key=self._salt_key,
                    provider_base_url=provider_base_url,
                )
        except LiteLLMAttestationError:
            raise
        except Exception:  # noqa: BLE001 - never attach driver rows or parameters.
            raise LiteLLMAttestationError("litellm_attestation_unavailable") from None
