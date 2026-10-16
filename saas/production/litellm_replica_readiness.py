"""Fresh read-only checks of known replica endpoints and canonical stored secrets."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID

import httpx

from saas.control_plane.litellm_client import (
    LiteLLMManagementClient,
    LiteLLMManagementConfiguration,
)
from saas.control_plane.model_deployments import CompiledModelDeploymentDraft
from saas.production.litellm_configuration_attestation import (
    LiteLLMAttestationError,
    LiteLLMConfigurationAttestor,
)

READINESS_CONTRACT = "litellm-1.105.1-replica-routes-and-storage-v1"
READINESS_SCOPE = "stored_credentials_and_visible_replica_routes_not_hidden_replica_memory"
_FRESHNESS = timedelta(seconds=30)


def _aware(value: object) -> bool:
    return (
        isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() is not None
    )


def _hex64(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _inventory_digest(entries: list[tuple[str, str]]) -> str:
    return hashlib.sha256(
        json.dumps(sorted(entries), separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()


class LiteLLMReplicaReadinessError(RuntimeError):
    """No endpoint, credential, driver exception, or upstream body is exposed."""

    def __init__(self, code: str = "litellm_replica_readiness_unavailable") -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class LiteLLMReplicaEndpoint:
    replica_id: str
    management: LiteLLMManagementConfiguration

    def __post_init__(self) -> None:
        if re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,127}", self.replica_id) is None:
            raise ValueError("litellm_replica_configuration_invalid")

    @property
    def endpoint_sha256(self) -> str:
        normalized = str(httpx.URL(self.management.base_url)).rstrip("/")
        return hashlib.sha256(normalized.encode("ascii")).hexdigest()


@dataclass(frozen=True, slots=True)
class LiteLLMReplicaObservation:
    replica_id: str
    endpoint_sha256: str
    observed_at: datetime


@dataclass(frozen=True, slots=True)
class LiteLLMReplicaReadiness:
    deployment_id: UUID
    credential_version_id: UUID
    configuration_sha256: str
    stored_state_sha256: str
    inventory_sha256: str
    observations: tuple[LiteLLMReplicaObservation, ...]
    started_at: datetime
    completed_at: datetime
    contract: str = READINESS_CONTRACT
    scope: str = READINESS_SCOPE

    def require_current(
        self, *, draft: CompiledModelDeploymentDraft, inventory_sha256: str, now: datetime
    ) -> None:
        if (
            not _aware(now)
            or self.contract != READINESS_CONTRACT
            or self.scope != READINESS_SCOPE
            or self.deployment_id != draft.deployment_id
            or self.credential_version_id != draft.credential_version_id
            or self.configuration_sha256 != draft.configuration_sha256
            or not isinstance(self.observations, tuple)
            or not 2 <= len(self.observations) <= 16
            or any(
                not isinstance(row, LiteLLMReplicaObservation)
                or not isinstance(row.replica_id, str)
                or re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,127}", row.replica_id) is None
                or not _hex64(row.endpoint_sha256)
                or not _aware(row.observed_at)
                for row in self.observations
            )
            or len({row.replica_id for row in self.observations}) != len(self.observations)
            or len({row.endpoint_sha256 for row in self.observations}) != len(self.observations)
            or not _hex64(self.stored_state_sha256)
            or not _hex64(self.inventory_sha256)
            or self.inventory_sha256 != inventory_sha256
            or self.inventory_sha256
            != _inventory_digest(
                [(row.replica_id, row.endpoint_sha256) for row in self.observations]
            )
            or not _aware(self.started_at)
            or not _aware(self.completed_at)
            or not self.started_at <= self.completed_at <= now
            or now - self.started_at > _FRESHNESS
            or any(
                not self.started_at <= row.observed_at <= self.completed_at
                for row in self.observations
            )
        ):
            raise LiteLLMReplicaReadinessError("litellm_replica_readiness_stale_or_unbound")

    def evidence(self) -> dict[str, object]:
        return {
            "contract": self.contract,
            "scope": self.scope,
            "deployment_id": str(self.deployment_id),
            "credential_version_id": str(self.credential_version_id),
            "configuration_sha256": self.configuration_sha256,
            "stored_state_sha256": self.stored_state_sha256,
            "inventory_sha256": self.inventory_sha256,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "replicas": [
                {
                    "replica_id": row.replica_id,
                    "endpoint_sha256": row.endpoint_sha256,
                    "observed_at": row.observed_at.isoformat(),
                }
                for row in self.observations
            ],
        }

    @property
    def evidence_sha256(self) -> str:
        return hashlib.sha256(
            json.dumps(self.evidence(), sort_keys=True, separators=(",", ":")).encode("ascii")
        ).hexdigest()


class LiteLLMReplicaReadinessAuthority:
    """The deployment-owned inventory supplies individual endpoints, not a load balancer."""

    def __init__(
        self,
        replicas: tuple[LiteLLMReplicaEndpoint, ...],
        *,
        storage: LiteLLMConfigurationAttestor,
        client_factory: Callable[[LiteLLMManagementConfiguration], LiteLLMManagementClient]
        | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if (
            not isinstance(replicas, tuple)
            or not 2 <= len(replicas) <= 16
            or any(not isinstance(row, LiteLLMReplicaEndpoint) for row in replicas)
            or len({row.replica_id for row in replicas}) != len(replicas)
            or len({row.endpoint_sha256 for row in replicas}) != len(replicas)
        ):
            raise ValueError("litellm_replica_configuration_invalid")
        self._replicas = tuple(sorted(replicas, key=lambda row: row.replica_id))
        self._storage = storage
        self._client_factory = client_factory or LiteLLMManagementClient
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    @property
    def inventory_sha256(self) -> str:
        return _inventory_digest([(row.replica_id, row.endpoint_sha256) for row in self._replicas])

    async def attest(
        self,
        *,
        draft: CompiledModelDeploymentDraft,
        credential_name: str,
        expected_api_key: str,
        provider_base_url: str = "https://api.deepseek.com",
    ) -> LiteLLMReplicaReadiness:
        try:
            started = self._clock()
            async with asyncio.timeout(30):

                def read_storage():
                    return self._storage.attest(
                        draft=draft,
                        credential_name=credential_name,
                        expected_api_key=expected_api_key,
                        provider_base_url=provider_base_url,
                    )

                before = await asyncio.to_thread(read_storage)
                before.require_binding(draft)

                async def observe(endpoint: LiteLLMReplicaEndpoint) -> LiteLLMReplicaObservation:
                    client = self._client_factory(endpoint.management)
                    await client.reconcile_deepseek_deployment(
                        deployment_id=draft.deployment_id,
                        alias=draft.alias,
                        model=draft.public_model_id,
                        credential_name=credential_name,
                        provider_base_url=provider_base_url,
                    )
                    return LiteLLMReplicaObservation(
                        endpoint.replica_id, endpoint.endpoint_sha256, self._clock()
                    )

                async with asyncio.TaskGroup() as group:
                    tasks = [group.create_task(observe(row)) for row in self._replicas]
                observations = tuple(task.result() for task in tasks)
                after = await asyncio.to_thread(read_storage)
                after.require_binding(draft)
                if before.stored_state_sha256 != after.stored_state_sha256:
                    raise LiteLLMReplicaReadinessError(
                        "litellm_configuration_changed_during_readiness"
                    )
                completed = self._clock()
                if not started <= before.observed_at <= after.observed_at <= completed:
                    raise LiteLLMReplicaReadinessError(
                        "litellm_replica_readiness_stale_or_unbound"
                    )
                result = LiteLLMReplicaReadiness(
                    draft.deployment_id,
                    draft.credential_version_id,
                    draft.configuration_sha256,
                    after.stored_state_sha256,
                    self.inventory_sha256,
                    observations,
                    started,
                    completed,
                )
                result.require_current(
                    draft=draft, inventory_sha256=self.inventory_sha256, now=self._clock()
                )
                return result
        except LiteLLMReplicaReadinessError:
            raise
        except LiteLLMAttestationError as error:
            raise LiteLLMReplicaReadinessError(error.code) from None
        except Exception:  # noqa: BLE001 - raw credentials and transport details stay private.
            raise LiteLLMReplicaReadinessError() from None
