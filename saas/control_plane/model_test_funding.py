"""Staff-managed, keyless platform funding for bounded model verification."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from uuid import UUID

import sqlalchemy as sa

from omnigent.db.utils import make_named_managed_session_maker
from saas.control_plane.model_budget import (
    _request_hash,
    latest_model_test_funding_policy,
    lock_model_provider_budget,
)
from saas.control_plane.model_connections import authorize_platform_model_operation
from saas.control_plane.platform_models import ModelTestFundingPolicyRecord
from saas.control_plane.platform_security import (
    PlatformAuthorizationService,
    PlatformSecurityError,
    ValidatedPlatformPrincipal,
)


@dataclass(frozen=True, slots=True)
class ModelTestFundingPolicy:
    enabled: bool
    monthly_budget_microusd: int
    daily_test_budget_microusd: int
    daily_test_token_limit: int
    max_test_microusd: int
    max_test_tokens: int
    daily_test_attempt_limit: int

    def validate(self) -> None:
        amounts = (
            self.monthly_budget_microusd,
            self.daily_test_budget_microusd,
            self.daily_test_token_limit,
            self.max_test_microusd,
            self.max_test_tokens,
            self.daily_test_attempt_limit,
        )
        if (
            type(self.enabled) is not bool
            or any(type(value) is not int or value <= 0 for value in amounts)
            or not self.max_test_microusd
            <= self.daily_test_budget_microusd
            <= self.monthly_budget_microusd
            <= 10**15
            or not self.max_test_tokens <= self.daily_test_token_limit <= 10**9
            or self.max_test_tokens > 2048
            or self.daily_test_attempt_limit > 1000
        ):
            raise PlatformSecurityError(
                "platform_model_test_funding_invalid", "Model test funding limits are invalid"
            )


@dataclass(frozen=True, slots=True)
class ModelTestFundingView:
    provider_id: str
    version: int
    policy: ModelTestFundingPolicy | None
    actor_principal_id: UUID | None
    occurred_at: datetime | None
    request_hash: str | None


def _view(record: ModelTestFundingPolicyRecord | None) -> ModelTestFundingView:
    if record is None:
        return ModelTestFundingView("deepseek", 0, None, None, None, None)
    return ModelTestFundingView(
        record.provider_id,
        record.version,
        ModelTestFundingPolicy(
            **{name: getattr(record, name) for name in ModelTestFundingPolicy.__dataclass_fields__}
        ),
        record.actor_principal_id,
        record.occurred_at,
        record.request_hash,
    )


class ModelTestFundingService:
    """Append a CAS-protected funding receipt; never change model availability."""

    def __init__(self, engine: sa.Engine, *, authorization: PlatformAuthorizationService) -> None:
        self._session = make_named_managed_session_maker(
            engine, query_name_prefix="saas.model_test_funding", immediate=True
        )
        self._authorization = authorization

    def get(self, actor: ValidatedPlatformPrincipal) -> ModelTestFundingView:
        with self._session("read_platform_test_funding") as db:
            authorize_platform_model_operation(
                db,
                self._authorization,
                actor,
                "platform.model_provider.read",
                datetime.now(timezone.utc),
            )
            return _view(latest_model_test_funding_policy(db))

    def configure(
        self,
        actor: ValidatedPlatformPrincipal,
        *,
        expected_version: int,
        policy: ModelTestFundingPolicy,
        now: datetime | None = None,
    ) -> ModelTestFundingView:
        at = now or datetime.now(timezone.utc)
        policy.validate()
        if type(expected_version) is not int or not 0 <= expected_version < (1 << 31) - 1:
            raise PlatformSecurityError(
                "platform_model_test_funding_invalid", "Funding version is invalid"
            )
        request_hash = _request_hash(expected_version=expected_version, **asdict(policy))
        with self._session("append_platform_test_funding") as db:
            authorize_platform_model_operation(
                db, self._authorization, actor, "platform.model_provider.manage", at
            )
            lock_model_provider_budget(db)
            current = latest_model_test_funding_policy(db)
            current_version = current.version if current is not None else 0
            if (
                current is not None
                and current_version == expected_version + 1
                and current.request_hash == request_hash
                and current.actor_principal_id == actor.principal_id
            ):
                return _view(current)
            if current_version != expected_version:
                raise PlatformSecurityError(
                    "platform_model_test_funding_conflict",
                    "Model test funding changed; reload before saving",
                )
            record = ModelTestFundingPolicyRecord(
                provider_id="deepseek",
                version=expected_version + 1,
                actor_principal_id=actor.principal_id,
                request_hash=request_hash,
                occurred_at=at,
                **asdict(policy),
            )
            db.add(record)
            return _view(record)
