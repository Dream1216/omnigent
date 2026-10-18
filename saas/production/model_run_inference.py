"""Inference-only LiteLLM transport and the existing customer's financial boundary."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

from omnigent.db.query_context import query_name_scope
from saas.control_plane.billing_metering import BillingMeteringAuthority, BillingMeteringError
from saas.control_plane.billing_models import BillingSubscriptionRecord, PricingSnapshotRecord
from saas.control_plane.litellm_client import validate_litellm_endpoint
from saas.control_plane.model_gateway_metering import GATEWAY_METERS
from saas.control_plane.rls import RlsContext, apply_rls_context
from saas.production.model_run_credentials import AuthorizedModelRun
from saas.production.onboarding import _read_bytes, _regular_file


def require_current_customer_pricing(
    billing_sessions: sessionmaker[Session], tenant_id: UUID
) -> None:
    """Read-only picker hint; actual Runs still freeze and recheck their own price."""
    with (
        query_name_scope("saas.model_run_inference.preview_customer_pricing"),
        billing_sessions.begin() as db,
    ):
        apply_rls_context(db, RlsContext(tenant_id=tenant_id))
        subscription = db.scalar(
            sa.select(BillingSubscriptionRecord).where(
                BillingSubscriptionRecord.tenant_id == tenant_id
            )
        )
        if subscription is None or subscription.status not in {"active", "trialing"}:
            raise BillingMeteringError(
                "metering_subscription_unavailable", "Customer billing is unavailable"
            )
        now = datetime.now(timezone.utc)
        prices = list(
            db.scalars(
                sa.select(PricingSnapshotRecord)
                .where(
                    PricingSnapshotRecord.tenant_id == tenant_id,
                    PricingSnapshotRecord.plan_key == subscription.plan_key,
                    PricingSnapshotRecord.effective_from <= now,
                    sa.or_(
                        PricingSnapshotRecord.effective_until.is_(None),
                        PricingSnapshotRecord.effective_until > now,
                    ),
                )
                .limit(2)
            )
        )
        if len(prices) != 1:
            raise BillingMeteringError(
                "metering_subscription_unavailable", "Customer billing is unavailable"
            )
        for meter in GATEWAY_METERS:
            BillingMeteringAuthority._charge(
                pricing=prices[0], meter=meter, quantity=Decimal(1), unit="tokens"
            )


@dataclass(frozen=True, slots=True)
class LiteLLMRunInference:
    base_url: str
    inference_key: str = field(repr=False)
    aliases: tuple[str, ...]
    billing_sessions: sessionmaker[Session] = field(repr=False)
    allowed_http_hosts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        validate_litellm_endpoint(
            self.base_url, allowed_http_hosts=self.allowed_http_hosts, timeout_seconds=120
        )
        if (
            not 16 <= len(self.inference_key) <= 4096
            or not all(33 <= ord(char) <= 126 for char in self.inference_key)
            or not self.aliases
            or len(self.aliases) > 128
            or len(set(self.aliases)) != len(self.aliases)
            or any(
                re.fullmatch(r"platform-model-[0-9a-f]{32}", alias) is None
                for alias in self.aliases
            )
        ):
            raise ValueError("platform_model_inference_configuration_invalid")

    def require_financial_scope(self, authorized: AuthorizedModelRun) -> None:
        if authorized.configuration.get("deployment_alias") not in self.aliases:
            raise BillingMeteringError(
                "metering_gateway_route_unavailable", "Inference key scope is unavailable"
            )
        with (
            query_name_scope("saas.model_run_inference.check_customer_pricing"),
            self.billing_sessions.begin() as db,
        ):
            apply_rls_context(db, RlsContext(tenant_id=authorized.claims.tenant_id))
            subscription = db.scalar(
                sa.select(BillingSubscriptionRecord)
                .where(BillingSubscriptionRecord.tenant_id == authorized.claims.tenant_id)
                .with_for_update()
            )
            pricing = db.scalar(
                sa.select(PricingSnapshotRecord).where(
                    PricingSnapshotRecord.id == authorized.customer_pricing_snapshot_id,
                    PricingSnapshotRecord.tenant_id == authorized.claims.tenant_id,
                )
            )
            if (
                subscription is None
                or subscription.status not in {"active", "trialing"}
                or pricing is None
            ):
                raise BillingMeteringError(
                    "metering_subscription_unavailable", "Customer billing is unavailable"
                )
            for meter in GATEWAY_METERS:
                BillingMeteringAuthority._charge(
                    pricing=pricing, meter=meter, quantity=Decimal(1), unit="tokens"
                )


def load_litellm_run_inference(
    source: Mapping[str, str], billing_sessions: sessionmaker[Session]
) -> LiteLLMRunInference | None:
    enabled = source.get("OMNIGENT_SAAS_MODEL_RUN_INFERENCE_ENABLED", "false")
    if enabled not in {"true", "false"}:
        raise ValueError("platform_model_inference_configuration_invalid")
    if enabled == "false":
        return None
    if source.get("OMNIGENT_SAAS_LITELLM_INFERENCE_KEY"):
        raise ValueError("platform_model_inference_configuration_invalid")
    path = _regular_file(source, "OMNIGENT_SAAS_LITELLM_INFERENCE_KEY_FILE", maximum_bytes=4098)
    key = (
        _read_bytes(path, "OMNIGENT_SAAS_LITELLM_INFERENCE_KEY_FILE", maximum_bytes=4098)
        .decode("ascii")
        .rstrip("\r\n")
    )
    return LiteLLMRunInference(
        source.get("OMNIGENT_SAAS_LITELLM_INFERENCE_BASE_URL", ""),
        key,
        tuple(source.get("OMNIGENT_SAAS_LITELLM_RUN_ALIASES", "").split(",")),
        billing_sessions,
        ("omnigent-litellm", "omnigent-litellm.omnigent-next-beta.svc.cluster.local"),
    )
