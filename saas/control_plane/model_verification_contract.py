"""Immutable, priced, bounded verification plans; no external effects or runtime grant."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from hashlib import sha256

from saas.control_plane.model_deployments import CompiledModelDeploymentDraft
from saas.control_plane.model_pricing import (
    PlatformModelPrice,
    PlatformModelPricingPolicy,
    token_cost_microusd,
)
from saas.control_plane.model_usage import ModelTokenUsage

PROBE_INPUT_TOKEN_CEILING = 1024
PROBE_OUTPUT_TOKEN_CEILING = 32


def canonical_verification_document(value: dict[str, object]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


@dataclass(frozen=True, slots=True)
class ModelVerificationPlan:
    canonical_price: str
    price_sha256: str
    pricing_revision: str
    funding_policy_version: int
    requested_microusd: int
    requested_tokens: int
    output_token_limit: int
    request_hash: str

    def price(self) -> PlatformModelPrice:
        document = json.loads(self.canonical_price)
        return PlatformModelPrice(**document["price"])

    def actual_cost(self, usage: ModelTokenUsage, *, at: datetime) -> int:
        if (
            not 0 <= usage.input_tokens <= PROBE_INPUT_TOKEN_CEILING
            or not 1 <= usage.output_tokens <= self.output_token_limit
        ):
            raise ValueError("model_verification_usage_invalid")
        cost = self.price().cost(usage, at=at)
        if not 1 <= cost <= self.requested_microusd or usage.total_tokens > self.requested_tokens:
            raise ValueError("model_verification_usage_exceeds_hold")
        return cost


def _plan(
    draft: CompiledModelDeploymentDraft, *, canonical_price: str, funding_policy_version: int
) -> ModelVerificationPlan:
    try:
        document = json.loads(canonical_price)
        if (
            not isinstance(document, dict)
            or set(document) != {"schema_version", "pricing_revision", "catalog_sha256", "price"}
            or type(document.get("schema_version")) is not int
            or document["schema_version"] != 1
            or not isinstance(document.get("price"), dict)
            or type(funding_policy_version) is not int
            or not 1 <= funding_policy_version < (1 << 31)
            or canonical_verification_document(document) != canonical_price
        ):
            raise ValueError
        price = PlatformModelPrice(**document["price"])
        if price.model_sha256 != sha256(draft.public_model_id.encode()).hexdigest():
            raise ValueError
        # The snapshot may be one member of a larger sealed catalog.
        PlatformModelPricingPolicy(
            document["pricing_revision"], document["catalog_sha256"], (price,)
        )
    except (TypeError, ValueError, KeyError, AttributeError):
        raise ValueError("model_verification_price_invalid") from None
    output_limit = min(PROBE_OUTPUT_TOKEN_CEILING, draft.max_output_tokens)
    price_hash = sha256(canonical_price.encode("ascii")).hexdigest()
    input_rate = max(
        price.peak_input_cache_hit_microusd_per_million_tokens,
        price.peak_input_cache_miss_microusd_per_million_tokens,
        price.off_peak_input_cache_hit_microusd_per_million_tokens,
        price.off_peak_input_cache_miss_microusd_per_million_tokens,
    )
    output_rate = max(
        price.peak_output_microusd_per_million_tokens,
        price.off_peak_output_microusd_per_million_tokens,
    )
    # Cache hit/miss components are rounded separately in actual accounting.
    hold = (
        token_cost_microusd(PROBE_INPUT_TOKEN_CEILING, input_rate)
        + token_cost_microusd(output_limit, output_rate)
        + 1
    )
    requested_tokens = PROBE_INPUT_TOKEN_CEILING + output_limit
    request_hash = sha256(
        canonical_verification_document(
            {
                "action": "verify_deployment",
                "deployment_id": str(draft.deployment_id),
                "configuration_sha256": draft.configuration_sha256,
                "price_sha256": price_hash,
                "funding_policy_version": funding_policy_version,
                "requested_microusd": hold,
                "requested_tokens": requested_tokens,
                "output_token_limit": output_limit,
            }
        ).encode("ascii")
    ).hexdigest()
    return ModelVerificationPlan(
        canonical_price,
        price_hash,
        document["pricing_revision"],
        funding_policy_version,
        hold,
        requested_tokens,
        output_limit,
        request_hash,
    )


def compile_model_verification(
    draft: CompiledModelDeploymentDraft,
    *,
    pricing: PlatformModelPricingPolicy,
    funding_policy_version: int,
) -> ModelVerificationPlan:
    price = pricing.for_catalog((draft.public_model_id,))[draft.public_model_id]
    return _plan(
        draft,
        canonical_price=canonical_verification_document(
            {
                "schema_version": 1,
                "pricing_revision": pricing.revision,
                "catalog_sha256": pricing.catalog_sha256,
                "price": asdict(price),
            }
        ),
        funding_policy_version=funding_policy_version,
    )


def restore_model_verification(
    draft: CompiledModelDeploymentDraft,
    *,
    canonical_price: str,
    funding_policy_version: int,
) -> ModelVerificationPlan:
    return _plan(
        draft, canonical_price=canonical_price, funding_policy_version=funding_policy_version
    )
