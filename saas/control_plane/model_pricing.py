"""Sealed provider cost rates shared by admission and actual-usage accounting."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone

from saas.control_plane.model_usage import ModelTokenUsage


def token_cost_microusd(tokens: int, rate_per_million: int) -> int:
    """Round each nonzero rated component up without floating-point money."""

    if (
        type(tokens) is not int
        or type(rate_per_million) is not int
        or tokens < 0
        or rate_per_million <= 0
    ):
        raise ValueError("Platform model cost input is invalid")
    return (tokens * rate_per_million + 999_999) // 1_000_000


@dataclass(frozen=True, slots=True)
class PlatformModelPrice:
    model_sha256: str
    peak_input_cache_hit_microusd_per_million_tokens: int
    peak_input_cache_miss_microusd_per_million_tokens: int
    peak_output_microusd_per_million_tokens: int
    off_peak_input_cache_hit_microusd_per_million_tokens: int
    off_peak_input_cache_miss_microusd_per_million_tokens: int
    off_peak_output_microusd_per_million_tokens: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.model_sha256, str)
            or len(self.model_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.model_sha256)
        ):
            raise ValueError("Platform model price is invalid")
        for name in self.__dataclass_fields__:
            if name == "model_sha256":
                continue
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= 10**12:
                raise ValueError("Platform model price is invalid")

    @property
    def reservation_rate(self) -> int:
        return max(
            getattr(self, name) for name in self.__dataclass_fields__ if name != "model_sha256"
        )

    def rates_at(self, at: datetime) -> tuple[int, int, int]:
        """Resolve the approved DeepSeek weekday UTC peak-window contract."""

        if at.tzinfo is None or at.utcoffset() is None:
            raise ValueError("Platform model price timestamp is invalid")
        normalized = at.astimezone(timezone.utc)
        peak = normalized.weekday() < 5 and (1 <= normalized.hour < 4 or 6 <= normalized.hour < 10)
        prefix = "peak" if peak else "off_peak"
        return tuple(
            getattr(self, f"{prefix}_{component}_microusd_per_million_tokens")
            for component in ("input_cache_hit", "input_cache_miss", "output")
        )

    def cost(self, usage: ModelTokenUsage, *, at: datetime) -> int:
        if (
            any(
                type(value) is not int or not 0 <= value <= (1 << 63) - 1
                for value in (
                    usage.input_tokens,
                    usage.input_cache_hit_tokens,
                    usage.input_cache_miss_tokens,
                    usage.output_tokens,
                    usage.total_tokens,
                )
            )
            or usage.input_cache_hit_tokens + usage.input_cache_miss_tokens != usage.input_tokens
            or usage.input_tokens + usage.output_tokens != usage.total_tokens
        ):
            raise ValueError("Platform model usage is inconsistent")
        counts = (usage.input_cache_hit_tokens, usage.input_cache_miss_tokens, usage.output_tokens)
        return sum(
            token_cost_microusd(tokens, rate)
            for tokens, rate in zip(counts, self.rates_at(at), strict=True)
        )


@dataclass(frozen=True, slots=True)
class PlatformModelPricingPolicy:
    revision: str
    catalog_sha256: str
    prices: tuple[PlatformModelPrice, ...]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.revision, str)
            or not self.revision
            or len(self.revision) > 32
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in self.revision)
            or not isinstance(self.catalog_sha256, str)
            or len(self.catalog_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.catalog_sha256)
            or not isinstance(self.prices, tuple)
            or not self.prices
            or any(not isinstance(price, PlatformModelPrice) for price in self.prices)
        ):
            raise ValueError("Platform model pricing policy is invalid")
        if len({price.model_sha256 for price in self.prices}) != len(self.prices):
            raise ValueError("Platform model pricing policy is invalid")

    def for_catalog(self, models: tuple[str, ...]) -> Mapping[str, PlatformModelPrice]:
        indexed = {price.model_sha256: price for price in self.prices}
        model_hashes = tuple(hashlib.sha256(model.encode("utf-8")).hexdigest() for model in models)
        if (
            not models
            or len(set(models)) != len(models)
            or any(model_hash not in indexed for model_hash in model_hashes)
        ):
            raise ValueError("Platform model pricing catalog is unavailable")
        if len(models) == len(self.prices):
            canonical = json.dumps(list(models), separators=(",", ":"), ensure_ascii=True).encode()
            if hashlib.sha256(canonical).hexdigest() != self.catalog_sha256:
                raise ValueError("Platform model pricing catalog is unavailable")
        return {
            model: indexed[model_hash]
            for model, model_hash in zip(models, model_hashes, strict=True)
        }
