"""Normalize provider usage without substituting reservations for actual tokens."""

from __future__ import annotations

from dataclasses import dataclass


class ModelUsageError(ValueError):
    """A stable, content-free usage contract failure."""


@dataclass(frozen=True, slots=True)
class ModelTokenUsage:
    input_tokens: int
    input_cache_hit_tokens: int
    input_cache_miss_tokens: int
    output_tokens: int
    total_tokens: int


def _count(value: object) -> int:
    if type(value) is not int or not 0 <= value <= (1 << 63) - 1:
        raise ModelUsageError("platform_model_usage_invalid")
    return value


def normalize_model_usage(value: object, *, responses: bool) -> ModelTokenUsage:
    """Accept native DeepSeek or standard OpenAI cache counts, never both inconsistently."""

    if not isinstance(value, dict):
        raise ModelUsageError("platform_model_usage_invalid")
    prompt = _count(value.get("input_tokens" if responses else "prompt_tokens"))
    completion = _count(value.get("output_tokens" if responses else "completion_tokens"))
    total = _count(value.get("total_tokens"))
    if total != prompt + completion:
        raise ModelUsageError("platform_model_usage_invalid")
    hit, miss = value.get("prompt_cache_hit_tokens"), value.get("prompt_cache_miss_tokens")
    if hit is not None:
        _count(hit)
    if miss is not None:
        _count(miss)
    details = value.get("input_tokens_details" if responses else "prompt_tokens_details")
    if isinstance(details, dict) and "cached_tokens" in details:
        standard_hit = _count(details["cached_tokens"])
        standard_miss = prompt - standard_hit
        if (
            standard_miss < 0
            or (hit is not None and hit != standard_hit)
            or (miss is not None and miss != standard_miss)
        ):
            raise ModelUsageError("platform_model_usage_invalid")
        hit, miss = standard_hit, standard_miss
    if hit is None and miss is None:
        hit, miss = 0, prompt
    else:
        hit, miss = _count(hit), _count(miss)
    if hit + miss != prompt:
        raise ModelUsageError("platform_model_usage_invalid")
    return ModelTokenUsage(prompt, hit, miss, completion, total)
