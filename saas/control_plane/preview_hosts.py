"""Canonical public hostnames for browser Preview sessions."""

from __future__ import annotations

import re
import secrets

_ROOT_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


def new_preview_host(root_domain: str) -> str:
    """Return a fresh wildcard-compatible host with an independent opaque label."""

    if _ROOT_DOMAIN.fullmatch(root_domain) is None:
        raise ValueError("Preview root domain is invalid")
    return f"app-{secrets.token_hex(12)}.{root_domain}"


__all__ = ["new_preview_host"]
