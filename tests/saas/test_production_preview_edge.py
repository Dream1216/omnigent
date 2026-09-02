from __future__ import annotations

import pytest

from saas.production import preview_edge
from saas.production.preview_edge import (
    ProductionPreviewEdgeError,
    load_production_preview_edge_config,
)


class _ReachedBindings(RuntimeError):
    pass


def _release(source: str, product: str) -> dict[str, str]:
    return {
        "OMNIGENT_SAAS_SOURCE_SHA": source,
        "OMNIGENT_SAAS_PRODUCT_REVISION": product,
        "OMNIGENT_SAAS_IMAGE_DIGEST": "sha256:" + "b" * 64,
        "OMNIGENT_SAAS_OFFICIAL_SCHEMA_REVISION": "official0001",
        "OMNIGENT_SAAS_CONTROL_PLANE_SCHEMA_REVISION": "p0s000000011",
    }


def test_preview_edge_rejects_product_revision_drift_before_loading_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        preview_edge,
        "load_production_service_role_bindings",
        lambda _source: (_ for _ in ()).throw(_ReachedBindings()),
    )

    with pytest.raises(ProductionPreviewEdgeError, match="release identity"):
        load_production_preview_edge_config(_release("a" * 40, "c" * 40))


def test_preview_edge_accepts_only_exact_source_product_pair_before_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        preview_edge,
        "load_production_service_role_bindings",
        lambda _source: (_ for _ in ()).throw(_ReachedBindings()),
    )

    with pytest.raises(_ReachedBindings):
        load_production_preview_edge_config(_release("a" * 40, "a" * 40))


@pytest.mark.parametrize(
    "name",
    [
        "OMNIGENT_SAAS_PREVIEW_GATEWAY_DATABASE_URL_FILE",
        "OMNIGENT_SAAS_PREVIEW_OWNER_DATABASE_URL_FILE",
    ],
)
def test_preview_edge_rejects_legacy_or_owner_database_authority(
    name: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        preview_edge,
        "load_production_service_role_bindings",
        lambda _source: (_ for _ in ()).throw(_ReachedBindings()),
    )
    source = _release("a" * 40, "a" * 40)
    source[name] = "/runtime/forbidden-database-url"

    with pytest.raises(ProductionPreviewEdgeError, match="must not receive"):
        load_production_preview_edge_config(source)
