from __future__ import annotations

from pathlib import Path


def test_successful_saas_alembic_run_keeps_receipt_log_json_only() -> None:
    root = Path(__file__).resolve().parents[2]
    source = (root / "saas/control_plane/migrations/env.py").read_text(encoding="utf-8")

    assert 'getLogger("alembic").setLevel(_logging.WARNING)' in source
    assert source.index("fileConfig(") < source.index('getLogger("alembic")')


def test_migration_job_exposes_no_owner_url_or_mutable_image_reference() -> None:
    root = Path(__file__).resolve().parents[2]
    manifest = (root / "saas/deployment/server/kubernetes.migration.yaml").read_text(
        encoding="utf-8"
    )

    assert "postgresql+psycopg://" not in manifest
    assert "@sha256:" in manifest
    assert "--product-revision" in manifest
    assert "OMNIGENT_SAAS_PRODUCT_REVISION" in manifest
    assert "OMNIGENT_SAAS_SOURCE_SHA" in manifest
    assert "automountServiceAccountToken: false" in manifest
