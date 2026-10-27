"""Regressions for dependency drift observed in repeated runtime builds."""

from pathlib import Path

from saas.scripts.check_image_supply_chain import validate_image_material_lock
from tests.saas.test_image_supply_chain import _material_lock_repo


def test_image_material_lock_rejects_floating_libcom_err_dependency(tmp_path: Path) -> None:
    repo = _material_lock_repo(tmp_path)
    dockerfile = repo / "deploy/docker/Dockerfile"
    source = dockerfile.read_text(encoding="utf-8")
    assert "libcom_err=1.47.4-r5" in source
    dockerfile.write_text(source.replace("libcom_err=1.47.4-r5", "libcom_err", 1))

    assert "Wolfi common_packages pins must be installed exactly" in validate_image_material_lock(
        repo
    )
