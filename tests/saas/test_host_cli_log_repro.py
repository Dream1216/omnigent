"""Keep volatile Jcode probe logs out of the signed Host image."""

from pathlib import Path

from saas.scripts.check_image_supply_chain import validate_image_material_lock

ROOT = Path(__file__).resolve().parents[2]
MATERIAL_INPUTS = (
    "deploy/docker/Dockerfile",
    "uv.lock",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    ".github/ci-deps/package.json",
    "saas/scripts/bind_runtime_build_revision.py",
    "saas/scripts/normalize_host_cli_tree.py",
    "saas/scripts/install-saas-harness-cli.sh",
)


def test_image_policy_rejects_jcode_probe_log_retention(tmp_path: Path) -> None:
    for relative in MATERIAL_INPUTS:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / relative).read_bytes())

    installer = tmp_path / "saas/scripts/install-saas-harness-cli.sh"
    source = installer.read_text(encoding="utf-8")
    cleanup = "rm -rf -- /opt/jcode/.jcode/logs"
    assert cleanup in source
    assert validate_image_material_lock(tmp_path) == []

    installer.write_text(source.replace(cleanup, ": # preserve volatile logs", 1))
    assert (
        "extra Host CLI layer must remove volatile Jcode logs before normalization"
        in validate_image_material_lock(tmp_path)
    )
