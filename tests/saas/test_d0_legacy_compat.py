"""Fixed-material integrity and adversarial wheel archive boundaries."""

from __future__ import annotations

import stat
import zipfile
from pathlib import Path

import pytest

from saas.scripts import prepare_d0_legacy_compat as recipe


def test_review_recipe_cannot_expand_paths_or_claim_existing_approval(tmp_path):
    repository = Path(__file__).resolve().parents[2]
    manifest = recipe.load_manifest(repository)
    assert len(manifest["files"]) == 8
    assert manifest["production_authority"] is False
    assert manifest["database_mutation"] is False
    assert "exceeds" in manifest["legacy_normal_source_budget"]
    target = tmp_path / recipe.ROOT
    target.mkdir(parents=True)
    for name in ("manifest.json", "M3659-D0-T.patch"):
        (target / name).write_bytes((repository / recipe.ROOT / name).read_bytes())
    with (target / "M3659-D0-T.patch").open("ab") as stream:
        stream.write(b"\n# expand compatibility scope\n")
    with pytest.raises(ValueError, match="fixed D0 compatibility patch differs"):
        recipe.load_manifest(tmp_path)
    (target / "manifest.json").write_text("{}\n")
    with pytest.raises(ValueError, match="fixed D0 compatibility manifest differs"):
        recipe.load_manifest(tmp_path)


@pytest.mark.parametrize("member", ["../escape", "/absolute", "a/../../escape", "a\\escape"])
def test_unsafe_archive_names_never_reach_materialization(tmp_path, member):
    path = tmp_path / "unsafe.whl"
    with zipfile.ZipFile(path, "w") as bundle:
        bundle.writestr(member, b"payload")
    with pytest.raises(ValueError, match="unsafe wheel member"):
        recipe.wheel_members(path, {"original_wheel_sha256": recipe.digest(path.read_bytes())})
    assert not (tmp_path / "escape").exists()


def test_symlink_and_duplicate_archive_members_are_refused(tmp_path):
    path = tmp_path / "symlink.whl"
    with zipfile.ZipFile(path, "w") as bundle:
        info = zipfile.ZipInfo("module.py")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        bundle.writestr(info, b"/outside")
    with pytest.raises(ValueError, match="unsafe wheel member"):
        recipe.wheel_members(path, {"original_wheel_sha256": recipe.digest(path.read_bytes())})
    duplicate = tmp_path / "duplicate.whl"
    with zipfile.ZipFile(duplicate, "w") as bundle:
        bundle.writestr("module.py", b"first")
        with pytest.warns(UserWarning, match="Duplicate name"):
            bundle.writestr("module.py", b"second")
    with pytest.raises(ValueError, match="duplicate wheel member"):
        recipe.wheel_members(
            duplicate, {"original_wheel_sha256": recipe.digest(duplicate.read_bytes())}
        )


def test_wrong_original_wheel_stops_before_any_output(tmp_path):
    path = tmp_path / "foreign.whl"
    path.write_bytes(b"foreign artifact")
    manifest = recipe.load_manifest(Path(__file__).resolve().parents[2])
    with pytest.raises(ValueError, match="original signed M3659 wheel differs"):
        recipe.wheel_members(path, manifest)
