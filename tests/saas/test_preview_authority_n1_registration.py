"""Keep native Preview packaging registration exact and preserve prior inputs."""

from pathlib import Path

import pytest

from tests.saas.test_n1_merge_gate import _run_full_gate


@pytest.mark.parametrize(
    "path,digest,accepted",
    [
        (
            "pyproject.toml",
            "3df60bf721d1df8558df6e569ff26a34d628c6590df7ac306a07f890cd9b1411",
            True,
        ),
        (
            "pyproject.toml",
            "24fe2762769bbd06e8da179caf64140a5869e3c33ee875c83bb3a51f266ba322",
            True,
        ),
        (
            "pyproject.toml",
            "2d50173296c09198dcafb573bdd0fc18abce0e1f6afbf702d077b54f3db770f9",
            True,
        ),
        (
            "pyproject.toml",
            "7b7bfc95d45ac928bb91cf6b383c94c48792474adf967e34fcfddca15d0c58a6",
            True,
        ),
        (
            "pyproject.toml",
            "f2dc2794af15424de2e97422d2bf4dd59eccc6f413fbbb3e6b4453ca302b3f27",
            True,
        ),
        (
            "pyproject.toml",
            "77ffd5d339656adfec3e7b15660599226ff29a527e05f75cdbbb386ad280550f",
            True,
        ),
        (
            "uv.lock",
            "51412e72b0d0119f388ad9349025fb40f1f5458e55695b736f9e79ab99395b5b",
            True,
        ),
        (
            "tests/saas/test_image_supply_chain.py",
            "109ac4d727d73b271613089acbb693944047f9705f10c33c4e676075fe52d4f7",
            True,
        ),
        (
            "tests/saas/test_n1_compat_patch.py",
            "f2dc2794af15424de2e97422d2bf4dd59eccc6f413fbbb3e6b4453ca302b3f27",
            False,
        ),
        (
            "tests/saas/test_image_supply_chain.py",
            "51412e72b0d0119f388ad9349025fb40f1f5458e55695b736f9e79ab99395b5b",
            False,
        ),
        (
            "uv.lock",
            "109ac4d727d73b271613089acbb693944047f9705f10c33c4e676075fe52d4f7",
            False,
        ),
        (
            "tests/saas/test_n1_merge_gate.py",
            "2621c5890478d5cc4d4d7a5e8fef6a1d69bd25b85943b64ec8a2e62f06db83d2",
            True,
        ),
        (
            "pyproject.toml",
            "2621c5890478d5cc4d4d7a5e8fef6a1d69bd25b85943b64ec8a2e62f06db83d2",
            False,
        ),
        ("pyproject.toml", "0" * 64, False),
        (
            "tests/saas/test_n1_compat_patch.py",
            "24fe2762769bbd06e8da179caf64140a5869e3c33ee875c83bb3a51f266ba322",
            False,
        ),
        (
            "tests/saas/test_n1_compat_patch.py",
            "3df60bf721d1df8558df6e569ff26a34d628c6590df7ac306a07f890cd9b1411",
            False,
        ),
    ],
)
def test_native_preview_registry_preserves_only_exact_reviewed_inputs(
    tmp_path: Path, path, digest, accepted
):
    result = _run_full_gate(tmp_path, trusted_input_override=(path, digest))
    assert (result.returncode == 0) is accepted
    if not accepted:
        assert "trusted input drift" in result.stdout
