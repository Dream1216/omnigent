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
