"""Downstream Host-image contract for the managed Kimi harness."""

from pathlib import Path


def test_kimi_cli_row_matches_official_install_table() -> None:
    """The managed Host installs the same pinned official Kimi package."""
    from omnigent.onboarding import harness_install as hi

    script = (
        Path(__file__).resolve().parents[2] / "deploy/docker/install-harness-cli.sh"
    ).read_text()
    kimi = hi._HARNESS_INSTALL[hi.KIMI_KEY]
    assert kimi.package == "@moonshot-ai/kimi-code"
    assert f"{kimi.package}@${{version:-0.43.1}}" in script
