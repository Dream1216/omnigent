from __future__ import annotations

import json
from pathlib import Path

from saas.production.beta_postgresql_data_plane import RenderedBetaPostgresqlDataPlane
from saas.scripts import render_beta_postgresql_data_plane as cli


def test_cli_emits_only_canonical_secret_free_receipt(monkeypatch, capsys, tmp_path: Path) -> None:
    def render(*_args, **_kwargs) -> RenderedBetaPostgresqlDataPlane:
        return RenderedBetaPostgresqlDataPlane(
            output_directory=tmp_path / "output",
            spec_sha256="1" * 64,
            bundle_sha256="2" * 64,
            receipt_sha256="3" * 64,
            files=("data/cluster.yaml",),
        )

    monkeypatch.setattr(cli, "render_beta_postgresql_data_plane", render)
    result = cli.main(
        [
            "--spec",
            str(tmp_path / "spec.json"),
            "--cert-manager-manifest",
            str(tmp_path / "cert-manager.yaml"),
            "--operator-manifest",
            str(tmp_path / "operator.yaml"),
            "--plugin-manifest",
            str(tmp_path / "plugin.yaml"),
            "--output-directory",
            str(tmp_path / "output"),
        ]
    )
    assert result == 0
    raw = capsys.readouterr().out
    assert (
        raw
        == json.dumps(
            {
                "bundle_sha256": "2" * 64,
                "receipt_sha256": "3" * 64,
                "schema_version": 1,
                "spec_sha256": "1" * 64,
                "status": "pass",
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )


def test_cli_failure_does_not_disclose_paths_or_exception(
    monkeypatch, capsys, tmp_path: Path
) -> None:
    def fail(*_args, **_kwargs):
        raise RuntimeError("credential from /private/owner/source")

    monkeypatch.setattr(cli, "render_beta_postgresql_data_plane", fail)
    assert (
        cli.main(
            [
                "--spec",
                str(tmp_path / "secret-spec.json"),
                "--cert-manager-manifest",
                str(tmp_path / "cert-manager.yaml"),
                "--operator-manifest",
                str(tmp_path / "operator.yaml"),
                "--plugin-manifest",
                str(tmp_path / "plugin.yaml"),
                "--output-directory",
                str(tmp_path / "output"),
            ]
        )
        == 1
    )
    assert capsys.readouterr().out == (
        '{"code":"beta_postgresql_data_plane_render_failed","schema_version":1,"status":"fail"}\n'
    )
