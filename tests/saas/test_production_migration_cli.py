from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from saas.scripts.run_postgresql_migration import (
    _DIRECT_URL_ENVIRONMENTS,
    _URL_ENVIRONMENTS,
    _required_url_file,
    _verify_installed_build_revision,
    main,
)


def test_migration_authorities_are_loaded_only_from_owner_only_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "authority-url"
    url = "postgresql+psycopg://authority:secret@db.example/omnigent?sslmode=verify-full"
    path.write_text(url + "\n", encoding="utf-8")
    path.chmod(0o400)

    monkeypatch.setenv("AUTHORITY_FILE", str(path))

    assert _required_url_file(argparse.ArgumentParser(), "AUTHORITY_FILE") == url


def test_migration_url_file_rejects_group_readable_or_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "authority-url"
    path.write_text("postgresql+psycopg://authority:secret@db/omnigent", encoding="utf-8")
    path.chmod(0o440)
    monkeypatch.setenv("AUTHORITY_FILE", str(path))

    with pytest.raises(SystemExit):
        _required_url_file(argparse.ArgumentParser(), "AUTHORITY_FILE")

    path.chmod(0o400)
    link = tmp_path / "authority-link"
    link.symlink_to(path)
    monkeypatch.setenv("AUTHORITY_FILE", str(link))
    with pytest.raises(SystemExit):
        _required_url_file(argparse.ArgumentParser(), "AUTHORITY_FILE")


def test_migration_cli_rejects_direct_authority_database_urls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("sys.argv", ["omnigent-saas-postgresql-migrate"])
    monkeypatch.setenv("OMNIGENT_SAAS_SOURCE_SHA", "a" * 40)
    monkeypatch.setenv("OMNIGENT_SAAS_PRODUCT_REVISION", "a" * 40)
    monkeypatch.setenv(_DIRECT_URL_ENVIRONMENTS[0], "postgresql+psycopg://secret")

    with pytest.raises(SystemExit):
        main()


def test_migration_cli_rejects_product_and_source_revision_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("sys.argv", ["omnigent-saas-postgresql-migrate"])
    monkeypatch.setenv("OMNIGENT_SAAS_SOURCE_SHA", "a" * 40)
    monkeypatch.setenv("OMNIGENT_SAAS_PRODUCT_REVISION", "b" * 40)

    with pytest.raises(SystemExit):
        main()


def test_migration_cli_rejects_unrendered_or_wrong_installed_build(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parser = argparse.ArgumentParser()
    from omnigent import _build_info

    monkeypatch.setattr(_build_info, "COMMIT_SHA", "a" * 40)
    with pytest.raises(SystemExit):
        _verify_installed_build_revision(parser, "0" * 40)
    with pytest.raises(SystemExit):
        _verify_installed_build_revision(parser, "b" * 40)

    _verify_installed_build_revision(parser, "a" * 40)


def test_every_migration_authority_environment_names_a_file() -> None:
    assert len(set(_URL_ENVIRONMENTS.values())) == 4
    assert all(name.endswith("_FILE") for name in _URL_ENVIRONMENTS.values())
