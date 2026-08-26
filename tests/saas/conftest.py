from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

import pytest
import sqlalchemy as sa


def _chromium_is_installed() -> bool:
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            return Path(playwright.chromium.executable_path).is_file()
    except Exception:
        return False


@pytest.fixture
def isolated_postgres_url() -> str:
    """Give destructive migration tests a disposable PostgreSQL database."""
    source = os.environ.get("OMNIGENT_SAAS_TEST_POSTGRES_URL")
    if not source:
        pytest.skip("OMNIGENT_SAAS_TEST_POSTGRES_URL is required for real RLS acceptance")

    base_url = sa.engine.make_url(source)
    database_name = f"omnigent_isolated_{uuid4().hex}"
    database_url = base_url.set(database=database_name)
    admin_engine = sa.create_engine(base_url, isolation_level="AUTOCOMMIT")
    database_admin_engine: sa.Engine | None = None
    try:
        with admin_engine.connect() as connection:
            connection.exec_driver_sql(f'CREATE DATABASE "{database_name}" TEMPLATE template0')
        root = Path(__file__).resolve().parents[2]
        database_admin_engine = sa.create_engine(database_url)
        with database_admin_engine.begin() as connection:
            connection.exec_driver_sql(
                (root / "saas/control_plane/postgresql_principals.sql").read_text(encoding="utf-8")
            )
            connection.exec_driver_sql(
                (root / "saas/control_plane/postgresql_database.sql").read_text(encoding="utf-8")
            )
        yield database_url.render_as_string(hide_password=False)
    finally:
        if database_admin_engine is not None:
            database_admin_engine.dispose()
        with admin_engine.connect() as connection:
            connection.exec_driver_sql(f'DROP DATABASE IF EXISTS "{database_name}" WITH (FORCE)')
        admin_engine.dispose()


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    browser_items = [item for item in items if item.path.name.endswith("_browser.py")]
    if not browser_items or _chromium_is_installed():
        return
    missing_browser = pytest.mark.skip(
        reason="Chromium is not installed in this generic test lane; SaaS compatibility runs it"
    )
    for item in browser_items:
        item.add_marker(missing_browser)
