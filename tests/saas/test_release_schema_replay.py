"""Opt-in source-level P0 application/R schema handoff on a disposable cluster."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest
import sqlalchemy as sa

from saas.production import postgresql_migration as migration
from saas.production.service_bindings import (
    EXPECTED_MODEL_PROJECTION_SERVICE_ROLES,
    ProductionServiceRoleBinding,
    ProductionServiceRoleBindings,
    render_production_service_role_bindings,
)
from tests.saas.test_production_migration_replay import (
    _startup_config,
)
from tests.saas.test_production_migration_replay import (
    production_replay as production_replay,
)

_P0 = "p0s000000016"
_R = "lm2r00000001"


def _producer_source():
    value = os.environ.get("OMNIGENT_SAAS_R_SCHEMA_SOURCE_REPO")
    revision = os.environ.get("OMNIGENT_SAAS_R_SCHEMA_SOURCE_SHA")
    if not value or not revision:
        pytest.skip("requires an exact R schema producer source checkout")
    root = Path(value)
    assert root.is_absolute() and root.is_dir()
    observed = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    assert len(revision) == 40 and observed == revision
    assert not subprocess.check_output(["git", "status", "--porcelain"], cwd=root)
    return root, revision


def _produce_schema():
    from saas.production.service_bindings import (
        load_model_projection_service_role_bindings,
        load_platform_admin_service_role_bindings,
        load_platform_model_service_role_bindings,
        load_production_service_role_bindings,
    )

    document = json.load(sys.stdin)
    root = Path(document["source_root"])
    revision = document["source_revision"]
    assert Path(migration.__file__).resolve().is_relative_to(root)
    assert (
        subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
        == revision
    )
    assert migration._expected_head("saas") == _R
    urls = document["urls"]
    for value in urls.values():
        url = sa.make_url(value)
        assert url.host in {"127.0.0.1", "localhost"} and url.port
        assert url.database == "admission_replay"
        assert isinstance(url.username, str) and url.username.startswith("replay_")
        assert url.query.get("sslmode") == "verify-full"
    source = document["bindings"]
    # Source tests substitute build identity; signed binary admission remains separate.
    migration._installed_product_revision = lambda: revision
    plan = migration.ProductionPostgreSqlPlan.from_urls(
        product_revision=revision,
        **urls,
        service_role_bindings=load_production_service_role_bindings(source),
        platform_model_service_role_bindings=load_platform_model_service_role_bindings(source),
        platform_admin_service_role_bindings=load_platform_admin_service_role_bindings(source),
        model_projection_service_role_bindings=load_model_projection_service_role_bindings(source),
    )
    receipt = migration.run_production_postgresql_migration(plan)
    print(json.dumps(receipt.to_dict()))


def _upgrade_runner_schema_if_requested(engine, *, schema_owner: str) -> str:
    requested = os.environ.get("OMNIGENT_SAAS_RUNNER_SCHEMA_REPLAY")
    if requested in {None, "p0"}:
        return _P0
    assert requested == "r"
    root, revision = _producer_source()
    environment = {key: os.environ[key] for key in ("PATH", "TMPDIR") if key in os.environ}
    environment.update(PYTHONPATH=str(root), OMNIGENT_SKIP_WEB_UI="true")
    result = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), "--produce-runner"],
        cwd=root,
        env=environment,
        input=json.dumps(
            {
                "source_root": str(root),
                "source_revision": revision,
                "database_url": engine.url.render_as_string(hide_password=False),
                "schema_owner": schema_owner,
            }
        ),
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, "R Runner fixture migration failed in the source subprocess"
    assert json.loads(result.stdout) == {"saas_head": _R, "source_revision": revision}
    return _R


def _produce_runner_schema() -> None:
    from tests.saas.test_scheduling_postgresql import _migrate

    document = json.load(sys.stdin)
    root = Path(document["source_root"])
    revision = document["source_revision"]
    assert Path(migration.__file__).resolve().is_relative_to(root)
    assert (
        subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
        == revision
    )
    assert migration._expected_head("saas") == _R
    url = sa.make_url(document["database_url"])
    assert url.host in {"127.0.0.1", "localhost"} and url.port and url.username == "postgres"
    assert isinstance(url.database, str) and re.fullmatch(
        r"omnigent_isolated_[0-9a-f]{32}", url.database
    )
    assert url.query.get("sslmode") == "verify-full"
    owner = document["schema_owner"]
    assert re.fullmatch(r"saas_test_fleet_owner_[0-9a-f]{12}", owner)
    engine = sa.create_engine(url)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(
                (root / "saas/control_plane/postgresql_principals.sql").read_text()
            )
            connection.exec_driver_sql(f'SET LOCAL ROLE "{owner}"')
            _migrate(connection, root)
            connection.exec_driver_sql(
                (root / "saas/control_plane/postgresql_roles.sql").read_text()
            )
            assert (
                connection.exec_driver_sql(
                    "SELECT version_num FROM saas_alembic_version"
                ).scalar_one()
                == _R
            )
    finally:
        engine.dispose()
    print(json.dumps({"saas_head": _R, "source_revision": revision}))


def _receipt_from_document(document):
    return migration.PostgreSqlMigrationReceipt(
        schema_version=document["schema_version"],
        status=document["status"],
        product_revision=document["product_revision"],
        official_head=document["official_head"],
        saas_head=document["saas_head"],
        database_identity_sha256=document["database_identity_sha256"],
        runtime_rls_table_count=document["runtime_rls_table_count"],
        authorities=tuple((row["kind"], row["login"]) for row in document["authorities"]),
        phases=tuple(document["phases"]),
        catalog_sha256=document["catalog_sha256"],
        service_role_bindings_sha256=document["service_role_bindings_sha256"],
        service_role_graph_sha256=document["service_role_graph_sha256"],
        completed_at=document["completed_at"],
        verify_only=document["verify_only"],
    )


def _rendered_role_handoff(plan, tmp_path, monkeypatch, capsys):
    from omnigent import _build_info
    from saas.production import service_bindings
    from saas.scripts import render_kubernetes_release as renderer
    from saas.scripts import run_postgresql_migration as cli
    from tests.saas.test_render_kubernetes_release import (
        _canonical_json,
        _copy_sources,
        _document,
        _resource,
        _spec_document,
    )

    document = _spec_document()
    assert document["product_revision"] == document["source_revision"] == plan.product_revision
    document["control_plane_schema_revision"] = _R
    document["service_logins"] = {
        row.service: row.login for row in plan.service_role_graph.bindings
    }
    spec = tmp_path / "release.json"
    spec.write_bytes(_canonical_json(document))
    spec.chmod(0o600)
    output = tmp_path / "rendered"
    renderer.render_kubernetes_release(spec, _copy_sources(tmp_path), output)
    manifest = _document(output / "kubernetes.migration.yaml")
    config = _resource(manifest, kind="ConfigMap", data_key="service-role-bindings.json")
    release = _resource(manifest, kind="ConfigMap", data_key="OMNIGENT_SAAS_PRODUCT_REVISION")
    job = _resource(manifest, kind="Job", name="omnigent-saas-postgresql-migration")
    pod = job["spec"]["template"]["spec"]
    init = next(row for row in pod["initContainers"] if row["name"] == "stage-authority-files")
    source, staged = tmp_path / "source-files", tmp_path / "staged-files"
    source.mkdir(mode=0o700)
    staged.mkdir(mode=0o700)
    for filename, raw in config["data"].items():
        assert Path(filename).name == filename
        path = source / filename
        path.write_text(raw)
        path.chmod(0o444)
    installed = set()
    for line in init["args"][0].splitlines():
        if "/source/bindings/" not in line:
            continue
        command = shlex.split(line)
        assert command[:3] == ["install", "-m", "0400"] and len(command) == 5
        filename = Path(command[3]).name
        assert command[3] == "/source/bindings/" + filename
        assert command[4] == "/authority/" + filename and filename in config["data"]
        subprocess.run([*command[:3], str(source / filename), str(staged / filename)], check=True)
        installed.add(filename)
    assert installed == set(config["data"])
    environment = dict(release["data"])
    for name in tuple(environment):
        if name.endswith("_ROLE_BINDINGS_FILE"):
            environment[name] = str(staged / Path(environment[name]).name)
    environment["OMNIGENT_SAAS_SERVICE_ROLE_BINDINGS_FILE"] = str(
        staged / "service-role-bindings.json"
    )
    graph = service_bindings.load_production_service_role_graph(environment)
    assert len(graph.bindings) == 19 and graph.sha256 == plan.service_role_graph.sha256
    plan = replace(
        plan,
        service_role_bindings=service_bindings.load_production_service_role_bindings(environment),
        platform_model_service_role_bindings=service_bindings.load_platform_model_service_role_bindings(
            environment
        ),
        platform_admin_service_role_bindings=service_bindings.load_platform_admin_service_role_bindings(
            environment
        ),
        model_projection_service_role_bindings=service_bindings.load_model_projection_service_role_bindings(
            environment
        ),
    )
    for field, name in cli._URL_ENVIRONMENTS.items():
        kind = field.removesuffix("_url")
        authority = next(row for row in plan.authorities() if row.kind == kind)
        path = staged / (kind + "-url")
        path.write_text(authority.url.render_as_string(hide_password=False))
        path.chmod(0o400)
        environment[name] = str(path)
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    # Synthetic source identity, not signed/compiled image admission.
    monkeypatch.setattr(_build_info, "COMMIT_SHA", plan.product_revision)
    migrate = next(row for row in pod["containers"] if row["name"] == "migrate")
    arguments = [
        plan.product_revision if value == "$(OMNIGENT_SAAS_SOURCE_SHA)" else value
        for value in migrate["args"]
    ]
    assert "--verify-only" in arguments and arguments[-1] == _R
    monkeypatch.setattr(sys, "argv", ["run_postgresql_migration", *arguments])
    capsys.readouterr()
    assert cli.main() == 0
    receipt = _receipt_from_document(json.loads(capsys.readouterr().out))
    return plan, receipt


def test_p0_source_reissues_its_own_receipt_and_verifies_r_through_narrow_logins(
    production_replay, tmp_path, monkeypatch, capsys
):
    root, revision = _producer_source()
    assert migration._expected_head("saas") == _P0
    plan = replace(production_replay, product_revision="1" * 40)
    monkeypatch.setattr(migration, "_installed_product_revision", lambda: plan.product_revision)
    initial = migration.run_production_postgresql_migration(plan)
    assert initial.saas_head == _P0
    known = {row.service: row for row in plan.service_role_graph.bindings}
    rows = tuple(
        known[service]
        if service in known
        else ProductionServiceRoleBinding(
            service=service, login="replay_model_projection", base_role=role
        )
        for service, role in sorted(EXPECTED_MODEL_PROJECTION_SERVICE_ROLES.items())
    )
    path = tmp_path / "projection-bindings.json"
    path.write_text(render_production_service_role_bindings(rows))
    path.chmod(0o400)
    profile = ProductionServiceRoleBindings(
        path, hashlib.sha256(path.read_bytes()).hexdigest(), rows
    )
    admin = sa.create_engine(
        sa.make_url(os.environ["OMNIGENT_SAAS_PRODUCTION_REPLAY_POSTGRES_URL"]).set(
            query=plan.saas_owner.url.query
        ),
        isolation_level="AUTOCOMMIT",
    )
    try:
        with admin.connect() as connection:
            connection.exec_driver_sql(
                "CREATE ROLE replay_model_projection LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                "INHERIT NOREPLICATION NOBYPASSRLS PASSWORD 'production-replay-test'"
            )
    finally:
        admin.dispose()
    plan = replace(plan, model_projection_service_role_bindings=profile)
    assert len(plan.service_role_graph.bindings) == 19
    source = {}
    for prefix, binding in (
        ("OMNIGENT_SAAS_SERVICE_ROLE_BINDINGS", plan.service_role_bindings),
        (
            "OMNIGENT_SAAS_PLATFORM_MODEL_SERVICE_ROLE_BINDINGS",
            plan.platform_model_service_role_bindings,
        ),
        (
            "OMNIGENT_SAAS_PLATFORM_ADMIN_SERVICE_ROLE_BINDINGS",
            plan.platform_admin_service_role_bindings,
        ),
        ("OMNIGENT_SAAS_MODEL_PROJECTION_SERVICE_ROLE_BINDINGS", profile),
    ):
        assert binding is not None
        source[prefix + "_FILE"] = str(binding.path)
        source[prefix + "_SHA256"] = binding.sha256
    document = {
        "source_root": str(root),
        "source_revision": revision,
        "bindings": source,
        "urls": {
            authority.kind + "_url": authority.url.render_as_string(hide_password=False)
            for authority in plan.authorities()
        },
    }
    environment = {key: os.environ[key] for key in ("PATH", "TMPDIR") if key in os.environ}
    environment["PYTHONPATH"] = str(root)
    environment["OMNIGENT_SKIP_WEB_UI"] = "true"
    produced = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), "--produce"],
        cwd=root,
        env=environment,
        input=json.dumps(document),
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert produced.returncode == 0, produced.stderr[-2000:]
    producer_receipt = _receipt_from_document(json.loads(produced.stdout))
    assert producer_receipt.saas_head == _R
    assert producer_receipt.product_revision == revision != plan.product_revision
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    config, engines = _startup_config(plan, producer_receipt, foreign)
    try:
        with pytest.raises(migration.PostgreSqlMigrationError) as rejected:
            migration.verify_production_postgresql_state(engines=engines, config=config)
        assert rejected.value.code == "migration_receipt_binding_mismatch"
    finally:
        for engine in engines.values():
            engine.dispose()
    with pytest.raises(migration.PostgreSqlMigrationError):
        migration.run_production_postgresql_migration(plan, verify_only=True)
    plan, refreshed = _rendered_role_handoff(plan, tmp_path, monkeypatch, capsys)
    assert refreshed.product_revision == plan.product_revision and refreshed.verify_only is True
    assert refreshed.catalog_sha256 == producer_receipt.catalog_sha256
    assert refreshed.saas_head == _R
    own = tmp_path / "own"
    own.mkdir()
    config, engines = _startup_config(plan, refreshed, own)
    try:
        migration.verify_production_postgresql_state(engines=engines, config=config)
    finally:
        for engine in engines.values():
            engine.dispose()
    owner = sa.create_engine(plan.saas_owner.url)
    try:
        with owner.connect() as connection:
            assert (
                connection.exec_driver_sql(
                    "SELECT version_num FROM saas_alembic_version"
                ).scalar_one()
                == _R
            )
    finally:
        owner.dispose()


if __name__ == "__main__":
    if sys.argv[1:] == ["--produce"]:
        _produce_schema()
    else:
        assert sys.argv[1:] == ["--produce-runner"]
        _produce_runner_schema()
