from __future__ import annotations

import hashlib
import importlib.util
import logging
import os
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from uuid import uuid4

import pytest
import yaml

from saas.scripts.build_n1_compat import build_n1_compat, materialize_n1_compat

_N1_BASE_COMMIT = "9451a64c1affa06630b9105bf39b56bb89feba3b"


def _repository() -> Path:
    return Path(__file__).resolve().parents[2]


def _require_n1_base_commit() -> None:
    completed = subprocess.run(
        ["git", "cat-file", "-e", f"{_N1_BASE_COMMIT}^{{commit}}"],
        cwd=_repository(),
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        pytest.skip(
            "the pinned N-1 base commit is unavailable in this shallow checkout; "
            "the full-history compatibility and N-1 lanes enforce this contract"
        )


def _load_module(name: str, path: Path) -> ModuleType:
    specification = importlib.util.spec_from_file_location(name, path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


def _source_hashes(root: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            material = f"symlink:{path.readlink()}".encode()
        elif path.is_file():
            material = path.read_bytes()
        else:
            continue
        hashes[relative] = hashlib.sha256(material).hexdigest()
    return hashes


def test_n1_compat_builder_applies_only_the_pinned_security_patch() -> None:
    _require_n1_base_commit()
    report = build_n1_compat(_repository())

    assert report == {
        "base_commit": "9451a64c1affa06630b9105bf39b56bb89feba3b",
        "contract_version": "p0s3-n1-outbox-security-compat-v1",
        "materialized_source": None,
        "patch_sha256": "810d1ffdf97f46408b39eb81a56345bdf463c736bc19789c734c92ccfaffcc35",
        "patched_tree_hash": "git-sha1:87e56c8f1b7669c2028c62cf537eac97f1e027ac",
        "required_schema_revision": "p0s000000003",
        "schema_change_policy": {
            "outbox_ddl_requires_worker_drain": True,
            "catalog_recheck_before_restart": True,
        },
        "status": "verified",
    }


def test_n1_compat_image_workflow_is_fixed_signed_and_production_blocked() -> None:
    workflow_path = _repository() / ".github/workflows/saas-n1-compat-image.yml"
    source = workflow_path.read_text(encoding="utf-8")
    manifest_source = (_repository() / "saas/n1_compat/manifest.json").read_text(encoding="utf-8")
    patch_source = (_repository() / "saas/n1_compat/9451a64c1.patch").read_text(encoding="utf-8")
    workflow = yaml.load(source, Loader=yaml.BaseLoader)

    assert isinstance(workflow, dict)
    jobs = workflow["jobs"]
    current_postgresql = jobs["verify-candidate"]
    n1_postgresql = jobs["verify-postgresql-n1"]
    assert current_postgresql["services"]["postgres"]["image"] == "postgres:18"
    assert n1_postgresql["services"]["postgres"]["image"] == (
        "postgres:16.14-bookworm@"
        "sha256:64154d0babcb1741988719e703419af0382b19953706149f9872fbd0f438efa8"
    )
    n1_postgresql_steps = n1_postgresql["steps"]
    n1_postgresql_commands = "\n".join(str(step.get("run", "")) for step in n1_postgresql_steps)
    assert workflow["run-name"] == (
        "SaaS N-1 ${{ github.event_name }} "
        "pr=${{ github.event.pull_request.number || 'none' }} "
        "base=${{ github.event.pull_request.base.sha || github.sha }} "
        "head=${{ github.event.pull_request.head.sha || github.sha }}"
    )
    setup_uv_index = next(
        index for index, step in enumerate(n1_postgresql_steps) if step["name"] == "Set up uv"
    )
    pin_environment_index = next(
        index
        for index, step in enumerate(n1_postgresql_steps)
        if step["name"] == "Pin isolated PostgreSQL N-1 environment"
    )
    assert setup_uv_index < pin_environment_index
    assert n1_postgresql_steps[pin_environment_index]["run"] == (
        "printf '%s\\n' \"UV_PROJECT_ENVIRONMENT=${RUNNER_TEMP}/postgresql-n1-venv\" "
        '>> "$GITHUB_ENV"'
    )
    assert "UV_PROJECT_ENVIRONMENT" not in n1_postgresql["env"]
    assert "--no-install-local --no-config" in n1_postgresql_commands
    assert "uv run" not in n1_postgresql_commands
    assert '"$UV_PROJECT_ENVIRONMENT/bin/python" -I' in n1_postgresql_commands
    assert 'sa.text("SHOW server_version_num")' in n1_postgresql_commands
    assert "server_major != 16" in n1_postgresql_commands
    assert "test_real_postgresql_pinned_n1_outbox_compatibility_bridge" in (n1_postgresql_commands)
    assert "test_real_postgresql_n1_compat_login_admission_and_roles_replay" in (
        n1_postgresql_commands
    )
    assert "p0s000000004" in n1_postgresql_commands
    assert "postgresql-n1.xml" in n1_postgresql_commands
    assert source.count("-c pyproject.toml --confcutdir=tests") == 3
    assert 'root.tag != "testsuites" or len(root) != 1' in n1_postgresql_commands
    assert 'root[0].tag != "testsuite"' in n1_postgresql_commands
    assert "suite = root[0]" in n1_postgresql_commands
    assert '"tests": 3' in n1_postgresql_commands
    assert '"skipped": 0' in n1_postgresql_commands
    expected_paths = {
        ".github/actions/compat-smoke-saas-n1-gate/**",
        ".github/workflows/saas-n1-merge-gate.yml",
        ".github/workflows/saas-n1-compat-image.yml",
        ".python-version",
        ".uv/**",
        ".venv/**",
        "conftest.py",
        "deploy/docker/Dockerfile",
        "pyproject.toml",
        "pytest.ini",
        "setup.cfg",
        "setup.py",
        "tox.ini",
        "uv.toml",
        "uv.lock",
        "saas/**",
        "tests/conftest.py",
        "tests/saas/**",
    }
    assert set(workflow["on"]["pull_request"]["paths"]) == expected_paths
    assert set(workflow["on"]["push"]["paths"]) == expected_paths
    dispatch_inputs = workflow["on"]["workflow_dispatch"]["inputs"]
    assert set(dispatch_inputs) == {"publish_signed", "product_revision"}
    assert (
        "base_commit:" not in source.split("workflow_dispatch:", 1)[1].split("permissions:", 1)[0]
    )
    assert "N1_BASE_COMMIT: 9451a64c1affa06630b9105bf39b56bb89feba3b" in source
    assert (
        "N1_PATCH_SHA256: "
        "810d1ffdf97f46408b39eb81a56345bdf463c736bc19789c734c92ccfaffcc35" in source
    )
    assert "N1_PATCHED_TREE_HASH: git-sha1:87e56c8f1b7669c2028c62cf537eac97f1e027ac" in source
    assert "N1_SCHEMA_REVISION: p0s000000003" in source
    assert "N1_IMAGE_NAME: omnigent-saas-n1-compat" in source
    assert source.count('      - "saas/**"') == 2
    assert source.count('      - "tests/saas/**"') == 2
    assert source.count('      - ".github/actions/compat-smoke-saas-n1-gate/**"') == 2
    assert (
        source.count("uses: docker/build-push-action@f9f3042f7e2789586610d6e8b85c8f03e5195baf")
        == 3
    )
    assert source.count("platforms: linux/amd64,linux/arm64") == 3
    assert source.count("provenance: mode=max") == 3
    assert source.count("sbom: true") == 3
    assert '--output-directory "${RUNNER_TEMP}/n1-source"' in source
    assert "test_real_postgresql_pinned_n1_outbox_compatibility_bridge" in source
    assert "test_real_postgresql_n1_compat_login_admission_and_roles_replay" in source
    assert "saas.scripts.compare_oci_rebuilds" in source
    assert "target: n1-compat-runtime" in source
    assert "cat >>" not in source
    assert '"deploy/docker/Dockerfile"' in manifest_source
    assert "diff --git a/deploy/docker/Dockerfile b/deploy/docker/Dockerfile" in patch_source
    assert "FROM runtime AS n1-compat-runtime" in patch_source
    assert 'CMD ["python", "-I", "-m", "saas.n1_outbox_launcher"]' in patch_source
    assert "ai.omnigent.saas.n1.base-commit=${N1_BASE_COMMIT}" in patch_source
    assert "ai.omnigent.saas.n1.patch-source-revision=${SOURCE_REVISION}" in patch_source
    assert "ai.omnigent.saas.n1.patch-sha256=${N1_PATCH_SHA256}" in patch_source
    assert "ai.omnigent.saas.n1.patched-tree-hash=${N1_PATCHED_TREE_HASH}" in patch_source
    assert "ai.omnigent.saas.n1.schema-revision=${CONTROL_PLANE_SCHEMA_REVISION}" in patch_source
    assert "ai.omnigent.saas.n1.contract-version=${N1_CONTRACT_VERSION}" in patch_source
    assert source.count("N1_BASE_COMMIT=${{ env.N1_BASE_COMMIT }}") == 3
    assert source.count("N1_PATCH_SHA256=${{ env.N1_PATCH_SHA256 }}") == 3
    assert source.count("N1_PATCHED_TREE_HASH=${{ env.N1_PATCHED_TREE_HASH }}") == 3
    assert "UPSTREAM_REVISION=${{ env.N1_BASE_COMMIT }}" not in source
    assert source.count("UPSTREAM_REVISION=${{ env.UPSTREAM_REVISION }}") == 3
    assert "ADAPTER_CONTRACT_VERSION=${{ env.N1_CONTRACT_VERSION }}" not in source
    assert source.count("ADAPTER_CONTRACT_VERSION=${{ env.ADAPTER_CONTRACT_VERSION }}") == 3
    assert (
        source.count(
            'jq -r .upstream_revision "${RUNNER_TEMP}/n1-source/saas/upstream-baseline.json"'
        )
        == 2
    )

    publish = jobs["publish-candidate"]
    assert publish["needs"] == ["verify-candidate", "verify-postgresql-n1"]
    publish_condition = publish["if"]
    assert "github.event_name == 'workflow_dispatch'" in publish_condition
    assert "github.ref == 'refs/heads/main'" in publish_condition
    assert "inputs.product_revision == github.sha" in publish_condition
    assert publish["environment"] == "production-image"
    assert publish["permissions"]["id-token"] == "write"
    assert publish["permissions"]["packages"] == "write"
    assert "ghcr.io/${owner}/${N1_IMAGE_NAME}" in source
    assert '--repo "$GITHUB_REPOSITORY"' in source
    assert '--signer-workflow "$SIGNER_WORKFLOW"' in source
    assert "--source-ref refs/heads/main" in source
    assert '--source-digest "$PRODUCT_REVISION"' in source
    assert source.count("uses: actions/attest@c32b4b8b198b65d0bd9d63490e847ff7b53989d4") == 1

    assert source.count("production_ready: false") == 2
    assert "production_ready: true" not in source
    assert source.count("production_receipt: null") == 2
    assert "external_hsm_receipt: null" in source
    assert "vulnerability_scan: null" in source
    assert "license_scan: null" in source
    assert "one-hour digest-pinned Canary is not completed" in source
    assert "900-second N-1 rollback exercise is not completed" in source
    assert source.count("outbox_ddl_requires_worker_drain == true") == 3
    assert source.count("catalog_recheck_before_restart == true") == 3
    assert source.count("compat_worker_drain_required: true") == 2
    assert "production-ready" not in source.lower()

    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("uses:") and not stripped.startswith("uses: ./"):
            reference = stripped.split("@", 1)[1].split()[0]
            assert len(reference) == 40
            assert all(character in "0123456789abcdef" for character in reference)


def test_n1_compat_builder_materializes_deterministic_git_free_source(
    tmp_path: Path,
) -> None:
    _require_n1_base_commit()
    first = tmp_path / "first"
    second = tmp_path / "second"

    first_report = build_n1_compat(_repository(), output_directory=first)
    second_report = build_n1_compat(_repository(), output_directory=second)

    assert first_report["materialized_source"] == str(first.resolve())
    assert second_report["materialized_source"] == str(second.resolve())
    assert not (first / ".git").exists()
    assert not (second / ".git").exists()
    assert _source_hashes(first) == _source_hashes(second)
    worker_main = (
        (first / "saas/outbox_worker.py").read_text(encoding="utf-8").split("def main()", 1)[1]
    )
    assert "catalog_fingerprint(engine, expected_login=expected_login)" in worker_main
    assert "verify_dispatcher_database_role(engine)" not in worker_main
    admission = (first / "saas/n1_outbox_compat_admission.py").read_text(encoding="utf-8")
    assert "_OUTBOX_SCHEMA_SIGNATURE" in admission
    assert "_N1_COLUMN_ACLS" in admission
    assert "_N1_EFFECTIVE_COLUMN_ACLS" in admission
    assert "effective_allowed_column_acls" in admission
    assert "forbidden_column_acl" in admission
    assert "forbidden_relation_acl" in admission
    assert "direct_catalog_authority" in admission
    assert "non_system_schema_ownership" in admission
    assert "executable_security_definers" in admission
    assert "effective_database_temp" in admission
    assert "ORDER BY relation.relname, rewrite.rulename" in admission

    occupied = tmp_path / "occupied"
    occupied.mkdir()
    (occupied / "keep.txt").write_text("preserve", encoding="utf-8")
    with pytest.raises(RuntimeError, match="output directory is not empty"):
        build_n1_compat(_repository(), output_directory=occupied)
    assert (occupied / "keep.txt").read_text(encoding="utf-8") == "preserve"


def test_n1_compat_hides_provider_db_and_dsn_secrets(caplog: pytest.LogCaptureFixture) -> None:
    _require_n1_base_commit()
    provider_secret = "provider-secret-must-never-appear"
    database_secret = "database-secret-must-never-appear"
    first_password = "first-password-must-never-appear"
    rotated_password = "rotated-password-must-never-appear"

    with materialize_n1_compat(_repository()) as (root, _):
        admission = _load_module(
            "n1_patched_admission",
            root / "saas/n1_outbox_compat_admission.py",
        )
        first_dsn = (
            "postgresql+psycopg://compat_user:"
            f"{first_password}@db.internal:5432/control?sslmode=require"
        )
        rotated_dsn = (
            "postgresql+psycopg://compat_user:"
            f"{rotated_password}@db.internal:5432/control?sslmode=require"
        )
        fingerprint = admission.dsn_coordinate_fingerprint(first_dsn)
        assert fingerprint == admission.dsn_coordinate_fingerprint(rotated_dsn)
        assert fingerprint != admission.dsn_coordinate_fingerprint(
            rotated_dsn.replace("db.internal", "other.internal")
        )
        assert all(secret not in fingerprint for secret in (first_password, rotated_password))

        with pytest.raises(RuntimeError) as unsafe_query:
            admission.dsn_coordinate_fingerprint(
                f"postgresql+psycopg://compat_user:{first_password}@db/control"
                f"?sslpassword={database_secret}"
            )
        assert unsafe_query.value.__suppress_context__
        assert all(
            secret not in str(unsafe_query.value)
            for secret in (first_password, rotated_password, database_secret)
        )

        outbox = _load_module(
            "n1_patched_outbox",
            root / "saas/control_plane/outbox.py",
        )

        class SecretPublisher:
            def publish(self, **_values: object) -> None:
                raise RuntimeError(provider_secret)

        dispatcher = outbox.OutboxDispatcher(lambda: None, SecretPublisher())
        event = outbox.ClaimedOutboxEvent(
            id=uuid4(),
            event_type="test.event",
            aggregate_type="test",
            aggregate_key="test",
            payload={},
            attempt_count=1,
        )
        dispatcher._claim = lambda **_values: [event]

        def release_failure(*_values: object) -> None:
            raise RuntimeError(database_secret)

        dispatcher._release_failure = release_failure
        with pytest.raises(RuntimeError) as release_error:
            dispatcher.dispatch_once(now=datetime.now(timezone.utc))
        assert str(release_error.value) == "outbox_failure_release_failed"
        assert release_error.value.__suppress_context__
        assert provider_secret not in str(release_error.value)
        assert database_secret not in str(release_error.value)

        previous_admission = sys.modules.get("saas.n1_outbox_compat_admission")
        sys.modules["saas.n1_outbox_compat_admission"] = admission
        try:
            worker = _load_module(
                "n1_patched_worker",
                root / "saas/outbox_worker.py",
            )
        finally:
            if previous_admission is None:
                sys.modules.pop("saas.n1_outbox_compat_admission", None)
            else:
                sys.modules["saas.n1_outbox_compat_admission"] = previous_admission

        class FailingDispatcher:
            def dispatch_once(self, **_values: object) -> object:
                raise RuntimeError(provider_secret + database_secret)

        class StopAfterFailure:
            def is_set(self) -> bool:
                return False

            def wait(self, _timeout: float | None = None) -> bool:
                return True

        logger = logging.getLogger(f"n1-compat-test-{uuid4()}")
        caplog.set_level(logging.ERROR, logger=logger.name)
        stats = worker.OutboxWorker(FailingDispatcher(), logger=logger).run(StopAfterFailure())
        assert stats.infrastructure_failures == 1
        assert provider_secret not in caplog.text
        assert database_secret not in caplog.text
        assert all(not record.exc_info for record in caplog.records)


def test_n1_compat_launcher_modules_ship_and_load_from_isolated_wheel(tmp_path: Path) -> None:
    _require_n1_base_commit()
    with materialize_n1_compat(_repository()) as (root, _):
        output = tmp_path / "dist"
        uv = shutil.which("uv")
        assert uv is not None
        subprocess.run(
            [
                uv,
                "build",
                "--wheel",
                "--no-build-isolation",
                "--python",
                sys.executable,
                "--offline",
                "--no-create-gitignore",
                "--out-dir",
                str(output),
                str(root),
            ],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            env={**os.environ, "OMNIGENT_SKIP_WEB_UI": "true"},
        )
        wheels = list(output.glob("*.whl"))
        assert len(wheels) == 1
        wheel = wheels[0]
        with zipfile.ZipFile(wheel) as archive:
            names = set(archive.namelist())
        assert "saas/n1_outbox_compat_admission.py" in names
        assert "saas/n1_outbox_launcher.py" in names

        probe = subprocess.run(
            [
                sys.executable,
                "-I",
                "-c",
                "import sys; sys.path.insert(0, sys.argv[1]); "
                "import saas.n1_outbox_launcher, saas.outbox_worker",
                str(wheel),
            ],
            cwd=tmp_path,
            check=False,
            capture_output=True,
            text=True,
        )
        assert probe.returncode == 0, probe.stderr
