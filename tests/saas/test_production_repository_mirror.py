from __future__ import annotations

import json
import os
import stat
import subprocess
from collections.abc import Sequence
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from saas.production.repository_mirror import (
    RepositoryBindingProvision,
    RepositoryMirrorError,
    RepositoryMirrorReceipt,
    RepositoryProvisioningSpec,
    SealedGitRepositoryFetcher,
    VerifiedRepositoryBindings,
    load_and_verify_repository_bindings,
    load_repository_provisioning_spec,
    provision_repository_mirrors,
    render_repository_provisioning_spec,
)


def _git(*arguments: str, cwd: Path | None = None) -> str:
    result = subprocess.run(
        ["/usr/bin/git", *arguments],
        capture_output=True,
        check=False,
        cwd=cwd,
        env={
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "HOME": "/nonexistent",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
        },
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


def _source_repository(path: Path) -> tuple[Path, str]:
    path.mkdir(mode=0o700)
    _git("init", "--initial-branch=main", cwd=path)
    (path / "README.md").write_text("trusted fixture\n", encoding="utf-8")
    _git("add", "README.md", cwd=path)
    _git(
        "-c",
        "user.name=Repository Fixture",
        "-c",
        "user.email=fixture@example.test",
        "commit",
        "-m",
        "fixture",
        cwd=path,
    )
    return path, _git("rev-parse", "HEAD", cwd=path).strip()


class LocalRepositoryFetcher:
    """Exercise real Git objects while keeping the suite completely offline."""

    def __init__(self, source: Path, *, secret: str) -> None:
        self.source = source
        self.secret = secret
        self.calls: list[tuple[str, ...]] = []

    def fetch(
        self,
        *,
        mirror: Path,
        source_url: str,
        refspecs: Sequence[str],
        credential_file: Path,
    ) -> None:
        assert source_url.startswith("https://example.test/")
        assert credential_file.read_text(encoding="ascii").find(self.secret) >= 0
        assert _git("-C", str(mirror), "config", "--get", "gc.auto") == "0\n"
        assert _git("-C", str(mirror), "config", "--get", "maintenance.auto") == "false\n"
        command = (
            "/usr/bin/git",
            "-C",
            str(mirror),
            "fetch",
            "--force",
            "--no-tags",
            "--no-recurse-submodules",
            "--no-write-fetch-head",
            "--prune",
            "--end-of-options",
            str(self.source),
            *refspecs,
        )
        assert self.secret not in "\0".join(command)
        self.calls.append(command)
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            env={
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_TERMINAL_PROMPT": "0",
                "HOME": "/nonexistent",
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
            },
            timeout=30,
        )
        assert result.returncode == 0
        assert self.secret.encode() not in result.stdout
        assert self.secret.encode() not in result.stderr


def _private_directory(path: Path, *, mode: int = 0o700) -> Path:
    path.mkdir(mode=mode)
    path.chmod(mode)
    return path


def _fixture_spec(
    tmp_path: Path,
    *,
    revision: str,
    refs: tuple[tuple[str, str], ...] = (),
    runner_id: UUID | None = None,
    runner_generation: int = 7,
    runner_slot: str = "a",
    mirror_root: Path | None = None,
    stem: str = "runner-a",
) -> tuple[Path, RepositoryProvisioningSpec, str]:
    secret = "not-for-the-main-runner"
    credentials = tmp_path / "credentials"
    if not credentials.exists():
        _private_directory(credentials)
    credential_file = credentials / f"{stem}.credentials"
    credential_file.write_text(
        f"https://runner:{secret}@example.test/acme/repository.git\n",
        encoding="ascii",
    )
    credential_file.chmod(0o400)
    runtime = tmp_path / stem
    if not runtime.exists():
        _private_directory(runtime)
    binding = RepositoryBindingProvision(
        binding_key="repository-primary",
        repository_id="example.test/acme/repository",
        source_url="https://example.test/acme/repository.git",
        credential_file=credential_file,
        revision=None if refs else revision,
        refs=refs,
    )
    spec = RepositoryProvisioningSpec(
        runner_id=runner_id or uuid4(),
        runner_generation=runner_generation,
        runner_slot=runner_slot,
        mirror_root=mirror_root or runtime / "mirrors",
        credential_root=credentials,
        bindings_file=runtime / "repository-bindings.json",
        receipt_file=runtime / "repository-mirror-receipt.json",
        expected_binding_keys=(binding.binding_key,),
        bindings=(binding,),
    )
    spec_file = runtime / "repository-provisioning.json"
    spec_file.write_text(render_repository_provisioning_spec(spec), encoding="ascii")
    spec_file.chmod(0o400)
    return spec_file, spec, secret


def _canonical_write(path: Path, document: object) -> None:
    path.chmod(0o600)
    path.write_text(
        json.dumps(document, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n",
        encoding="ascii",
    )
    path.chmod(0o400)


def _verify_receipt(
    receipt: RepositoryMirrorReceipt,
    spec: RepositoryProvisioningSpec,
) -> VerifiedRepositoryBindings:
    return load_and_verify_repository_bindings(
        receipt.bindings_file,
        receipt.receipt_file,
        expected_runner_id=spec.runner_id,
        expected_runner_generation=spec.runner_generation,
        expected_runner_slot=spec.runner_slot,
        expected_binding_keys=spec.expected_binding_keys,
        expected_spec_sha256=receipt.spec_sha256,
        expected_bindings_sha256=receipt.bindings_sha256,
        expected_receipt_sha256=receipt.receipt_sha256,
    )


def test_provisions_atomic_credential_free_bare_mirror_and_reverifies(
    tmp_path: Path,
) -> None:
    source, revision = _source_repository(tmp_path / "source")
    spec_file, spec, secret = _fixture_spec(tmp_path, revision=revision)
    fetcher = LocalRepositoryFetcher(source, secret=secret)

    receipt = provision_repository_mirrors(spec_file, fetcher=fetcher)
    repeated = provision_repository_mirrors(spec_file, fetcher=fetcher)
    verified = _verify_receipt(receipt, spec)

    assert len(fetcher.calls) == 1
    assert repeated.receipt_sha256 == receipt.receipt_sha256
    assert verified.bindings == receipt.bindings
    assert verified.spec_sha256 == receipt.spec_sha256
    bindings_raw = receipt.bindings_file.read_bytes()
    receipt_raw = receipt.receipt_file.read_bytes()
    assert bindings_raw == (
        json.dumps(json.loads(bindings_raw), separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("ascii")
    assert receipt_raw == (
        json.dumps(json.loads(receipt_raw), separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("ascii")
    assert stat.S_IMODE(receipt.bindings_file.stat().st_mode) == 0o400
    assert stat.S_IMODE(receipt.receipt_file.stat().st_mode) == 0o400
    assert secret.encode() not in bindings_raw + receipt_raw
    assert b"source_url" not in receipt_raw
    assert b"credential" not in receipt_raw
    assert str(spec.credential_root).encode() not in bindings_raw + receipt_raw
    mirror = receipt.bindings["repository-primary"]
    assert _git("-C", str(mirror), "rev-parse", "--is-bare-repository") == "true\n"
    assert _git("-C", str(mirror), "cat-file", "-t", revision) == "commit\n"
    config = _git("-C", str(mirror), "config", "--local", "--list")
    assert "remote." not in config
    assert "credential." not in config
    assert "alias." not in config
    assert "gc.auto" not in config
    assert "maintenance.auto" not in config
    assert not (mirror / "hooks").exists()
    assert not (mirror / "FETCH_HEAD").exists()


def test_beta_profile_rejects_secondary_binding_and_credential_path_drift(
    tmp_path: Path,
) -> None:
    source, revision = _source_repository(tmp_path / "source")
    spec_file, _spec, secret = _fixture_spec(tmp_path, revision=revision)
    document = json.loads(spec_file.read_text(encoding="ascii"))
    document["bindings"][0]["binding_key"] = "secondary"
    document["expected_binding_keys"] = ["secondary"]
    _canonical_write(spec_file, document)

    with pytest.raises(RepositoryMirrorError, match="release binding profile"):
        provision_repository_mirrors(
            spec_file,
            fetcher=LocalRepositoryFetcher(source, secret=secret),
            expected_binding_keys=("primary",),
            expected_credential_files={
                "primary": Path("/provisioning-private/credentials/primary.credential")
            },
        )

    document["bindings"][0]["binding_key"] = "primary"
    document["expected_binding_keys"] = ["primary"]
    _canonical_write(spec_file, document)
    with pytest.raises(RepositoryMirrorError, match="credential projection"):
        provision_repository_mirrors(
            spec_file,
            fetcher=LocalRepositoryFetcher(source, secret=secret),
            expected_binding_keys=("primary",),
            expected_credential_files={
                "primary": Path("/provisioning-private/credentials/primary.credential")
            },
        )


def test_runtime_reverifier_rejects_release_expected_binding_key_drift(
    tmp_path: Path,
) -> None:
    source, revision = _source_repository(tmp_path / "source")
    spec_file, spec, secret = _fixture_spec(tmp_path, revision=revision)
    receipt = provision_repository_mirrors(
        spec_file,
        fetcher=LocalRepositoryFetcher(source, secret=secret),
    )

    with pytest.raises(RepositoryMirrorError, match="release key set"):
        load_and_verify_repository_bindings(
            receipt.bindings_file,
            receipt.receipt_file,
            expected_runner_id=spec.runner_id,
            expected_runner_generation=spec.runner_generation,
            expected_runner_slot=spec.runner_slot,
            expected_binding_keys=("primary",),
            expected_spec_sha256=receipt.spec_sha256,
            expected_bindings_sha256=receipt.bindings_sha256,
            expected_receipt_sha256=receipt.receipt_sha256,
        )


@pytest.mark.parametrize(
    "pin",
    ["spec", "bindings", "receipt", "slot"],
)
def test_startup_reverifier_requires_every_release_authority_pin(
    tmp_path: Path,
    pin: str,
) -> None:
    source, revision = _source_repository(tmp_path / "source")
    spec_file, spec, secret = _fixture_spec(tmp_path, revision=revision)
    receipt = provision_repository_mirrors(
        spec_file,
        fetcher=LocalRepositoryFetcher(source, secret=secret),
    )
    arguments = {
        "expected_runner_id": spec.runner_id,
        "expected_runner_generation": spec.runner_generation,
        "expected_runner_slot": spec.runner_slot,
        "expected_binding_keys": spec.expected_binding_keys,
        "expected_spec_sha256": receipt.spec_sha256,
        "expected_bindings_sha256": receipt.bindings_sha256,
        "expected_receipt_sha256": receipt.receipt_sha256,
    }
    if pin == "slot":
        arguments["expected_runner_slot"] = "b"
    else:
        arguments[f"expected_{pin}_sha256"] = "0" * 64

    with pytest.raises(RepositoryMirrorError, match=r"digest changed|authority changed"):
        load_and_verify_repository_bindings(
            receipt.bindings_file,
            receipt.receipt_file,
            **arguments,
        )


def test_mirror_root_marker_binds_same_generation_to_exact_spec(tmp_path: Path) -> None:
    source, revision = _source_repository(tmp_path / "source")
    spec_file, _spec, secret = _fixture_spec(tmp_path, revision=revision)
    provision_repository_mirrors(
        spec_file,
        fetcher=LocalRepositoryFetcher(source, secret=secret),
    )
    replacement = json.loads(spec_file.read_text(encoding="ascii"))
    replacement["bindings"][0]["revision"] = "0" * 40
    _canonical_write(spec_file, replacement)

    with pytest.raises(RepositoryMirrorError, match="authority changed"):
        provision_repository_mirrors(
            spec_file,
            fetcher=LocalRepositoryFetcher(source, secret=secret),
        )


def test_owner_file_reader_rejects_metadata_change_during_read(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _source, revision = _source_repository(tmp_path / "source")
    spec_file, _spec, _secret = _fixture_spec(tmp_path, revision=revision)
    original_read = os.read
    changed = False

    def racing_read(descriptor: int, count: int) -> bytes:
        nonlocal changed
        result = original_read(descriptor, count)
        if not changed:
            changed = True
            spec_file.chmod(0o600)
        return result

    monkeypatch.setattr(os, "read", racing_read)

    with pytest.raises(RepositoryMirrorError, match="changed during inspection"):
        load_repository_provisioning_spec(spec_file)


def test_sealed_fetcher_keeps_secret_values_out_of_argv_environment_and_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    secret = "credential-value-must-stay-in-file"
    credential = tmp_path / "credential root" / "repository credentials"
    credential.parent.mkdir(mode=0o700)
    credential.write_text(
        f"https://runner:{secret}@example.test/acme/repository.git\n",
        encoding="ascii",
    )
    credential.chmod(0o400)
    calls: list[tuple[Sequence[str], dict[str, object]]] = []

    def run(command: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(subprocess, "run", run)

    SealedGitRepositoryFetcher().fetch(
        mirror=tmp_path / "mirror.git",
        source_url="https://example.test/acme/repository.git",
        refspecs=("+" + "1" * 40 + ":refs/omnigent/pins/" + "1" * 40,),
        credential_file=credential,
    )

    assert len(calls) == 1
    command, options = calls[0]
    child_environment = options["env"]
    assert isinstance(child_environment, dict)
    serialized = "\0".join(command) + json.dumps(child_environment, sort_keys=True)
    assert secret not in serialized
    assert "credential.helper=store --file='" in serialized
    assert "http.followRedirects=false" in command
    assert "GIT_CONFIG_PARAMETERS" not in child_environment
    assert "GIT_ALTERNATE_OBJECT_DIRECTORIES" not in child_environment


def test_reviewed_ref_sha_drift_is_rejected_without_publishing_outputs(tmp_path: Path) -> None:
    source, reviewed_revision = _source_repository(tmp_path / "source")
    spec_file, spec, secret = _fixture_spec(
        tmp_path,
        revision=reviewed_revision,
        refs=(("refs/heads/main", reviewed_revision),),
    )
    (source / "README.md").write_text("drifted\n", encoding="utf-8")
    _git("add", "README.md", cwd=source)
    _git(
        "-c",
        "user.name=Repository Fixture",
        "-c",
        "user.email=fixture@example.test",
        "commit",
        "-m",
        "drift",
        cwd=source,
    )

    with pytest.raises(RepositoryMirrorError, match="SHA changed"):
        provision_repository_mirrors(
            spec_file,
            fetcher=LocalRepositoryFetcher(source, secret=secret),
        )

    assert not spec.bindings_file.exists()
    assert not spec.receipt_file.exists()
    assert {entry.name for entry in spec.mirror_root.iterdir()} == {
        ".omnigent-runner-mirror-root.json"
    }


@pytest.mark.parametrize(
    "source_url",
    [
        "file:///private/tmp/repository",
        "/private/tmp/repository",
        "../repository",
        "http://example.test/acme/repository.git",
        "https://localhost/acme/repository.git",
        "https://127.0.0.1/acme/repository.git",
        "https://Example.test/acme/repository.git",
        "https://example.test/acme/../repository.git",
        "https://runner@example.test/acme/repository.git",
    ],
)
def test_rejects_local_relative_or_noncanonical_repository_substitution(
    tmp_path: Path,
    source_url: str,
) -> None:
    _source, revision = _source_repository(tmp_path / "source")
    spec_file, _spec, _secret = _fixture_spec(tmp_path, revision=revision)
    document = json.loads(spec_file.read_text(encoding="ascii"))
    document["bindings"][0]["source_url"] = source_url
    if source_url.startswith("https://127.0.0.1/"):
        document["bindings"][0]["repository_id"] = "127.0.0.1/acme/repository"

    _canonical_write(spec_file, document)

    with pytest.raises(RepositoryMirrorError):
        load_repository_provisioning_spec(spec_file)


def test_rejects_outputs_nested_in_writable_mirror_root(tmp_path: Path) -> None:
    source, revision = _source_repository(tmp_path / "source")
    spec_file, spec, secret = _fixture_spec(tmp_path, revision=revision)
    document = json.loads(spec_file.read_text(encoding="ascii"))
    document["bindings_file"] = str(spec.mirror_root / "repository-bindings.json")
    _canonical_write(spec_file, document)

    with pytest.raises(RepositoryMirrorError, match="mirror_root"):
        provision_repository_mirrors(
            spec_file,
            fetcher=LocalRepositoryFetcher(source, secret=secret),
        )


@pytest.mark.parametrize("mutation", ["missing", "extra", "duplicate_repository"])
def test_rejects_extra_missing_or_duplicate_binding_authority(
    tmp_path: Path,
    mutation: str,
) -> None:
    _source, revision = _source_repository(tmp_path / "source")
    spec_file, _spec, _secret = _fixture_spec(tmp_path, revision=revision)
    document = json.loads(spec_file.read_text(encoding="ascii"))
    if mutation == "missing":
        document["expected_binding_keys"] = []
    elif mutation == "extra":
        document["expected_binding_keys"].append("repository-secondary")
    else:
        second = dict(document["bindings"][0])
        second["binding_key"] = "repository-secondary"
        credential = Path(document["credential_root"]) / "secondary.credentials"
        credential.write_text(
            "https://runner:other@example.test/acme/repository.git\n",
            encoding="ascii",
        )
        credential.chmod(0o400)
        second["credential_file"] = str(credential)
        document["bindings"].append(second)
        document["expected_binding_keys"].append("repository-secondary")
    document["expected_binding_keys"].sort()
    _canonical_write(spec_file, document)

    with pytest.raises(RepositoryMirrorError):
        load_repository_provisioning_spec(spec_file)


def test_rejects_noncanonical_oversized_or_mutable_spec(tmp_path: Path) -> None:
    _source, revision = _source_repository(tmp_path / "source")
    spec_file, _spec, _secret = _fixture_spec(tmp_path, revision=revision)
    document = json.loads(spec_file.read_text(encoding="ascii"))

    spec_file.chmod(0o600)
    spec_file.write_text(json.dumps(document, indent=2), encoding="ascii")
    spec_file.chmod(0o400)
    with pytest.raises(RepositoryMirrorError, match="canonical JSON"):
        load_repository_provisioning_spec(spec_file)

    spec_file.chmod(0o600)
    spec_file.write_bytes(b"{" + b" " * (65 * 1024) + b"}")
    spec_file.chmod(0o400)
    with pytest.raises(RepositoryMirrorError, match="owner-only regular file"):
        load_repository_provisioning_spec(spec_file)

    spec_file.chmod(0o600)
    _canonical_write(spec_file, document)
    spec_file.chmod(0o600)
    with pytest.raises(RepositoryMirrorError, match="owner-only regular file"):
        load_repository_provisioning_spec(spec_file)


@pytest.mark.parametrize("mutation", ["extra_file", "missing_file", "symlink", "mutable"])
def test_rejects_unprotected_or_inexact_credential_root(tmp_path: Path, mutation: str) -> None:
    source, revision = _source_repository(tmp_path / "source")
    spec_file, spec, secret = _fixture_spec(tmp_path, revision=revision)
    credential = spec.bindings[0].credential_file
    if mutation == "extra_file":
        extra = spec.credential_root / "unreviewed.credentials"
        extra.write_text("unused\n", encoding="ascii")
        extra.chmod(0o400)
    elif mutation == "missing_file":
        credential.unlink()
    elif mutation == "symlink":
        target = tmp_path / "outside.credentials"
        target.write_text(credential.read_text(encoding="ascii"), encoding="ascii")
        target.chmod(0o400)
        credential.unlink()
        credential.symlink_to(target)
    else:
        credential.chmod(0o600)

    with pytest.raises(RepositoryMirrorError):
        provision_repository_mirrors(
            spec_file,
            fetcher=LocalRepositoryFetcher(source, secret=secret),
        )


def test_runner_identity_marker_rejects_shared_writable_ab_root(tmp_path: Path) -> None:
    source, revision = _source_repository(tmp_path / "source")
    first_file, first, secret = _fixture_spec(tmp_path, revision=revision, stem="runner-a")
    provision_repository_mirrors(
        first_file,
        fetcher=LocalRepositoryFetcher(source, secret=secret),
    )
    second_file, _second, secret = _fixture_spec(
        tmp_path,
        revision=revision,
        runner_id=uuid4(),
        runner_generation=9,
        runner_slot="b",
        mirror_root=first.mirror_root,
        stem="runner-b",
    )
    first.bindings[0].credential_file.unlink()

    with pytest.raises(RepositoryMirrorError, match="authority changed"):
        provision_repository_mirrors(
            second_file,
            fetcher=LocalRepositoryFetcher(source, secret=secret),
        )


def test_reverifier_rejects_executable_config_and_symlink_tampering(tmp_path: Path) -> None:
    source, revision = _source_repository(tmp_path / "source")
    spec_file, spec, secret = _fixture_spec(tmp_path, revision=revision)
    receipt = provision_repository_mirrors(
        spec_file,
        fetcher=LocalRepositoryFetcher(source, secret=secret),
    )
    mirror = receipt.bindings["repository-primary"]
    _git("-C", str(mirror), "config", "alias.unsafe", "!touch /tmp/should-not-run")
    (mirror / "config").chmod(0o600)

    with pytest.raises(RepositoryMirrorError, match="allowlist"):
        _verify_receipt(receipt, spec)

    _git("-C", str(mirror), "config", "--unset-all", "alias.unsafe")
    (mirror / "config").chmod(0o600)
    (mirror / "unsafe-link").symlink_to("HEAD")
    with pytest.raises(RepositoryMirrorError, match="file is unsafe"):
        _verify_receipt(receipt, spec)


@pytest.mark.parametrize(
    ("config_key", "config_value"),
    [
        ("remote.origin.url", "https://example.test/acme/repository.git"),
        ("credential.helper", "store --file=/private/tmp/untrusted"),
        ("core.hookspath", "/private/tmp/hooks"),
        ("include.path", "/private/tmp/git-config"),
        ("alias.unsafe", "!touch /private/tmp/should-not-run"),
        ("url.file:///private/tmp/.insteadof", "https://example.test/"),
        ("filter.unsafe.clean", "touch /private/tmp/should-not-run"),
        ("submodule.vendor.url", "file:///private/tmp/vendor"),
    ],
)
def test_reverifier_rejects_remote_credential_and_executable_git_config(
    tmp_path: Path,
    config_key: str,
    config_value: str,
) -> None:
    source, revision = _source_repository(tmp_path / "source")
    spec_file, spec, secret = _fixture_spec(tmp_path, revision=revision)
    receipt = provision_repository_mirrors(
        spec_file,
        fetcher=LocalRepositoryFetcher(source, secret=secret),
    )
    mirror = receipt.bindings["repository-primary"]
    _git("-C", str(mirror), "config", config_key, config_value)
    (mirror / "config").chmod(0o600)

    with pytest.raises(RepositoryMirrorError, match="allowlist"):
        _verify_receipt(receipt, spec)


def test_rejects_submodule_selection(tmp_path: Path) -> None:
    source, revision = _source_repository(tmp_path / "source")
    _git(
        "update-index",
        "--add",
        "--cacheinfo",
        f"160000,{revision},vendor/dependency",
        cwd=source,
    )
    _git(
        "-c",
        "user.name=Repository Fixture",
        "-c",
        "user.email=fixture@example.test",
        "commit",
        "-m",
        "gitlink",
        cwd=source,
    )
    gitlink_revision = _git("rev-parse", "HEAD", cwd=source).strip()
    spec_file, _spec, secret = _fixture_spec(tmp_path, revision=gitlink_revision)

    with pytest.raises(RepositoryMirrorError, match="submodules"):
        provision_repository_mirrors(
            spec_file,
            fetcher=LocalRepositoryFetcher(source, secret=secret),
        )


def test_rejects_nested_gitmodules_path_without_gitlink(tmp_path: Path) -> None:
    source, _revision = _source_repository(tmp_path / "source")
    nested = source / "nested"
    nested.mkdir()
    (nested / ".gitmodules").write_text(
        '[submodule "forbidden"]\n\tpath = forbidden\n',
        encoding="utf-8",
    )
    _git("add", "nested/.gitmodules", cwd=source)
    _git(
        "-c",
        "user.name=Repository Fixture",
        "-c",
        "user.email=fixture@example.test",
        "commit",
        "-m",
        "nested gitmodules",
        cwd=source,
    )
    revision = _git("rev-parse", "HEAD", cwd=source).strip()
    spec_file, _spec, secret = _fixture_spec(tmp_path, revision=revision)

    with pytest.raises(RepositoryMirrorError, match="submodules"):
        provision_repository_mirrors(
            spec_file,
            fetcher=LocalRepositoryFetcher(source, secret=secret),
        )


def test_output_reverification_rejects_owner_mode_and_canonical_drift(tmp_path: Path) -> None:
    source, revision = _source_repository(tmp_path / "source")
    spec_file, spec, secret = _fixture_spec(tmp_path, revision=revision)
    receipt = provision_repository_mirrors(
        spec_file,
        fetcher=LocalRepositoryFetcher(source, secret=secret),
    )
    receipt.bindings_file.chmod(0o600)
    with pytest.raises(RepositoryMirrorError, match="owner-only"):
        _verify_receipt(receipt, spec)

    receipt.bindings_file.chmod(0o400)
    document = json.loads(receipt.receipt_file.read_text(encoding="ascii"))
    receipt.receipt_file.chmod(0o600)
    receipt.receipt_file.write_text(json.dumps(document, indent=2), encoding="ascii")
    receipt.receipt_file.chmod(0o400)
    with pytest.raises(RepositoryMirrorError, match="canonical JSON"):
        _verify_receipt(receipt, spec)


def test_local_fetcher_receives_no_ambient_git_or_credential_environment(tmp_path: Path) -> None:
    source, revision = _source_repository(tmp_path / "source")
    spec_file, _spec, secret = _fixture_spec(tmp_path, revision=revision)
    fetcher = LocalRepositoryFetcher(source, secret=secret)
    os.environ["GIT_CONFIG_PARAMETERS"] = "'url.file:///tmp/.insteadOf=https://'"
    os.environ["GIT_ALTERNATE_OBJECT_DIRECTORIES"] = "/tmp/untrusted"
    try:
        provision_repository_mirrors(spec_file, fetcher=fetcher)
    finally:
        os.environ.pop("GIT_CONFIG_PARAMETERS")
        os.environ.pop("GIT_ALTERNATE_OBJECT_DIRECTORIES")
    assert len(fetcher.calls) == 1
