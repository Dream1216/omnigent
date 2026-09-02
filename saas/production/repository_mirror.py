"""Fail-closed Runner repository mirror provisioning and startup verification.

The provisioning process is intended to run in an init container.  It consumes
the only credential mount, creates an atomic set of credential-free bare
mirrors, and emits the small binding document consumed by the main Runner.
"""

from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Protocol, cast
from urllib.parse import unquote, urlsplit
from uuid import UUID, uuid4

_MAX_SPEC_BYTES = 64 * 1024
_MAX_OUTPUT_BYTES = 256 * 1024
_MAX_CREDENTIAL_BYTES = 16 * 1024
_MAX_BINDINGS = 64
_MAX_REFS = 32
_FULL_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_BINDING_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_REPOSITORY_SEGMENT = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$")
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SAFE_CONFIG: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "core.bare": frozenset({"true"}),
        "core.filemode": frozenset({"true"}),
        "core.repositoryformatversion": frozenset({"0"}),
    }
)
_ROOT_MARKER = ".omnigent-runner-mirror-root.json"
_ACTIVE_DIRECTORY = "active"


class RepositoryMirrorError(ValueError):
    """Stable, secret-free rejection for repository supply-chain drift."""


@dataclass(frozen=True, slots=True)
class RepositoryBindingProvision:
    """One exact repository identity and immutable object selection."""

    binding_key: str
    repository_id: str
    source_url: str
    credential_file: Path
    revision: str | None
    refs: tuple[tuple[str, str], ...]

    @property
    def object_ids(self) -> tuple[str, ...]:
        if self.revision is not None:
            return (self.revision,)
        return tuple(sorted({object_id for _ref, object_id in self.refs}))

    @property
    def selection_type(self) -> str:
        return "revision" if self.revision is not None else "refs"


@dataclass(frozen=True, slots=True)
class RepositoryProvisioningSpec:
    """Canonical init-container authority for one Runner mirror root."""

    runner_id: UUID
    runner_generation: int
    runner_slot: str
    mirror_root: Path
    credential_root: Path
    bindings_file: Path
    receipt_file: Path
    expected_binding_keys: tuple[str, ...]
    bindings: tuple[RepositoryBindingProvision, ...]
    sha256: str = ""


@dataclass(frozen=True, slots=True)
class RepositoryMirrorReceipt:
    """Secret-free canonical receipt and the compatible Runner bindings."""

    bindings_file: Path
    receipt_file: Path
    bindings_sha256: str
    receipt_sha256: str
    spec_sha256: str
    bindings: Mapping[str, Path]


@dataclass(frozen=True, slots=True)
class VerifiedRepositoryBindings:
    """Startup-safe mirror registry after full filesystem and Git re-verification."""

    bindings_file: Path
    receipt_file: Path
    bindings_sha256: str
    receipt_sha256: str
    spec_sha256: str
    runner_id: UUID
    runner_generation: int
    runner_slot: str
    bindings: Mapping[str, Path]


class RepositoryFetcher(Protocol):
    """Credential-bearing fetch boundary; production uses the sealed implementation."""

    def fetch(
        self,
        *,
        mirror: Path,
        source_url: str,
        refspecs: Sequence[str],
        credential_file: Path,
    ) -> None: ...


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("ascii")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _reject_symlink_components(path: Path, *, field: str) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            break
        except OSError as error:
            raise RepositoryMirrorError(f"{field} cannot be inspected") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise RepositoryMirrorError(f"{field} must not traverse a symlink")


def _absolute_path(value: object, *, field: str) -> Path:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or "\x00" in value
        or any(ord(character) < 0x20 for character in value)
        or not Path(value).is_absolute()
        or os.path.normpath(value) != value
    ):
        raise RepositoryMirrorError(f"{field} must be one canonical absolute path")
    path = Path(value)
    _reject_symlink_components(path, field=field)
    return path


def _file_snapshot(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _inspect_regular_file(
    path: Path,
    *,
    maximum: int,
    field: str,
) -> tuple[int, int, int, int, int, int, int, int]:
    if not path.is_absolute():
        raise RepositoryMirrorError(f"{field} must be an absolute path")
    _reject_symlink_components(path, field=field)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise RepositoryMirrorError(f"{field} cannot be inspected") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o400
        or metadata.st_nlink != 1
        or not 0 < metadata.st_size <= maximum
    ):
        raise RepositoryMirrorError(f"{field} must be one owner-only regular file")
    return _file_snapshot(metadata)


def _read_owner_file(path: Path, *, maximum: int, field: str) -> bytes:
    initial = _inspect_regular_file(path, maximum=maximum, field=field)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RepositoryMirrorError(f"{field} cannot be opened safely") from error
    try:
        opened = os.fstat(descriptor)
        if (
            _file_snapshot(opened) != initial
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o400
            or opened.st_nlink != 1
            or not 0 < opened.st_size <= maximum
        ):
            raise RepositoryMirrorError(f"{field} changed during inspection")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after_read = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        after_path = path.lstat()
    except OSError as error:
        raise RepositoryMirrorError(f"{field} changed during inspection") from error
    if (
        _file_snapshot(after_read) != initial
        or _file_snapshot(after_path) != initial
        or not raw
        or len(raw) > maximum
        or len(raw) != initial[5]
    ):
        raise RepositoryMirrorError(f"{field} changed during inspection")
    if not raw or len(raw) > maximum:
        raise RepositoryMirrorError(f"{field} has an invalid size")
    return raw


def _private_directory(path: Path, *, field: str, writable: bool) -> Path:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise RepositoryMirrorError(f"{field} cannot be inspected") from error
    mode = stat.S_IMODE(metadata.st_mode)
    owner_access = mode & 0o700
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or mode & 0o077
        or owner_access not in ({0o700} if writable else {0o500, 0o700})
    ):
        raise RepositoryMirrorError(f"{field} must be an owner-only directory")
    return resolved


def _validate_hostname(hostname: str) -> str:
    host = hostname.lower()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise RepositoryMirrorError("repository source host must not be an IP literal")
    if (
        host != hostname
        or len(host) > 253
        or "." not in host
        or host.endswith((".local", ".localhost"))
        or host in {"localhost", "localhost.localdomain"}
        or all(label.isdigit() for label in host.split("."))
        or any(_HOST_LABEL.fullmatch(label) is None for label in host.split("."))
    ):
        raise RepositoryMirrorError("repository source host is invalid")
    return host


def _repository_identity(source_url: str) -> str:
    if (
        source_url != source_url.strip()
        or any(ord(character) < 0x20 for character in source_url)
        or "\\" in source_url
        or "%" in source_url
    ):
        raise RepositoryMirrorError("repository source URL is invalid")
    try:
        parsed = urlsplit(source_url)
        port = parsed.port
    except ValueError as error:
        raise RepositoryMirrorError("repository source URL is invalid") from error
    canonical_netloc = (
        cast(str, parsed.hostname) if port is None else f"{cast(str, parsed.hostname)}:443"
    )
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.netloc != canonical_netloc
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
        or parsed.path.endswith("/")
        or "//" in parsed.path
    ):
        raise RepositoryMirrorError("repository source must be one credential-free HTTPS URL")
    host = _validate_hostname(parsed.hostname)
    raw_path = parsed.path[1:]
    path = raw_path[:-4] if raw_path.endswith(".git") else raw_path
    segments = path.split("/")
    if (
        not 2 <= len(segments) <= 8
        or any(segment in {".", ".."} for segment in segments)
        or any(_REPOSITORY_SEGMENT.fullmatch(segment) is None for segment in segments)
    ):
        raise RepositoryMirrorError("repository identity path is invalid")
    return f"{host}/{path}"


def _validate_repository_id(value: object) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise RepositoryMirrorError("repository identity is invalid")
    parts = value.split("/")
    if (
        not 3 <= len(parts) <= 9
        or _validate_hostname(parts[0]) != parts[0]
        or any(_REPOSITORY_SEGMENT.fullmatch(segment) is None for segment in parts[1:])
    ):
        raise RepositoryMirrorError("repository identity is invalid")
    return value


def _validate_binding_key(value: object) -> str:
    if not isinstance(value, str) or _BINDING_KEY.fullmatch(value) is None:
        raise RepositoryMirrorError("repository binding key is invalid")
    return value


def _validate_ref(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith(("refs/heads/", "refs/tags/"))
        or len(value) > 255
        or value.endswith(("/", ".", ".lock"))
        or ".." in value
        or "//" in value
        or "@{" in value
        or "\\" in value
        or any(ord(character) < 0x20 or character in " ~^:?*[" for character in value)
    ):
        raise RepositoryMirrorError("reviewed repository ref is invalid")
    return value


def _validate_sha1(value: object) -> str:
    if not isinstance(value, str) or _FULL_SHA1.fullmatch(value) is None:
        raise RepositoryMirrorError("repository revision must be one full lowercase SHA-1")
    return value


def _validate_sha256(value: object, *, field: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise RepositoryMirrorError(f"{field} must be one lowercase SHA-256")
    return value


def _binding_document(binding: RepositoryBindingProvision) -> dict[str, object]:
    document: dict[str, object] = {
        "binding_key": binding.binding_key,
        "credential_file": str(binding.credential_file),
        "repository_id": binding.repository_id,
        "source_url": binding.source_url,
    }
    if binding.revision is not None:
        document["revision"] = binding.revision
    else:
        document["refs"] = dict(binding.refs)
    return document


def render_repository_provisioning_spec(spec: RepositoryProvisioningSpec) -> str:
    """Render the unique owner-reviewed provisioning-spec representation."""

    document = {
        "bindings": [_binding_document(binding) for binding in spec.bindings],
        "bindings_file": str(spec.bindings_file),
        "credential_root": str(spec.credential_root),
        "expected_binding_keys": list(spec.expected_binding_keys),
        "mirror_root": str(spec.mirror_root),
        "receipt_file": str(spec.receipt_file),
        "runner_generation": spec.runner_generation,
        "runner_id": str(spec.runner_id),
        "runner_slot": spec.runner_slot,
        "schema_version": 1,
    }
    return _canonical_json(document).decode("ascii")


def load_repository_provisioning_spec(path: Path | str) -> RepositoryProvisioningSpec:
    """Load one owner-only, bounded, byte-canonical repository authority."""

    spec_path = Path(path)
    raw = _read_owner_file(
        spec_path,
        maximum=_MAX_SPEC_BYTES,
        field="repository provisioning spec",
    )
    try:
        document = json.loads(raw.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RepositoryMirrorError("repository provisioning spec is invalid") from error
    expected_keys = {
        "bindings",
        "bindings_file",
        "credential_root",
        "expected_binding_keys",
        "mirror_root",
        "receipt_file",
        "runner_generation",
        "runner_id",
        "runner_slot",
        "schema_version",
    }
    if not isinstance(document, dict) or set(document) != expected_keys:
        raise RepositoryMirrorError("repository provisioning spec has an invalid shape")
    rows = document.get("bindings")
    expected = document.get("expected_binding_keys")
    generation = document.get("runner_generation")
    schema_version = document.get("schema_version")
    if (
        isinstance(schema_version, bool)
        or schema_version != 1
        or not isinstance(rows, list)
        or not 1 <= len(rows) <= _MAX_BINDINGS
        or not isinstance(expected, list)
        or isinstance(generation, bool)
        or not isinstance(generation, int)
        or not 1 <= generation <= 2**63 - 1
        or document.get("runner_slot") not in {"a", "b"}
    ):
        raise RepositoryMirrorError("repository provisioning spec has invalid values")
    try:
        runner_id = UUID(cast(str, document["runner_id"]))
    except (TypeError, ValueError) as error:
        raise RepositoryMirrorError("repository Runner identity is invalid") from error
    if runner_id.int == 0 or str(runner_id) != document["runner_id"]:
        raise RepositoryMirrorError("repository Runner identity is invalid")
    expected_binding_keys = tuple(_validate_binding_key(value) for value in expected)
    if tuple(sorted(expected_binding_keys)) != expected_binding_keys or len(
        set(expected_binding_keys)
    ) != len(expected_binding_keys):
        raise RepositoryMirrorError("expected repository bindings must be unique and sorted")
    bindings: list[RepositoryBindingProvision] = []
    for row in rows:
        common = {"binding_key", "credential_file", "repository_id", "source_url"}
        if not isinstance(row, dict) or (
            set(row) != common | {"revision"} and set(row) != common | {"refs"}
        ):
            raise RepositoryMirrorError("repository binding has an invalid shape")
        binding_key = _validate_binding_key(row.get("binding_key"))
        source_url = row.get("source_url")
        repository_id = row.get("repository_id")
        if not isinstance(source_url, str) or not isinstance(repository_id, str):
            raise RepositoryMirrorError("repository identity is invalid")
        derived_identity = _repository_identity(source_url)
        if _validate_repository_id(repository_id) != derived_identity:
            raise RepositoryMirrorError("repository identity does not match its source URL")
        credential_file = _absolute_path(row.get("credential_file"), field="credential_file")
        revision: str | None = None
        refs: tuple[tuple[str, str], ...] = ()
        if "revision" in row:
            revision = _validate_sha1(row.get("revision"))
        else:
            raw_refs = row.get("refs")
            if not isinstance(raw_refs, dict) or not 1 <= len(raw_refs) <= _MAX_REFS:
                raise RepositoryMirrorError("reviewed repository refs are invalid")
            refs = tuple(
                sorted(
                    (
                        _validate_ref(source_ref),
                        _validate_sha1(object_id),
                    )
                    for source_ref, object_id in raw_refs.items()
                )
            )
        bindings.append(
            RepositoryBindingProvision(
                binding_key=binding_key,
                repository_id=repository_id,
                source_url=source_url,
                credential_file=credential_file,
                revision=revision,
                refs=refs,
            )
        )
    parsed_bindings = tuple(sorted(bindings, key=lambda item: item.binding_key))
    binding_keys = tuple(binding.binding_key for binding in parsed_bindings)
    if binding_keys != expected_binding_keys:
        raise RepositoryMirrorError("repository bindings must exactly match the expected key set")
    if len({binding.repository_id for binding in parsed_bindings}) != len(parsed_bindings):
        raise RepositoryMirrorError("one repository identity cannot have duplicate bindings")
    if len({binding.source_url for binding in parsed_bindings}) != len(parsed_bindings):
        raise RepositoryMirrorError("one repository source cannot have duplicate bindings")
    spec = RepositoryProvisioningSpec(
        runner_id=runner_id,
        runner_generation=cast(int, generation),
        runner_slot=cast(str, document["runner_slot"]),
        mirror_root=_absolute_path(document["mirror_root"], field="mirror_root"),
        credential_root=_absolute_path(document["credential_root"], field="credential_root"),
        bindings_file=_absolute_path(document["bindings_file"], field="bindings_file"),
        receipt_file=_absolute_path(document["receipt_file"], field="receipt_file"),
        expected_binding_keys=expected_binding_keys,
        bindings=parsed_bindings,
        sha256=_sha256(raw),
    )
    if raw != render_repository_provisioning_spec(spec).encode("ascii"):
        raise RepositoryMirrorError("repository provisioning spec must be canonical JSON")
    return spec


def _path_contains(parent: Path, child: Path) -> bool:
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return True


def _validate_credential_file(binding: RepositoryBindingProvision, credential_root: Path) -> None:
    credential = binding.credential_file
    try:
        if credential.parent.resolve(strict=True) != credential_root:
            raise RepositoryMirrorError(
                "credential files must be direct children of credential_root"
            )
    except OSError as error:
        raise RepositoryMirrorError("credential file parent cannot be inspected") from error
    raw = _read_owner_file(
        credential,
        maximum=_MAX_CREDENTIAL_BYTES,
        field="repository credential file",
    )
    try:
        text = raw.decode("ascii")
    except UnicodeError as error:
        raise RepositoryMirrorError("repository credential file is invalid") from error
    if not text.endswith("\n") or "\n" in text[:-1] or "\r" in text:
        raise RepositoryMirrorError("repository credential file is invalid")
    try:
        parsed = urlsplit(text[:-1])
        source = urlsplit(binding.source_url)
        port = parsed.port
    except ValueError as error:
        raise RepositoryMirrorError("repository credential file is invalid") from error
    username = unquote(parsed.username) if parsed.username is not None else ""
    password = unquote(parsed.password) if parsed.password is not None else ""
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.hostname.lower() != cast(str, source.hostname).lower()
        or not username
        or not password
        or any(ord(character) < 0x20 for character in username + password)
        or port not in {None, 443}
        or parsed.path != source.path
        or parsed.query
        or parsed.fragment
    ):
        raise RepositoryMirrorError("repository credential does not match its exact source")


def _validate_credentials(spec: RepositoryProvisioningSpec) -> Path:
    root = _private_directory(spec.credential_root, field="credential_root", writable=False)
    expected_names = {binding.credential_file.name for binding in spec.bindings}
    if len(expected_names) != len(spec.bindings):
        raise RepositoryMirrorError("repository credential files must be unique")
    try:
        actual_names = {entry.name for entry in root.iterdir()}
    except OSError as error:
        raise RepositoryMirrorError("credential_root cannot be enumerated") from error
    if actual_names != expected_names:
        raise RepositoryMirrorError("credential_root must contain the exact credential file set")
    for binding in spec.bindings:
        _validate_credential_file(binding, root)
    return root


def _atomic_write(path: Path, content: bytes) -> str:
    parent = _private_directory(path.parent, field="output directory", writable=True)
    if path.exists() or path.is_symlink():
        _inspect_regular_file(path, maximum=_MAX_OUTPUT_BYTES, field="existing output file")
    temporary = parent / f".{path.name}.{uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o400)
    try:
        os.fchmod(descriptor, 0o400)
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
    else:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return _sha256(content)


def _root_marker_document(spec: RepositoryProvisioningSpec) -> dict[str, object]:
    return {
        "runner_generation": spec.runner_generation,
        "runner_id": str(spec.runner_id),
        "runner_slot": spec.runner_slot,
        "schema_version": 1,
        "spec_sha256": spec.sha256,
    }


def _ensure_mirror_root(spec: RepositoryProvisioningSpec) -> Path:
    root = spec.mirror_root
    if not root.exists() and not root.is_symlink():
        _private_directory(root.parent, field="mirror_root parent", writable=True)
        with contextlib.suppress(FileExistsError):
            root.mkdir(mode=0o700)
    resolved = _private_directory(root, field="mirror_root", writable=True)
    marker = resolved / _ROOT_MARKER
    expected = _canonical_json(_root_marker_document(spec))
    if marker.exists() or marker.is_symlink():
        raw = _read_owner_file(marker, maximum=4096, field="mirror_root identity marker")
        if raw != expected:
            raise RepositoryMirrorError("writable mirror_root authority changed")
    else:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(marker, flags, 0o400)
        except FileExistsError:
            raw = _read_owner_file(marker, maximum=4096, field="mirror_root identity marker")
            if raw != expected:
                raise RepositoryMirrorError("writable mirror_root authority changed") from None
        else:
            try:
                view = memoryview(expected)
                while view:
                    written = os.write(descriptor, view)
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            directory = os.open(resolved, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    return resolved


def _git_environment() -> dict[str, str]:
    return {
        "GIT_ASKPASS": "/usr/bin/false" if Path("/usr/bin/false").exists() else "/bin/false",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def _git_binary() -> str:
    candidate = Path("/usr/bin/git")
    if not candidate.exists():
        raise RepositoryMirrorError("trusted Git executable is unavailable")
    try:
        metadata = candidate.stat()
    except OSError as error:
        raise RepositoryMirrorError("trusted Git executable is unavailable") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o022:
        raise RepositoryMirrorError("trusted Git executable is unsafe")
    return str(candidate)


def _run_git(
    mirror: Path,
    arguments: Sequence[str],
    *,
    output: bool = False,
    allowed_exit_codes: frozenset[int] = frozenset({0}),
) -> bytes:
    command = [_git_binary(), "-C", str(mirror), *arguments]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            stdin=subprocess.DEVNULL,
            env=_git_environment(),
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise RepositoryMirrorError("Git repository verification failed") from error
    if result.returncode not in allowed_exit_codes:
        raise RepositoryMirrorError("Git repository verification failed")
    if len(result.stdout) > 8 * 1024 * 1024 or len(result.stderr) > 8 * 1024 * 1024:
        raise RepositoryMirrorError("Git repository verification output is excessive")
    return result.stdout if output else b""


class SealedGitRepositoryFetcher:
    """Fetch HTTPS objects with credentials read only by Git's trusted helper."""

    def fetch(
        self,
        *,
        mirror: Path,
        source_url: str,
        refspecs: Sequence[str],
        credential_file: Path,
    ) -> None:
        command = [
            _git_binary(),
            "-c",
            "credential.helper=",
            "-c",
            f"credential.helper=store --file={shlex.quote(str(credential_file))}",
            "-c",
            "credential.useHttpPath=true",
            "-c",
            "http.followRedirects=false",
            "-C",
            str(mirror),
            "fetch",
            "--force",
            "--no-tags",
            "--no-recurse-submodules",
            "--no-write-fetch-head",
            "--prune",
            "--end-of-options",
            source_url,
            *refspecs,
        ]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                check=False,
                stdin=subprocess.DEVNULL,
                env=_git_environment(),
                timeout=300,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise RepositoryMirrorError("repository fetch failed") from error
        if (
            result.returncode != 0
            or len(result.stdout) > 8 * 1024 * 1024
            or len(result.stderr) > 8 * 1024 * 1024
        ):
            raise RepositoryMirrorError("repository fetch failed")


def _internal_ref(source_ref: str) -> str:
    return f"refs/omnigent/reviewed/{_sha256(source_ref.encode('ascii'))[:48]}"


def _expected_internal_refs(binding: RepositoryBindingProvision) -> dict[str, str]:
    if binding.revision is not None:
        return {f"refs/omnigent/pins/{binding.revision}": binding.revision}
    return {_internal_ref(source_ref): object_id for source_ref, object_id in binding.refs}


def _refspecs(binding: RepositoryBindingProvision) -> tuple[str, ...]:
    if binding.revision is not None:
        target = f"refs/omnigent/pins/{binding.revision}"
        return (f"+{binding.revision}:{target}",)
    return tuple(
        f"+{source_ref}:{_internal_ref(source_ref)}" for source_ref, _object_id in binding.refs
    )


def _initialize_bare_mirror(path: Path) -> None:
    path.mkdir(mode=0o700)
    try:
        result = subprocess.run(
            [_git_binary(), "init", "--bare", str(path)],
            capture_output=True,
            check=False,
            stdin=subprocess.DEVNULL,
            env=_git_environment(),
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise RepositoryMirrorError("bare repository initialization failed") from error
    if result.returncode != 0:
        raise RepositoryMirrorError("bare repository initialization failed")
    hooks = path / "hooks"
    if hooks.exists():
        shutil.rmtree(hooks)
    for optional_key in ("core.ignorecase", "core.precomposeunicode"):
        _run_git(
            path,
            ["config", "--local", "--unset-all", optional_key],
            allowed_exit_codes=frozenset({0, 5}),
        )
    _run_git(path, ["config", "--local", "core.filemode", "true"])


def _normalize_mirror_permissions(mirror: Path) -> None:
    for root, directories, files in os.walk(mirror, topdown=True, followlinks=False):
        root_path = Path(root)
        root_metadata = root_path.lstat()
        if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
            raise RepositoryMirrorError("repository mirror contains an unsafe directory")
        os.chmod(root_path, 0o700, follow_symlinks=False)
        for name in directories:
            candidate = root_path / name
            metadata = candidate.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise RepositoryMirrorError("repository mirror contains an unsafe directory")
        for name in files:
            candidate = root_path / name
            metadata = candidate.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
            ):
                raise RepositoryMirrorError("repository mirror contains an unsafe file")
            os.chmod(candidate, 0o600, follow_symlinks=False)


def _verify_filesystem_tree(mirror: Path) -> None:
    try:
        root_metadata = mirror.lstat()
    except OSError as error:
        raise RepositoryMirrorError("repository mirror cannot be inspected") from error
    if (
        stat.S_ISLNK(root_metadata.st_mode)
        or not stat.S_ISDIR(root_metadata.st_mode)
        or root_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(root_metadata.st_mode) != 0o700
    ):
        raise RepositoryMirrorError("repository mirror root is unsafe")
    for root, directories, files in os.walk(mirror, topdown=True, followlinks=False):
        root_path = Path(root)
        metadata = root_path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise RepositoryMirrorError("repository mirror directory is unsafe")
        for name in directories:
            candidate = root_path / name
            child = candidate.lstat()
            if stat.S_ISLNK(child.st_mode) or not stat.S_ISDIR(child.st_mode):
                raise RepositoryMirrorError("repository mirror directory is unsafe")
        for name in files:
            candidate = root_path / name
            child = candidate.lstat()
            mode = stat.S_IMODE(child.st_mode)
            if (
                stat.S_ISLNK(child.st_mode)
                or not stat.S_ISREG(child.st_mode)
                or child.st_uid != os.geteuid()
                or child.st_nlink != 1
                or mode & 0o177
                or not mode & 0o400
            ):
                raise RepositoryMirrorError("repository mirror file is unsafe")


def _local_config(mirror: Path) -> dict[str, str]:
    raw = _run_git(
        mirror,
        ["config", "--local", "--no-includes", "--null", "--list"],
        output=True,
    )
    result: dict[str, str] = {}
    for item in raw.split(b"\0"):
        if not item:
            continue
        try:
            key, value = item.decode("utf-8").split("\n", 1)
        except (UnicodeError, ValueError) as error:
            raise RepositoryMirrorError("repository Git config is invalid") from error
        if key in result:
            raise RepositoryMirrorError("repository Git config has duplicate values")
        result[key.lower()] = value
    return result


def _verify_config(mirror: Path) -> None:
    config = _local_config(mirror)
    if (
        not {"core.repositoryformatversion", "core.filemode", "core.bare"} <= set(config)
        or any(key not in _SAFE_CONFIG for key in config)
        or any(value not in _SAFE_CONFIG[key] for key, value in config.items())
    ):
        raise RepositoryMirrorError("repository Git config is outside the final allowlist")
    if (mirror / "hooks").exists() or (mirror / "hooks").is_symlink():
        raise RepositoryMirrorError("repository mirror must not retain Git hooks")
    for relative in (
        "FETCH_HEAD",
        "objects/info/alternates",
        "objects/info/http-alternates",
        "shallow",
    ):
        candidate = mirror / relative
        if candidate.exists() or candidate.is_symlink():
            raise RepositoryMirrorError("repository mirror retains mutable transport state")
    for candidate in (mirror / "objects").rglob("*.promisor"):
        if candidate.exists() or candidate.is_symlink():
            raise RepositoryMirrorError("partial repository mirrors are forbidden")


def _read_refs(mirror: Path) -> dict[str, str]:
    raw = _run_git(
        mirror,
        ["for-each-ref", "--format=%(refname) %(objectname)"],
        output=True,
    )
    refs: dict[str, str] = {}
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError as error:
        raise RepositoryMirrorError("repository refs are invalid") from error
    for line in lines:
        try:
            ref, object_id = line.split(" ", 1)
        except ValueError as error:
            raise RepositoryMirrorError("repository refs are invalid") from error
        if ref in refs or _FULL_SHA1.fullmatch(object_id) is None:
            raise RepositoryMirrorError("repository refs are invalid")
        refs[ref] = object_id
    return refs


def _verify_no_submodules(mirror: Path, object_ids: Sequence[str]) -> None:
    for object_id in object_ids:
        raw = _run_git(
            mirror,
            ["ls-tree", "-r", "--full-tree", object_id],
            output=True,
        )
        lines = raw.splitlines()
        contains_gitmodules = any(
            any(
                component.lower() == b".gitmodules"
                for component in line.partition(b"\t")[2].split(b"/")
            )
            for line in lines
        )
        if contains_gitmodules or any(line.startswith(b"160000 ") for line in lines):
            raise RepositoryMirrorError("repository selection contains forbidden submodules")


def _reachable_objects(mirror: Path, object_ids: Sequence[str]) -> tuple[str, ...]:
    raw = _run_git(
        mirror,
        ["rev-list", "--objects", "--no-object-names", *object_ids],
        output=True,
    )
    try:
        objects = tuple(sorted(set(raw.decode("ascii").splitlines())))
    except UnicodeError as error:
        raise RepositoryMirrorError("repository object inventory is invalid") from error
    if not objects or any(_FULL_SHA1.fullmatch(object_id) is None for object_id in objects):
        raise RepositoryMirrorError("repository object inventory is invalid")
    all_raw = _run_git(
        mirror,
        ["cat-file", "--batch-all-objects", "--batch-check=%(objectname)"],
        output=True,
    )
    try:
        all_objects = tuple(sorted(set(all_raw.decode("ascii").splitlines())))
    except UnicodeError as error:
        raise RepositoryMirrorError("repository object inventory is invalid") from error
    if all_objects != objects:
        raise RepositoryMirrorError("repository mirror contains unreviewed objects")
    return objects


def _mirror_digest_document(
    *,
    binding_key: str,
    repository_id: str,
    selection_type: str,
    refs: Mapping[str, str],
    object_ids: Sequence[str],
    reachable_objects_sha256: str,
) -> dict[str, object]:
    return {
        "binding_key": binding_key,
        "object_ids": list(object_ids),
        "reachable_objects_sha256": reachable_objects_sha256,
        "refs": dict(refs),
        "repository_id": repository_id,
        "selection_type": selection_type,
    }


def _verify_mirror(
    mirror: Path,
    *,
    binding_key: str,
    repository_id: str,
    selection_type: str,
    refs: Mapping[str, str],
    object_ids: Sequence[str],
    expected_digest: str | None = None,
    expected_reachable_sha256: str | None = None,
) -> tuple[str, str]:
    _verify_filesystem_tree(mirror)
    if _run_git(mirror, ["rev-parse", "--is-bare-repository"], output=True) != b"true\n":
        raise RepositoryMirrorError("repository mirror is not bare")
    _verify_config(mirror)
    internal_refs = (
        {f"refs/omnigent/pins/{object_ids[0]}": object_ids[0]}
        if selection_type == "revision"
        else {_internal_ref(source_ref): object_id for source_ref, object_id in refs.items()}
    )
    if _read_refs(mirror) != internal_refs:
        raise RepositoryMirrorError("repository refs do not match the reviewed selection")
    for object_id in object_ids:
        object_type = _run_git(mirror, ["cat-file", "-t", object_id], output=True)
        if object_type != b"commit\n":
            raise RepositoryMirrorError("repository selection is not a commit")
    _run_git(mirror, ["fsck", "--full", "--strict", "--no-reflogs", "--no-dangling"])
    _verify_no_submodules(mirror, object_ids)
    reachable = _reachable_objects(mirror, object_ids)
    reachable_sha256 = _sha256(("\n".join(reachable) + "\n").encode("ascii"))
    if expected_reachable_sha256 is not None and reachable_sha256 != expected_reachable_sha256:
        raise RepositoryMirrorError("repository object inventory changed")
    digest = _sha256(
        _canonical_json(
            _mirror_digest_document(
                binding_key=binding_key,
                repository_id=repository_id,
                selection_type=selection_type,
                refs=refs,
                object_ids=object_ids,
                reachable_objects_sha256=reachable_sha256,
            )
        )
    )
    if expected_digest is not None and digest != expected_digest:
        raise RepositoryMirrorError("repository mirror digest changed")
    return reachable_sha256, digest


def _mirror_name(binding_key: str) -> str:
    return f"repo-{_sha256(binding_key.encode('ascii'))}.git"


def _provision_binding(
    binding: RepositoryBindingProvision,
    mirror: Path,
    fetcher: RepositoryFetcher,
) -> None:
    _initialize_bare_mirror(mirror)
    fetcher.fetch(
        mirror=mirror,
        source_url=binding.source_url,
        refspecs=_refspecs(binding),
        credential_file=binding.credential_file,
    )
    _normalize_mirror_permissions(mirror)
    if _read_refs(mirror) != _expected_internal_refs(binding):
        raise RepositoryMirrorError("repository SHA changed during fetch")
    public_refs = dict(binding.refs)
    _verify_mirror(
        mirror,
        binding_key=binding.binding_key,
        repository_id=binding.repository_id,
        selection_type=binding.selection_type,
        refs=public_refs,
        object_ids=binding.object_ids,
    )


def _receipt_binding(
    binding: RepositoryBindingProvision,
    mirror: Path,
) -> dict[str, object]:
    refs = dict(binding.refs)
    reachable_sha256, digest = _verify_mirror(
        mirror,
        binding_key=binding.binding_key,
        repository_id=binding.repository_id,
        selection_type=binding.selection_type,
        refs=refs,
        object_ids=binding.object_ids,
    )
    return {
        "binding_key": binding.binding_key,
        "mirror_digest": digest,
        "mirror_path": str(mirror),
        "object_ids": list(binding.object_ids),
        "reachable_objects_sha256": reachable_sha256,
        "refs": refs,
        "repository_id": binding.repository_id,
        "selection_type": binding.selection_type,
    }


def _verify_spec_paths(spec: RepositoryProvisioningSpec, credential_root: Path) -> None:
    resolved_spec_paths = {
        "mirror_root": spec.mirror_root.resolve(strict=False),
        "credential_root": credential_root,
        "bindings_file": spec.bindings_file.resolve(strict=False),
        "receipt_file": spec.receipt_file.resolve(strict=False),
    }
    if len(set(resolved_spec_paths.values())) != len(resolved_spec_paths):
        raise RepositoryMirrorError("repository provisioning paths must be distinct")
    mirror_root = resolved_spec_paths["mirror_root"]
    if _path_contains(mirror_root, credential_root) or _path_contains(
        credential_root, mirror_root
    ):
        raise RepositoryMirrorError("credential_root and writable mirror_root must be isolated")
    if any(
        _path_contains(credential_root, resolved_spec_paths[name])
        for name in ("bindings_file", "receipt_file")
    ):
        raise RepositoryMirrorError("Runner outputs must not be written into credential_root")
    if any(
        _path_contains(mirror_root, resolved_spec_paths[name])
        for name in ("bindings_file", "receipt_file")
    ):
        raise RepositoryMirrorError("Runner outputs must not be written into mirror_root")
    if spec.bindings_file == spec.receipt_file:
        raise RepositoryMirrorError("repository output paths must be distinct")


def provision_repository_mirrors(
    spec_path: Path | str,
    *,
    fetcher: RepositoryFetcher | None = None,
    expected_binding_keys: tuple[str, ...] | None = None,
    expected_credential_files: Mapping[str, Path] | None = None,
) -> RepositoryMirrorReceipt:
    """Create or re-verify one atomic, credential-free Runner mirror set."""

    spec = load_repository_provisioning_spec(spec_path)
    if expected_binding_keys is not None:
        canonical_expected_keys = tuple(
            _validate_binding_key(value) for value in expected_binding_keys
        )
        if (
            not canonical_expected_keys
            or canonical_expected_keys != tuple(sorted(canonical_expected_keys))
            or len(set(canonical_expected_keys)) != len(canonical_expected_keys)
            or spec.expected_binding_keys != canonical_expected_keys
        ):
            raise RepositoryMirrorError(
                "repository provisioning spec does not match the release binding profile"
            )
        if expected_credential_files is None or set(expected_credential_files) != set(
            canonical_expected_keys
        ):
            raise RepositoryMirrorError(
                "repository credential projection does not match the release binding profile"
            )
        projected_credentials = {
            binding.binding_key: binding.credential_file for binding in spec.bindings
        }
        if projected_credentials != dict(expected_credential_files):
            raise RepositoryMirrorError(
                "repository credential projection does not match the release binding profile"
            )
    elif expected_credential_files is not None:
        raise RepositoryMirrorError(
            "repository credential projection requires expected binding keys"
        )
    credential_root = _validate_credentials(spec)
    _verify_spec_paths(spec, credential_root)
    root = _ensure_mirror_root(spec)
    active = root / _ACTIVE_DIRECTORY
    expected_names = {_mirror_name(binding.binding_key) for binding in spec.bindings}
    allowed_root_names = {_ROOT_MARKER, _ACTIVE_DIRECTORY}
    try:
        root_names = {entry.name for entry in root.iterdir()}
    except OSError as error:
        raise RepositoryMirrorError("mirror_root cannot be enumerated") from error
    if not root_names <= allowed_root_names:
        raise RepositoryMirrorError("mirror_root contains unmanaged state")
    transport = fetcher or SealedGitRepositoryFetcher()
    if not active.exists() and not active.is_symlink():
        staging = root / f".staging-{uuid4().hex}"
        staging.mkdir(mode=0o700)
        try:
            for binding in spec.bindings:
                _provision_binding(binding, staging / _mirror_name(binding.binding_key), transport)
            os.replace(staging, active)
            directory = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except BaseException:
            if staging.exists() and not staging.is_symlink():
                shutil.rmtree(staging)
            raise
    active_resolved = _private_directory(active, field="active mirror set", writable=True)
    try:
        if {entry.name for entry in active_resolved.iterdir()} != expected_names:
            raise RepositoryMirrorError("active mirror set does not match the exact bindings")
    except OSError as error:
        raise RepositoryMirrorError("active mirror set cannot be enumerated") from error
    receipt_bindings = [
        _receipt_binding(binding, active_resolved / _mirror_name(binding.binding_key))
        for binding in spec.bindings
    ]
    bindings_document = {
        "bindings": {
            binding.binding_key: str(active_resolved / _mirror_name(binding.binding_key))
            for binding in spec.bindings
        },
        "schema_version": 1,
    }
    receipt_document = {
        "bindings": receipt_bindings,
        "mirror_root": str(root),
        "runner_generation": spec.runner_generation,
        "runner_id": str(spec.runner_id),
        "runner_slot": spec.runner_slot,
        "schema_version": 1,
        "spec_sha256": spec.sha256,
    }
    bindings_raw = _canonical_json(bindings_document)
    receipt_raw = _canonical_json(receipt_document)
    bindings_sha256 = _atomic_write(spec.bindings_file, bindings_raw)
    receipt_sha256 = _atomic_write(spec.receipt_file, receipt_raw)
    return RepositoryMirrorReceipt(
        bindings_file=spec.bindings_file,
        receipt_file=spec.receipt_file,
        bindings_sha256=bindings_sha256,
        receipt_sha256=receipt_sha256,
        spec_sha256=spec.sha256,
        bindings=MappingProxyType(
            {
                binding.binding_key: active_resolved / _mirror_name(binding.binding_key)
                for binding in spec.bindings
            }
        ),
    )


def _load_canonical_output(path: Path | str, *, field: str) -> tuple[bytes, object]:
    output_path = Path(path)
    raw = _read_owner_file(output_path, maximum=_MAX_OUTPUT_BYTES, field=field)
    try:
        document = json.loads(raw.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RepositoryMirrorError(f"{field} is invalid") from error
    if raw != _canonical_json(document):
        raise RepositoryMirrorError(f"{field} must be canonical JSON")
    return raw, document


def load_and_verify_repository_bindings(
    bindings_file: Path | str,
    receipt_file: Path | str,
    *,
    expected_runner_id: UUID,
    expected_runner_generation: int,
    expected_runner_slot: str,
    expected_binding_keys: tuple[str, ...],
    expected_spec_sha256: str,
    expected_bindings_sha256: str,
    expected_receipt_sha256: str,
) -> VerifiedRepositoryBindings:
    """Re-verify the complete mirror authority before Runner startup."""

    try:
        canonical_expected_keys = tuple(
            _validate_binding_key(value) for value in expected_binding_keys
        )
    except (RepositoryMirrorError, TypeError):
        raise RepositoryMirrorError("expected repository binding keys are invalid") from None
    if (
        expected_runner_id.int == 0
        or isinstance(expected_runner_generation, bool)
        or not 1 <= expected_runner_generation <= 2**63 - 1
        or expected_runner_slot not in {"a", "b"}
        or not canonical_expected_keys
        or canonical_expected_keys != expected_binding_keys
        or canonical_expected_keys != tuple(sorted(canonical_expected_keys))
        or len(set(canonical_expected_keys)) != len(canonical_expected_keys)
    ):
        raise RepositoryMirrorError("expected Runner repository authority is invalid")
    expected_spec_sha256 = _validate_sha256(
        expected_spec_sha256,
        field="expected_spec_sha256",
    )
    expected_bindings_sha256 = _validate_sha256(
        expected_bindings_sha256,
        field="expected_bindings_sha256",
    )
    expected_receipt_sha256 = _validate_sha256(
        expected_receipt_sha256,
        field="expected_receipt_sha256",
    )
    bindings_path = Path(bindings_file)
    receipt_path = Path(receipt_file)
    bindings_raw, bindings_document = _load_canonical_output(
        bindings_path,
        field="repository bindings",
    )
    receipt_raw, receipt_document = _load_canonical_output(
        receipt_path,
        field="repository mirror receipt",
    )
    if (
        _sha256(bindings_raw) != expected_bindings_sha256
        or _sha256(receipt_raw) != expected_receipt_sha256
    ):
        raise RepositoryMirrorError("repository release-pinned output digest changed")
    if (
        not isinstance(bindings_document, dict)
        or set(bindings_document) != {"bindings", "schema_version"}
        or isinstance(bindings_document.get("schema_version"), bool)
        or bindings_document.get("schema_version") != 1
        or not isinstance(bindings_document.get("bindings"), dict)
        or not cast(dict[object, object], bindings_document["bindings"])
    ):
        raise RepositoryMirrorError("repository bindings have an invalid shape")
    receipt_keys = {
        "bindings",
        "mirror_root",
        "runner_generation",
        "runner_id",
        "runner_slot",
        "schema_version",
        "spec_sha256",
    }
    if not isinstance(receipt_document, dict) or set(receipt_document) != receipt_keys:
        raise RepositoryMirrorError("repository mirror receipt has an invalid shape")
    rows = receipt_document.get("bindings")
    generation = receipt_document.get("runner_generation")
    schema_version = receipt_document.get("schema_version")
    if (
        isinstance(schema_version, bool)
        or schema_version != 1
        or not isinstance(rows, list)
        or not 1 <= len(rows) <= _MAX_BINDINGS
        or not isinstance(generation, int)
        or isinstance(generation, bool)
        or not 1 <= generation <= 2**63 - 1
        or receipt_document.get("runner_slot") not in {"a", "b"}
        or not isinstance(receipt_document.get("spec_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", cast(str, receipt_document["spec_sha256"])) is None
    ):
        raise RepositoryMirrorError("repository mirror receipt has invalid values")
    try:
        runner_id = UUID(cast(str, receipt_document["runner_id"]))
    except (TypeError, ValueError) as error:
        raise RepositoryMirrorError(
            "repository mirror receipt Runner identity is invalid"
        ) from error
    if (
        runner_id.int == 0
        or str(runner_id) != receipt_document["runner_id"]
        or runner_id != expected_runner_id
        or generation != expected_runner_generation
        or receipt_document["runner_slot"] != expected_runner_slot
        or receipt_document["spec_sha256"] != expected_spec_sha256
    ):
        raise RepositoryMirrorError("repository mirror receipt release authority changed")
    mirror_root = _absolute_path(receipt_document["mirror_root"], field="receipt mirror_root")
    root = _private_directory(mirror_root, field="mirror_root", writable=True)
    marker = _read_owner_file(
        root / _ROOT_MARKER,
        maximum=4096,
        field="mirror_root identity marker",
    )
    expected_marker = _canonical_json(
        {
            "runner_generation": generation,
            "runner_id": str(runner_id),
            "runner_slot": receipt_document["runner_slot"],
            "schema_version": 1,
            "spec_sha256": receipt_document["spec_sha256"],
        }
    )
    if marker != expected_marker:
        raise RepositoryMirrorError("mirror_root identity marker changed")
    active = _private_directory(root / _ACTIVE_DIRECTORY, field="active mirror set", writable=True)
    bindings = cast(dict[object, object], bindings_document["bindings"])
    if len(bindings) != len(rows):
        raise RepositoryMirrorError("repository receipt and bindings differ")
    if tuple(sorted(cast(str, key) for key in bindings)) != canonical_expected_keys:
        raise RepositoryMirrorError("repository bindings changed from the release key set")
    verified: dict[str, Path] = {}
    expected_names: set[str] = set()
    previous_key = ""
    row_keys = {
        "binding_key",
        "mirror_digest",
        "mirror_path",
        "object_ids",
        "reachable_objects_sha256",
        "refs",
        "repository_id",
        "selection_type",
    }
    for row in rows:
        if not isinstance(row, dict) or set(row) != row_keys:
            raise RepositoryMirrorError("repository mirror receipt binding is invalid")
        binding_key = _validate_binding_key(row.get("binding_key"))
        if binding_key <= previous_key:
            raise RepositoryMirrorError("repository mirror receipt bindings are not sorted")
        previous_key = binding_key
        repository_id = row.get("repository_id")
        selection_type = row.get("selection_type")
        raw_refs = row.get("refs")
        raw_objects = row.get("object_ids")
        mirror_digest = row.get("mirror_digest")
        reachable_sha256 = row.get("reachable_objects_sha256")
        if (
            not isinstance(repository_id, str)
            or selection_type not in {"revision", "refs"}
            or not isinstance(raw_refs, dict)
            or not isinstance(raw_objects, list)
            or not raw_objects
            or not isinstance(mirror_digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", mirror_digest) is None
            or not isinstance(reachable_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", reachable_sha256) is None
        ):
            raise RepositoryMirrorError("repository mirror receipt binding is invalid")
        repository_id = _validate_repository_id(repository_id)
        refs = {
            _validate_ref(source_ref): _validate_sha1(object_id)
            for source_ref, object_id in raw_refs.items()
        }
        object_ids = tuple(_validate_sha1(value) for value in raw_objects)
        if tuple(sorted(set(object_ids))) != object_ids:
            raise RepositoryMirrorError("repository receipt object IDs are not canonical")
        if selection_type == "revision":
            if refs or len(object_ids) != 1:
                raise RepositoryMirrorError("repository revision receipt is invalid")
        elif not refs or tuple(sorted(set(refs.values()))) != object_ids:
            raise RepositoryMirrorError("repository refs receipt is invalid")
        expected_path = active / _mirror_name(binding_key)
        mirror_path = _absolute_path(row.get("mirror_path"), field="receipt mirror_path")
        if mirror_path != expected_path or bindings.get(binding_key) != str(expected_path):
            raise RepositoryMirrorError("repository mirror path binding changed")
        _verify_mirror(
            mirror_path,
            binding_key=binding_key,
            repository_id=repository_id,
            selection_type=cast(str, selection_type),
            refs=refs,
            object_ids=object_ids,
            expected_digest=mirror_digest,
            expected_reachable_sha256=reachable_sha256,
        )
        expected_names.add(mirror_path.name)
        verified[binding_key] = mirror_path
    if set(bindings) != set(verified):
        raise RepositoryMirrorError("repository bindings contain an extra or missing key")
    if tuple(verified) != canonical_expected_keys:
        raise RepositoryMirrorError("repository receipt changed from the release key set")
    try:
        if {entry.name for entry in active.iterdir()} != expected_names:
            raise RepositoryMirrorError("active mirror set contains unmanaged repositories")
    except OSError as error:
        raise RepositoryMirrorError("active mirror set cannot be enumerated") from error
    return VerifiedRepositoryBindings(
        bindings_file=bindings_path,
        receipt_file=receipt_path,
        bindings_sha256=_sha256(bindings_raw),
        receipt_sha256=_sha256(receipt_raw),
        spec_sha256=cast(str, receipt_document["spec_sha256"]),
        runner_id=runner_id,
        runner_generation=cast(int, generation),
        runner_slot=cast(str, receipt_document["runner_slot"]),
        bindings=MappingProxyType(verified),
    )


__all__ = [
    "RepositoryBindingProvision",
    "RepositoryFetcher",
    "RepositoryMirrorError",
    "RepositoryMirrorReceipt",
    "RepositoryProvisioningSpec",
    "SealedGitRepositoryFetcher",
    "VerifiedRepositoryBindings",
    "load_and_verify_repository_bindings",
    "load_repository_provisioning_spec",
    "provision_repository_mirrors",
    "render_repository_provisioning_spec",
]
