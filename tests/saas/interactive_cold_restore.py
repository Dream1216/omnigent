"""Fixture-only durable material shared by initial and genuinely cold processes."""

from __future__ import annotations

import json
import os
import stat
from hashlib import sha256
from pathlib import Path


def immutable_private_material(path: Path, value: str) -> str:
    data = value.encode("utf-8")
    if len(data) > 1024 * 1024:
        raise ValueError("invalid private fixture material")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    except FileExistsError:
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError:
            raise ValueError("invalid private fixture material") from None
        with os.fdopen(descriptor, "rb") as current:
            metadata = os.fstat(current.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o400
                or metadata.st_nlink != 1
                or metadata.st_size != len(data)
                or current.read(len(data) + 1) != data
            ):
                raise ValueError("invalid private fixture material") from None
            latest = path.lstat()
            if (latest.st_dev, latest.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise ValueError("invalid private fixture material") from None
    else:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    return str(path)


def _read_material(path: Path, *, modes: tuple[int, ...]) -> tuple[bytes, int]:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise ValueError("invalid cold fixture checkpoint") from None
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or mode not in modes
            or metadata.st_size > 1024 * 1024
        ):
            raise ValueError("invalid cold fixture checkpoint")
        value = source.read(1024 * 1024 + 1)
        latest = path.lstat()
        if len(value) != metadata.st_size or (latest.st_dev, latest.st_ino) != (
            metadata.st_dev,
            metadata.st_ino,
        ):
            raise ValueError("invalid cold fixture checkpoint")
    return value, mode


def _private_root(root: Path) -> None:
    metadata = root.lstat()
    if (
        not root.is_absolute()
        or root.resolve() != root
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ValueError("invalid cold fixture checkpoint")


def _material_path(root: Path, relative: str) -> Path:
    candidate = root / relative
    if (
        not relative
        or Path(relative).is_absolute()
        or ".." in Path(relative).parts
        or candidate.resolve(strict=True) != candidate
        or not candidate.is_relative_to(root)
    ):
        raise ValueError("invalid cold fixture checkpoint")
    return candidate


def write_cold_checkpoint(root: Path, payload: dict, paths: list[Path]) -> Path:
    _private_root(root)
    if not 1 <= len(paths) <= 512 or len(set(paths)) != len(paths):
        raise ValueError("invalid cold fixture checkpoint")
    inventory = []
    for path in sorted(paths):
        relative = path.relative_to(root).as_posix()
        candidate = _material_path(root, relative)
        value, mode = _read_material(candidate, modes=(0o400, 0o600, 0o644))
        inventory.append({"path": relative, "mode": mode, "sha256": sha256(value).hexdigest()})
    document = {"schema_version": 1, "payload": payload, "files": inventory}
    path = root / "cold-restore.json"
    immutable_private_material(path, json.dumps(document, sort_keys=True, default=str))
    return path


def load_cold_checkpoint(root: Path) -> dict:
    _private_root(root)
    raw, _ = _read_material(root / "cold-restore.json", modes=(0o400,))
    document = json.loads(raw)
    if (
        set(document) != {"schema_version", "payload", "files"}
        or document["schema_version"] != 1
        or not isinstance(document["payload"], dict)
        or not isinstance(document["files"], list)
        or not 1 <= len(document["files"]) <= 512
    ):
        raise ValueError("invalid cold fixture checkpoint")
    paths = set()
    for entry in document["files"]:
        if set(entry) != {"path", "mode", "sha256"} or entry["path"] in paths:
            raise ValueError("invalid cold fixture checkpoint")
        paths.add(entry["path"])
        value, mode = _read_material(
            _material_path(root, entry["path"]), modes=(0o400, 0o600, 0o644)
        )
        if mode != entry["mode"] or sha256(value).hexdigest() != entry["sha256"]:
            raise ValueError("invalid cold fixture checkpoint")
    return document


def find_cold_checkpoint(base: Path) -> Path:
    _private_root(base)
    candidates = [
        child / "cold-restore.json"
        for child in base.iterdir()
        if child.is_dir() and not child.is_symlink() and (child / "cold-restore.json").is_file()
    ]
    if len(candidates) != 1:
        raise ValueError("invalid cold fixture checkpoint")
    load_cold_checkpoint(candidates[0].parent)
    return candidates[0]


def checkpoint_suspended_fixture(
    *, root: Path, bootstrap: dict, source: dict, record, old_bearer: str, cluster: dict
) -> dict:
    from dataclasses import asdict

    from saas.production.interactive_recovery import (
        managed_suspension_proof_sha256,
        physical_recovery_proof_sha256,
    )

    if (
        cluster.get("managed_cold_restore") is not True
        or cluster.get("managed_dormant") is not True
        or cluster.get("provider") != "agent_sandbox"
        or record.phase != "terminal"
        or not record.process_stopped
        or record.outcome != "succeeded"
        or record.managed_suspension is None
        or not record.managed_suspension.complete
    ):
        raise ValueError("invalid cold fixture checkpoint")
    evidence = {
        "old_suspension_sha256": managed_suspension_proof_sha256(record),
        "old_physical_stop_sha256": physical_recovery_proof_sha256(record),
        "old_suspension": asdict(record.managed_suspension),
    }
    return _checkpoint_fixture(
        root=root,
        bootstrap=bootstrap,
        source=source,
        record=record,
        old_bearer=old_bearer,
        cluster=cluster,
        details={"checkpoint_kind": "suspended", **evidence},
        evidence=evidence,
    )


def checkpoint_active_fixture(
    *, root: Path, bootstrap: dict, source: dict, record, old_bearer: str, cluster: dict
) -> dict:
    if (
        cluster.get("managed_cold_restore") is not True
        or cluster.get("managed_cold_active") is not True
        or cluster.get("scenario") != "controller_crash_recovery"
        or cluster.get("provider") != "agent_sandbox"
        or record.phase != "dispatching"
        or record.process_stopped
        or record.outcome is not None
        or record.managed_resources is None
        or record.managed_creation is None
        or record.managed_creation.pod_uid is None
    ):
        raise ValueError("invalid active cold fixture checkpoint")
    pending = sorted(record.grant.spool_directory.glob("*.pending.json"))
    if len(pending) != 1:
        raise ValueError("invalid active cold fixture checkpoint")
    raw, _ = _read_material(root / "crash-state.json", modes=(0o400,))
    state = json.loads(raw)
    if state["run_id"] != str(record.run_id) or state["old_bearer"] != old_bearer:
        raise ValueError("invalid active cold fixture checkpoint")
    evidence = {"original_phase": record.phase, "original_pending_references": len(pending)}
    return _checkpoint_fixture(
        root=root,
        bootstrap=bootstrap,
        source=source,
        record=record,
        old_bearer=old_bearer,
        cluster=cluster,
        details={"checkpoint_kind": "active", **evidence},
        evidence=evidence,
        extra_paths=[root / "crash-state.json"],
    )


def _checkpoint_fixture(
    *, root, bootstrap, source, record, old_bearer, cluster, details, evidence, extra_paths=()
):
    from dataclasses import asdict

    payload = {
        **bootstrap,
        "must_not_reseed": True,
        "root": str(root),
        "source": source,
        "cluster": cluster,
        "run_id": str(record.run_id),
        "old_bearer": old_bearer,
        "old_resources": asdict(record.managed_resources),
        **details,
        "runtime_environment": {
            key: value
            for key, value in os.environ.items()
            if key.startswith("OMNIGENT_SAAS_RUNNER_READINESS_")
            or key
            in {
                "OMNIGENT_HOST_WORKSPACE_ID",
                "OMNIGENT_SAAS_PLATFORM_MODEL_CONTROLLER_BOUND",
                "OMNIGENT_WS_ALLOWED_ORIGINS",
                "OMNIGENT_DB_POOL_SIZE",
                "OMNIGENT_DB_MAX_OVERFLOW",
                "SSL_CERT_FILE",
            }
        },
    }
    paths = {
        path
        for directory in (
            root / "controller-journal",
            root / "artifacts",
            root / "control",
            root / "metering",
        )
        for path in directory.rglob("*")
        if path.is_file()
    }
    for values in (bootstrap["case"]["source"], source):
        for value in values.values():
            if isinstance(value, str):
                path = Path(value)
                if path.is_absolute() and path.is_relative_to(root) and path.is_file():
                    paths.add(path)
    paths.update((root / "readiness.pem", root / "readiness-key.pem"))
    paths.update(extra_paths)
    path = write_cold_checkpoint(root, payload, sorted(paths))
    loaded = load_cold_checkpoint(root)
    if loaded["payload"] != json.loads(json.dumps(payload, default=str)):
        raise ValueError("invalid cold fixture checkpoint")
    return {
        "run_id": payload["run_id"],
        "checkpoint_sha256": sha256(path.read_bytes()).hexdigest(),
        "retained_files": len(loaded["files"]),
        "old_resources": asdict(record.managed_resources),
        "old_creation_pod_uid": record.managed_creation.pod_uid,
        **evidence,
        "bootstrap_contains_existing_identities_not_seeds": True,
    }
