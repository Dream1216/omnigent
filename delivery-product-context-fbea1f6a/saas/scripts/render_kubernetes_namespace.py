"""Render the fixed SaaS Kubernetes namespace boundary without touching secrets.

Only resource ``metadata.namespace`` values, Kubernetes service-DNS suffixes,
and the fixed external PostgreSQL namespace boundary are authorized to change.
All other release inputs remain byte-for-byte and semantically unchanged for
their dedicated trusted renderers.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from collections.abc import Mapping, Sequence
from contextlib import suppress
from pathlib import Path
from typing import Any, Final

import yaml

SOURCE_NAMESPACE: Final = "omnigent"
TARGET_NAMESPACE: Final = "omnigent-next-beta"
SOURCE_EXTERNAL_DATABASE_NAMESPACE: Final = "omnigent-data"
TARGET_EXTERNAL_DATABASE_NAMESPACE: Final = "omnigent-next-beta-data"
EVIDENCE_FILE_NAME: Final = "namespace-render-evidence.json"
MANIFEST_NAMES: Final = (
    "kubernetes.migration.yaml",
    "kubernetes.artifact-admission.yaml",
    "kubernetes.production.yaml",
    "kubernetes.network-policy.yaml",
)

_MAX_MANIFEST_BYTES = 4 * 1024 * 1024
_NETWORK_POLICY_MANIFEST: Final = "kubernetes.network-policy.yaml"
_EXPECTED_EXTERNAL_DATABASE_REFERENCE_COUNT: Final = 6
_DATABASE_CONSUMERS: Final = frozenset(
    {
        "omnigent-saas-migration",
        "omnigent-saas-server",
        "omnigent-saas-worker",
        "omnigent-saas-runner-agent",
        "omnigent-saas-preview-edge",
        "omnigent-saas-preview-owner",
    }
)
_SOURCE_NAMESPACE_LINE = re.compile(
    rf"^(?P<prefix>[ \t]+namespace:[ \t]*){re.escape(SOURCE_NAMESPACE)}"
    r"(?P<suffix>[ \t]*(?:#.*)?)$",
    re.MULTILINE,
)
_SOURCE_DNS = re.compile(
    rf"(?<![A-Za-z0-9-]){re.escape(SOURCE_NAMESPACE)}\.svc"
    r"(?:\.cluster\.local)?(?![A-Za-z0-9.-])"
)
_RESIDUAL_SOURCE_DNS = re.compile(rf"(?<![A-Za-z0-9-]){re.escape(SOURCE_NAMESPACE)}\.svc")
_SOURCE_EXTERNAL_DATABASE_NAMESPACE_LINE = re.compile(
    rf"^(?P<prefix>[ \t]+kubernetes\.io/metadata\.name:[ \t]*)"
    rf"{re.escape(SOURCE_EXTERNAL_DATABASE_NAMESPACE)}"
    r"(?P<suffix>[ \t]*(?:#.*)?)$",
    re.MULTILINE,
)


class NamespaceRenderError(RuntimeError):
    """Stable fail-closed namespace rendering error."""


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("ascii")


def _load_yaml(name: str, text: str) -> dict[str, Any]:
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as error:
        raise NamespaceRenderError(f"{name}: YAML parse failed") from error
    if not isinstance(document, dict):
        raise NamespaceRenderError(f"{name}: manifest must be one Kubernetes List")
    return document


def _read_manifest(path: Path) -> tuple[bytes, str]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise NamespaceRenderError(f"{path.name}: source manifest is unavailable") from error
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise NamespaceRenderError(f"{path.name}: source manifest must be a regular file")
    if not 1 <= metadata.st_size <= _MAX_MANIFEST_BYTES:
        raise NamespaceRenderError(f"{path.name}: source manifest size is invalid")
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8")
    except (OSError, UnicodeError) as error:
        raise NamespaceRenderError(f"{path.name}: source manifest is unreadable") from error
    if not text.endswith("\n") or "\x00" in text:
        raise NamespaceRenderError(f"{path.name}: source manifest encoding is invalid")
    return raw, text


def _replace_dns(value: str) -> tuple[str, int]:
    def replacement(match: re.Match[str]) -> str:
        return match.group(0).replace(f"{SOURCE_NAMESPACE}.svc", f"{TARGET_NAMESPACE}.svc", 1)

    return _SOURCE_DNS.subn(replacement, value)


def _replace_external_database_namespace(value: str) -> tuple[str, int]:
    return _SOURCE_EXTERNAL_DATABASE_NAMESPACE_LINE.subn(
        lambda match: (
            f"{match.group('prefix')}{TARGET_EXTERNAL_DATABASE_NAMESPACE}{match.group('suffix')}"
        ),
        value,
    )


def _walk_values(value: Any) -> list[str]:
    values: list[str] = []
    if isinstance(value, dict):
        for child in value.values():
            values.extend(_walk_values(child))
    elif isinstance(value, list):
        for child in value:
            values.extend(_walk_values(child))
    elif isinstance(value, str):
        values.append(value)
    return values


def _validate_mapping_keys(value: Any, *, name: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str) and _RESIDUAL_SOURCE_DNS.search(key):
                raise NamespaceRenderError(
                    f"{name}: service DNS in a mapping key is not authorized"
                )
            if isinstance(key, str) and (
                SOURCE_EXTERNAL_DATABASE_NAMESPACE in key
                or TARGET_EXTERNAL_DATABASE_NAMESPACE in key
            ):
                raise NamespaceRenderError(
                    f"{name}: external database namespace in a mapping key is forbidden"
                )
            _validate_mapping_keys(child, name=name)
    elif isinstance(value, list):
        for child in value:
            _validate_mapping_keys(child, name=name)


def _validate_database_consumers(name: str, items: list[Any]) -> None:
    if name != _NETWORK_POLICY_MANIFEST:
        return

    expected_peer = {
        "namespaceSelector": {
            "matchLabels": {
                "kubernetes.io/metadata.name": SOURCE_EXTERNAL_DATABASE_NAMESPACE,
            }
        },
        "podSelector": {"matchLabels": {"cnpg.io/cluster": "omnigent-postgres"}},
    }
    observed_consumers: set[str] = set()
    for item in items:
        if not isinstance(item, dict) or item.get("kind") != "NetworkPolicy":
            continue
        metadata = item.get("metadata")
        spec = item.get("spec")
        if not isinstance(metadata, dict) or not isinstance(spec, dict):
            continue
        resource_name = metadata.get("name")
        matching_rules = []
        for rule in spec.get("egress", []):
            if not isinstance(rule, dict):
                continue
            if rule.get("to") == [expected_peer]:
                matching_rules.append(rule)
        if matching_rules:
            if (
                resource_name not in _DATABASE_CONSUMERS
                or len(matching_rules) != 1
                or matching_rules[0].get("ports") != [{"protocol": "TCP", "port": 5432}]
            ):
                raise NamespaceRenderError(
                    f"{name}: external database consumer projection is invalid"
                )
            observed_consumers.add(str(resource_name))
    if observed_consumers != _DATABASE_CONSUMERS:
        raise NamespaceRenderError(f"{name}: external database consumer projection is incomplete")


def _validate_source_document(name: str, document: dict[str, Any]) -> tuple[int, int, int]:
    if document.get("apiVersion") != "v1" or document.get("kind") != "List":
        raise NamespaceRenderError(f"{name}: manifest must be apiVersion v1 kind List")
    items = document.get("items")
    if not isinstance(items, list) or not items:
        raise NamespaceRenderError(f"{name}: manifest List must not be empty")

    resource_names: set[tuple[str, str]] = set()
    for item in items:
        if not isinstance(item, dict):
            raise NamespaceRenderError(f"{name}: every List item must be a resource")
        kind = item.get("kind")
        metadata = item.get("metadata")
        if kind == "Secret":
            raise NamespaceRenderError(f"{name}: Secret resources are forbidden")
        if not isinstance(kind, str) or not isinstance(metadata, dict):
            raise NamespaceRenderError(f"{name}: resource identity is invalid")
        resource_name = metadata.get("name")
        if not isinstance(resource_name, str) or not resource_name:
            raise NamespaceRenderError(f"{name}: resource name is invalid")
        identity = (kind, resource_name)
        if identity in resource_names:
            raise NamespaceRenderError(f"{name}: duplicate resource identity")
        resource_names.add(identity)
        if metadata.get("namespace") != SOURCE_NAMESPACE:
            raise NamespaceRenderError(
                f"{name}: every metadata.namespace must equal {SOURCE_NAMESPACE}"
            )

    _validate_mapping_keys(document, name=name)
    scalar_values = _walk_values(document)
    for value in scalar_values:
        if (
            SOURCE_EXTERNAL_DATABASE_NAMESPACE in value
            and value != SOURCE_EXTERNAL_DATABASE_NAMESPACE
        ):
            raise NamespaceRenderError(
                f"{name}: external database namespace must be one exact scalar"
            )
        if TARGET_EXTERNAL_DATABASE_NAMESPACE in value:
            raise NamespaceRenderError(
                f"{name}: pre-rendered external database namespace is forbidden"
            )
    dns_replacements = sum(len(_SOURCE_DNS.findall(value)) for value in scalar_values)
    external_database_references = sum(
        value == SOURCE_EXTERNAL_DATABASE_NAMESPACE for value in scalar_values
    )
    expected_external_database_references = (
        _EXPECTED_EXTERNAL_DATABASE_REFERENCE_COUNT if name == _NETWORK_POLICY_MANIFEST else 0
    )
    if external_database_references != expected_external_database_references:
        raise NamespaceRenderError(
            f"{name}: external database namespace reference count is invalid"
        )
    _validate_database_consumers(name, items)
    return len(items), dns_replacements, external_database_references


def _assert_authorized_changes(
    source: Any,
    rendered: Any,
    *,
    name: str,
    path: tuple[str | int, ...] = (),
) -> None:
    if isinstance(source, dict):
        if not isinstance(rendered, dict) or source.keys() != rendered.keys():
            raise NamespaceRenderError(f"{name}: renderer changed mapping structure")
        for key, value in source.items():
            _assert_authorized_changes(
                value,
                rendered[key],
                name=name,
                path=(*path, key),
            )
        return
    if isinstance(source, list):
        if not isinstance(rendered, list) or len(source) != len(rendered):
            raise NamespaceRenderError(f"{name}: renderer changed list structure")
        for index, value in enumerate(source):
            _assert_authorized_changes(
                value,
                rendered[index],
                name=name,
                path=(*path, index),
            )
        return
    if isinstance(source, str):
        if len(path) >= 2 and path[-2:] == ("metadata", "namespace"):
            expected = TARGET_NAMESPACE
        elif source == SOURCE_EXTERNAL_DATABASE_NAMESPACE:
            expected = TARGET_EXTERNAL_DATABASE_NAMESPACE
        else:
            expected, _count = _replace_dns(source)
        if rendered != expected:
            raise NamespaceRenderError(f"{name}: renderer changed an unauthorized scalar")
        return
    if type(source) is not type(rendered) or source != rendered:
        raise NamespaceRenderError(f"{name}: renderer changed an unauthorized scalar")


def _audit_rendered_document(name: str, document: dict[str, Any]) -> None:
    items = document.get("items")
    if not isinstance(items, list):
        raise NamespaceRenderError(f"{name}: rendered List is invalid")
    for item in items:
        if not isinstance(item, dict):
            raise NamespaceRenderError(f"{name}: rendered resource is invalid")
        metadata = item.get("metadata")
        if not isinstance(metadata, dict) or metadata.get("namespace") != TARGET_NAMESPACE:
            raise NamespaceRenderError(f"{name}: rendered metadata.namespace did not converge")
    scalar_values = _walk_values(document)
    for value in scalar_values:
        if value == SOURCE_NAMESPACE:
            raise NamespaceRenderError(f"{name}: residual source namespace reference")
        if _RESIDUAL_SOURCE_DNS.search(value):
            raise NamespaceRenderError(f"{name}: residual source service DNS reference")
        if SOURCE_EXTERNAL_DATABASE_NAMESPACE in value:
            raise NamespaceRenderError(
                f"{name}: residual source external database namespace reference"
            )
        if (
            TARGET_EXTERNAL_DATABASE_NAMESPACE in value
            and value != TARGET_EXTERNAL_DATABASE_NAMESPACE
        ):
            raise NamespaceRenderError(
                f"{name}: rendered external database namespace is malformed"
            )
    target_database_references = sum(
        value == TARGET_EXTERNAL_DATABASE_NAMESPACE for value in scalar_values
    )
    expected_target_database_references = (
        _EXPECTED_EXTERNAL_DATABASE_REFERENCE_COUNT if name == _NETWORK_POLICY_MANIFEST else 0
    )
    if target_database_references != expected_target_database_references:
        raise NamespaceRenderError(
            f"{name}: rendered external database namespace count is invalid"
        )


def _render_manifest(name: str, raw: bytes, text: str) -> tuple[bytes, dict[str, Any]]:
    source_document = _load_yaml(name, text)
    namespace_count, expected_dns_count, external_database_references = _validate_source_document(
        name, source_document
    )

    rendered_text, namespace_replacements = _SOURCE_NAMESPACE_LINE.subn(
        lambda match: f"{match.group('prefix')}{TARGET_NAMESPACE}{match.group('suffix')}",
        text,
    )
    if namespace_replacements != namespace_count:
        raise NamespaceRenderError(
            f"{name}: metadata.namespace textual replacement count is invalid"
        )
    rendered_text, dns_replacements = _replace_dns(rendered_text)
    if dns_replacements != expected_dns_count:
        raise NamespaceRenderError(f"{name}: service DNS replacement count is invalid")
    rendered_text, external_database_text_replacements = _replace_external_database_namespace(
        rendered_text
    )
    expected_external_database_text_replacements = 1 if name == _NETWORK_POLICY_MANIFEST else 0
    if external_database_text_replacements != expected_external_database_text_replacements:
        raise NamespaceRenderError(
            f"{name}: external database namespace textual replacement count is invalid"
        )
    if _SOURCE_NAMESPACE_LINE.search(rendered_text):
        raise NamespaceRenderError(f"{name}: source namespace line remains")
    if _SOURCE_EXTERNAL_DATABASE_NAMESPACE_LINE.search(rendered_text):
        raise NamespaceRenderError(f"{name}: source external database namespace line remains")

    rendered_document = _load_yaml(name, rendered_text)
    _audit_rendered_document(name, rendered_document)
    _assert_authorized_changes(source_document, rendered_document, name=name)
    rendered = rendered_text.encode("utf-8")
    return rendered, {
        "dns_suffix_replacements": dns_replacements,
        "external_database_namespace_replacements": external_database_references,
        "external_database_namespace_text_replacements": external_database_text_replacements,
        "metadata_namespace_replacements": namespace_replacements,
        "name": name,
        "rendered_sha256": _sha256(rendered),
        "source_sha256": _sha256(raw),
    }


def _validate_source_directory(source_dir: Path) -> None:
    try:
        metadata = source_dir.lstat()
    except OSError as error:
        raise NamespaceRenderError("source directory is unavailable") from error
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise NamespaceRenderError("source directory must be a real directory")
    yaml_names = {path.name for path in source_dir.glob("*.yaml")}
    if yaml_names != set(MANIFEST_NAMES):
        raise NamespaceRenderError("source directory must contain exactly four YAML manifests")


def _prepare_output_directory(source_dir: Path, output_dir: Path) -> None:
    if output_dir.resolve(strict=False).is_relative_to(source_dir.resolve(strict=True)):
        raise NamespaceRenderError("output directory must be outside the source directory")
    if output_dir.exists():
        try:
            metadata = output_dir.lstat()
        except OSError as error:
            raise NamespaceRenderError("output directory cannot be inspected") from error
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise NamespaceRenderError("output directory must be a real directory")
        try:
            has_entries = any(output_dir.iterdir())
        except OSError as error:
            raise NamespaceRenderError("output directory cannot be inspected") from error
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise NamespaceRenderError("output directory must not be group/world accessible")
        if has_entries:
            raise NamespaceRenderError("output directory must be empty")
        return
    try:
        output_dir.mkdir(mode=0o700)
    except OSError as error:
        raise NamespaceRenderError("output directory cannot be created") from error


def _write_exclusive(path: Path, value: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as error:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
        with suppress(OSError):
            path.unlink()
        raise NamespaceRenderError(f"{path.name}: rendered output cannot be written") from error


def render_namespace_manifests(source_dir: Path, output_dir: Path) -> dict[str, Any]:
    """Render the exact four manifests and return secret-free hash evidence."""

    _validate_source_directory(source_dir)
    rendered_files: dict[str, bytes] = {}
    evidence_rows: list[dict[str, Any]] = []
    for name in MANIFEST_NAMES:
        raw, text = _read_manifest(source_dir / name)
        rendered, row = _render_manifest(name, raw, text)
        rendered_files[name] = rendered
        evidence_rows.append(row)

    _prepare_output_directory(source_dir, output_dir)
    rendered_set_material = _canonical_json(
        {
            "files": [
                {"name": row["name"], "rendered_sha256": row["rendered_sha256"]}
                for row in evidence_rows
            ]
        }
    )
    evidence: dict[str, Any] = {
        "external_database_namespace": {
            "replacement_count": sum(
                int(row["external_database_namespace_replacements"]) for row in evidence_rows
            ),
            "source": SOURCE_EXTERNAL_DATABASE_NAMESPACE,
            "target": TARGET_EXTERNAL_DATABASE_NAMESPACE,
        },
        "files": evidence_rows,
        "manifest_count": len(evidence_rows),
        "rendered_set_sha256": _sha256(rendered_set_material),
        "schema_version": 2,
        "source_namespace": SOURCE_NAMESPACE,
        "status": "pass",
        "target_namespace": TARGET_NAMESPACE,
    }
    evidence_bytes = _canonical_json(evidence)
    created_paths: list[Path] = []
    try:
        for name in MANIFEST_NAMES:
            path = output_dir / name
            _write_exclusive(path, rendered_files[name])
            created_paths.append(path)
        evidence_path = output_dir / EVIDENCE_FILE_NAME
        _write_exclusive(evidence_path, evidence_bytes)
        created_paths.append(evidence_path)
    except NamespaceRenderError:
        for path in created_paths:
            with suppress(OSError):
                path.unlink()
        raise

    return {
        "evidence_file": EVIDENCE_FILE_NAME,
        "evidence_sha256": _sha256(evidence_bytes),
        "manifest_count": len(evidence_rows),
        "rendered_set_sha256": evidence["rendered_set_sha256"],
        "status": "pass",
    }


def _default_source_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "deployment" / "server"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Render the fixed omnigent Kubernetes namespace to omnigent-next-beta "
            "and emit secret-free SHA256 evidence."
        )
    )
    parser.add_argument("--source-dir", type=Path, default=_default_source_dir())
    parser.add_argument("--output-dir", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        result = render_namespace_manifests(arguments.source_dir, arguments.output_dir)
    except NamespaceRenderError as error:
        print(
            json.dumps(
                {"error": str(error), "status": "fail"},
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    print(
        json.dumps(
            result,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "EVIDENCE_FILE_NAME",
    "MANIFEST_NAMES",
    "SOURCE_EXTERNAL_DATABASE_NAMESPACE",
    "SOURCE_NAMESPACE",
    "TARGET_EXTERNAL_DATABASE_NAMESPACE",
    "TARGET_NAMESPACE",
    "NamespaceRenderError",
    "main",
    "render_namespace_manifests",
]
