"""Compare platform manifest, config, and labels from repeated OCI image builds."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Any

_OCI_INDEX_MEDIA_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
_OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
_PREDICATES = {
    "https://slsa.dev/provenance/v1": "slsa_provenance",
    "https://spdx.dev/Document": "spdx_sbom",
}
_EXECUTABLE_LABELS = frozenset(
    {
        "org.opencontainers.image.revision",
        "ai.omnigent.upstream.revision",
        "ai.omnigent.saas.schema-revision",
        "ai.omnigent.saas.adapter-contract-version",
    }
)
_N1_LABELS = _EXECUTABLE_LABELS | frozenset(
    {
        "ai.omnigent.saas.n1.base-commit",
        "ai.omnigent.saas.n1.patch-source-revision",
        "ai.omnigent.saas.n1.patch-sha256",
        "ai.omnigent.saas.n1.patched-tree-hash",
        "ai.omnigent.saas.n1.schema-revision",
        "ai.omnigent.saas.n1.contract-version",
    }
)
_LABEL_PROFILES = {
    "executable": _EXECUTABLE_LABELS,
    "n1": _N1_LABELS,
}

_SAFE_DIAGNOSTIC_POLICY = {
    "config_environment": "omitted",
    "history_created_by": "equality-and-ordinal-drift-only",
    "layer_contents": "omitted",
}


def _blob_path(root: Path, digest: str) -> tuple[Path, str]:
    algorithm, separator, value = digest.partition(":")
    if (
        separator != ":"
        or algorithm != "sha256"
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError("unsupported OCI digest")
    path = root / "blobs" / algorithm / value
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"OCI blob is unavailable: {digest}")
    return path, value


def _verify_blob(root: Path, digest: str) -> Path:
    path, expected = _blob_path(root, digest)
    observed = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            observed.update(chunk)
    if observed.hexdigest() != expected:
        raise ValueError(f"OCI blob digest mismatch: {digest}")
    return path


def _blob(root: Path, digest: str) -> bytes:
    return _verify_blob(root, digest).read_bytes()


def _history(config: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    history = config.get("history", [])
    if not isinstance(history, list):
        raise ValueError("OCI config history is invalid")
    facts: list[dict[str, Any]] = []
    commands: list[str] = []
    for item in history:
        if not isinstance(item, dict):
            raise ValueError("OCI config history is invalid")
        created = item.get("created")
        created_by = item.get("created_by", "")
        empty_layer = item.get("empty_layer", False)
        if (
            (created is not None and not isinstance(created, str))
            or not isinstance(created_by, str)
            or not isinstance(empty_layer, bool)
        ):
            raise ValueError("OCI config history is invalid")
        facts.append(
            {
                "created": created,
                "empty_layer": empty_layer,
            }
        )
        commands.append(created_by)
    return facts, commands


def _rootfs_diff_ids(config: dict[str, Any]) -> list[str]:
    rootfs = config.get("rootfs", {})
    if not isinstance(rootfs, dict) or rootfs.get("type") != "layers":
        raise ValueError("OCI config rootfs is invalid")
    diff_ids = rootfs.get("diff_ids", [])
    if not isinstance(diff_ids, list) or any(not isinstance(item, str) for item in diff_ids):
        raise ValueError("OCI config rootfs is invalid")
    for digest in diff_ids:
        algorithm, separator, value = digest.partition(":")
        if (
            separator != ":"
            or algorithm != "sha256"
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise ValueError("OCI config rootfs is invalid")
    return diff_ids


def _layer_facts(root: Path, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    layers = manifest.get("layers", [])
    if not isinstance(layers, list):
        raise ValueError("OCI manifest layers are invalid")
    facts: list[dict[str, Any]] = []
    for layer in layers:
        if not isinstance(layer, dict) or not isinstance(layer.get("digest"), str):
            raise ValueError("OCI manifest layers are invalid")
        digest = layer["digest"]
        path = _verify_blob(root, digest)
        size = layer.get("size")
        media_type = layer.get("mediaType")
        if size is not None and (not isinstance(size, int) or isinstance(size, bool) or size < 0):
            raise ValueError("OCI manifest layers are invalid")
        if media_type is not None and not isinstance(media_type, str):
            raise ValueError("OCI manifest layers are invalid")
        if size is not None and path.stat().st_size != size:
            raise ValueError("OCI manifest layer size mismatch")
        facts.append({"digest": digest, "media_type": media_type, "size": size})
    return facts


def _approved_labels(label_profile: str) -> frozenset[str]:
    try:
        return _LABEL_PROFILES[label_profile]
    except KeyError as error:
        raise ValueError(f"unsupported OCI label profile: {label_profile}") from error


def _inspect_oci_archive(
    path: Path, *, label_profile: str
) -> tuple[dict[str, Any], dict[str, list[str]]]:
    """Return public facts plus process-local command strings for comparison only."""

    approved_labels = _approved_labels(label_profile)
    with tempfile.TemporaryDirectory(prefix="omnigent-oci-inspect-") as temp_name:
        root = Path(temp_name)
        with tarfile.open(path) as archive:
            archive.extractall(root, filter="data")
        index = json.loads((root / "index.json").read_text(encoding="utf-8"))
        platforms: dict[str, dict[str, Any]] = {}
        history_commands_by_platform: dict[str, list[str]] = {}
        attestations: list[dict[str, Any]] = []

        def inspect_descriptor(descriptor: dict[str, Any]) -> int:
            platform = descriptor.get("platform", {})
            key = f"{platform.get('os')}/{platform.get('architecture')}"
            if key == "unknown/unknown":
                attestations.append(descriptor)
                return 0
            descriptor_path = _verify_blob(root, descriptor["digest"])
            if (
                descriptor.get("size") is not None
                and descriptor["size"] != descriptor_path.stat().st_size
            ):
                raise ValueError("OCI descriptor size mismatch")
            document = json.loads(_blob(root, descriptor["digest"]))
            media_type = descriptor.get("mediaType")
            if media_type in _OCI_INDEX_MEDIA_TYPES or "manifests" in document:
                return sum(inspect_descriptor(child) for child in document.get("manifests", []))
            if key not in {"linux/amd64", "linux/arm64"}:
                raise ValueError("OCI archive contains an unexpected executable descriptor")
            if descriptor.get("mediaType") not in (None, _OCI_MANIFEST_MEDIA_TYPE):
                raise ValueError("OCI platform manifest media type is invalid")
            if key in platforms:
                raise ValueError(f"OCI archive repeats production platform {key}: {path}")
            manifest = document
            config_descriptor = manifest["config"]
            if config_descriptor.get("mediaType") not in (
                None,
                "application/vnd.oci.image.config.v1+json",
            ):
                raise ValueError("OCI platform config media type is invalid")
            config_digest = config_descriptor["digest"]
            config_path = _verify_blob(root, config_digest)
            if config_descriptor.get("size") not in (None, config_path.stat().st_size):
                raise ValueError("OCI config descriptor size mismatch")
            config = json.loads(config_path.read_text(encoding="utf-8"))
            config_created = config.get("created")
            if config_created is not None and not isinstance(config_created, str):
                raise ValueError("OCI config created timestamp is invalid")
            history, history_commands = _history(config)
            history_commands_by_platform[key] = history_commands
            rootfs_diff_ids = _rootfs_diff_ids(config)
            layers = _layer_facts(root, manifest)
            if len(rootfs_diff_ids) != len(layers):
                raise ValueError("OCI layer and rootfs diff-id cardinality mismatch")
            if sum(not item["empty_layer"] for item in history) != len(rootfs_diff_ids):
                raise ValueError("OCI history and rootfs diff-id cardinality mismatch")
            labels = config.get("config", {}).get("Labels", {})
            if (
                not isinstance(labels, dict)
                or set(labels) != approved_labels
                or any(not isinstance(value, str) for value in labels.values())
            ):
                raise ValueError(
                    "OCI config does not contain exactly the approved "
                    f"{label_profile} image labels"
                )
            platforms[key] = {
                "manifest_digest": descriptor["digest"],
                "config_digest": config_digest,
                "labels": labels,
                "config_created": config_created,
                "history": history,
                "rootfs_diff_ids": rootfs_diff_ids,
                "layers": layers,
            }
            return 0

        for descriptor in index.get("manifests", []):
            inspect_descriptor(descriptor)
        if set(platforms) != {"linux/amd64", "linux/arm64"}:
            raise ValueError(f"OCI archive does not contain both production platforms: {path}")
        manifest_to_platform = {
            facts["manifest_digest"]: platform for platform, facts in platforms.items()
        }
        attestation_by_platform: dict[str, dict[str, bool]] = {}
        for descriptor in attestations:
            descriptor_path = _verify_blob(root, descriptor.get("digest", ""))
            if descriptor.get("size") != descriptor_path.stat().st_size:
                raise ValueError("OCI attestation descriptor size mismatch")
            annotations = descriptor.get("annotations", {})
            if (
                not isinstance(annotations, dict)
                or annotations.get("vnd.docker.reference.type") != "attestation-manifest"
            ):
                raise ValueError("OCI unknown platform descriptor is not a BuildKit attestation")
            reference = annotations.get("vnd.docker.reference.digest")
            platform = manifest_to_platform.get(reference)
            if platform is None or platform in attestation_by_platform:
                raise ValueError("OCI attestation is not uniquely bound to a platform manifest")
            document = json.loads(descriptor_path.read_text(encoding="utf-8"))
            if descriptor.get("mediaType") != _OCI_MANIFEST_MEDIA_TYPE:
                raise ValueError("OCI attestation manifest media type is invalid")
            config_descriptor = document.get("config", {})
            if config_descriptor.get("mediaType") not in (
                None,
                "application/vnd.oci.empty.v1+json",
                "application/vnd.oci.image.config.v1+json",
            ):
                raise ValueError("OCI attestation config media type is invalid")
            config_path = _verify_blob(root, config_descriptor.get("digest", ""))
            if config_descriptor.get("size") != config_path.stat().st_size:
                raise ValueError("OCI attestation config size mismatch")
            attestation_config = json.loads(config_path.read_text(encoding="utf-8"))
            if config_descriptor.get("mediaType") == "application/vnd.oci.image.config.v1+json":
                if (
                    attestation_config.get("architecture") != "unknown"
                    or attestation_config.get("os") != "unknown"
                    or not isinstance(attestation_config.get("config"), dict)
                    or attestation_config.get("rootfs", {}).get("type") != "layers"
                    or attestation_config.get("rootfs", {}).get("diff_ids")
                    != [layer.get("digest") for layer in document.get("layers", [])]
                ):
                    raise ValueError("OCI attestation image config is invalid")
            elif attestation_config != {}:
                raise ValueError("OCI legacy empty attestation config is invalid")
            predicates = set()
            for layer in document.get("layers", []):
                if not isinstance(layer, dict):
                    raise ValueError("OCI attestation layer is invalid")
                layer_path = _verify_blob(root, layer.get("digest", ""))
                if layer.get("size") != layer_path.stat().st_size:
                    raise ValueError("OCI attestation layer size mismatch")
                if layer.get("mediaType") != "application/vnd.in-toto+json":
                    raise ValueError("OCI attestation layer media type is invalid")
                predicate = layer.get("annotations", {}).get("in-toto.io/predicate-type")
                if predicate not in _PREDICATES or predicate in predicates:
                    raise ValueError("OCI attestation predicate is invalid or repeated")
                statement = json.loads(layer_path.read_text(encoding="utf-8"))
                if (
                    statement.get("_type")
                    not in {
                        "https://in-toto.io/Statement/v0.1",
                        "https://in-toto.io/Statement/v1",
                    }
                    or statement.get("predicateType") != predicate
                ):
                    raise ValueError("OCI attestation statement does not match its predicate")
                predicate_body = statement.get("predicate")
                if not isinstance(predicate_body, dict):
                    raise ValueError("OCI attestation predicate body is invalid")
                if predicate == "https://slsa.dev/provenance/v1" and (
                    not isinstance(predicate_body.get("buildDefinition"), dict)
                    or not isinstance(predicate_body.get("runDetails"), dict)
                ):
                    raise ValueError("OCI SLSA provenance predicate is incomplete")
                if predicate == "https://spdx.dev/Document" and (
                    predicate_body.get("spdxVersion") != "SPDX-2.3"
                    or predicate_body.get("SPDXID") != "SPDXRef-DOCUMENT"
                    or not isinstance(predicate_body.get("dataLicense"), str)
                    or not isinstance(predicate_body.get("documentNamespace"), str)
                    or not isinstance(predicate_body.get("creationInfo"), dict)
                ):
                    raise ValueError("OCI SPDX predicate is incomplete")
                subjects = statement.get("subject", [])
                if not isinstance(subjects, list):
                    raise ValueError("OCI attestation subject is invalid")
                if not isinstance(reference, str):
                    raise ValueError("OCI attestation reference digest is invalid")
                if subjects and not any(
                    isinstance(subject, dict)
                    and subject.get("digest", {}).get("sha256")
                    == reference.removeprefix("sha256:")
                    for subject in subjects
                ):
                    raise ValueError(
                        "OCI attestation subject is not bound to its platform manifest"
                    )
                predicates.add(predicate)
            attestation_by_platform[platform] = {
                name: predicate in predicates for predicate, name in _PREDICATES.items()
            }
        if set(attestation_by_platform) != set(platforms) or any(
            not all(facts.values()) for facts in attestation_by_platform.values()
        ):
            raise ValueError(
                "OCI archive lacks per-platform SLSA provenance and SPDX attestations"
            )
        return (
            {
                "platforms": platforms,
                "attestations": attestation_by_platform,
                "attestation_descriptor_count": len(attestations),
            },
            history_commands_by_platform,
        )


def inspect_oci_archive(path: Path, *, label_profile: str) -> dict[str, Any]:
    """Return public reproducibility facts without Docker history commands."""

    facts, _ = _inspect_oci_archive(path, label_profile=label_profile)
    return facts


def compare_archives(first: Path, second: Path, *, label_profile: str) -> dict[str, Any]:
    """Compare only executable platform facts; attestation timestamps may differ."""

    left, left_commands = _inspect_oci_archive(first, label_profile=label_profile)
    right, right_commands = _inspect_oci_archive(second, label_profile=label_profile)
    history_command_drift_ordinals = {
        platform: [
            index
            for index in range(max(len(left_commands[platform]), len(right_commands[platform])))
            if index >= len(left_commands[platform])
            or index >= len(right_commands[platform])
            or left_commands[platform][index] != right_commands[platform][index]
        ]
        for platform in left_commands
    }
    matching = left["platforms"] == right["platforms"] and not any(
        history_command_drift_ordinals.values()
    )
    return {
        "label_profile": label_profile,
        "matching_platform_manifest_and_config": matching,
        "history_created_by_equal": not any(history_command_drift_ordinals.values()),
        "history_created_by_drift_ordinals": history_command_drift_ordinals,
        "first": left,
        "second": right,
    }


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--image",
        action="append",
        required=True,
        metavar="NAME=FIRST,SECOND",
        help="two repeated OCI archives for one image",
    )
    parser.add_argument(
        "--label-profile",
        choices=tuple(sorted(_LABEL_PROFILES)),
        required=True,
        help="exact approved label contract for every compared image",
    )
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    repo = Path(_git(Path.cwd(), "rev-parse", "--show-toplevel"))
    manifest = json.loads((repo / "saas/upstream-baseline.json").read_text(encoding="utf-8"))
    images: dict[str, Any] = {}
    violations: list[str] = []
    for spec in args.image:
        try:
            name, archives = spec.split("=", 1)
            first, second = archives.split(",", 1)
            comparison = compare_archives(
                Path(first), Path(second), label_profile=args.label_profile
            )
        except (OSError, ValueError, KeyError, json.JSONDecodeError, tarfile.TarError) as error:
            violations.append(f"{spec}: {error}")
            continue
        images[name] = comparison
        if not comparison["matching_platform_manifest_and_config"]:
            violations.append(f"{name} repeated build platform facts differ")
        for attempt in ("first", "second"):
            if comparison[attempt]["attestation_descriptor_count"] < 2:
                violations.append(f"{name} {attempt} build lacks SBOM/provenance descriptors")
    report = {
        "candidate_evidence_version": 3,
        "diagnostic_policy": _SAFE_DIAGNOSTIC_POLICY,
        "status": "pass" if not violations else "fail",
        "product_revision": _git(repo, "rev-parse", "HEAD"),
        "source_date_epoch": int(_git(repo, "show", "-s", "--format=%ct", "HEAD")),
        "upstream_revision": manifest["upstream_revision"],
        "adapter_contract_version": manifest["adapter_contract_version"],
        "label_profile": args.label_profile,
        "images": images,
        "violations": violations,
        "production_ready": False,
        "production_blockers": [
            "candidate archives are not registry-published immutable digests",
            "keyless signatures have not been verified",
            "protected production workflow identity has not been verified",
            "vulnerability and license admission evidence is not attached",
            "digest-pinned canary and N-1 rollback have not been exercised",
        ],
    }
    output = repo / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
