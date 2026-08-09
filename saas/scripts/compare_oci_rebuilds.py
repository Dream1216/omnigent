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


def _blob(root: Path, digest: str) -> bytes:
    algorithm, value = digest.split(":", 1)
    if algorithm != "sha256":
        raise ValueError(f"unsupported OCI digest algorithm: {algorithm}")
    data = (root / "blobs" / algorithm / value).read_bytes()
    actual = hashlib.sha256(data).hexdigest()
    if actual != value:
        raise ValueError(f"OCI blob digest mismatch: {digest}")
    return data


def inspect_oci_archive(path: Path) -> dict[str, Any]:
    """Return reproducibility facts for one BuildKit OCI archive."""

    with tempfile.TemporaryDirectory(prefix="omnigent-oci-inspect-") as temp_name:
        root = Path(temp_name)
        with tarfile.open(path) as archive:
            archive.extractall(root, filter="data")
        index = json.loads((root / "index.json").read_text(encoding="utf-8"))
        platforms: dict[str, dict[str, Any]] = {}

        def inspect_descriptor(descriptor: dict[str, Any]) -> int:
            platform = descriptor.get("platform", {})
            key = f"{platform.get('os')}/{platform.get('architecture')}"
            if key == "unknown/unknown":
                return 1
            document = json.loads(_blob(root, descriptor["digest"]))
            media_type = descriptor.get("mediaType")
            if media_type in _OCI_INDEX_MEDIA_TYPES or "manifests" in document:
                return sum(inspect_descriptor(child) for child in document.get("manifests", []))
            if key not in {"linux/amd64", "linux/arm64"}:
                return 1
            if key in platforms:
                raise ValueError(f"OCI archive repeats production platform {key}: {path}")
            manifest = document
            config_digest = manifest["config"]["digest"]
            config = json.loads(_blob(root, config_digest))
            platforms[key] = {
                "manifest_digest": descriptor["digest"],
                "config_digest": config_digest,
                "labels": config.get("config", {}).get("Labels", {}),
            }
            return 0

        attestation_descriptors = sum(
            inspect_descriptor(descriptor) for descriptor in index.get("manifests", [])
        )
        if set(platforms) != {"linux/amd64", "linux/arm64"}:
            raise ValueError(f"OCI archive does not contain both production platforms: {path}")
        return {
            "platforms": platforms,
            "attestation_descriptor_count": attestation_descriptors,
        }


def compare_archives(first: Path, second: Path) -> dict[str, Any]:
    """Compare only executable platform facts; attestation timestamps may differ."""

    left = inspect_oci_archive(first)
    right = inspect_oci_archive(second)
    matching = left["platforms"] == right["platforms"]
    return {
        "matching_platform_manifest_and_config": matching,
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
            comparison = compare_archives(Path(first), Path(second))
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
        "candidate_evidence_version": 1,
        "status": "pass" if not violations else "fail",
        "product_revision": _git(repo, "rev-parse", "HEAD"),
        "source_date_epoch": int(_git(repo, "show", "-s", "--format=%ct", "HEAD")),
        "upstream_revision": manifest["upstream_revision"],
        "adapter_contract_version": manifest["adapter_contract_version"],
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
