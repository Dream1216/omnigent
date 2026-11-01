"""Verify reproducible fixed-base legacy image candidates; never authorize rollout."""

from __future__ import annotations

import argparse
import base64
import csv
import gzip
import hashlib
import io
import json
import shutil
import subprocess
import tarfile
from pathlib import Path

from saas.scripts import compare_oci_rebuilds as compare
from saas.scripts import core_f440_compat_release as shared
from saas.scripts import export_d0_legacy_overlay as overlay
from saas.scripts import oci_promotion as oci
from saas.scripts import prepare_d0_legacy_compat as recipe
from saas.scripts import resume_oci_promotion as signatures
from saas.scripts import scan_oci_candidates as scans

WORKFLOW = ".github/workflows/saas-d0-legacy-compat.yml"
REPOSITORY = "Dream1216/omnigent"
BASE_RUN = "41221717927"
SITE = "opt/venv/lib/python3.12/site-packages/"
ROLES = ("server", "host")


def read(path: Path) -> dict:
    return json.loads(path.read_text())


def bound_json(path: Path, digest: str) -> dict:
    raw = path.read_bytes()
    shared.require(
        digest.removeprefix("sha256:")
        in {hashlib.sha256(raw).hexdigest(), hashlib.sha256(raw.removesuffix(b"\n")).hexdigest()},
        "base registry JSON does not match signed digest",
    )
    return json.loads(raw)


def base_config(root: Path, role: str, platform: str, materials: dict) -> tuple[dict, dict]:
    digest = materials["base_images"][role].split("@", 1)[1]
    index = bound_json(root / (role + "-index.json"), digest)
    os_name, architecture = platform.split("/")
    matches = [
        row
        for row in index["manifests"]
        if row.get("platform", {}).get("os") == os_name
        and row.get("platform", {}).get("architecture") == architecture
    ]
    shared.require(len(matches) == 1, "one exact base platform required")
    manifest = bound_json(root / f"{role}-{architecture}-manifest.json", matches[0]["digest"])
    config = bound_json(root / f"{role}-{architecture}-config.json", manifest["config"]["digest"])
    shared.require(
        config["os"] == os_name and config["architecture"] == architecture, "base platform differs"
    )
    shared.require(
        config["config"]["Labels"]["org.opencontainers.image.revision"]
        == materials["base_product_revision"],
        "base source label differs",
    )
    return manifest, config


def archive_blob(archive, digest):
    algorithm, value = digest.split(":", 1)
    shared.require(algorithm == "sha256" and len(value) == 64, "invalid OCI blob digest")
    member = archive.getmember("blobs/sha256/" + value)
    shared.require(member.isfile(), "OCI blob must be regular")
    stream = archive.extractfile(member)
    shared.require(stream is not None, "OCI blob missing")
    raw = stream.read()
    shared.require(hashlib.sha256(raw).hexdigest() == value, "OCI blob bytes differ")
    return raw


def require_signed_base_layers(actual: list[dict], expected: list[dict], epoch: int) -> None:
    """Keep exact compressed blobs and every descriptor field except builder epoch annotation."""
    shared.require(len(actual) == len(expected), "legacy base layer count changed")
    key = "buildkit/rewritten-timestamp"
    for observed, signed in zip(actual, expected, strict=True):
        observed_annotations = observed.get("annotations", {})
        signed_annotations = signed.get("annotations", {})
        shared.require(
            isinstance(observed_annotations, dict) and isinstance(signed_annotations, dict),
            "legacy base annotations malformed",
        )
        shared.require(
            observed_annotations.get(key) in (None, signed_annotations.get(key), str(epoch)),
            "legacy base timestamp annotation is not this source epoch",
        )

        def identity(descriptor):
            value = dict(descriptor)
            annotations = dict(value.pop("annotations", {}))
            annotations.pop(key, None)
            if annotations:
                value["annotations"] = annotations
            return value

        shared.require(identity(observed) == identity(signed), "legacy base layers changed")


def verify_overlay(archive_path, facts, materials, bases, role, revision, epoch):
    expected_paths = {SITE + name for name in materials["files"]}
    expected_paths |= {SITE + recipe.BUILD_INFO, SITE + recipe.RECORD}
    directories = {parent.as_posix() for name in expected_paths for parent in Path(name).parents}
    with tarfile.open(archive_path) as archive:
        for platform, fact in facts["platforms"].items():
            parent, parent_config = base_config(bases, role, platform, materials)
            manifest = json.loads(archive_blob(archive, fact["manifest_digest"]))
            config = json.loads(archive_blob(archive, fact["config_digest"]))
            require_signed_base_layers(manifest["layers"][:-1], parent["layers"], epoch)
            shared.require(
                config["rootfs"]["diff_ids"][:-1] == parent_config["rootfs"]["diff_ids"]
                and len(config["rootfs"]["diff_ids"])
                == len(parent_config["rootfs"]["diff_ids"]) + 1,
                "exactly one compatibility layer required",
            )
            shared.require(
                {k: v for k, v in config["config"].items() if k != "Labels"}
                == {k: v for k, v in parent_config["config"].items() if k != "Labels"},
                "base command/user/environment configuration changed",
            )
            layer = manifest["layers"][-1]
            raw = archive_blob(archive, layer["digest"])
            if layer["mediaType"].endswith("+gzip"):
                raw = gzip.decompress(raw)
            else:
                shared.require(
                    layer["mediaType"].endswith(".tar"), "unsupported overlay compression"
                )
            shared.require(
                "sha256:" + hashlib.sha256(raw).hexdigest() == config["rootfs"]["diff_ids"][-1],
                "overlay diff-id differs",
            )
            files = {}
            with tarfile.open(fileobj=io.BytesIO(raw)) as bundle:
                for member in bundle:
                    name = member.name.removeprefix("./").rstrip("/")
                    if member.isdir():
                        shared.require(
                            name in directories
                            and member.mode == 0o755
                            and member.uid == member.gid == 0,
                            "unexpected overlay directory",
                        )
                        continue
                    shared.require(
                        member.isfile()
                        and name in expected_paths
                        and name not in files
                        and member.mode == 0o644
                        and member.uid == member.gid == 0
                        and member.mtime == epoch,
                        "unexpected overlay path, type, owner or mode",
                    )
                    stream = bundle.extractfile(member)
                    if stream is None:
                        raise ValueError("overlay file has no stream")
                    files[name] = stream.read()
            shared.require(set(files) == expected_paths, "incomplete fixed overlay")
            rows = list(csv.reader(io.StringIO(files[SITE + recipe.RECORD].decode())))
            shared.require(all(len(row) == 3 for row in rows), "malformed installed RECORD")
            records = {row[0]: row[1:] for row in rows}
            shared.require(len(records) == len(rows), "duplicate installed RECORD")
            shared.require(records.get(recipe.RECORD) == ["", ""], "RECORD self-hash differs")
            for name, content in files.items():
                relative = name.removeprefix(SITE)
                if relative == recipe.RECORD:
                    continue
                encoded = (
                    base64.urlsafe_b64encode(hashlib.sha256(content).digest()).decode().rstrip("=")
                )
                shared.require(
                    records.get(relative) == ["sha256=" + encoded, str(len(content))],
                    "installed RECORD payload hash differs",
                )
            for name, pins in materials["files"].items():
                shared.require(
                    recipe.digest(files[SITE + name]) == pins["patched_sha256"],
                    "installed compatibility payload differs",
                )
            shared.require(
                overlay.build_identity(files[SITE + recipe.BUILD_INFO])
                == {"COMMIT_SHA": revision, "BUILD_TIME_EPOCH": epoch},
                "installed compatibility identity differs",
            )


def candidate(
    repository: Path,
    first: Path,
    second: Path,
    bases: Path,
    revision: str,
    epoch: int,
    *,
    diagnostics: Path | None = None,
):
    materials = recipe.load_manifest(repository)
    images = {}
    labels = {
        "org.opencontainers.image.revision": revision,
        "ai.omnigent.upstream.revision": "825f8500d7cc8e997e5562fa55694cd146165f3c",
        "ai.omnigent.saas.schema-revision": "lm2t00000001",
        "ai.omnigent.saas.adapter-contract-version": "0.2.0",
    }
    for role in ROLES:
        left, right = first / (role + ".tar"), second / (role + ".tar")
        facts = compare.compare_archives(left, right, label_profile="executable")
        if diagnostics is not None:
            expected_base = {
                platform: base_config(bases, role, platform, materials)[0]["layers"]
                for platform in scans.PLATFORMS
            }
            with tarfile.open(left) as original_archive:
                original_layers = {
                    platform: json.loads(archive_blob(original_archive, item["manifest_digest"]))[
                        "layers"
                    ]
                    for platform, item in facts["first"]["platforms"].items()
                }
            (diagnostics / (role + "-original-repeat-comparison.json")).write_text(
                json.dumps(
                    {
                        "comparison": facts,
                        "signed_base_layers": expected_base,
                        "original_candidate_layers": original_layers,
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            )
        shared.require(
            facts["matching_platform_manifest_and_config"], "repeated image builds differ"
        )
        for attempt in ("first", "second"):
            value = facts[attempt]
            shared.require(
                set(value["platforms"]) == set(scans.PLATFORMS)
                and value["attestation_descriptor_count"] >= 2
                and all(row["labels"] == labels for row in value["platforms"].values()),
                "complete provenance/SBOM and both exact platforms required",
            )
        verify_overlay(left, facts["first"], materials, bases, role, revision, epoch)
        images[role] = {
            "image_repository": "ghcr.io/dream1216/omnigent-saas-" + role,
            "index_digest": oci.archive_index_digest(left),
            "archive_sha256": scans.file_sha256(left),
            "facts": facts["first"],
            "repeat_comparison": facts,
            "labels": labels,
        }
    return {
        "schema_version": 1,
        "contract": materials["contract"],
        "product_revision": revision,
        "source_date_epoch": epoch,
        "materials": materials,
        "images": images,
        "repeated_build_platforms_match": True,
        "production_authority": False,
        "runtime_semantics_qualification": False,
        "physical_restore_qualification": False,
    }


def verify_binding(entries, *, subject, revision, workflow, run_id, attempt):
    claims = signatures.certificate_claims(revision, workflow, run_id, attempt)
    matching = [
        entry
        for entry in entries
        if entry["verificationResult"]["statement"].get("predicateType")
        == "https://slsa.dev/provenance/v1"
    ]
    shared.require(bool(matching), "native SLSA verification required")
    for entry in matching:
        try:
            signed = entry["verificationResult"]["statement"]["predicate"]
            shared.require(
                signed["runDetails"]["builder"]["id"] == claims["subjectAlternativeName"]
                and signed["runDetails"]["metadata"]["invocationId"] == claims["runInvocationURI"]
                and any(
                    row.get("uri") == "git+https://github.com/" + REPOSITORY + "@refs/heads/main"
                    and row.get("digest", {}).get("gitCommit") == revision
                    for row in signed["buildDefinition"]["resolvedDependencies"]
                ),
                "native provenance source or invocation differs",
            )
            signatures.verify_predicate(
                [entry],
                subject=subject,
                predicate=entry["verificationResult"]["statement"]["predicate"],
                predicate_type="https://slsa.dev/provenance/v1",
                claims=claims,
            )
            return
        except ValueError:
            continue
    raise ValueError("native signature does not bind exact source/workflow/run/subject")


def predicate(manifest, role, run_id, attempt):
    shared.require(role in ROLES, "unexpected signing role")
    revision = manifest["product_revision"]
    materials = manifest["materials"]
    return {
        "buildDefinition": {
            "buildType": "https://actions.github.io/buildtypes/workflow/v1",
            "externalParameters": {
                "workflow": {
                    "repository": "https://github.com/" + REPOSITORY,
                    "path": WORKFLOW,
                    "ref": "refs/heads/main",
                },
                "compatibility_contract": materials["contract"],
                "source_revision": revision,
                "source_date_epoch": manifest["source_date_epoch"],
                "role": role,
                "pair_manifest_sha256": recipe.digest(
                    json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
                ),
                "database_changed": False,
                "runner_permissions_changed": False,
                "dependency_changes": False,
                "production_authority": False,
                "runtime_semantics_qualification": False,
                "physical_restore_qualification": False,
            },
            "internalParameters": {
                "github": {
                    "event_name": "workflow_dispatch",
                    "repository_id": "1319241251",
                    "repository_owner_id": "39821512",
                    "runner_environment": "github-hosted",
                }
            },
            "resolvedDependencies": [
                {
                    "uri": "git+https://github.com/" + REPOSITORY + "@refs/heads/main",
                    "digest": {"gitCommit": revision},
                },
                {
                    "uri": "git+https://github.com/"
                    + REPOSITORY
                    + "@"
                    + materials["base_product_revision"],
                    "digest": {"gitCommit": materials["base_product_revision"]},
                },
                {
                    "uri": "pkg:pypi/omnigent@" + materials["legacy_runtime_version"],
                    "digest": {"sha256": materials["original_wheel_sha256"]},
                },
                {
                    "uri": recipe.ROOT + "/manifest.json",
                    "digest": {"sha256": recipe.MANIFEST_SHA256},
                },
                {
                    "uri": recipe.ROOT + "/M3659-D0-T.patch",
                    "digest": {"sha256": materials["patch_sha256"]},
                },
                *[
                    {"uri": image, "digest": {"sha256": image.split("@sha256:")[1]}}
                    for image in materials["base_images"].values()
                ],
                *[
                    {"uri": "installed:" + name, "digest": {"sha256": pins["patched_sha256"]}}
                    for name, pins in materials["files"].items()
                ],
            ],
        },
        "runDetails": {
            "builder": {
                "id": "https://github.com/" + REPOSITORY + "/" + WORKFLOW + "@refs/heads/main"
            },
            "metadata": {
                "invocationId": f"https://github.com/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}"
            },
        },
    }


def native_verification(subject, revision, workflow, kind):
    return subprocess.check_output(
        [
            "gh",
            "attestation",
            "verify",
            subject,
            "--repo",
            REPOSITORY,
            "--signer-workflow",
            REPOSITORY + "/" + workflow,
            "--source-ref",
            "refs/heads/main",
            "--source-digest",
            revision,
            "--signer-digest",
            revision,
            "--deny-self-hosted-runners",
            "--predicate-type",
            kind,
            "--format",
            "json",
        ],
        timeout=180,
    )


def verify_signatures(root, manifest, run_id, attempt):
    revision = manifest["product_revision"]
    claims = signatures.certificate_claims(revision, WORKFLOW, run_id, attempt)
    for role in ROLES:
        image = manifest["images"][role]
        for arch in (None, "amd64", "arm64"):
            digest = (
                image["index_digest"]
                if arch is None
                else image["facts"]["platforms"]["linux/" + arch]["manifest_digest"]
            )
            expected = (
                predicate(manifest, role, run_id, attempt)
                if arch is None
                else read(root / "supply-chain" / f"{role}-{arch}.spdx.json")
            )
            kind = signatures.PREDICATE_TYPE if arch is None else signatures.SPDX_PREDICATE_TYPE
            raw = native_verification(
                "oci://" + image["image_repository"] + "@" + digest, revision, WORKFLOW, kind
            )
            entries = json.loads(raw)
            if arch is None:
                signatures.verify_predicate(
                    entries, subject=digest, predicate=expected, predicate_type=kind, claims=claims
                )
            else:
                signatures.verify_sbom(entries, subject=digest, predicate=expected, claims=claims)
            (root / f"{role}-{arch or 'index'}-signature.json").write_bytes(raw)


def readback(repository, manifest, archives, bases):
    shared.require(
        manifest["materials"] == recipe.load_manifest(repository), "readback recipe differs"
    )
    value = json.loads(json.dumps(manifest))
    for role in ROLES:
        path = archives / (role + ".tar")
        expected = manifest["images"][role]
        shared.require(
            oci.archive_index_digest(path) == expected["index_digest"], "registry index differs"
        )
        facts = compare.inspect_oci_archive(path, label_profile="executable")
        shared.require(facts == expected["facts"], "registry executable or embedded facts differ")
        verify_overlay(
            path,
            facts,
            manifest["materials"],
            bases,
            role,
            manifest["product_revision"],
            manifest["source_date_epoch"],
        )
        value["images"][role]["original_archive_sha256"] = expected["archive_sha256"]
        value["images"][role]["archive_sha256"] = scans.file_sha256(path)
    value["evidence_scope"] = "registry-readback-repacked-archives-only"
    return value


def verify_wheel_artifact_metadata(metadata):
    shared.require(
        metadata["id"] == 13056135283
        and metadata["name"] == "omnigent-saas-wheel-3659f0b010f86d581299e8035e19ce226d518fab"
        and metadata["size_in_bytes"] == 8659166
        and metadata["expired"] is False
        and metadata["digest"]
        == "sha256:412f53aa38a92cfc25e91e573c7d20c659efc1dede8711734070cf94daf9e43b"
        and metadata["workflow_run"]["id"] == int(BASE_RUN)
        and metadata["workflow_run"]["head_branch"] == "main"
        and metadata["workflow_run"]["repository_id"] == 1319241251
        and metadata["workflow_run"]["head_repository_id"] == 1319241251
        and metadata["workflow_run"]["head_sha"] == "3659f0b010f86d581299e8035e19ce226d518fab",
        "original wheel native artifact metadata differs",
    )


def stage(repository, root, revision):
    materials = recipe.load_manifest(repository)
    root.mkdir(parents=True, exist_ok=False)
    metadata = json.loads(
        subprocess.check_output(
            ["gh", "api", "repos/" + REPOSITORY + "/actions/artifacts/13056135283"], timeout=60
        )
    )
    verify_wheel_artifact_metadata(metadata)
    (root / "original-wheel-artifact-metadata.json").write_text(
        json.dumps(metadata, sort_keys=True) + "\n"
    )
    archive = root / "original-wheel.zip"
    with archive.open("wb") as stream:
        subprocess.run(
            ["gh", "api", "repos/" + REPOSITORY + "/actions/artifacts/13056135283/zip"],
            stdout=stream,
            check=True,
            timeout=180,
        )
    oci.extract_artifact(
        archive, root / "original-wheel", zip_sha256=metadata["digest"].split(":")[1]
    )
    wheels = list((root / "original-wheel").rglob("*.whl"))
    shared.require(len(wheels) == 1, "one original signed wheel required")
    wheel = wheels[0]
    shared.require(
        scans.file_sha256(wheel) == materials["original_wheel_sha256"], "original wheel differs"
    )
    workflow = ".github/workflows/saas-image-candidate.yml"
    raw = native_verification(
        str(wheel), materials["base_product_revision"], workflow, signatures.PREDICATE_TYPE
    )
    verify_binding(
        json.loads(raw),
        subject="sha256:" + materials["original_wheel_sha256"],
        revision=materials["base_product_revision"],
        workflow=workflow,
        run_id=BASE_RUN,
        attempt="1",
    )
    (root / "original-wheel-signature.json").write_bytes(raw)
    context = root / "context"
    inputs = context / "runtime-inputs"
    inputs.mkdir(parents=True)
    shutil.copyfile(wheel, inputs / "original.whl")
    recipe.prepare(repository, wheel, inputs / "unsigned", revision)
    for name in (
        recipe.ROOT + "/manifest.json",
        recipe.ROOT + "/M3659-D0-T.patch",
        "saas/scripts/prepare_d0_legacy_compat.py",
        "saas/scripts/export_d0_legacy_overlay.py",
    ):
        target = inputs / "source" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(repository / name, target)
    shutil.copyfile(repository / recipe.ROOT / "Dockerfile", context / "Dockerfile")
    bases = root / "bases"
    bases.mkdir()
    for role, image in materials["base_images"].items():
        raw = native_verification(
            "oci://" + image,
            materials["base_product_revision"],
            workflow,
            signatures.PREDICATE_TYPE,
        )
        verify_binding(
            json.loads(raw),
            subject=image.split("@", 1)[1],
            revision=materials["base_product_revision"],
            workflow=workflow,
            run_id=BASE_RUN,
            attempt="1",
        )
        (bases / (role + "-signature.json")).write_bytes(raw)
        index_raw = subprocess.check_output(["crane", "manifest", image], timeout=120)
        (bases / (role + "-index.json")).write_bytes(index_raw)
        index = bound_json(bases / (role + "-index.json"), image.split("@", 1)[1])
        for arch in ("amd64", "arm64"):
            matches = [
                row
                for row in index["manifests"]
                if row.get("platform", {}) == {"os": "linux", "architecture": arch}
            ]
            shared.require(len(matches) == 1, "exact signed base platform required")
            subject = image.split("@", 1)[0] + "@" + matches[0]["digest"]
            for kind, command in (("manifest", "manifest"), ("config", "config")):
                (bases / f"{role}-{arch}-{kind}.json").write_bytes(
                    subprocess.check_output(["crane", command, subject], timeout=120)
                )
            base_config(bases, role, "linux/" + arch, materials)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command", choices=("stage", "candidate", "scans", "predicate", "signatures", "readback")
    )
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--first", type=Path)
    parser.add_argument("--second", type=Path)
    parser.add_argument("--archives", type=Path)
    parser.add_argument("--bases", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--epoch", type=int)
    parser.add_argument("--role", choices=ROLES)
    parser.add_argument("--run-id")
    parser.add_argument("--attempt", default="1")
    args = parser.parse_args()
    path = args.root / "pair-manifest.json"
    if args.command == "stage":
        stage(args.repository.resolve(), args.root.resolve(), args.revision)
        return
    if args.command == "candidate":
        value = candidate(
            args.repository,
            args.first,
            args.second,
            args.bases,
            args.revision,
            args.epoch,
            diagnostics=args.root,
        )
        path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
        return
    manifest = read(path)
    shared.require(
        manifest["product_revision"] == args.revision
        and manifest["materials"] == recipe.load_manifest(args.repository),
        "candidate source differs",
    )
    if args.command == "scans":
        value = shared.validate_component_scans(
            args.archives, manifest["images"], summary_name="candidate-scan-summary.json"
        )
    elif args.command == "predicate":
        value = predicate(manifest, args.role, args.run_id, args.attempt)
    elif args.command == "signatures":
        verify_signatures(args.root, manifest, args.run_id, args.attempt)
        value = {"status": "pass", "exact_native_index_and_spdx_signatures": 6}
    else:
        value = readback(args.repository, manifest, args.archives, args.bases)
        args.output.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    print(json.dumps(value, sort_keys=True))


if __name__ == "__main__":
    main()
