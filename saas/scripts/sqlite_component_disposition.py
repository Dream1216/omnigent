"""Verify the finite SQLite shell-component disposition without changing raw scans."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tarfile
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

RULE: dict[str, Any] = {
    "id": "CVE-2026-119586",
    "package": "sqlite-libs",
    "version": "3.54.1-r0",
    "justification": "vulnerable_component_not_present",
    "owner": "OmniAgent release-engineering and independent security acceptance",
    "expires_at": "2026-11-11T10:40:00Z",
    "compensating_control": (
        "Verify exact library bytes and absence of the SQLite C shell/recover component "
        "in every final image; retain complete original raw findings."
    ),
    "library_sha256": {
        "linux/amd64": "7c8f466fe08716da0c3ce29ef451e8443313b296717fd8ef98b020030fb282f7",
        "linux/arm64": "8f68e1e2567a00b7a986468884f2b166a9feff1e3e77ece7b63358fe6d3cb373",
    },
}
RULE_SHA256 = hashlib.sha256(json.dumps(RULE, sort_keys=True).encode()).hexdigest()


def rule_enabled() -> bool:
    path = Path(__file__).resolve().parents[1] / "supply_chain/release-policy.json"
    policy = json.loads(path.read_text())
    return policy.get("vulnerability_policy", {}).get("component_not_applicable") == RULE


def eligible_match(report: dict[str, Any], *, now: datetime) -> bool:
    from saas.scripts.scan_oci_candidates import scan_report

    parsed = scan_report(report)
    if not rule_enabled() or parsed["counts"] != {"Critical": 0, "High": 1}:
        return False
    configuration = report.get("descriptor", {}).get("configuration", {})
    if (
        configuration.get("only-fixed") is not False
        or configuration.get("only-notfixed") is not False
        or configuration.get("exclude", []) != []
        or configuration.get("vex-documents", []) != []
    ):
        return False
    if now.tzinfo is None or now >= datetime.fromisoformat(
        RULE["expires_at"].replace("Z", "+00:00")
    ):
        return False
    high = [item for item in report["matches"] if item["vulnerability"]["severity"] == "High"]
    item = high[0]
    vulnerability, artifact = item["vulnerability"], item["artifact"]
    return (
        vulnerability.get("id") == RULE["id"]
        and vulnerability.get("namespace") == "nvd:cpe"
        and artifact.get("type") == "apk"
        and artifact.get("name") == RULE["package"]
        and artifact.get("version") == RULE["version"]
        and isinstance(item.get("matchDetails"), list)
        and len(item["matchDetails"]) == 1
        and isinstance(item["matchDetails"][0], dict)
        and item["matchDetails"][0].get("matcher") == "apk-matcher"
        and item["matchDetails"][0].get("type") == "cpe-match"
    )


class ImageBlobs:
    """Read digest-verified blobs from an existing OCI archive or admitted layout."""

    def __init__(self, source: Path, archive: tarfile.TarFile | None):
        self.source = source
        self.archive = archive

    @contextmanager
    def member(self, name: str) -> Iterator[Any]:
        if self.archive is not None:
            matches = [item for item in self.archive.getmembers() if item.name == name]
            if len(matches) != 1 or not matches[0].isfile():
                raise ValueError("OCI member is missing, duplicated or not regular")
            stream = self.archive.extractfile(matches[0])
            assert stream is not None
        else:
            path = self.source / name
            if path.is_symlink() or not path.is_file():
                raise ValueError("OCI layout member is not regular")
            stream = path.open("rb")
        with stream:
            yield stream

    @contextmanager
    def blob(self, digest: str) -> Iterator[Any]:
        if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
            raise ValueError("invalid OCI component blob digest")
        with self.member("blobs/sha256/" + digest[7:]) as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != digest[7:]:
                raise ValueError("OCI component blob digest mismatch")
            stream.seek(0)
            yield stream

    def document(self, digest: str) -> dict[str, Any]:
        with self.blob(digest) as stream:
            body = stream.read(2_000_001)
        if len(body) > 2_000_000:
            raise ValueError("OCI component document is too large")
        return json.loads(body)

    def platform(self, platform: str) -> tuple[str, dict[str, Any]]:
        with self.member("index.json") as stream:
            index = json.load(stream)
        found = []

        def visit(document: dict[str, Any], depth: int) -> None:
            if depth > 8:
                raise ValueError("OCI component index nesting is excessive")
            for descriptor in document.get("manifests", []):
                coordinate = descriptor.get("platform", {})
                if coordinate.get("os") == "unknown":
                    continue
                child = self.document(descriptor["digest"])
                if "manifests" in child:
                    visit(child, depth + 1)
                elif f"{coordinate.get('os')}/{coordinate.get('architecture')}" == platform:
                    found.append((descriptor["digest"], child))

        visit(index, 0)
        if len(found) != 1:
            raise ValueError("OCI component platform must occur exactly once")
        return found[0]


@contextmanager
def image_blobs(source: Path) -> Iterator[ImageBlobs]:
    with ExitStack() as stack:
        archive = stack.enter_context(tarfile.open(source)) if source.is_file() else None
        yield ImageBlobs(source, archive)


def component_inventory(
    blobs: ImageBlobs,
    manifest: dict[str, Any],
    *,
    additional_paths: frozenset[str] = frozenset(),
) -> list[dict[str, Any]]:
    entries: dict[str, dict[str, Any]] = {}
    for descriptor in manifest["layers"]:
        additions, overwritten, whiteouts = {}, set(), []
        with (
            blobs.blob(descriptor["digest"]) as source,
            tarfile.open(fileobj=source, mode="r|*") as layer,
        ):
            for member in layer:
                path = PurePosixPath(member.name.removeprefix("./"))
                if path.is_absolute() or ".." in path.parts:
                    raise ValueError("unsafe OCI component path")
                name = str(path)
                if path.name.startswith(".wh."):
                    target = (
                        path.parent if path.name == ".wh..wh..opq" else path.parent / path.name[4:]
                    )
                    whiteouts.append(str(target))
                    continue
                if not member.isdir():
                    overwritten.add(name)
                selected = (
                    "sqlite" in name.lower()
                    or "recover" in path.name.lower()
                    or name in additional_paths
                )
                facts: dict[str, Any] = {
                    "path": name,
                    "type": member.type.decode(),
                    "link": member.linkname,
                    "mode": member.mode,
                }
                if member.isfile():
                    stream = layer.extractfile(member)
                    assert stream is not None
                    prefix = stream.read(4)
                    if selected or prefix == b"\x7fELF":
                        checksum = hashlib.sha256(prefix)
                        markers = {
                            b".recover": False,
                            b"sqlite> ": False,
                            b"sqlite3_recover_init": False,
                        }
                        tail = prefix
                        while chunk := stream.read(1024 * 1024):
                            checksum.update(chunk)
                            for marker in markers:
                                markers[marker] |= marker in tail + chunk
                            tail = chunk[-64:]
                        shell = (
                            prefix == b"\x7fELF" and markers[b".recover"] and markers[b"sqlite> "]
                        )
                        recover = prefix == b"\x7fELF" and markers[b"sqlite3_recover_init"]
                        selected |= shell or recover
                        facts.update(sha256=checksum.hexdigest(), shell=shell, recover=recover)
                if selected:
                    additions[name] = facts
        for name in list(entries):
            if name in overwritten or any(
                name == prefix or name.startswith(prefix + "/") for prefix in whiteouts
            ):
                del entries[name]
        entries.update(additions)
    return [entries[name] for name in sorted(entries)]


def inspect_disposition(
    image: Path, report_path: Path, *, platform: str, now: datetime
) -> dict[str, Any]:
    raw = report_path if isinstance(report_path, bytes) else report_path.read_bytes()
    report = json.loads(raw)
    if not eligible_match(report, now=now) or platform not in RULE["library_sha256"]:
        raise ValueError("raw findings do not qualify for the finite SQLite disposition")
    target = report.get("source", {}).get("target", {})
    with image_blobs(image) as blobs:
        manifest_digest, manifest = blobs.platform(platform)
        config_digest = manifest["config"]["digest"]
        config = blobs.document(config_digest)
        if (
            target.get("manifestDigest") != manifest_digest
            or target.get("imageID") != config_digest
            or target.get("architecture") != platform.split("/")[1]
            or target.get("os") != "linux"
            or target.get("labels") != config.get("config", {}).get("Labels")
        ):
            raise ValueError("SQLite disposition does not bind the actual OCI subject")
        inventory = component_inventory(blobs, manifest)
    return disposition_receipt(report_path, inventory, platform=platform, now=now)


def disposition_receipt(
    report_path: Path | bytes, inventory: list[dict[str, Any]], *, platform: str, now: datetime
) -> dict[str, Any]:
    from saas.scripts.scan_oci_candidates import parse_database_status

    raw = report_path if isinstance(report_path, bytes) else report_path.read_bytes()
    report = json.loads(raw)
    if not eligible_match(report, now=now) or platform not in RULE["library_sha256"]:
        raise ValueError("raw findings do not qualify for the finite SQLite disposition")
    descriptor = report.get("descriptor", {})
    if descriptor.get("name") != "grype" or descriptor.get("version") != "0.120.1":
        raise ValueError("component disposition scanner differs")
    parse_database_status(descriptor["db"]["status"], now=now)
    target = report.get("source", {}).get("target", {})
    if (
        not isinstance(target, dict)
        or target.get("os") != "linux"
        or target.get("architecture") != platform.split("/")[1]
    ):
        raise ValueError("component disposition platform differs")
    for field in ("manifestDigest", "imageID"):
        if re.fullmatch(r"sha256:[0-9a-f]{64}", str(target.get(field))) is None:
            raise ValueError("component disposition requires exact subject digests")
    revision = target.get("labels", {}).get("org.opencontainers.image.revision")
    if re.fullmatch(r"[0-9a-f]{40}", str(revision)) is None:
        raise ValueError("component disposition requires exact source revision")
    component = sqlite_component_facts(inventory, platform=platform)
    return {
        "rule_sha256": RULE_SHA256,
        "id": RULE["id"],
        "justification": RULE["justification"],
        "owner": RULE["owner"],
        "expires_at": RULE["expires_at"],
        "platform": platform,
        "manifest_digest": target["manifestDigest"],
        "config_digest": target["imageID"],
        "source_revision": revision,
        "report_sha256": hashlib.sha256(raw).hexdigest(),
        **component,
        "inventory": inventory,
        "raw_critical": 0,
        "raw_high": 1,
    }


def sqlite_component_facts(inventory: list[dict[str, Any]], *, platform: str) -> dict[str, str]:
    """Validate component bytes/absence only; this does not classify a finding."""
    if (
        platform not in RULE["library_sha256"]
        or not isinstance(inventory, list)
        or not inventory
        or len({item["path"] for item in inventory}) != len(inventory)
    ):
        raise ValueError("component disposition inventory is missing or duplicated")
    library_path = "usr/lib/libsqlite3.so.3.54.1"
    libraries = [item for item in inventory if item["path"] == library_path]
    if len(libraries) != 1 or libraries[0].get("sha256") != RULE["library_sha256"][platform]:
        raise ValueError("SQLite disposition library bytes differ")
    for item in inventory:
        basename = PurePosixPath(item["path"]).name
        if (
            item.get("shell")
            or item.get("recover")
            or (
                item["type"] != "5"
                and re.fullmatch(r"sqlite3(?:\.exe|-[0-9][0-9.]*)?", basename)
                and (item["type"] in {"1", "2"} or bool(item.get("mode", 0) & 0o111))
            )
        ):
            raise ValueError("SQLite shell or recovery component is present")
        if (
            basename.startswith("libsqlite3.so")
            and item["type"] == "0"
            and item["path"] != library_path
        ):
            raise ValueError("additional unapproved SQLite library is present")
    return {
        "library_sha256": libraries[0]["sha256"],
        "inventory_sha256": hashlib.sha256(
            json.dumps(inventory, sort_keys=True).encode()
        ).hexdigest(),
    }


def _validate_disposition_receipt(
    report_path: Path | bytes, proof: object, *, now: datetime
) -> dict[str, Any]:
    if (
        not isinstance(proof, dict)
        or type(proof.get("raw_high")) is not int
        or type(proof.get("raw_critical")) is not int
    ):
        raise ValueError(
            "unapproved Critical or High finding: finite component disposition proof is missing"
        )
    inventory, platform = proof.get("inventory"), proof.get("platform")
    if not isinstance(inventory, list) or not isinstance(platform, str):
        raise ValueError("finite component disposition inventory or platform is missing")
    if proof.get("classification") == "mitigated_by_verified_runtime_conditions":
        scanner_exit = proof.get("scanner_exit")
        if type(scanner_exit) is not int or scanner_exit != 2:
            raise ValueError("finite combination requires original integer scanner exit 2")
        from saas.scripts.combined_runtime_disposition import (
            disposition_receipt as combined_receipt,
        )
        from saas.scripts.runtime_evidence_intake import (
            authenticated_runtime_graph,
            verifier_from_registered_inputs,
        )

        raw = report_path if isinstance(report_path, bytes) else report_path.read_bytes()
        expected = combined_receipt(
            raw,
            inventory,
            platform=platform,
            now=now,
            scanner_exit=scanner_exit,
            verify_runtime=verifier_from_registered_inputs(
                authenticated_runtime_graph(
                    Path(__file__).resolve().parents[2],
                    product_revision=json.loads(raw)["source"]["target"]["labels"][
                        "org.opencontainers.image.revision"
                    ],
                    now=now,
                ),
                inventory,
            ),
        )
        if json.dumps(proof, sort_keys=True, allow_nan=False) != json.dumps(
            expected, sort_keys=True, allow_nan=False
        ):
            raise ValueError(
                "finite combination differs from unchanged raw and registered native proof"
            )
        return expected
    expected = disposition_receipt(report_path, inventory, platform=platform, now=now)
    if proof != expected:
        raise ValueError("finite component disposition differs from original raw report or rule")
    return expected


def validate_disposition(
    report_path: Path, proof: object, *, image: Path | None = None, now: datetime
) -> dict[str, Any]:
    receipt = _validate_disposition_receipt(report_path, proof, now=now)
    if image is None:
        raise ValueError("finite component disposition requires actual verified OCI input")
    from saas.scripts.approved_disposition import inspect_approved_disposition

    actual = inspect_approved_disposition(
        image, report_path, platform=receipt["platform"], now=now
    )
    if receipt != actual:
        raise ValueError("finite component inventory differs from actual OCI contents")
    return actual


def main() -> None:
    from saas.scripts.approved_disposition import inspect_approved_disposition
    from saas.scripts.scan_oci_candidates import scan_report

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scanner-exit", type=int, required=True)
    args = parser.parse_args()
    raw = json.loads(args.report.read_bytes())
    parsed = scan_report(raw)
    if args.scanner_exit not in (0, 2) or (
        args.scanner_exit == 2 and not any(parsed["counts"].values())
    ):
        raise ValueError("unexpected actual scanner exit")
    proof = (
        inspect_approved_disposition(
            args.image, args.report, platform=args.platform, now=datetime.now(UTC)
        )
        if any(parsed["counts"].values())
        else None
    )
    args.output.write_text(
        json.dumps(
            {
                "raw_counts": parsed["counts"],
                "scanner_exit": args.scanner_exit,
                "component_disposition": proof,
            },
            sort_keys=True,
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()


def validate_release_dispositions(
    repo: Path,
    image: dict[str, Any],
    scan: dict[str, Any],
    evidence: dict[str, Any],
    *,
    now: datetime,
) -> None:
    require_admitted_image_inventory(repo, evidence, image, now=now)
    bundle = scan.get("component_dispositions")
    if (
        not isinstance(bundle, list)
        or not bundle
        or type(scan.get("critical")) is not int
        or scan["critical"] != 0
        or type(scan.get("high")) is not int
        or scan["high"] != sum(item.get("proof", {}).get("raw_high", 0) for item in bundle)
    ):
        raise ValueError("release raw counts do not bind finite component dispositions")
    if hashlib.sha256(json.dumps(bundle, sort_keys=True).encode()).hexdigest() != scan.get(
        "report_sha256"
    ):
        raise ValueError("release component report bundle digest differs")
    seen = set()
    for item in bundle:
        raw = item["raw_report"].encode()
        proof = _validate_disposition_receipt(raw, item["proof"], now=now)
        platform = proof["platform"]
        if (
            platform in seen
            or proof["manifest_digest"] != image["platform_digests"].get(platform)
            or proof["config_digest"] != image["config_digests"].get(platform)
            or proof["source_revision"] != image["labels"]["org.opencontainers.image.revision"]
        ):
            raise ValueError("release component disposition belongs to another subject")
        seen.add(platform)


def require_admitted_image_inventory(
    repo: Path, evidence: dict[str, Any], image: dict[str, Any], *, now: datetime
) -> None:
    from saas.scripts.runtime_evidence_intake import authenticated_image_documents

    documents = authenticated_image_documents(
        repo, product_revision=image["labels"]["org.opencontainers.image.revision"], now=now
    )
    bodies = [document.get("release_evidence", document) for document in documents]
    if evidence not in bodies or image not in evidence.get("images", []):
        raise ValueError("finite image inventory differs from the authenticated evidence document")
