"""Verify locked source bytes and check Debian backports without production admission."""

from __future__ import annotations

import argparse
import email.utils
import hashlib
import io
import json
import re
import subprocess
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any


def verified_materials(lock: dict[str, Any], cache: Path) -> dict[str, bytes]:
    if (
        type(lock.get("schema_version")) is not int
        or lock.get("schema_version") != 1
        or lock.get("distribution") != "debian"
        or lock.get("codename") != "trixie"
        or lock.get("production_admission") is not False
    ):
        raise ValueError("source replay must remain a non-production Debian 13 operation")
    materials: dict[str, bytes] = {}
    for item in [*lock["artifacts"], *lock["patches"]]:
        name, expected = item["name"], item["sha256"]
        if not re.fullmatch(r"[A-Za-z0-9_.+-]+", name) or name in materials:
            raise ValueError("source material filename is unsafe or duplicated")
        if not re.fullmatch(r"[a-f0-9]{64}", expected):
            raise ValueError("source material must have an exact SHA-256")
        path = cache / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"source material is missing or symlinked: {name}")
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(f"source material hash mismatch: {name}")
        materials[name] = data
    cves: set[str] = set()
    for patch in lock["patches"]:
        commit, cve = patch["commit"], patch["cve"]
        if not re.fullmatch(r"[a-f0-9]{40}", commit) or not re.fullmatch(
            r"CVE-[0-9]{4}-[0-9]{4,10}", cve
        ):
            raise ValueError("backport needs an exact upstream commit and CVE")
        if cve in cves or not materials[patch["name"]].startswith(f"From {commit} ".encode()):
            raise ValueError("backport commit binding is invalid or CVE is duplicated")
        cves.add(cve)
    return materials


def _extract(data: bytes, destination: Path, root: str) -> None:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        for member in archive.getmembers():
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != root:
                raise ValueError(f"source archive path is outside {root}: {member.name}")
        archive.extractall(destination, filter="data")


def _apply(root: Path, patch: Path) -> subprocess.CompletedProcess[str]:
    command = ["git", "apply", "--whitespace=nowarn", str(patch)]
    checked = subprocess.run(
        [*command[:2], "--check", *command[2:]],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )
    if checked.returncode:
        return checked
    return subprocess.run(
        command, cwd=root, text=True, capture_output=True, check=False, timeout=60
    )


def _patch_date(data: bytes) -> float:
    match = re.search(rb"(?m)^Date: (.+)$", data)
    if match is None:
        raise ValueError("locked upstream patch is missing its date")
    return email.utils.parsedate_to_datetime(match.group(1).decode()).timestamp()


def replay(lock_path: Path, cache: Path, destination: Path) -> dict[str, Any]:
    lock_bytes = lock_path.read_bytes()
    lock = json.loads(lock_bytes)
    materials = verified_materials(lock, cache)
    if destination.exists():
        raise ValueError("source replay destination must not already exist")
    root_name = lock["source_root"]
    if not re.fullmatch(r"[A-Za-z0-9_.+-]+", root_name):
        raise ValueError("source root is unsafe")
    roles = {item["role"]: item["name"] for item in lock["artifacts"]}
    if len(lock["artifacts"]) != 4 or set(roles) != {"dsc", "upstream", "signature", "debian"}:
        raise ValueError("source bundle roles do not match the locked contract")
    dsc = materials[roles["dsc"]].decode()
    if f"\nSource: {lock['component']}\n" not in dsc or (
        f"\nVersion: {lock['source_version']}\n" not in dsc
    ):
        raise ValueError("Debian source manifest identity does not match the lock")
    checksum_section = dsc.split("\nChecksums-Sha256:\n", 1)[1].split("\nFiles:", 1)[0]
    expected_source = {
        item["name"]: item["sha256"] for item in lock["artifacts"] if item["role"] != "dsc"
    }
    actual_source = {}
    for line in checksum_section.splitlines():
        digest, size, name = line.split()
        if len(materials.get(name, b"")) != int(size):
            raise ValueError("Debian source manifest size binding failed")
        actual_source[name] = digest
    if actual_source != expected_source:
        raise ValueError("Debian source manifest hash binding failed")
    patches = sorted(lock["patches"], key=lambda item: _patch_date(materials[item["name"]]))
    destination.mkdir(parents=True)
    _extract(materials[roles["upstream"]], destination, root_name)
    root = destination / root_name
    _extract(materials[roles["debian"]], root, "debian")
    report: dict[str, Any] = {
        "schema_version": 1,
        "status": "fail",
        "production_admission": False,
        "component": lock["component"],
        "source_version": lock["source_version"],
        "source_lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
        "baseline_patches": [],
        "backports": [],
        "blockers": [],
        "required_followup": ["compiled-regression", "ABI-comparison", "full-image-admission"],
    }
    patch_root = root / "debian/patches"
    for line in (patch_root / "series").read_text().splitlines():
        name = line.partition("#")[0].strip()
        if not name:
            continue
        if not re.fullmatch(r"[A-Za-z0-9_.+-]+", name):
            raise ValueError("Debian patch series needs a plain relative filename")
        result = _apply(root, patch_root / name)
        report["baseline_patches"].append({"name": name, "exit_code": result.returncode})
        if result.returncode:
            report["blockers"].append(f"baseline patch failed: {name}: {result.stderr.strip()}")
            return report
    for item in patches:
        result = _apply(root, (cache / item["name"]).resolve())
        report["backports"].append(
            {
                "cve": item["cve"],
                "commit": item["commit"],
                "patch_sha256": item["sha256"],
                "exit_code": result.returncode,
                "diagnostic": result.stderr.strip(),
            }
        )
        if result.returncode:
            report["blockers"].append(f"upstream patch needs reviewed backport: {item['cve']}")
    report["status"] = "fail" if report["blockers"] else "pass"
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    report = replay(args.lock, args.cache, args.destination)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
