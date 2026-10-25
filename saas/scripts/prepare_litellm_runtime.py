"""Fetch checksum-locked packages and signed indexes for offline LiteLLM builds."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import tomllib
from packaging.utils import canonicalize_name, parse_wheel_filename
from packaging.version import Version

_LOCK = Path(__file__).resolve().parents[1] / "production/litellm_release.json"
_UV_CONFIG = Path(__file__).resolve().parents[2] / "uv.toml"
_MAX_DOWNLOAD_BYTES = 32 * 1024 * 1024


def _python_wheels(lock: dict, architecture: str) -> tuple[dict[str, tuple[str, str]], str]:
    config = tomllib.loads(_UV_CONFIG.read_text())
    if config.get("exclude-newer") != "P7D":
        raise ValueError("LiteLLM wheels require the existing seven-day cooldown")
    now = datetime.now(UTC)
    sources, requirements = {}, []
    entries = dict(lock.get("python_packages", {}))
    if "pip" in entries:
        raise ValueError("the Python installer must not ship as a runtime overlay")
    if "python_installer" in lock:
        entries["pip"] = lock["python_installer"]
    for package, entry in entries.items():
        wheel = entry["wheels"].get(architecture, entry["wheels"].get("any"))
        if wheel is None:
            raise ValueError("missing LiteLLM wheel architecture")
        filename, version = wheel["filename"], entry["version"]
        name, parsed_version, _, tags = parse_wheel_filename(filename)
        expected_tags = (
            {"py3-none-any"}
            if "any" in entry["wheels"]
            else {
                f"cp313-cp313-{platform}_{architecture}"
                for platform in ("manylinux2014", "manylinux_2_17", "manylinux_2_28")
            }
        )
        if (
            name != canonicalize_name(package)
            or parsed_version != Version(version)
            or not {str(tag) for tag in tags} <= expected_tags
            or not wheel["url"].startswith("https://files.pythonhosted.org/packages/")
            or not wheel["url"].endswith("/" + filename)
        ):
            raise ValueError("LiteLLM wheel identity or target differs")
        uploaded = datetime.fromisoformat(wheel["uploaded_at"].replace("Z", "+00:00"))
        exception = config.get("exclude-newer-package", {}).get(package)
        cutoff = (
            datetime.fromisoformat(exception.replace("Z", "+00:00"))
            if exception
            else now - timedelta(days=7)
        )
        if uploaded.tzinfo is None or not uploaded <= min(cutoff, now):
            raise ValueError("LiteLLM wheel has not satisfied the existing cooldown")
        sources[filename] = (wheel["url"], wheel["sha256"])
        if package != "pip":
            requirements.append(f"{package}=={version} --hash=sha256:{wheel['sha256']}\n")
    return sources, "".join(requirements)


def prepare(destination: Path) -> dict[str, object]:
    lock = json.loads(_LOCK.read_text())["runtime_patch"]
    materials: dict[str, object] = {}
    with httpx.Client(timeout=60, follow_redirects=True, trust_env=False) as client:
        for architecture, packages in lock["packages"].items():
            wheels, requirements = _python_wheels(lock, architecture)
            sources = {
                filename: (
                    f"{lock['repository']}/{architecture}/{filename}",
                    packages.get(filename),
                )
                for filename in ("APKINDEX.tar.gz", *packages)
            }
            sources.update(wheels)
            directory = destination / architecture
            directory.mkdir(parents=True, exist_ok=True)
            hashes: dict[str, str] = {}
            for filename, (url, expected_digest) in sources.items():
                with client.stream("GET", url) as response:
                    response.raise_for_status()
                    content = bytearray()
                    for chunk in response.iter_bytes():
                        content.extend(chunk)
                        if len(content) > _MAX_DOWNLOAD_BYTES:
                            raise ValueError("LiteLLM runtime material is oversized")
                digest = hashlib.sha256(content).hexdigest()
                if expected_digest is not None and digest != expected_digest:
                    raise ValueError("LiteLLM runtime package checksum mismatch")
                (directory / filename).write_bytes(content)
                hashes[filename] = digest
            (directory / "packages.sha256").write_text(
                "".join(
                    f"{digest}  {architecture}/{name}\n"
                    for name, (_, digest) in sources.items()
                    if digest is not None
                )
            )
            (directory / "requirements.txt").write_text(requirements)
            materials[architecture] = hashes
    report: dict[str, object] = {
        "schema_version": 1,
        "materials": materials,
        "signature_verified": False,
    }
    # Signature verification occurs inside the pinned base during the offline
    # build; a downloaded index alone is not verified evidence.
    (destination / "materials.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    prepare(args.destination)
    print(json.dumps({"downloaded": True, "destination": str(args.destination)}))


if __name__ == "__main__":
    main()
