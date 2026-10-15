"""Fetch checksum-locked packages and signed indexes for offline LiteLLM builds."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import httpx

_LOCK = Path(__file__).resolve().parents[1] / "production/litellm_release.json"
_MAX_DOWNLOAD_BYTES = 32 * 1024 * 1024


def prepare(destination: Path) -> dict[str, object]:
    lock = json.loads(_LOCK.read_text())["runtime_patch"]
    materials: dict[str, object] = {}
    with httpx.Client(timeout=60, follow_redirects=True, trust_env=False) as client:
        for architecture, packages in lock["packages"].items():
            directory = destination / architecture
            directory.mkdir(parents=True, exist_ok=True)
            hashes: dict[str, str] = {}
            for filename in ("APKINDEX.tar.gz", *packages):
                with client.stream(
                    "GET", f"{lock['repository']}/{architecture}/{filename}"
                ) as response:
                    response.raise_for_status()
                    content = bytearray()
                    for chunk in response.iter_bytes():
                        content.extend(chunk)
                        if len(content) > _MAX_DOWNLOAD_BYTES:
                            raise ValueError("LiteLLM runtime material is oversized")
                digest = hashlib.sha256(content).hexdigest()
                if filename in packages and digest != packages[filename]:
                    raise ValueError("LiteLLM runtime package checksum mismatch")
                (directory / filename).write_bytes(content)
                hashes[filename] = digest
            (directory / "packages.sha256").write_text(
                "".join(f"{digest}  {architecture}/{name}\n" for name, digest in packages.items())
            )
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
