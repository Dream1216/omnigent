"""Compare ELF identity and versioned exports without claiming complete ABI admission."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any


def inventory(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("ELF comparison requires a regular, resolved file")
    before = hashlib.sha256(path.read_bytes()).hexdigest()

    def readelf(*args: str) -> str:
        return subprocess.run(
            ["readelf", "--wide", *args, str(path)],
            check=True,
            text=True,
            capture_output=True,
            timeout=30,
            env={**os.environ, "LC_ALL": "C"},
        ).stdout

    header = readelf("--file-header")
    metadata = {}
    for name in ("Class", "Data", "Machine"):
        match = re.search(rf"(?m)^\s*{name}:\s*(.+)$", header)
        if match is None:
            raise ValueError(f"ELF identity is missing {name}")
        metadata[name] = match[1].strip()
    soname = re.findall(r"\(SONAME\).*\[([^\]]+)\]", readelf("--dynamic"))
    if len(soname) != 1:
        raise ValueError("ELF comparison requires exactly one SONAME")
    exports = {}
    for line in readelf("--dyn-syms").splitlines():
        fields = line.split()
        if (
            len(fields) >= 8
            and fields[0].endswith(":")
            and fields[0][:-1].isdigit()
            and fields[4] in {"GLOBAL", "WEAK"}
            and fields[5] in {"DEFAULT", "PROTECTED"}
            and fields[6] != "UND"
        ):
            name = fields[7]
            if name in exports:
                raise ValueError("ELF export inventory has ambiguous duplicate names")
            exports[name] = {"type": fields[3], "size": int(fields[2])}
    if not exports:
        raise ValueError("ELF comparison cannot pass an empty export inventory")
    if hashlib.sha256(path.read_bytes()).hexdigest() != before:
        raise ValueError("ELF changed during inventory")
    return {"sha256": before, "identity": metadata, "soname": soname[0], "exports": exports}


def compare(baseline: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    blockers = []
    if baseline["identity"] != candidate["identity"]:
        blockers.append("ELF class, byte order or machine differs")
    if baseline["soname"] != candidate["soname"]:
        blockers.append("SONAME differs")
    if not baseline["exports"] or not candidate["exports"]:
        blockers.append("export inventory is empty")
    missing = sorted(set(baseline["exports"]) - set(candidate["exports"]))
    for name in sorted(set(baseline["exports"]) & set(candidate["exports"])):
        old, new = baseline["exports"][name], candidate["exports"][name]
        if old["type"] != new["type"] or (
            old["type"] in {"OBJECT", "TLS"} and old["size"] != new["size"]
        ):
            blockers.append(f"export type or data size differs: {name}")
    if missing:
        blockers.append("baseline versioned exports are missing")
    return {
        "schema_version": 1,
        "status": "fail" if blockers else "pass",
        "production_admission": False,
        "scope": "ELF identity, SONAME, versioned exports and exported data sizes only",
        "baseline_sha256": baseline["sha256"],
        "candidate_sha256": candidate["sha256"],
        "baseline_soname": baseline["soname"],
        "candidate_soname": candidate["soname"],
        "missing_exports": missing,
        "added_exports": sorted(set(candidate["exports"]) - set(baseline["exports"])),
        "blockers": blockers,
        "required_followup": [
            "typed-ABI-comparison",
            "linked-consumer-regressions",
            "full-image-admission",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    args = parser.parse_args()
    report = compare(inventory(args.baseline), inventory(args.candidate))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
