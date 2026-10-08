"""Render the narrow OpenVEX document for the authenticated runtime overlays."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

_EXPECTED: dict[tuple[str, str], str] = {
    ("CVE-2026-102010", "gcc-16-base"): "16.2.0-3",
    ("CVE-2026-102010", "libgcc-s1"): "16.2.0-3",
    ("CVE-2026-102010", "libstdc++6"): "16.2.0-3",
    ("CVE-2026-95619", "gcc-16-base"): "16.2.0-3",
    ("CVE-2026-95619", "libgcc-s1"): "16.2.0-3",
    ("CVE-2026-95619", "libstdc++6"): "16.2.0-3",
    ("CVE-2026-82560", "libperl5.42"): "5.42.3-1",
    ("CVE-2026-82560", "perl"): "5.42.3-1",
    ("CVE-2026-82560", "perl-base"): "5.42.3-1",
    ("CVE-2026-82560", "perl-modules-5.42"): "5.42.3-1",
    ("CVE-2026-85091", "zlib1g"): "1:1.3.dfsg+really1.3.2-3",
}

_STATEMENTS = {
    "CVE-2026-102010": (
        "vulnerable_code_not_present",
        "The affected PBDS binary-heap erase_if template is a development "
        "header and is absent from the runtime image.",
    ),
    "CVE-2026-95619": (
        "vulnerable_code_not_in_execute_path",
        "The shipped implementation rejects all nine upstream aligned-allocation "
        "overflow regression cases before the affected fallback path can execute.",
    ),
    "CVE-2026-82560": (
        "vulnerable_code_not_in_execute_path",
        "The tested Podlators v6.1.1 overlay is earlier on Perl's runtime search "
        "path than Debian's vulnerable Pod::Text module.",
    ),
    "CVE-2026-85091": (
        "vulnerable_code_not_present",
        "The runtime libz.so.1.3.2 bytes are replaced by signed zlib 1.3.2 plus "
        "upstream fix df84af25dc1942490e1d1c899a07619152a46148.",
    ),
}


def render(report: dict[str, Any], *, architecture: str, timestamp: str) -> dict[str, Any]:
    if architecture not in {"amd64", "arm64"}:
        raise ValueError(f"unsupported architecture: {architecture}")
    matches = report.get("matches")
    if not isinstance(matches, list):
        raise ValueError("Grype report has no matches array")

    observed: dict[tuple[str, str], dict[str, Any]] = {}
    for match in matches:
        vulnerability = match.get("vulnerability", {})
        severity = vulnerability.get("severity")
        if severity not in {"Critical", "High"}:
            continue
        artifact = match.get("artifact", {})
        key = (vulnerability.get("id"), artifact.get("name"))
        if key not in _EXPECTED:
            raise ValueError(f"unexpected Critical/High finding: {key!r}")
        if artifact.get("version") != _EXPECTED[key]:
            raise ValueError(f"unexpected version for {key!r}: {artifact.get('version')!r}")
        purl = artifact.get("purl")
        if not isinstance(purl, str) or not purl.startswith("pkg:deb/debian/"):
            raise ValueError(f"missing Debian purl for {key!r}")
        expected_arch = "all" if artifact.get("name") == "perl-modules-5.42" else architecture
        if f"arch={expected_arch}" not in purl:
            raise ValueError(f"unexpected architecture in purl for {key!r}: {purl}")
        observed[key] = artifact

    missing = set(_EXPECTED) - set(observed)
    if missing:
        raise ValueError(f"expected Critical/High findings are missing: {sorted(missing)!r}")

    statements: list[dict[str, Any]] = []
    for vulnerability_id, (justification, impact) in _STATEMENTS.items():
        products = sorted(
            {
                artifact["purl"]
                for (cve, _), artifact in observed.items()
                if cve == vulnerability_id
            }
        )
        statements.append(
            {
                "vulnerability": {"name": vulnerability_id},
                "products": [{"@id": purl} for purl in products],
                "status": "not_affected",
                "justification": justification,
                "impact_statement": impact,
            }
        )

    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"https://next.jxhh.com/security/vex/runtime-security-{architecture}-{timestamp}",
        "author": "next.jxhh.com Release Engineering",
        "role": "Document Creator",
        "timestamp": timestamp,
        "version": 1,
        "statements": statements,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--grype-report", type=Path, required=True)
    parser.add_argument("--architecture", required=True)
    parser.add_argument("--timestamp", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = json.loads(args.grype_report.read_text(encoding="utf-8"))
    document = render(report, architecture=args.architecture, timestamp=args.timestamp)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
