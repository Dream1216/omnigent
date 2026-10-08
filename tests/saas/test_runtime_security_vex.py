from __future__ import annotations

import pytest

from saas.scripts.render_runtime_security_vex import _EXPECTED, render


def _report(architecture: str = "amd64") -> dict[str, object]:
    matches: list[dict[str, object]] = []
    for (vulnerability, package), version in _EXPECTED.items():
        arch = "all" if package == "perl-modules-5.42" else architecture
        matches.append(
            {
                "vulnerability": {"id": vulnerability, "severity": "High"},
                "artifact": {
                    "name": package,
                    "version": version,
                    "purl": f"pkg:deb/debian/{package}@{version}?arch={arch}&distro=debian",
                },
            }
        )
    return {"matches": matches}


def test_vex_is_exact_and_architecture_bound() -> None:
    document = render(_report("arm64"), architecture="arm64", timestamp="2026-10-09T00:00:00Z")
    assert document["@context"] == "https://openvex.dev/ns/v0.2.0"
    statements = document["statements"]
    assert isinstance(statements, list)
    assert len(statements) == 4
    assert {item["vulnerability"]["name"] for item in statements} == {
        "CVE-2026-102010",
        "CVE-2026-95619",
        "CVE-2026-82560",
        "CVE-2026-85091",
    }
    assert all(item["status"] == "not_affected" for item in statements)
    purls = [product["@id"] for item in statements for product in item["products"]]
    assert all("arch=arm64" in purl or "arch=all" in purl for purl in purls)


def test_vex_rejects_unknown_or_missing_high_findings() -> None:
    report = _report()
    report["matches"].pop()  # type: ignore[union-attr]
    with pytest.raises(ValueError, match="missing"):
        render(report, architecture="amd64", timestamp="2026-10-09T00:00:00Z")

    report = _report()
    report["matches"].append(  # type: ignore[union-attr]
        {
            "vulnerability": {"id": "CVE-2099-1", "severity": "Critical"},
            "artifact": {
                "name": "surprise",
                "version": "1",
                "purl": "pkg:deb/debian/surprise@1?arch=amd64&distro=debian",
            },
        }
    )
    with pytest.raises(ValueError, match="unexpected Critical/High"):
        render(report, architecture="amd64", timestamp="2026-10-09T00:00:00Z")
