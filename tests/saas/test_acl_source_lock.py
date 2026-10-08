import json
import re
from pathlib import Path


def test_acl_whole_release_keeps_cross_suite_build_nonproduction() -> None:
    lock = json.loads(
        (
            Path(__file__).resolve().parents[2] / "saas/supply_chain/debian13-acl-source-lock.json"
        ).read_text()
    )
    assert lock["production_admission"] is False
    assert lock["source_version"] == "2.4.0-1"
    assert lock["source_suite"] == "sid"
    assert lock["build_dependency_suite"] == lock["codename"] == "trixie"
    assert "--require-valid-signature" in lock["extraction_contract"]
    assert "--require-strong-checksums" in lock["extraction_contract"]
    assert lock["source_authentication"]["primary_fingerprint"] == (
        "4F3E74F436050C10F5696574B972BF3EA4AE57A3"
    )
    assert {item["role"] for item in lock["artifacts"]} == {
        "dsc",
        "upstream",
        "signature",
        "debian",
        "keyring",
    }
    assert all(
        re.fullmatch(r"[a-f0-9]{64}", item["sha256"]) and item["size"] > 0
        for item in lock["artifacts"]
    )
    assert lock["patches"] == []
    assert "tar-and-other-linked-consumer-compatibility" in lock["required_followup"]
