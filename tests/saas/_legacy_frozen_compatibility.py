"""Reuse the existing native fixture for historical C2 subjects, never current CI."""

import json
from pathlib import Path

from saas.scripts.legacy_domain_native import native_digest

ROOT = Path(__file__).resolve().parents[2]


def frozen_entries():
    original = json.loads(
        (
            ROOT / "tests/saas/resources/legacy_compatibility_fixed_runner_bootstrap_native.json"
        ).read_text()
    )[0]
    names = (
        "legacy-security-build-profiles.json",
        "legacy-security-ci-profiles.json",
        "legacy-security-original-inputs.json",
        "legacy-security-pg-profiles.json",
        "legacy-security-transfer-profiles.json",
        "legacy-source-qualification-profiles.json",
    )
    rows = {
        name: json.loads((ROOT / "saas/supply_chain" / name).read_text())[
            "inputs" if name == "legacy-security-original-inputs.json" else "profiles"
        ]["Compatibility018"]
        for name in names
    }
    rows[names[0]], rows[names[1]] = original["profile"], original["identity"]
    pg = rows["legacy-security-pg-profiles.json"]
    pg.update({key: original["profile"][key] for key in ("product_revision", "product_tree")})
    pg["trusted_inputs"]["uv.lock"] = (
        "8c4aef4e0da8a83415effabc4f9b4e946756145729a88ee43c466f994a35730f"
    )
    normalized = json.loads(json.dumps(rows))
    normalized[names[-1]].pop("bootstrap_positive_origin", None)
    assert (
        native_digest(normalized)
        == "8f960409bd18a2c26b635f081f6cf371b678d9c2ed9496cab0ae34e22be2a719"
    )
    return rows


def frozen_profile():
    return frozen_entries()["legacy-security-build-profiles.json"]
