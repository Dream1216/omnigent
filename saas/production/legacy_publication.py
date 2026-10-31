"""Bind a registered typed legacy publication to the existing N-1 drill gates."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from saas.scripts import legacy_initial_publisher as publisher
from saas.scripts.legacy_publication_reader import (
    HistoricalProducer,
    trusted_entries,
)
from saas.scripts.oci_promotion import require
from saas.scripts.protected_legacy_initial_build import validate_profile

VARIANT = "production_release_with_legacy_fallback/v2"
REGISTRY = "saas/supply_chain/legacy-production-publications.json"


def registered_publication(repo: Path, identifier: Any) -> dict[str, Any]:
    from saas.scripts.check_image_supply_chain import load_release_evidence

    require(
        bool(
            isinstance(identifier, str)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", identifier)
        ),
        "legacy publication identifier is invalid",
    )
    registry = load_release_evidence(repo, REGISTRY)
    require(
        registry is not None
        and set(registry) == {"schema_version", "publications"}
        and type(registry["schema_version"]) is int
        and registry["schema_version"] == 1
        and isinstance(registry["publications"], dict),
        "legacy publication registry differs",
    )
    registry = cast(dict[str, Any], registry)
    row = registry["publications"].get(identifier)
    require(isinstance(row, dict), "legacy publication is not registered")
    require(
        set(row)
        == {
            "input_variant",
            "profile",
            "producer",
            "admission",
            "stage_artifacts",
            "predicate_sha256",
            "deployment_roles",
        }
        and row["input_variant"] == publisher.VARIANT,
        "unknown registered legacy publication variant",
    )
    profile = row["profile"]
    require(isinstance(profile, dict), "registered legacy profile is invalid")
    validate_profile(profile, profile.get("component"))
    entries = trusted_entries(repo, profile["component"])
    require(
        entries["legacy-security-build-profiles.json"] == profile,
        "current legacy source profile differs from publication registration",
    )
    producer = row["producer"]
    require(
        isinstance(producer, dict)
        and set(producer)
        == {"control_revision", "control_tree", "workflow_sha256", "run_id", "attempt", "actor"},
        "registered historical producer fields differ",
    )
    for field in ("control_revision", "control_tree"):
        require(
            bool(
                isinstance(producer[field], str) and re.fullmatch(r"[0-9a-f]{40}", producer[field])
            ),
            "registered historical control object differs",
        )
    for field in ("run_id", "attempt"):
        require(
            type(producer[field]) is int and producer[field] > 0,
            "registered historical run coordinate differs",
        )
    require(
        bool(
            isinstance(producer["actor"], str)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*(?:\[bot\])?", producer["actor"])
        ),
        "registered historical actor differs",
    )
    for value in (producer["workflow_sha256"], row["predicate_sha256"]):
        require(
            bool(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)),
            "registered historical digest differs",
        )
    admission = row["admission"]
    context = HistoricalProducer(**producer).context
    require(
        isinstance(admission, dict)
        and set(admission)
        == {
            "kind",
            "profile",
            "control",
            "transfer_profile",
            "original_pr_oci",
            "fresh_control_wheel",
            "source_qualification",
            "native_product_pg",
            "rebuild_in_publisher",
        }
        and admission["kind"] == publisher.VARIANT
        and admission["profile"] == profile
        and admission["control"]
        == {
            **context,
            "workflow_path": publisher.WORKFLOW,
            "workflow_sha256": producer["workflow_sha256"],
        }
        and admission["rebuild_in_publisher"] is False,
        "registered legacy admission differs",
    )
    publisher.validate_input_identities(admission)
    publisher.strict_qualification(
        admission["source_qualification"]["result"], profile, producer["control_revision"]
    )
    require(
        admission["source_qualification"]["result"].get("complete_domain_discovery") is True,
        "registered legacy publication lacks complete domain discovery",
    )
    require(
        isinstance(row["stage_artifacts"], dict)
        and set(row["stage_artifacts"]) == {"preparation", "publication", "runtime", "signatures"},
        "registered legacy stage set differs",
    )
    artifact_ids = []
    for role, coordinate in row["stage_artifacts"].items():
        require(
            bool(
                isinstance(coordinate, dict)
                and set(coordinate)
                == {"job_id", "artifact_id", "artifact_name", "zip_size", "zip_sha256"}
                and all(
                    type(coordinate[field]) is int and coordinate[field] > 0
                    for field in ("job_id", "artifact_id", "zip_size")
                )
                and coordinate["artifact_name"] == publisher.artifact_name(role, profile, context)
                and isinstance(coordinate["zip_sha256"], str)
                and re.fullmatch(r"[0-9a-f]{64}", coordinate["zip_sha256"])
            ),
            "registered legacy stage coordinate differs",
        )
        artifact_ids.append(coordinate["artifact_id"])
    artifact_ids.extend(
        admission[key]["artifact_id"] for key in ("original_pr_oci", "fresh_control_wheel")
    )
    require(
        len(set(artifact_ids)) == len(artifact_ids),
        "registered legacy artifact roles are conflated",
    )
    roles = row["deployment_roles"]
    require(
        bool(
            isinstance(roles, dict)
            and roles
            and all(role in publisher.IMAGES for role in roles.values())
        ),
        "registered legacy deployment roles differ",
    )
    return row


def validate_legacy_fallback(
    repo: Path,
    envelope: dict[str, Any],
    *,
    now: datetime,
    expected_product_revision: str | None,
) -> dict[str, Any]:
    """A single publication cannot qualify the three-service physical fallback."""
    require(
        envelope.get("kind") != "production_release_with_legacy_fallback/v1",
        "single-publication fallback cannot qualify the complete Core/Gateway/Model stack",
    )
    from saas.production.legacy_stack import validate_stack_fallback

    return validate_stack_fallback(
        repo,
        envelope,
        now=now,
        expected_product_revision=expected_product_revision,
    )
