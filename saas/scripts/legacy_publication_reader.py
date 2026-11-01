"""Read a registered historical publication without assuming its GHA environment.

Only current verifier code runs. Git views, native downloads, cryptographic
verification and registry reads are local/read-only; product code never runs.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import yaml

from saas.scripts import legacy_initial_publisher as publisher
from saas.scripts.legacy_control_results import _collect_pg_receipts, verify_control_run
from saas.scripts.legacy_domain_eligibility import require_publication_source_origin
from saas.scripts.legacy_native_evidence import preserve_native_evidence
from saas.scripts.legacy_source_qualification import _qualify_source_ci
from saas.scripts.oci_promotion import read_json, require

TRUSTED_STORES = (
    "legacy-security-build-profiles.json",
    "legacy-security-ci-profiles.json",
    "legacy-security-original-inputs.json",
    "legacy-security-pg-profiles.json",
    "legacy-security-transfer-profiles.json",
    "legacy-source-qualification-profiles.json",
)


def trusted_entries(control: Path, component: str) -> dict[str, Any]:
    from saas.scripts.check_image_supply_chain import load_release_evidence

    entries = {}
    for name in TRUSTED_STORES:
        store = load_release_evidence(control, "saas/supply_chain/" + name)
        key = "inputs" if name == "legacy-security-original-inputs.json" else "profiles"
        require(
            isinstance(store, dict)
            and set(store) == {"schema_version", key}
            and type(store["schema_version"]) is int
            and store["schema_version"] == 1
            and isinstance(store[key], dict)
            and isinstance(store[key].get(component), dict),
            "current exact legacy registration is missing: " + name,
        )
        store = cast(dict[str, Any], store)
        entries[name] = store[key][component]
    return entries


@contextmanager
def object_view(repository: Path, revision: str, destination: Path):
    """Create an owned index/worktree from existing objects, without hooks or fetch."""
    require(
        bool(isinstance(revision, str) and re.fullmatch(r"[0-9a-f]{40}", revision)),
        "historical object revision is not immutable",
    )
    environment = {
        name: value for name, value in os.environ.items() if not name.startswith("GIT_")
    }
    environment.update(
        {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_ATTR_NOSYSTEM": "1"}
    )
    objects = subprocess.check_output(
        ["git", "rev-parse", "--path-format=absolute", "--git-path", "objects"],
        cwd=repository,
        text=True,
        env=environment,
    ).strip()
    destination.mkdir(parents=True, exist_ok=False)
    subprocess.run(["git", "init", "--quiet", str(destination)], check=True, env=environment)
    (destination / ".git/objects/info/alternates").write_text(objects + "\n")
    subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "checkout", "--quiet", "--detach", revision],
        cwd=destination,
        check=True,
        capture_output=True,
        env=environment,
    )
    yield destination


@dataclass(frozen=True)
class HistoricalProducer:
    control_revision: str
    control_tree: str
    workflow_sha256: str
    run_id: int
    attempt: int
    actor: str

    @property
    def context(self) -> dict[str, Any]:
        return {
            key: getattr(self, key) for key in ("control_revision", "run_id", "attempt", "actor")
        }

    def verify(self, control: Path, revision: str) -> None:
        require(revision == self.control_revision, "historical control revision differs")

        def git(*arguments: str) -> str:
            return subprocess.check_output(["git", *arguments], cwd=control, text=True).strip()

        require(
            git("rev-parse", "HEAD") == revision
            and git("rev-parse", "HEAD^{tree}") == self.control_tree
            and not git("status", "--porcelain=v1", "--untracked-files=all")
            and publisher.file_sha256(control / publisher.WORKFLOW) == self.workflow_sha256,
            "historical control view differs from reviewed objects",
        )
        try:
            workflow = yaml.load(
                (control / publisher.WORKFLOW).read_text(), Loader=yaml.BaseLoader
            )
        except yaml.YAMLError as error:
            raise ValueError("historical publication workflow is not valid YAML") from error
        jobs = workflow["jobs"]
        require(
            {name for name, job in jobs.items() if "environment" in job}
            == {"publish-exact-oci", "attest-exact-inputs"}
            and all(
                jobs[name]["environment"] == "production-image"
                for name in ("publish-exact-oci", "attest-exact-inputs")
            )
            and jobs["publish-exact-oci"]["permissions"].get("packages") == "write"
            and "id-token" not in jobs["publish-exact-oci"]["permissions"]
            and jobs["attest-exact-inputs"]["permissions"].get("id-token") == "write"
            and jobs["attest-exact-inputs"]["permissions"].get("attestations") == "write",
            "historical publisher did not use the original protected identities",
        )
        sequence = len(list(control.parent.glob(control.name + "-native-*")))
        with preserve_native_evidence(control.parent / f"{control.name}-native-{sequence}"):
            run = publisher.verify_native_control(control, self.context)
            attempt = publisher.api(
                f"{publisher.PREFIX}/actions/runs/{self.run_id}/attempts/{self.attempt}"
            )
            for observed in (run, attempt):
                verify_control_run(
                    observed,
                    revision=revision,
                    run_id=self.run_id,
                    attempt=self.attempt,
                    actor=self.actor,
                )
                require(
                    observed.get("status") == "completed"
                    and observed.get("conclusion") == "success",
                    "historical producer must be completed and successful",
                )
            commit = publisher.api(f"{publisher.PREFIX}/git/commits/{revision}")
            require(
                commit.get("sha") == revision
                and commit.get("tree", {}).get("sha") == self.control_tree,
                "native historical control tree differs",
            )


def qualify_historical_source(
    control: Path, product: Path, component: str, producer: HistoricalProducer, destination: Path
) -> dict[str, Any]:
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    # Bracket the shared parser with native producer validation; its recorder
    # remains independent from the historical context recorder.
    producer.verify(control, producer.control_revision)
    with preserve_native_evidence(
        destination / "native-api", evidence_root=destination
    ) as evidence:
        result = _qualify_source_ci(
            control,
            product,
            component,
            producer.control_revision,
            destination,
            evidence,
            context_verifier=lambda root, revision: require(
                root == control and revision == producer.control_revision,
                "historical source context differs",
            ),
        )
    producer.verify(control, producer.control_revision)
    return result


def collect_historical_inputs(
    control: Path,
    product: Path,
    registration: dict[str, Any],
    producer: HistoricalProducer,
    destination: Path,
) -> tuple[dict[str, Any], Path, Path]:
    destination.mkdir(parents=True, exist_ok=False)
    component = registration["profile"]["component"]
    profile = publisher.load_profile(control, component)
    require(
        profile == registration["profile"], "historical profile differs from current registration"
    )
    publisher.verify_source_delta(product, profile)
    source = qualify_historical_source(
        control, product, component, producer, destination / "source"
    )
    publisher.strict_qualification(source, profile, producer.control_revision)
    require_publication_source_origin(control, profile, source)
    producer.verify(control, producer.control_revision)
    pg = _collect_pg_receipts(
        control,
        product,
        component,
        producer.control_revision,
        run_id=producer.run_id,
        attempt=producer.attempt,
        actor=producer.actor,
        destination=destination / "pg",
        context_verifier=lambda root, revision: require(
            root == control and revision == producer.control_revision,
            "historical PG context differs",
        ),
    )
    require(pg.get("native_PG_receipts_pass") is True, "historical native PG did not pass")
    original = publisher.collect_original_input(control, profile, destination / "original")
    fresh, wheel = publisher.collect_fresh_wheel(
        control, product, profile, producer.context, destination / "fresh"
    )
    admission = {
        "kind": publisher.VARIANT,
        "control": {
            **producer.context,
            "workflow_path": publisher.WORKFLOW,
            "workflow_sha256": producer.workflow_sha256,
        },
        "profile": profile,
        "transfer_profile": publisher.load_transfer_profile(control, component),
        "original_pr_oci": original,
        "fresh_control_wheel": fresh,
        "source_qualification": {"sha256": publisher.digest(source), "result": source},
        "native_product_pg": {"sha256": publisher.digest(pg), "result": pg},
        "rebuild_in_publisher": False,
    }
    publisher.validate_input_identities(admission)
    require(
        admission == registration["admission"], "historical admission differs from registration"
    )
    return admission, destination / "original/download/original-oci.zip", wheel


def read_registered_publication(
    repository: Path, registration: dict[str, Any], destination: Path
) -> dict[str, Any]:
    """Re-read every producer input, stage ZIP, OCI and real native signature."""
    producer = HistoricalProducer(**registration["producer"])
    with (
        object_view(repository, producer.control_revision, destination / "control") as control,
        object_view(
            repository, registration["profile"]["product_revision"], destination / "product"
        ) as product,
    ):
        component = registration["profile"]["component"]
        require(
            trusted_entries(repository, component) == trusted_entries(control, component),
            "historical registrations differ from current trusted control",
        )
        producer.verify(control, producer.control_revision)
        admission, archive, wheel = collect_historical_inputs(
            control, product, registration, producer, destination / "inputs"
        )
        profile = admission["profile"]
        exports = {}
        coordinates = {}
        for role, job in (
            ("preparation", "prepare-publication"),
            ("publication", "publish-exact-oci"),
            ("runtime", "verify-published-runtime"),
            ("signatures", "attest-exact-inputs"),
        ):
            root, coordinate = publisher.collect_job_export(
                control,
                product,
                profile,
                producer.context,
                job_name=job,
                role=role,
                destination=destination / role,
            )
            require(
                coordinate == registration["stage_artifacts"][role],
                "historical stage ZIP differs from registration",
            )
            exports[role] = root
            coordinates[role] = coordinate
            if role != "signatures":
                publisher.compare_admission(root, admission)
        oci = destination / "oci"
        publisher.unpack_original(archive, admission["original_pr_oci"], oci)
        manifest = publisher.admitted_manifest(
            oci, admission, product, exports["preparation"] / "scans"
        )
        publication = read_json(exports["publication"] / "publication.json")
        expected = {
            "kind": "legacy_exact_oci_publication/v1",
            "admission_sha256": publisher.digest(admission),
            "images": publisher.image_references(admission, manifest),
            "candidate_seal_sha256": admission["original_pr_oci"]["seal_sha256"],
            "registry_readback_pass": True,
            "rebuilt": False,
        }
        require(publication == expected, "historical publication differs from exact OCI")
        runtime = publisher.verify_runtime_report(
            exports["runtime"], admission, publication, manifest
        )
        predicate = publisher.typed_provenance(
            admission,
            publication,
            runtime,
            preparation_artifact=coordinates["preparation"],
            publication_artifact=coordinates["publication"],
            runtime_artifact=coordinates["runtime"],
        )
        require(
            publisher.digest(predicate) == registration["predicate_sha256"],
            "historical typed predicate differs from registration",
        )
        publisher.read_registry(destination / "registry", manifest, publication["images"])
        # Build the exact expected verification inputs from freshly re-read facts.
        output = destination / "verified"
        output.mkdir()
        for name, value in (
            ("provenance", predicate),
            ("publication", publication),
            ("runtime", runtime),
        ):
            publisher.write_json(output / (name + ".json"), value)
        publisher.shutil.copytree(exports["runtime"] / "sbom", output / "sbom")
        signature = publisher.verify_signatures(output, admission, wheel)
        require(
            signature == read_json(exports["signatures"] / "native-signatures.json"),
            "historical signature receipt differs from actual native cryptographic readback",
        )
        producer.verify(control, producer.control_revision)
        publisher.verify_source_delta(product, profile)
        baseline = json.loads(
            subprocess.check_output(
                [
                    "git",
                    "cat-file",
                    "blob",
                    profile["product_revision"] + ":saas/production/baseline.json",
                ],
                cwd=product,
            )
        )
        require(
            isinstance(baseline.get("revision_contract"), dict),
            "verified product has no exact revision contract",
        )
        return {
            "images": publication["images"],
            "wheel_sha256": admission["fresh_control_wheel"]["wheel_sha256"],
            "product_revision": profile["product_revision"],
            "product_tree": profile["product_tree"],
            "revision_contract": baseline["revision_contract"],
            "manifest": manifest,
            "production_admission": False,
        }
