"""Offline refusal tests; generated fixtures do not claim real OCI qualification."""

import hashlib
import importlib.util
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
import zipfile
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "compat018_oci_recovery.py"
if not SCRIPT.is_file():
    SCRIPT = HERE.parents[1] / "saas/scripts/compat018_oci_recovery.py"
spec = importlib.util.spec_from_file_location("c2_recovery_draft", SCRIPT)
assert spec is not None and spec.loader is not None
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def digest(body):
    return hashlib.sha256(body).hexdigest()


def encode(value):
    return (json.dumps(value, indent=2) + "\n").encode()


def registered_failed_parent_records():
    value = m.REGISTERED_FAILED_PAIR
    run = {
        "id": value["run_id"],
        "head_sha": value["controller_revision"],
        "run_attempt": 1,
        "head_branch": "main",
        "path": m.WORKFLOW,
        "event": "workflow_dispatch",
        "status": "completed",
        "conclusion": "failure",
        "repository": {"full_name": m.REPOSITORY},
    }
    job = {
        "id": value["builder_job_id"],
        "run_id": value["run_id"],
        "run_attempt": 1,
        "head_sha": value["controller_revision"],
        "name": "build-compat018-product",
        "status": "completed",
        "conclusion": "failure",
        "labels": ["ubuntu-24.04"],
        "runner_group_name": "GitHub Actions",
        "steps": [
            {"name": name, "conclusion": "success"}
            for name in (
                "Recover Server using its existing first-attempt build cache",
                "Recover Host using its existing first-attempt build cache",
                "Audit actual fixed C2 source, UI, and historical Host",
                "Independently build only C2 Server without cache",
                "Independently build C2 Host without cache",
                "Stage actual independent C2 Host and reclaim only its builder cache",
                "Preserve actual OCI before any fresh vulnerability scan",
            )
        ]
        + [{"name": "Confirm exact C2 comparison profile", "conclusion": "failure"}],
    }
    metadata = {
        "id": value["artifact_id"],
        "name": f"compat018-raw-{value['product_revision']}-{value['run_id']}",
        "size_in_bytes": value["zip_size"],
        "digest": "sha256:" + value["zip_sha256"],
        "expired": False,
        "workflow_run": {"id": value["run_id"], "head_sha": value["controller_revision"]},
    }
    return run, job, metadata


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "raw"
        self.root.mkdir()
        self.report = {
            "candidate_evidence_version": 3,
            "status": "pass",
            "violations": [],
            "product_revision": m.PRODUCT,
            "upstream_revision": m.UPSTREAM,
            "source_date_epoch": m.EPOCH,
            "adapter_contract_version": "0.2.0",
            "label_profile": "executable",
            "images": {},
        }
        self.facts = {}
        self.entries = {}
        reports = {}
        for role in ("server", "host"):
            facts = {
                "platforms": {},
                "attestations": {"fixture": role},
                "attestation_descriptor_count": 2,
            }
            for arch in ("amd64", "arm64"):
                fact = {
                    "labels": m.LABELS.copy(),
                    "manifest_digest": f"sha256:{role}-{arch}",
                    "config_digest": f"sha256:config-{role}-{arch}",
                }
                facts["platforms"]["linux/" + arch] = fact
                raw = {
                    "matches": [{"vulnerability": {"severity": "High", "id": "CVE-2026-119586"}}],
                    "source": {
                        "target": {
                            "manifestDigest": fact["manifest_digest"],
                            "imageID": fact["config_digest"],
                        }
                    },
                    "descriptor": {"name": "grype", "version": "0.120.1"},
                }
                name = f"grype/{role}-{arch}-grype.json"
                self.entries[name] = encode(raw)
                reports[name] = digest(self.entries[name])
            self.facts[role] = facts
            self.report["images"]["omnigent-saas-" + role] = {
                "matching_platform_manifest_and_config": True,
                "history_created_by_equal": True,
                "first": deepcopy(facts),
                "second": deepcopy(facts),
            }
        self.entries["grype/candidate-scan-summary.json"] = encode({"historical_fixture": True})
        self.seal = {
            "product_revision": m.PRODUCT,
            "source_date_epoch": m.EPOCH,
            "labels": m.LABELS.copy(),
            "images": {role: {"facts": facts} for role, facts in self.facts.items()},
            "scans": {
                "reports": reports,
                "summary_sha256": digest(self.entries["grype/candidate-scan-summary.json"]),
            },
        }
        self.archive = self.root / "original-report.zip"
        self.write_fixture()
        self.controller = "a" * 40
        self.zipsha = "b" * 64
        self.run = {
            "id": 1,
            "run_attempt": 1,
            "head_sha": self.controller,
            "head_branch": "main",
            "event": "workflow_dispatch",
            "path": m.WORKFLOW,
            "repository": {"full_name": m.REPOSITORY},
        }
        self.job = {
            "name": "build-compat018-product",
            "run_id": 1,
            "run_attempt": 1,
            "status": "completed",
            "conclusion": "success",
            "runner_group_name": "GitHub Actions",
            "labels": ["ubuntu-24.04"],
        }
        self.meta = {
            "id": 2,
            "name": f"compat018-raw-{m.PRODUCT}-1",
            "digest": "sha256:" + self.zipsha,
            "expired": False,
            "workflow_run": {"id": 1, "head_sha": self.controller},
            "size_in_bytes": 100,
        }

    def write_fixture(self):
        self.entries["saas-image-candidate.json"] = encode(self.report)
        self.seal["comparison_sha256"] = digest(self.entries["saas-image-candidate.json"])
        self.entries["oci-promotion-manifest.json"] = encode(self.seal)
        with zipfile.ZipFile(self.archive, "w") as bundle:
            for name, body in self.entries.items():
                bundle.writestr(name, body)
        self.pins = {
            "REPORT_SIZE": self.archive.stat().st_size,
            "REPORT_SHA": m.sha256(self.archive),
            "OLD_SEAL_SHA": digest(self.entries["oci-promotion-manifest.json"]),
        }

    def original(self):
        with patch.multiple(m, **self.pins):
            return m.original_evidence(self.archive)

    def producer(self):
        m.verify_raw_producer(self.run, [self.job], self.meta, 1, 2, self.zipsha, self.controller)

    def verify(self, changed_role=None):
        for role in ("server", "host"):
            (self.root / f"{role}-1.tar").write_bytes(role.encode())

        def inspect(path, **kwargs):
            role = path.name.split("-")[0]
            facts = deepcopy(self.facts[role])
            if role == changed_role:
                facts["platforms"]["linux/amd64"]["config_digest"] = "sha256:drift"
            return facts

        fake = SimpleNamespace(inspect_oci_archive=inspect)
        with (
            patch.multiple(m, **self.pins),
            patch.dict(sys.modules, {"saas.scripts.compare_oci_rebuilds": fake}),
        ):
            return m.verify_raw(self.root)

    def test_historical_evidence_does_not_claim_freshness(self):
        report, _, _ = self.original()
        self.assertEqual(report["product_revision"], m.PRODUCT)

    def test_corrupt_zip_is_refused(self):
        with self.archive.open("ab") as stream:
            stream.write(b"changed")
        with self.assertRaisesRegex(ValueError, "bytes differ"):
            self.original()

    def test_wrong_product_upstream_epoch_are_refused(self):
        for key, value in (
            ("product_revision", "c" * 40),
            ("upstream_revision", "d" * 40),
            ("source_date_epoch", m.EPOCH + 1),
        ):
            with self.subTest(key=key):
                original = self.report[key]
                self.report[key] = value
                self.write_fixture()
                with self.assertRaises(ValueError):
                    self.original()
                self.report[key] = original

    def test_wrong_old_seal_hash_is_refused(self):
        self.pins["OLD_SEAL_SHA"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "seal/comparison"):
            self.original()

    def test_original_repeat_drift_is_refused(self):
        self.report["images"]["omnigent-saas-host"]["second"]["attestations"] = {}
        self.write_fixture()
        with self.assertRaisesRegex(ValueError, "repeated facts"):
            self.original()

    def test_raw_flags_and_exact_comparison_bytes(self):
        receipt = self.verify()
        self.assertTrue(receipt["rebuilt"])
        self.assertTrue(receipt["raw_checkpoint_only"])
        for flag in (
            "fresh_scans_passed",
            "source_and_pg_same_final_run_qualified",
            "signed_or_production_admitted",
        ):
            self.assertIs(receipt[flag], False)
        self.assertEqual(
            (self.root / "saas-image-candidate.json").read_bytes(),
            self.entries["saas-image-candidate.json"],
        )
        self.assertFalse((self.root / "grype").exists())

    def test_rebuilt_platform_drift_refused_for_both_roles(self):
        for role in ("server", "host"):
            with (
                self.subTest(role=role),
                self.assertRaisesRegex(ValueError, "recovered OCI differs"),
            ):
                self.verify(changed_role=role)

    def test_stale_report_directory_refused(self):
        (self.root / "grype").mkdir()
        with self.assertRaisesRegex(ValueError, "stale admission"):
            self.verify()

    def test_actual_controller_is_separate_from_fixed_product(self):
        self.producer()
        self.assertNotEqual(self.controller, m.PRODUCT)
        registered_product = "8" * 40
        self.meta["name"] = f"compat018-raw-{registered_product}-1"
        with self.assertRaises(ValueError):
            self.producer()
        m.verify_raw_producer(
            self.run,
            [self.job],
            self.meta,
            1,
            2,
            self.zipsha,
            self.controller,
            product_revision=registered_product,
        )
        self.meta["name"] = f"compat018-raw-{m.PRODUCT}-1"
        with self.assertRaises(ValueError):
            m.verify_raw_producer(
                self.run,
                [self.job],
                self.meta,
                1,
                2,
                self.zipsha,
                self.controller,
                product_revision=registered_product,
            )

    def test_producer_identity_mismatches_refused(self):
        for key, value in (
            ("head_sha", m.PRODUCT),
            ("event", "pull_request"),
            ("run_attempt", 2),
            ("path", ".github/workflows/ci.yml"),
            ("repository", {"full_name": "other/omnigent"}),
        ):
            with self.subTest(key=key):
                before = self.run[key]
                self.run[key] = value
                with self.assertRaises(ValueError):
                    self.producer()
                self.run[key] = before

    def test_unsuccessful_or_wrong_builder_refused(self):
        for key, value in (
            ("conclusion", "failure"),
            ("labels", ["self-hosted"]),
            ("runner_group_name", "custom"),
        ):
            with self.subTest(key=key):
                before = self.job[key]
                self.job[key] = value
                with self.assertRaises(ValueError):
                    self.producer()
                self.job[key] = before

    def test_expired_wrong_or_unbounded_artifact_refused(self):
        for key, value in (
            ("expired", True),
            ("digest", "sha256:" + "0" * 64),
            ("name", "saas-oci-promotion-" + m.PRODUCT),
            ("size_in_bytes", 0),
            ("size_in_bytes", 17 * 1024**3),
            ("size_in_bytes", True),
        ):
            with self.subTest(key=key, value=value):
                before = self.meta[key]
                self.meta[key] = value
                with self.assertRaises(ValueError):
                    self.producer()
                self.meta[key] = before

    def test_seal_uses_c2_labels_not_controller_baseline(self):
        received = {}

        def sealer(root, **kwargs):
            received.update(kwargs)
            return {"actual_mock_seal": True}

        fake = SimpleNamespace(seal_candidate=sealer)
        with (
            patch.multiple(m, **self.pins),
            patch.dict(sys.modules, {"saas.scripts.oci_promotion": fake}),
        ):
            m.seal(self.root)
        self.assertEqual(received["labels"], m.LABELS)
        self.assertEqual(received["source_date_epoch"], m.EPOCH)

    def test_retained_failed_first_pair_has_a_single_exact_origin(self):
        pinned = m.RETAINED_FIRST
        log = b"ValueError: new C2 Host does not equal its actual historical independent pair\n"
        run = {
            **self.run,
            "id": pinned["run_id"],
            "head_sha": pinned["controller_revision"],
            "status": "completed",
            "conclusion": "failure",
        }
        names = [
            "Verify product checkout and install its existing locked helpers",
            "Build the original locked React18 login export before the original OCI action",
            "Recover Server using its existing first-attempt build cache",
            "Recover Host using its existing first-attempt build cache",
            "Stage actual OCI before cleanup or inspection can fail",
            "Audit actual fixed C2 source, UI, and historical Host",
            "Preserve actual OCI before any fresh vulnerability scan",
        ]
        job = {
            **self.job,
            "id": pinned["builder_job_id"],
            "run_id": pinned["run_id"],
            "head_sha": pinned["controller_revision"],
            "conclusion": "failure",
            "steps": [
                {
                    "name": name,
                    "conclusion": "failure" if i == 5 else "success",
                    "started_at": "2026-11-08T17:20:00Z",
                    "completed_at": "2026-11-08T17:25:00Z",
                }
                for i, name in enumerate(names)
            ],
        }
        metadata = {
            **self.meta,
            "id": pinned["artifact_id"],
            "name": f"compat018-raw-{m.PRODUCT}-{pinned['run_id']}",
            "size_in_bytes": pinned["zip_size"],
            "digest": "sha256:" + pinned["zip_sha256"],
            "workflow_run": {"id": pinned["run_id"], "head_sha": pinned["controller_revision"]},
            "created_at": "2026-11-08T17:22:00Z",
        }
        with patch.dict(m.RETAINED_FIRST, original_log_sha256=digest(log)):
            m.verify_retained_first_native(run, job, metadata, log)
            cases = [
                (run, "id", 1),
                (run, "conclusion", "success"),
                (run, "head_sha", m.PRODUCT),
                (run, "run_attempt", 2),
                (job, "id", 1),
                (job, "conclusion", "success"),
                (job, "labels", ["self-hosted"]),
                (job["steps"][2], "conclusion", "skipped"),
                (job["steps"][3], "conclusion", "failure"),
                (job["steps"][5], "conclusion", "success"),
                (metadata, "id", 2),
                (metadata, "expired", True),
                (metadata, "digest", "sha256:" + "0" * 64),
                (metadata, "size_in_bytes", pinned["zip_size"] - 1),
                (metadata, "created_at", "2026-11-08T17:19:00Z"),
            ]
            for target, key, value in cases:
                with self.subTest(key=key, value=value):
                    previous = target[key]
                    target[key] = value
                    with self.assertRaises(ValueError):
                        m.verify_retained_first_native(run, job, metadata, log)
                    target[key] = previous
            with self.assertRaises(ValueError):
                m.verify_retained_first_native(run, job, metadata, log + b"changed")
        # The ordinary successful raw producer guard still rejects this failed job.
        with self.assertRaises(ValueError):
            m.verify_raw_producer(
                run,
                [job],
                metadata,
                pinned["run_id"],
                pinned["artifact_id"],
                pinned["zip_sha256"],
                pinned["controller_revision"],
            )

    def test_workflow_preserves_before_inspection_and_scanning(self):
        workflow = HERE / "saas-compat018-oci-recovery.yml"
        if not workflow.is_file():
            workflow = HERE.parents[1] / ".github/workflows/saas-compat018-oci-recovery.yml"
        s = workflow.read_text()
        self.assertLess(s.index('mv "$RUNNER_TEMP/server-1.tar"'), s.index("docker buildx prune"))
        self.assertLess(
            s.index("retention-days: 30"), s.index("saas.scripts.scan_oci_candidates --image")
        )
        self.assertIn(
            "if: always() && ((steps.server.outcome == 'success' "
            "&& steps.host.outcome == 'success') || steps.retained.outcome == 'success' "
            "|| steps.registered-retained.outcome == 'success')",
            s,
        )
        self.assertIn('--controller "$RAW_CONTROLLER"', s)
        self.assertNotIn("d404ce0e80e5f5b10b9dd8dec8673fb02382f3ec", s)
        self.assertNotIn("saas.scripts.oci_promotion seal", s)
        self.assertIn("Source must integrate its own Source + PG16/18 jobs in the SAME", s)
        preservation = s[s.index("      - name: Preserve completed OCI bytes from a failed") :]
        preservation = preservation[: preservation.index("\n  scan-and-seal-same-oci:")]
        self.assertIn(
            "if: failure() && !cancelled() && (inputs.phase == 'build-reviewed' "
            "|| inputs.phase == 'repair-reviewed-server')",
            preservation,
        )
        self.assertIn("name: compat018-unqualified-partial-", preservation)
        self.assertIn("${{ runner.temp }}/server-2.tar", preservation)
        self.assertIn("${{ runner.temp }}/host-2.tar", preservation)
        self.assertIn("${{ runner.temp }}/compat018-raw/*.tar", preservation)
        self.assertIn("compression-level: 0", preservation)
        self.assertIn("if-no-files-found: warn", preservation)
        self.assertIn("retention-days: 1", preservation)
        self.assertNotIn("id:", preservation)

    def test_checkout_verification_imports_protected_controller_from_product_cwd(self):
        repo = SCRIPT.parents[2]
        workflow = repo / ".github/workflows/saas-compat018-oci-recovery.yml"
        command = next(
            line.strip()
            for line in workflow.read_text().splitlines()
            if 'PYTHONPATH="$RUNNER_TEMP/compat018-control" python ' in line
        )
        arguments = shlex.split(command.split(" python ", 1)[1].split(" <<", 1)[0])
        control = Path(self.tmp.name) / "control"
        control.mkdir()
        (control / "saas").symlink_to(repo / "saas", target_is_directory=True)
        product = Path(self.tmp.name) / "product"
        scripts = product / "saas/scripts"
        scripts.mkdir(parents=True)
        (product / "saas/__init__.py").touch()
        (scripts / "__init__.py").touch()
        (scripts / "protected_legacy_initial_build.py").write_text(
            'raise RuntimeError("product controller must not execute")\n'
        )
        body = (
            "from pathlib import Path\n"
            "from saas.scripts import protected_legacy_initial_build as controller\n"
            f"expected = Path({str(repo / 'saas/scripts/protected_legacy_initial_build.py')!r})\n"
            "assert Path(controller.__file__).resolve() == expected.resolve()\n"
            f"controller.load_profile(Path({str(control)!r}), 'Compatibility018')\n"
        )
        result = subprocess.run(
            [sys.executable, *arguments],
            input=body,
            cwd=product,
            env={**os.environ, "PYTHONPATH": str(control)},
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_registered_raw_binds_own_profile_pair_and_rejects_drift(self):
        from saas.scripts import compare_oci_rebuilds

        profile = {
            "product_revision": "8" * 40,
            "product_tree": "9" * 40,
            "source_date_epoch": 123,
        }
        pairs = deepcopy(self.report["images"])
        first = {**profile, "historical_4e_byte_identity_claimed": False, "images": {}}
        for role in ("server", "host"):
            for attempt in (1, 2):
                (self.root / f"{role}-{attempt}.tar").write_bytes(role.encode())
            pair = pairs["omnigent-saas-" + role]
            for side in ("first", "second"):
                for actual in pair[side]["platforms"].values():
                    actual["labels"]["org.opencontainers.image.revision"] = "8" * 40
            first["images"][role] = {
                "facts": deepcopy(pair["first"]),
                "archive_sha256": digest(role.encode()),
            }
        (self.root / "registered-source-profile.json").write_bytes(encode(profile))
        original = self.root / "reviewed-subject-image-facts.json"
        original.write_bytes(encode(first))
        with (
            patch.object(m, "registered_profile", return_value=profile),
            patch.object(
                compare_oci_rebuilds,
                "compare_archives",
                side_effect=lambda a, _b, **_kw: pairs["omnigent-saas-" + a.name.split("-")[0]],
            ),
        ):
            result = m.registered_raw(self.root, write=True)
            self.assertEqual(result["product_revision"], "8" * 40)
            self.assertFalse(result["production_ready"])
            self.assertFalse(result["historical_4e_byte_identity_claimed"])
            self.assertEqual(m.registered_raw(self.root), result)
            actual_second = pairs["omnigent-saas-host"]["second"]
            for field, replacement in (
                ("attestation_descriptor_count", 1),
                ("platforms", {"linux/amd64": actual_second["platforms"]["linux/amd64"]}),
            ):
                with self.subTest(second_pair_field=field):
                    saved = actual_second[field]
                    actual_second[field] = replacement
                    with self.assertRaisesRegex(ValueError, "provenance/SBOM"):
                        m.registered_raw(self.root)
                    actual_second[field] = saved
            for fault in ("profile", "first-facts", "archive", "pair", "report"):
                with self.subTest(fault=fault):
                    path = None
                    if fault == "profile":
                        path = self.root / "registered-source-profile.json"
                    elif fault == "first-facts":
                        path = original
                    elif fault == "archive":
                        path = self.root / "server-1.tar"
                    elif fault == "report":
                        path = self.root / "saas-image-candidate.json"
                    if path is not None:
                        saved = path.read_bytes()
                        if fault == "archive":
                            path.write_bytes(b"different archive")
                        else:
                            changed = json.loads(saved)
                            changed["product_revision"] = m.PRODUCT
                            path.write_bytes(encode(changed))
                    else:
                        pairs["omnigent-saas-server"]["matching_platform_manifest_and_config"] = (
                            False
                        )
                    with self.assertRaises(ValueError):
                        m.registered_raw(self.root)
                    if path is not None:
                        path.write_bytes(saved)
                    else:
                        pairs["omnigent-saas-server"]["matching_platform_manifest_and_config"] = (
                            True
                        )

    def test_registered_repair_accepts_only_exact_four_build_failed_comparison_parent(self):
        run, job, metadata = registered_failed_parent_records()
        m.verify_registered_failed_pair(run, job, metadata)
        for section, field, replacement in (
            (run, "id", 1),
            (run, "head_sha", "f" * 40),
            (run, "run_attempt", 2),
            (run, "head_branch", "feature"),
            (run, "path", "other.yml"),
            (run, "conclusion", "success"),
            (run, "event", "push"),
            (job, "id", 1),
            (job, "run_id", 1),
            (job, "run_attempt", 2),
            (job, "head_sha", "f" * 40),
            (job, "conclusion", "success"),
            (job, "runner_group_name", "private"),
            (job, "labels", ["self-hosted"]),
            (metadata, "id", 1),
            (metadata, "size_in_bytes", 1),
            (metadata, "digest", "sha256:" + "f" * 64),
            (metadata, "expired", True),
        ):
            with self.subTest(field=field, replacement=replacement):
                saved = section[field]
                section[field] = replacement
                with self.assertRaises(ValueError):
                    m.verify_registered_failed_pair(run, job, metadata)
                section[field] = saved
        for index in range(len(job["steps"]) - 1):
            with self.subTest(missing_success=job["steps"][index]["name"]):
                job["steps"][index]["conclusion"] = "skipped"
                with self.assertRaises(ValueError):
                    m.verify_registered_failed_pair(run, job, metadata)
                job["steps"][index]["conclusion"] = "success"
        job["steps"].append(deepcopy(job["steps"][0]))
        with self.assertRaises(ValueError):
            m.verify_registered_failed_pair(run, job, metadata)

    def test_registered_repair_workflow_reuses_three_good_archives_and_builds_only_Server(self):
        import yaml

        workflow = yaml.load((HERE.parents[1] / m.WORKFLOW).read_text(), Loader=yaml.BaseLoader)
        builder = workflow["jobs"]["build-compat018-product"]
        steps = builder["steps"]
        self.assertIn("repair-reviewed-server", builder["if"])
        self.assertIn("repair-reviewed-server", builder["env"]["PYTHONDONTWRITEBYTECODE"])
        retained = next(s for s in steps if s.get("id") == "registered-retained")
        self.assertEqual(retained["if"], "inputs.phase == 'repair-reviewed-server'")
        self.assertIn("registered-server-repair", retained["run"])
        builds = [s for s in steps if s.get("uses") == "./saas/actions/build-oci-candidate"]
        self.assertEqual(len(builds), 4)
        self.assertEqual(
            builds[0]["if"], "inputs.phase == 'build' || inputs.phase == 'build-reviewed'"
        )
        self.assertEqual(builds[1]["if"], builds[0]["if"])
        self.assertIn("inputs.phase != 'repair-reviewed-server'", builds[3]["if"])
        self.assertEqual(
            builds[2]["with"], {"artifact": "server", "target": "runtime", "attempt": "2"}
        )
        audit = next(
            s
            for s in steps
            if s.get("name") == "Audit actual fixed C2 source, UI, and historical Host"
        )
        self.assertIn("registered-repair-audit", audit["run"])
        self.assertLess(steps.index(audit), steps.index(builds[2]))
        self.assertIn(
            "registered-confirm", next(s for s in steps if s.get("id") == "compare")["run"]
        )
        self.assertIn(
            "steps.registered-retained.outcome == 'success'",
            next(s for s in steps if s.get("id") == "raw")["if"],
        )
        self.assertIn(
            "inputs.phase != 'repair-reviewed-server'",
            workflow["jobs"]["scan-and-seal-same-oci"]["if"],
        )

    def test_registered_repair_download_checks_whole_zip_and_preserves_rejected_bytes(self):
        import importlib
        import shutil

        compare_oci_rebuilds = importlib.import_module("saas.scripts.compare_oci_rebuilds")
        legacy_artifact_download = importlib.import_module("saas.scripts.legacy_artifact_download")

        original = self.root / "repair-fixture.zip"
        profile = {
            key: m.REGISTERED_FAILED_PAIR[key] for key in ("product_revision", "product_tree")
        }
        profile["source_date_epoch"] = 1794205843
        first = {
            "images": {
                role: {"facts": self.facts[role], "archive_sha256": digest(role.encode())}
                for role in ("server", "host")
            }
        }
        with zipfile.ZipFile(original, "w") as bundle:
            bundle.writestr("registered-source-profile.json", encode(profile))
            bundle.writestr("reviewed-subject-image-facts.json", encode(first))
            for role in ("server", "host"):
                for attempt in (1, 2):
                    bundle.writestr(f"{role}-{attempt}.tar", role.encode())
        value = {
            **m.REGISTERED_FAILED_PAIR,
            "zip_size": original.stat().st_size,
            "zip_sha256": digest(original.read_bytes()),
        }
        checked = []

        def download(identifier, destination, **kwargs):
            self.assertEqual(identifier, value["artifact_id"])
            self.assertEqual(
                kwargs,
                {"expected_size": value["zip_size"], "expected_sha256": value["zip_sha256"]},
            )
            checked.append(identifier)
            shutil.copyfile(original, destination)

        root, environment = self.root / "repaired", self.root / "github-env"
        with patch.object(m, "REGISTERED_FAILED_PAIR", value):
            run, job, metadata = registered_failed_parent_records()

            def api(endpoint):
                return (
                    metadata if "/artifacts/" in endpoint else job if "/jobs/" in endpoint else run
                )

            with (
                patch.object(m, "api", side_effect=api),
                patch.object(m, "registered_profile", return_value=profile),
                patch.object(
                    legacy_artifact_download, "download_artifact_bytes", side_effect=download
                ),
                patch.object(
                    compare_oci_rebuilds,
                    "compare_archives",
                    return_value=deepcopy(self.report["images"]["omnigent-saas-host"]),
                ),
            ):
                m.prepare_registered_server_repair(root, environment)
        self.assertEqual(checked, [value["artifact_id"]])
        self.assertFalse((root / "server-2.tar").exists())
        self.assertEqual((root / "original-failed-pair/server-2.tar").read_bytes(), b"server")
        for name in ("server-1.tar", "host-1.tar", "host-2.tar"):
            self.assertTrue((root / name).is_file())
        parent = json.loads((root / "registered-server-repair-parent.json").read_text())
        self.assertEqual(parent["rejected_second_Server_archive_sha256"], digest(b"server"))
        self.assertEqual(parent["original_job_conclusion"], "failure")
        self.assertEqual(parent["new_Server_builds"], 1)
        self.assertIn("PRODUCT_REVISION=" + profile["product_revision"], environment.read_text())


if __name__ == "__main__":
    unittest.main()
