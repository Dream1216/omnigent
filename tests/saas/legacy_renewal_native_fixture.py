"""Owned native fixture data, with only API/gh transport/registry processes doubled."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import shutil
import subprocess
import sys
import types
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from saas.scripts import legacy_initial_publisher as publisher
from saas.scripts import legacy_publication_reader as reader
from saas.scripts import legacy_publication_renewal as renewal
from tests.saas import test_image_supply_chain as image
from tests.saas import test_legacy_stack as stack_fixture
from tests.saas import test_oci_promotion as oci
from tests.saas.test_legacy_build_controller import controller, make_wheel
from tests.saas.test_legacy_pg_contract import result_xml

ROOT = Path(__file__).resolve().parents[2]


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n")


def git(root, *args):
    return subprocess.check_output(["git", *args], cwd=root, text=True).strip()


def init(root):
    root.mkdir(parents=True, exist_ok=True)
    for args in (
        ("init", "-q"),
        ("config", "user.name", "Owned renewal fixture"),
        ("config", "user.email", "fixture@example.invalid"),
        ("config", "commit.gpgsign", "false"),
    ):
        git(root, *args)


def archive(root, target):
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_STORED) as bundle:
        for path in sorted(root.rglob("*")):
            if path.is_file():
                bundle.write(path, str(path.relative_to(root)))


class NativeRenewal:
    def __init__(self, root, monkeypatch):
        self.root, self.monkeypatch = root, monkeypatch
        self.now = datetime.now(UTC)
        self.old = self.now - timedelta(days=35)
        self.runs, self.jobs, self.logs, self.artifacts, self.archives = {}, {}, {}, {}, {}
        self.sources, self.pulls, self.commits, self.subjects = {}, {}, {}, {}
        self.calls, self.crypto_calls = [], []
        self.fault = None
        self.next_id = 10000
        self.control = root / "native-control"
        self.products = {}
        self.rows = {"old": {}, "current": {}}
        self.run_components = {}
        self._prepare_products()
        self._prepare_control()
        self._prepare_native_inputs()
        self._install_boundaries()
        self._prepare_publications()

    def identifier(self):
        self.next_id += 1
        return self.next_id

    def _prepare_products(self):
        qualifier = reader._qualify_source_ci.__globals__
        for number, component in enumerate(sorted(stack_fixture.BASELINES), 1):
            path = self.root / ("product-" + component)
            init(path)
            schema = "lm2t00000001" if component == "Gateway" else "p0s000000015"
            contract = {
                "upstream_manifest": "saas/upstream-baseline.json",
                "upstream_revision": "u" * 40,
                "adapter_contract_version": "adapter-v1",
                "control_plane_schema_revision": schema,
                "deployment_scope": "single-region-multi-az",
            }
            write(
                path / "saas/upstream-baseline.json",
                {"upstream_revision": "u" * 40, "adapter_contract_version": "adapter-v1"},
            )
            write(path / "saas/production/baseline.json", {"revision_contract": contract})
            (path / "pyproject.toml").write_text(
                '[project]\nname="omnigent"\nversion="0.18.0.dev20261006"\n'
            )
            (path / "uv.lock").write_bytes(
                (ROOT / "tests/saas/resources/legacy_backend.toml").read_bytes()
            )
            script = path / "saas/scripts/check_wheel_contents.py"
            script.parent.mkdir(parents=True)
            script.write_text(
                'REQUIRED_WHEEL_PATHS = ("saas/application.py", '
                '"saas/upstream-baseline.json")\n'
                'raise RuntimeError("never execute fixture product code")\n'
            )
            write(path / "fixture-component.json", {"component": component})
            workflows = sorted(
                qualifier["_MANDATORY_TECHNICAL"] | {".github/workflows/saas-image-candidate.yml"}
            )
            for workflow in workflows:
                target = path / workflow
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(
                    "name: Owned native command fixture\non: pull_request\njobs: {}\n"
                )
            pg_paths = []
            for index in range(21):
                name = f"fixtures/pg-input-{index:02d}.txt"
                target = path / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(f"owned {component} PostgreSQL source {index}\n")
                pg_paths.append(name)
            before, after = (
                b'prerelease="if-necessary"\n',
                b'prerelease="if-necessary"\nresolution="lowest-direct"\n',
            )
            (path / "uv.toml").write_bytes(before)
            git(path, "add", ".")
            git(path, "commit", "-qm", "owned immutable baseline fixture")
            baseline = git(path, "rev-parse", "HEAD")
            (path / "uv.toml").write_bytes(after)
            git(path, "add", "uv.toml")
            git(path, "commit", "-qm", "owned material fixture")
            profile = {
                "schema_version": 1,
                "repository": publisher.REPOSITORY,
                "component": component,
                "baseline_revision": baseline,
                "product_revision": git(path, "rev-parse", "HEAD"),
                "product_tree": git(path, "rev-parse", "HEAD^{tree}"),
                "source_date_epoch": int(git(path, "show", "-s", "--format=%ct", "HEAD")),
                "application_version": "0.18.0.dev20261006",
                "source_delta": [
                    {
                        "path": "uv.toml",
                        "before": {"mode": "100644", "sha256": hashlib.sha256(before).hexdigest()},
                        "after": {"mode": "100644", "sha256": hashlib.sha256(after).hexdigest()},
                    }
                ],
            }
            # Only fixture-owned baseline identities change; verifier code is real.
            for module in list(sys.modules.values()):
                values = getattr(module, "__dict__", {})
                if values.get("__name__", "").startswith("saas.scripts.") and isinstance(
                    values.get("BASELINES"), dict
                ):
                    self.monkeypatch.setitem(values["BASELINES"], component, baseline)
            pending = [
                *vars(publisher).values(),
                *vars(reader).values(),
                *vars(controller).values(),
            ]
            seen = set()
            while pending:
                function = pending.pop()
                if not isinstance(function, types.FunctionType) or id(function) in seen:
                    continue
                seen.add(id(function))
                if not function.__module__.startswith("saas.scripts."):
                    continue
                values = function.__globals__
                if isinstance(values.get("BASELINES"), dict):
                    self.monkeypatch.setitem(values["BASELINES"], component, baseline)
                pending.extend(values.values())
            candidate = self.root / ("oci-" + component)
            self.monkeypatch.setattr(oci, "REVISION", profile["product_revision"])
            self.monkeypatch.setattr(oci, "EPOCH", profile["source_date_epoch"])
            original_builder = image._write_oci
            self.monkeypatch.setattr(
                oci,
                "_write_oci",
                lambda *a, _schema=schema, _builder=original_builder, **kw: _builder(
                    *a, schema_revision=_schema, **kw
                ),
            )
            labels, _ = oci.candidate(candidate)
            oci.refresh_scan_time(candidate, self.old)
            manifest = oci.seal(candidate, labels, self.old)
            write(candidate / "oci-promotion-manifest.json", manifest)
            sealed = self.root / ("original-" + component)
            sealed.mkdir()
            for name in (
                "server-1.tar",
                "host-1.tar",
                "oci-promotion-manifest.json",
                "saas-image-candidate.json",
            ):
                shutil.copyfile(candidate / name, sealed / name)
            shutil.copytree(candidate / "grype", sealed / "grype")
            original_zip = self.root / (component + "-original.zip")
            archive(sealed, original_zip)
            wheel = make_wheel(self.root / ("wheel-" + component), profile)
            self.products[component] = {
                "path": path,
                "profile": profile,
                "contract": contract,
                "candidate": candidate,
                "manifest": manifest,
                "labels": labels,
                "original_zip": original_zip,
                "wheel": wheel,
                "pg_paths": pg_paths,
                "workflows": workflows,
                "merge": f"{number + 900:040x}",
                "pull_number": 9000 + number,
            }

    def job(self, run, name, names, checkouts=None, stamp=None):
        stamp = stamp or self.now - timedelta(hours=1)
        job_id = self.identifier()
        steps, lines = [], []
        for number, step_name in enumerate(names, 1):
            start = stamp + timedelta(seconds=number * 10)
            steps.append(
                {
                    "number": number,
                    "name": step_name,
                    "status": "completed",
                    "conclusion": "success",
                    "started_at": start.isoformat(),
                    "completed_at": (start + timedelta(seconds=5)).isoformat(),
                }
            )
            if step_name in (checkouts or {}):
                for line in (
                    "##[group]Run actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
                    "[command]git log -1 --format=%H",
                    checkouts[step_name],
                ):
                    lines.append(start.isoformat() + " " + line)
        row = {
            "id": job_id,
            "name": name,
            "run_id": run["id"],
            "run_attempt": run["run_attempt"],
            "head_sha": run["head_sha"],
            "status": "completed",
            "conclusion": "success",
            "runner_group_name": "GitHub Actions",
            "labels": ["ubuntu-latest"],
            "check_run_url": f"https://api.github.com/repos/{publisher.REPOSITORY}/check-runs/{job_id}",
            "steps": steps,
        }
        self.jobs[job_id] = row
        self.logs[job_id] = "\n".join(lines) + "\n"
        return row

    def artifact(self, run, job, name, path):
        identifier = self.identifier()
        row = {
            "id": identifier,
            "name": name,
            "expired": False,
            "size_in_bytes": path.stat().st_size,
            "digest": "sha256:" + publisher.file_sha256(path),
            "created_at": job["steps"][-1]["started_at"],
            "workflow_run": {"id": run["id"], "head_sha": run["head_sha"]},
        }
        self.artifacts[identifier] = row
        self.archives[identifier] = path
        return row

    def source_run(self, data, path):
        profile = data["profile"]
        identifier = self.identifier()
        api_url = "https://api.github.com/repos/" + publisher.REPOSITORY
        run = {
            "id": identifier,
            "run_attempt": 1,
            "workflow_id": identifier + 100000,
            "check_suite_id": identifier + 200000,
            "path": path,
            "name": "Owned native command fixture",
            "head_sha": profile["product_revision"],
            "head_branch": "fixture-" + profile["component"],
            "event": "pull_request",
            "repository": {"full_name": publisher.REPOSITORY},
            "head_repository": {"full_name": publisher.REPOSITORY},
            "actor": {"login": "fixture"},
            "triggering_actor": {"login": "fixture"},
            "status": "completed",
            "conclusion": "success",
            "pull_requests": [
                {
                    "number": data["pull_number"],
                    "url": f"{api_url}/pulls/{data['pull_number']}",
                    "head": {"sha": profile["product_revision"], "repo": {"url": api_url}},
                    "base": {"sha": profile["baseline_revision"], "repo": {"url": api_url}},
                }
            ],
        }
        self.runs[identifier] = run
        return run

    def _prepare_control(self):
        init(self.control)
        stores = {name: {} for name in reader.TRUSTED_STORES}
        original_collector = publisher.download_original_oci.__globals__["collect_native_pr_oci"]
        pr_steps = original_collector.__globals__["verify_pr_oci_artifact"].__globals__[
            "_REQUIRED_STEPS"
        ]
        for component, data in self.products.items():
            profile = data["profile"]
            repo = {"full_name": publisher.REPOSITORY}
            self.pulls[data["pull_number"]] = {
                "number": data["pull_number"],
                "state": "open",
                "draft": False,
                "head": {
                    "sha": profile["product_revision"],
                    "ref": "fixture-" + component,
                    "repo": repo,
                },
                "base": {
                    "sha": profile["baseline_revision"],
                    "ref": (
                        f"codex/legacy-validation-{component.lower()}-"
                        f"{stack_fixture.BASELINES[component][:8]}"
                    ),
                    "repo": repo,
                },
                "merge_commit_sha": data["merge"],
            }
            self.commits[data["merge"]] = {
                "sha": data["merge"],
                "tree": {"sha": profile["product_tree"]},
                "parents": [
                    {"sha": profile["baseline_revision"]},
                    {"sha": profile["product_revision"]},
                ],
            }
            identity = {
                "schema_version": 1,
                "component": component,
                "product_revision": profile["product_revision"],
                "product_tree": profile["product_tree"],
                "validation_pr": data["pull_number"],
                "validation_base_ref": self.pulls[data["pull_number"]]["base"]["ref"],
                "workflows": [],
            }
            plans = {}
            for path in data["workflows"]:
                run = self.source_run(data, path)
                candidate = path.endswith("saas-image-candidate.yml")
                names = (
                    pr_steps
                    if candidate
                    else ("Original checkout", "Run original fixture command")
                )
                checkout = names[0]
                job = self.job(
                    run,
                    "build-candidate" if candidate else "Original tests",
                    names,
                    {checkout: profile["product_revision"]},
                    stamp=self.old,
                )
                specification = {
                    "path": path,
                    "name": run["name"],
                    "source_sha256": publisher.file_sha256(data["path"] / path),
                    "run_id": run["id"],
                    "attempt": 1,
                    "jobs": {
                        job["name"]: {
                            "labels": ["ubuntu-latest"],
                            "conclusion": "success",
                            "checkouts": [{"number": 1, "name": checkout, "revision": "product"}],
                        }
                    },
                }
                identity["workflows"].append(specification)
                plans[path] = {
                    job["name"]: {
                        "kind": "native-command",
                        "reason": "Owned original command fixture",
                        "execution_steps": [{"number": 2, "name": names[1]}],
                        "pytest": None,
                    }
                }
                if candidate:
                    metadata = self.artifact(
                        run,
                        job,
                        f"legacy-validation-oci-{component}-{profile['product_revision']}-{run['id']}-1",
                        data["original_zip"],
                    )
                    transfer = {
                        "component": component,
                        "pull_number": data["pull_number"],
                        "base_ref": identity["validation_base_ref"],
                        "workflow_sha256": specification["source_sha256"],
                        "actor": "fixture",
                    }
                    original = {
                        "kind": "legacy_pr_sealed_oci/v1",
                        "component": component,
                        "product_revision": profile["product_revision"],
                        "product_tree": profile["product_tree"],
                        "baseline_revision": profile["baseline_revision"],
                        **transfer,
                        "merge_revision": data["merge"],
                        "workflow_path": path,
                        "run_id": run["id"],
                        "attempt": 1,
                        "job_id": job["id"],
                        "artifact_id": metadata["id"],
                        "zip_size": metadata["size_in_bytes"],
                        "zip_sha256": metadata["digest"][7:],
                        "seal_sha256": publisher.file_sha256(
                            data["candidate"] / "oci-promotion-manifest.json"
                        ),
                    }
            policy = {
                "component": component,
                "product_revision": profile["product_revision"],
                "product_tree": profile["product_tree"],
                "identity_contract_sha256": publisher.digest(identity),
                "workflow_catalog": {
                    path: {
                        "sha256": publisher.file_sha256(data["path"] / path),
                        "disposition": "required-technical",
                        "reason": "Owned original command fixture",
                    }
                    for path in data["workflows"]
                },
                "job_evidence": plans,
                "other_checks": [],
                "statuses": [],
                "domain_not_applicable": {},
            }
            pg = {
                **{key: profile[key] for key in ("component", "product_revision", "product_tree")},
                "trusted_inputs": {
                    path: publisher.file_sha256(data["path"] / path) for path in data["pg_paths"]
                },
            }
            original_input = {
                **{key: profile[key] for key in ("component", "product_revision", "product_tree")},
                "original_pr_oci": {
                    key: original[key]
                    for key in (
                        "run_id",
                        "attempt",
                        "artifact_id",
                        "zip_size",
                        "zip_sha256",
                        "seal_sha256",
                    )
                },
            }
            for name, value in zip(
                reader.TRUSTED_STORES,
                (profile, identity, original_input, pg, transfer, policy),
                strict=True,
            ):
                stores[name][component] = value
            data.update(original=original, transfer=transfer)
        for name, values in stores.items():
            write(
                self.control / "saas/supply_chain" / name,
                {
                    "schema_version": 1,
                    "inputs" if "original-inputs" in name else "profiles": values,
                },
            )
        target = self.control / publisher.WORKFLOW
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / publisher.WORKFLOW).read_bytes())
        target = self.control / ".github/actions/compat-smoke-saas-n1-gate/evaluate.sh"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            "POSTGRESQL_N1_TRUSTED_INPUTS=(\n"
            + "".join(
                f'  "{p}|{"f" * 64}"\n' for p in next(iter(self.products.values()))["pg_paths"]
            )
            + ")\n"
        )
        git(self.control, "add", ".")
        git(self.control, "commit", "-qm", "owned exact native control fixture")
        self.control_sha = git(self.control, "rev-parse", "HEAD")
        self.control_tree = git(self.control, "rev-parse", "HEAD^{tree}")
        self.commits[self.control_sha] = {
            "sha": self.control_sha,
            "tree": {"sha": self.control_tree},
        }

    def _prepare_native_inputs(self):
        pg_globals = reader._collect_pg_receipts.__globals__
        for generation in ("old", "current"):
            for component, data in self.products.items():
                identifier = self.identifier()
                stamp = self.old if generation == "old" else self.now - timedelta(hours=1)
                context = {
                    "control_revision": self.control_sha,
                    "run_id": identifier,
                    "attempt": 1,
                    "actor": "fixture",
                }
                self.run_components[identifier] = (generation, component)
                run = {
                    "id": identifier,
                    "run_attempt": 1,
                    "head_sha": self.control_sha,
                    "head_branch": "main",
                    "event": "workflow_dispatch",
                    "path": publisher.WORKFLOW,
                    "repository": {"full_name": publisher.REPOSITORY},
                    "head_repository": {"full_name": publisher.REPOSITORY},
                    "actor": {"login": "fixture"},
                    "triggering_actor": {"login": "fixture"},
                    "status": "completed",
                    "conclusion": "success",
                }
                self.runs[identifier] = run
                for major in (16, 18):
                    job = self.job(
                        run,
                        f"legacy-pg ({major})",
                        pg_globals["_PG_STEPS"],
                        {
                            "Checkout exact main PG verifier": self.control_sha,
                            "Checkout exact PG product": data["profile"]["product_revision"],
                        },
                        stamp,
                    )
                    step = next(
                        s
                        for s in job["steps"]
                        if s["name"] == "Execute original exact-source PostgreSQL contracts"
                    )
                    cases = sorted(
                        pg_globals["verify_pg_results"].__globals__["expected_cases"](major)
                    )
                    lines = [f"collecting ... collected {len(cases)} items"] + [
                        f"{c.replace('.', '/')}.py::{n} PASSED [100%]" for c, n in cases
                    ]
                    self.logs[job["id"]] += (
                        "\n".join(step["started_at"] + " " + line for line in lines) + "\n"
                    )
                    source = {
                        "component": component,
                        "product_revision": data["profile"]["product_revision"],
                        "product_tree": data["profile"]["product_tree"],
                        "control_revision": self.control_sha,
                        "trusted_input_count": 21,
                        "trusted_inputs_sha256": hashlib.sha256(
                            json.dumps(
                                {
                                    p: publisher.file_sha256(data["path"] / p)
                                    for p in data["pg_paths"]
                                },
                                sort_keys=True,
                            ).encode()
                        ).hexdigest(),
                    }
                    major_source = {
                        **source,
                        "postgresql_major": major,
                        "service_image": pg_globals["PG_IMAGES"][major],
                        "production_admission": False,
                    }
                    xml = result_xml(major)
                    version = "160014" if major == 16 else "180006"
                    result = pg_globals["verify_pg_results"](
                        xml, major=major, observed_version=version
                    )
                    pgzip = self.root / f"{identifier}-PG{major}.zip"
                    with zipfile.ZipFile(pgzip, "w", compression=zipfile.ZIP_STORED) as bundle:
                        for name, payload in {
                            "legacy-pg-source.json": json.dumps(major_source),
                            "legacy-pg-version.txt": version,
                            "legacy-pg.xml": xml,
                            "legacy-pg-result.json": json.dumps(
                                {**major_source, "result": result}
                            ),
                        }.items():
                            bundle.writestr(name, payload)
                    self.artifact(
                        run,
                        job,
                        f"legacy-pg-{component}-{major}-{data['profile']['product_revision']}-{self.control_sha}-{identifier}-1",
                        pgzip,
                    )
                job = self.job(
                    run,
                    "build-initial",
                    publisher.FRESH_STEPS,
                    {
                        publisher.FRESH_STEPS[0]: self.control_sha,
                        publisher.FRESH_STEPS[2]: data["profile"]["product_revision"],
                    },
                    stamp,
                )
                facts = controller.wheel_source_facts(
                    data["path"], data["wheel"], data["profile"], self.control_sha
                )
                freshroot = self.root / f"fresh-{identifier}"
                freshroot.mkdir()
                shutil.copyfile(data["wheel"], freshroot / data["wheel"].name)
                write(freshroot / "wheel-source.json", facts)
                (freshroot / "SHA256SUMS").write_text(
                    f"{facts['wheel_sha256']}  {data['wheel'].name}\n"
                )
                freshzip = self.root / f"fresh-{identifier}.zip"
                archive(freshroot, freshzip)
                self.artifact(
                    run,
                    job,
                    f"legacy-initial-{component}-{data['profile']['product_revision']}-{self.control_sha}-{identifier}-1",
                    freshzip,
                )
                data[generation] = {"context": context, "run": run, "stamp": stamp}

    def api(self, endpoint):
        self.calls.append(endpoint)
        path, _, query = endpoint.partition("?")
        if "/contents/" in path:
            name = path.split("/contents/", 1)[1]
            ref = query.split("ref=", 1)[1]
            root = (
                self.control
                if ref == self.control_sha
                else next(d["path"] for d in self.products.values() if d["merge"] == ref)
            )
            body = (root / name).read_bytes()
            return {
                "path": name,
                "encoding": "base64",
                "size": len(body),
                "content": base64.b64encode(body).decode(),
            }
        if "/pulls/" in path:
            return copy.deepcopy(self.pulls[int(path.rsplit("/", 1)[1])])
        if "/git/commits/" in path:
            return copy.deepcopy(self.commits[path.rsplit("/", 1)[1]])
        if "/commits/" in path:
            revision = path.split("/commits/", 1)[1].split("/", 1)[0]
            runs = [r for r in self.runs.values() if r["head_sha"] == revision]
            if path.endswith("/statuses"):
                return []
            checks = [
                {
                    "id": j["id"],
                    "head_sha": revision,
                    "name": j["name"],
                    "app": {"id": 15368},
                    "check_suite": {"id": self.runs[j["run_id"]]["check_suite_id"]},
                    "status": "completed",
                    "conclusion": "success",
                }
                for j in self.jobs.values()
                if j["run_id"] in {r["id"] for r in runs}
            ]
            return {"total_count": len(checks), "check_runs": checks}
        if path.endswith("/actions/runs"):
            revision = query.split("head_sha=", 1)[1].split("&")[0]
            runs = [r for r in self.runs.values() if r["head_sha"] == revision]
            return {"total_count": len(runs), "workflow_runs": copy.deepcopy(runs)}
        if "/actions/artifacts/" in path:
            row = copy.deepcopy(self.artifacts[int(path.rsplit("/", 1)[1])])
            if (
                self.fault == "expired_original"
                and row["id"] == self.products["Gateway"]["original"]["artifact_id"]
            ):
                row["expired"] = True
            if (
                self.fault == "expired_old_wheel"
                and row["id"]
                == self.rows["old"]["Gateway"]["admission"]["fresh_control_wheel"]["artifact_id"]
            ):
                row["expired"] = True
            return row
        if "/actions/jobs/" in path:
            return copy.deepcopy(self.jobs[int(path.rsplit("/", 1)[1])])
        match = re.search(r"/actions/runs/([0-9]+)", path)
        if match:
            identifier = int(match[1])
            if path.endswith("/jobs"):
                rows = [j for j in self.jobs.values() if j["run_id"] == identifier]
                return {"total_count": len(rows), "jobs": copy.deepcopy(rows)}
            if path.endswith("/artifacts"):
                rows = [
                    a for a in self.artifacts.values() if a["workflow_run"]["id"] == identifier
                ]
                if self.fault == "expired_old_wheel":
                    rows = copy.deepcopy(rows)
                    expired_id = self.rows["old"]["Gateway"]["admission"]["fresh_control_wheel"][
                        "artifact_id"
                    ]
                    for row in rows:
                        if row["id"] == expired_id:
                            row["expired"] = True
                if self.fault and self.fault.startswith("missing_anchor_"):
                    component = self.fault.removeprefix("missing_anchor_")
                    old = self.rows["old"][component]
                    if identifier == old["producer"]["run_id"]:
                        omitted = old["stage_artifacts"]["signatures"]["artifact_id"]
                        rows = [a for a in rows if a["id"] != omitted]
                return {"total_count": len(rows), "artifacts": copy.deepcopy(rows)}
            return copy.deepcopy(self.runs[identifier])
        raise AssertionError(endpoint)

    def _install_boundaries(self):
        self.monkeypatch.setitem(publisher.api.__globals__, "_native_api", self.api)
        popen = subprocess.Popen
        run = subprocess.run
        output = subprocess.check_output

        def spawn(command, **kwargs):
            if command[:2] == ["gh", "api"]:
                endpoint = command[2]
                if endpoint.endswith("/logs"):
                    identifier = int(endpoint.rsplit("/", 2)[1])
                    body = self.logs[identifier].encode()
                    return popen(
                        [sys.executable, "-c", "import os;os.write(1," + repr(body) + ")"],
                        **kwargs,
                    )
                identifier = int(endpoint.rsplit("/", 2)[1])
                source = self.archives[identifier]
                assert endpoint.endswith("/zip")
                return popen(
                    [
                        sys.executable,
                        "-c",
                        "import sys;sys.stdout.buffer.write(open(sys.argv[1],'rb').read())",
                        str(source),
                    ],
                    **kwargs,
                )
            return popen(command, **kwargs)

        def process(command, **kwargs):
            if command[:2] == ["crane", "pull"]:
                reference = command[-2]
                for data in self.products.values():
                    for role in publisher.IMAGES:
                        if reference.endswith(data["manifest"]["images"][role]["index_digest"]):
                            shutil.copytree(data["candidate"] / f"{role}-1-layout", command[-1])
                            return subprocess.CompletedProcess(command, 0, "", "")
                raise AssertionError(reference)
            return run(command, **kwargs)

        def command_output(command, **kwargs):
            if command[:3] == ["gh", "attestation", "verify"]:
                self.crypto_calls.append(command)
                subject = command[3]
                digest = (
                    subject.split("sha256:", 1)[1]
                    if subject.startswith("oci://")
                    else publisher.file_sha256(Path(subject))
                )
                predicate_type = command[command.index("--predicate-type") + 1]
                entries = []
                for entry in self.subjects.get((digest, predicate_type), []):
                    if entry not in entries:
                        entries.append(copy.deepcopy(entry))
                if self.fault == "original_signature":
                    bad_run = self.rows["old"]["Gateway"]["producer"]["run_id"]
                    for entry in entries:
                        certificate = entry["verificationResult"]["signature"]["certificate"]
                        if f"/runs/{bad_run}/" in certificate["runInvocationURI"]:
                            certificate["issuer"] = "https://untrusted.invalid"
                return json.dumps(entries)
            return output(command, **kwargs)

        self.monkeypatch.setattr(subprocess, "Popen", spawn)
        self.monkeypatch.setattr(subprocess, "run", process)
        self.monkeypatch.setattr(subprocess, "check_output", command_output)
        for name in (
            "GITHUB_REPOSITORY",
            "GITHUB_REF",
            "GITHUB_SHA",
            "GITHUB_EVENT_NAME",
            "GITHUB_WORKFLOW_SHA",
            "GITHUB_WORKFLOW_REF",
            "GITHUB_JOB",
        ):
            self.monkeypatch.delenv(name, raising=False)

    def _signed_entry(self, subject, predicate, context, predicate_type):
        repository = "https://github.com/" + publisher.REPOSITORY
        certificate = {
            "issuer": "https://token.actions.githubusercontent.com",
            "sourceRepositoryURI": repository,
            "sourceRepositoryRef": "refs/heads/main",
            "sourceRepositoryDigest": self.control_sha,
            "buildSignerDigest": self.control_sha,
            "buildConfigDigest": self.control_sha,
            "runnerEnvironment": "github-hosted",
            "subjectAlternativeName": f"{repository}/{publisher.WORKFLOW}@refs/heads/main",
            "runInvocationURI": f"{repository}/actions/runs/{context['run_id']}/attempts/1",
        }
        return {
            "verificationResult": {
                "signature": {"certificate": certificate},
                "statement": {
                    "predicate": predicate,
                    "predicateType": predicate_type,
                    "subject": [{"digest": {"sha256": subject}}],
                },
            }
        }

    def _prepare_publications(self):
        for generation in ("old", "current"):
            for component, data in self.products.items():
                item = data[generation]
                context = item["context"]
                producer = reader.HistoricalProducer(
                    self.control_sha,
                    self.control_tree,
                    publisher.file_sha256(self.control / publisher.WORKFLOW),
                    context["run_id"],
                    1,
                    "fixture",
                )
                dest = self.root / f"build-facts-{context['run_id']}"
                source = reader.qualify_historical_source(
                    self.control, data["path"], component, producer, dest / "source"
                )
                pg = reader._collect_pg_receipts(
                    self.control,
                    data["path"],
                    component,
                    self.control_sha,
                    run_id=context["run_id"],
                    attempt=1,
                    actor="fixture",
                    destination=dest / "pg",
                    context_verifier=lambda root, revision: publisher.require(
                        root == self.control and revision == self.control_sha,
                        "fixture source context differs from the verified producer",
                    ),
                )
                original = publisher.collect_original_input(
                    self.control, data["profile"], dest / "original"
                )
                fresh, wheel = publisher.collect_fresh_wheel(
                    self.control, data["path"], data["profile"], context, dest / "fresh"
                )
                admission = {
                    "kind": publisher.VARIANT,
                    "profile": data["profile"],
                    "transfer_profile": data["transfer"],
                    "control": {
                        **context,
                        "workflow_path": publisher.WORKFLOW,
                        "workflow_sha256": producer.workflow_sha256,
                    },
                    "original_pr_oci": original,
                    "fresh_control_wheel": fresh,
                    "source_qualification": {"sha256": publisher.digest(source), "result": source},
                    "native_product_pg": {"sha256": publisher.digest(pg), "result": pg},
                    "rebuild_in_publisher": False,
                }
                exports = {}
                coordinates = {}
                publication = {
                    "kind": "legacy_exact_oci_publication/v1",
                    "admission_sha256": publisher.digest(admission),
                    "images": publisher.image_references(admission, data["manifest"]),
                    "candidate_seal_sha256": original["seal_sha256"],
                    "registry_readback_pass": True,
                    "rebuilt": False,
                }
                for role, job_name in (
                    ("preparation", "prepare-publication"),
                    ("publication", "publish-exact-oci"),
                    ("runtime", "verify-published-runtime"),
                ):
                    export = self.root / f"export-{context['run_id']}-{role}"
                    export.mkdir()
                    write(export / "admission.json", admission)
                    if role == "publication":
                        write(export / "publication.json", publication)
                    else:
                        shutil.copytree(data["candidate"] / "grype", export / "scans/grype")
                        oci.refresh_scan_time(
                            export / "scans", self.old if generation == "old" else self.now
                        )
                    if role == "runtime":
                        for image_role in publisher.IMAGES:
                            for platform in publisher.PLATFORMS:
                                prefix = f"{image_role}-{platform.split('/')[-1]}"
                                write(
                                    export / f"sbom/{prefix}.spdx.json",
                                    {
                                        "spdxVersion": "SPDX-2.3",
                                        "SPDXID": "SPDXRef-DOCUMENT",
                                        "creationInfo": {
                                            "creators": [f"Tool: syft-{publisher.SYFT_VERSION}"]
                                        },
                                        "packages": [{"name": "fixture"}],
                                    },
                                )
                                write(
                                    export / f"sbom/{prefix}.cyclonedx.json",
                                    {
                                        "bomFormat": "CycloneDX",
                                        "components": [{"name": "fixture"}],
                                    },
                                )
                        runtime = {
                            "kind": "legacy_independent_published_runtime/v1",
                            "admission_sha256": publisher.digest(admission),
                            "publication_sha256": publisher.digest(publication),
                            "status": "pass",
                            "runtime": [
                                {
                                    "role": r,
                                    "platform": p,
                                    "image": publisher.child_reference(
                                        publication["images"], data["manifest"], r, p
                                    ),
                                    "status": "pass",
                                }
                                for r in publisher.IMAGES
                                for p in publisher.PLATFORMS
                            ],
                            "scans": renewal._scan_integrity(export / "scans"),
                            "sboms": publisher.validate_sbom_files(
                                export / "sbom", publication["images"], data["manifest"]
                            ),
                        }
                        write(export / "runtime.json", runtime)
                    job = self.job(
                        item["run"],
                        job_name,
                        publisher.RUN_STEPS[job_name],
                        {
                            publisher.CHECKOUT: self.control_sha,
                            publisher.PRODUCT_CHECKOUT: data["profile"]["product_revision"],
                        },
                        item["stamp"],
                    )
                    path = self.root / f"export-{context['run_id']}-{role}.zip"
                    archive(export, path)
                    metadata = self.artifact(
                        item["run"],
                        job,
                        publisher.artifact_name(role, data["profile"], context),
                        path,
                    )
                    coordinates[role] = publisher.artifact_coordinate(metadata, job)
                    exports[role] = export
                predicate = publisher.typed_provenance(
                    admission,
                    publication,
                    runtime,
                    preparation_artifact=coordinates["preparation"],
                    publication_artifact=coordinates["publication"],
                    runtime_artifact=coordinates["runtime"],
                )
                for subject in (
                    fresh["wheel_sha256"],
                    *(
                        reference.split("sha256:")[1]
                        for reference in publication["images"].values()
                    ),
                ):
                    self.subjects.setdefault(
                        (subject, "https://slsa.dev/provenance/v1"), []
                    ).append(
                        self._signed_entry(
                            subject, predicate, context, "https://slsa.dev/provenance/v1"
                        )
                    )
                for name, facts in runtime["sboms"].items():
                    subject = facts["image"].split("sha256:")[1]
                    sbom = json.loads((exports["runtime"] / f"sbom/{name}.spdx.json").read_text())
                    self.subjects.setdefault((subject, publisher.SPDX_PREDICATE_TYPE), []).append(
                        self._signed_entry(subject, sbom, context, publisher.SPDX_PREDICATE_TYPE)
                    )
                verification = self.root / f"signature-input-{context['run_id']}"
                verification.mkdir()
                for name, value in (
                    ("provenance", predicate),
                    ("publication", publication),
                    ("runtime", runtime),
                ):
                    write(verification / (name + ".json"), value)
                shutil.copytree(exports["runtime"] / "sbom", verification / "sbom")
                receipt = publisher.verify_signatures(verification, admission, wheel)
                export = self.root / f"export-{context['run_id']}-signatures"
                export.mkdir()
                write(export / "native-signatures.json", receipt)
                job_name = "attest-exact-inputs"
                job = self.job(
                    item["run"],
                    job_name,
                    publisher.RUN_STEPS[job_name],
                    {
                        publisher.CHECKOUT: self.control_sha,
                        publisher.PRODUCT_CHECKOUT: data["profile"]["product_revision"],
                    },
                    item["stamp"],
                )
                path = self.root / f"export-{context['run_id']}-signatures.zip"
                archive(export, path)
                metadata = self.artifact(
                    item["run"],
                    job,
                    publisher.artifact_name("signatures", data["profile"], context),
                    path,
                )
                coordinates["signatures"] = publisher.artifact_coordinate(metadata, job)
                self.rows[generation][component] = {
                    "input_variant": publisher.VARIANT,
                    "profile": data["profile"],
                    "producer": {
                        **context,
                        "control_tree": self.control_tree,
                        "workflow_sha256": producer.workflow_sha256,
                    },
                    "admission": admission,
                    "stage_artifacts": coordinates,
                    "predicate_sha256": publisher.digest(predicate),
                    "deployment_roles": {},
                }
                item.update(
                    exports=exports, predicate=predicate, publication=publication, runtime=runtime
                )
