"""Replace one retained Job controller without restarting or deleting its Pods."""

from __future__ import annotations

import argparse
import contextlib
import http.client
import json
import os
import re
import socket
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, overload
from urllib.parse import quote

from saas.production.retained_sandbox_job import plan_retained_job_image_repair


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str):
        super().__init__("localhost", timeout=30)
        self.path = path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


@contextlib.contextmanager
def kubernetes_api(directory: Path):
    """Keep kubectl's existing authentication inside a private Unix socket."""
    with tempfile.TemporaryDirectory(prefix="omnigent-kube-api-") as temporary:
        path = str(Path(temporary) / "api.sock")
        with (directory / "proxy.stderr").open("ab") as log:
            process = subprocess.Popen(
                ["kubectl", "proxy", "--unix-socket=" + path],
                stdout=log,
                stderr=log,
            )
            try:
                deadline = time.monotonic() + 15
                while not Path(path).exists():
                    if process.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError("private Kubernetes proxy did not start")
                    time.sleep(0.1)
                Path(path).chmod(0o600)

                @overload
                def request(
                    method: str,
                    url: str,
                    body: object = None,
                    *,
                    missing_ok: Literal[False] = False,
                ) -> dict[str, Any]: ...

                @overload
                def request(
                    method: str,
                    url: str,
                    body: object = None,
                    *,
                    missing_ok: Literal[True],
                ) -> dict[str, Any] | None: ...

                def request(
                    method: str, url: str, body: object = None, *, missing_ok: bool = False
                ) -> dict[str, Any] | None:
                    connection = UnixConnection(path)
                    try:
                        connection.request(
                            method,
                            url,
                            None if body is None else json.dumps(body),
                            {
                                "Content-Type": "application/json-patch+json"
                                if method == "PATCH"
                                else "application/json"
                            },
                        )
                        response = connection.getresponse()
                        raw = response.read()
                        if response.status == 404 and missing_ok:
                            return None
                        if response.status not in (200, 201, 202):
                            raise RuntimeError(
                                f"Kubernetes {method} {url}: HTTP {response.status}"
                            )
                        return json.loads(raw)
                    finally:
                        connection.close()

                yield request
            finally:
                process.terminate()
                process.wait(timeout=10)


def _identity(kind: str, name: str) -> str:
    return subprocess.check_output(
        ["kubectl", "get", kind, name, "-o", "jsonpath={.metadata.uid}"], text=True
    ).strip()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--namespace-uid", required=True)
    parser.add_argument("--cluster-uid", required=True)
    parser.add_argument("--job", required=True)
    parser.add_argument("--job-uid", required=True)
    parser.add_argument("--old-image", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    if not all(re.fullmatch(r"[a-z0-9-]+", x) for x in (args.namespace, args.job)):
        parser.error("namespace and Job must be DNS labels")
    os.umask(0o077)
    args.evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
    if args.evidence.stat().st_mode & 0o077:
        parser.error("evidence directory must be private")
    if _identity("namespace", "kube-system") != args.cluster_uid:
        raise RuntimeError("cluster identity changed")
    if _identity("namespace", args.namespace) != args.namespace_uid:
        raise RuntimeError("namespace identity changed")
    plan_path = args.evidence / "plan.json"
    journal_path = args.evidence / "journal.json"
    jobs = f"/apis/batch/v1/namespaces/{args.namespace}/jobs"
    job_url = jobs + "/" + args.job
    selector = "batch.kubernetes.io/controller-uid=" + args.job_uid
    pods_url = f"/api/v1/namespaces/{args.namespace}/pods?labelSelector={quote(selector)}"

    def save(phase: str, **facts) -> None:
        journal_path.write_text(
            json.dumps(
                {"phase": phase, "at": datetime.now(timezone.utc).isoformat(), **facts},
                indent=2,
            )
            + "\n"
        )

    with kubernetes_api(args.evidence) as api:
        if args.resume:
            plan = json.loads(plan_path.read_text())
            if not (
                plan["namespace"] == args.namespace
                and plan["job"] == args.job
                and plan["old_job_uid"] == args.job_uid
                and plan["image"] == args.image
            ):
                raise RuntimeError("recovery arguments do not match retained plan")
        else:
            if plan_path.exists():
                raise RuntimeError("evidence exists; review journal and use --resume")
            job = api("GET", job_url)
            pods = api("GET", pods_url)["items"]
            plan = plan_retained_job_image_repair(
                job,
                pods,
                namespace=args.namespace,
                expected_job_uid=args.job_uid,
                old_image=args.old_image,
                image=args.image,
                now=datetime.now(timezone.utc),
            )
            for name, value in (("original-job", job), ("original-pods", pods), ("plan", plan)):
                (args.evidence / (name + ".json")).write_text(json.dumps(value, indent=2) + "\n")
            save("planned", production_mutation=False)
        if not args.execute:
            print(json.dumps({"status": "plan_only", "job": args.job}))
            return
        current = api("GET", job_url, missing_ok=True)
        if current is not None and current["metadata"]["uid"] == args.job_uid:
            save("before_orphan_delete", pod_deletion_allowed=False, pvc_deletion_allowed=False)
            api("DELETE", job_url, plan["delete_options"])
        deadline = time.monotonic() + 120
        while True:
            current = api("GET", job_url, missing_ok=True)
            pods = api("GET", pods_url)["items"]
            actual = sorted(p["metadata"]["uid"] for p in pods)
            if actual != plan["retained_pod_uids"]:
                raise RuntimeError("retained Pod identities changed; no further mutation")
            if current is not None and current["metadata"]["uid"] != args.job_uid:
                annotations = current["metadata"].get("annotations", {})
                if annotations.get("omnigent.io/retained-job-source-uid") != args.job_uid:
                    raise RuntimeError("foreign replacement Job; no further mutation")
                break
            orphaned = all(not p["metadata"].get("ownerReferences") for p in pods)
            if current is None and orphaned:
                replacement = plan["replacement"]
                if plan["expires_at"] is not None:
                    expiry = datetime.fromisoformat(plan["expires_at"])
                    remaining = int((expiry - datetime.now(timezone.utc)).total_seconds())
                    if remaining < 600:
                        raise RuntimeError("expiry too close; retained Pods remain orphaned")
                    replacement["spec"]["activeDeadlineSeconds"] = remaining
                save("pods_retained_before_create", retained_pod_uids=actual)
                current = api("POST", jobs, replacement)
                save("replacement_created", new_job_uid=current["metadata"]["uid"])
                break
            if time.monotonic() > deadline:
                raise TimeoutError("original controller orphaning")
            time.sleep(1)
        if current is None:
            raise RuntimeError("replacement controller is missing")
        new_uid = current["metadata"]["uid"]
        if current["spec"].get("manualSelector") is not True:
            raise RuntimeError("replacement selector mode changed")
        if current["spec"]["selector"] != plan["replacement"]["spec"]["selector"]:
            raise RuntimeError("replacement selector changed")
        template = current["spec"]["template"]["spec"]
        if any(
            c["image"] != args.image
            for f in ("containers", "initContainers")
            for c in template.get(f, [])
        ):
            raise RuntimeError("replacement images changed")
        deadline = time.monotonic() + 120
        while True:
            pods = api("GET", pods_url)["items"]
            if sorted(p["metadata"]["uid"] for p in pods) != plan["retained_pod_uids"]:
                raise RuntimeError("Pod identities changed during adoption")
            running = [p for p in pods if p["metadata"]["uid"] == plan["running_pod_uid"]]
            if len(running) != 1 or running[0]["status"]["phase"] != "Running":
                raise RuntimeError("original running Pod lost")
            if all(
                any(
                    o.get("controller") and o["uid"] == new_uid
                    for o in p["metadata"].get("ownerReferences", [])
                )
                for p in pods
            ):
                effective_expiry = None
                if plan["expires_at"] is not None:
                    current = api("GET", job_url)
                    started = current.get("status", {}).get("startTime")
                    if not started:
                        if time.monotonic() > deadline:
                            raise TimeoutError("replacement controller start time")
                        time.sleep(1)
                        continue
                    start_time = datetime.fromisoformat(started.replace("Z", "+00:00"))
                    expiry = datetime.fromisoformat(plan["expires_at"])
                    remaining = int((expiry - start_time).total_seconds())
                    if remaining <= 0:
                        raise RuntimeError("original lifetime elapsed during handoff")
                    actual = current["spec"]["activeDeadlineSeconds"]
                    if actual > remaining:
                        api(
                            "PATCH",
                            job_url,
                            [
                                {"op": "test", "path": "/metadata/uid", "value": new_uid},
                                {
                                    "op": "test",
                                    "path": "/metadata/resourceVersion",
                                    "value": current["metadata"]["resourceVersion"],
                                },
                                {
                                    "op": "replace",
                                    "path": "/spec/activeDeadlineSeconds",
                                    "value": remaining,
                                },
                            ],
                        )
                        actual = remaining
                    effective_expiry = start_time.timestamp() + actual
                    if effective_expiry > expiry.timestamp():
                        raise RuntimeError("replacement extended the original lifetime")
                save(
                    "pass",
                    new_job_uid=new_uid,
                    retained_pod_uids=plan["retained_pod_uids"],
                    image=args.image,
                    pod_deleted=False,
                    pvc_deleted=False,
                    original_expiry=plan["expires_at"],
                    effective_expiry_epoch=effective_expiry,
                )
                print(
                    json.dumps(
                        {
                            "status": "pass",
                            "job": args.job,
                            "new_job_uid": new_uid,
                            "pod_deleted": False,
                            "pvc_deleted": False,
                        }
                    )
                )
                break
            if time.monotonic() > deadline:
                raise TimeoutError("replacement controller adoption")
            time.sleep(1)


if __name__ == "__main__":
    main()
