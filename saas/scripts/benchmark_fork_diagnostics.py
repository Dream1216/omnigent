"""Non-verdict fork evidence for the existing downstream performance job."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import signal
import time
import uuid
from collections.abc import Mapping
from pathlib import Path

import httpx
from fastapi import APIRouter, Request

_REPO_ROOT = Path(__file__).resolve().parents[2]


def install_fork_diagnostic(target: APIRouter, binding: dict[str, str]) -> None:
    """Enable one fixed-target replay in an explicitly opted-in benchmark server."""
    import secrets

    from fastapi import HTTPException

    source_id, token = binding["source_id"], binding["token"]
    used = False

    @target.post("/server-metrics")
    async def diagnose_fork(request: Request) -> dict[str, object]:
        nonlocal used
        if not secrets.compare_digest(
            request.headers.get("X-Omnigent-Bench-Diagnostic", ""), token
        ):
            raise HTTPException(403, "benchmark diagnostic binding required")
        if used:
            raise HTTPException(409, "benchmark diagnostic already consumed")
        used = True
        return await _profile_original_fork(request, source_id)


async def _profile_original_fork(request: Request, source_id: str) -> dict[str, object]:
    """Collect bounded SQL and executor stages without SQL text or arguments."""
    import asyncio
    import contextvars
    import functools
    import hashlib
    import threading
    import time

    import httpx
    from sqlalchemy import event
    from sqlalchemy.engine import Engine

    import omnigent
    from omnigent._build_info import COMMIT_SHA
    from omnigent.db.query_context import current_query_name

    marker = contextvars.ContextVar("benchmark_fork_diagnostic", default=False)
    records: list[dict[str, object]] = []
    dropped = 0
    records_lock = threading.Lock()

    def record(row: dict[str, object]) -> None:
        nonlocal dropped
        with records_lock:
            if len(records) < 2048:
                records.append(row)
            else:
                dropped += 1

    def sql_start(_conn, _cursor, _statement, _parameters, context, _many):
        if marker.get():
            context._benchmark_started = (time.perf_counter_ns(), time.thread_time_ns())

    def sql_end(_conn, _cursor, statement, _parameters, context, _many):
        started = getattr(context, "_benchmark_started", None)
        if started is not None:
            record(
                {
                    "kind": "sql",
                    "thread_id": threading.get_native_id(),
                    "started_ns": started[0],
                    "completed_ns": time.perf_counter_ns(),
                    "query_name": current_query_name(),
                    "statement_sha256": hashlib.sha256(statement.encode()).hexdigest(),
                    "operation": statement.split(maxsplit=1)[0] if statement.strip() else "",
                    "wall_ns": time.perf_counter_ns() - started[0],
                    "thread_cpu_ns": time.thread_time_ns() - started[1],
                }
            )

    loop = asyncio.get_running_loop()
    original_executor = loop.run_in_executor
    pending: list[asyncio.Future] = []

    def traced_executor(executor, function, *args):
        if not marker.get():
            return original_executor(executor, function, *args)
        queued = time.perf_counter_ns()
        call = (
            function.args[0]
            if isinstance(function, functools.partial) and function.args
            else function
        )

        def invoke():
            started, cpu = time.perf_counter_ns(), time.thread_time_ns()
            try:
                return function(*args)
            finally:
                record(
                    {
                        "kind": "thread_pool",
                        "operation": getattr(call, "__qualname__", type(call).__name__),
                        "thread_id": threading.get_native_id(),
                        "queued_ns": queued,
                        "started_ns": started,
                        "completed_ns": time.perf_counter_ns(),
                        "queue_ns": started - queued,
                        "wall_ns": time.perf_counter_ns() - started,
                        "thread_cpu_ns": time.thread_time_ns() - cpu,
                    }
                )

        worker = original_executor(executor, invoke)
        pending.append(worker)

        def retrieve_error(future) -> None:
            if not future.cancelled() and (error := future.exception()) is not None:
                record({"kind": "executor_error", "error_type": type(error).__name__})

        worker.add_done_callback(retrieve_error)
        return asyncio.shield(worker)

    installed = True

    def uninstall() -> None:
        nonlocal installed
        if not installed:
            return
        installed = False
        if loop.run_in_executor is traced_executor:
            loop.run_in_executor = original_executor  # type: ignore[method-assign]
        event.remove(Engine, "before_cursor_execute", sql_start)
        event.remove(Engine, "after_cursor_execute", sql_end)

    event.listen(Engine, "before_cursor_execute", sql_start)
    event.listen(Engine, "after_cursor_execute", sql_end)
    loop.run_in_executor = traced_executor  # type: ignore[method-assign]
    identity = marker.set(True)
    start, cpu = time.perf_counter_ns(), time.process_time_ns()
    fork_id = None
    result: dict[str, object] = {
        "source_id": source_id,
        "status": "incomplete",
        "component_revision": COMMIT_SHA,
        "component_module": omnigent.__file__,
        "executor_scope": "asyncio run_in_executor only; AnyIO worker waits are not profiled",
    }
    headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in {"host", "content-length", "x-omnigent-bench-diagnostic"}
    }
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=request.app),
            base_url="http://benchmark.invalid",
            headers=headers,
        ) as client:
            try:
                async with asyncio.timeout(15):
                    response = await client.post(f"/v1/sessions/{source_id}/fork", json={})
                    response.raise_for_status()
                    fork_id = response.json()["id"]
                    result["status"] = "complete"
            except Exception as error:  # noqa: BLE001 — emit diagnostic evidence only.
                result["error_type"] = type(error).__name__
            finally:
                result.update(
                    {
                        "fork_wall_ns": time.perf_counter_ns() - start,
                        "process_cpu_ns": time.process_time_ns() - cpu,
                        "process_cpu_scope": "whole server; background work may contribute",
                    }
                )
                marker.reset(identity)
                _, remaining = (
                    await asyncio.wait(pending, timeout=5) if pending else (set(), set())
                )
                result["workers_remaining"] = len(remaining)
                if remaining:
                    result["status"] = "incomplete"

                    def release_when_done(_future) -> None:
                        if all(worker.done() for worker in pending):
                            uninstall()

                    for worker in remaining:
                        worker.add_done_callback(release_when_done)
                else:
                    uninstall()
                if fork_id is not None:
                    async with asyncio.timeout(5):
                        deleted = await client.delete(f"/v1/sessions/{fork_id}")
                    result["fork_cleanup_status"] = deleted.status_code
                    if deleted.is_error:
                        result["status"] = "incomplete"
                else:
                    result["fork_cleanup_status"] = "unknown"
    finally:
        if marker.get():
            marker.reset(identity)
        if not pending or all(worker.done() for worker in pending):
            uninstall()
        else:

            def release_after_exit(_future) -> None:
                if all(worker.done() for worker in pending):
                    uninstall()

            for worker in pending:
                worker.add_done_callback(release_after_exit)
        with records_lock:
            result["records"] = list(records)
            result["dropped_records"] = dropped
        if dropped or {row["kind"] for row in records} != {"sql", "thread_pool"}:
            result["status"] = "incomplete"
    return result


def _diagnostic_binding() -> dict[str, str] | None:
    import json
    import os
    import re

    raw = os.environ.get("OMNIGENT_BENCH_FORK_DIAGNOSTICS")
    if raw is None:
        return None
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("GITHUB_REPOSITORY") != "Dream1216/omnigent"
    ):
        raise ValueError("fork diagnostics require the existing downstream CI job")
    binding = json.loads(raw)
    if (
        set(binding) != {"source_id", "token"}
        or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", binding["source_id"]) is None
        or re.fullmatch(r"[0-9a-f]{32}", binding["token"]) is None
    ):
        raise ValueError("invalid explicit benchmark diagnostic binding")
    return binding


async def _fork_source_snapshot(client: httpx.AsyncClient, source_id: str) -> dict[str, object]:
    """Read the retained original target completely, or reject the bounded snapshot."""
    import hashlib

    result: dict[str, object] = {
        "source_id": source_id,
        "phase": "after_both_formal_sides",
        "started_unix_ns": time.time_ns(),
    }
    for name, suffix in (("items", "items"), ("files", "resources/files")):
        rows: list[object] = []
        after = None
        for _ in range(20):
            response = await client.get(
                f"/v1/sessions/{source_id}/{suffix}",
                params={"limit": 1000, "order": "asc", **({"after": after} if after else {})},
            )
            response.raise_for_status()
            page = response.json()
            rows.extend(page["data"])
            if not page.get("has_more"):
                break
            cursor = page.get("last_id")
            if not cursor or cursor == after:
                raise ValueError("source snapshot cursor did not advance")
            after = cursor
        else:
            raise ValueError("source snapshot exceeded its page bound")
        canonical = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
        if len(canonical) > 4 * 1024 * 1024:
            raise ValueError("source snapshot exceeded its byte bound")
        result[name] = {
            "count": len(rows),
            "sha256": hashlib.sha256(canonical).hexdigest(),
            "data": rows,
        }
    result["completed_unix_ns"] = time.time_ns()
    return result


def _require_component_binding(
    profile: Mapping[str, object], installed: Mapping[str, str]
) -> None:
    """Bind the installed module receipt without assuming an installation layout."""
    module = profile.get("component_module")
    if (
        not isinstance(module, str)
        or profile.get("component_revision") != installed["revision"]
        or Path(module).resolve() != Path(installed["module"]).resolve()
    ):
        raise ValueError("diagnostic component differs from the pinned install")


async def diagnose_retained_fork(
    state_path: Path, *, teardown_started: asyncio.Event | None = None
) -> dict[str, object]:
    """Replay one original target only after the workflow's formal comparison."""
    import stat

    from dev.benchmarks.omnigent.environment import BenchEnvironment

    report: dict[str, object] = {
        "status": "unavailable",
        "formal_verdict_input": False,
        "started_unix_ns": time.time_ns(),
    }
    try:
        if (
            os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("GITHUB_REPOSITORY") != "Dream1216/omnigent"
        ):
            raise ValueError("diagnostics require the existing downstream CI environment")
        if state_path.name not in {"baseline-fork-state.json", "candidate-fork-state.json"}:
            raise ValueError("state must belong to an original comparison side")
        side = state_path.name.split("-", 1)[0]
        installed = json.loads((state_path.parent / f"{side}-install.json").read_text())
        state = json.loads(state_path.read_text())
        database_uri = state["database_uri"]
        if database_uri != f"sqlite:///{_REPO_ROOT.parent / side / 'bench.db'}":
            raise ValueError("diagnostics require the same-side original CI SQLite corpus")
        root = Path(state["root"])
        if (
            state["schema"] != 1
            or state.get("process_groups_stopped") is not True
            or root.is_symlink()
            or root.parent.resolve() != Path("/tmp").resolve()
            or re.fullmatch(r"omni-bench-[0-9a-f]{8}", root.name) is None
            or root.stat().st_uid != os.getuid()
            or stat.S_IMODE(root.stat().st_mode) != 0o700
        ):
            raise ValueError("retained benchmark root is not qualified")
        sources = state["source_ids"]
        if not sources or any(re.fullmatch(r"[A-Za-z0-9_-]{1,128}", x) is None for x in sources):
            raise ValueError("original fork target is missing or malformed")
        source_id = sources[0]  # The first original setup target, never a cheaper substitute.
        report.update({"original_setup_targets": sources, "selected_setup_ordinal": 0})
        (root / "fork-diagnostic-consumed").touch(exist_ok=False)
        for log in root.glob("*.log"):
            log.rename(log.with_name("formal-" + log.name))
        binding = {"source_id": source_id, "token": uuid.uuid4().hex}
        async with BenchEnvironment(
            with_runner=state["with_runner"],
            with_host=state["with_host"],
            database_uri=state["database_uri"],
            retained_root=root,
            fork_diagnostic_binding=binding,
            diagnostic_router=Path(__file__),
            teardown_started=teardown_started,
        ) as env:
            assert env.client is not None
            report["context"] = "restarted_existing_benchmark_stack_after_formal_comparison"
            async with asyncio.timeout(60):
                before = await _fork_source_snapshot(env.client, source_id)
                report["source_before"] = before
                response = await env.client.post(
                    "/debug/server-metrics",
                    headers={"X-Omnigent-Bench-Diagnostic": binding["token"]},
                    timeout=25,
                )
                response.raise_for_status()
                report["profile"] = response.json()
                profile = report["profile"]
                _require_component_binding(profile, installed)
                after = await _fork_source_snapshot(env.client, source_id)
                stable = all(
                    before[name]["sha256"] == after[name]["sha256"]  # type: ignore[index]
                    for name in ("items", "files")
                )
                report["source_after"] = {
                    name: {k: v for k, v in after[name].items() if k != "data"}  # type: ignore[union-attr]
                    for name in ("items", "files")
                }
                report["source_stable_during_diagnostic"] = stable
                report["status"] = (
                    "complete"
                    if stable and report["profile"].get("status") == "complete"
                    else "incomplete"
                )
    except Exception as error:  # noqa: BLE001 — preserve the independent formal verdict.
        report["error_type"] = type(error).__name__
    report["completed_unix_ns"] = time.time_ns()
    return report


def main() -> int:
    from dev.benchmarks.omnigent.run import _run_until_terminated

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    async def diagnose(teardown_started):
        return await diagnose_retained_fork(args.state, teardown_started=teardown_started), True

    try:
        report, _ = asyncio.run(_run_until_terminated(args, operation=diagnose))
    except asyncio.CancelledError:
        return 128 + signal.SIGTERM
    args.output.write_text(json.dumps(report, indent=2))
    return 0


if __name__ == "omnigent_benchmark_fork_diagnostics":
    from omnigent_benchmark_debug import DEBUG_ROUTERS as DEBUG_ROUTERS
    from omnigent_benchmark_debug import router

    if (_binding := _diagnostic_binding()) is not None:
        install_fork_diagnostic(router, _binding)

if __name__ == "__main__":
    import sys

    sys.path.insert(0, str(_REPO_ROOT))
    raise SystemExit(main())
