"""Observe one isolated interrupt path without qualifying performance or a release."""

from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import tempfile
import time
from pathlib import Path

from dev.benchmarks.omnigent.environment import BenchEnvironment
from dev.benchmarks.omnigent.journeys import resolve_journeys, run_latency

_BASE = "ddcc2fda36de155575d4374abac16fa1f660fd07"
_ROUTER = """from omnigent_benchmark_debug import DEBUG_ROUTERS
import json
import threading
import time
from omnigent.server import session_live_state
from omnigent.server.routes import sessions
from omnigent.stores.conversation_store.sqlalchemy_store import SqlAlchemyConversationStore

local = threading.local()
original_get = SqlAlchemyConversationStore.get_conversation
original_index = SqlAlchemyConversationStore.get_runner_host_ids
original_native = sessions._is_native_terminal_session
original_record = session_live_state.record_recovery_turn

def timed(stage, action, *args, **kwargs):
    spans = getattr(local, "spans", None)
    if spans is None:
        return action(*args, **kwargs)
    start = time.perf_counter_ns()
    result = None
    try:
        result = action(*args, **kwargs)
        return result
    finally:
        row = {"stage": stage, "ns": time.perf_counter_ns() - start}
        if stage == "conversation":
            row["host_present"] = bool(result and result.host_id)
            row["parent_present"] = bool(result and result.parent_conversation_id)
        elif stage == "runner_index":
            row["host_binding_present"] = bool(result)
        spans.append(row)

def observed_get(*args, **kwargs):
    return timed("conversation", original_get, *args, **kwargs)

def observed_index(*args, **kwargs):
    return timed("runner_index", original_index, *args, **kwargs)

def observed_native(*args, **kwargs):
    return timed("native", original_native, *args, **kwargs)

def observed_record(*args, **kwargs):
    previous = getattr(local, "spans", None)
    spans = []
    local.spans = spans
    start = time.perf_counter_ns()
    try:
        return original_record(*args, **kwargs)
    finally:
        duration = time.perf_counter_ns() - start
        local.spans = previous
        print("INTERRUPT_DIAGNOSTIC " + json.dumps({"start_ns": start, "recovery_ns": duration,
            "finished": kwargs.get("finished"), "spans": spans}), flush=True)

SqlAlchemyConversationStore.get_conversation = observed_get
SqlAlchemyConversationStore.get_runner_host_ids = observed_index
sessions._is_native_terminal_session = observed_native
session_live_state.record_recovery_turn = observed_record

import importlib
events = importlib.import_module("omnigent.server.routes.sessions.routes_events")
original_control = events._get_runner_client
async def observed_control(*args, **kwargs):
    start = time.perf_counter_ns()
    try:
        return await original_control(*args, **kwargs)
    finally:
        if kwargs.get("for_control"):
            print("CONTROL_DIAGNOSTIC " + json.dumps({
                "start_ns": start, "control_ns": time.perf_counter_ns() - start,
                "loaded_conversation": kwargs.get("conversation") is not None}), flush=True)
events._get_runner_client = observed_control
"""


async def observe(output: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    subprocess.run(["git", "diff", "--exit-code", _BASE, "--", "omnigent"], cwd=root, check=True)
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    output.mkdir(parents=True, exist_ok=True)
    router = output / "interrupt-router.py"
    router.write_text(_ROUTER)
    client_rows: list[dict[str, int | str]] = []
    probe_root = Path(tempfile.mkdtemp(prefix="oi-"))
    async with BenchEnvironment(
        with_runner=True,
        with_host=True,
        retained_root=probe_root,
        fork_state_path=output / "stopped-process-state.json",
        fork_diagnostic_binding={"kind": "interrupt_observation"},
        diagnostic_router=router,
    ) as env:
        assert env.client is not None
        original_interrupt = env.interrupt_gated_turn
        original_post = env.client.post

        def stamp(phase: str) -> None:
            client_rows.append({"phase": phase, "ns": time.perf_counter_ns()})

        async def observed_post(*args, **kwargs):
            response = await original_post(*args, **kwargs)
            if kwargs.get("json", {}).get("type") == "interrupt":
                stamp("post_return")
            return response

        async def observed_interrupt(turn, *, timeout=180.0):
            original_set = turn.idle.set

            def observed_idle() -> None:
                if not turn.idle.is_set():
                    stamp("idle_seen")
                original_set()

            turn.idle.set = observed_idle
            stamp("start")
            await original_interrupt(turn, timeout=timeout)
            stamp("end")

        env.client.post = observed_post
        env.interrupt_gated_turn = observed_interrupt
        result = await run_latency(
            resolve_journeys(["interrupt"])[0], env, iterations=10, warmup=1
        )
        server_rows = [
            json.loads(line.split("INTERRUPT_DIAGNOSTIC ", 1)[1])
            for line in (probe_root / "server.log").read_text().splitlines()
            if line.startswith("INTERRUPT_DIAGNOSTIC ")
        ]
        control_rows = [
            json.loads(line.split("CONTROL_DIAGNOSTIC ", 1)[1])
            for line in (probe_root / "server.log").read_text().splitlines()
            if line.startswith("CONTROL_DIAGNOSTIC ")
        ]
        record = {
            "diagnostic_only": True,
            "production_slo_or_release_qualification": False,
            "diagnostic_head": head,
            "runtime_source_base": _BASE,
            "runtime_source_bytes_unchanged": True,
            "client": client_rows,
            "server": server_rows,
            "control": control_rows,
            "sample_ms": result.latencies_ms,
            "failure_count": sum(result.failures.values()),
        }
        (output / "interrupt-observation.json").write_text(json.dumps(record, indent=2) + "\n")
        assert server_rows and client_rows and control_rows and not result.failures


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    asyncio.run(observe(args.output.resolve()))


if __name__ == "__main__":
    main()
