from __future__ import annotations

import asyncio
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from saas.scripts.run_litellm_contract import Probe, ProbeFailure, _platform_usage


def _probe(*, mode: str = "protocol_restore", command: tuple[str, ...] = ()) -> Probe:
    return Probe(
        "test-context", "candidate", Path("source.tar"), "amd64", "upstream", command, mode
    )


def test_live_mode_cannot_silently_fall_back_to_simulation() -> None:
    with pytest.raises(ValueError, match="approved credential source"):
        _probe(mode="live_protocol")


@pytest.mark.parametrize("resolver", ("127.0.0.1", "0.0.0.0", "224.0.0.1", "https://dns.test"))
def test_invalid_dns_override_is_rejected(resolver: str) -> None:
    with pytest.raises(ValueError):
        Probe(
            "test", "candidate", Path("source.tar"), "amd64", "upstream", dns_servers=(resolver,)
        )


def test_dns_override_only_applies_to_owned_probe_containers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe = Probe(
        "test",
        "candidate",
        Path("source.tar"),
        "amd64",
        "upstream",
        dns_servers=("192.0.2.53", "2001:db8::53"),
    )
    calls = []

    def docker(*args, **kwargs):
        calls.append(args)
        return "owned-container-id"

    monkeypatch.setattr(probe, "docker", docker)
    name = probe.start("proxy", "candidate")
    assert name == probe.run_id + "-proxy"
    assert calls == [
        (
            "run",
            "--detach",
            "--pull=never",
            "--name",
            name,
            "--label",
            f"omnigent.litellm.probe={probe.run_id}",
            "--network",
            probe.run_id,
            "--dns",
            "192.0.2.53",
            "--dns",
            "2001:db8::53",
            "candidate",
        )
    ]
    assert probe.report["explicit_dns_resolver_count"] == 2
    assert probe.report["production_traffic_changed"] is False


def test_cleanup_never_removes_a_resource_with_different_ownership(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe = _probe()
    probe.names.append("foreign-container")
    calls = []

    def docker(*args, **kwargs):
        calls.append(args)
        if args[0] == "container":
            return "foreign-id"
        if args[0] == "inspect":
            return json.dumps([{"Config": {"Labels": {"omnigent.litellm.probe": "another-run"}}}])
        return ""

    monkeypatch.setattr(probe, "docker", docker)
    probe.cleanup()
    assert not any(call[0] == "rm" for call in calls)
    assert probe.report["cleanup_completed"] is False
    assert probe.report["resources_remaining"] == ["foreign-container"]


def test_cleanup_reclaims_only_its_own_containers_and_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe = _probe()
    probe.names.append(probe.run_id + "-proxy")
    removed = []

    def docker(*args, **kwargs):
        if args[0] == "container" or args[:2] == ("network", "ls"):
            return "owned-id"
        if args[0] == "inspect":
            return json.dumps([{"Config": {"Labels": {"omnigent.litellm.probe": probe.run_id}}}])
        if args[:2] == ("network", "inspect"):
            return json.dumps([{"Labels": {"omnigent.litellm.probe": probe.run_id}}])
        removed.append(args)
        return "removed"

    monkeypatch.setattr(probe, "docker", docker)
    probe.cleanup()
    assert removed == [("rm", "--force", probe.names[0]), ("network", "rm", probe.run_id)]
    assert probe.report["cleanup_completed"] is True


def test_docker_timeout_is_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("docker", 1, output=b"sensitive-provider-details")

    monkeypatch.setattr(subprocess, "run", timeout)
    with pytest.raises(ProbeFailure, match=r"^docker_operation_timed_out$"):
        _probe().docker("info")


def test_invalid_live_credential_source_never_reaches_management(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe = _probe(mode="live_protocol", command=("trusted-source",))

    def source(argv, **kwargs):
        assert argv == ("trusted-source",)
        assert not kwargs.get("shell", False)
        return SimpleNamespace(
            stdout=b'{"provider_id":"not-approved","api_key":"do-not-print","model":"other"}'
        )

    monkeypatch.setattr(subprocess, "run", source)
    with pytest.raises(ProbeFailure, match=r"^provider_credential_source_invalid$"):
        asyncio.run(probe.live_contract("http://127.0.0.1:4000"))
    assert "do-not-print" not in json.dumps(probe.report)


@pytest.mark.parametrize("responses", (False, True))
@pytest.mark.parametrize("terminal", (False, True))
def test_platform_usage_contract_requires_the_selected_wire_terminal(responses, terminal):
    if responses:
        event = {
            "type": "response.completed" if terminal else "response.in_progress",
            "response": {
                "usage": {
                    "input_tokens": 17,
                    "output_tokens": 5,
                    "total_tokens": 22,
                    "input_tokens_details": {"cached_tokens": 9},
                }
            },
        }
        body = b"data: " + json.dumps(event).encode() + b"\n\n"
    else:
        event = {
            "choices": [{"index": 0, "delta": {"role": "assistant", "content": ""}}],
            "usage": {
                "prompt_tokens": 17,
                "completion_tokens": 5,
                "total_tokens": 22,
                "prompt_tokens_details": {"cached_tokens": 9},
            },
        }
        body = b"data: " + json.dumps(event).encode() + b"\n\n"
        if terminal:
            body += b"data: [DONE]\n\n"
    expected = {
        "total_tokens": 22,
        "cache_hit_tokens": 9,
        "cache_miss_tokens": 8,
        "completion_tokens": 5,
    }
    unknown = dict.fromkeys(expected)
    assert _platform_usage(body, responses=responses) == (expected if terminal else unknown)
    assert _platform_usage(body, responses=not responses) == unknown
