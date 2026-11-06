"""Actual libc locale initialization and ordering at production entry boundaries."""

import importlib
import json
import locale
import os
import subprocess
import sys
from pathlib import Path

import pytest

from saas.production import runtime_locale

KEYS = ("LANG", "LC_ALL", "LC_MESSAGES", "LANGUAGE", "LOCPATH")
POISON = dict.fromkeys(KEYS, "fr_FR.UTF-8") | {
    "LANGUAGE": "../../synthetic-catalog:fr",
    "LOCPATH": "/nonexistent/synthetic-locale",
}


@pytest.mark.skipif(sys.platform != "linux", reason="actual Linux libc locale contract")
def test_actual_linux_entry_removes_catalog_inputs_and_initializes_utf8_messages() -> None:
    root = Path(__file__).resolve().parents[2]
    program = (
        "import json,locale,os,sys;"
        f"sys.path.insert(0,{str(root)!r});"
        "from saas.production.runtime_locale import initialize_production_locale;"
        "initialize_production_locale();"
        "print(json.dumps({'messages':locale.setlocale(locale.LC_MESSAGES),"
        "'encoding':locale.getencoding(),"
        f"'environment':{{k:os.environ.get(k) for k in {KEYS!r}}},"
        "'unrelated':os.environ.get('SYNTHETIC_UNRELATED')}))"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", program],
        env={"PATH": os.defpath, **POISON, "SYNTHETIC_UNRELATED": "preserved"},
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
    )
    observed = json.loads(result.stdout)
    assert observed["messages"] in {"C.UTF-8", "C.utf8"}
    assert observed["encoding"].lower().replace("-", "") == "utf8"
    assert observed["environment"] == dict.fromkeys(KEYS[:3], "C.UTF-8") | dict.fromkeys(KEYS[3:])
    assert observed["unrelated"] == "preserved"


def test_runtime_locale_import_has_no_environment_or_locale_side_effect() -> None:
    root = Path(__file__).resolve().parents[2]
    program = (
        "import locale,os,sys;"
        f"sys.path.insert(0,{str(root)!r});"
        "before=(dict(os.environ),locale.setlocale(locale.LC_ALL));"
        "import saas.production.runtime_locale;"
        "assert before==(dict(os.environ),locale.setlocale(locale.LC_ALL))"
    )
    subprocess.run(
        [sys.executable, "-I", "-B", "-c", program],
        env={"PATH": os.defpath, **POISON},
        capture_output=True,
        check=True,
        timeout=15,
    )


def test_other_platform_is_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    for key, value in POISON.items():
        monkeypatch.setenv(key, value)
    before = dict(os.environ), locale.setlocale(locale.LC_ALL)
    runtime_locale.initialize_production_locale()
    assert before == (dict(os.environ), locale.setlocale(locale.LC_ALL))


@pytest.mark.parametrize(
    ("module", "loader"),
    [
        ("server", "load_production_server_config"),
        ("worker", "load_production_worker_config"),
        ("preview_edge", "load_production_preview_edge_config"),
        ("preview_owner", "load_production_preview_owner_config"),
        ("runner_agent", "load_production_runner_agent_config"),
        ("runner_control", "load_production_runner_control_config"),
    ],
)
def test_each_actual_entry_initializes_before_config(
    monkeypatch: pytest.MonkeyPatch, module: str, loader: str
) -> None:
    entry = importlib.import_module("saas.production." + module)
    calls = []

    class BeforeConfig(Exception):
        pass

    def initialize() -> None:
        calls.append("locale")

    def load():
        assert calls == ["locale"]
        raise BeforeConfig

    monkeypatch.setattr(runtime_locale, "initialize_production_locale", initialize)
    monkeypatch.setattr(entry, loader, load)
    with pytest.raises(BeforeConfig):
        entry.main()


def test_unsupported_locale_fails_before_trusting_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    for key, value in POISON.items():
        monkeypatch.setenv(key, value)

    def unavailable(category, value=None):
        assert category == locale.LC_ALL and value == "C.UTF-8"
        assert "LANGUAGE" not in os.environ and "LOCPATH" not in os.environ
        raise locale.Error("synthetic missing locale")

    monkeypatch.setattr(locale, "setlocale", unavailable)
    with pytest.raises(locale.Error, match="synthetic missing locale"):
        runtime_locale.initialize_production_locale()


@pytest.mark.parametrize("fault", ["messages", "encoding"])
def test_unexpected_effective_locale_or_encoding_is_rejected(
    monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    for key, value in POISON.items():
        monkeypatch.setenv(key, value)

    def selected(category, value=None):
        if value is not None:
            return "C.UTF-8"
        assert category == locale.LC_MESSAGES
        return "fr_FR.UTF-8" if fault == "messages" else "C.UTF-8"

    monkeypatch.setattr(locale, "setlocale", selected)
    monkeypatch.setattr(locale, "getencoding", lambda: "ASCII" if fault == "encoding" else "UTF-8")
    with pytest.raises(RuntimeError, match=r"requires C\.UTF-8 messages and UTF-8 encoding"):
        runtime_locale.initialize_production_locale()
