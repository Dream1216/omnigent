from __future__ import annotations

import hashlib
import io
from pathlib import Path

import pytest

from saas.scripts import materialize_debian_snapshot_packages as packages


def line(payload: bytes = b"locked package") -> str:
    return (
        "'https://snapshot.debian.org/archive/debian/20261005T000000Z/"
        "pool/main/t/tool/tool_1.0_amd64.deb' tool_1.0_amd64.deb "
        f"{len(payload)} SHA256:{hashlib.sha256(payload).hexdigest()}"
    )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.replace("SHA256:", "MD5Sum:"),
        lambda value: value.replace("https:", "http:"),
        lambda value: value.replace("20261005T000000Z", "latest"),
        lambda value: value.replace("pool/main/", "pool/../"),
        lambda value: value.replace(" tool_1.0_amd64.deb ", " ../bad.deb "),
        lambda value: value.replace(" tool_1.0_amd64.deb ", " tool_1%2f0_amd64.deb "),
        lambda value: value + "\n" + value,
    ],
)
def test_input_drift_rejected(mutate) -> None:
    with pytest.raises(ValueError):
        packages.parse_inputs(mutate(line()))


def test_verified_download_is_exported(tmp_path: Path, monkeypatch) -> None:
    payload = b"locked package"
    monkeypatch.setattr(
        packages.urllib.request, "urlopen", lambda *args, **kwargs: io.BytesIO(payload)
    )
    item = packages.parse_inputs(line(payload))[0]
    assert packages.fetch(item, tmp_path) == item
    assert (tmp_path / str(item["name"])).read_bytes() == payload
    assert list(tmp_path.iterdir()) == [tmp_path / str(item["name"])]


def test_apt_epoch_cache_filename_is_preserved() -> None:
    value = line().replace(" tool_1.0_amd64.deb ", " tool_2%3a1.0_amd64.deb ")
    assert packages.parse_inputs(value)[0]["name"] == "tool_2%3a1.0_amd64.deb"


def test_bad_download_never_exports(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        packages.urllib.request, "urlopen", lambda *args, **kwargs: io.BytesIO(b"bad")
    )
    with pytest.raises(ValueError):
        packages.fetch(packages.parse_inputs(line())[0], tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_existing_cache_is_verified(tmp_path: Path) -> None:
    item = packages.parse_inputs(line())[0]
    (tmp_path / str(item["name"])).write_bytes(b"bad")
    with pytest.raises(ValueError):
        packages.fetch(item, tmp_path)


def test_cache_symlink_is_rejected(tmp_path: Path) -> None:
    item = packages.parse_inputs(line())[0]
    source = tmp_path / "source"
    source.write_bytes(b"locked package")
    (tmp_path / str(item["name"])).symlink_to(source)
    with pytest.raises(ValueError):
        packages.fetch(item, tmp_path)
