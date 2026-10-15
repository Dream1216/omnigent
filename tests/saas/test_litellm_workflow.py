from __future__ import annotations

from pathlib import Path

import yaml


def test_component_lane_uses_native_runners_and_cannot_publish_or_use_vendor_secrets():
    path = Path(__file__).resolve().parents[2] / ".github/workflows/litellm-contract.yml"
    document = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
    assert document["permissions"] == {"contents": "read"}
    assert set(document["on"]) == {"push", "workflow_dispatch"}
    job = document["jobs"]["native-contract"]
    assert job["strategy"]["matrix"]["include"] == [
        {"arch": "amd64", "runner": "ubuntu-24.04"},
        {"arch": "arm64", "runner": "ubuntu-24.04-arm"},
    ]
    source = path.read_text()
    assert "real-provider-command" not in source
    assert "secrets." not in source
    assert "docker push" not in source
    assert "--skip" not in source
    assert "setup-qemu" not in source
    assert '.execution_mode == "native"' in source
    assert ".production_traffic_changed == false" in source
    assert ".real_provider_tested == false" in source
    assert document["concurrency"]["cancel-in-progress"] == "false"
