from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from saas.production.service_bindings import (
    EXPECTED_PRODUCTION_SERVICE_ROLES,
    ProductionServiceRoleBinding,
    ProductionServiceRoleBindingsError,
    load_production_service_role_bindings,
    render_production_service_role_bindings,
)


def _bindings() -> tuple[ProductionServiceRoleBinding, ...]:
    return tuple(
        ProductionServiceRoleBinding(
            service=service,
            login=f"prod_{service}",
            base_role=base_role,
        )
        for service, base_role in sorted(EXPECTED_PRODUCTION_SERVICE_ROLES.items())
    )


def _write(path: Path, rendered: str, *, mode: int = 0o400) -> dict[str, str]:
    path.write_text(rendered, encoding="ascii")
    path.chmod(mode)
    return {"OMNIGENT_SAAS_SERVICE_ROLE_BINDINGS_FILE": str(path)}


def test_loads_exact_ten_binding_canonical_profile(tmp_path: Path) -> None:
    bindings = _bindings()
    rendered = render_production_service_role_bindings(tuple(reversed(bindings)))
    assert rendered == render_production_service_role_bindings(bindings)
    loaded = load_production_service_role_bindings(
        _write(tmp_path / "service-bindings.json", rendered)
    )

    assert len(loaded.bindings) == 10
    assert loaded.login_for("runtime") == "prod_runtime"
    assert loaded.login_for("dispatcher") == "prod_dispatcher"
    assert loaded.login_for("executor") == "prod_executor"
    assert loaded.sha256 == hashlib.sha256(rendered.encode("ascii")).hexdigest()
    assert set(loaded.by_service) == set(EXPECTED_PRODUCTION_SERVICE_ROLES)


def test_rejects_noncanonical_or_mutable_binding_file(tmp_path: Path) -> None:
    bindings = _bindings()
    noncanonical = json.dumps(
        {
            "schema_version": 1,
            "bindings": [
                {
                    "service": binding.service,
                    "login": binding.login,
                    "base_role": binding.base_role,
                }
                for binding in reversed(bindings)
            ],
        },
        indent=2,
    )
    with pytest.raises(ProductionServiceRoleBindingsError, match="canonical JSON"):
        load_production_service_role_bindings(_write(tmp_path / "noncanonical.json", noncanonical))

    with pytest.raises(ProductionServiceRoleBindingsError, match="owner-readable"):
        load_production_service_role_bindings(
            _write(
                tmp_path / "mutable.json",
                render_production_service_role_bindings(bindings),
                mode=0o600,
            )
        )


@pytest.mark.parametrize("mutation", ["missing", "duplicate_login", "wrong_base", "extra_key"])
def test_rejects_profile_drift(tmp_path: Path, mutation: str) -> None:
    document = json.loads(render_production_service_role_bindings(_bindings()))
    if mutation == "missing":
        document["bindings"].pop()
    elif mutation == "duplicate_login":
        document["bindings"][1]["login"] = document["bindings"][0]["login"]
    elif mutation == "wrong_base":
        document["bindings"][0]["base_role"] = "saas_wrong"
    else:
        document["bindings"][0]["unexpected"] = True
    rendered = json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"

    with pytest.raises(ProductionServiceRoleBindingsError):
        load_production_service_role_bindings(_write(tmp_path / f"{mutation}.json", rendered))
