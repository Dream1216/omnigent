from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from saas.production.service_bindings import (
    EXPECTED_PLATFORM_ADMIN_SERVICE_ROLES,
    EXPECTED_PLATFORM_MODEL_SERVICE_ROLES,
    EXPECTED_PRODUCTION_SERVICE_ROLES,
    ProductionServiceRoleBinding,
    ProductionServiceRoleBindings,
    ProductionServiceRoleBindingsError,
    compose_production_service_role_graph,
    load_platform_admin_service_role_bindings,
    load_platform_model_service_role_bindings,
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


def _platform_model_bindings() -> tuple[ProductionServiceRoleBinding, ...]:
    return tuple(
        ProductionServiceRoleBinding(
            service=service,
            login=f"next_beta_{service}",
            base_role=base_role,
        )
        for service, base_role in sorted(EXPECTED_PLATFORM_MODEL_SERVICE_ROLES.items())
    )


def _platform_admin_bindings() -> tuple[ProductionServiceRoleBinding, ...]:
    return tuple(
        ProductionServiceRoleBinding(
            service=service,
            login=f"next_beta_{service}",
            base_role=base_role,
        )
        for service, base_role in sorted(EXPECTED_PLATFORM_ADMIN_SERVICE_ROLES.items())
    )


def _write(path: Path, rendered: str, *, mode: int = 0o400) -> dict[str, str]:
    path.write_text(rendered, encoding="ascii")
    path.chmod(mode)
    return {"OMNIGENT_SAAS_SERVICE_ROLE_BINDINGS_FILE": str(path)}


def test_loads_exact_fifteen_binding_canonical_profile(tmp_path: Path) -> None:
    bindings = _bindings()
    rendered = render_production_service_role_bindings(tuple(reversed(bindings)))
    assert rendered == render_production_service_role_bindings(bindings)
    loaded = load_production_service_role_bindings(
        _write(tmp_path / "service-bindings.json", rendered)
    )

    assert len(loaded.bindings) == 15
    assert loaded.login_for("runtime") == "prod_runtime"
    assert loaded.login_for("dispatcher") == "prod_dispatcher"
    assert loaded.login_for("executor") == "prod_executor"
    assert loaded.login_for("registration") == "prod_registration"
    assert loaded.login_for("onboarding") == "prod_onboarding"
    assert loaded.login_for("onboarding_status") == "prod_onboarding_status"
    assert loaded.login_for("runtime_provider_journal") == ("prod_runtime_provider_journal")
    assert loaded.sha256 == hashlib.sha256(rendered.encode("ascii")).hexdigest()
    assert set(loaded.by_service) == set(EXPECTED_PRODUCTION_SERVICE_ROLES)


def test_loads_isolated_platform_model_binding_profile(tmp_path: Path) -> None:
    rendered = render_production_service_role_bindings(_platform_model_bindings())
    path = tmp_path / "platform-model-service-bindings.json"
    path.write_text(rendered, encoding="ascii")
    path.chmod(0o400)

    loaded = load_platform_model_service_role_bindings(
        {"OMNIGENT_SAAS_PLATFORM_MODEL_SERVICE_ROLE_BINDINGS_FILE": str(path)}
    )

    assert len(loaded.bindings) == 5
    assert loaded.login_for("billing") == "next_beta_billing"
    assert loaded.login_for("platform_app") == "next_beta_platform_app"
    assert set(loaded.by_service) == set(EXPECTED_PLATFORM_MODEL_SERVICE_ROLES)

    production_path = tmp_path / "production-service-bindings.json"
    production_path.write_text(
        render_production_service_role_bindings(_bindings()),
        encoding="ascii",
    )
    production_path.chmod(0o400)
    with pytest.raises(ProductionServiceRoleBindingsError, match="exact production"):
        load_platform_model_service_role_bindings(
            {"OMNIGENT_SAAS_PLATFORM_MODEL_SERVICE_ROLE_BINDINGS_FILE": str(production_path)}
        )


def test_loads_isolated_platform_admin_binding_profile(tmp_path: Path) -> None:
    rendered = render_production_service_role_bindings(_platform_admin_bindings())
    path = tmp_path / "platform-admin-service-bindings.json"
    path.write_text(rendered, encoding="ascii")
    path.chmod(0o400)

    loaded = load_platform_admin_service_role_bindings(
        {"OMNIGENT_SAAS_PLATFORM_ADMIN_SERVICE_ROLE_BINDINGS_FILE": str(path)}
    )

    assert len(loaded.bindings) == 3
    assert loaded.login_for("platform_authenticator") == "next_beta_platform_authenticator"
    assert loaded.login_for("platform_app") == "next_beta_platform_app"
    assert loaded.login_for("platform_governance") == "next_beta_platform_governance"
    assert set(loaded.by_service) == set(EXPECTED_PLATFORM_ADMIN_SERVICE_ROLES)


def test_composes_exact_platform_model_extension_without_weakening_core() -> None:
    production = ProductionServiceRoleBindings(
        path=Path("/production.json"),
        sha256="a" * 64,
        bindings=_bindings(),
    )
    production_by_service = production.by_service
    platform = ProductionServiceRoleBindings(
        path=Path("/platform.json"),
        sha256="b" * 64,
        bindings=tuple(
            production_by_service[service]
            if service in production_by_service
            else ProductionServiceRoleBinding(
                service=service,
                login=f"next_beta_{service}",
                base_role=base_role,
            )
            for service, base_role in sorted(EXPECTED_PLATFORM_MODEL_SERVICE_ROLES.items())
        ),
    )

    graph = compose_production_service_role_graph(production, platform)

    assert len(graph.bindings) == 17
    assert graph.login_for("app") == "prod_app"
    assert graph.login_for("billing") == "next_beta_billing"
    assert graph.login_for("platform_app") == "next_beta_platform_app"
    assert (
        graph.sha256
        == hashlib.sha256(
            render_production_service_role_bindings(graph.bindings).encode("ascii")
        ).hexdigest()
    )

    platform_by_service = platform.by_service
    platform_admin = ProductionServiceRoleBindings(
        path=Path("/platform-admin.json"),
        sha256="c" * 64,
        bindings=tuple(
            production_by_service[service]
            if service in production_by_service
            else platform_by_service[service]
            if service in platform_by_service
            else ProductionServiceRoleBinding(
                service=service,
                login=f"next_beta_{service}",
                base_role=base_role,
            )
            for service, base_role in sorted(EXPECTED_PLATFORM_ADMIN_SERVICE_ROLES.items())
        ),
    )
    extended = compose_production_service_role_graph(production, platform, platform_admin)
    assert len(extended.bindings) == 18
    assert extended.login_for("platform_authenticator") == "next_beta_platform_authenticator"
    assert extended.login_for("platform_app") == "next_beta_platform_app"
    assert extended.login_for("platform_governance") == "prod_platform_governance"


def test_composition_rejects_changed_overlap_and_reused_login() -> None:
    production = ProductionServiceRoleBindings(
        path=Path("/production.json"),
        sha256="a" * 64,
        bindings=_bindings(),
    )
    changed_overlap = ProductionServiceRoleBindings(
        path=Path("/platform.json"),
        sha256="b" * 64,
        bindings=(ProductionServiceRoleBinding("app", "another_app", "saas_app"),),
    )
    with pytest.raises(ProductionServiceRoleBindingsError, match="different bindings"):
        compose_production_service_role_graph(production, changed_overlap)

    reused_login = ProductionServiceRoleBindings(
        path=Path("/platform.json"),
        sha256="b" * 64,
        bindings=(ProductionServiceRoleBinding("billing", "prod_runtime", "saas_billing"),),
    )
    with pytest.raises(ProductionServiceRoleBindingsError, match="reuse a login"):
        compose_production_service_role_graph(production, reused_login)


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
