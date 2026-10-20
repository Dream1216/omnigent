"""Trusted Server composition of the interactive Runner controller; opt-in only."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import ssl
from collections.abc import Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit
from uuid import UUID

import sqlalchemy as sa
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from sqlalchemy.orm import sessionmaker

from saas.control_plane.interactive_run_route import interactive_session_identity
from saas.production.interactive_controller import ProductionInteractiveExecutor, _unavailable
from saas.production.interactive_driver import OfficialInteractiveDriver
from saas.production.interactive_model_channel import (
    SessionModelChannelMiddleware,
    SessionModelChannels,
)
from saas.production.interactive_recovery import (
    InteractiveRecoveryJournal,
    UnstartedInteractiveRecoveryRecord,
    physical_recovery_proof_sha256,
)
from saas.production.runner_agent import (
    ProductionRunnerAgent,
    _secure_file,
    build_runner_client,
    load_production_runner_agent_config,
    verify_installed_runner_agent_lineage,
)
from saas.production.runner_control import RunnerControlError, runner_identity_from_certificate
from saas.production.runner_executor import _runner_agent_database_login
from saas.production.runner_readiness import build_remote_tls_runner_control_readiness
from saas.production.server_config import load_production_database_url_file
from saas.runner_adapter.metering import ManagedMeteringGrant

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class InteractiveMeteringCredentials:
    ca: Path
    certificate: Path
    key: Path


def load_interactive_metering_credentials(
    source: Mapping[str, str], *, runner_id: UUID, control_certificate: Path
) -> InteractiveMeteringCredentials:
    """Control and Billing require separately registered purpose-bound leaves."""
    try:
        ca = _secure_file(source, "OMNIGENT_SAAS_INTERACTIVE_METERING_CA_FILE", secret=False)
        certificate = _secure_file(
            source, "OMNIGENT_SAAS_INTERACTIVE_METERING_CLIENT_CERTIFICATE_FILE", secret=False
        )
        key = _secure_file(
            source, "OMNIGENT_SAAS_INTERACTIVE_METERING_CLIENT_KEY_FILE", secret=True
        )
        leaf = certificate.read_bytes()
        fingerprint = x509.load_pem_x509_certificate(leaf).fingerprint(hashes.SHA256())
        control_fingerprint = x509.load_pem_x509_certificate(
            control_certificate.read_bytes()
        ).fingerprint(hashes.SHA256())
        if (
            runner_identity_from_certificate(leaf) != runner_id
            or fingerprint == control_fingerprint
        ):
            raise _unavailable()
        tls = ssl.create_default_context(cafile=str(ca))
        tls.minimum_version = ssl.TLSVersion.TLSv1_3
        tls.load_cert_chain(str(certificate), str(key))
    except (OSError, ValueError, RunnerControlError):
        raise _unavailable() from None
    return InteractiveMeteringCredentials(ca, certificate, key)


class ProductionInteractiveControllerAdapter:
    def __init__(self, *, config, source):
        self._release, self._source = config, dict(source)
        self._readiness = build_remote_tls_runner_control_readiness(config=config)
        # Server authority stays in the trusted composition; no App DSN enters a workload.
        selected = {
            key: value for key, value in source.items() if key.startswith("OMNIGENT_SAAS_RUNNER_")
        }
        selected.update(
            OMNIGENT_SAAS_PRODUCT_REVISION=config.product_revision,
            OMNIGENT_SAAS_SOURCE_SHA=config.product_revision,
            OMNIGENT_SAAS_IMAGE_DIGEST=config.image_digest,
            OMNIGENT_SAAS_RUNNER_EXECUTOR_FACTORY="saas.production.interactive_controller:ProductionInteractiveExecutor",
        )
        self._config = load_production_runner_agent_config(selected)
        verify_installed_runner_agent_lineage(self._config)
        database_url, parsed, _ = load_production_database_url_file(selected, "runner_agent")
        if parsed.username != _runner_agent_database_login(
            self._config.runner_id, self._config.connection_generation
        ):
            raise _unavailable()
        self._engine = sa.create_engine(
            database_url, pool_pre_ping=True, pool_size=4, max_overflow=4
        )
        self._sessions = sessionmaker(self._engine, expire_on_commit=False)
        try:
            self._client = build_runner_client(self._config)
        except Exception:
            self._engine.dispose()
            raise
        self._task: asyncio.Task | None = None
        self._bound = False
        self._executor = None
        self._journal = None
        self._installed = False

    def assert_production_ready(self) -> None:
        self._readiness.assert_production_ready()
        # Composition probes dependencies before binding the app lifespan.
        if not self._installed:
            return
        if not self._bound or self._executor is None or self._task is None or self._task.done():
            raise _unavailable()
        self._executor.assert_production_ready()

    async def stop_session(self, conversation, context, cancel_inputs):
        # Stopping owned work must not require spare admission capacity.
        if not self._bound or self._executor is None or self._task is None or self._task.done():
            raise _unavailable()
        return await self._executor.stop_session(
            context, conversation.id, conversation.runner_id, cancel_inputs
        )

    def bind_runtime(self, *, app, runtime, official, auth_provider) -> None:
        del auth_provider
        if self._installed:
            raise _unavailable()
        try:
            self._bind_runtime(app=app, runtime=runtime, official=official)
        except Exception:
            self.close()
            raise
        self._installed = True

    def _bind_runtime(self, *, app, runtime, official) -> None:
        source = self._source
        url = source.get("OMNIGENT_SAAS_INTERACTIVE_METERING_URL", "")
        parsed = urlsplit(url)
        root = Path(source.get("OMNIGENT_SAAS_INTERACTIVE_RECOVERY_DIRECTORY", ""))
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or not root.is_absolute()
        ):
            raise _unavailable()
        cfg = self._config
        metering = load_interactive_metering_credentials(
            source, runner_id=cfg.runner_id, control_certificate=cfg.client_certificate_path
        )
        journal = InteractiveRecoveryJournal(root)
        self._journal = journal
        authority = runtime.create_authority(
            identity=cfg, control=self._client, runner_sessions=self._sessions, fleet_source=source
        )
        channels = SessionModelChannels(public_origin=self._release.public_origin)
        driver = OfficialInteractiveDriver(
            app=app, dependencies=official, contract_version=self._release.adapter_contract_version
        )
        from saas.production.interactive_managed_lifecycle import protect_managed_deployment

        protect_managed_deployment(app.state.sandbox_config, journal)

        async def authorize(lease):
            return await runtime.authorize_model(
                lease=lease,
                identity=cfg,
                control=self._client,
                runner_sessions=self._sessions,
                fleet_source=source,
            )

        def grant(authorized, lease):
            context = authorized.runtime
            return ManagedMeteringGrant(
                session_id=interactive_session_identity(
                    context.tenant_id,
                    context.space_id,
                    context.runtime_partition_id,
                    authorized.session_id,
                ),
                run_id=lease.run_id,
                runner_id=cfg.runner_id,
                capability_token=lease.capability_token,
                expires_at=lease.expires_at,
                metering_base_url=url,
                expected_host=parsed.hostname,
                ca_certificate_path=metering.ca,
                client_certificate_path=metering.certificate,
                client_key_path=metering.key,
                spool_directory=journal.root / "usage" / str(lease.run_id),
            )

        async def verify_recovery(record):
            if isinstance(record, UnstartedInteractiveRecoveryRecord):
                if record.runner_id != cfg.runner_id:
                    raise _unavailable()
                await self._client.heartbeat_runner()
                return
            if (
                record.grant.metering_base_url != url
                or record.grant.expected_host != parsed.hostname
                or record.grant.ca_certificate_path != metering.ca
                or record.grant.client_certificate_path != metering.certificate
                or record.grant.client_key_path != metering.key
                or record.grant.spool_directory != journal.root / "usage" / str(record.run_id)
            ):
                raise _unavailable()
            await self._client.heartbeat_runner()
            await asyncio.to_thread(authority.verify_recovery, record)

        def assert_authority():
            runtime.create_authority(
                identity=cfg,
                control=self._client,
                runner_sessions=self._sessions,
                fleet_source=source,
            )

        async def confirm_recovery(record):
            await self._client.confirm_interactive_recovery(
                run_id=record.run_id,
                fence_token=record.fence_token,
                capability_token=record.capability_token
                if isinstance(record, UnstartedInteractiveRecoveryRecord)
                else record.grant.capability_token,
                proof_sha256=physical_recovery_proof_sha256(record),
                cleanup_kind="never_started"
                if isinstance(record, UnstartedInteractiveRecoveryRecord)
                or record.stop_kind == "never_started"
                else "physical_stop",
            )

        async def inspect_revocation(record):
            return await self._client.inspect_interactive_recovery(
                run_id=record.run_id,
                fence_token=record.fence_token,
                capability_token=record.grant.capability_token,
            )

        async def verify_released(record):
            # This RPC checks the original authenticated dispatch is terminal and released.
            await inspect_revocation(record)

        executor = ProductionInteractiveExecutor(
            authorize_model=authorize,
            grant_for_run=grant,
            driver=driver,
            journal=journal,
            recovery_certificate_path=metering.certificate,
            channels=channels,
            connection_generation=cfg.connection_generation,
            product_revision=cfg.product_revision,
            image_digest=cfg.image_digest,
            assert_authority=assert_authority,
            verify_recovery=verify_recovery,
            confirm_recovery=confirm_recovery,
            verify_released=verify_released,
            inspect_revocation=inspect_revocation,
        )
        self._executor = executor

        from saas.production.interactive_managed_retirement import ControllerManagedSandboxReaper

        app.state.managed_sandbox_reaper_factory = lambda **kwargs: ControllerManagedSandboxReaper(
            executor=executor, driver=driver, **kwargs
        )

        app.state.production_interactive_conversation_store.runtime_readiness_check = (
            self.assert_production_ready
        )
        app.state.production_interactive_conversation_store.session_stop_handler = (
            self.stop_session
        )
        app.state.production_interactive_conversation_store.runtime_status_observer = (
            driver.observe_runtime_status
        )
        app.add_middleware(SessionModelChannelMiddleware, channels=channels)
        original = app.router.lifespan_context

        async def recover_and_run(stop):
            # Host ingress must be listening before stranded processes can be stopped.
            while not stop.is_set():
                try:
                    await executor.reconcile_physical_gc(limit=cfg.physical_gc_limit)
                    await asyncio.to_thread(executor.assert_claimable)
                except RunnerControlError as error:
                    if error.code != "interactive_controller_recovery_pending":
                        raise
                    try:
                        await asyncio.wait_for(
                            stop.wait(), timeout=max(1, cfg.poll_interval_seconds)
                        )
                    except TimeoutError:
                        continue
                    return
                break
            if stop.is_set():
                return
            agent = ProductionRunnerAgent(
                self._client,
                executor,
                poll_interval_seconds=cfg.poll_interval_seconds,
                heartbeat_interval_seconds=cfg.heartbeat_interval_seconds,
                shutdown_timeout_seconds=cfg.shutdown_timeout_seconds,
                physical_gc_interval_seconds=cfg.physical_gc_interval_seconds,
                physical_gc_limit=cfg.physical_gc_limit,
            )
            self._bound = True
            try:
                await agent.run(stop)
            finally:
                self._bound = False

        @asynccontextmanager
        async def lifespan(instance):
            stop = asyncio.Event()
            try:
                async with original(instance) as state:
                    self._task = asyncio.create_task(
                        recover_and_run(stop), name="production-interactive-controller"
                    )
                    self._task.add_done_callback(self._finished)
                    yield state
            finally:
                self._bound = False
                stop.set()
                try:
                    if self._task is not None:
                        with contextlib.suppress(Exception, asyncio.CancelledError):
                            await asyncio.wait_for(
                                self._task, timeout=cfg.shutdown_timeout_seconds
                            )
                    await executor.shutdown()
                finally:
                    self.close()

        app.router.lifespan_context = cast(Any, lifespan)

    @staticmethod
    def _finished(task):
        if not task.cancelled() and task.exception() is not None:
            _LOGGER.error("Interactive controller stopped; readiness is unavailable")

    def close(self) -> None:
        if self._journal is not None:
            self._journal.close()
            self._journal = None
        self._engine.dispose()


def build_production_interactive_controller(*, config) -> ProductionInteractiveControllerAdapter:
    if os.environ.get("OMNIGENT_SAAS_INTERACTIVE_CONTROLLER_ENABLED") != "true":
        raise _unavailable()
    return ProductionInteractiveControllerAdapter(config=config, source=os.environ)
