ARG RUNTIME_IMAGE=ghcr.io/dream1216/omnigent-saas-server@sha256:2555fafc4527912705014f5a2e84ad9db4632afb18b317daeb07a433fb9bdbc2
ARG UI_IMAGE=ghcr.io/dream1216/omnigent-saas-server@sha256:d40b0cf4c226eb1a8743f7ffe5fbf4f8d9380e556d0330ef70ce9c6bbb13313c
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.12.1@sha256:cf4eedcaa81655197f625739489effcbe71b61ceb1506f332c3facae5deceded
FROM ${UI_IMAGE} AS original-ui
FROM ${UV_IMAGE} AS uv-bin
FROM ${RUNTIME_IMAGE} AS compat-builder
USER 0
ARG SOURCE_REVISION
ARG SOURCE_DATE_EPOCH
ENV PYTHONDONTWRITEBYTECODE=1 UV_NO_INSTALLER_METADATA=1 SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
COPY --from=uv-bin /uv /usr/local/bin/uv
COPY runtime-inputs/ /compat-inputs/
RUN python3 -B -I -c 'import hashlib,json;from pathlib import Path;r=Path("/compat-inputs");m=json.loads((r/"manifest.json").read_text());w=list(r.glob("*.whl"));assert len(w)==1 and hashlib.sha256(w[0].read_bytes()).hexdigest()==m["original_wheel_sha256"];assert hashlib.sha256((r/"postgresql_migration.py").read_bytes()).hexdigest()==m["patched_module_sha256"]' \
 && /usr/local/bin/uv pip install --python /opt/venv/bin/python --no-index --no-deps --reinstall /compat-inputs/*.whl \
 && /opt/venv/bin/python -B -I -c 'import hashlib,json;from pathlib import Path;import saas.production.postgresql_migration as m;r=Path("/compat-inputs");p=Path(m.__file__);v=json.loads((r/"manifest.json").read_text());assert p.is_relative_to(Path("/opt/venv")) and hashlib.sha256(p.read_bytes()).hexdigest()==v["original_module_sha256"];p.write_bytes((r/"postgresql_migration.py").read_bytes());assert hashlib.sha256(p.read_bytes()).hexdigest()==v["patched_module_sha256"]' \
 && /opt/venv/bin/python -B -I /compat-inputs/bind_runtime_build_revision.py --source-revision "${SOURCE_REVISION}" --source-date-epoch "${SOURCE_DATE_EPOCH}" \
 && /opt/venv/bin/python -B -I -c 'import hashlib,json;from pathlib import Path;from importlib.metadata import distribution;r=Path("/compat-inputs");m=json.loads((r/"manifest.json").read_text());p=Path(distribution("omnigent")._path)/"METADATA";assert p.is_relative_to(Path("/opt/venv")) and hashlib.sha256(p.read_bytes()).hexdigest()==m["original_metadata_sha256"];b=(r/"METADATA").read_bytes();assert hashlib.sha256(b).hexdigest()==m["patched_metadata_sha256"];p.write_bytes(b)' \
 && /usr/local/bin/uv pip check --python /opt/venv/bin/python
COPY --from=original-ui /opt/venv/lib/python3.12/site-packages/omnigent/server/static/ /opt/venv/lib/python3.12/site-packages/omnigent/server/static/
COPY --from=original-ui /opt/venv/lib/python3.12/site-packages/saas/login_ui/static/ /opt/venv/lib/python3.12/site-packages/saas/login_ui/static/
RUN /opt/venv/bin/python -B -I /compat-inputs/normalize_host_cli_tree.py --root /opt/venv --source-date-epoch "${SOURCE_DATE_EPOCH}" \
 && /opt/venv/bin/python -B -I -c 'from pathlib import Path;import saas.production.postgresql_migration as m;assert callable(m._canonical_runner_management_catalog);assert (Path("/opt/venv/lib/python3.12/site-packages/omnigent/server/static/web-ui/index.html")).is_file()'

FROM ${RUNTIME_IMAGE} AS core-f440-compat
ARG SOURCE_REVISION
ARG SOURCE_DATE_EPOCH
ARG UPSTREAM_REVISION
ARG ADAPTER_CONTRACT_VERSION
LABEL org.opencontainers.image.revision=${SOURCE_REVISION} \
      ai.omnigent.upstream.revision=${UPSTREAM_REVISION} \
      ai.omnigent.saas.schema-revision=p0s000000015 \
      ai.omnigent.saas.adapter-contract-version=${ADAPTER_CONTRACT_VERSION}
COPY --from=compat-builder /opt/venv /opt/venv
RUN rm -rf /build
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PATH="/opt/venv/bin:${PATH}"
WORKDIR /app
