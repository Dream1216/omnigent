ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.12.1@sha256:cf4eedcaa81655197f625739489effcbe71b61ceb1506f332c3facae5deceded
ARG PYTHON_IMAGE
FROM ${UV_IMAGE} AS uv-bin

FROM ${PYTHON_IMAGE} AS n1-compat-builder
ARG SOURCE_DATE_EPOCH
ENV PYTHONDONTWRITEBYTECODE=1 \
    OMNIGENT_SKIP_WEB_UI=true \
    SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
    UV_NO_INSTALLER_METADATA=1
COPY --from=uv-bin /uv /usr/local/bin/uv
WORKDIR /build
COPY pyproject.toml setup.py uv.lock README.md ./
COPY LICENSE NOTICE ./
COPY sdks/ ./sdks/
COPY omnigent/ ./omnigent/
COPY saas/ ./saas/
COPY integrations/slack/ ./integrations/slack/
COPY examples/ ./examples/
RUN sed -i '/^\[tool\.uv\.workspace\]$/,/^$/d' pyproject.toml \
 && python -m venv --without-pip /opt/venv \
 && /usr/local/bin/uv pip install --python /opt/venv/bin/python --require-hashes \
      -r saas/n1_compat/build-requirements.txt \
 && VIRTUAL_ENV=/opt/venv /usr/local/bin/uv sync --frozen --active --package omnigent \
      --extra saas --no-dev --no-editable --no-cache --no-build-isolation \
 && installed="$(/opt/venv/bin/python -B -I -c 'import importlib.metadata as m; print(m.version("psycopg"))')" \
 && [ "${installed}" = "3.3.4" ] \
 && /opt/venv/bin/python -B -I -c 'from pathlib import Path; import saas.n1_outbox_launcher as l, saas.outbox_worker as w; p=Path("/opt/venv").resolve(); assert all(Path(m.__file__).resolve().is_relative_to(p) for m in (l, w))' \
 && /usr/local/bin/uv pip check --python /opt/venv/bin/python \
 && test -z "$(find /opt/venv -type f -name '*.pyc' -print -quit)" \
 && test -z "$(find /opt/venv -type f -name 'uv_cache.json' -print -quit)"

FROM ${PYTHON_IMAGE} AS n1-compat-runtime
ARG SOURCE_REVISION
ARG UPSTREAM_REVISION
ARG CONTROL_PLANE_SCHEMA_REVISION
ARG ADAPTER_CONTRACT_VERSION
ARG N1_BASE_COMMIT
ARG N1_CONTRACT_VERSION
ARG N1_PATCH_SHA256
ARG N1_PATCHED_TREE_HASH
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PATH="/opt/venv/bin:${PATH}"
LABEL org.opencontainers.image.revision=${SOURCE_REVISION} \
      ai.omnigent.upstream.revision=${UPSTREAM_REVISION} \
      ai.omnigent.saas.schema-revision=${CONTROL_PLANE_SCHEMA_REVISION} \
      ai.omnigent.saas.adapter-contract-version=${ADAPTER_CONTRACT_VERSION} \
      ai.omnigent.saas.n1.base-commit=${N1_BASE_COMMIT} \
      ai.omnigent.saas.n1.patch-source-revision=${SOURCE_REVISION} \
      ai.omnigent.saas.n1.patch-sha256=${N1_PATCH_SHA256} \
      ai.omnigent.saas.n1.patched-tree-hash=${N1_PATCHED_TREE_HASH} \
      ai.omnigent.saas.n1.schema-revision=${CONTROL_PLANE_SCHEMA_REVISION} \
      ai.omnigent.saas.n1.contract-version=${N1_CONTRACT_VERSION}
COPY --from=n1-compat-builder /opt/venv /opt/venv
WORKDIR /app
HEALTHCHECK NONE
CMD ["python", "-B", "-I", "-m", "saas.n1_outbox_launcher"]
