ARG BASE_IMAGE
FROM ${BASE_IMAGE} AS compatibility-builder
USER 0
ARG SOURCE_REVISION
ARG SOURCE_DATE_EPOCH
ENV PYTHONDONTWRITEBYTECODE=1
COPY runtime-inputs/ /compat-inputs/
RUN /opt/venv/bin/python -B -I /compat-inputs/source/saas/scripts/export_d0_legacy_overlay.py \
    --repository /compat-inputs/source \
    --original-wheel /compat-inputs/original.whl \
    --wheel /compat-inputs/unsigned/omnigent-0.18.0.dev20261006-py3-none-any.whl \
    --materialization /compat-inputs/unsigned/materialization.json \
    --source-revision "${SOURCE_REVISION}" --source-date-epoch "${SOURCE_DATE_EPOCH}" \
    --output /compat-overlay

FROM ${BASE_IMAGE} AS d0-legacy-compatible
ARG SOURCE_REVISION
LABEL org.opencontainers.image.revision=${SOURCE_REVISION} \
      ai.omnigent.upstream.revision=825f8500d7cc8e997e5562fa55694cd146165f3c \
      ai.omnigent.saas.schema-revision=lm2t00000001 \
      ai.omnigent.saas.adapter-contract-version=0.2.0
COPY --from=compatibility-builder /compat-overlay/ /opt/venv/
