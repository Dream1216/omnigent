# Local overrides are diagnostic only; release builds use the admitted digest.
ARG LITELLM_BASE_IMAGE=ghcr.io/berriai/litellm@sha256:b7b9e2c306343721802253d0dd9436b9634a2eb4e14da7c7cf06c5c7b7530802
FROM ${LITELLM_BASE_IMAGE} AS oss-rootfs
ARG TARGETARCH
ARG SOURCE_DATE_EPOCH=1580601600
# The original image keys validate the repository index; apk then checks each
# package against that index. Do not install these unsigned APKs by file path.
RUN --network=none --mount=type=bind,source=.litellm-runtime,target=/runtime,readonly \
    case "${TARGETARCH}" in amd64) apk_arch=x86_64 ;; arm64) apk_arch=aarch64 ;; *) exit 2 ;; esac \
 && cd /runtime \
 && sha256sum -c "${apk_arch}/packages.sha256" \
 && apk --repositories-file /dev/null --repository /runtime --no-cache --no-network \
      add libcrypto3=3.6.5-r2 libssl3=3.6.5-r2 \
 && apk info -e libcrypto3=3.6.5-r2 libssl3=3.6.5-r2 \
 && python -B -I -c 'import ctypes; library=ctypes.CDLL("/usr/lib/libcrypto.so.3"); library.OpenSSL_version.restype=ctypes.c_char_p; version=library.OpenSSL_version(0).decode(); assert version.startswith("OpenSSL 3.6.5 "), version; print(version)'
# Only the MIT core ships. Optional commercial imports must remain unavailable;
# do not patch a license check or substitute an enterprise implementation.
RUN --network=none python -B -I -c 'import importlib.metadata as m; assert m.version("litellm-enterprise") == "0.1.73"' \
 && test -d /app/enterprise \
 && test -d /app/.venv/lib/python3.13/site-packages/litellm_enterprise \
 && test -d /app/.venv/lib/python3.13/site-packages/litellm_enterprise-0.1.73.dist-info \
 && rm -r -- /app/enterprise \
      /app/.venv/lib/python3.13/site-packages/litellm_enterprise \
      /app/.venv/lib/python3.13/site-packages/litellm_enterprise-0.1.73.dist-info \
 && LITELLM_LOCAL_MODEL_COST_MAP=True python -B -I -c 'import importlib.util; assert importlib.util.find_spec("litellm_enterprise") is None; import litellm.proxy.proxy_server' \
 && case "${SOURCE_DATE_EPOCH}" in *[!0-9]*|'') exit 2 ;; esac \
 && rm -f /var/cache/ldconfig/aux-cache \
 && find /app /etc /usr /lib /var /opt /root /tmp -depth \
      ! -path /etc/hosts ! -path /etc/hostname ! -path /etc/resolv.conf \
      -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} + \
 && if test -d /runtime; then touch -h -d "@${SOURCE_DATE_EPOCH}" /runtime; fi \
 && touch -h -d "@${SOURCE_DATE_EPOCH}" /

# Flatten the sanitized filesystem: deleting a commercial module in a later
# layer would still redistribute its bytes in the inherited image layers.
FROM scratch AS runtime
COPY --from=oss-rootfs / /
COPY deploy/litellm/LICENSE.upstream /usr/share/licenses/omnigent-litellm/LICENSE.upstream
ARG SOURCE_REVISION=unknown
ARG SOURCE_DATE_EPOCH=1580601600
LABEL io.omnigent.litellm.upstream.digest="sha256:b7b9e2c306343721802253d0dd9436b9634a2eb4e14da7c7cf06c5c7b7530802" \
      io.omnigent.litellm.openssl.version="3.6.5-r2" \
      io.omnigent.litellm.profile="oss-core" \
      io.omnigent.integration.revision="${SOURCE_REVISION}"
ENV PATH="/app/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/sbin:/bin" \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    PRISMA_BINARY_CACHE_DIR=/opt/prisma/binaries \
    PRISMA_CLI_PATH=/opt/prisma/binaries/node_modules/.bin/prisma \
    PRISMA_CLI_QUERY_ENGINE_TYPE=binary \
    PRISMA_OFFLINE_MODE=true
USER root
WORKDIR /app
EXPOSE 4000/tcp
ENTRYPOINT ["docker/prod_entrypoint.sh"]
CMD ["--port", "4000"]
