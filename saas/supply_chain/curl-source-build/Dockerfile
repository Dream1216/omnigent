# Isolated source-build experiment; this image cannot authorize production admission.
ARG SOURCE_BASE_IMAGE=python:3.12-slim@sha256:05cda9777409a9c3ffddd94a4c476b79f0769a0b4857f0c7ed9226b6800b0d6f
FROM ${SOURCE_BASE_IMAGE} AS compile
ARG SOURCE_DATE_EPOCH
ENV DEBIAN_FRONTEND=noninteractive \
    SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
WORKDIR /work
COPY replay_debian_source_backports.py /work/replay.py
COPY source-lock.json /work/source-lock.json
COPY source/ /work/materials/
RUN python -B -I -c 'import os,platform,re; from pathlib import Path; assert platform.freedesktop_os_release()["VERSION_CODENAME"] == "trixie"; assert os.environ["SOURCE_DATE_EPOCH"].isascii() and os.environ["SOURCE_DATE_EPOCH"].isdigit(); p=Path("/etc/apt/sources.list.d/debian.sources"); s=p.read_text(); pattern=re.compile(r"(?m)^# (http://snapshot[.]debian[.]org/archive/(?:debian|debian-security)/[0-9]{8}T[0-9]{6}Z)\nURIs: http://deb[.]debian[.]org/(?:debian|debian-security)$"); s,n=pattern.subn(lambda m: "# "+m[1]+"\nURIs: "+m[1].replace("http:","https:",1),s); assert n == 2; uris=re.findall(r"(?m)^URIs: (\S+)$",s); assert len(uris) == 2 and all(u.startswith("https://snapshot.debian.org/archive/") for u in uris); assert set(re.findall(r"(?m)^Suites: (.+)$",s)) == {"trixie trixie-updates","trixie-security"}; p.write_text(s)' \
 && apt-get -o Acquire::Check-Valid-Until=false -o Acquire::Retries=3 -o Acquire::https::Timeout=30 update \
 && apt-get -o Acquire::Check-Valid-Until=false -o Acquire::Retries=3 -o Acquire::https::Timeout=30 install -y --no-install-recommends \
      build-essential autoconf automake libtool pkgconf perl git \
      openssl openssh-server stunnel4 gnutls-bin python3-impacket \
      libgnutls28-dev libkrb5-dev libnghttp2-dev libnghttp3-dev \
      libngtcp2-dev libngtcp2-crypto-gnutls-dev libpsl-dev libbrotli-dev \
      libzstd-dev libidn2-dev libssh2-1-dev libldap2-dev librtmp-dev zlib1g-dev \
 && python -B -I /work/replay.py --lock /work/source-lock.json \
      --cache /work/materials --destination /work/src
WORKDIR /work/src/curl-8.22.0
ENV CFLAGS="-O2 -g -fstack-protector-strong -Wformat -Werror=format-security -ffile-prefix-map=/work/src/curl-8.22.0=." \
    CPPFLAGS="-D_FORTIFY_SOURCE=3" \
    LDFLAGS="-Wl,-z,relro,-z,now,-z,noexecstack -Wl,--as-needed"
RUN ./configure --prefix=/usr --libdir="/usr/lib/$(dpkg-architecture -qDEB_HOST_MULTIARCH)" \
      --enable-symbol-hiding --enable-versioned-symbols --enable-threaded-resolver \
      --with-gnutls --with-nghttp2 --with-ngtcp2 --with-nghttp3 --with-gssapi=/usr \
      --without-libssh --with-libssh2 --with-ca-path=/etc/ssl/certs \
      --with-ca-bundle=/etc/ssl/certs/ca-certificates.crt \
 && make -j2 \
 && make test-nonflaky TFLAGS='-n -j2' \
 && make DESTDIR=/out install

FROM scratch AS artifacts
COPY --from=compile /out/ /
