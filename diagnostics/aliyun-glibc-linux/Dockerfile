FROM debian:sid-slim@sha256:10e9e0d7aa4ed47205c7053f117199e6b06a9b17ac3eeb7f7bb1a818b963a803
COPY ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY . /probe
RUN printf '%s\n' \
      'Types: deb' \
      'URIs: https://snapshot.debian.org/archive/debian/20261030T000000Z/' \
      'Suites: sid' 'Components: main' \
      'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
      'Check-Valid-Until: no' > /etc/apt/sources.list.d/debian.sources \
 && apt-get -o Acquire::https::CaInfo=/etc/ssl/certs/ca-certificates.crt -o APT::Update::Error-Mode=any update \
 && echo '23fab9795bb10ed4d7c39a32d04400600d1f68a151692ac1c23ec2629a243fc0  /var/lib/apt/lists/snapshot.debian.org_archive_debian_20261030T000000Z_dists_sid_InRelease' | sha256sum --check - \
 && DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::https::CaInfo=/etc/ssl/certs/ca-certificates.crt install -y --no-install-recommends \
      ca-certificates curl python3 gnupg gpgv git dpkg-dev fakeroot build-essential \
 && python3 /probe/qualify.py prepare \
 && DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::https::CaInfo=/etc/ssl/certs/ca-certificates.crt build-dep -y --no-install-recommends /work/glibc \
 && useradd --create-home --uid 1000 --shell /bin/bash builder \
 && chown -R 1000:1000 /work \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt/*
USER builder
WORKDIR /work/glibc
ENTRYPOINT ["python3", "/probe/qualify.py", "run"]
