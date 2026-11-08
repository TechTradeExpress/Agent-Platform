# Official library/debian trixie-slim, observed 2026-11-04; amd64 manifest.
FROM debian:trixie-slim@sha256:1e1a22175fbf1b32157ddaf0219e1db4e5401fab2b94ed285add64d18587cd2d AS base
ENV DEBIAN_FRONTEND=noninteractive
RUN printf 'AP-PKG-CI-DISPOSABLE-v1\n' > /ap-package-ci-fixture

# Cache dependencies without installing them: lifecycle starts with no Python/Git/gh.
FROM base AS lifecycle
RUN rm -f /etc/apt/apt.conf.d/docker-clean && apt-get update && \
    apt-get --download-only --no-install-recommends -y install python3 python3-cryptography git gh
COPY lifecycle.sh smoke.py /opt/ap-tests/
ENTRYPOINT ["/bin/sh", "/opt/ap-tests/lifecycle.sh"]

# Quality tools are confined to a different disposable image/container.
FROM base AS quality
RUN apt-get update && apt-get --no-install-recommends -y install \
    python3 python3-cryptography git gh lintian autopkgtest ca-certificates
