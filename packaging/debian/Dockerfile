# Official full Debian 13, same date/package versions as prior slim pin.
# Verified man1 is already root:root 0755; no permission repair (PKG-05).
FROM debian:trixie-20261027@sha256:e2914ec98e08b24b4cee3cefcb9f90dfb5519f8d215a2ccf0c9a49b10b6e43de AS base
ENV DEBIAN_FRONTEND=noninteractive
# Keep docs/manuals so installed manifests and provenance can be tested.
RUN test "$(LC_ALL=C stat -c '%u:%g:%a:%F' /usr/share/man/man1)" = "0:0:755:directory" && \
    rm -f /etc/dpkg/dpkg.cfg.d/docker && \
    printf 'AP-PKG-CI-DISPOSABLE-v1\n' > /ap-package-ci-fixture

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

COPY quality.sh /opt/ap-tests/

# P1 tools are configured in the disposable image, before any project units exist.
# Deny baseline dependency service activation too; never load host kernel profiles.
FROM base AS worker-p1
ARG P1_CASE=clean
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d && chmod 755 /usr/sbin/policy-rc.d && \
    apt-get update && apt-get --no-install-recommends -y install passwd && \
    if [ "$P1_CASE" = existing ]; then groupadd --gid 989 ap-publisher && useradd --uid 999 --gid ap-publisher --system --no-create-home --home-dir /var/lib/ap-publisher --shell /usr/sbin/nologin ap-publisher; fi && \
    groupadd --gid 2000 agentdev && useradd --uid 2000 --gid agentdev --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin agentdev && \
    printf '%s\n' "$P1_CASE" > /ap-worker-p1-case && \
    apt-get --no-install-recommends -y install \
    python3 python3-cryptography git gh ca-certificates systemd apparmor apparmor-utils acl passwd && \
    test "$(LC_ALL=C stat -c '%u:%g:%a:%F' /usr/share/man/man1)" = "0:0:755:directory"
COPY worker_p1_lifecycle.py worker_metadata_evidence.py /opt/ap-tests/
ENTRYPOINT ["/usr/bin/python3", "-IB", "/opt/ap-tests/worker_p1_lifecycle.py"]

# Separate Codex installer fixture, with synthetic pins/ELFs and loopback HTTP.
# No project .deb, official executable, login, host socket or lifecycle network.
FROM base AS codex-pkg05
RUN apt-get update && apt-get --no-install-recommends -y install \
    python3 python3-pytest ca-certificates
COPY codex_pkg05_lifecycle.py /usr/share/ap-tests/
ENTRYPOINT ["/usr/bin/python3", "-IB", "/usr/share/ap-tests/codex_pkg05_lifecycle.py"]

# Retain the actual prior 0775 image as an independent negative regression.
FROM debian:trixie-slim@sha256:1e1a22175fbf1b32157ddaf0219e1db4e5401fab2b94ed285add64d18587cd2d AS manpage-negative
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get --no-install-recommends -y install python3 && \
    printf 'AP-PKG-CI-DISPOSABLE-v1\n' > /ap-package-ci-fixture
COPY worker_manpage_negative.py /usr/share/ap-tests/
ENTRYPOINT ["/usr/bin/python3", "-IB", "/usr/share/ap-tests/worker_manpage_negative.py"]
