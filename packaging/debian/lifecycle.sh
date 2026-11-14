#!/bin/sh
set -eu
# Refuse host execution BEFORE any write or package-manager command.
test -f /.dockerenv
test "$(cat /ap-package-ci-fixture)" = AP-PKG-CI-DISPOSABLE-v1
test "$(id -u)" = 0
test "$(dpkg --print-architecture)" = amd64
grep -qx 'VERSION_CODENAME=trixie' /etc/os-release
test ! -S /var/run/docker.sock
for name in systemctl service invoke-rc.d codex adduser useradd groupadd systemd-sysusers systemd-tmpfiles apparmor_parser; do
    test ! -e "/usr/local/bin/$name"
    printf '#!/bin/sh\nprintf forbidden >> /tmp/ap-forbidden-call\nexit 99\n' > "/usr/local/bin/$name"
    chmod 755 "/usr/local/bin/$name"
done
# There is deliberately no /usr/bin/codex, not even a fake link.
test ! -e /usr/bin/codex
# Dependencies were downloaded in the disposable image, never from maintainer scripts.
apt-get --no-download --no-install-recommends -y install python3
exec python3 /opt/ap-tests/smoke.py --lifecycle
