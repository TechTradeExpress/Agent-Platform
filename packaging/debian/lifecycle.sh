#!/bin/sh
set -eu
# Refuse host execution BEFORE any destructive command.
test -f /.dockerenv
test "$(cat /ap-package-ci-fixture)" = AP-PKG-CI-DISPOSABLE-v1
test "$(id -u)" = 0
test "$(dpkg --print-architecture)" = amd64
grep -qx 'VERSION_CODENAME=trixie' /etc/os-release
test ! -S /var/run/docker.sock
# Fixed fake tripwires precede even the initial apt installation.
for name in codex systemctl service invoke-rc.d; do
    test ! -e "/usr/local/bin/$name"
    printf '#!/bin/sh\nprintf forbidden >> /tmp/ap-forbidden-call\nexit 99\n' > "/usr/local/bin/$name"
    chmod 755 "/usr/local/bin/$name"
done
test ! -e /usr/bin/codex
ln -s /usr/local/bin/codex /usr/bin/codex
# Dependency acquisition happened during image construction. No network at lifecycle.
apt-get --no-download --no-install-recommends -y install python3 python3-cryptography git gh
apt-get --no-install-recommends -y install /packages/n/agent-platform_0.1.0-1_amd64.deb
exec python3 /opt/ap-tests/smoke.py --lifecycle
