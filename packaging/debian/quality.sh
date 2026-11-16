#!/bin/sh
set -eu
# This is testbed code, never a host installer.
test -f /.dockerenv
test "$(cat /ap-package-ci-fixture)" = AP-PKG-CI-DISPOSABLE-v1
test "$(id -u)" = 0
grep -qx 'VERSION_CODENAME=trixie' /etc/os-release
test ! -S /var/run/docker.sock
for role in control worker; do
    package="/packages/next/agent-platform-${role}_0.1.0-4_amd64.deb"
    dpkg-deb --info "$package" > "/evidence/${role}-info.txt"
    dpkg-deb --contents "$package" > "/evidence/${role}-files.txt"
    test "$(dpkg-deb -f "$package" Architecture)" = amd64
    test "$(dpkg-deb -f "$package" Version)" = 0.1.0-4
    dpkg-deb --control "$package" "/tmp/ap-control-${role}"
    for hook in preinst postinst prerm postrm triggers; do
        test ! -e "/tmp/ap-control-${role}/$hook"
    done
done
lintian --allow-root --fail-on error /packages/n/*.deb /packages/next/*.deb > /evidence/lintian.txt 2>&1
lintian --allow-root --fail-on error /packages/p1/*.deb /packages/p1-next/*.deb > /evidence/p1-lintian.txt 2>&1
lintian --allow-root --fail-on error /packages/pkg09-candidate/*.deb /packages/pkg09-upgrade-test/*.deb > /evidence/pkg09-lintian.txt 2>&1
apt-get --no-install-recommends -y install /packages/next/*.deb
autopkgtest --no-built-binaries -o /evidence/autopkgtest /packages/next/agent-platform-control_0.1.0-4_amd64.deb /packages/next/agent-platform-worker_0.1.0-4_amd64.deb /source -- null
test -s /evidence/autopkgtest/summary
grep -Eq 'smoke[[:space:]]+PASS' /evidence/autopkgtest/summary
dpkg-query -W > /evidence/quality-toolchain.txt

# Exercise the exact -7 compatibility test artifacts separately from P0 smoke.
apt-get --no-install-recommends -y install /packages/pkg09-upgrade-test/*.deb
autopkgtest --no-built-binaries -o /evidence/pkg09-autopkgtest /packages/pkg09-upgrade-test/agent-platform-control_0.1.0-7_amd64.deb /packages/pkg09-upgrade-test/agent-platform-worker_0.1.0-7_amd64.deb /source -- null
grep -Eq 'smoke[[:space:]]+PASS' /evidence/pkg09-autopkgtest/summary
chmod -R a+rX /evidence
