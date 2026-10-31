#!/usr/bin/env python3
"""Wrap the combined Debian package in a self-removing, verifiable Builder installer."""
import argparse
import base64
import hashlib
from pathlib import Path


def build(package,output):
    payload=Path(package).read_bytes();checksum=hashlib.sha256(payload).hexdigest()
    script=r'''#!/bin/bash
set -Eeuo pipefail
if (( EUID != 0 ));then echo 'Run this saved file with sudo bash.' >&2;exit 1;fi
if [[ $(uname -m) != x86_64 ]];then echo 'This installer requires an amd64 Builder.' >&2;exit 1;fi
. /etc/os-release
if [[ ${ID:-} != ubuntu || ${VERSION_ID:-} != 24.04 ]];then echo 'This Builder requires Ubuntu 24.04.' >&2;exit 1;fi
self=$(readlink -f -- "${BASH_SOURCE[0]}")
if [[ ! -f $self ]];then echo 'Save this installer to a file before running it.' >&2;exit 1;fi
umask 077
logdir=/var/log/kagnode/httpboot
mkdir -p "$logdir" /var/cache/kagnode/httpboot /var/lib/kagnode/httpboot
log="$logdir/builder-install-$(date -u +%Y%m%dT%H%M%SZ).log"
exec > >(tee -a "$log") 2>&1
work=$(mktemp -d /var/tmp/httpboot-builder-install.XXXXXXXX)
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT
# Take the same locks as existing build and maintenance operations.
exec 9>/var/cache/kagnode/httpboot/worker.lock
exec 8>/var/lib/kagnode/httpboot/management.lock
exec 7>/var/lib/kagnode/httpboot/update.lock
for descriptor in 9 8 7;do
    if ! flock -n "$descriptor";then echo 'A Builder operation is active. Retry after it finishes; nothing was stopped.';exit 1;fi
done
sed '1,/^__HTTPBOOT_DEB_PAYLOAD__$/d' "$self" | base64 --decode >"$work/httpboot-server-builder.deb"
printf '%s  %s\n' '__CHECKSUM__' "$work/httpboot-server-builder.deb" | sha256sum --check --status
chmod 755 "$work"
chmod 644 "$work/httpboot-server-builder.deb"
# Installing this explicitly selected payload may cross Debian's dev/beta
# ordering. Dependencies have no exact lower-version pins; removal is forbidden.
DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 --no-remove --reinstall --allow-downgrades install -y "$work/httpboot-server-builder.deb"
/usr/sbin/httpboot-builder --version
/usr/sbin/httpboot-server --version
python3 -m compileall -q /opt/kagnode/httpboot/source/httpboot
systemctl daemon-reload
printf 'Builder installed. Caches and existing services retained. Log: %s\n' "$log"
rm -- "$self"
echo 'The installer removed its own .sh file. No restart was requested.'
exit 0
__HTTPBOOT_DEB_PAYLOAD__
'''
    script=script.replace('__CHECKSUM__',checksum)
    Path(output).write_text(script+base64.encodebytes(payload).decode())
    Path(output).chmod(0o700)
    return Path(output)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();print(build(args.package,args.output))
