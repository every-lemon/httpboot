#!/usr/bin/env python3
"""Standalone service precondition: require the intended mounted ext4 UUID."""
import argparse
import json
import subprocess
from pathlib import Path


def check(uuid, mountpoint):
    result = subprocess.run(['findmnt', '--json', '--mountpoint', str(mountpoint),
                             '--output', 'UUID,TARGET,FSTYPE,OPTIONS'], check=True, capture_output=True, text=True)
    mounts = json.loads(result.stdout).get('filesystems', [])
    if len(mounts) != 1:
        raise ValueError('Expected storage volume is not mounted')
    m = mounts[0]
    if (m.get('uuid', '').lower() != uuid.lower() or m['fstype'] != 'ext4' or
            Path(m['target']).resolve() != Path(mountpoint).resolve() or 'rw' not in m['options'].split(',')):
        raise ValueError('Storage UUID, filesystem, mount location, or write mode does not match')


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--uuid', required=True)
    p.add_argument('--mount', required=True)
    a = p.parse_args()
    check(a.uuid, a.mount)
