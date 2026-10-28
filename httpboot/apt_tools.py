"""Ubuntu Noble dependency installation with retained downloads and solver checks."""
import importlib.util
import os
import platform
import re
import shutil
import subprocess
import time
from pathlib import Path

from common import atomic, run

SOURCES = Path('/etc/apt/sources.list.d')
KEYRING = Path('/usr/share/keyrings/ubuntu-archive-keyring.gpg')
KEEP_CONF = Path('/etc/apt/apt.conf.d/80-httpboot-keep-downloads')


def objcopy_tool():
    for name in ('x86_64-linux-gnu-objcopy', 'llvm-objcopy', 'llvm-objcopy-18'):
        path = shutil.which(name)
        if path:
            return path
    return None


def keep_downloads(path=KEEP_CONF):
    data = ('// Managed by httpboot: keep downloaded packages\n'
            'APT::Keep-Downloaded-Packages "true";\n'
            'Binary::apt::APT::Keep-Downloaded-Packages "true";\n'
            'Binary::apt-get::APT::Keep-Downloaded-Packages "true";\n')
    if path.exists() and path.read_text() == data:
        return
    if path.exists():
        shutil.copy2(path, path.with_name(path.name + f'.before-{time.time_ns()}'))
    atomic(path, data, 0o644)


def ensure_noble_updates():
    info = platform.freedesktop_os_release()
    if info.get('ID') != 'ubuntu' or info.get('VERSION_ID') != '24.04':
        raise ValueError('Automatic boot dependency setup requires Ubuntu 24.04')
    arch = run(['dpkg', '--print-architecture'], capture_output=True, text=True).stdout.strip()
    if arch not in ('amd64', 'i386', 'arm64', 'armhf', 'ppc64el', 'riscv64', 's390x'):
        raise ValueError('Unsupported Ubuntu repository architecture')
    policy = run(['apt-cache', 'policy'], capture_output=True, text=True, env={**os.environ, 'LC_ALL':'C'}).stdout
    present = {component for component in ('main', 'universe') if any(
        'o=Ubuntu,' in line and 'a=noble-updates,' in line and f'c={component},' in line and f'b={arch}' in line
        for line in policy.splitlines())}
    if present == {'main', 'universe'}:
        return False
    if not KEYRING.is_file():
        raise ValueError('Ubuntu archive keyring is missing; repository authentication was not disabled')
    uri = 'http://archive.ubuntu.com/ubuntu/' if arch in ('amd64', 'i386') else 'http://ports.ubuntu.com/ubuntu-ports/'
    data = ('# Managed by httpboot: required Noble update dependencies\n'
            f'Types: deb\nURIs: {uri}\nSuites: noble-updates\n'
            f'Components: {" ".join(c for c in ("main", "universe") if c not in present)}\n'
            f'Architectures: {arch}\nSigned-By: {KEYRING}\n')
    target = SOURCES / 'httpboot-noble-updates.sources'
    if target.exists():
        if target.read_text() == data:
            return True
        # Preserve existing administrator content rather than rewriting it.
        target = SOURCES / f'httpboot-noble-updates-{time.time_ns()}.sources'
    atomic(target, data, 0o644)
    print('Enabled signed Ubuntu noble-updates components required by boot tools.', flush=True)
    return True


def install_boot_dependencies():
    keep_downloads()
    ready = Path('/usr/lib/systemd/ukify').is_file() and importlib.util.find_spec('pefile') is not None and objcopy_tool()
    if ready:
        return
    run(['apt-get', 'update'])
    if ensure_noble_updates():
        run(['apt-get', 'update'])
    base = ['systemd-ukify', 'python3-pefile']
    choices = [base] if objcopy_tool() else [base + ['binutils-x86-64-linux-gnu'], base + ['llvm-18']]
    last = ''
    for packages in choices:
        trial = subprocess.run(['apt-get', '--simulate', '--no-remove', 'install', '-y', *packages],
                               capture_output=True, text=True, env={**os.environ, 'LC_ALL':'C'})
        if trial.returncode:
            last = (trial.stdout + trial.stderr)[-5000:]
            if 'binutils-x86-64-linux-gnu' in packages:
                print('Cross-binutils versions cannot be resolved; checking the LLVM alternative.', flush=True)
            continue
        run(['apt-get', '--no-remove', 'install', '-y', *packages])
        importlib.invalidate_caches()
        if not objcopy_tool() or importlib.util.find_spec('pefile') is None or not Path('/usr/lib/systemd/ukify').is_file():
            raise ValueError('Boot dependency installation completed but a required tool is still unavailable')
        return
    raise ValueError('APT could not resolve boot dependencies. Existing package holds were preserved.\n' + last)
