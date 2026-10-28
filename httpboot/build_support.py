"""Durable build stages, isolated resolver setup and memory-aware concurrency."""
import json
import os
import re
import socket
import subprocess
from pathlib import Path
from common import atomic, dump, load

REPOSITORIES = ('archive.ubuntu.com', 'security.ubuntu.com', 'dl.google.com', 'dl.flathub.org')

def resolver_text():
    # /etc/resolv.conf can point at the host stub. Prefer its upstream resolver list.
    for path in (Path('/run/systemd/resolve/resolv.conf'), Path('/etc/resolv.conf')):
        if path.is_file():
            text = path.read_text()
            if re.search(r'^nameserver\s+\S+', text, re.M):
                return text
    raise ValueError('No usable host DNS configuration. Fix Builder networking, then resume; build files are retained.')

def prepare_resolver(root):
    text = resolver_text()
    target = root/'etc/resolv.conf'
    if target.is_symlink():
        target.unlink()
    atomic(target, text, 0o644)
    # systemd-resolved's package scripts may replace /etc/resolv.conf while apt is
    # still downloading. Supply both symlink targets in the private build /run.
    for name in ('resolv.conf', 'stub-resolv.conf'):
        atomic(root/'run/systemd/resolve'/name, text, 0o644)

def check_dns(root=None,hosts=REPOSITORIES):
    for host in hosts:
        try:
            if root is None:
                socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
            else:
                result = subprocess.run(['chroot', str(root), 'getent', 'ahostsv4', host],
                                        capture_output=True, timeout=20)
                if result.returncode:
                    raise OSError(result.stderr.decode(errors='replace'))
        except (OSError, subprocess.TimeoutExpired) as exc:
            location = 'inside the build filesystem' if root else 'on the Builder'
            raise ValueError(f'DNS failed {location} for {host}. Fix DNS and select Resume; packages and completed stages were kept.') from exc

def parallelism(requested):
    values = dict((line.split(':',1)[0], int(line.split()[1]))
                  for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith(('MemTotal:', 'MemAvailable:')))
    memory = min(values['MemTotal'], values.get('MemAvailable', values['MemTotal']))
    # zstd + desktop packaging must leave RAM for the OS and filesystem caches.
    return max(1, min(requested, os.cpu_count() or 1, max(1, (memory-1024*1024)//(1200*1024))))

class Stages:
    def __init__(self, path):
        self.path = path
        self.data = load(path) if path.exists() else {'schema': 1, 'completed': []}
        if self.data.get('schema') != 1 or not isinstance(self.data.get('completed'), list):
            raise ValueError('Invalid stage journal; files retained for inspection')
    def done(self, name):
        return name in self.data['completed']
    def run(self, name, action):
        if self.done(name):
            print(f'HTTPBOOT_STAGE:Reusing completed stage: {name}', flush=True)
            return
        print(f'HTTPBOOT_STAGE:{name}', flush=True)
        action()
        self.data['completed'].append(name)
        dump(self.path, self.data)
        if os.environ.get('HTTPBOOT_TEST_STOP_AFTER_STAGE') == name:
            raise ValueError('Validation interruption after committed stage: '+name)
