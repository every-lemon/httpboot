"""Root-owned persistent APT archives and completed desktop checkpoints."""
import errno
import fcntl
import hashlib
import json
import os
import pwd
import re
import shutil
import time
from pathlib import Path

from common import dump, load, run, sha256

CACHE_BASE = Path('/var/lib/httpboot-build-cache')
BOOT_FILES = {'init', 'initramfs-hook', 'wifi.sh', 'boot-checks.sh', 'dhclient-script', 'network.sh', 'tui.sh', 'session.py', 'storage.py', 'storage_health.py', 'desktop_state.py'}


def cache_directories(base=CACHE_BASE):
    if base.is_symlink():
        raise ValueError('Build cache must not be a symlink')
    base.mkdir(parents=True, exist_ok=True)
    base.chmod(0o711)
    archives = base / 'apt/archives'
    archives.mkdir(parents=True, exist_ok=True)
    (base/'apt').chmod(0o755)
    archives.chmod(0o755)
    partial = archives/'partial'
    partial.mkdir(exist_ok=True)
    partial.chmod(0o700)
    user = pwd.getpwnam('_apt')
    os.chown(partial, user.pw_uid, user.pw_gid)
    profiles = base/'profiles'
    profiles.mkdir(exist_ok=True)
    profiles.chmod(0o700)
    return archives


def desktop_inputs(config, hashes, source):
    code = (source/'httpboot/build.py').read_text()
    recipe = code.split('# DESKTOP_RECIPE_BEGIN\n',1)[1].split('# DESKTOP_RECIPE_END',1)[0]
    recipe = '\n'.join(line.strip() for line in recipe.splitlines())
    files = {p.name:sha256(p) for p in sorted((source/'client').iterdir()) if p.is_file() and p.name not in BOOT_FILES}
    data = {'schema':1, 'arch':'amd64', 'ubuntu':'24.04', 'config':config, 'hashes':hashes,
            'recipe':hashlib.sha256(recipe.encode()).hexdigest(), 'desktop_files':files, 'support':{name:sha256(source/'httpboot'/name) for name in ('build_support.py', 'recovery.py', 'desktop_recipe.py') if (source/'httpboot'/name).is_file()}}
    return data


def input_key(data):
    return hashlib.sha256(json.dumps(data,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def desktop_key(config, hashes, source):
    return input_key(desktop_inputs(config, hashes, source))


def compatible_desktop_key(base, config, hashes, source):
    data = desktop_inputs(config, hashes, source)
    current = input_key(data)
    current_path = base/'profiles'/current
    if any((current_path/name).exists() for name in ('rootfs','stages.json','desktop.json','latest-generation.json')):
        return current
    compatibility = source/'httpboot/desktop_compat.json'
    if not compatibility.is_file():
        return current
    rule = load(compatibility)
    if isinstance(rule.get('rules'),list):
        for candidate in rule['rules']:
            if any(data[field]!=candidate.get(field) for field in ('recipe','desktop_files','support')):continue
            previous={**data,**candidate['previous']}
            old=input_key(previous);old_path=base/'profiles'/old
            if old_path.is_symlink():raise ValueError('Compatible cache must not be a symlink')
            if (old_path/'rootfs').is_dir() and (old_path/'stages.json').is_file():
                stages=load(old_path/'stages.json')
                if stages.get('schema')==1 and 'Bootstrap Ubuntu' in stages.get('completed',[]):
                    print('HTTPBOOT_STAGE:Reusing compatible desktop; only recovery/startup changes',flush=True)
                    return old
        return current
    # Only the exact 3.0.0 -> 3.0.1 initialization fix is compatible. A later
    # change to desktop scripts, packages, recovery or support code invalidates it.
    if any(data[field] != rule.get(field) for field in ('recipe','desktop_files','support')):
        return current
    previous = {**data, 'recipe': rule['legacy_recipe']}
    old = input_key(previous)
    old_path = base/'profiles'/old
    if old_path.is_symlink():
        raise ValueError('Legacy cache profile must not be a symlink')
    if (old_path/'rootfs').is_dir() and (old_path/'stages.json').is_file():
        stages = load(old_path/'stages.json')
        if stages.get('schema') == 1 and 'Bootstrap Ubuntu' in stages.get('completed', []):
            print('HTTPBOOT_STAGE:Reusing compatible 3.0.0 desktop and package stages', flush=True)
            return old
    return current


def link_or_copy(source, target):
    try:
        os.link(source, target)
    except OSError as exc:
        if exc.errno != errno.EXDEV:
            raise
        shutil.copyfile(source, target)


class DesktopCache:
    def __init__(self, base, key):
        if not re.fullmatch('[0-9a-f]{64}',key):
            raise ValueError('Invalid desktop cache key')
        self.archives = cache_directories(base)
        self.path = base/'profiles'/key
        self.path.mkdir(exist_ok=True,mode=0o700)
        self.path.chmod(0o700)
        self.key = key
        self.root = self.path/'rootfs'
        self.lock = open(self.path/'build.lock','a')
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.lock.close()
            raise ValueError('A build already uses this desktop checkpoint; reconnect to it or wait')

    def close(self):
        self.lock.close()

    def has_mounts(self):
        prefix = str(self.root.resolve())
        return any(line.split()[4] == prefix or line.split()[4].startswith(prefix+'/')
                   for line in Path('/proc/self/mountinfo').read_text().splitlines())

    def restore(self, output):
        if self.root.is_symlink() or self.has_mounts():
            raise ValueError('Cached root has active mounts or an unsafe path; stop its old build before retrying')
        meta = self.path/'desktop.json'
        if not meta.exists():
            return None
        data = load(meta)
        if (not isinstance(data, dict) or data.get('key') != self.key or not self.root.is_dir() or
                not isinstance(data.get('artifacts'), dict) or not isinstance(data.get('kernel'), str) or
                not re.fullmatch('[A-Za-z0-9._+-]+', data['kernel'])):
            raise ValueError('Desktop checkpoint metadata is invalid')
        for name in ('filesystem.squashfs','vmlinuz'):
            path = self.path/name
            expected = data['artifacts'].get(name)
            if (not isinstance(expected, dict) or type(expected.get('size')) is not int or expected['size'] <= 0 or
                    not isinstance(expected.get('sha256'), str) or not re.fullmatch('[0-9a-f]{64}', expected['sha256'])):
                raise ValueError('Desktop checkpoint artifact metadata is invalid')
            if path.is_symlink() or path.stat().st_size != expected['size'] or sha256(path) != expected['sha256']:
                raise ValueError('Desktop checkpoint failed verification; use a fresh build to replace it')
        for name in ('filesystem.squashfs','vmlinuz'):
            link_or_copy(self.path/name, output/name)
        return data

    def stages(self):
        from build_support import Stages
        return Stages(self.path/'stages.json')

    def preserve_previous(self):
        if self.has_mounts():
            raise ValueError('Cannot replace a cached root with active mounts')
        existing = [self.path/name for name in ('rootfs','desktop.json','filesystem.squashfs','vmlinuz','stages.json') if (self.path/name).exists()]
        if existing:
            history = self.path/'history'/str(time.time_ns())
            history.mkdir(parents=True,mode=0o700)
            for path in existing:
                os.rename(path,history/path.name)

    def checkpoint(self, output, kernel):
        metadata = {'schema':1, 'key':self.key, 'created':time.time(), 'kernel':kernel, 'artifacts':{}}
        for name in ('filesystem.squashfs','vmlinuz'):
            source = output/name
            target = self.path/name
            link_or_copy(source,target)
            metadata['artifacts'][name] = {'size':source.stat().st_size, 'sha256':sha256(source)}
        dump(self.path/'desktop.json', metadata)
        return metadata


def seed_delta(cache,config,hashes):
    """Clone a verified matching identity checkpoint; never mutate the donor."""
    if cache.root.exists():return False
    base=cache.path.parent
    candidates=[]
    for meta in base.glob('*/desktop.json'):
        if meta.parent==cache.path or meta.parent.is_symlink():continue
        profile=meta.parent;root=profile/'rootfs'
        if not root.is_dir() or root.is_symlink():continue
        cfg=root/'etc/httpboot-client.json'
        if not cfg.is_file():continue
        c=load(cfg)
        if any(c.get(k)!=config.get(k) for k in ('server_ip','users')):continue
        # Password hashes must match exactly; no account migration by cloning.
        shadow={line.split(':')[0]:line.split(':')[1] for line in (root/'etc/shadow').read_text().splitlines()}
        if any(shadow.get(name)!=value for name,value in hashes.items()):continue
        candidates.append((meta.stat().st_mtime,profile))
    for _,profile in sorted(candidates,reverse=True):
        donor=DesktopCache(base.parent,profile.name)
        try:
            if donor.has_mounts():continue
            data=load(profile/'desktop.json')
            if any(sha256(profile/name)!=data['artifacts'][name]['sha256'] for name in ('filesystem.squashfs','vmlinuz')):continue
            needed=sum(p.stat().st_size for p in donor.root.rglob('*') if p.is_file() and not p.is_symlink())
            if shutil.disk_usage(cache.path).free<needed+8*1024**3:raise ValueError('Not enough space to clone the retained desktop; no caches were erased')
            temporary=cache.path/'rootfs.partial'
            if temporary.exists():temporary.rename(cache.path/('retained-partial-'+str(time.time_ns())))
            from common import run
            run(['cp','-a','--reflink=auto',donor.root,temporary]);os.rename(temporary,cache.root)
            stages=load(profile/'stages.json')
            stages['completed']=[name for name in stages['completed'] if name in ('Bootstrap Ubuntu','Install desktop and kernel','Install Chrome','Install Sober and Prism')]
            dump(cache.path/'stages.json',stages)
            dump(cache.path/'delta-parent.json',{'key':profile.name,'kernel':data['kernel']})
            print('HTTPBOOT_STAGE:Cloned verified cached desktop; reusing installed Ubuntu, kernel and applications',flush=True)
            return True
        finally:donor.close()
    return False
