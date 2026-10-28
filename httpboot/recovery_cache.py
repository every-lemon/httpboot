"""Verified recovery generations with an atomic FAT-compatible active pointer."""
import os
import shutil
import tempfile
from pathlib import Path
from common import RELEASE,atomic,dump,load,recovery_size_ok,sha256


def selected(identity):
    identity=Path(identity);pointer=identity/'recovery-current'
    if not pointer.exists():return identity # Existing enrolled cards remain readable.
    release=pointer.read_text().strip()
    if not RELEASE.fullmatch(release):raise ValueError('Invalid recovery cache generation')
    return identity/'recovery-cache'/release


def publish(identity,manifest,sources):
    previous=selected(identity)
    release=manifest['release']
    if not RELEASE.fullmatch(release):raise ValueError('Invalid recovery release')
    recovery_size_ok(manifest['artifacts']['recovery.squashfs']['size'])
    parent=Path(identity)/'recovery-cache';parent.mkdir(parents=True,exist_ok=True)
    target=parent/release
    if target.exists():
        if load(target/'verified-image.json')!=manifest:raise ValueError('Recovery generations are immutable')
        if any(not (target/name).is_file() or (target/name).stat().st_size!=manifest['artifacts'][name]['size'] or sha256(target/name)!=manifest['artifacts'][name]['sha256'] for name in ('recovery.squashfs','recovery.efi')):
            target=parent/(release[:48]+'-repair-'+__import__('secrets').token_hex(6))
    if not target.exists():
        temporary=Path(tempfile.mkdtemp(prefix='.staging-',dir=parent))
        try:
            for name in ('recovery.squashfs','recovery.efi'):
                metadata=manifest['artifacts'][name]
                with open(sources/name,'rb') as source,open(temporary/name,'xb') as out:
                    shutil.copyfileobj(source,out,1024*1024);out.flush();os.fsync(out.fileno())
                if (temporary/name).stat().st_size!=metadata['size'] or sha256(temporary/name)!=metadata['sha256']:
                    raise ValueError('Recovery cache copy failed verification')
            dump(temporary/'verified-image.json',manifest)
            os.rename(temporary,target)
            directory=os.open(parent,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(directory)
            finally:os.close(directory)
        finally:
            if temporary.exists():shutil.rmtree(temporary)
    for name in ('recovery.squashfs','recovery.efi'):
        metadata=manifest['artifacts'][name]
        if (target/name).stat().st_size!=metadata['size'] or sha256(target/name)!=metadata['sha256']:
            raise ValueError('Recovery cache generation failed verification')
    # Previous generations stay intact through download, copy, and power loss.
    atomic(Path(identity)/'recovery-current',target.name+'\n')
    (Path(identity)/'recovery-invalid').unlink(missing_ok=True)
    # Prune only our recovery artifacts, and only when the previous generation
    # also passes verification. Never remove device credentials or user data.
    if previous!=target:
        try:
            prior=load(previous/'verified-image.json')
            valid=all((previous/name).is_file() and (previous/name).stat().st_size==prior['artifacts'][name]['size'] and sha256(previous/name)==prior['artifacts'][name]['sha256'] for name in ('recovery.squashfs','recovery.efi'))
            if valid:
                obsolete=[path for path in parent.iterdir() if path.is_dir() and not path.is_symlink() and RELEASE.fullmatch(path.name) and path not in (previous,target) and (path/'verified-image.json').is_file()]
                if previous!=Path(identity):obsolete.append(Path(identity))
                for folder in obsolete:
                    for name in ('recovery.squashfs','recovery.efi','verified-image.json'):(folder/name).unlink(missing_ok=True)
                    if folder!=Path(identity):
                        try:folder.rmdir()
                        except OSError:pass
        except (OSError,ValueError,KeyError):pass  # Retention cannot invalidate a successful promotion.
    return target


def available(identity, manifest):
    """Fast online cache check; execution still requires full signature/hash checks.

    Files are never trusted for execution by this check. It only avoids redundant
    network transfer for an already atomically published, signed generation.
    """
    try:
        cache=selected(identity)
        marker=Path(identity)/'recovery-invalid'
        if marker.exists() and marker.read_text().strip()==cache.name:return False
        if load(cache/'verified-image.json')!=manifest:return False
        return all((cache/name).is_file() and (cache/name).stat().st_size==manifest['artifacts'][name]['size']
                   for name in ('recovery.squashfs','recovery.efi'))
    except (OSError,ValueError,KeyError):return False


def reuse(identity, manifest, name, target):
    """Reuse verified identical content from a previous release without networking."""
    try:
        cache=selected(identity);old=load(cache/'verified-image.json')
        metadata=manifest['artifacts'][name];source=cache/name
        if old['artifacts'][name]!=metadata or not source.is_file():return False
        if source.stat().st_size!=metadata['size'] or sha256(source)!=metadata['sha256']:return False
        target=Path(target)
        with source.open('rb') as stream,target.open('wb') as out:
            shutil.copyfileobj(stream,out,1024*1024);out.flush();os.fsync(out.fileno())
        return True
    except (OSError,ValueError,KeyError):return False


def check_integrity(identity):
    """Background readback; mark corruption for a bounded repair on next boot."""
    cache=selected(identity);manifest=load(cache/'verified-image.json')
    for name in ('recovery.squashfs','recovery.efi'):
        metadata=manifest['artifacts'][name]
        if not (cache/name).is_file() or (cache/name).stat().st_size!=metadata['size'] or sha256(cache/name)!=metadata['sha256']:
            atomic(Path(identity)/'recovery-invalid',cache.name+'\n')
            raise ValueError('Offline recovery failed integrity verification; previous generations retained')
    return True
