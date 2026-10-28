"""Encrypted pending work on an explicitly approved filesystem, never a verified save."""
import json
import os
import re
import subprocess
import tarfile
import time
from pathlib import Path
from persistence_v2 import Home,identity


def validate(policy):
    if not isinstance(policy,dict) or set(policy)!={'uuid','mountpoint','recipient'}:raise ValueError('Invalid pending-media policy')
    if not isinstance(policy['uuid'],str) or not re.fullmatch(r'[A-Za-z0-9-]{4,64}',policy['uuid']):raise ValueError('Invalid approved filesystem UUID')
    path=Path(policy['mountpoint'])
    if not path.is_absolute() or '..' in path.parts or path==Path('/'):raise ValueError('Invalid approved media mountpoint')
    if not re.fullmatch(r'age1[0-9a-z]{50,100}',policy['recipient']):raise ValueError('Use an administrator-provided age public recipient')
    return policy


def save(home,rules,policy,user,run_source=None):
    policy=validate(policy);mount=Path(policy['mountpoint'])
    if mount.is_symlink() or not mount.is_dir():raise ValueError('Approved pending-save medium is unavailable')
    actual=subprocess.run(['findmnt','-n','-o','UUID','--target',str(mount)],check=True,capture_output=True,text=True).stdout.strip()
    if actual!=policy['uuid']:raise ValueError('Mounted filesystem does not match the administrator-approved medium')
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,30}',user):raise ValueError('Invalid account name')
    folder=mount/'httpboot-pending';folder.mkdir(mode=0o700,exist_ok=True)
    if folder.is_symlink():raise ValueError('Pending storage must not be a symlink')
    target=folder/(user+'-'+str(time.time_ns())+'.tar.age');partial=target.with_suffix('.partial')
    process=subprocess.Popen(['age','-r',policy['recipient'],'-o',str(partial)],stdin=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        source=Home(home)
        with tarfile.open(fileobj=process.stdin,mode='w|') as archive:
            for rule in rules:
                for path,expected in source.walk(rule['folder']):
                    with source.file(rule['folder'],path) as stream:
                        if identity(os.fstat(stream.fileno()))!=expected:raise ValueError('Pending file changed before encryption')
                        record=tarfile.TarInfo(rule['folder']+'/'+path);record.size=expected[2];record.mode=0o600
                        archive.addfile(record,stream)
                        if identity(os.fstat(stream.fileno()))!=expected:raise ValueError('Pending file changed during encryption')
        process.stdin.close()
        if process.wait(timeout=120):raise ValueError('Pending-work encryption failed')
        os.replace(partial,target)
        return {'file':target.name,'verified_backup':False,'message':'Encrypted pending work retained; applications may require recovery. This is not a verified application backup.'}
    finally:
        if process.poll() is None:process.kill();process.wait()
        if process.stdin and not process.stdin.closed:process.stdin.close()
        if process.stderr:process.stderr.close()
        partial.unlink(missing_ok=True)
