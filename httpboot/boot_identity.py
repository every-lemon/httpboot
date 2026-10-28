"""Select and verify persistent Client identity storage before enrollment."""
import json
import os
import subprocess
import time
from pathlib import Path
from common import atomic,load

MOUNT=Path('/run/httpboot-v2/media')


def firmware_partition(root=Path('/sys/firmware/efi/efivars')):
    for file in root.glob('LoaderDevicePartUUID-*'):
        try:
            value=file.read_bytes()[4:].decode('utf-16-le').rstrip('\0').lower()
            if __import__('re').fullmatch('[0-9a-f-]{36}',value):return value
        except (OSError,UnicodeError):pass
    return None


def choose(candidates,boot_partition=None):
    matching=[row for row in candidates if row['partuuid'] and row['partuuid'].lower()==boot_partition]
    if len(matching)==1:return matching[0]
    if len(candidates)==1:return candidates[0]
    if not candidates:raise ValueError('No persistent Client identity volume was detected')
    raise ValueError('Multiple HTTP Boot volumes found; select the intended boot volume')


def verify_writable(identity):
    identity.mkdir(parents=True,exist_ok=True,mode=0o700)
    probe=identity/'.write-check';value=os.urandom(32)
    try:
        atomic(probe,value)
        if probe.read_bytes()!=value:raise ValueError('Identity storage readback failed')
    finally:probe.unlink(missing_ok=True)
    # Existing credentials are never replaced to repair a failed read.
    key=identity/'client.key'
    if (identity/'client.pem').exists() and not key.exists():raise ValueError('Certificate exists but the Client key is missing; restore the original identity')
    if key.exists():
        public=subprocess.run(['openssl','pkey','-in',str(key),'-pubout'],check=True,capture_output=True).stdout
        certificate=identity/'client.pem'
        if certificate.exists():
            enrolled=subprocess.run(['openssl','x509','-in',str(certificate),'-pubkey','-noout'],check=True,capture_output=True).stdout
            if enrolled!=public:raise ValueError('Stored certificate does not match its Client key; original identity retained')


def persist_credentials(identity):
    identity=Path(identity)
    for name in ('client.key','client.csr','client.pem','ca.pem'):
        file=identity/name
        if file.exists():
            with file.open('rb') as stream:os.fsync(stream.fileno())
    descriptor=os.open(identity,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(descriptor)
    finally:os.close(descriptor)
    key=identity/'client.key'
    if key.exists():
        public=subprocess.run(['openssl','pkey','-in',str(key),'-pubout'],capture_output=True,check=True).stdout
        csr=identity/'client.csr'
        if csr.exists():
            requested=subprocess.run(['openssl','req','-in',str(csr),'-pubkey','-noout'],capture_output=True,check=True).stdout
            if public!=requested:raise ValueError('Stored Client request does not match its key; original identity retained')


def discover():
    MOUNT.mkdir(parents=True,exist_ok=True)
    candidates=[]
    for device in subprocess.run(['blkid','-t','TYPE=vfat','-o','device'],capture_output=True,text=True).stdout.split():
        result=subprocess.run(['mount','-t','vfat','-o','ro,nosuid,nodev,noexec,umask=0077',device,str(MOUNT)],capture_output=True)
        if result.returncode:continue
        try:
            if (MOUNT/'httpboot-v2').is_dir():
                part=subprocess.run(['blkid','-s','PARTUUID','-o','value',device],capture_output=True,text=True).stdout.strip()
                candidates.append({'device':device,'partuuid':part})
        finally:subprocess.run(['umount',str(MOUNT)],check=True)
    return candidates


def prepare():
    candidates=[]
    for attempt in range(10):
        candidates=discover()
        if candidates:break
        subprocess.run(['udevadm','settle','--timeout=2'],capture_output=True)
        time.sleep(1)
    try:selection=choose(candidates,firmware_partition())
    except ValueError as error:
        if not candidates:raise
        choices=[item for row in candidates for item in (row['device'],row['partuuid'] or 'HTTP Boot volume')]
        console=open('/dev/console','w')
        result=subprocess.run(['whiptail','--title','HTTP Boot identity storage','--menu',str(error),'20','78','10',*choices],stdout=console,stderr=subprocess.PIPE,text=True)
        console.close()
        if result.returncode:raise ValueError('Identity volume selection cancelled')
        selection=next(row for row in candidates if row['device']==result.stderr.strip())
    subprocess.run(['mount','-t','vfat','-o','rw,nosuid,nodev,noexec,umask=0077',selection['device'],str(MOUNT)],check=True)
    try:
        identity=MOUNT/'httpboot-v2/identity';verify_writable(identity)
        embedded=Path('/httpboot/embedded-identity/client.key')
        if embedded.exists():
            if (identity/'client.key').exists() and embedded.read_bytes()!=(identity/'client.key').read_bytes():
                raise ValueError('Boot-volume identity differs from the verified kernel-transition identity')
            if not (identity/'client.key').exists():
                for file in embedded.parent.iterdir():
                    if file.name in ('client.key','client.pem','client.csr','ca.pem'):atomic(identity/file.name,file.read_bytes())
        atomic(Path('/run/httpboot-v2/identity-storage.json'),json.dumps({'state':'persistent','partuuid':selection['partuuid']}))
        return identity
    except BaseException:
        subprocess.run(['umount',str(MOUNT)],check=True)
        raise


if __name__=='__main__':
    try:print(prepare())
    except Exception as error:
        print('Identity storage: '+str(error),file=__import__('sys').stderr)
        raise SystemExit(1)
