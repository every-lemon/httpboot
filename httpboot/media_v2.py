"""Enroll an existing mounted FAT32 boot volume without formatting or replacing its identity."""
import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from common import atomic,dump,load
from client_updates import copy_verified


def ancestors(device):
    result=subprocess.run(['lsblk','--json','--inverse','-o','MAJ:MIN,TYPE',device],check=True,capture_output=True,text=True)
    identifiers=set()
    def visit(nodes):
        for node in nodes:
            identifiers.add(node['maj:min']);visit(node.get('children',[]))
    visit(json.loads(result.stdout)['blockdevices']);return identifiers


def enroll(authority,mount,release=None):
    mount=Path(mount).resolve(strict=True)
    if mount==Path('/') or not mount.is_mount():raise ValueError('Select the mountpoint of an existing FAT32 boot volume')
    details=subprocess.run(['findmnt','-n','-o','SOURCE,FSTYPE,UUID','--target',str(mount)],check=True,capture_output=True,text=True).stdout.split()
    if len(details)!=3 or details[1]!='vfat' or not details[0].startswith('/dev/'):
        raise ValueError('Boot media must be a mounted FAT32 block-device filesystem')
    selected=ancestors(details[0])
    for path in ('/','/boot','/boot/efi','/home','/var'):
        if not Path(path).exists():continue
        system=subprocess.run(['findmnt','-n','-o','SOURCE','--target',path],check=True,capture_output=True,text=True).stdout.strip()
        if not system.startswith('/dev/'):raise ValueError('Cannot establish protected system devices in this environment')
        if selected & ancestors(system):raise ValueError('The selected medium shares a protected system device')
    with authority.db() as db:
        row=db.execute('SELECT id,manifest FROM images WHERE id=?',(release,)).fetchone() if release else db.execute('SELECT id,manifest FROM images WHERE active=1').fetchone()
        if not row:raise ValueError('A qualified published release is required')
        release=row['id'];manifest=json.loads(row['manifest'])
        db.execute('INSERT OR IGNORE INTO image_pins VALUES (?,?)',(release,'enrolled-card:'+details[2]))
    source=authority.images.root/release
    needed=sum(manifest['artifacts'][name]['size'] for name in ('boot.efi','recovery.efi','recovery.squashfs'))*2+64*1024**2
    if shutil.disk_usage(mount).free<needed:raise ValueError('Insufficient free space to preserve existing startup files and recovery')
    subprocess.run(['mount','-o','remount,nosuid,nodev,noexec,umask=0077',str(mount)],check=True)
    base=mount/'httpboot-v2';identity=base/'identity';identity.mkdir(parents=True,exist_ok=True)
    legacy=mount/'httpboot/device.json'
    if legacy.is_file() and not (identity/'client.key').exists():
        value=load(legacy)
        atomic(identity/'client.key',value['key']);atomic(identity/'client.pem',value['certificate'])
    if (identity/'client.key').exists():
        # Renew an imported, approved key before the first v2 boot so verified
        # offline recovery does not depend on a successful online activation.
        from server_v2 import csr_key
        from control_transport import issue
        csr=subprocess.run(['openssl','req','-new','-key',str(identity/'client.key'),
                            '-subj','/CN=httpboot-client'],capture_output=True,text=True,check=True).stdout
        with authority.db() as db:
            device=db.execute('SELECT id FROM devices WHERE fingerprint=? AND approved=1',(csr_key(csr),)).fetchone()
            if not device:raise ValueError('Approve or migrate the existing device key before enrolling this card')
            certificate=issue(authority.database.parent/'pki',csr,device['id'])
            db.execute('UPDATE devices SET certificate=? WHERE id=?',(certificate,device['id']))
        atomic(identity/'client.pem',certificate)
    atomic(identity/'ca.pem',(authority.database.parent/'pki/ca.pem').read_bytes())
    backup=base/('before-'+str(time.time_ns()));backup.mkdir()
    targets=(('boot.efi',mount/'EFI/BOOT/BOOTX64.EFI'),('recovery.efi',mount/'EFI/HTTPBOOT/RECOVERY.EFI'))
    for name,target in targets:
        if target.is_file():shutil.copyfile(target,backup/name)
    from recovery_cache import publish
    publish(identity,manifest,source)
    # Commit the verified recovery generation before replacing the default
    # bootstrap. Old flat caches and generations remain readable after failure.
    for name,target in reversed(targets):
        copy_verified(source/name,target,manifest['artifacts'][name]['sha256'])
    dump(base/'media.json',{'schema':2,'release':release,'filesystem_uuid':details[2]})
    os.sync()
    return {'ok':True,'release':release,'filesystem_uuid':details[2],'identity_preserved':True,'formatted':False,
            'readback':'files verified before atomic replacement; remount verification required on the Client'}
