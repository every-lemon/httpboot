"""Interactive v2 USB/SD creation with protected-device checks and readback."""
import json
import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from common import load, run, sha256
import storage

EFI=Path('EFI/BOOT/BOOTX64.EFI')
ESP='c12a7328-f81f-11d2-ba4b-00a0c93ec93b'
EXTRA_FILES=('recovery.efi','recovery.squashfs')
FAT_MAX=4*1024**3-1


def verify_file(path, metadata):
    if path.is_symlink() or not path.is_file() or path.stat().st_size != metadata['size'] or sha256(path) != metadata['sha256']:
        raise ValueError('Boot/recovery file failed verification: '+path.name)


class Cancelled(Exception):
    pass


class Dialog:
    def call(self, title, arguments):
        result=subprocess.run(['whiptail','--title',title,*arguments],stderr=subprocess.PIPE,text=True)
        if result.returncode:raise Cancelled()
        return result.stderr.strip()
    def menu(self,title,message,options):
        return self.call(title,['--menu',message,'22','90','12',*[str(v) for pair in options for v in pair]])
    def input(self,title,message):
        return self.call(title,['--inputbox',message,'16','90'])
    def yes(self,title,message,default=False):
        return subprocess.run(['whiptail','--title',title,'--defaultno','--yesno',message,'16','90']).returncode==0
    def message(self,title,message):
        subprocess.run(['whiptail','--title',title,'--msgbox',message,'20','90'],check=False)


def identity(nodes, path):
    value = storage.identity(nodes[path])
    parents, seen = list(nodes[path].get('parents', [])), set()
    ancestors = []
    while parents:
        parent = parents.pop()
        if parent in seen:
            continue
        seen.add(parent)
        node = nodes[parent]
        ancestors.append({k: node.get(k) for k in ('path', 'type', 'size', 'serial', 'wwn', 'maj:min')})
        parents.extend(node.get('parents', []))
    value['ancestors'] = sorted(ancestors, key=lambda n: n['path'])
    return value


def protect_family(nodes, protected, selected):
    """Exclude every partition of the data/state drive, even when unmounted."""
    queue, family = [selected], set()
    while queue:
        path = queue.pop()
        if path in family or path not in nodes:
            continue
        family.add(path)
        queue.extend(nodes[path].get('parents', []))
    for path in family:
        protected.update(storage.descendants(nodes, path))


def inventory(config, state):
    nodes, protected = storage.inventory()
    for path in (config['data_dir'], config['web_dir'], str(state)):
        found = run(['findmnt', '--json', '--target', path, '--output', 'MAJ:MIN'], capture_output=True, text=True)
        ids = {m['maj:min'] for m in json.loads(found.stdout).get('filesystems', [])}
        if not ids or not any(n.get('maj:min') in ids for n in nodes.values()):
            raise ValueError('Cannot trace the workstation data disk; media writing is disabled')
        for name, node in nodes.items():
            if node.get('maj:min') in ids:
                protect_family(nodes, protected, name)
    # UUID also protects a configured volume if its usual directory is on another mount.
    for name, node in nodes.items():
        if config.get('storage', {}).get('uuid') == node.get('uuid') and node.get('uuid'):
            protect_family(nodes, protected, name)
    return nodes, protected


def eligible(nodes, protected, path, mode):
    if mode not in ('erase', 'reuse', 'reuse-new'):
        raise ValueError('Unknown boot-media preparation mode')
    node = nodes[path]
    if not storage.usable(nodes, protected, path, True):
        return False
    return (node['type'] == 'disk' if mode == 'erase' else
            node['type'] == 'part' and (mode == 'reuse-new' or node.get('fstype') == 'vfat'))


def recheck(expected, mode, config, state):
    nodes, protected = inventory(config, state)
    path = expected['path']
    if path not in nodes or identity(nodes, path) != expected:
        raise ValueError('Device identity changed. Reselect the USB/SD.')
    if not eligible(nodes, protected, path, mode) or not stat.S_ISBLK(os.stat(path).st_mode):
        raise ValueError('Target is protected, mounted, read-only, or in use')
    return nodes


def verify_fat32(path):
    with open(path, 'rb') as stream:
        header = stream.read(512)
    if len(header) != 512 or header[82:90] != b'FAT32   ' or header[510:512] != b'\x55\xaa':
        raise ValueError('Existing partition must be FAT32 (not FAT16/exFAT)')
    kind = run(['lsblk', '--nodeps', '--noheadings', '--output', 'PARTTYPE', path], capture_output=True, text=True).stdout.strip().lower()
    if kind not in (ESP, '0xef', 'ef'):
        raise ValueError('Existing FAT32 partition must be an EFI System Partition; use erase-and-create for other media')


def write(authority, ui, config, manifest, source, expected, mode):
    if mode not in ('erase', 'reuse'):
        raise ValueError('Unknown boot-media preparation mode')
    state = authority.database.parent
    from common import recovery_size_ok
    if (source/'recovery.squashfs').exists():
        recovery_size_ok((source/'recovery.squashfs').stat().st_size)
    efi_size = sum((source/n).stat().st_size for n in ('boot.efi', *EXTRA_FILES) if (source/n).exists())
    if any((source/n).stat().st_size > FAT_MAX for n in ('boot.efi', *EXTRA_FILES) if (source/n).exists()):
        raise ValueError('EFI executable exceeds FAT32 file limits')
    required = max(512 * 1024**2, efi_size * 2 + 64 * 1024**2)
    if int(expected['size']) < required:
        raise ValueError('Target is too small for verified boot media (minimum 512 MiB)')
    recheck(expected, mode, config, state)
    path = expected['path']
    if mode == 'erase':
        answer = ui.input('Erase boot device', f"ALL DATA WILL BE LOST on {path}\nSerial: {expected.get('serial') or 'unreported'}\nCapacity: {int(expected['size']) / 1024**3:.1f} GiB\nType exactly: ERASE {path}")
        if answer != f'ERASE {path}':
            raise ValueError('Erase confirmation did not match; nothing was erased')
    elif not ui.yes('Use existing FAT32', f'Write boot files to {path} without formatting? The partition must be unmounted.', False):
        raise ValueError('Media creation cancelled')
    recheck(expected, mode, config, state)
    if mode == 'reuse':
        verify_fat32(path)
    # Protect before first write, including an interrupted operation that might leave a bootable card.
    with authority.db() as db:
        db.execute('INSERT OR IGNORE INTO image_pins VALUES (?,?)', (manifest['release'], 'media-write:'+expected['path']))
    if mode == 'erase':
        run(['wipefs', '--all', path])
        # UUID/filesystem signatures changed intentionally; all immutable identity fields must match.
        nodes, protected = inventory(config, state)
        fixed = ('path', 'type', 'size', 'serial', 'wwn', 'maj:min')
        if path not in nodes or any(nodes[path].get(k) != expected.get(k) for k in fixed) or not eligible(nodes, protected, path, mode):
            raise ValueError('Device changed after wipe; stopped before partitioning')
        run(['sfdisk', '--wipe', 'always', path], input=f'label: gpt\nstart=2048, type={ESP}\n', text=True)
        run(['udevadm', 'settle'])
        nodes, protected = inventory(config, state)
        children = [n for n in nodes.values() if n.get('parent') == path and n['type'] == 'part']
        if (path not in nodes or any(nodes[path].get(k) != expected.get(k) for k in fixed) or len(children) != 1 or
                not storage.usable(nodes, protected, path, True)):
            raise ValueError('New boot partition became unsafe; stopped before formatting')
        child = children[0]
        path = child['path']
        recheck(identity(nodes, path), 'reuse-new', config, state)
        run(['mkfs.vfat', '-F', '32', '-n', 'HTTPBOOT', path])
        run(['udevadm', 'trigger', '--action=change', '--subsystem-match=block', '--sysname-match=' + Path(path).name])
        run(['udevadm', 'settle'])
    # Recheck after format and before mount; never write to an already mounted partition.
    nodes, protected = inventory(config, state)
    if path not in nodes or not eligible(nodes, protected, path, 'reuse'):
        raise ValueError('Boot partition became active or unavailable before mounting')
    if mode == 'reuse' and identity(nodes, path) != expected:
        raise ValueError('Device identity changed before mounting')
    if mode == 'erase':
        fixed_child = ('path', 'type', 'size', 'serial', 'wwn', 'maj:min')
        parent = expected['path']
        if (any(nodes[path].get(k) != child.get(k) for k in fixed_child) or parent not in nodes or
                any(nodes[parent].get(k) != expected.get(k) for k in fixed)):
            raise ValueError('Device identity changed after formatting')
    mount_identity = identity(nodes, path)
    mount = Path(tempfile.mkdtemp(prefix='httpboot-boot-media-'))
    mounted = False
    try:
        recheck(mount_identity, 'reuse', config, state)
        run(['mount', '-t', 'vfat', '-o', 'rw,nosuid,nodev,noexec,umask=0077', path, mount])
        mounted = True
        from media_v2 import enroll
        print('Copying and verifying bootstrap and recovery files. Please wait...', flush=True)
        enroll(authority, mount, manifest['release'])
        run(['umount', mount])
        mounted = False
        recheck(mount_identity, 'reuse', config, state)
        run(['mount', '-t', 'vfat', '-o', 'ro,nosuid,nodev,noexec', path, mount])
        mounted = True
        from recovery_cache import selected
        cache = selected(mount/'httpboot-v2/identity')
        for name, target in (('boot.efi', mount/EFI), ('recovery.efi', mount/'EFI/HTTPBOOT/RECOVERY.EFI'),
                             ('recovery.efi', cache/'recovery.efi'), ('recovery.squashfs', cache/'recovery.squashfs')):
            verify_file(target, manifest['artifacts'][name])
        if load(mount/'httpboot-v2/media.json')['release'] != manifest['release']:
            raise ValueError('Boot-media metadata readback failed')
    finally:
        if mounted or os.path.ismount(mount):
            try:
                run(['umount', mount])
            except subprocess.CalledProcessError as exc:
                raise ValueError(f'Could not unmount {mount}; mount directory retained. Do not remove media yet.') from exc
        if os.path.ismount(mount):
            raise ValueError(f'{mount} is still mounted; directory retained. Do not remove media yet.')
        shutil.rmtree(mount)
    ui.message('Boot media verified', 'Safe to remove the USB/SD. Boot the Client in UEFI mode with Secure Boot disabled.\n\nA new card generates its device key on first boot. Approve its pairing code and assign accounts on the Server. Recovery files are cached, but offline recovery requires completed activation. Existing approved card identities are preserved. No Client restart was requested.')

def interactive(authority,ui=None):
    ui=ui or Dialog()
    try:
        if subprocess.run(['systemd-detect-virt','--container','--quiet']).returncode==0:
            raise ValueError('Prepare physical USB/SD media on the Server, not inside a container')
        missing=[name for name in ('sfdisk','mkfs.vfat','lsblk','mount','wipefs','udevadm','whiptail') if not shutil.which(name)]
        if missing:raise ValueError('Missing media tools: '+', '.join(missing)+'. Install fdisk, dosfstools, util-linux, udev and whiptail.')
        with authority.db() as db:
            row=db.execute('SELECT id,manifest FROM images WHERE active=1').fetchone()
        if not row:raise ValueError('Publish a qualified image before preparing USB/SD media')
        manifest=json.loads(row['manifest']);source=authority.images.root/row['id']
        config={'data_dir':str(authority.database.parent),'web_dir':str(authority.images.root)}
        # Also protect legacy data/web volumes during a side-by-side migration.
        legacy=Path('/etc/httpboot/server.json')
        if legacy.exists():
            value=load(legacy)
            config={key:value[key] for key in ('data_dir','web_dir')}
            if 'storage' in value:config['storage']=value['storage']
        mode=ui.menu('Create/update Client USB or SD', 'Current qualified image: '+row['id']+'\nUnmount the target first. System and Server data disks are excluded.',
                     [('erase','Erase an unused USB/SD; create GPT + FAT32 EFI partition'),
                      ('reuse','Update an unused FAT32 EFI partition; preserve identity and files')])
        nodes,protected=inventory(config,authority.database.parent)
        options=[(path,f"{n.get('model') or ''} {int(n['size'])/1024**3:.1f} GiB | serial {n.get('serial') or 'unreported'}")
                 for path,n in nodes.items() if int(n['size'])>=512*1024**2 and eligible(nodes,protected,path,mode)]
        if not options:raise ValueError('No eligible media. Unmount an unused USB/SD; system and Server data disks are protected.')
        path=ui.menu('Select USB/SD','Check model, serial and capacity carefully:',options)
        expected=identity(nodes,path)
        print('Verifying published startup and recovery files before any disk changes...',flush=True)
        for name in ('boot.efi',*EXTRA_FILES):verify_file(source/name,manifest['artifacts'][name])
        write(authority,ui,config,manifest,source,expected,mode)
    except Cancelled:
        return
    except (ValueError,OSError,subprocess.CalledProcessError) as error:
        ui.message('USB/SD preparation stopped',str(error)+'\nNo Client restart was requested.')
        raise
