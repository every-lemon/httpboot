"""Block-device discovery and explicit, identity-checked storage preparation."""
import copy
import json
import os
import re
import shutil
import stat
import subprocess
import time
from pathlib import Path

from common import atomic, dump, run, validate_config
from storage_guard import check as check_mount

FSTAB = Path('/etc/fstab')
COLUMNS = 'NAME,PATH,TYPE,SIZE,MODEL,SERIAL,WWN,TRAN,FSTYPE,UUID,MOUNTPOINTS,PKNAME,RO,MAJ:MIN'


class Settings(dict):
    """A questionnaire draft can carry a plan without changing persisted config."""
    storage_plan = None
    deployed = False


def flatten(nodes):
    result = {}
    def walk(items, parent=None):
        for item in items:
            n = dict(item)
            n['parent'] = parent
            n['children_paths'] = [c['path'] for c in n.get('children', [])]
            n.pop('children', None)
            # lsblk can repeat nodes for devices with multiple parents: protect either branch.
            if n['path'] in result:
                n['parents'] = result[n['path']].get('parents', []) + ([parent] if parent else [])
            else:
                n['parents'] = [parent] if parent else []
            result[n['path']] = n
            walk(item.get('children', []), n['path'])
    walk(nodes)
    return result


def inventory():
    raw = json.loads(run(['lsblk', '--json', '--bytes', '--paths', '--output', COLUMNS],
                         capture_output=True, text=True).stdout)
    nodes = flatten(raw['blockdevices'])
    swaps = {str(Path(line.split()[0]).resolve()) for line in Path('/proc/swaps').read_text().splitlines()[1:]}
    critical = set()
    root_ids = set()
    protected_dirs = ('/', '/boot', '/boot/efi', '/usr', '/var', '/home')
    for target in protected_dirs:
        r = subprocess.run(['findmnt', '--json', '--target', target, '--output', 'MAJ:MIN'], capture_output=True, text=True)
        if r.returncode == 0:
            for item in json.loads(r.stdout).get('filesystems', []):
                critical.add(item.get('maj:min'))
                if target == '/':
                    root_ids.add(item.get('maj:min'))
        elif target == '/':
            raise ValueError('Cannot identify the running root filesystem; disk preparation is disabled')
    if not root_ids or not any(n.get('maj:min') in root_ids for n in nodes.values()):
        raise ValueError('Cannot trace the system disk through lsblk; disk preparation is disabled')
    # Swap files also protect their backing filesystem.
    for path in swaps:
        if not path.startswith('/dev/'):
            r = subprocess.run(['findmnt', '--json', '--target', path, '--output', 'MAJ:MIN'], capture_output=True, text=True)
            if r.returncode == 0:
                critical.update(m.get('maj:min') for m in json.loads(r.stdout).get('filesystems', []))
    protected = {p for p, n in nodes.items() if n.get('maj:min') in critical or str(Path(p).resolve()) in swaps}
    queue = list(protected)
    while queue:
        for parent in nodes[queue.pop()].get('parents', []):
            if parent and parent not in protected:
                protected.add(parent)
                queue.append(parent)
    # Protect every partition on a system disk, not merely the mounted root partition.
    for p, n in nodes.items():
        current = n
        while current.get('parent'):
            if current['parent'] in protected:
                protected.add(p)
                break
            current = nodes[current['parent']]
    return nodes, protected


def identity(node):
    return {k: node.get(k) for k in ('path', 'type', 'size', 'serial', 'wwn', 'maj:min', 'uuid', 'fstype')}


def descendants(nodes, path):
    result = {path}
    queue = [path]
    while queue:
        for child in nodes[queue.pop()].get('children_paths', []):
            if child not in result:
                result.add(child)
                queue.append(child)
    return result


def usable(nodes, protected, path, destructive):
    n = nodes[path]
    if path in protected or n.get('ro') or n['type'] not in ('disk', 'part'):
        return False
    group = descendants(nodes, path)
    if destructive:
        for p in group:
            item = nodes[p]
            if p in protected or any(item.get('mountpoints') or []) or item['type'] not in ('disk', 'part'):
                return False
            holders = Path('/sys/dev/block') / item['maj:min'] / 'holders'
            if holders.is_dir() and any(holders.iterdir()):
                return False
    return True


def select(ui):
    if subprocess.run(['systemd-detect-virt', '--container', '--quiet']).returncode == 0:
        raise ValueError('Prepare physical storage on the bare-metal Server, not from inside a container')
    mode = ui.menu('Storage action', 'Choose how to use the DS72 or another data device:', [
        ('reuse', 'Reuse an existing ext4 partition; preserve existing files'),
        ('partition', 'Erase and format one unused partition'),
        ('disk', 'Erase an entire unused disk and create one ext4 partition')])
    nodes, protected = inventory()
    options = []
    for path, n in nodes.items():
        desired = 'disk' if mode == 'disk' else 'part'
        if n['type'] != desired or not usable(nodes, protected, path, mode != 'reuse'):
            continue
        if mode == 'reuse' and (n.get('fstype') != 'ext4' or not n.get('uuid')):
            continue
        label = f"{n.get('model') or ''} {int(n['size']) / 1024**3:.1f} GiB | serial {n.get('serial') or 'not reported'} | {n.get('fstype') or 'unformatted'}"
        options.append((path, label))
    if not options:
        raise ValueError('No eligible device found. System disks, active storage, and read-only devices are excluded. Unmount an unused target before formatting.')
    path = ui.menu('Select storage', 'Check the device model and capacity carefully:', options)
    node = nodes[path]
    mounts = [m for m in node.get('mountpoints', []) if m]
    mountpoint = mounts[0] if mode == 'reuse' and mounts else '/srv/httpboot'
    if not re.fullmatch(r'/[A-Za-z0-9_./-]+', mountpoint) or '..' in Path(mountpoint).parts or mountpoint == '/':
        raise ValueError('Select an ext4 volume with a simple mount path, or unmount it first')
    return {'schema': 1, 'mode': mode, 'identity': identity(node), 'mountpoint': mountpoint}


def planned_settings(config, plan):
    c = Settings(copy.deepcopy(config))
    c['schema'] = 1
    c.pop('storage', None)
    base = Path(plan['mountpoint']) / 'httpboot'
    c['data_dir'], c['web_dir'] = str(base / 'data'), str(base / 'boot')
    c['require_data_mount'] = False  # The mount is checked after the plan has been executed.
    c.storage_plan = plan
    return c


def verify_plan(plan):
    if set(plan) != {'schema', 'mode', 'identity', 'mountpoint'} or plan['schema'] != 1 or plan['mode'] not in ('reuse', 'partition', 'disk'):
        raise ValueError('Invalid storage plan; reselect the device')
    mountpoint = plan['mountpoint']
    if not isinstance(mountpoint, str) or not re.fullmatch(r'/[A-Za-z0-9_./-]+', mountpoint) or '..' in Path(mountpoint).parts or mountpoint == '/':
        raise ValueError('Invalid planned mount point')
    nodes, protected = inventory()
    path = plan['identity']['path']
    if path not in nodes or identity(nodes[path]) != plan['identity']:
        raise ValueError('Device identity changed. Reselect storage; nothing was erased.')
    expected_type = 'disk' if plan['mode'] == 'disk' else 'part'
    if nodes[path]['type'] != expected_type or not usable(nodes, protected, path, plan['mode'] != 'reuse'):
        raise ValueError('The selected device is now in use or protected; nothing was erased')
    if plan['mode'] == 'reuse' and nodes[path].get('fstype') != 'ext4':
        raise ValueError('Reuse requires an existing ext4 filesystem')
    if not stat.S_ISBLK(os.stat(path).st_mode):
        raise ValueError('Selected path is not a block device')
    return path


def mount_uuid(uuid, mountpoint, fstab=FSTAB):
    """Only this tool's marked fstab entry is replaced; restore it if mount fails."""
    target = Path(mountpoint)
    if not re.fullmatch(r'[a-fA-F0-9-]{16,64}', uuid):
        raise ValueError('Unexpected filesystem UUID')
    if not re.fullmatch(r'/[A-Za-z0-9_./-]+', mountpoint) or '..' in target.parts or mountpoint == '/':
        raise ValueError('Unsafe data mount path')
    if target.is_symlink() or any(p.is_symlink() for p in target.parents):
        raise ValueError('The data mount path must not contain symlinks')
    previous = fstab.read_bytes()
    text = previous.decode()
    marker = '# httpboot-managed'
    entries = []
    mount_options = 'defaults,nofail,x-systemd.device-timeout=10s'
    for line in text.splitlines():
        fields = line.split()
        if marker in line:
            continue
        if fields and not line.lstrip().startswith('#') and len(fields) >= 2:
            if fields[0].lower() == f'uuid={uuid}'.lower() or fields[1] == mountpoint:
                if fields[0].lower() != f'uuid={uuid}'.lower() or fields[1] != mountpoint:
                    raise ValueError('Existing fstab entry conflicts with this UUID or mount point')
                if len(fields) < 4 or fields[2] != 'ext4' or 'ro' in fields[3].split(','):
                    raise ValueError('Existing fstab entry is not a writable ext4 data volume')
                retained = [o for o in fields[3].split(',') if o != 'nofail' and not o.startswith('x-systemd.device-timeout=')]
                mount_options = ','.join([*retained, 'nofail', 'x-systemd.device-timeout=10s'])
                continue
        entries.append(line)
    target.mkdir(parents=True, exist_ok=True)
    if os.path.ismount(target):
        check_mount(uuid, mountpoint)
    elif any(target.iterdir()):
        raise ValueError('Mount point contains files; choose an empty mount point')
    backup = fstab.with_name(fstab.name + f'.httpboot-{time.time_ns()}.bak')
    shutil.copy2(fstab, backup)
    entries.append(f'UUID={uuid} {mountpoint} ext4 {mount_options} 0 2 {marker}')
    atomic(fstab, '\n'.join(entries) + '\n', 0o644)
    mounted_here = False
    try:
        run(['findmnt', '--verify', '--tab-file', fstab], capture_output=True)
        run(['systemctl', 'daemon-reload'])
        if not os.path.ismount(target):
            run(['mount', '--fstab', fstab, mountpoint])
            mounted_here = True
        check_mount(uuid, mountpoint)
    except BaseException:
        if mounted_here:
            subprocess.run(['umount', mountpoint], check=False)
        atomic(fstab, previous, 0o644)
        subprocess.run(['systemctl', 'daemon-reload'], check=False)
        raise


def execute(plan, ui, config):
    path = verify_plan(plan)
    if plan['mode'] != 'reuse':
        i = plan['identity']
        phrase = 'ERASE ' + path
        ui.message('Erase selected storage', f"Device: {path}\nSerial: {i.get('serial') or 'not reported'}\n"
                   f"Capacity: {int(i['size']) / 1024**3:.1f} GiB\n\n"
                   + ('ALL partitions and files on this disk will be destroyed.' if plan['mode'] == 'disk' else 'All files on this partition will be destroyed; other partitions are retained.'))
        if ui.input('Confirm erasure', f'Type exactly {phrase} to continue:') != phrase:
            raise ValueError('Erase confirmation did not match. No disk changes were made.')
        path = verify_plan(plan)  # Recheck after the human confirmation and before every destructive tool.
        if plan['mode'] == 'disk':
            run(['wipefs', '--all', path])
            # Later checks cannot compare the old partition table; identity of the parent remains fixed.
            fresh, protected = inventory()
            fixed = ('path', 'type', 'size', 'serial', 'wwn', 'maj:min')
            if any(fresh[path].get(k) != plan['identity'].get(k) for k in fixed) or not usable(fresh, protected, path, True):
                raise ValueError('Device changed after removing signatures; stopped before partitioning')
            run(['sfdisk', '--wipe', 'always', path], input=b'label: gpt\n, , L\n')
            run(['udevadm', 'settle'])
            nodes, _ = inventory()
            children = [nodes[p] for p in nodes[path]['children_paths'] if nodes[p]['type'] == 'part']
            if len(children) != 1:
                raise ValueError('Partition creation did not produce exactly one partition; inspect the device')
            path = children[0]['path']
            fresh, protected = inventory()
            if (path not in fresh or identity(fresh[path]) != identity(children[0]) or
                    any(fresh[plan['identity']['path']].get(k) != plan['identity'].get(k) for k in fixed) or
                    not usable(fresh, protected, path, True)):
                raise ValueError('New partition became active; stopped before formatting')
        else:
            verify_plan(plan)
        run(['mkfs.ext4', '-F', '-L', 'httpboot-data', path])
        run(['udevadm', 'settle'])
    uuid = run(['blkid', '-s', 'UUID', '-o', 'value', path], capture_output=True, text=True).stdout.strip()
    mount_uuid(uuid, plan['mountpoint'])
    base = Path(plan['mountpoint']) / 'httpboot'
    if base.is_symlink():
        raise ValueError('Managed storage directory must not be a symlink')
    marker = base / '.volume.json'
    if base.exists() and any(base.iterdir()):
        if not marker.is_file() or marker.is_symlink() or json.loads(marker.read_text()) != {'uuid': uuid}:
            raise ValueError('The httpboot directory already contains unmanaged data; it was not modified')
    base.mkdir(exist_ok=True, mode=0o755)
    for name, mode in (('data', 0o755), ('boot', 0o755), ('private', 0o700)):
        target = base / name
        if target.is_symlink():
            raise ValueError('Managed storage paths must not be symlinks')
        target.mkdir(exist_ok=True, mode=mode)
        if name == 'private':
            os.chown(target, 0, 0)
            os.chmod(target, 0o700)
    dump(marker, {'uuid': uuid}, 0o600)
    c = dict(config)
    c.update(schema=2, storage={'uuid': uuid, 'mountpoint': plan['mountpoint'],
             'device_id': plan['identity'].get('wwn') or plan['identity'].get('serial') or plan['identity']['path']},
             require_data_mount=True, data_dir=str(base / 'data'), web_dir=str(base / 'boot'))
    validate_config(c)
    config.clear()
    config.update(c)
    config.storage_plan = None


def check_config(config):
    if config['schema'] == 2:
        s = config['storage']
        check_mount(s['uuid'], s['mountpoint'])
        base = Path(s['mountpoint']) / 'httpboot'
        for path in (base, Path(config['data_dir']), Path(config['web_dir']), base / 'private'):
            if path.is_symlink() or not path.resolve().is_relative_to(Path(s['mountpoint']).resolve()):
                raise ValueError('Managed storage path escapes the mounted volume')


def state_dir(config, legacy):
    if config['schema'] == 1:
        return Path(legacy)
    check_config(config)
    path = Path(config['storage']['mountpoint']) / 'httpboot/private/state'
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def unit_name(path):
    return '-'.join(''.join(c if c.isalnum() or c in '_.' else f'\\x{ord(c):02x}' for c in part)
                    for part in Path(path).parts[1:]) + '.mount'
