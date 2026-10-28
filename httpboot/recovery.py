"""Small independent offline graphical recovery image; no user data or secrets."""
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from common import atomic, run, sha256, recovery_size_ok
from build_support import Stages, prepare_resolver, check_dns

PACKAGES = ('systemd-sysv', 'systemd-resolved', 'udev', 'dbus-x11', 'dbus-user-session', 'libpam-systemd', 'xserver-xorg-legacy', 'xfonts-base', 'fonts-dejavu-core', 'xserver-xorg-core', 'xserver-xorg-input-libinput',
            'xserver-xorg-video-fbdev', 'xinit', 'openbox', 'xterm', 'mousepad', 'network-manager',
            'network-manager-gnome', 'zenity', 'curl', 'ca-certificates', 'sudo', 'iproute2', 'libgl1-mesa-dri',
            'whiptail','kmod','python3', 'python3-gi', 'gir1.2-webkit2-4.1', 'openssl', 'systemd-boot-efi')

def build_recovery(cache_base, desktop, output, kernel, jobs, generation=""):
    # Package checkpoints survive changes to recovery tools and desktop Client code.
    key = hashlib.sha256((kernel + json.dumps(PACKAGES) + generation).encode()).hexdigest()
    recipe = hashlib.sha256((sha256(Path(__file__)) + ''.join(sha256(Path(__file__).with_name(name))
        for name in ('recovery_browser.py','recovery_tools.py','common.py','boot_reports.py','control_transport.py','driver_store.py','driver_imports.py','usb_importer.py'))+
        ''.join(sha256(Path(__file__).resolve().parents[1]/'client'/name) for name in ('network.py','httpboot-network.service'))).encode()).hexdigest()
    base = cache_base/'recovery'/key
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    root = base/'rootfs'
    stages = Stages(base/'stages.json')
    ready, checksum = base/'recovery.squashfs', base/'recovery.sha256'
    recipe_file=base/'recipe.sha256'
    if ready.is_file() and checksum.is_file() and recipe_file.is_file() and recipe_file.read_text().strip()==recipe and sha256(ready) == checksum.read_text().strip():
        recovery_size_ok(ready.stat().st_size)
        from build_cache import link_or_copy
        link_or_copy(ready, output/'recovery.squashfs')
        if (base/'packages-recovery.tsv').is_file():shutil.copyfile(base/'packages-recovery.tsv',output/'packages-recovery.tsv')
        return
    def bootstrap():
        if root.exists():
            import time
            root.rename(base/f'incomplete-{time.time_ns()}')
        run(['debootstrap', '--arch=amd64', '--variant=minbase', '--components=main,universe',
             '--cache-dir='+str(cache_base/'apt/archives'), 'noble', root, 'http://archive.ubuntu.com/ubuntu'])
    stages.run('Bootstrap recovery', bootstrap)
    mounts=[]
    try:
        for target, command in (('proc',['mount','-t','proc','proc']), ('sys',['mount','-t','sysfs','sysfs']),
                                ('dev',['mount','--rbind','/dev'])):
            run([*command,root/target]);mounts.append(root/target)
        run(['mount','--make-rslave',root/'dev'])
        archives=root/'var/cache/apt/archives';archives.mkdir(parents=True,exist_ok=True)
        run(['mount','--bind',cache_base/'apt/archives',archives]);mounts.append(archives)
        atomic(root/'usr/sbin/policy-rc.d','#!/bin/sh\nexit 101\n',0o755)
        atomic(root/'etc/apt/sources.list', ''.join(f'deb http://archive.ubuntu.com/ubuntu {s} main universe restricted multiverse\n' for s in ('noble','noble-updates','noble-security')),0o644)
        atomic(root/'etc/apt/apt.conf.d/99-httpboot', '#clear DPkg::Post-Invoke;\n#clear APT::Update::Post-Invoke;\nAPT::Keep-Downloaded-Packages "true";\nAcquire::Retries "3";\n',0o644)
        def ch(*args):
            prepare_resolver(root)
            return run(['chroot',root,*args], env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','DEBIAN_FRONTEND':'noninteractive'})
        def install():
            check_dns(root,hosts=('archive.ubuntu.com','security.ubuntu.com'))
            ch('dpkg','--configure','-a')
            ch('apt-get','-o','APT::Update::Error-Mode=any','update')
            ch('apt-get','--no-remove','install','-y','--no-install-recommends',*PACKAGES)
        stages.run('Install recovery desktop',install)
        if not any(line.startswith('recovery:') for line in (root/'etc/passwd').read_text().splitlines()):
            ch('useradd','-m','-s','/bin/bash','recovery')
        ch('passwd','-l','root')
        # Local console autologin only; no SSH server and no inherited accounts.
        atomic(root/'etc/systemd/system/getty@tty1.service.d/autologin.conf',
               '[Service]\nExecStart=\nExecStart=-/sbin/agetty --autologin recovery --noclear %I $TERM\n',0o644)
        atomic(root/'etc/sudoers.d/httpboot-recovery','recovery ALL=(ALL) NOPASSWD: ALL\n',0o440)
        atomic(root/'home/recovery/.bash_profile','if [ "$(tty)" = /dev/tty1 ]; then exec startx; fi\n',0o644)
        atomic(root/'home/recovery/.xinitrc','#!/bin/sh\nsudo -n /bin/sh -c \'echo HTTPBOOT_RECOVERY_DISPLAY_STARTED >/dev/console\'\nnm-applet &\npython3 /usr/local/lib/httpboot/recovery_browser.py &\nxterm -e sudo python3 /usr/local/lib/httpboot/recovery_tools.py &\nxterm -title "httpboot recovery: RAM only; export work before shutdown" &\nzenity --warning --text="Offline recovery. Server profiles are unavailable. Files are temporary and disappear at shutdown. Export work to another drive before restarting." &\nexec openbox-session\n',0o755)
        atomic(root/'usr/local/lib/httpboot/recovery_browser.py',(Path(__file__).with_name('recovery_browser.py')).read_bytes(),0o644)
        atomic(root/'usr/share/applications/httpboot-recovery-browser.desktop','[Desktop Entry]\nType=Application\nName=Recovery Browser\nExec=python3 /usr/local/lib/httpboot/recovery_browser.py\nCategories=Network;\n',0o644)
        for tool in ('common.py','boot_reports.py','control_transport.py','driver_store.py','driver_imports.py','usb_importer.py','recovery_tools.py'):
            atomic(root/'usr/local/lib/httpboot'/tool,Path(__file__).with_name(tool).read_bytes(),0o644)
        atomic(root/'usr/share/applications/httpboot-repair.desktop','[Desktop Entry]\nType=Application\nName=HTTP Boot repair tools\nExec=xterm -e sudo python3 /usr/local/lib/httpboot/recovery_tools.py\nCategories=System;\n',0o644)
        ch('chown','-R','recovery:recovery','/home/recovery')
        source=Path(__file__).resolve().parents[1]/'client'
        atomic(root/'usr/local/lib/httpboot/network.py',(source/'network.py').read_bytes(),0o755)
        atomic(root/'etc/systemd/system/httpboot-network.service',(source/'httpboot-network.service').read_bytes(),0o644)
        ch('systemctl','enable','httpboot-network.service','NetworkManager.service','systemd-resolved.service','getty@tty1.service')
        ch('systemctl','set-default','multi-user.target')
        atomic(root/'etc/hostname','httpboot-recovery\n',0o644)
        atomic(root/'etc/machine-id','',0o644)
        dbus_id=root/'var/lib/dbus/machine-id';dbus_id.unlink(missing_ok=True)
        dbus_id.symlink_to('/etc/machine-id')
        (root/'usr/sbin/policy-rc.d').unlink(missing_ok=True)
        inventory=run(['chroot',root,'dpkg-query','-W','-f=${binary:Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n'],capture_output=True).stdout
        atomic(base/'packages-recovery.tsv',inventory,0o644)
    finally:
        for mount in reversed(mounts):
            run(['umount','-R',mount])
    # Desktop and recovery boot the same kernel. Copy no desktop users or data.
    for sub in ('usr/lib/modules/'+kernel, 'usr/lib/firmware'):
        source=desktop/sub
        if not source.exists():
            source=desktop/sub.removeprefix('usr/')
        target=root/sub;target.mkdir(parents=True,exist_ok=True)
        run(['cp','-a','--reflink=auto',str(source)+'/.',target])
    copy_kernel_notices(desktop,root,kernel)
    atomic(root/'etc/resolv.conf','nameserver 127.0.0.53\n',0o644)
    partial=base/'recovery.partial.squashfs'
    if partial.exists():
        import time
        partial.rename(base/f'partial-{time.time_ns()}.squashfs')
    run(['mksquashfs',root,partial,'-noappend','-comp','zstd','-Xcompression-level','6','-processors',jobs,'-wildcards','-e',
         'tmp/*','var/log/*','var/cache/apt/archives/*','run/*','proc/*','sys/*','dev/*'])
    recovery_size_ok(partial.stat().st_size)
    if ready.exists():
        import time
        ready.rename(base/f'previous-{time.time_ns()}.squashfs')
    partial.rename(ready)
    atomic(checksum,sha256(ready)+'\n')
    atomic(recipe_file,recipe+'\n')
    from build_cache import link_or_copy
    link_or_copy(ready,output/'recovery.squashfs')
    shutil.copyfile(base/'packages-recovery.tsv',output/'packages-recovery.tsv')


def copy_kernel_notices(desktop,root,kernel):
    """Preserve distribution notices for binaries copied outside APT."""
    docs=desktop/'usr/share/doc'
    names=[p for p in docs.glob('linux-*') if p.name=='linux-firmware' or kernel in p.name]
    target=root/'usr/share/doc/httpboot-copied-kernel-firmware'
    target.mkdir(parents=True,exist_ok=True)
    for source in names:
        if source.is_dir():shutil.copytree(source,target/source.name,dirs_exist_ok=True,symlinks=False)
    if not (target/'linux-firmware/copyright').is_file():
        raise ValueError('Recovery firmware copyright notice is missing')
