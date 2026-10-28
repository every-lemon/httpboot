"""Build the generic amd64 Client with retained caches and no embedded accounts."""
import argparse
import fcntl
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from common import atomic,dump,load,run,safe_url,sha256,validate_config
from build_support import Stages,prepare_resolver,parallelism
from product_version import VERSION

SOURCE=Path(__file__).resolve().parents[1]
MODULES=('loop','squashfs','overlay','usb_storage','uas','sd_mod','vfat','nls_cp437','nls_iso8859_1',
         'e1000','e1000e','r8169','virtio_net','virtio_balloon','r8152','iwlwifi','iwlmvm','mmc_block','sdhci_pci')
PACKAGES=('ubuntu-desktop-minimal','gdm3','linux-generic-hwe-24.04','linux-firmware','initramfs-tools',
          'busybox-initramfs','network-manager','wpasupplicant','isc-dhcp-client','rfkill','age','curl',
          'ca-certificates','gcc','libpam0g-dev','python3','python3-gi','python3-cups','gir1.2-gtk-3.0','flatpak','rsync','vulkan-tools','mesa-vulkan-drivers',
          'cups','cups-client','cups-filters','cups-browsed','ipp-usb','avahi-daemon','libnotify-bin','whiptail','iw',
          'kexec-tools','openssl','sudo','systemd-sysv','systemd-resolved','zstd','kmod','xauth','gnome-terminal',
          'fonts-dejavu-core','fonts-noto-core','fonts-noto-cjk','fonts-noto-color-emoji','yaru-theme-gtk','yaru-theme-icon')
CLIENT_MODULES=('product_version.py','client_power.py','session_leases.py','client_policy.py','terminal_preferences.py','driver_store.py','boot_ui.py','boot_identity.py','recovery_cache.py','boot_client_v2.py','kernel_stage.py','client_updates.py','pending_storage.py','pending_worker.py','common.py','control_transport.py','snapshot_store.py','image_delivery.py','server_v2.py',
                'persistence_v2.py','client_agent.py','client_worker.py','client_ui.py','flatpak_content.py',
                'printers.py','sober_check.py','boot_reports.py','driver_imports.py','usb_importer.py')
CLIENT_INPUTS=('init','init-v2-rest','initramfs-hook','initramfs-v2-hook','network.sh','network.py',
               'httpboot-network.service','httpboot-client-v2.service','httpboot-saver-v2.service',
               'httpboot-power-guard.service','power_guard.py','pam-session-v2','pam-httpboot.c',
               'desktop_state.py','wifi.sh','dhclient-script','tui.sh','boot-checks.sh','age-unlock.c')


def image_recipe(source=SOURCE):
    source=Path(source)
    inputs=[source/'httpboot/build_public.py']
    inputs.extend(source/'httpboot'/name for name in CLIENT_MODULES)
    inputs.extend(source/'client'/name for name in sorted(CLIENT_INPUTS))
    inputs.extend(source/'httpboot/assets/fonts'/name for name in ('DejaVuSansMono.ttf','DejaVuSansMono-LICENSE.txt'))
    return hashlib.sha256(json.dumps(PACKAGES).encode()+b''.join(path.read_bytes() for path in inputs)).hexdigest()


def require_builder():
    if os.geteuid()!=0 or os.uname().machine!='x86_64':raise ValueError('Use a root session on an amd64 Builder')
    info=Path('/etc/os-release').read_text()
    if 'VERSION_ID="24.04"' not in info or 'ID=ubuntu' not in info:raise ValueError('Builder requires Ubuntu 24.04')
    if subprocess.run(['systemd-detect-virt','--container','--quiet']).returncode==0:
        raise ValueError('Image preparation requires a full Builder; this environment is a container')
    for tool in ('debootstrap','mksquashfs','chroot','mount','cc'):
        if not shutil.which(tool):raise ValueError('Install the documented Builder prerequisite: '+tool)
    if not Path('/usr/lib/systemd/boot/efi/linuxx64.efi.stub').is_file():
        raise ValueError('Install the Builder prerequisite systemd-boot-efi before preparing an image')


def finalize_runtime_resolver(root):
    # Build-only resolver_text() is never a deployable Client configuration.
    target=root/'etc/resolv.conf';target.unlink(missing_ok=True)
    target.symlink_to('/run/systemd/resolve/stub-resolv.conf')


def install_client(root):
    lib=root/'usr/local/lib/httpboot';lib.mkdir(parents=True,exist_ok=True)
    for name in CLIENT_MODULES:shutil.copyfile(SOURCE/'httpboot'/name,lib/name)
    fonts=root/'usr/local/share/fonts/httpboot';fonts.mkdir(parents=True,exist_ok=True)
    for font in ('DejaVuSansMono.ttf','DejaVuSansMono-LICENSE.txt'):
        shutil.copyfile(SOURCE/'httpboot/assets/fonts'/font,fonts/font)
    for name in ('httpboot-client-v2.service','httpboot-network.service','network.py','pam-session-v2','desktop_state.py','power_guard.py','httpboot-power-guard.service'):
        target=root/('etc/systemd/system' if name.endswith('.service') else 'usr/local/lib/httpboot')/name
        target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(SOURCE/'client'/name,target);target.chmod(0o755 if not name.endswith('.service') else 0o644)
    target=root/'etc/systemd/user/httpboot-saver-v2.service';target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(SOURCE/'client/httpboot-saver-v2.service',target)
    wanted=target.parent/'default.target.wants';wanted.mkdir(exist_ok=True)
    link=wanted/target.name
    if not link.exists():link.symlink_to('../'+target.name)
    atomic(root/'etc/systemd/system/display-manager.service.d/httpboot.conf','[Unit]\nRequires=httpboot-client-v2.service\nAfter=httpboot-client-v2.service\n',0o644)
    pam=root/'etc/pam.d/common-session'
    shutil.copyfile(SOURCE/'client/pam-httpboot.c',lib/'pam-httpboot.c')
    run(['chroot',root,'cc','-shared','-fPIC','-O2','-Wall','-Wextra','-o',
         '/usr/local/lib/httpboot/pam-httpboot.so','/usr/local/lib/httpboot/pam-httpboot.c','-lpam'])
    text='\n'.join(line for line in pam.read_text().splitlines() if 'pam-session-v2' not in line and 'pam-httpboot.so' not in line)
    entry='session requisite /usr/local/lib/httpboot/pam-httpboot.so\n'
    # Restore before pam_systemd/keyring can start user processes.
    atomic(pam,entry+text+'\n',0o644)
    desktop='[Desktop Entry]\nType=Application\nName=HTTP Boot\nExec=python3 /usr/local/lib/httpboot/client_ui.py\nIcon=system-software-update\nCategories=System;\n'
    atomic(root/'usr/share/applications/httpboot.desktop',desktop,0o644)
    (root/'etc/xdg/autostart/httpboot.desktop').unlink(missing_ok=True)
    atomic(root/'etc/systemd/system/httpboot-startup-report.service','[Unit]\nDescription=Report verified HTTP Boot startup\nAfter=httpboot-client-v2.service display-manager.service\nRequires=httpboot-client-v2.service display-manager.service\n[Service]\nType=oneshot\nExecStart=/bin/sh -c \'systemctl is-active --quiet display-manager.service && echo HTTPBOOT_SYSTEMD_STARTED >/dev/console\'\n[Install]\nWantedBy=graphical.target\n',0o644)
    cups=root/'etc/cups/cupsd.conf'
    lines=[line for line in cups.read_text().splitlines() if not line.strip().startswith(('PreserveJobFiles ','PreserveJobHistory '))]
    atomic(cups,'\n'.join(lines)+'\nPreserveJobFiles No\nPreserveJobHistory No\n',0o640)
    finalize_runtime_resolver(root)
    atomic(root/'etc/hostname','httpboot-client\n',0o644)
    atomic(root/'etc/hosts','127.0.0.1 localhost\n127.0.1.1 httpboot-client\n::1 localhost ip6-localhost ip6-loopback\n',0o644)
    wants=root/'etc/systemd/system/multi-user.target.wants';wants.mkdir(parents=True,exist_ok=True)
    guard=wants/'httpboot-power-guard.service';guard.unlink(missing_ok=True);guard.symlink_to('../httpboot-power-guard.service')



GUI_PACKAGE_REMOVALS=('gnome-software','gnome-software-plugin-flatpak','gnome-software-plugin-snap',
                      'software-properties-gtk','update-manager','update-notifier','ubuntu-release-upgrader-gtk','synaptic')

def remove_software_guis(root,ch):
    result=ch('dpkg-query','-W','-f=${binary:Package} ${db:Status-Abbrev}\n',capture_output=True).stdout
    if isinstance(result,bytes):result=result.decode()
    installed={line.split()[0].split(':')[0] for line in result.splitlines() if len(line.split())>1 and line.split()[1].startswith('ii')}
    packages=sorted(installed.intersection(GUI_PACKAGE_REMOVALS))
    if packages:
        result=ch('apt-get','--simulate','remove',*packages,capture_output=True).stdout
        if isinstance(result,bytes):result=result.decode()
        removed={line.split()[1].split(':')[0] for line in result.splitlines() if line.startswith('Remv ')}
        allowed=set(GUI_PACKAGE_REMOVALS)|{'ubuntu-desktop','ubuntu-desktop-minimal'}
        if removed-allowed:raise ValueError('GUI removal would remove required or unreviewed packages: '+', '.join(sorted(removed-allowed)))
        ch('apt-get','remove','-y',*packages)
    # Old HTTP Boot driver launcher is not owned by an Ubuntu package.
    (root/'usr/share/applications/ubuntu-drivers.desktop').unlink(missing_ok=True)


def strip_private_accounts(root,config):
    names={u['name'] for u in validate_config(load(config))['users']}
    for relative in ('etc/passwd','etc/shadow','etc/group','etc/gshadow'):
        file=root/relative;lines=[]
        for line in file.read_text().splitlines():
            parts=line.split(':')
            if parts[0] in names:continue
            if relative.endswith(('group','gshadow')) and len(parts)>=4:
                parts[-1]=','.join(name for name in parts[-1].split(',') if name not in names)
            lines.append(':'.join(parts))
        atomic(file,'\n'.join(lines)+'\n',0o600 if relative.endswith(('shadow','gshadow')) else 0o644)
        # useradd/usermod and periodic maintenance retain previous account files.
        # They are not login databases, but still expose deployment password hashes.
        (root/(relative+'-')).unlink(missing_ok=True)
        for backup in (root/'var/backups').glob(Path(relative).name+'.bak*'):
            if backup.is_file() or backup.is_symlink():backup.unlink()
    for name in names:
        home=root/'home'/name
        if home.is_symlink():home.unlink()
        elif home.exists():shutil.rmtree(home)
        (root/'var/lib/AccountsService/users'/name).unlink(missing_ok=True)
    (root/'etc/httpboot-client.json').unlink(missing_ok=True)
    # Existing Chrome desktop entries may retain this compatibility launcher.
    # Restores and closed-app saves now belong to the v2 session service.
    atomic(root/'usr/local/lib/httpboot/chrome-launch','#!/bin/sh\nexec /usr/bin/google-chrome-stable "$@"\n',0o755)
    for name in ('httpboot-storage.service','httpboot-storage-health.service','httpboot-storage-health.timer','httpboot-control.service','httpboot-shutdown-guard.service'):
        for directory in ('multi-user.target.wants','graphical.target.wants','timers.target.wants'):
            (root/'etc/systemd/system'/directory/name).unlink(missing_ok=True)
        target=root/'etc/systemd/system'/name;target.unlink(missing_ok=True);target.symlink_to('/dev/null')
    for path in ('etc/xdg/autostart/httpboot-control.desktop','etc/systemd/user/default.target.wants/httpboot-session.service'):
        (root/path).unlink(missing_ok=True)
    for name in ('httpboot-status.desktop','httpboot-system-control.desktop'):
        (root/'usr/share/applications'/name).unlink(missing_ok=True)


def reset_machine_certificate(root):
    # ssl-cert.service generates a fresh key in each Client's RAM at startup.
    # CUPS installation creates this key on the Builder; never clone it.
    for name in ('etc/ssl/private/ssl-cert-snakeoil.key','etc/ssl/certs/ssl-cert-snakeoil.pem'):
        (root/name).unlink(missing_ok=True)


def audit_root(root):
    if (root/'etc/ssl/private/ssl-cert-snakeoil.key').exists():
        raise ValueError('Client image contains a Builder-generated TLS private key')
    resolver=root/'etc/resolv.conf'
    if not resolver.is_symlink() or os.readlink(resolver)!='/run/systemd/resolve/stub-resolv.conf':
        raise ValueError('Client DNS must use its runtime resolver, not Builder DNS settings')
    for line in (root/'etc/passwd').read_text().splitlines():
        parts=line.split(':')
        if 1000<=int(parts[2])<65534:raise ValueError('Public image contains a deployment account')
    for line in (root/'etc/shadow').read_text().splitlines():
        password=line.split(':')[1]
        if password and not password.startswith(('!','*')):raise ValueError('Public image contains an active password hash')
    if any((root/'home').iterdir()):raise ValueError('Public image contains a user home')
    for directory in (root/'etc/httpboot',root/'run',root/'root/.ssh'):
        if directory.exists() and any(p.is_file() for p in directory.rglob('*')) and directory!=root/'run':
            raise ValueError('Public image contains deployment-specific state')


def restore_kernel_files(root,ch):
    kernels=list((root/'boot').glob('vmlinuz-*'))
    if kernels and all((root/'boot'/('config-'+p.name.removeprefix('vmlinuz-'))).is_file() for p in kernels):return
    # Legacy squashfs omits /boot, but dpkg still records these packages as
    # installed. linux-modules owns the configuration/System.map on Ubuntu.
    inventory=ch('dpkg-query','-W','-f=${db:Status-Abbrev} ${binary:Package}\n',
                 'linux-image-*','linux-modules-*',capture_output=True).stdout.decode()
    packages=[line.split()[1] for line in inventory.splitlines() if line.startswith('ii ') and
              __import__('re').fullmatch(r'linux-(?:image-(?:unsigned-)?|modules-)[0-9].*',line.split()[1])]
    if not any(name.startswith('linux-image-') for name in packages):
        raise ValueError('Private image has no installed kernel package to restore')
    ch('apt-get','--no-remove','install','--reinstall','-y',*packages)


def build(args):
    require_builder();safe_url(args.server,https=True)
    if not args.ca.is_file():raise ValueError('Provide the public Server CA certificate')
    if b'PRIVATE KEY' in args.ca.read_bytes():raise ValueError('Bootstrap accepts only public CA certificates')
    run(['openssl','x509','-in',args.ca,'-noout'],capture_output=True)
    if args.output.exists():raise ValueError('Use a new output directory; existing releases are immutable')
    cache=args.cache.resolve();cache.mkdir(parents=True,exist_ok=True)
    with open(cache/'worker.lock','a') as guard:
        fcntl.flock(guard,fcntl.LOCK_EX|fcntl.LOCK_NB)
        recipe=image_recipe()
        # Reuse the expensive OS/package checkpoint when only Client code changes.
        package_key=hashlib.sha256(b'ubuntu-noble-amd64-v2:'+json.dumps(PACKAGES).encode()).hexdigest()
        if args.private_base:
            if not args.legacy_config:raise ValueError('Private image migration requires the original account configuration')
            recipe=hashlib.sha256((recipe+sha256(args.private_base)+sha256(args.legacy_config)).encode()).hexdigest()
            package_key=hashlib.sha256((package_key+sha256(args.private_base)+sha256(args.legacy_config)).encode()).hexdigest()
        if args.drivers:
            recipe=hashlib.sha256(recipe.encode()+b''.join(p.read_bytes() for p in sorted(args.drivers.glob('*/record.json')))).hexdigest()
            package_key=hashlib.sha256(package_key.encode()+b''.join(p.read_bytes() for p in sorted(args.drivers.glob('*/record.json')))).hexdigest()
        if args.refresh_packages:recipe=hashlib.sha256((recipe+':refresh:'+args.output.name).encode()).hexdigest()
        base=cache/'public-v2'/package_key;root=base/'rootfs';base.mkdir(parents=True,exist_ok=True)
        from build_cache import cache_directories
        stages=Stages(base/'stages.json');archives=cache_directories(cache)
        def bootstrap():
            if root.exists():root.rename(base/('incomplete-'+str(__import__('time').time_ns())))
            if args.private_base:
                run(['unsquashfs','-d',root,args.private_base]);strip_private_accounts(root,args.legacy_config);return
            run(['debootstrap','--arch=amd64','--variant=minbase','--components=main,universe',
                 '--cache-dir='+str(archives),'noble',root,'http://archive.ubuntu.com/ubuntu'])
        stages.run('Bootstrap generic Client',bootstrap)
        # A retained root may contain the preceding build's hook while its
        # build-only settings were excluded from the image. Package triggers
        # must use normal initramfs hooks; our current hook is installed later.
        (root/'etc/initramfs-tools/hooks/zzz-httpboot').unlink(missing_ok=True)
        mounted=[]
        def ch(*command,**kwargs):return run(['chroot',root,*command],env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','DEBIAN_FRONTEND':'noninteractive'},**kwargs)
        try:
            for sub,command in (('proc',['mount','-t','proc','proc']),('sys',['mount','-t','sysfs','sysfs']),('dev',['mount','--rbind','/dev'])):
                run([*command,root/sub]);mounted.append(root/sub)
            run(['mount','--make-rslave',root/'dev'])
            (root/'var/cache/apt/archives').mkdir(parents=True,exist_ok=True)
            run(['mount','--bind',archives,root/'var/cache/apt/archives']);mounted.append(root/'var/cache/apt/archives')
            prepare_resolver(root)
            atomic(root/'usr/sbin/policy-rc.d','#!/bin/sh\nexit 101\n',0o755)
            atomic(root/'etc/apt/sources.list',''.join('deb http://archive.ubuntu.com/ubuntu '+suite+' main universe restricted multiverse\n' for suite in ('noble','noble-updates','noble-security')),0o644)
            atomic(root/'etc/apt/apt.conf.d/99-httpboot','APT::Keep-Downloaded-Packages "true";\nAcquire::Retries "3";\n',0o644)
            def packages():
                ch('dpkg','--configure','-a');ch('apt-get','update')
                ch('apt-get','--no-remove','install','-y','--no-install-recommends',*PACKAGES)
                if args.refresh_packages:ch('apt-get','--no-remove','upgrade','--with-new-pkgs','-y')
                restore_kernel_files(root,ch)
            stages.run('Install generic desktop'+(' refresh '+args.output.name if args.refresh_packages else ''),packages)
            remove_software_guis(root,ch)
            install_client(root);ch('passwd','--lock','root');reset_machine_certificate(root)
            for service in ('ssl-cert.service','httpboot-network.service','NetworkManager.service','systemd-resolved.service','gdm3.service','cups.service','cups-browsed.service','avahi-daemon.service','httpboot-client-v2.service','httpboot-startup-report.service'):
                ch('systemctl','enable',service)
            ch('systemctl','disable','apt-daily.timer','apt-daily-upgrade.timer')
            ch('systemctl','set-default','graphical.target')
            atomic(root/'etc/hostname','httpboot-client\n',0o644);atomic(root/'etc/machine-id','',0o644)
            dbus_id=root/'var/lib/dbus/machine-id';dbus_id.unlink(missing_ok=True)
            dbus_id.symlink_to('/etc/machine-id')
            (root/'usr/sbin/policy-rc.d').unlink(missing_ok=True)
            resolver=root/'etc/resolv.conf';resolver.unlink(missing_ok=True)
            resolver.symlink_to('/run/systemd/resolve/stub-resolv.conf')
            audit_root(root)
            kernel=max((root/'boot').glob('vmlinuz-*'),key=lambda p:p.stat().st_mtime)
            version=kernel.name.removeprefix('vmlinuz-')
            imported=[]
            if args.drivers:
                from driver_imports import apply
                imported=apply(args.drivers,root,version)
            args.output.mkdir(parents=True,mode=0o700)
            packages=ch('dpkg-query','-W','-f=${binary:Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n',capture_output=True).stdout
            atomic(args.output/'packages-desktop.tsv',packages,0o644)
            shutil.copyfile(kernel,args.output/'vmlinuz')
            for target in reversed(mounted):run(['umount','-R',target])
            mounted.clear()
            jobs=parallelism(args.jobs)
            run(['mksquashfs',root,args.output/'filesystem.squashfs','-noappend','-comp','zstd','-Xcompression-level','6','-processors',jobs,
                 '-wildcards','-e','boot','etc/httpboot-build','tmp/*','var/tmp/*','var/log/*','run/*','proc/*','sys/*','dev/*','var/cache/apt/archives/*'])
            from recovery import build_recovery
            firmware=ch('dpkg-query','-W','-f=${Version}', 'linux-firmware',capture_output=True).stdout.decode()
            build_recovery(cache,root,args.output,version,jobs,generation=package_key+firmware)
            # Bootstrap configuration is separate from the generic shared desktop.
            lib=root/'usr/local/lib/httpboot'
            for name in ('init','init-v2-rest','initramfs-hook','network.sh','wifi.sh','dhclient-script','tui.sh','boot-checks.sh'):
                shutil.copyfile(SOURCE/'client'/name,lib/name);(lib/name).chmod(0o755)
            run(['cc','-O2',SOURCE/'client/age-unlock.c','-lutil','-o',lib/'age-unlock'])
            settings=root/'etc/httpboot-build';settings.mkdir(mode=0o700,exist_ok=True)
            atomic(settings/'boot.conf','HTTPBOOT_PROTOCOL=2\n')
            modules=[*MODULES,'ccm','cmac','gcm',*imported]
            for provider in ('ctr','aes_generic','aesni_intel','ghash_generic','sha256_generic','hmac'):
                try:ch('modinfo','-k',version,'-F','filename',provider,capture_output=True);modules.append(provider)
                except subprocess.CalledProcessError:pass
            from hardware_bundle import extend_modules
            modules=extend_modules(root,version,modules)
            atomic(settings/'modules','\n'.join(dict.fromkeys(modules))+'\n')
            shutil.copyfile(args.ca,settings/'server-ca.pem')
            dump(settings/'client-v2.json',{'schema':2,'server':args.server,'ca':'/httpboot/server-ca.pem'})
            payload=settings/'v2';payload.mkdir(exist_ok=True)
            for name in ('product_version.py','client_policy.py','boot_identity.py','boot_ui.py','common.py','control_transport.py','image_delivery.py','boot_client_v2.py','kernel_stage.py','recovery_cache.py','boot_reports.py'):
                shutil.copyfile(SOURCE/'httpboot'/name,payload/name)
            hook=root/'etc/initramfs-tools/hooks/zzz-httpboot'
            shutil.copyfile(SOURCE/'client/initramfs-hook',hook);hook.chmod(0o755)
            with open(hook,'a') as stream:stream.write('\n'+(SOURCE/'client/initramfs-v2-hook').read_text())
            atomic(root/'etc/initramfs-tools/conf.d/httpboot','MODULES=most\nCOMPRESS=zstd\n',0o644)
            run(['mount','-t','proc','proc',root/'proc']);mounted.append(root/'proc')
            run(['mount','--rbind','/dev',root/'dev']);mounted.append(root/'dev');run(['mount','--make-rslave',root/'dev'])
            ch('mkinitramfs','-o','/tmp/httpboot-public-initrd',version)
            shutil.copyfile(root/'tmp/httpboot-public-initrd',args.output/'initrd')
            for target in reversed(mounted):run(['umount','-R',target])
            mounted.clear()
            for name,cmdline in (('boot.efi','console=tty0 loglevel=3'),('recovery.efi','console=tty0 loglevel=3 httpboot.recovery=1')):
                run(['/usr/lib/systemd/ukify','build','--linux',args.output/'vmlinuz','--initrd',args.output/'initrd',
                     '--cmdline',cmdline,'--uname',version,'--os-release','@'+str(root/'etc/os-release'),'--output',args.output/name])
            dump(args.output/'release.json',{'schema':2,'version':VERSION,'architecture':'amd64','recipe':recipe,'kernel':version,'users':[],
                  'validation':'required','artifacts':{name:{'size':(args.output/name).stat().st_size,'sha256':sha256(args.output/name)}
                       for name in ('boot.efi','recovery.efi','filesystem.squashfs','recovery.squashfs')}})
            if args.validate_startup:
                from validate_v2 import check
                check(args.output)
        finally:
            for target in reversed(mounted):subprocess.run(['umount','-R',str(target)],check=False)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version',action='version',version=f'HTTP Boot Builder {VERSION} (amd64)')
    parser.add_argument('--server',required=True);parser.add_argument('--ca',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--cache',type=Path,default=Path('/var/lib/httpboot-build-cache'))
    parser.add_argument('--private-base',type=Path,help='Retained private desktop to migrate without removing installed applications')
    parser.add_argument('--legacy-config',type=Path)
    parser.add_argument('--refresh-packages',action='store_true')
    parser.add_argument('--validate-startup',action='store_true')
    parser.add_argument('--drivers',type=Path,help='Administrator-approved driver import store')
    parser.add_argument('--jobs',type=int,default=2)
    build(parser.parse_args())

if __name__=='__main__':main()
