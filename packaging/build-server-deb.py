#!/usr/bin/env python3
"""Build Server or combined Server/Builder packages from an explicit public allowlist."""
import argparse
import shutil
import subprocess
import tempfile
import sys
from pathlib import Path

SOURCE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(SOURCE/'httpboot'))
from product_version import DEBIAN_VERSION as VERSION
MODULES=('product_version.py','client_power.py','session_leases.py','client_policy.py','terminal_preferences.py','approval_wizard.py','builder_v2.py','server_jobs.py','driver_store.py','boot_ui.py','boot_identity.py','media_setup.py','storage.py','storage_guard.py','recovery_cache.py','kernel_stage.py','hardware_bundle.py','recovery_tools.py','media_v2.py','server_maintenance.py','maintenance.py','apt_tools.py','validate_v2.py','initrd_reader.py','legacy_snapshots.py','client_updates.py','pending_storage.py','pending_worker.py','bootstrap_http.py','common.py','control_transport.py','server_v2.py','snapshot_store.py','image_delivery.py',
         'persistence_v2.py','restore_progress.py','client_agent.py','client_worker.py','client_ui.py','flatpak_content.py',
         'schedule_policy.py','migration_v2.py','release_cleanup.py','server_setup.py','server_console.py',
         'printers.py','driver_imports.py','usb_importer.py','sober_check.py','boot_reports.py','boot_client_v2.py',
         'build_public.py','build_support.py','recovery.py','recovery_browser.py','build_cache.py')
CLIENT=('power_guard.py','httpboot-power-guard.service','desktop_state.py','pam-httpboot.c','init','init-v2-rest','boot-guard.sh','initramfs-hook','initramfs-v2-hook','network.sh','network.py','httpboot-network.service','wifi.sh','dhclient-script',
        'tui.sh','boot-checks.sh','age-unlock.c','pam-session-v2','httpboot-client-v2.service','httpboot-saver-v2.service')


def tree(root,builder=False):
    base=root/'usr/lib/httpboot-source'
    for directory,names in (('httpboot',MODULES),('client',CLIENT)):
        target=base/directory;target.mkdir(parents=True)
        for name in names:shutil.copyfile(SOURCE/directory/name,target/name)
    fonts=base/'httpboot/assets/fonts';fonts.mkdir(parents=True,exist_ok=True)
    for name in ('DejaVuSansMono.ttf','DejaVuSansMono-LICENSE.txt'):
        shutil.copyfile(SOURCE/'httpboot/assets/fonts'/name,fonts/name)
    binary=root/'usr/sbin';binary.mkdir(parents=True)
    for name,module in (('httpboot-server','server_v2.py'),('httpboot-builder-service','builder_v2.py'),('httpboot-builder','build_public.py'),('httpboot-import-drivers','usb_importer.py')):
        launcher=binary/name
        launcher.write_text('#!/bin/sh\nexec /usr/bin/python3 /usr/lib/httpboot-source/httpboot/'+module+' "$@"\n');launcher.chmod(0o755)
    units=root/'usr/lib/systemd/system';units.mkdir(parents=True)
    # Pull existing companions back up on start, and propagate authority restarts
    # even when a deployment overrides a companion's main unit in /etc.
    companions=units/'httpboot-server.service.d';companions.mkdir()
    (companions/'20-companions.conf').write_text('[Unit]\nWants=httpboot-server-console.service httpboot-bootstrap-v2.service\n')
    for unit in ('httpboot-server-console.service','httpboot-bootstrap-v2.service'):
        drop=units/(unit+'.d');drop.mkdir()
        (drop/'20-lifecycle.conf').write_text('[Unit]\nPartOf=httpboot-server.service\n')
    (units/'httpboot-bootstrap-v2.service').write_text('''[Unit]
Description=HTTP Boot public bootstrap only
After=network-online.target httpboot-server.service
Requires=httpboot-server.service
[Service]
ExecStart=/usr/sbin/httpboot-server bootstrap-http --host 0.0.0.0 --port 8083
Restart=on-failure
UMask=0077
[Install]
WantedBy=multi-user.target
''')
    (units/'httpboot-server.service').write_text('''[Unit]
Description=HTTP Boot Server authority
Wants=network-online.target
After=network-online.target
ConditionPathExists=/var/lib/httpboot-server/pki/server.pem
[Service]
ExecStart=/usr/sbin/httpboot-server serve --host 0.0.0.0
Restart=on-failure
RestartSec=5
UMask=0077
[Install]
WantedBy=multi-user.target
''')
    (units/'httpboot-server-console.service').write_text('''[Unit]
Description=HTTP Boot local administration console
After=httpboot-server.service
Requires=httpboot-server.service
[Service]
ExecStart=/usr/sbin/httpboot-server console
Restart=on-failure
UMask=0077
[Install]
WantedBy=multi-user.target
''')
    (units/'httpboot-server-maintenance.service').write_text('[Unit]\nDescription=HTTP Boot scheduled maintenance\nAfter=network-online.target\n[Service]\nType=oneshot\nExecStart=/usr/sbin/httpboot-server maintain\nTimeoutStartSec=infinity\nUMask=0077\n')
    (units/'httpboot-server-maintenance.timer').write_text('[Unit]\nDescription=Check HTTP Boot independent maintenance schedules\n[Timer]\nOnBootSec=60\nOnUnitInactiveSec=60\n[Install]\nWantedBy=timers.target\n')
    (units/'httpboot-builder-v2.service').write_text('[Unit]\nDescription=HTTP Boot Builder job supervisor\nAfter=network-online.target\nConditionPathExists=/etc/httpboot/builder-v2.json\n[Service]\nExecStart=/usr/sbin/httpboot-builder-service serve /etc/httpboot/builder-v2.json\nRestart=on-failure\nRestartSec=10\nTimeoutStopSec=60\nUMask=0077\n[Install]\nWantedBy=multi-user.target\n')
    docs=root/'usr/share/doc/httpboot-server';docs.mkdir(parents=True)
    for name,source in (('README.md','docs/INSTALL-v2.md'),('IMPLEMENTATION.md','docs/3.1.15-implementation.md'),
                        ('3.1.15-verification.md','docs/3.1.15-verification.md'),
                        ('copyright','LICENSE'),('THIRD_PARTY_NOTICES.md','THIRD_PARTY_NOTICES.md')):
        shutil.copyfile(SOURCE/source,docs/name)
    examples=docs/'examples';examples.mkdir()
    for name in ('client-v2.json','maintenance-policy.json','persistence-rules.json'):
        shutil.copyfile(SOURCE/'examples'/name,examples/name)
    debian=root/'DEBIAN';debian.mkdir()
    depends='python3 (>= 3.10), openssl, whiptail, age, kmod, fdisk, dosfstools, util-linux, udev'
    if builder:depends+=', debootstrap, squashfs-tools, initramfs-tools, systemd-ukify, systemd-boot-efi, gcc, zstd, qemu-system-x86, ovmf, mtools, fdisk, cpio, python3-pefile, python3-virt-firmware'
    (debian/'control').write_text('Package: httpboot-server\nVersion: '+VERSION+'\nArchitecture: '+('amd64' if builder else 'all')+'\nMaintainer: HTTP Boot contributors <httpboot@example.invalid>\nDepends: '+depends+'\nSection: admin\nPriority: optional\nDescription: HTTP Boot Server and optional amd64 Builder\n Authenticated activation, accounts, persistence, image delivery and administration.\n')
    # Package permissions must not inherit the operator's private umask.
    for path in root.rglob('*'):
        path.chmod(0o755 if path.is_dir() else 0o644)
    for launcher in binary.iterdir():launcher.chmod(0o755)
    # Deliberately no postinst activation: enrollment and PKI must precede rollout.
    return root


def build(output,builder=False):
    output=Path(output).resolve();output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory() as temporary:
        root=Path(temporary);root.chmod(0o755);tree(root,builder)
        subprocess.run(['dpkg-deb','--root-owner-group','--build',str(root),str(output)],check=True)
    return output

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--with-builder',action='store_true');args=parser.parse_args()
    print(build(args.output,args.with_builder))
