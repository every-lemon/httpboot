import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'httpboot'))
from common import dump,load
from server_v2 import Authority
from migration_v2 import migrate
from driver_imports import inspect,approve,apply
from printers import validate_configuration

class OperationTests(unittest.TestCase):
    def test_private_kernel_repair_restores_configuration_after_partial_install(self):
        from build_public import restore_kernel_files
        from types import SimpleNamespace
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'boot').mkdir()
            (root/'boot/vmlinuz-7.0-test').write_bytes(b'kernel already restored')
            ch=Mock(return_value=SimpleNamespace(stdout=b'ii  linux-image-7.0-test\nii  linux-modules-7.0-test\nii  linux-image-generic\nrc  linux-image-6.8-old\n'))
            restore_kernel_files(root,ch)
            ch.assert_called_with('apt-get','--no-remove','install','--reinstall','-y','linux-image-7.0-test','linux-modules-7.0-test')
            (root/'boot/config-7.0-test').write_bytes(b'configuration')
            ch.reset_mock();restore_kernel_files(root,ch);ch.assert_not_called()

    def test_private_image_scrubs_account_backups_and_preserves_apps(self):
        from build_public import strip_private_accounts,reset_machine_certificate
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);image=root/'image'
            config={'schema':1,'server_ip':'192.0.2.10','allowed_clients':['192.0.2.0/24'],'boot_base_url':'http://192.0.2.10/httpboot','data_dir':'/srv/data','web_dir':'/srv/boot','require_data_mount':True,'retention':5,'workspace_interval':30,'users':[{'name':'alice','uid':1000,'gid':1000,'visible':True,'workspace':True,'admin':True}]}
            dump(root/'config.json',config)
            files={'passwd':'root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n',
                   'shadow':'root:!:1::::::\nalice:$6$salt$fixture:1::::::\n',
                   'group':'root:x:0:\nsudo:x:27:alice\nalice:x:1000:\n',
                   'gshadow':'root:!::\nsudo:!::alice\nalice:!::\n'}
            from common import atomic
            for name,content in files.items():
                for path in ('etc/'+name,'etc/'+name+'-','var/backups/'+name+'.bak','var/backups/'+name+'.bak.1.gz'):
                    atomic(image/path,content)
            atomic(image/'home/alice/Documents/private','private fixture')
            atomic(image/'usr/share/applications/kept.desktop','retained application')
            atomic(image/'etc/ssl/private/ssl-cert-snakeoil.key','Builder fixture private key')
            atomic(image/'etc/ssl/certs/ssl-cert-snakeoil.pem','Builder fixture certificate')
            atomic(image/'etc/ssl/certs/ca-certificates.crt','retained public trust')
            (image/'etc/systemd/system').mkdir(parents=True)
            strip_private_accounts(image,root/'config.json')
            reset_machine_certificate(image)
            self.assertFalse((image/'etc/ssl/private/ssl-cert-snakeoil.key').exists())
            self.assertFalse((image/'etc/ssl/certs/ssl-cert-snakeoil.pem').exists())
            self.assertEqual((image/'etc/ssl/certs/ca-certificates.crt').read_text(),'retained public trust')
            for name in files:
                self.assertNotIn('alice',(image/'etc'/name).read_text())
                self.assertFalse((image/'etc'/(name+'-')).exists())
                self.assertFalse(list((image/'var/backups').glob(name+'.bak*')))
            self.assertFalse((image/'home/alice').exists())
            self.assertEqual((image/'usr/share/applications/kept.desktop').read_text(),'retained application')
            self.assertIn('root:',(image/'etc/passwd').read_text())

    def test_migration_conflict_rolls_back_and_keeps_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);etc=root/'etc';etc.mkdir();state=root/'legacy';state.mkdir()
            config={'schema':1,'server_ip':'192.0.2.10','allowed_clients':['192.0.2.0/24'],'boot_base_url':'http://192.0.2.10/httpboot','data_dir':'/srv/httpboot-data','web_dir':'/srv/httpboot-boot','require_data_mount':True,'retention':5,'workspace_interval':30,'users':[]}
            config['users']=[{'name':'alice','uid':1000,'gid':1000,'visible':True,'workspace':True,'admin':True},
                             {'name':'bob','uid':1001,'gid':1001,'visible':True,'workspace':True,'admin':False}]
            dump(etc/'server.json',config);dump(etc/'desktop-passwords.json',{'alice':'$6$salt$hash','bob':'$6$salt$hash'})
            before=(etc/'server.json').read_bytes()
            authority=Authority(root/'new/authority.db');authority.account('bob',1001,1001,'$6$salt$hash','status')
            with self.assertRaises(ValueError):migrate(authority,etc,state)
            with authority.db() as db:
                self.assertIsNone(db.execute("SELECT name FROM accounts WHERE name='alice'").fetchone())
                db.execute("DELETE FROM accounts WHERE name='bob'")
            result=migrate(authority,etc,state);self.assertEqual(result['accounts'],2)
            with authority.db() as db:self.assertEqual(db.execute("SELECT system_admin FROM accounts WHERE name='alice'").fetchone()[0],1)
            authority.account('alice',1000,1000,'$6$salt$hash','status',False)
            self.assertTrue(migrate(authority,etc,state)['unchanged'])
            self.assertEqual((etc/'server.json').read_bytes(),before)
            with authority.db() as db:
                self.assertEqual(db.execute("SELECT system_admin FROM accounts WHERE name='alice'").fetchone()[0],0)
                self.assertEqual(json.loads(db.execute("SELECT value FROM settings WHERE key='schedules'").fetchone()[0])['timezone'],'Asia/Taipei')

    def test_firmware_retained_across_kernel_and_changed_import_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);file=root/'fixture.ucode';file.write_bytes(b'firmware')
            record=inspect(file,'6.8.0-test',['pci:fixture'],'test fixture')
            retained=approve(root/'store',file,record)
            destination=root/'image';destination.mkdir()
            with patch('driver_imports.subprocess.run'):
                apply(root/'store',destination,'6.9.0-new')
            self.assertEqual((destination/'usr/lib/firmware/fixture.ucode').read_bytes(),b'firmware')
            file.write_bytes(b'changed')
            with self.assertRaises(ValueError):approve(root/'store',file,record)
            metadata=load(retained/'record.json');metadata['modules']=True;dump(retained/'record.json',metadata)
            with self.assertRaisesRegex(ValueError,'original kernel'):apply(root/'store',destination,'6.9.0-new')

    def test_driver_package_rejects_scripts_and_system_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);package=root/'package';(package/'DEBIAN').mkdir(parents=True)
            (package/'DEBIAN').chmod(0o755)
            (package/'DEBIAN/control').write_text('Package: fixture\nVersion: 1\nArchitecture: amd64\nMaintainer: Test <test@example.invalid>\nDescription: test fixture\n')
            (package/'etc').mkdir();(package/'etc/shadow').write_text('not allowed')
            binary=root/'fixture.deb'
            subprocess.run(['dpkg-deb','--root-owner-group','--build',str(package),str(binary)],check=True,capture_output=True)
            with self.assertRaisesRegex(ValueError,'outside'):inspect(binary,'6.8.0-test',['pci:fixture'],'test fixture')
            shutil.rmtree(package/'etc');(package/'DEBIAN/postinst').write_text('#!/bin/sh\ntrue\n');(package/'DEBIAN/postinst').chmod(0o755)
            subprocess.run(['dpkg-deb','--root-owner-group','--build',str(package),str(binary)],check=True,capture_output=True)
            with self.assertRaisesRegex(ValueError,'scripts'):inspect(binary,'6.8.0-test',['pci:fixture'],'test fixture')

    def test_printer_config_cannot_include_documents_credentials_or_server_paths(self):
        self.assertEqual(validate_configuration({'lpoptions':'Default printer\n'}),{'lpoptions':'Default printer\n'})
        for value in ({'spool':'document'}, {'printers.conf':'DeviceURI ipp://user:password@host/'},
                      {'printers.conf':'Include /etc/shadow'}, {'lpoptions':'password=secret'}):
            with self.assertRaises(ValueError):validate_configuration(value)

    def test_sober_report_classifies_without_exporting_log_content(self):
        from sober_check import collect
        with tempfile.TemporaryDirectory() as temporary:
            home=Path(temporary);logs=home/'.var/app/org.vinegarhq.Sober/data/sober/sober_logs';logs.mkdir(parents=True)
            (logs/'fixture.log').write_text('download failed; password=PRIVATE_SENTINEL; personal-url/path')
            with patch('sober_check.subprocess.run',side_effect=FileNotFoundError):result=collect(home)
            encoded=json.dumps(result)
            self.assertIn('download_failure',result['log_categories'])
            self.assertNotIn('PRIVATE_SENTINEL',encoded);self.assertNotIn('personal-url',encoded)
            self.assertEqual(result['finding'],'no-demonstrated-httpboot-fault')

if __name__=='__main__':unittest.main()

class EncryptedPendingTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('age') and shutil.which('age-keygen'),'age unavailable')
    def test_pending_archive_is_encrypted_and_uuid_is_enforced(self):
        import io,tarfile
        from types import SimpleNamespace
        from pending_storage import save
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);home=root/'home';(home/'Documents').mkdir(parents=True)
            (home/'Documents/file').write_text('PRIVATE_PENDING_FIXTURE')
            media=root/'media';media.mkdir();key=root/'key'
            subprocess.run(['age-keygen','-o',str(key)],check=True,capture_output=True)
            recipient=subprocess.run(['age-keygen','-y',str(key)],check=True,capture_output=True,text=True).stdout.strip()
            policy={'uuid':'TEST-1234','mountpoint':str(media),'recipient':recipient}
            with patch('pending_storage.subprocess.run',return_value=SimpleNamespace(stdout='TEST-1234\n')):
                result=save(home,[{'folder':'Documents'}],policy,'alice')
            encrypted=media/'httpboot-pending'/result['file']
            self.assertNotIn(b'PRIVATE_PENDING_FIXTURE',encrypted.read_bytes());self.assertFalse(result['verified_backup'])
            plain=subprocess.run(['age','-d','-i',str(key),str(encrypted)],check=True,capture_output=True).stdout
            with tarfile.open(fileobj=io.BytesIO(plain)) as archive:
                self.assertEqual(archive.extractfile('Documents/file').read(),b'PRIVATE_PENDING_FIXTURE')
            with patch('pending_storage.subprocess.run',return_value=SimpleNamespace(stdout='OTHER-9999\n')):
                with self.assertRaisesRegex(ValueError,'approved'):save(home,[{'folder':'Documents'}],policy,'alice')

    def test_update_file_copy_retains_previous_on_verification_failure(self):
        from client_updates import copy_verified
        from common import sha256
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);source=root/'source';target=root/'target';source.write_bytes(b'new');target.write_bytes(b'previous')
            with self.assertRaises(ValueError):copy_verified(source,target,'0'*64)
            self.assertEqual(target.read_bytes(),b'previous')
            copy_verified(source,target,sha256(source));self.assertEqual(target.read_bytes(),b'new')
