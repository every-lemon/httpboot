import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'httpboot'))
import media_setup as media
from server_v2 import Authority
from common import sha256


def node(path,kind='disk',parent=None):
    return {'path':path,'type':kind,'size':8*1024**3,'serial':'fixture','wwn':None,'maj:min':'999:1' if kind=='disk' else '999:2',
            'uuid':'fixture-uuid' if parent else None,'fstype':'vfat' if parent else None,'parents':[parent] if parent else [],
            'parent':parent,'children_paths':[],'mountpoints':[],'ro':False}


class MediaSetupTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.authority=Authority(self.root/'state/authority.sqlite3')
        self.source=self.authority.images.root/'fixture';self.source.mkdir(parents=True)
        self.manifest={'release':'fixture','artifacts':{}}
        for name in ('boot.efi','recovery.efi','recovery.squashfs'):
            path=self.source/name;path.write_bytes(b'fixture')
            self.manifest['artifacts'][name]={'size':7,'sha256':sha256(path)}
        with self.authority.db() as db:db.execute('INSERT INTO images VALUES (?,?,0,1)',('fixture',json.dumps(self.manifest)))
        disk=node('/dev/fixture');part=node('/dev/fixture1','part','/dev/fixture');disk['children_paths']=[part['path']]
        self.nodes={disk['path']:disk,part['path']:part};self.expected=media.identity(self.nodes,disk['path'])
        self.ui=Mock();self.ui.input.return_value='ERASE /dev/fixture'

    def write(self,mode='erase',expected=None):
        return media.write(self.authority,self.ui,{},self.manifest,self.source,expected or self.expected,mode)

    def test_wrong_erase_confirmation_cannot_write_or_pin(self):
        self.ui.input.return_value='wrong'
        with patch.object(media,'recheck'),patch.object(media,'run') as run:
            with self.assertRaisesRegex(ValueError,'confirmation'):self.write()
            run.assert_not_called()
        with self.authority.db() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM image_pins').fetchone()[0],0)

    def test_changed_identity_after_confirmation_stops_before_wipe(self):
        with patch.object(media,'recheck',side_effect=[None,ValueError('identity changed')]),patch.object(media,'run') as run:
            with self.assertRaisesRegex(ValueError,'identity'):self.write()
            run.assert_not_called()

    def test_system_data_siblings_mounted_and_readonly_excluded(self):
        protected=set();media.protect_family(self.nodes,protected,'/dev/fixture1')
        self.assertEqual(protected,set(self.nodes))
        self.assertFalse(media.eligible(self.nodes,protected,'/dev/fixture','erase'))
        part=self.nodes['/dev/fixture1'];part['mountpoints']=['/media/fixture']
        self.assertFalse(media.eligible(self.nodes,set(),part['path'],'reuse'))
        part['mountpoints']=[];part['ro']=True
        self.assertFalse(media.eligible(self.nodes,set(),part['path'],'reuse'))

    def test_parent_replacement_is_detected(self):
        expected=media.identity(self.nodes,'/dev/fixture1');self.nodes['/dev/fixture']['serial']='replacement'
        with patch.object(media,'inventory',return_value=(self.nodes,set())):
            with self.assertRaisesRegex(ValueError,'identity'):media.recheck(expected,'reuse',{},self.root)

    def test_copy_failure_unmounts_and_never_reports_success(self):
        expected=media.identity(self.nodes,'/dev/fixture1');calls=[]
        with patch.object(media,'recheck'),patch.object(media,'verify_fat32'),patch.object(media,'inventory',return_value=(self.nodes,set())), \
             patch.object(media,'run',side_effect=lambda args,**kwargs:calls.append(args)), \
             patch('media_v2.enroll',side_effect=OSError('copy failed')):
            with self.assertRaisesRegex(OSError,'copy failed'):self.write('reuse',expected)
        self.assertTrue(any(call[0]=='umount' for call in calls));self.ui.message.assert_not_called()

    def test_verified_remount_reports_success_without_formatting(self):
        expected=media.identity(self.nodes,'/dev/fixture1');calls=[]
        def enroll(authority,mount,release):
            identity=mount/'httpboot-v2/identity';identity.mkdir(parents=True)
            from recovery_cache import publish
            publish(identity,self.manifest,self.source)
            for name,target in (('boot.efi',mount/media.EFI),('recovery.efi',mount/'EFI/HTTPBOOT/RECOVERY.EFI')):
                target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((self.source/name).read_bytes())
            (mount/'httpboot-v2/media.json').write_text(json.dumps({'release':release}))
        with patch.object(media,'recheck'),patch.object(media,'verify_fat32'),patch.object(media,'inventory',return_value=(self.nodes,set())), \
             patch.object(media,'run',side_effect=lambda args,**kwargs:calls.append(args)),patch('media_v2.enroll',side_effect=enroll):
            self.write('reuse',expected)
        self.assertEqual(sum(call[0]=='umount' for call in calls),2)
        self.assertTrue(any(call[0]=='mount' and 'ro,nosuid,nodev,noexec' in call for call in calls))
        self.assertFalse(any(call[0] in ('wipefs','mkfs.vfat','sfdisk') for call in calls))
        self.ui.message.assert_called_once();self.assertEqual(self.ui.message.call_args.args[0],'Boot media verified')

    def test_bad_published_content_rejected(self):
        path=self.source/'boot.efi';path.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'verification'):media.verify_file(path,self.manifest['artifacts']['boot.efi'])

    def test_cancel_menu_never_starts_device_inventory(self):
        self.ui.menu.side_effect=media.Cancelled()
        with patch.object(media.subprocess,'run',return_value=SimpleNamespace(returncode=1)),patch.object(media.shutil,'which',return_value='/bin/tool'), \
             patch.object(media,'inventory') as inventory:
            media.interactive(self.authority,self.ui)
            inventory.assert_not_called()

if __name__=='__main__':unittest.main()
