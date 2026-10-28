import gzip
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'httpboot'))
from common import sha256
from kernel_stage import sections,identity_overlay,transition,offline_transition
from recovery_cache import selected,publish


class BootTests(unittest.TestCase):
    def test_efi_parser_rejects_wrong_architecture_and_truncation(self):
        with tempfile.TemporaryDirectory() as temporary:
            file=Path(temporary)/'boot.efi';data=bytearray(512)
            data[:2]=b'MZ';struct.pack_into('<I',data,0x3c,64);data[64:68]=b'PE\0\0'
            struct.pack_into('<HHIIIHH',data,68,0x8664,3,0,0,0,0,0)
            for index,(name,content) in enumerate(((b'.linux',b'kernel'),(b'.initrd',b'ram'),(b'.cmdline',b'console=tty0'))):
                offset=88+index*40;data[offset:offset+8]=name.ljust(8,b'\0')
                struct.pack_into('<IIII',data,offset+8,len(content),0,len(content),256+index*64)
                data[256+index*64:256+index*64+len(content)]=content
            file.write_bytes(data);self.assertEqual(sections(file)['.linux'],b'kernel')
            struct.pack_into('<H',data,68,0xaa64);file.write_bytes(data)
            with self.assertRaisesRegex(ValueError,'amd64'):sections(file)
            struct.pack_into('<H',data,68,0x8664);file.write_bytes(data[:260])
            with self.assertRaisesRegex(ValueError,'Truncated'):sections(file)

    def test_kernel_transition_is_bounded_online_and_offline(self):
        with patch.object(Path,'read_text',return_value='httpboot.kernel-repair=1'):
            with self.assertRaisesRegex(ValueError,'already ran'):transition('',Path('/run'),{},lambda **_:None)
            with self.assertRaisesRegex(ValueError,'already ran'):offline_transition(Path('/run'),{})

    def test_identity_overlay_has_private_modes_and_no_unrelated_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'client.key').write_bytes(b'PRIVATE_FIXTURE');(root/'unrelated').write_bytes(b'EXCLUDE_FIXTURE')
            raw=gzip.decompress(identity_overlay(root))
            self.assertIn(b'PRIVATE_FIXTURE',raw);self.assertNotIn(b'EXCLUDE_FIXTURE',raw)
            self.assertIn(b'00008180',raw) # regular file, mode 0600

    def test_interrupted_recovery_replacement_keeps_previous_generation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);identity=root/'identity';identity.mkdir();source=root/'source';source.mkdir()
            for name in ('recovery.efi','recovery.squashfs'):(source/name).write_bytes(b'verified')
            record={'release':'first','artifacts':{name:{'size':8,'sha256':sha256(source/name)} for name in ('recovery.efi','recovery.squashfs')}}
            first=publish(identity,record,source);self.assertEqual(selected(identity),first)
            broken={**record,'release':'second'};(source/'recovery.efi').write_bytes(b'corrupted')
            with self.assertRaisesRegex(ValueError,'verification'):publish(identity,broken,source)
            self.assertEqual(selected(identity),first);self.assertEqual((first/'recovery.efi').read_bytes(),b'verified')
            (identity/'recovery-current').write_text('../../escape')
            with self.assertRaises(ValueError):selected(identity)

if __name__=='__main__':unittest.main()
