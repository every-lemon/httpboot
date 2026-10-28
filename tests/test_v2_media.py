import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'httpboot'))
from common import sha256
from control_transport import ca, issue, key_request
from media_v2 import enroll
from recovery_cache import selected
from server_v2 import Authority


class MediaMigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.authority = Authority(root / 'state/authority.sqlite3')
        self.pki = root / 'state/pki'
        ca(self.pki, '127.0.0.1')
        old_pki = root / 'old-pki'
        ca(old_pki, '127.0.0.1')
        key_dir = root / 'device'
        csr = key_request(key_dir, 'fixture')
        request = self.authority.activation({'csr': csr, 'hardware': {'model': 'fixture'}}, 'fixture')
        self.device = self.authority.approve(request['code'], lambda csr, name: issue(old_pki, csr, name))
        with self.authority.db() as db:
            certificate = db.execute('SELECT certificate FROM devices WHERE id=?', (self.device,)).fetchone()[0]
        self.key = (key_dir / 'client.key').read_text()
        self.mount = root / 'card'
        self.legacy = self.mount / 'httpboot/device.json'
        self.legacy.parent.mkdir(parents=True)
        self.legacy.write_text(json.dumps({'key': self.key, 'certificate': certificate}))
        self.legacy_bytes = self.legacy.read_bytes()
        self.boot = self.mount / 'EFI/BOOT/BOOTX64.EFI'
        self.boot.parent.mkdir(parents=True)
        self.boot.write_bytes(b'old bootstrap')
        self.identity = self.mount / 'httpboot-v2/identity'
        self.identity.mkdir(parents=True)
        (self.identity / 'recovery.squashfs').write_bytes(b'old recovery')
        source = self.authority.images.root / 'fixture-release'
        source.mkdir(parents=True)
        names = ('boot.efi', 'recovery.efi', 'recovery.squashfs')
        for name in names:
            (source / name).write_bytes(('new ' + name).encode())
        manifest = {'release': 'fixture-release', 'artifacts': {
            name: {'size': (source / name).stat().st_size, 'sha256': sha256(source / name)} for name in names}}
        # Fixture catalogue only: production publication has separate proof gates.
        with self.authority.db() as db:
            db.execute('INSERT INTO images VALUES (?,?,0,1)', ('fixture-release', json.dumps(manifest)))
        real_run = subprocess.run
        def run(command, **kwargs):
            if command[0] == 'findmnt':
                value = '/dev/fixture-usb vfat fixture-uuid' if command[-1] == str(self.mount) else '/dev/fixture-root'
                return subprocess.CompletedProcess(command, 0, stdout=value)
            if command[0] == 'mount':
                return subprocess.CompletedProcess(command, 0)
            return real_run(command, **kwargs)
        for item in (patch.object(Path, 'is_mount', return_value=True),
                     patch('media_v2.ancestors', side_effect=lambda device: {device}),
                     patch('media_v2.subprocess.run', side_effect=run), patch('media_v2.os.sync')):
            item.start()
            self.addCleanup(item.stop)

    def test_legacy_key_renewed_and_recovery_committed_before_bootstrap(self):
        with patch('recovery_cache.publish', side_effect=OSError('interrupted recovery copy')):
            with self.assertRaisesRegex(OSError, 'interrupted'):
                enroll(self.authority, self.mount)
        self.assertEqual(self.boot.read_bytes(), b'old bootstrap')
        self.assertEqual((self.identity / 'recovery.squashfs').read_bytes(), b'old recovery')
        self.assertEqual(self.legacy.read_bytes(), self.legacy_bytes)
        self.assertFalse((self.identity / 'recovery-current').exists())
        self.assertTrue(enroll(self.authority, self.mount)['ok'])
        self.assertEqual(self.boot.read_bytes(), b'new boot.efi')
        self.assertEqual((selected(self.identity) / 'recovery.squashfs').read_bytes(), b'new recovery.squashfs')
        self.assertEqual((self.identity / 'recovery.squashfs').read_bytes(), b'old recovery')
        self.assertEqual((self.identity / 'client.key').read_text(), self.key)
        self.assertEqual(self.legacy.read_bytes(), self.legacy_bytes)
        subprocess.run(['openssl', 'verify', '-CAfile', str(self.pki / 'ca.pem'),
                        str(self.identity / 'client.pem')], check=True, capture_output=True)

    def test_unapproved_existing_key_keeps_old_bootstrap(self):
        with self.authority.db() as db:
            db.execute('UPDATE devices SET approved=0 WHERE id=?', (self.device,))
        with self.assertRaisesRegex(ValueError, 'Approve or migrate'):
            enroll(self.authority, self.mount)
        self.assertEqual(self.boot.read_bytes(), b'old bootstrap')
        self.assertEqual(self.legacy.read_bytes(), self.legacy_bytes)


if __name__ == '__main__':
    unittest.main()
