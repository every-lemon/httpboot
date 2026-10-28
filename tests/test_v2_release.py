import hashlib
import http.client
import importlib.util
import io
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import tarfile
import unittest
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'httpboot'))
from common import dump
from control_transport import ca, certificate_host, Server
from builder_v2 import LimitedServer
from client_updates import Updates
from product_version import VERSION, DEBIAN_VERSION, debian_version


class ReleaseTests(unittest.TestCase):
    def test_package_builds_with_private_umask_and_readable_installed_files(self):
        spec=importlib.util.spec_from_file_location('umask_package', ROOT/'packaging/build-server-deb.py')
        package=importlib.util.module_from_spec(spec); spec.loader.exec_module(package)
        with tempfile.TemporaryDirectory() as temporary:
            target=Path(temporary)/'server.deb'; previous=os.umask(0o077)
            try:package.build(target)
            finally:os.umask(previous)
            result=subprocess.run(['dpkg-deb','-f',str(target),'Version'],check=True,capture_output=True,text=True)
            self.assertEqual(result.stdout.strip(),DEBIAN_VERSION)
            raw=subprocess.run(['dpkg-deb','--fsys-tarfile',str(target)],check=True,capture_output=True).stdout
            with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
                for member in archive.getmembers():
                    if member.name in ('.','./'):continue
                    if member.isdir():self.assertEqual(member.mode & 0o777,0o755,member.name)
                    elif member.isfile():self.assertEqual(member.mode & 0o444,0o444,member.name)

    def test_public_audit_rejects_credentials_and_private_state(self):
        spec=importlib.util.spec_from_file_location('audit_release', ROOT/'packaging/audit-public.py')
        audit=importlib.util.module_from_spec(spec); spec.loader.exec_module(audit)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); file=root/'example.txt'; file.write_text('public example')
            self.assertEqual(audit.audit([file],root),1)
            for payload in (b'-'*5+b'BEGIN PRIVATE KEY'+b'-'*5, b'gh'+b'p_'+b'A'*36):
                file.write_bytes(payload)
                with self.assertRaisesRegex(ValueError,'Credential'): audit.audit([file],root)
            file.write_text('public example'); private=root/'private'; private.mkdir(); file.rename(private/file.name)
            with self.assertRaisesRegex(ValueError,'Private state'): audit.audit([private/file.name],root)

    def test_public_archive_is_reproducible_and_uses_the_public_readme(self):
        spec=importlib.util.spec_from_file_location('export_release', ROOT/'packaging/public-source.py')
        export=importlib.util.module_from_spec(spec); spec.loader.exec_module(export)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            export.build(root/'first.tar.gz'); export.build(root/'second.tar.gz')
            self.assertEqual((root/'first.tar.gz').read_bytes(),(root/'second.tar.gz').read_bytes())
            with tarfile.open(root/'first.tar.gz') as archive:
                self.assertEqual(archive.extractfile('README.md').read(),(ROOT/'docs/README-public.md').read_bytes())
                self.assertFalse(any(name.startswith('private/') or '__pycache__' in name for name in archive.getnames()))

    def test_debian_versions_order_beta_rc_and_final(self):
        versions = ['3.1.15-beta.1', '3.1.15-beta.2', '3.1.15-beta.10',
                    '3.1.15-rc.1', '3.1.15-rc.2', '3.1.15']
        for before, after in zip(versions, versions[1:]):
            subprocess.run(['dpkg', '--compare-versions', debian_version(before),
                            'lt', debian_version(after)], check=True)
        self.assertEqual(DEBIAN_VERSION, debian_version(VERSION))
        for invalid in ('../3.1.15', '3.1.15-beta.0', '03.1.15-rc.1',
                        '3.1.15-rc.01', '3.1.15-beta/rc.1', '3.1.15-beta.1\n'):
            with self.subTest(version=invalid), self.assertRaises(ValueError):
                debian_version(invalid)

    def test_installed_version_and_public_allowlists_agree(self):
        spec = importlib.util.spec_from_file_location('release_package', ROOT/'packaging/build-server-deb.py')
        package = importlib.util.module_from_spec(spec); spec.loader.exec_module(package)
        from build_public import CLIENT_MODULES
        self.assertEqual(package.VERSION, DEBIAN_VERSION)
        self.assertIn('product_version.py', package.MODULES)
        self.assertIn('product_version.py', CLIENT_MODULES)
        for program in ('server_v2.py', 'build_public.py'):
            result = subprocess.run([sys.executable, str(ROOT/'httpboot'/program), '--version'],
                                    check=True, capture_output=True, text=True)
            self.assertIn(VERSION, result.stdout)


class CertificateTests(unittest.TestCase):
    def test_host_validation_rejects_config_and_subject_injection(self):
        for host in ('name\nsubjectAltName=DNS:other', 'name/OU=other', '-bad.example',
                     'bad..example', 'name:9444', 'https://example.org', 'a'*64+'.org', 'fe80::1%eth0'):
            with self.subTest(host=host), self.assertRaises(ValueError): certificate_host(host)
        self.assertEqual(certificate_host('BOOT.example.org'), ('DNS', 'boot.example.org'))
        self.assertEqual(certificate_host('::1'), ('IP', '::1'))

    def test_fresh_domain_certificate_verifies_for_its_hostname(self):
        from server_v2 import main
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)/'pki'; previous=os.umask(0o077)
            try:
                with patch('sys.argv',['httpboot-server','--state',temporary,'init-pki','--address','boot.example.invalid']), patch('os.geteuid',return_value=0):
                    main()
            finally:os.umask(previous)
            subprocess.run(['openssl', 'verify', '-CAfile', str(folder/'ca.pem'),
                            '-verify_hostname', 'boot.example.invalid', str(folder/'server.pem')],
                           check=True, capture_output=True)
            wrong = subprocess.run(['openssl', 'verify', '-CAfile', str(folder/'ca.pem'),
                                    '-verify_hostname', 'wrong.example.invalid', str(folder/'server.pem')],
                                   capture_output=True)
            self.assertNotEqual(wrong.returncode, 0)

    def test_slow_tls_handshake_does_not_block_other_clients(self):
        class Probe(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                self.send_response(200); self.send_header('Content-Length', '2')
                self.end_headers(); self.wfile.write(b'ok')
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)/'pki'; ca(folder, '127.0.0.1')
            client = ssl.create_default_context(cafile=str(folder/'ca.pem'))
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(folder/'server.pem', folder/'server.key')
            for make in (lambda: Server(('127.0.0.1', 0), folder, None, handler=Probe),
                         lambda: LimitedServer(('127.0.0.1', 0), Probe, context)):
                server = make(); thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
                slow = socket.create_connection(server.server_address)
                try:
                    # A connected TCP peer sends no TLS ClientHello at all.
                    started = time.monotonic()
                    connection = http.client.HTTPSConnection(*server.server_address, context=client, timeout=3)
                    connection.request('GET', '/'); response = connection.getresponse()
                    self.assertEqual(response.status, 200); self.assertEqual(response.read(), b'ok')
                    self.assertLess(time.monotonic()-started, 3)
                    connection.close()
                finally:
                    slow.close(); server.shutdown(); server.server_close(); thread.join(3)


class InterruptedUpdateTests(unittest.TestCase):
    def test_failed_recovery_commit_does_not_replace_working_efi(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); run=root/'run'; media=run/'media'; identity=media/'httpboot-v2/identity'
            identity.mkdir(parents=True)
            (run/'cache-location').write_text(str(identity))
            boot=media/'EFI/BOOT/BOOTX64.EFI'; recovery=media/'EFI/HTTPBOOT/RECOVERY.EFI'
            for path in (boot, recovery): path.parent.mkdir(parents=True); path.write_bytes(b'previous EFI')
            records={name:{'size':len(name), 'sha256':hashlib.sha256(name.encode()).hexdigest()}
                     for name in ('boot.efi','recovery.efi','recovery.squashfs')}
            manifest={'release':'fixture-update', 'artifacts':records}
            agent=SimpleNamespace(run=run, credentials=root, url='https://example.invalid',
                                  config={'server':'https://example.invalid'},
                                  call=Mock(return_value={'images':[manifest]}), queue_report=Mock())
            def download(url, release, name, metadata, credentials, target, progress): target.write_bytes(name.encode())
            def command(args, **kwargs): return SimpleNamespace(stdout='/dev/fixture', returncode=0)
            with patch.object(Path, 'is_mount', lambda path: path == media), \
                 patch('client_updates.verify_manifest'), patch('client_updates.download', side_effect=download), \
                 patch('client_updates.subprocess.run', side_effect=command), \
                 patch('recovery_cache.publish', side_effect=OSError('Interrupted recovery commit')) as publish:
                updates=Updates(agent); updates.start(); deadline=time.monotonic()+30
                while updates.lock.locked() and time.monotonic()<deadline: time.sleep(.01)
                self.assertFalse(updates.lock.locked())
                self.assertEqual(updates.snapshot()['state'], 'failed')
                publish.assert_called_once()
                self.assertIn('Interrupted recovery commit', updates.snapshot()['message'])
                self.assertEqual(boot.read_bytes(), b'previous EFI')
                self.assertEqual(recovery.read_bytes(), b'previous EFI')


if __name__ == '__main__': unittest.main()
