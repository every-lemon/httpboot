import hashlib
import base64
import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'httpboot'))
from server_v2 import Authority
from client_policy import validate,FLATHUB
from recovery_cache import publish,available,reuse
from persistence_v2 import Saver

class DesktopUpdateTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
    def test_visibility_changes_only_chooser_policy(self):
        authority=Authority(self.root/'authority.db')
        authority.account('fixture',1000,1000,'$6$fixture$value','edit',True)
        with authority.db(write=False) as db:before=dict(db.execute('SELECT * FROM accounts').fetchone())
        authority.visibility('fixture',False)
        with authority.db(write=False) as db:after=dict(db.execute('SELECT * FROM accounts').fetchone())
        self.assertEqual(after.pop('login_visible'),0);before.pop('login_visible');self.assertEqual(before,after)
        with self.assertRaises(ValueError):authority.visibility('absent',True)
        with self.assertRaises(ValueError):authority.visibility('fixture','false')
    def test_flathub_default_and_explicit_disabled_policy_survives_restart(self):
        authority=Authority(self.root/'authority.db')
        with authority.db() as db:
            self.assertEqual(json.loads(db.execute("SELECT value FROM settings WHERE key='sources'").fetchone()[0]),[FLATHUB])
            db.execute("UPDATE settings SET value='[]' WHERE key='sources'")
        authority=Authority(self.root/'authority.db')
        with authority.db(write=False) as db:self.assertEqual(db.execute("SELECT value FROM settings WHERE key='sources'").fetchone()[0],'[]')
    def test_policy_does_not_accept_client_ips_or_untrusted_http(self):
        for origin in ('http://example.org','https://name:password@example.org','https://example.org/path','https://example.org/#fragment'):
            with self.assertRaises(ValueError):validate({'allowed_origins':[origin]})
        self.assertEqual(validate({'allowed_origins':['https://example.org/']})['allowed_origins'],['https://example.org'])
        with self.assertRaises(ValueError):validate({'preferred_origin':'https://other.example'})
    def test_recovery_reuse_and_corruption_detection(self):
        sources=self.root/'sources';sources.mkdir();artifacts={}
        for name in ('recovery.squashfs','recovery.efi'):
            data=name.encode();(sources/name).write_bytes(data)
            artifacts[name]={'size':len(data),'sha256':hashlib.sha256(data).hexdigest()}
        manifest={'release':'fixture-1','artifacts':artifacts}
        identity=self.root/'identity';generation=publish(identity,manifest,sources)
        self.assertTrue(available(identity,manifest))
        other={**manifest,'release':'fixture-2'}
        self.assertFalse(available(identity,other))
        self.assertTrue(reuse(identity,other,'recovery.squashfs',self.root/'copy'))
        (generation/'recovery.squashfs').write_bytes(b'corrupt')
        self.assertFalse(available(identity,manifest))
        self.assertFalse(reuse(identity,other,'recovery.squashfs',self.root/'copy'))
    def test_recovery_retains_current_and_verified_previous_without_touching_identity(self):
        sources=self.root/'sources';sources.mkdir();identity=self.root/'identity';identity.mkdir()
        (identity/'client.key').write_text('fixture-device-key');artifacts={}
        for name in ('recovery.squashfs','recovery.efi'):
            data=name.encode();(sources/name).write_bytes(data);artifacts[name]={'size':len(data),'sha256':hashlib.sha256(data).hexdigest()}
        generations=[publish(identity,{'release':'fixture-'+str(n),'artifacts':artifacts},sources) for n in range(3)]
        self.assertFalse(generations[0].exists());self.assertTrue(generations[1].is_dir());self.assertTrue(generations[2].is_dir())
        self.assertEqual((identity/'client.key').read_text(),'fixture-device-key')

    def test_restore_concurrency_bounded_and_content_verified(self):
        home=self.root/'home';home.mkdir();data=b'contents';digest=hashlib.sha256(data).hexdigest()
        files={f'file-{n}':{'size':len(data),'chunks':[digest]} for n in range(12)}
        lock=threading.Lock();active=0;peak=0;statuses=[]
        def call(route,value):
            nonlocal active,peak
            if route=='latest':return {'snapshot':{'id':'fixture'}}
            if route=='manifest-page':return {'files':files,'next':None}
            if route=='get':
                with lock:active+=1;peak=max(active,peak)
                time.sleep(.02)
                with lock:active-=1
                return {'content':base64.b64encode(data).decode()}
            raise AssertionError(route)
        saver=Saver(home,self.root/'cache',call,lambda **v:statuses.append(v));saver.restore({'folder':'Documents','mode':'folder'})
        self.assertGreater(peak,1);self.assertLessEqual(peak,4)
        for name in files:self.assertEqual((home/'Documents'/name).read_bytes(),data)
        self.assertEqual(statuses[-1]['bytes_done'],len(data)*12)
    def test_restore_corruption_does_not_prune_previous_files(self):
        home=self.root/'home';(home/'Documents').mkdir(parents=True);(home/'Documents/old').write_text('keep')
        digest=hashlib.sha256(b'good').hexdigest()
        def call(route,value):
            return {'latest':{'snapshot':{'id':'fixture'}},'manifest-page':{'files':{'new':{'size':4,'chunks':[digest]}},'next':None},'get':{'content':base64.b64encode(b'bad').decode()}}[route]
        with self.assertRaisesRegex(ValueError,'checksum'):Saver(home,self.root/'cache',call).restore({'folder':'Documents','mode':'folder'})
        self.assertEqual((home/'Documents/old').read_text(),'keep');self.assertFalse((home/'Documents/new').exists())


    def test_alias_certificate_keeps_key_and_old_name(self):
        import subprocess
        from control_transport import ca
        from client_policy import extend_transport_certificate
        folder=self.root/'pki';ca(folder,'127.0.0.1')
        key=(folder/'server.key').read_bytes();old=(folder/'server.pem').read_bytes()
        extend_transport_certificate(folder,['https://boot.example.org'])
        self.assertEqual((folder/'server.key').read_bytes(),key)
        self.assertEqual((folder/'server-before-origins.pem').read_bytes(),old)
        for kind,name in (('-verify_ip','127.0.0.1'),('-verify_hostname','boot.example.org')):
            subprocess.run(['openssl','verify','-CAfile',str(folder/'ca.pem'),kind,name,str(folder/'server.pem')],check=True,capture_output=True)
    def test_staging_never_runs_session_save_or_pauses_saver(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        from client_updates import Updates
        manifest={'release':'fixture','artifacts':{name:{'size':1,'sha256':'0'*64} for name in ('boot.efi','recovery.efi','recovery.squashfs')}}
        agent=SimpleNamespace(run=self.root,credentials=self.root,url='https://example.org',config={'server':'https://example.org'},sessions={'1000':{}},saving_paused=False,
                              call=Mock(return_value={'images':[manifest]}),worker=Mock(side_effect=AssertionError('Must not save')),queue_report=Mock())
        updates=Updates(agent)
        with patch('client_updates.verify_manifest'),patch('client_updates.download') as download:
            updates.start()
            deadline=time.monotonic()+5
            while updates.lock.locked() and time.monotonic()<deadline:time.sleep(.01)
            self.assertEqual(updates.snapshot()['phase'],'ready-to-restart')
            self.assertFalse(agent.saving_paused);agent.worker.assert_not_called()
            self.assertEqual(download.call_count,3)
            updates.start()
            while updates.lock.locked() and time.monotonic()<deadline:time.sleep(.01)
            self.assertEqual(download.call_count,3)

if __name__=='__main__':unittest.main()
