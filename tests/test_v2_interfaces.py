import datetime
import hashlib
import http.client
import json
import ssl
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'httpboot'))
from common import dump,atomic,sha256
from server_v2 import Authority
from image_delivery import ARTIFACTS,ImageHandler,download
from control_transport import Server,ca,key_request,issue,request
import schedule_policy
from product_version import VERSION

class InterfaceTests(unittest.TestCase):
    def test_actual_authenticated_images_and_resume(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);pki=root/'pki';client=root/'client';source=root/'source';source.mkdir()
            ca(pki,'127.0.0.1');csr=key_request(client,'request');atomic(client/'ca.pem',(pki/'ca.pem').read_text())
            authority=Authority(root/'authority.db')
            pending=authority.activation({'csr':csr,'hardware':{'model':'test'}},'127.0.0.1')
            peer=authority.approve(pending['code'],lambda csr,name:issue(pki,csr,name))
            atomic(client/'client.pem',authority.activation({'csr':csr,'hardware':{'model':'test'}},'127.0.0.1')['certificate'])
            for name in ARTIFACTS:(source/name).write_bytes((name.encode()+b'!')*10000)
            records={name:{'size':(source/name).stat().st_size,'sha256':sha256(source/name)} for name in ARTIFACTS}
            proof={'schema':2,'architecture':'amd64','kernel':'fixture-kernel','startup_verified':True,'recovery_verified':True,'assigned_login_verified':True,'native_http_pairing_verified':True,'clean_shutdown_verified':True,'startup_interrupt_verified':True,'artifacts':records,'validator_sha256':sha256(Path(__file__).resolve().parents[1]/'httpboot/validate_v2.py')}
            dump(source/'release.json',{'kernel':'fixture-kernel'})
            for check in ('assigned_login_verified','native_http_pairing_verified','clean_shutdown_verified','startup_interrupt_verified'):
                dump(root/'proof.json',{**proof,check:False})
                with self.assertRaisesRegex(ValueError,'proof'):
                    authority.images.publish('unqualified',source,root/'proof.json')
            dump(root/'proof.json',proof)
            authority.images.publish('first',source,root/'proof.json')
            authority.images.publish('latest',source,root/'proof.json')
            self.assertEqual([r['release'] for r in authority.images.catalogue(peer)['images']],['latest'])
            self.assertEqual(len(authority.images.catalogue(peer,True)['images']),2)
            with self.assertRaisesRegex(ValueError,'immutable'):authority.images.publish('latest',source,root/'proof.json')
            server=Server(('127.0.0.1',0),pki,authority,handler=ImageHandler)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            url='https://127.0.0.1:'+str(server.server_port)
            try:
                context=ssl.create_default_context(cafile=str(pki/'ca.pem'))
                connection=http.client.HTTPSConnection('127.0.0.1',server.server_port,context=context)
                connection.request('GET','/v2/image/latest/filesystem.squashfs')
                self.assertEqual(connection.getresponse().status,403);connection.close()
                output=root/'download'
                output.with_name('download.partial').write_bytes((source/'filesystem.squashfs').read_bytes()[:16000])
                progress=[]
                download(url,'latest','filesystem.squashfs',records['filesystem.squashfs'],client,output,lambda **v:progress.append(v))
                self.assertEqual(output.read_bytes(),(source/'filesystem.squashfs').read_bytes())
                self.assertTrue(progress);self.assertEqual(progress[-1]['bytes_done'],records['filesystem.squashfs']['size'])
                self.assertIn('eta_seconds',progress[-1])
                result=request(url,'/v2/images',credentials=client)
                self.assertEqual(result['images'][0]['release'],'latest')
                from boot_client_v2 import verify_manifest
                verify_manifest(result['images'][0],client/'ca.pem',url)
                corrupt=json.loads(json.dumps(result['images'][0]));corrupt['artifacts']['boot.efi']['sha256']='0'*64
                with self.assertRaises(Exception):verify_manifest(corrupt,client/'ca.pem',url)
                evil=root/'other-key';other=key_request(evil,'another-key')
                atomic(evil/'ca.pem',(pki/'ca.pem').read_bytes());atomic(evil/'client.pem',issue(pki,other,peer))
                with self.assertRaisesRegex(ValueError,'key does not match'):request(url,'/v2/images',credentials=evil)
                with authority.db() as db:
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM image_pins WHERE reason LIKE 'transfer:%'").fetchone()[0],0)
            finally:server.shutdown();server.server_close();thread.join(3)

    def test_publication_requires_matching_successful_proof(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);source=root/'source';source.mkdir()
            authority=Authority(root/'authority.db')
            for name in ARTIFACTS:(source/name).write_bytes(b'x')
            dump(root/'proof',{'schema':2,'architecture':'amd64','startup_verified':False})
            with self.assertRaisesRegex(ValueError,'proof'):authority.images.publish('failed',source,root/'proof')
            with authority.db() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM images').fetchone()[0],0)

    def test_independent_schedule_switches_timezone_and_duplicate_claim(self):
        policy=schedule_policy.defaults('Asia/Taipei')
        before=datetime.datetime(2026,10,24,19,59,tzinfo=datetime.timezone.utc).timestamp()
        after=before+120
        self.assertFalse(schedule_policy.due(policy,'host_packages',0,before))
        self.assertTrue(schedule_policy.due(policy,'host_packages',0,after))
        policy['host_packages']['enabled']=False
        self.assertFalse(schedule_policy.due(policy,'host_packages',0,after))
        self.assertTrue(schedule_policy.due(policy,'image_updates',0,after))
        with tempfile.TemporaryDirectory() as temporary:
            authority=Authority(Path(temporary)/'authority.db')
            with authority.db() as db:db.execute("INSERT INTO settings VALUES ('schedules',?)",(json.dumps(policy),))
            with self.assertRaises(ValueError):schedule_policy.claim(authority,'image_updates',after,{'state':'healthy','version':'3.1.14','seen':after})
            claim=schedule_policy.claim(authority,'image_updates',after,{'state':'healthy','version':VERSION,'seen':after})
            self.assertIsNotNone(claim);schedule_policy.finish(authority,claim)
            self.assertIsNone(schedule_policy.claim(authority,'image_updates',after,{'state':'healthy','version':VERSION,'seen':after}))

    def test_cleanup_keeps_three_active_and_card_pinned(self):
        from release_cleanup import candidates,cleanup
        with tempfile.TemporaryDirectory() as temporary:
            authority=Authority(Path(temporary)/'authority.db')
            with authority.db() as db:
                for number in range(7):
                    db.execute('INSERT INTO images VALUES (?,?,?,?)',(str(number),'{}',number,int(number==0)))
                    (authority.images.root/str(number)).mkdir()
            candidates(authority,40*86400)
            with authority.db() as db:db.execute('INSERT INTO image_pins VALUES (?,?)',('1','enrolled-card'))
            self.assertEqual(candidates(authority,40*86400),['3','2'])
            cleanup(authority,40*86400,True)
            for identifier in ('0','1','4','5','6'):self.assertTrue((authority.images.root/identifier).exists())

class ClientPermissionTests(unittest.TestCase):
    def setUp(self):
        from client_agent import Agent
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.agent=Agent({'identity':self.temp.name,'server':'https://127.0.0.1'},Path(self.temp.name)/'run')
        self.agent.accounts={'1000':{'name':'alice','uid':1000,'gid':1000,'access':'status','rules':'[]'}}
        self.agent.sessions={'1000':{'name':'alice','token':'private'}}

    def test_user_cannot_request_another_account_or_token(self):
        self.agent.call=lambda path,data:data
        result=self.agent.dispatch(1000,{'action':'snapshot','route':'get','value':{'name':'bob','token':'stolen','digest':'0'*64}})
        self.assertEqual(result['name'],'alice');self.assertEqual(result['token'],'private')
        with self.assertRaises(ValueError):self.agent.dispatch(1001,{'action':'state'})
        with self.assertRaises(ValueError):self.agent.dispatch(1000,{'action':'open-login','name':'alice'})
        state=self.agent.dispatch(1000,{'action':'state'})
        self.assertNotIn('token',json.dumps(state))

    def test_power_checks_live_admin_role_and_does_not_grant_unassigned_access(self):
        from unittest.mock import Mock
        self.agent.power.start=Mock(return_value={'ok':True})
        fresh={'name':'alice','uid':1000,'system_admin':0}
        self.agent.call=lambda *args:{'accounts':[fresh]}
        self.assertTrue(self.agent.dispatch(1000,{'action':'power','operation':'reboot'})['ok'])
        self.agent.sessions['1001']={'name':'bob','token':'second'}
        self.agent.accounts['1000']['system_admin']=1
        with self.assertRaises(ValueError):self.agent.dispatch(1000,{'action':'power','operation':'reboot'})
        with self.assertRaises(ValueError):self.agent.dispatch(1001,{'action':'power','operation':'poweroff'})
        fresh['system_admin']=1
        self.assertTrue(self.agent.dispatch(1000,{'action':'power','operation':'poweroff'})['ok'])

    def test_status_only_and_no_access_cannot_edit(self):
        for access in ('none','status'):
            self.agent.accounts['1000']['access']=access
            with self.assertRaises(ValueError):self.agent.dispatch(1000,{'action':'rules','rules':[]})
        self.agent.accounts['1000']['access']='none'
        with self.assertRaises(ValueError):self.agent.dispatch(1000,{'action':'images'})
        self.assertIn('warning',self.agent.dispatch(1000,{'action':'state'}))

if __name__=='__main__':unittest.main()

class LoginLifecycleTests(unittest.TestCase):
    setUp=ClientPermissionTests.setUp
    def test_login_restore_barrier_and_failed_logout_continues_ram(self):
        authority=Authority(Path(self.temp.name)/'authority.db');peer='client-test'
        with authority.db() as db:db.execute('INSERT INTO devices(id,approved) VALUES (?,1)',(peer,))
        authority.account('alice',1000,1000,'$6$salt$hash','edit');authority.assign('alice',peer)
        self.agent.sessions={}
        self.agent.call=lambda route,data=None:authority('POST' if data else 'GET',route,peer,'127.0.0.1',data)
        calls=[]
        def restore(uid,action):
            calls.append(action)
            self.assertFalse(self.agent.sessions[uid]['ready'])
            with self.assertRaisesRegex(ValueError,'Restore'):
                self.agent.dispatch(1000,{'action':'snapshot','route':'put','value':{}})
        self.agent.worker=restore
        self.agent.dispatch(0,{'action':'open-login','name':'alice'})
        token=self.agent.sessions['1000']['token'];self.assertTrue(self.agent.sessions['1000']['ready'])
        def fail(*_):raise OSError('Server disconnected')
        self.agent.worker=fail
        with self.assertRaises(OSError):self.agent.dispatch(0,{'action':'close-login','name':'alice'})
        self.assertTrue(self.agent.sessions['1000']['detached'])
        self.assertTrue(self.agent.dispatch(0,{'action':'open-login','name':'alice'})['continued_ram_session'])
        self.assertEqual(self.agent.sessions['1000']['token'],token)
        self.assertEqual(calls,['restore'])

    def test_same_client_console_and_desktop_share_one_persistent_session(self):
        self.agent.sessions={};calls=[];self.agent.worker=lambda uid,action:calls.append(action)
        self.agent.call=lambda route,data=None: {'token':'fixture'} if route=='/v2/sessions' else {'ok':True}
        first={'name':'alice','login_id':'100:200'};second={'name':'alice','login_id':'101:201'}
        self.agent.dispatch(0,{'action':'open-login',**first})
        self.agent.dispatch(0,{'action':'open-login',**second})
        self.assertEqual(calls,['restore'])
        self.assertTrue(self.agent.dispatch(1000,{'action':'state'})['session_ready'])
        self.agent.dispatch(0,{'action':'close-login',**first})
        self.assertIn('1000',self.agent.sessions)
        self.assertEqual(calls,['restore'])
        self.agent.dispatch(0,{'action':'close-login',**second})
        self.assertEqual(calls,['restore','save'])
        self.assertNotIn('1000',self.agent.sessions)

    def test_second_login_during_restore_is_refused_without_new_session(self):
        self.agent.sessions={'1000':{'name':'alice','token':'fixture','ready':False}}
        with self.assertRaisesRegex(ValueError,'restore is still running'):
            self.agent.dispatch(0,{'action':'open-login','name':'alice','login_id':'101:201'})
        self.assertFalse(self.agent.dispatch(1000,{'action':'state'})['session_ready'])

    def test_worker_failure_uses_redacted_location_not_command_or_private_path(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        from client_agent import WorkerError
        result=SimpleNamespace(returncode=1,stderr='private path /home/alice/secret\nHTTPBOOT_WORKER_ERROR=PermissionError:persistence_v2.py:80\n')
        with patch('client_agent.subprocess.run',return_value=result):
            with self.assertRaises(WorkerError) as caught:self.agent.worker('1000','restore')
        self.assertNotIn('/home/',str(caught.exception))
        self.assertEqual(caught.exception.diagnostic_code,'PermissionError:persistence_v2.py:80')

    def test_lost_release_response_can_resume_same_ram_session(self):
        self.agent.sessions={};self.agent.worker=lambda *_:None
        def call(route,data=None):
            if route=='/v2/sessions':return {'token':'fixture'}
            if route=='/v2/sessions/release':raise OSError('Disconnected')
            return {'ok':True}
        self.agent.call=call
        request={'name':'alice','login_id':'100:200'}
        self.agent.dispatch(0,{'action':'open-login',**request})
        with self.assertRaises(OSError):self.agent.dispatch(0,{'action':'close-login',**request})
        self.assertTrue(self.agent.dispatch(0,{'action':'open-login',**request})['continued_ram_session'])
