import concurrent.futures
import contextlib
import importlib.util
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'httpboot'))
import server_v2

class AuthorityTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.now=1000
        self.authority=server_v2.Authority(Path(self.temp.name)/'state/authority.db',lambda:self.now)
        self.key=patch.object(server_v2,'csr_key',side_effect=lambda csr:csr)
        self.key.start();self.addCleanup(self.key.stop)

    def activate(self, key='key'):
        return self.authority.activation({'csr':key,'hardware':{'model':'test','serial':'fixture'}},key)

    def approved(self,key='key'):
        request=self.activate(key)
        identifier=self.authority.approve(request['code'],lambda csr, peer:'cert:'+peer)
        return identifier

    def account(self,peer,access='edit'):
        self.authority.account('alice',1000,1000,'$6$salt$hash',access)
        self.authority.assign('alice',peer)

    def test_unknown_client_pairing_expires(self):
        request=self.activate()
        self.assertRegex(request['code'],r'^[A-Z0-9]{6}$')
        self.assertEqual(request['message'],server_v2.UNKNOWN)
        self.now+=600
        with self.assertRaisesRegex(ValueError,'expired'):
            self.authority.approve(request['code'],lambda *_:self.fail('Expired code issued a cert'))
        self.assertGreater(self.activate()['expires'],request['expires'])

    def test_approval_consumed_and_hardware_bound(self):
        peer=self.approved()
        self.assertEqual(self.activate()['certificate'],'cert:'+peer)
        with self.assertRaisesRegex(ValueError,'Hardware changed'):
            self.authority.activation({'csr':'key','hardware':{'model':'different'}},'another')
        with self.assertRaises(ValueError):self.authority.approve('INVALID',lambda *_:'cert')

    def test_failed_approval_attempts_are_rate_limited(self):
        for _ in range(5):
            with self.assertRaisesRegex(ValueError,'expired'):
                self.authority.approve('BAD',lambda *_:'cert')
        with self.assertRaisesRegex(ValueError,'Too many'):
            self.authority.approve('BAD',lambda *_:'cert')

    def test_issuer_failure_keeps_pairing_pending(self):
        request=self.activate()
        with self.assertRaises(OSError):
            self.authority.approve(request['code'],lambda *_:(_ for _ in ()).throw(OSError('issuer failed')))
        self.assertFalse(self.activate()['approved'])

    def test_unapproved_and_unassigned_accounts_denied(self):
        request=self.activate()
        with self.assertRaises(ValueError):self.authority.accounts(request['device'])
        peer=self.approved('other')
        self.assertEqual(self.authority.accounts(peer),[])
        with self.assertRaises(ValueError):self.authority.acquire(peer,'alice')

    def test_reassignment_and_stale_session_fencing(self):
        first=self.approved();second=self.approved('second')
        self.account(first);self.authority.assign('alice',second)
        old=self.authority.acquire(first,'alice')['token']
        with self.assertRaisesRegex(ValueError,'active'):self.authority.acquire(second,'alice')
        self.authority.release('alice')
        new=self.authority.acquire(second,'alice')['token']
        with self.assertRaisesRegex(ValueError,'Stale'):self.authority.rules(first,'alice',old,[])
        self.assertTrue(self.authority.rules(second,'alice',new,[])['ok'])

    def test_concurrent_sessions_only_one_wins(self):
        first=self.approved();second=self.approved('second')
        self.account(first);self.authority.assign('alice',second)
        barrier=threading.Barrier(2)
        def attempt(peer):
            barrier.wait()
            try:return self.authority.acquire(peer,'alice')
            except ValueError:return None
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            results=list(pool.map(attempt,(first,second)))
        self.assertEqual(sum(r is not None for r in results),1)

    def test_unassign_preserves_active_session_and_denies_future_login(self):
        first=self.approved();second=self.approved('second');self.account(first)
        token=self.authority.acquire(first,'alice')['token']
        with self.assertRaisesRegex(ValueError,'active persistent session'):
            self.authority.unassign('alice',first)
        self.assertTrue(self.authority.rules(first,'alice',token,[])['ok'])
        self.authority.release('alice');self.authority.unassign('alice',first)
        self.assertEqual(self.authority.accounts(first),[])
        with self.assertRaisesRegex(ValueError,'not assigned'):self.authority.acquire(first,'alice')
        self.authority.assign('alice',second)
        self.assertTrue(self.authority.acquire(second,'alice')['token'])

    def test_policy_permissions_enforced_at_server(self):
        peer=self.approved();self.account(peer,'status')
        token=self.authority.acquire(peer,'alice')['token']
        with self.assertRaisesRegex(ValueError,'policy'):self.authority.rules(peer,'alice',token,[])
        self.account(peer,'none')
        with self.assertRaisesRegex(ValueError,'policy'):self.authority.rules(peer,'alice',token,[])

    def test_system_admin_is_independent_of_app_access_and_preserved_on_edit(self):
        peer=self.approved();self.account(peer,'edit')
        self.assertEqual(self.authority.accounts(peer)[0]['system_admin'],0)
        self.authority.account('alice',1000,1000,'$6$salt$hash','status',True)
        self.authority.account('alice',1000,1000,'$6$salt$hash','none')
        self.assertEqual(self.authority.accounts(peer)[0]['system_admin'],1)
        self.authority.account('alice',1000,1000,'$6$salt$hash','edit',False)
        self.assertEqual(self.authority.accounts(peer)[0]['system_admin'],0)

    def test_app_sources_require_approval(self):
        peer=self.approved();self.account(peer)
        token=self.authority.acquire(peer,'alice')['token']
        rules=[{'folder':'.local/share/httpboot/flatpak-bundles/org.example.App','mode':'app-only','source':'https://example.org'}]
        with self.assertRaisesRegex(ValueError,'source'):self.authority.rules(peer,'alice',token,rules)
        with self.authority.db() as db:
            db.execute("INSERT OR REPLACE INTO settings VALUES ('sources',?)",(json.dumps(['https://example.org']),))
        self.assertTrue(self.authority.rules(peer,'alice',token,rules)['ok'])

    def test_stable_ids_and_transactional_updates(self):
        peer=self.approved();self.account(peer)
        with self.assertRaisesRegex(ValueError,'stable'):
            self.authority.account('alice',1001,1001,'$6$salt$hash','edit')
        self.assertEqual(self.authority.accounts(peer)[0]['uid'],1000)

    def test_invalid_paths(self):
        for path in ('/etc/shadow','../bob','.','a/../b','a//b','a/',''):
            with self.subTest(path=path),self.assertRaises(ValueError):server_v2.folder_rule(path)
        self.assertEqual(server_v2.folder_rule('.config/app'),'.config/app')

    def test_authorization_precedes_route_dispatch(self):
        with self.assertRaisesRegex(ValueError,'configure your server'):
            self.authority('GET','/v2/health',None,'127.0.0.1',None)

    def test_deferred_driver_uploads_are_not_enabled_by_approval(self):
        peer=self.approved()
        with self.assertRaisesRegex(ValueError,'deferred'):
            self.authority('POST','/v2/drivers/begin',peer,'127.0.0.1',{})

    def test_shared_application_folders_require_a_process_for_close_detection(self):
        rule={'folder':'.config/example','mode':'closed-folder','source':None}
        with self.assertRaises(ValueError):server_v2.validate_rules([rule])
        rule['process']='example-app';self.assertEqual(server_v2.validate_rules([rule]),[rule])
        rule['process']='../another/app'
        with self.assertRaises(ValueError):server_v2.validate_rules([rule])

    def test_server_independently_enforces_printer_configuration_permission(self):
        peer=self.approved();self.account(peer,'status')
        token=self.authority.acquire(peer,'alice')['token']
        data={'name':'alice','token':token,'configuration':{'lpoptions':'Default fixture\n'}}
        with self.assertRaisesRegex(ValueError,'policy'):self.authority('POST','/v2/printers',peer,'127.0.0.1',data)
        self.authority.account('alice',1000,1000,'$6$salt$hash','edit')
        self.assertEqual(self.authority('POST','/v2/printers',peer,'127.0.0.1',data)['configuration'],data['configuration'])
        self.authority.release('alice')
        with self.assertRaisesRegex(ValueError,'Stale'):self.authority('POST','/v2/printers',peer,'127.0.0.1',data)


class RealCertificateTests(unittest.TestCase):
    def test_actual_csr_and_mutual_tls_activation(self):
        from common import atomic
        from control_transport import ca, key_request, issue, request, Server
        with tempfile.TemporaryDirectory() as temporary:
            base=Path(temporary);pki=base/'pki';credentials=base/'client'
            ca(pki,'127.0.0.1')
            csr=key_request(credentials,'request')
            authority=server_v2.Authority(base/'authority.db')
            self.assertRegex(server_v2.csr_key(csr),r'^[0-9a-f]{64}$')
            with self.assertRaises(ValueError):server_v2.csr_key('invalid')
            atomic(credentials/'ca.pem',(pki/'ca.pem').read_text())
            server=Server(('127.0.0.1',0),pki,authority)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            url='https://127.0.0.1:'+str(server.server_port)
            try:
                payload={'csr':csr,'hardware':{'model':'test-machine'}}
                response=request(url,'/v2/activation',payload,credentials)
                self.assertFalse(response['approved'])
                with self.assertRaises(ValueError):request(url,'/v2/accounts',credentials=credentials)
                peer=authority.approve(response['code'],lambda csr,name:issue(pki,csr,name))
                response=request(url,'/v2/activation',payload,credentials)
                atomic(credentials/'client.pem',response['certificate'])
                authority.account('alice',1000,1000,'$6$salt$hash','status');authority.assign('alice',peer)
                accounts=request(url,'/v2/accounts',credentials=credentials)
                self.assertEqual(accounts['accounts'][0]['name'],'alice')
            finally:
                server.shutdown();server.server_close();thread.join(3)

if __name__=='__main__':unittest.main()
