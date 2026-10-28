import base64
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'httpboot'))
from server_v2 import Authority
from boot_identity import choose,firmware_partition,verify_writable
from boot_reports import sanitize,collect,store,health
from driver_store import Imports
from common import sha256


class RepairTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.authority=Authority(self.root/'authority.sqlite3')
    def test_boot_volume_selection_never_silently_chooses_first(self):
        rows=[{'device':'one','partuuid':'a'},{'device':'two','partuuid':'b'}]
        self.assertEqual(choose(rows,'b')['device'],'two')
        with self.assertRaisesRegex(ValueError,'Multiple'):choose(rows)
        with self.assertRaisesRegex(ValueError,'No persistent'):choose([])
    def test_efi_partition_variable_decodes_attributes_and_utf16(self):
        value='12345678-1234-1234-1234-123456789abc'
        (self.root/'LoaderDevicePartUUID-fixture').write_bytes(b'\7\0\0\0'+(value+'\0').encode('utf-16-le'))
        self.assertEqual(firmware_partition(self.root),value)
    def test_missing_key_is_not_regenerated(self):
        identity=self.root/'identity';identity.mkdir();(identity/'client.pem').write_text('fixture')
        with self.assertRaisesRegex(ValueError,'key is missing'):verify_writable(identity)
        self.assertFalse((identity/'client.key').exists())
    def test_approval_and_assignments_are_atomic(self):
        with patch('server_v2.csr_key',return_value='fixture'):
            pending=self.authority.activation({'csr':'fixture','hardware':{'model':'fixture'}},'fixture')
        self.authority.account('alice',1000,1000,'$6$salt$fixture','edit')
        with self.assertRaisesRegex(ValueError,'Unknown selected'):self.authority.approve(pending['code'],lambda *_:'cert',['missing'])
        with self.authority.db() as db:self.assertEqual(db.execute('SELECT approved FROM devices').fetchone()[0],0)
        peer=self.authority.approve(pending['code'],lambda *_:'cert',['alice'])
        self.assertEqual(self.authority.accounts(peer)[0]['name'],'alice')
    def test_reports_preserve_schema_one_and_exclude_secrets(self):
        old={'schema':1,'stage':'fixture','line':0,'exit_status':1}
        self.assertEqual(sanitize(old),old)
        for secret in ('password=x','SSID=private','/home/alice/document'):
            with self.assertRaises(ValueError):sanitize({**old,'schema':2,'details':{'driver_errors':secret}})
        self.assertEqual(sanitize({**old,'schema':2,'details':{'hardware':'10ec:b852 driver=rtw89_8852be'}})['schema'],2)
    def test_heartbeat_refreshes_server_contact_without_duplicate_report(self):
        peer='fixture'
        with self.authority.db() as db:db.execute('INSERT INTO devices(id,approved) VALUES (?,1)',(peer,))
        folder=self.root/'reports'/peer;data={'schema':1,'stage':'fixture','line':0,'exit_status':0}
        store(folder,data);file=next(folder.glob('*.json'))
        import os
        os.utime(file,(1,1));self.assertTrue(health(self.authority)[0]['stale'])
        store(folder,data);self.assertFalse(health(self.authority)[0]['stale']);self.assertEqual(len(list(folder.glob('*.json'))),1)
    def test_provision_recovers_group_created_before_interruption(self):
        from client_agent import Agent
        from types import SimpleNamespace
        agent=Agent({'identity':str(self.root/'identity'),'server':'https://example.invalid'},self.root/'run')
        account={'name':'fixture','uid':12345,'gid':12345,'password_hash':'$6$salt$fixture','system_admin':False,'access':'status','rules':'[]'}
        def call(path,*args):
            return {'/v2/accounts':{'accounts':[account]},'/v2/policy':{'sources':[]},'/v2/printers':{'configuration':{}}}[path]
        agent.call=call
        def group(name):
            if name=='sudo':return SimpleNamespace(gr_mem=[])
            return SimpleNamespace(gr_name='fixture')
        with patch('client_agent.subprocess.run',return_value=SimpleNamespace(stdout='overlay')) as run, patch('client_agent.pwd.getpwnam',side_effect=KeyError), patch('client_agent.pwd.getpwuid',side_effect=KeyError), patch('client_agent.grp.getgrgid',return_value=SimpleNamespace(gr_name='fixture')), patch('client_agent.grp.getgrnam',side_effect=group), patch('client_agent.os.chown'), patch('printers.install_configuration'), patch('client_agent.ACCOUNT_SERVICE_USERS',self.root/'AccountsService'):
            agent.provision()
        commands=[item.args[0][0] for item in run.call_args_list]
        self.assertNotIn('groupadd',commands)
        self.assertIn('useradd',commands)
        self.assertIn('chpasswd',commands)
        self.assertNotIn('password_hash',agent.accounts['12345'])

    def test_account_and_certificate_reads_do_not_wait_for_snapshot_writer(self):
        import threading,hashlib
        peer='fixture';der=b'fixture-certificate';fingerprint='fixture-key'
        self.authority.account('alice',1000,1000,'$6$salt$fixture','edit')
        with self.authority.db() as db:db.execute('INSERT INTO devices(id,fingerprint,approved) VALUES (?,?,1)',(peer,fingerprint))
        self.authority.assign('alice',peer)
        self.authority.certificate_cache[hashlib.sha256(der).hexdigest()]=fingerprint
        done=threading.Event();values=[];errors=[]
        def reader():
            try:
                self.authority.verify_certificate(peer,der)
                values.extend(self.authority.accounts(peer))
                self.authority('GET','/v2/health',peer,'fixture',None)
            except Exception as error:errors.append(error)
            finally:done.set()
        with self.authority.db() as db:
            db.execute("UPDATE accounts SET access='none' WHERE name='alice'")
            thread=threading.Thread(target=reader,daemon=True);thread.start()
            completed=done.wait(2)
        thread.join(3)
        self.assertTrue(completed,'Account authentication waited for an unrelated writer')
        self.assertFalse(errors)
        self.assertEqual(values[0]['access'],'edit')
        self.assertEqual(self.authority.accounts(peer)[0]['access'],'none')

    def test_read_transaction_rejects_accidental_mutation(self):
        import sqlite3
        with self.authority.db(write=False) as db:
            with self.assertRaises(sqlite3.OperationalError):db.execute("INSERT INTO settings VALUES ('fixture','value')")

    def test_driver_resume_integrity_ownership_and_explicit_approval(self):
        imports=Imports(self.authority)
        for peer in ('first','other'):
            with self.authority.db() as db:db.execute('INSERT INTO devices(id,approved) VALUES (?,1)',(peer,))
        file=self.root/'fixture.fw';file.write_bytes(b'firmware')
        metadata={'filename':file.name,'sha256':sha256(file),'size':8,'kernel':'fixture-kernel','hardware_ids':['pci:fixture'],'provenance':'fixture USB'}
        job=imports.dispatch('first','begin',metadata)
        chunk={'id':job['id'],'offset':0,'content':base64.b64encode(b'firm').decode()}
        imports.dispatch('first','chunk',chunk);imports.dispatch('first','chunk',chunk)
        self.assertEqual(imports.dispatch('first','begin',metadata)['offset'],4)
        with self.assertRaisesRegex(ValueError,'another Client'):imports.dispatch('other','status',{'id':job['id']})
        with self.assertRaisesRegex(ValueError,'integrity'):imports.dispatch('first','finish',{'id':job['id']})
        imports.dispatch('first','chunk',{'id':job['id'],'offset':4,'content':base64.b64encode(b'ware').decode()})
        self.assertEqual(imports.dispatch('first','finish',{'id':job['id']})['state'],'pending')
        self.assertFalse((self.root/'approved-drivers').exists())
        self.assertEqual(imports.review(job['id'],True)['state'],'approved')
        self.assertEqual((self.root/'approved-drivers'/metadata['sha256']/'payload').read_bytes(),b'firmware')

if __name__=='__main__':unittest.main()
