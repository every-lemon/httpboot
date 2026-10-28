import json
import os
import runpy
import socket
import stat
import unittest
from pathlib import Path
from unittest.mock import patch
from test_v2_storage import StorageTests


class SSHTests(StorageTests):
    def test_defaults_overrides_and_existing_accounts(self):
        account=lambda:self.authority.accounts(self.peer)[0]
        self.assertTrue(account()['persist_ssh'])
        self.assertIn('.ssh',[r['folder'] for r in json.loads(account()['rules'])])
        self.authority.ssh_policy(None,False)
        self.assertFalse(account()['persist_ssh'])
        self.authority.ssh_policy('alice',True)
        self.assertTrue(account()['persist_ssh'])
        self.authority.ssh_policy('alice',None)
        self.assertFalse(account()['persist_ssh'])
        self.authority.ssh_policy(None,True)
        self.assertTrue(account()['persist_ssh'])
        with self.authority.db(write=False) as db:
            self.assertEqual(json.loads(db.execute('SELECT rules FROM accounts').fetchone()[0]),[self.rule])

    def test_private_key_roundtrip_skips_socket_and_disable_retains_snapshot(self):
        rule={'folder':'.ssh','mode':'folder','source':None}
        folder=self.home/'.ssh';folder.mkdir(mode=0o700)
        key=folder/'id_fixture';key.write_bytes(b'synthetic test key, not a credential');key.chmod(0o600)
        sock=socket.socket(socket.AF_UNIX);self.addCleanup(sock.close);sock.bind(str(folder/'agent.sock'))
        saved=self.saver.save(rule)
        key.unlink();self.saver.restore(rule)
        self.assertEqual(key.read_bytes(),b'synthetic test key, not a credential')
        self.assertEqual(stat.S_IMODE(key.stat().st_mode),0o600)
        self.authority.ssh_policy('alice',False)
        with self.assertRaises(ValueError):self.saver.restore(rule)
        with self.assertRaises(ValueError):self.saver.save(rule)
        with self.assertRaisesRegex(ValueError,'disabled'):
            self.authority.rules(self.peer,'alice',self.session['token'],[rule])
        self.authority.ssh_policy('alice',True)
        self.assertEqual(self.call('latest',{'folder':'.ssh'})['snapshot']['id'],saved['id'])

    def test_pam_message_cadence_does_not_outpace_gnome(self):
        with patch.dict(os.environ,{'PAM_TYPE':'','PAM_SERVICE':''}):
            module=runpy.run_path(str(Path(__file__).resolve().parents[1]/'client/pam-session-v2'))
        for message in ('Preparing saved data…','100/200 MiB restored, 5 MiB/s, ~20s left'):
            self.assertGreater(module['message_interval'](message,True),len(message)*0.048)
        self.assertEqual(module['message_interval']('console',False),1)

if __name__=='__main__':unittest.main()
