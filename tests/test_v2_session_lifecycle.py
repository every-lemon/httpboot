import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import threading
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'httpboot'))
from server_v2 import Authority
from client_power import Power
from build_public import finalize_runtime_resolver

BOOT1='11111111-1111-1111-1111-111111111111'
BOOT2='22222222-2222-2222-2222-222222222222'

class LeaseTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.now=1000;self.a=Authority(self.root/'authority.sqlite3',lambda:self.now)
        with self.a.db() as db:
            for peer in ('one','two'):db.execute('INSERT INTO devices(id,approved) VALUES (?,1)',(peer,))
        self.a.account('alice',1000,1000,'$6$fixture$hash','edit')
        for peer in ('one','two'):self.a.assign('alice',peer)
    def acquire(self,peer='one',boot=BOOT1):return self.a.acquire(peer,'alice',boot)['token']
    def heartbeat(self,token,boot=BOOT1,peer='one'):
        return self.a.leases.heartbeat(peer,{'boot_id':boot,'sessions':[{'name':'alice','token':token}]})
    def test_offline_grace_and_fencing_after_takeover(self):
        old=self.acquire();self.now+=899
        with self.assertRaises(ValueError):self.acquire('two',BOOT2)
        self.now+=1;new=self.acquire('two',BOOT2)
        self.assertNotEqual(old,new)
        with self.assertRaises(ValueError):self.a.rules('one','alice',old,[])
        self.assertFalse(self.heartbeat(old)['sessions'][0]['active'])
        self.assertTrue(self.heartbeat(new,BOOT2,'two')['sessions'][0]['active'])
    def test_heartbeat_keeps_idle_user_online_and_wrong_boot_cannot_extend(self):
        token=self.acquire()
        for _ in range(4):self.now+=600;self.assertTrue(self.heartbeat(token)['sessions'][0]['active'])
        self.now+=800;self.assertFalse(self.heartbeat(token,BOOT2)['sessions'][0]['active'])
        self.now+=100
        with self.a.db(write=False) as db:
            with self.assertRaisesRegex(ValueError,'expired'):self.a.session(db,'one','alice',token)
    def test_late_heartbeat_cannot_revive_even_without_takeover(self):
        token=self.acquire();self.now+=900
        self.assertFalse(self.heartbeat(token)['sessions'][0]['active'])
        self.assertNotEqual(token,self.acquire())
    def test_clean_release_is_immediate_idempotent_and_cannot_release_new_owner(self):
        token=self.acquire();entry={'name':'alice','token':token}
        self.a.leases.release_many('one',[entry]);self.a.leases.release_many('one',[entry])
        new=self.acquire('two',BOOT2)
        with self.assertRaises(ValueError):self.a.leases.release_many('one',[entry])
        self.assertTrue(self.heartbeat(new,BOOT2,'two')['sessions'][0]['active'])
    def test_legacy_reports_keep_current_boot_but_not_rebooted_lock_alive(self):
        self.a.leases.observe_legacy('one',BOOT1)
        token=self.a.acquire('one','alice')['token']
        self.now+=600;self.a.leases.observe_legacy('one',BOOT1)
        self.now+=800;self.a.leases.observe_legacy('one',BOOT2)
        with self.assertRaises(ValueError):self.acquire()
        self.now+=100
        self.assertNotEqual(token,self.acquire())
    def test_server_restart_does_not_reset_offline_timer(self):
        token=self.acquire();self.now+=800
        self.a=Authority(self.root/'authority.sqlite3',lambda:self.now);self.now+=100
        with self.a.db(write=False) as db:
            with self.assertRaisesRegex(ValueError,'expired'):self.a.session(db,'one','alice',token)
    def test_batch_release_is_atomic_if_one_token_is_wrong(self):
        token=self.acquire()
        self.a.account('bob',1001,1001,'$6$fixture$hash','edit');self.a.assign('bob','one')
        self.a.acquire('one','bob',BOOT1)
        with self.assertRaises(ValueError):self.a.leases.release_many('one',[{'name':'alice','token':token},{'name':'bob','token':'wrong'}])
        self.assertTrue(self.heartbeat(token)['sessions'][0]['active'])
    def test_anonymous_and_unassigned_heartbeats_cannot_extend(self):
        token=self.acquire()
        with self.assertRaises(ValueError):self.heartbeat(token,peer='unknown')
        self.assertFalse(self.heartbeat(token,peer='two')['sessions'][0]['active'])
        self.now+=900
        with self.a.db(write=False) as db:
            with self.assertRaises(ValueError):self.a.session(db,'one','alice',token)

class PowerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);root=Path(self.temp.name);self.calls=[]
        self.agent=SimpleNamespace(run=root,journal=root/'sessions.json',lock=threading.RLock(),sessions={'1000':{'name':'alice','token':'old','ready':True}},
            saving_paused=False,boot_id=BOOT1,queue_report=lambda *_:None,updates=SimpleNamespace(lock=threading.Lock(),snapshot=lambda:{}))
        self.agent.worker=lambda uid,action:self.calls.append(('worker',uid,action))
        def call(route,value):
            self.calls.append((route,value));return {'token':'rejoined'} if route=='/v2/sessions' else {'ok':True}
        self.agent.call=call;self.power=Power(self.agent)
    def wait(self):
        deadline=time.monotonic()+3
        while self.power.lock.locked() and time.monotonic()<deadline:time.sleep(.01)
        self.assertFalse(self.power.lock.locked())
    def test_success_saves_then_releases_before_system_power_command(self):
        def system(command,**kw):
            self.assertFalse(self.agent.sessions)
            self.assertEqual(self.calls[0],('worker','1000','save'))
            self.assertEqual(self.calls[1][0],'/v2/sessions/release-all')
            self.assertTrue((self.agent.run/'power-approved').exists())
            self.assertEqual(command[-3:],['RebootWithFlags','t','1'])
            self.assertNotIn('--force',command)
            self.calls.append(('power',command))
        with patch('client_power.subprocess.run',side_effect=system):self.power.start('reboot');self.wait()
        self.assertEqual(self.power.snapshot()['state'],'completed')
        self.assertFalse(self.agent.saving_paused)
    def test_failed_save_never_releases_or_powers_off(self):
        self.agent.worker=lambda *_:(_ for _ in ()).throw(ValueError('application is open'))
        with patch('client_power.subprocess.run') as system:self.power.start('poweroff');self.wait();system.assert_not_called()
        self.assertEqual(self.agent.sessions['1000']['token'],'old');self.assertFalse(self.calls)
        self.assertEqual(self.power.snapshot()['state'],'failed')
    def test_second_user_failed_save_keeps_both_leases(self):
        self.agent.sessions['1001']={'name':'bob','token':'second','ready':True}
        def save(uid,_):
            if uid=='1001':raise ValueError('pending data')
        self.agent.worker=save
        with patch('client_power.subprocess.run') as system:self.power.start('poweroff');self.wait();system.assert_not_called()
        self.assertEqual(len(self.agent.sessions),2);self.assertFalse(self.calls)
    def test_interrupted_release_keeps_ram_journal_and_does_not_power_off(self):
        self.agent.call=lambda *_:(_ for _ in ()).throw(OSError('offline'))
        with patch('client_power.subprocess.run') as system:self.power.start('poweroff');self.wait();system.assert_not_called()
        self.assertIn('1000',self.agent.sessions)
    def test_denied_power_rejoins_without_restoring_over_ram_work(self):
        with patch('client_power.subprocess.run',side_effect=OSError('inhibitor')):self.power.start('reboot');self.wait()
        self.assertEqual(self.agent.sessions['1000']['token'],'rejoined')
        self.assertEqual([x for x in self.calls if x[0]=='worker'],[('worker','1000','save')])
        self.assertFalse((self.agent.run/'power-approved').exists())
    def test_os_rejection_reports_its_reason_and_retains_ram_session(self):
        import subprocess
        error=subprocess.CalledProcessError(1,['systemctl','poweroff'],stderr='Operation inhibited by a pending system task.\n')
        with patch('client_power.subprocess.run',side_effect=error):self.power.start('poweroff');self.wait()
        self.assertIn('Operation inhibited by a pending system task',self.power.snapshot()['message'])
        self.assertEqual(self.agent.sessions['1000']['token'],'rejoined')
        self.assertEqual([x for x in self.calls if x[0]=='worker'],[('worker','1000','save')])
    def test_update_and_power_operations_cannot_overlap(self):
        self.agent.updates.lock.acquire()
        with self.assertRaises(ValueError):self.power.start('poweroff')
        self.agent.updates.lock.release()
    def test_approved_shutdown_cleanup_does_not_repeat_saves_or_wait_for_power_thread(self):
        (self.agent.run/'power-approved').touch()
        self.power.lock.acquire()
        try:self.assertEqual(self.power.cleanup(),{'ok':True})
        finally:self.power.lock.release()
        self.assertFalse(self.calls)
    def test_dns_finalization_removes_builder_config(self):
        root=self.agent.run/'root';(root/'etc').mkdir(parents=True)
        (root/'etc/resolv.conf').write_text('nameserver 10.0.2.3\n')
        finalize_runtime_resolver(root)
        self.assertTrue((root/'etc/resolv.conf').is_symlink())
        self.assertEqual(__import__('os').readlink(root/'etc/resolv.conf'),'/run/systemd/resolve/stub-resolv.conf')

class DNSQualificationTests(unittest.TestCase):
    def test_memory_constrained_stage_budget_is_explicit_and_bounded(self):
        from validate_v2 import stage_budget
        with patch.dict('os.environ',{},clear=True):self.assertEqual(stage_budget(),180)
        with patch.dict('os.environ',{'HTTPBOOT_QUALIFY_STAGE_SECONDS':'600'}):self.assertEqual(stage_budget(),600)
    def test_invalid_qualification_stage_budget_is_rejected(self):
        from validate_v2 import stage_budget
        for value in ('179','601','-1','unlimited'):
            with patch.dict('os.environ',{'HTTPBOOT_QUALIFY_STAGE_SECONDS':value}):
                with self.assertRaises(ValueError):stage_budget()
    def test_qualified_image_requires_runtime_link_not_builder_dns_file(self):
        from validate_v2 import verify_runtime_dns
        good='lrwxrwxrwx root/root 40 2026-01-01 00:00 squashfs-root/etc/resolv.conf -> /run/systemd/resolve/stub-resolv.conf\n'
        with patch('validate_v2.subprocess.run',return_value=SimpleNamespace(stdout=good)):verify_runtime_dns(Path('/fixture'))
        for bad in ('-rw-r--r-- root/root 25 2026-01-01 00:00 squashfs-root/etc/resolv.conf\n',good.replace('stub-resolv.conf','builder-resolv.conf')):
            with patch('validate_v2.subprocess.run',return_value=SimpleNamespace(stdout=bad)):
                with self.assertRaisesRegex(ValueError,'build-time'):verify_runtime_dns(Path('/fixture'))
    def test_service_restart_does_not_run_shutdown_cleanup(self):
        from client_power import main
        with patch('client_power.subprocess.run',return_value=SimpleNamespace(stdout='running\n')),patch('client_agent.rpc') as rpc:
            main();rpc.assert_not_called()
        with patch('client_power.subprocess.run',return_value=SimpleNamespace(stdout='stopping\n')),patch('client_agent.rpc') as rpc:
            main();rpc.assert_called_once_with('shutdown-cleanup')

if __name__=='__main__':unittest.main()
