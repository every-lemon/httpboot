import base64,hashlib,json,os,sys,tempfile,threading,time,unittest,runpy,contextlib,io
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'httpboot'))
from server_v2 import Authority
from persistence_v2 import Saver
from snapshot_store import CHUNK_SIZE
from restore_progress import RestoreProgress,message
import client_worker

class RestoreTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.home=self.root/'home';self.home.mkdir();self.a=Authority(self.root/'authority.db');self.peer='client-fixture'
        with self.a.db() as db:db.execute('INSERT INTO devices(id,approved) VALUES (?,1)',(self.peer,))
        self.a.account('alice',1000,1000,'$6$salt$hash','edit');self.a.assign('alice',self.peer);self.a.ssh_policy(None,False)
        self.session={'name':'alice',**self.a.acquire(self.peer,'alice')}
        self.rules=[{'folder':f,'mode':'folder','source':None} for f in ('Documents','workspace')]
        self.a.rules(self.peer,'alice',self.session['token'],self.rules);self.events=[]
        self.call=lambda route,value:self.a.snapshots.dispatch(route,self.peer,{**value,**self.session})
        self.saver=Saver(self.home,self.root/'cache.db',self.call,lambda **row:self.events.append(row))
    def seed(self,rule,data):
        folder=self.home/rule['folder'];folder.mkdir(exist_ok=True);(folder/'file').write_bytes(data);self.saver.save(rule)

    def test_worker_prepares_all_totals_once_before_copying(self):
        self.seed(self.rules[0],b'a'*10);self.seed(self.rules[1],b'b'*30)
        for rule in self.rules:(self.home/rule['folder']/'file').unlink()
        self.events.clear();reads=[]
        def rpc(action,**value):
            if action=='state':return {'rules':self.rules,'supports_checkpoints':True}
            if action=='status':self.events.append(value['value']);return {'ok':True}
            if action=='snapshot':
                if value['route']=='get':reads.append(len([r for r in self.events if r.get('stage')=='preparing']))
                return self.call(value['route'],value['value'])
            raise AssertionError(action)
        real=Saver
        with patch.object(client_worker,'rpc',side_effect=rpc),patch.object(client_worker.Path,'home',return_value=self.home),patch.object(client_worker,'Saver',side_effect=lambda home,cache,call,status:real(home,self.root/'worker.db',call,status)),patch.object(sys,'argv',['worker','restore']):client_worker.main()
        general=[r for r in self.events if r.get('folder')=='general'];copy=[r for r in general if 'bytes_total' in r]
        self.assertTrue(reads and all(n>=3 for n in reads));self.assertEqual({r['bytes_total'] for r in copy},{40})
        self.assertEqual([r['bytes_done'] for r in copy],sorted(r['bytes_done'] for r in copy))
        self.assertEqual(copy[-1]['bytes_done'],40);self.assertEqual(copy[-1]['phase'],'restored')
        self.assertEqual((self.home/'workspace/file').read_bytes(),b'b'*30)

    def test_progress_arrives_while_one_large_file_is_still_copying(self):
        rule=self.rules[0];self.seed(rule,b'a'*CHUNK_SIZE+b'b'*CHUNK_SIZE+b'c'*CHUNK_SIZE)
        (self.home/'Documents/file').unlink();self.events.clear();release=threading.Event();progress=threading.Event();calls=[0];errors=[]
        def call(route,value):
            if route=='get':
                calls[0]+=1
                if calls[0]==2:release.wait(4)
            return self.call(route,value)
        def status(**row):
            self.events.append(row)
            if 0<row.get('bytes_done',0)<row.get('bytes_total',0):progress.set()
        self.saver.call=call;self.saver.status=status
        def restore():
            try:self.saver.restore(rule)
            except BaseException as e:errors.append(e)
        thread=threading.Thread(target=restore);thread.start()
        try:self.assertTrue(progress.wait(3),'Large-file restore did not report intermediate bytes');self.assertTrue(thread.is_alive())
        finally:release.set();thread.join(6)
        self.assertFalse(errors);self.assertFalse(thread.is_alive());self.assertEqual(self.events[-1]['bytes_done'],3*CHUNK_SIZE)

    def test_old_server_fallback_and_changed_summary_are_safe(self):
        rule=self.rules[0];self.seed(rule,b'previous');original=self.call
        def legacy(route,value):
            result=original(route,value)
            if route=='latest' and result['snapshot']:
                for key in ('bytes_total','files_total'):result['snapshot'].pop(key)
            return result
        self.saver.call=legacy;plan=self.saver.prepare_restore(rule);self.assertEqual(plan['bytes_total'],8)
        with self.assertRaisesRegex(ValueError,'prepared total'):self.saver.restore(rule,plan={**plan,'bytes_total':9})
        self.assertEqual((self.home/'Documents/file').read_bytes(),b'previous')

    def test_invalid_pagination_is_bounded(self):
        self.saver.call=lambda route,value:{'files':{},'next':0}
        with self.assertRaisesRegex(ValueError,'did not advance'):self.saver.restore_manifest('Documents','fixture')

    def test_summary_uses_appropriate_units_and_never_claims_unknown_total(self):
        self.assertNotIn('MiB',message({'stage':'preparing','folders_total':2,'folders_done':1}))
        self.assertIn('2.0 / 4.0 KiB',message({'bytes_done':2048,'bytes_total':4096}))
        self.assertIn('Finishing',message({'bytes_done':10,'bytes_total':10,'folders_total':2,'folders_done':1}))
        self.assertIn('Finishing',message({'bytes_done':float('nan'),'bytes_total':0}))

    def test_failed_progress_poll_does_not_cancel_a_valid_login_restore(self):
        import client_agent
        finish=threading.Event();calls=[]
        def rpc(action,**values):
            calls.append((action,values))
            if action=='open-login':finish.wait(4);return {'ok':True}
            if action=='login-progress':finish.set();raise TimeoutError('Status temporarily unavailable')
            raise AssertionError(action)
        output=io.StringIO()
        with patch.object(client_agent,'rpc',side_effect=rpc),patch.dict(os.environ,{'PAM_TYPE':'open_session','PAM_SERVICE':'login','PAM_USER':'alice'}),patch.object(sys,'argv',['pam-session-v2','--progress']),contextlib.redirect_stdout(output):
            runpy.run_path(str(Path(__file__).resolve().parents[1]/'client/pam-session-v2'))
        self.assertIn('verified; starting',output.getvalue());self.assertNotIn('ERROR',output.getvalue())
        self.assertEqual(len([r for r in calls if r[0]=='open-login']),1)
        self.assertEqual(next(v['timeout'] for a,v in calls if a=='login-progress'),2)

if __name__=='__main__':unittest.main()
