import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'httpboot'))
from server_v2 import Authority
from persistence_v2 import Saver,Watcher
from client_worker import closed
from snapshot_store import coherent_folders

class SaveIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.home=self.root/'home';self.home.mkdir()
        self.a=Authority(self.root/'server/authority.db')
        with self.a.db() as db:db.execute('INSERT INTO devices(id,approved) VALUES (?,1)',('fixture',))
        self.a.account('alice',1000,1000,'$6$fixture$hash','edit');self.a.assign('alice','fixture');self.token=self.a.acquire('fixture','alice')['token']
        self.rules=[{'folder':name,'mode':'folder','source':None} for name in ('.config/Codex','.local/share/keyrings')]
        self.a.rules('fixture','alice',self.token,self.rules)
        def call(route,value):return self.a.snapshots.dispatch(route,'fixture',{**value,'name':'alice','token':self.token})
        self.call=call;self.saver=Saver(self.home,self.root/'cache.db',call)
    def save_pair(self,value):
        ids={}
        for rule in self.rules:
            directory=self.home/rule['folder'];directory.mkdir(parents=True,exist_ok=True)
            (directory/'fixture').write_text(value)
            ids[rule['folder']]=self.saver.save(rule)['id']
        return self.call('checkpoint',{'snapshots':ids,'apps_closed':True})['id'],ids
    def test_interrupted_save_restores_previous_matching_profile_and_keyring(self):
        checkpoint,ids=self.save_pair('old synthetic auth pair')
        (self.home/'.config/Codex/fixture').write_text('new synthetic auth half')
        self.saver.save(self.rules[0])
        selected=self.call('restore-set',{})
        self.assertEqual(selected['checkpoint'],checkpoint);self.assertEqual(selected['snapshots'],ids)
        for rule in self.rules:
            self.saver.restore(rule,selected['snapshots'][rule['folder']])
            self.assertEqual((self.home/rule['folder']/'fixture').read_text(),'old synthetic auth pair')
        new,_=self.save_pair('new coherent pair');self.assertNotEqual(checkpoint,new)
    def test_checkpoint_protects_snapshots_beyond_ordinary_retention(self):
        checkpoint,ids=self.save_pair('protected')
        for n in range(8):
            (self.home/'.config/Codex/fixture').write_text('partial-'+str(n));self.saver.save(self.rules[0])
        self.assertEqual(self.call('restore-set',{})['checkpoint'],checkpoint)
        for folder,identifier in ids.items():self.assertIsNotNone(self.call('latest',{'folder':folder,'snapshot':identifier})['snapshot'])
    def test_incomplete_or_unclosed_sets_are_not_published(self):
        previous,ids=self.save_pair('old')
        for value in ({'snapshots':ids,'apps_closed':False},{'snapshots':{},'apps_closed':True},{'snapshots':{**ids,'.ssh':'other'},'apps_closed':True}):
            with self.assertRaises(ValueError):self.call('checkpoint',value)
        self.assertEqual(self.call('restore-set',{})['checkpoint'],previous)
    def test_checkpoint_cannot_reference_another_owner(self):
        _,ids=self.save_pair('private')
        self.a.account('bob',1001,1001,'$6$fixture$hash','edit');self.a.assign('bob','fixture')
        token=self.a.acquire('fixture','bob')['token'];self.a.rules('fixture','bob',token,self.rules)
        with self.assertRaises(ValueError):self.a.snapshots.dispatch('checkpoint','fixture',{'name':'bob','token':token,'snapshots':ids,'apps_closed':True})
    def test_unrelated_apps_do_not_block_chatgpt(self):
        proc=self.root/'12345';proc.mkdir()
        with patch('client_worker.owned_processes',return_value=[(proc,'/opt/google/chrome/chrome'),(proc,'/usr/lib/chatgpt/resources/codex')]),patch('client_worker.Path.home',return_value=self.home):
            self.assertTrue(closed({'folder':'.config/ChatGPT','mode':'folder'}))
            self.assertTrue(closed({'folder':'.config/Codex','mode':'folder'}))
        with patch('client_worker.owned_processes',return_value=[(proc,'/usr/lib/chatgpt/ChatGPT')]),patch('client_worker.Path.home',return_value=self.home):
            self.assertFalse(closed({'folder':'.config/Codex','mode':'folder'}))
    def test_open_profile_descriptor_blocks_a_renamed_writer(self):
        folder=self.home/'.config/Codex';folder.mkdir(parents=True)
        proc=self.root/'12345';(proc/'fd').mkdir(parents=True);(proc/'fd/1').symlink_to(folder/'database')
        with patch('client_worker.owned_processes',return_value=[(proc,'/usr/bin/custom-writer')]),patch('client_worker.Path.home',return_value=self.home):
            self.assertFalse(closed({'folder':'.config/Codex','mode':'folder'}))
    def test_watcher_reports_only_the_changed_selected_root(self):
        first=self.home/'Documents';second=self.home/'.config/Codex';first.mkdir();second.mkdir(parents=True)
        watcher=Watcher([first,second]);self.addCleanup(watcher.close)
        (second/'active-db').write_text('app is noisy')
        self.assertEqual(watcher.changed_roots(.5),{second})
        (first/'document').write_text('document change')
        self.assertEqual(watcher.changed_roots(.5),{first})
    def test_project_name_does_not_turn_it_into_app_database_rule(self):
        self.assertFalse(coherent_folders([{'folder':'workspace/codex-project','mode':'folder'}]))

class SaveQueueTests(unittest.TestCase):
    def test_noisy_app_does_not_starve_document_quiet_period(self):
        import client_worker
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as temporary:
            home=Path(temporary);rules=[{'folder':f,'mode':'folder','source':None} for f in ('Documents','.codex')]
            state={'session_ready':True,'rules':rules,'sources':[]};clock=[0.0];saved=[];closed=[]
            class FakeWatcher:
                def __init__(self,*_):pass
                def changed_roots(self,_):
                    clock[0]+=.5
                    if clock[0]>=4:client_worker.STOP=True
                    return {home/'.codex'}
                def close(self):closed.append(True)
            class FakeSaver:
                def __init__(self,*_):pass
                def save(self,rule,*_):saved.append(rule['folder']);return {'id':'fixture'}
            with patch.object(client_worker,'STOP',False),patch.object(client_worker,'Watcher',FakeWatcher),patch.object(client_worker,'Saver',FakeSaver),patch.object(client_worker,'rpc',side_effect=lambda action,**_:state if action=='state' else {'ok':True}),patch.object(client_worker.Path,'home',return_value=home),patch.object(client_worker.time,'monotonic',side_effect=lambda:clock[0]),patch.object(client_worker.subprocess,'run'),patch.dict(sys.modules,{'desktop_state':SimpleNamespace(restore=lambda:None),'terminal_preferences':SimpleNamespace(apply=lambda:None)}),patch.object(sys,'argv',['client_worker','daemon']):
                client_worker.main()
            self.assertEqual(saved,['Documents']);self.assertTrue(closed)
    def test_manual_save_keeps_saving_documents_after_an_open_app(self):
        import client_worker
        rules=[{'folder':f,'mode':'folder','source':None} for f in ('.config/Codex','Documents')];saved=[];statuses=[]
        class FakeSaver:
            def __init__(self,*_):pass
            def save(self,rule,*_):
                if rule['folder']=='.config/Codex':raise ValueError('Waiting for app close')
                saved.append(rule['folder']);return {'id':'document'}
        def rpc(action,**value):
            if action=='state':return {'rules':rules,'sources':[]}
            if action=='status':statuses.append(value['value'])
            return {'ok':True}
        with patch.object(client_worker,'Saver',FakeSaver),patch.object(client_worker,'rpc',side_effect=rpc),patch.object(sys,'argv',['client_worker','save']):
            with self.assertRaisesRegex(ValueError,'1 selected folders'):client_worker.main()
        self.assertEqual(saved,['Documents']);self.assertEqual(statuses[0]['folder'],'.config/Codex')

if __name__=='__main__':unittest.main()
