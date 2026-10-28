import base64
import contextlib
import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'httpboot'))
from server_v2 import Authority
from persistence_v2 import Home,Saver,Watcher
from snapshot_store import CHUNK_SIZE,manifest

class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.home=self.root/'home';self.home.mkdir()
        self.authority=Authority(self.root/'server/authority.db')
        self.peer='client-fixture'
        with self.authority.db() as db:
            db.execute('INSERT INTO devices(id,approved) VALUES (?,1)',(self.peer,))
        self.authority.account('alice',1000,1000,'$6$salt$hash','edit')
        self.authority.assign('alice',self.peer)
        self.session={'name':'alice',**self.authority.acquire(self.peer,'alice')}
        self.rule={'folder':'Documents','mode':'folder','source':None}
        self.authority.rules(self.peer,'alice',self.session['token'],[self.rule])
        self.calls=[]
        def call(route,value):
            self.calls.append(route)
            return self.authority.snapshots.dispatch(route,self.peer,{**value,**self.session})
        self.call=call
        self.saver=Saver(self.home,self.root/'cache.db',call)

    def write(self,value,path='file'):
        folder=self.home/'Documents';folder.mkdir(exist_ok=True)
        (folder/path).write_bytes(value)

    def test_roundtrip_changed_chunks_and_unchanged_hash_cache(self):
        self.write(b'a'*CHUNK_SIZE+b'b'*CHUNK_SIZE)
        first=self.saver.save(self.rule)
        self.assertEqual(self.calls.count('put'),2)
        self.calls.clear()
        with patch.object(self.saver.home,'file',side_effect=AssertionError('Unchanged file reopened')):
            self.assertTrue(self.saver.save(self.rule)['unchanged'])
        self.assertEqual(self.calls.count('put'),0)
        self.write(b'a'*CHUNK_SIZE+b'c'*CHUNK_SIZE)
        self.calls.clear();second=self.saver.save(self.rule)
        self.assertEqual(self.calls.count('put'),1)
        self.assertNotEqual(first['id'],second['id'])
        (self.home/'Documents/file').unlink()
        self.saver.restore(self.rule)
        self.assertEqual((self.home/'Documents/file').read_bytes(),b'a'*CHUNK_SIZE+b'c'*CHUNK_SIZE)

    def test_failed_commit_retains_previous(self):
        self.write(b'previous');first=self.saver.save(self.rule)
        self.write(b'next')
        original=self.saver.call
        def fail(route,data):
            if route=='commit':raise OSError('network interrupted')
            return original(route,data)
        self.saver.call=fail
        with self.assertRaises(OSError):self.saver.save(self.rule)
        self.assertEqual(self.call('latest',{'folder':'Documents'})['snapshot']['id'],first['id'])
        self.saver.call=original;self.calls.clear();self.saver.save(self.rule)
        self.assertEqual(self.calls.count('put'),0) # Reuse verified interrupted transfer.

    def test_released_session_cannot_write(self):
        self.write(b'pending');self.authority.release('alice')
        with self.assertRaisesRegex(ValueError,'Stale'):self.saver.save(self.rule)
        self.assertEqual((self.home/'Documents/file').read_bytes(),b'pending')

    def test_source_change_before_commit_is_pending(self):
        self.write(b'before')
        original=self.saver.call
        def modify(route,data):
            result=original(route,data)
            if route=='put':self.write(b'after')
            return result
        self.saver.call=modify
        with self.assertRaisesRegex(ValueError,'changed'):self.saver.save(self.rule)
        self.assertIsNone(self.call('latest',{'folder':'Documents'})['snapshot'])

    def test_symlinked_folder_and_files_rejected(self):
        outside=self.root/'outside';outside.mkdir();(outside/'private').write_text('secret')
        (self.home/'Documents').symlink_to(outside)
        with self.assertRaises(OSError):self.saver.save(self.rule)
        (self.home/'Documents').unlink();(self.home/'Documents').mkdir()
        (self.home/'Documents/link').symlink_to(outside/'private')
        with self.assertRaises(ValueError):self.saver.save(self.rule)

    def test_restore_does_not_follow_target_symlink(self):
        self.write(b'good');self.saver.save(self.rule)
        outside=self.root/'outside';outside.write_bytes(b'private')
        (self.home/'Documents/file').unlink();(self.home/'Documents/file').symlink_to(outside)
        self.saver.restore(self.rule)
        self.assertEqual(outside.read_bytes(),b'private')
        self.assertFalse((self.home/'Documents/file').is_symlink())

    def test_manifest_paths_and_missing_objects_rejected(self):
        for value in ({'../bob':{'size':0,'chunks':[]}}, {'a':{'size':1,'chunks':[]}},
                      {'a':{'size':0,'chunks':[]},'a/b':{'size':0,'chunks':[]}}):
            with self.assertRaises(ValueError):manifest(value)
        files={'file':{'size':1,'chunks':['0'*64]}}
        with self.assertRaises(ValueError):self.call('commit',{'folder':'Documents','files':files})

    def test_objects_are_private_per_account(self):
        self.write(b'private');self.saver.save(self.rule)
        digest=hashlib.sha256(b'private').hexdigest()
        self.authority.account('bob',1001,1001,'$6$salt$hash','edit');self.authority.assign('bob',self.peer)
        session={'name':'bob',**self.authority.acquire(self.peer,'bob')}
        with self.assertRaises(ValueError):
            self.authority.snapshots.dispatch('get',self.peer,{**session,'digest':digest})

    def test_live_app_cannot_be_labeled_clean(self):
        rule={'folder':'Documents','mode':'app-and-data','source':'https://example.org'}
        with self.authority.db() as db:
            db.execute("INSERT OR REPLACE INTO settings VALUES ('sources',?)",(json.dumps(['https://example.org']),))
        self.authority.rules(self.peer,'alice',self.session['token'],[rule]);self.write(b'database')
        with self.assertRaisesRegex(ValueError,'application'):self.saver.save(rule,lambda:False)
        with self.assertRaisesRegex(ValueError,'close'):self.call('commit',{'folder':'Documents','files':{}})

    def test_inotify_ignores_read_and_detects_write(self):
        folder=self.home/'Documents';folder.mkdir();(folder/'a').write_text('first')
        watcher=Watcher([folder]);self.addCleanup(watcher.close)
        (folder/'a').read_text();self.assertFalse(watcher.changed(0.01))
        (folder/'a').write_text('changed');self.assertTrue(watcher.changed(1))

if __name__=='__main__':unittest.main()

class StagingTests(unittest.TestCase):
    setUp=StorageTests.setUp
    def test_release_during_verification_fences_commit(self):
        from unittest.mock import patch
        data=b'pending';digest=hashlib.sha256(data).hexdigest()
        self.call('put',{'digest':digest,'content':base64.b64encode(data).decode()})
        target=self.authority.snapshots.object_path('alice',digest)
        with self.authority.db() as db:db.execute('UPDATE objects SET stamp=NULL')
        original=Path.read_bytes
        released=[]
        def read(path):
            value=original(path)
            if path==target and not released:
                self.authority.release('alice');released.append(True)
            return value
        with patch.object(Path,'read_bytes',read):
            with self.assertRaisesRegex(ValueError,'Stale'):
                self.call('commit',{'folder':'Documents','files':{'file':{'size':len(data),'chunks':[digest]}}})
        with self.authority.db() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM snapshots').fetchone()[0],0)

    def test_restore_preserves_private_executable_mode(self):
        self.home.joinpath('Documents').mkdir()
        file=self.home/'Documents/script';file.write_text('#!/bin/sh\ntrue\n');file.chmod(0o700)
        self.saver.save(self.rule);file.unlink();self.saver.restore(self.rule)
        self.assertEqual(file.stat().st_mode&0o777,0o700)

    def test_restore_removes_deleted_files_without_following_stale_links(self):
        self.home.joinpath('Documents').mkdir();(self.home/'Documents/kept').write_text('saved')
        self.saver.save(self.rule)
        outside=self.root/'outside';outside.mkdir();(outside/'private').write_text('private')
        (self.home/'Documents/stale-link').symlink_to(outside,target_is_directory=True)
        (self.home/'Documents/old').mkdir();(self.home/'Documents/old/deleted').write_text('stale')
        self.saver.restore(self.rule)
        self.assertEqual(sorted(p.name for p in (self.home/'Documents').iterdir()),['kept'])
        self.assertEqual((outside/'private').read_text(),'private')

    def test_internal_links_round_trip_and_chained_escapes_are_rejected(self):
        self.home.joinpath('Documents/sub').mkdir(parents=True)
        (self.home/'Documents/file').write_text('kept')
        (self.home/'Documents/sub/alias').symlink_to('../file')
        self.saver.save(self.rule)
        (self.home/'Documents/sub/alias').unlink();self.saver.restore(self.rule)
        self.assertEqual((self.home/'Documents/sub/alias').read_text(),'kept')
        self.assertTrue((self.home/'Documents/sub/alias').is_symlink())
        for files in ({'a':{'link':'../outside'}},{'a':{'link':'b'},'b':{'link':'a'}},
                      {'a':{'link':'sub/elsewhere'},'sub/elsewhere':{'link':'../../outside'}}):
            with self.assertRaises(ValueError):manifest(files)

    def test_electron_runtime_links_and_codex_sockets_are_not_saved(self):
        import socket
        rules=[{'folder':folder,'mode':'folder','source':None} for folder in ('.config/Codex','.codex')]
        self.authority.rules(self.peer,'alice',self.session['token'],rules)
        for rule in rules:
            folder=self.home/rule['folder'];folder.mkdir(parents=True)
            (folder/'settings.json').write_text('durable fixture')
            endpoint=socket.socket(socket.AF_UNIX);self.addCleanup(endpoint.close)
            endpoint.bind(str(folder/'runtime.sock'))
            if rule['folder']=='.config/Codex':
                for name,target in [('SingletonSocket','/tmp/fixture/socket'),('SingletonCookie','cookie'),('SingletonLock','fixture-123')]:
                    (folder/name).symlink_to(target)
            self.saver.save(rule)
            snapshot=self.call('latest',{'folder':rule['folder']})['snapshot']
            page=self.call('manifest-page',{'folder':rule['folder'],'id':snapshot['id'],'offset':0})
            self.assertEqual(set(page['files']),{'settings.json'})
            (folder/'settings.json').unlink()
            self.saver.restore(rule)
            self.assertEqual((folder/'settings.json').read_text(),'durable fixture')

    def test_unrelated_external_links_and_special_files_still_reject_save(self):
        StorageTests.write(self,b'previous');first=self.saver.save(self.rule)
        (self.home/'Documents/SingletonSocket').symlink_to('/tmp/external')
        with self.assertRaises(ValueError):self.saver.save(self.rule)
        self.assertEqual(self.call('latest',{'folder':'Documents'})['snapshot']['id'],first['id'])
        (self.home/'Documents/SingletonSocket').unlink()
        os.mkfifo(self.home/'Documents/pipe')
        with self.assertRaises(ValueError):self.saver.save(self.rule)
        self.assertEqual(self.call('latest',{'folder':'Documents'})['snapshot']['id'],first['id'])

    def test_codex_plugin_alias_and_history_restore_without_runtime_shims(self):
        rule={'folder':'.codex','mode':'folder','source':None}
        self.authority.rules(self.peer,'alice',self.session['token'],[rule])
        root=self.home/'.codex';plugin=root/'plugins/cache/openai-bundled/chrome/fixture-version'
        plugin.mkdir(parents=True);(plugin/'manifest.json').write_text('plugin fixture')
        (plugin.parent/'latest').symlink_to(str(plugin.absolute()),target_is_directory=True)
        runtime=root/'tmp/arg0-linux/codex-arg0fixture';runtime.mkdir(parents=True)
        (runtime/'apply_patch').symlink_to('/usr/lib/chatgpt/resources/codex')
        (root/'tmp/note.txt').write_text('retain other tmp data')
        (root/'sessions').mkdir();(root/'sessions/history.jsonl').write_text('history fixture')
        self.saver.save(rule)
        snapshot=self.call('latest',{'folder':'.codex'})['snapshot']
        files=self.call('manifest-page',{'folder':'.codex','id':snapshot['id'],'offset':0})['files']
        self.assertEqual(files['plugins/cache/openai-bundled/chrome/latest'],{'link':'fixture-version'})
        self.assertFalse(any(name.startswith('tmp/arg0-linux/') for name in files))
        self.assertIn('tmp/note.txt',files)
        import shutil
        shutil.rmtree(root)
        self.saver.restore(rule)
        self.assertEqual((root/'plugins/cache/openai-bundled/chrome/latest/manifest.json').read_text(),'plugin fixture')
        self.assertEqual((root/'sessions/history.jsonl').read_text(),'history fixture')
        self.assertFalse((root/'tmp/arg0-linux').exists())

    def test_normalized_absolute_alias_cannot_escape_through_another_link(self):
        self.home.joinpath('Documents/sub').mkdir(parents=True)
        (self.home/'Documents/sub/out').symlink_to('/tmp/outside')
        (self.home/'Documents/alias').symlink_to(str((self.home/'Documents/sub/out/file').absolute()))
        with self.assertRaises(ValueError):self.saver.save(self.rule)

    def test_staging_is_invisible_until_atomic_commit_and_old_token_cannot_commit(self):
        stage=self.call('begin',{'folder':'Documents'})['stage']
        self.call('stage',{'stage':stage,'files':{'first':{'size':0,'chunks':[]}}})
        self.call('stage',{'stage':stage,'files':{'second':{'size':0,'chunks':[]}}})
        self.assertIsNone(self.call('latest',{'folder':'Documents'})['snapshot'])
        committed=self.call('commit',{'stage':stage})
        page=self.call('manifest-page',{'folder':'Documents','id':committed['id']})
        self.assertEqual(set(page['files']),{'first','second'})
        obsolete=self.call('begin',{'folder':'Documents'})['stage']
        self.authority.release('alice')
        self.session={'name':'alice',**self.authority.acquire(self.peer,'alice')}
        with self.assertRaisesRegex(ValueError,'stale'):self.call('commit',{'stage':obsolete})

    def test_restore_manifest_is_paged_for_large_folders(self):
        stage=self.call('begin',{'folder':'Documents'})['stage']
        names=[str(number).zfill(6)+'x'*240 for number in range(10000)]
        for start in range(0,len(names),2000):
            self.call('stage',{'stage':stage,'files':{name:{'size':0,'chunks':[]} for name in names[start:start+2000]}})
        result=self.call('commit',{'stage':stage})
        first=self.call('manifest-page',{'folder':'Documents','id':result['id']})
        self.assertIsNotNone(first['next'])
        second=self.call('manifest-page',{'folder':'Documents','id':result['id'],'offset':first['next']})
        self.assertEqual(len(first['files'])+len(second['files']),10000)

    def test_corrupted_upload_is_not_published(self):
        data=b'document';digest=hashlib.sha256(data).hexdigest()
        self.call('put',{'digest':digest,'content':base64.b64encode(data).decode()})
        self.authority.snapshots.object_path('alice',digest).write_bytes(b'corrupted')
        with self.assertRaisesRegex(ValueError,'verification'):
            self.call('commit',{'folder':'Documents','files':{'file':{'size':len(data),'chunks':[digest]}}})
        self.assertIsNone(self.call('latest',{'folder':'Documents'})['snapshot'])
