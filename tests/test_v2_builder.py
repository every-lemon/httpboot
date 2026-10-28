import hashlib
import json
import os
import ssl
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'httpboot'))
from builder_v2 import Handler,LimitedServer,Remote,REVISION,validate,read_request
from common import dump,sha256
from product_version import VERSION
from control_transport import ca


class BuilderTests(unittest.TestCase):
    def test_job_rejects_commands_passwords_and_wrong_revision(self):
        request={'schema':2,'job':'a'*32,'profile':'clean','revision':REVISION,'drivers':[]}
        self.assertEqual(validate(request),request)
        for changes in ({'password_hashes':{}},{'command':'shell'},{'profile':'../escape'},{'revision':'old'}):
            with self.assertRaises(ValueError):validate({**request,**changes})
    def test_supervisor_refuses_symlinked_request(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);dump(root/'request',{'schema':2,'job':'a'*32,'profile':'clean','revision':REVISION,'drivers':[]})
            (root/'link').symlink_to(root/'request')
            with self.assertRaises(OSError):read_request(root/'link',os.getuid())
    def test_disabled_schedule_does_not_require_builder_connection(self):
        from unittest.mock import patch
        from server_v2 import Authority
        from server_jobs import tick
        from schedule_policy import defaults
        with tempfile.TemporaryDirectory() as temp:
            authority=Authority(Path(temp)/'authority.sqlite3');policy=defaults();policy['image_updates']['enabled']=False
            with authority.db() as db:db.execute("INSERT INTO settings VALUES ('schedules',?)",(json.dumps(policy),))
            with patch('server_jobs.Remote') as remote:
                self.assertEqual(tick(authority,{'profile':'clean'},1735732800)['state'],'not-due')
                remote.return_value.call.assert_not_called()

    def test_remote_job_resumes_after_lost_submission_response(self):
        from unittest.mock import patch
        from server_v2 import Authority
        from server_jobs import tick
        with tempfile.TemporaryDirectory() as temp:
            authority=Authority(Path(temp)/'authority.sqlite3');calls=[];lost=[True]
            class Connection:
                def __init__(self,cfg):pass
                def call(self,path,data=None):
                    calls.append((path,data))
                    if path=='/v2/health':return {'version':VERSION,'revision':REVISION,'architecture':'amd64','healthy':True}
                    if path=='/v2/jobs':
                        if lost.pop() if lost else False:raise OSError('Lost response after accepted submission')
                        return {'state':'accepted'}
                    return {'state':'running'}
            with patch('server_jobs.Remote',Connection),patch('server_jobs.claim',return_value='scheduled-claim') as claim,patch('server_jobs.finish'):
                with self.assertRaises(OSError):tick(authority,{'profile':'clean'},1735732800)
                result=tick(authority,{'profile':'clean'},1735732800)
                self.assertEqual(claim.call_count,1)
            submitted=[data['job'] for path,data in calls if path=='/v2/jobs']
            self.assertEqual(len(submitted),2);self.assertEqual(submitted[0],submitted[1])
            self.assertEqual(result['state'],'building')

    def test_real_pinned_tls_jobs_and_range_resume(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            for name in ('inbox','public'):(root/name).mkdir()
            ca(root/'tls','127.0.0.1');context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(root/'tls/server.pem',root/'tls/server.key')
            server=LimitedServer(('127.0.0.1',0),Handler,context)
            server.config={'state':str(root),'token':'fixture-secret','profiles':['clean','private']}
            dump(root/'public/health.json',{'seen':time.time(),'revision':REVISION,'architecture':'amd64'})
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            token=root/'token';token.write_text('fixture-secret')
            fingerprint=hashlib.sha256(ssl.PEM_cert_to_DER_cert((root/'tls/server.pem').read_text())).hexdigest()
            config={'url':f'https://127.0.0.1:{server.server_port}','fingerprint':fingerprint,'token_file':str(token),'profile':'clean'}
            remote=Remote(config)
            try:
                self.assertTrue(remote.call('/v2/health')['healthy'])
                with self.assertRaisesRegex(ValueError,'certificate changed'):Remote({**config,'fingerprint':'0'*64}).call('/v2/health')
                token.write_text('wrong')
                with self.assertRaisesRegex(ValueError,'rejected'):remote.call('/v2/health')
                token.write_text('fixture-secret')
                request={'schema':2,'job':'a'*32,'profile':'clean','revision':REVISION,'drivers':[]}
                remote.call('/v2/jobs',request);remote.call('/v2/jobs',request)
                self.assertEqual(len(list((root/'inbox').glob('*.json'))),1)
                with self.assertRaisesRegex(ValueError,'rejected'):remote.call('/v2/jobs',{**request,'profile':'private'})
                folder=root/'public'/request['job'];folder.mkdir();dump(folder/'status.json',{'state':'complete'})
                artifact=folder/'boot.efi';artifact.write_bytes(b'0123456789'*1000)
                target=root/'download';target.with_name('download.part').write_bytes(artifact.read_bytes()[:300])
                remote.download(request['job'],'boot.efi',{'size':artifact.stat().st_size,'sha256':sha256(artifact)},target)
                self.assertEqual(target.read_bytes(),artifact.read_bytes())
            finally:server.shutdown();server.server_close();thread.join(3)

if __name__=='__main__':unittest.main()
