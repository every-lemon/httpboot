import contextlib,importlib.util,io,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'httpboot'))
import server_console

class ConsoleTests(unittest.TestCase):
    def test_daemon_log_does_not_include_console_credential(self):
        with tempfile.TemporaryDirectory() as temporary:
            authority=SimpleNamespace(database=Path(temporary)/'authority.db')
            server=SimpleNamespace(serve_forever=lambda:None)
            class Context:
                def __enter__(self):return server
                def __exit__(self,*_):pass
            output=io.StringIO()
            with patch.object(server_console,'ThreadingHTTPServer',return_value=Context()),contextlib.redirect_stdout(output):server_console.serve(authority,None)
            token=(Path(temporary)/'console-token').read_text().strip()
            self.assertTrue(token);self.assertNotIn(token,output.getvalue());self.assertNotIn('/#',output.getvalue())

    def test_package_companions_start_and_restart_with_authority(self):
        spec=importlib.util.spec_from_file_location('package_lifecycle',ROOT/'packaging/build-server-deb.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temporary:
            module.tree(Path(temporary));units=Path(temporary)/'usr/lib/systemd/system'
            wanted=(units/'httpboot-server.service.d/20-companions.conf').read_text()
            for name in ('httpboot-server-console.service','httpboot-bootstrap-v2.service'):
                self.assertIn(name,wanted);self.assertIn('PartOf=httpboot-server.service',(units/(name+'.d')/'20-lifecycle.conf').read_text())
                self.assertTrue((units/name).is_file())

if __name__=='__main__':unittest.main()
