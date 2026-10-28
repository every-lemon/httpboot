import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'httpboot'))
from flatpak_content import export,restore,command,remote_name
from common import load


@unittest.skipUnless(shutil.which('flatpak') and shutil.which('ostree'),'Flatpak/OSTree tools unavailable')
class FlatpakContentTests(unittest.TestCase):
    def test_real_app_and_runtime_bundle_round_trip_without_private_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);home=root/'home';home.mkdir();repo=root/'repo'
            runtime='org.httpboot.Runtime';app='org.httpboot.Fixture'
            for name,is_runtime in ((runtime,True),(app,False)):
                build=root/name;(build/'files/bin').mkdir(parents=True)
                (build/'files/bin/fixture').write_text('#!/bin/sh\nexit 0\n');(build/'files/bin/fixture').chmod(0o755)
                (build/'metadata').write_text(('['+('Runtime' if is_runtime else 'Application')+']\nname='+name+'\n'+
                    'runtime='+runtime+'/x86_64/stable\nsdk='+runtime+'/x86_64/stable\n'+('' if is_runtime else 'command=fixture\n')))
                if not is_runtime:subprocess.run(['flatpak','build-finish',str(build)],check=True,capture_output=True)
                subprocess.run(['flatpak','build-export','--disable-sandbox','--files=files',*(['--runtime'] if is_runtime else []),str(repo),str(build),'stable'],check=True,capture_output=True)
            private=home/'.var/app'/app;private.mkdir(parents=True);(private/'secret').write_text('PRIVATE_DATA_FIXTURE')
            source='https://example.invalid/fixture.flatpakrepo';remote=remote_name(source)
            env={'XDG_DATA_HOME':str(home/'.local/share'),'XDG_CONFIG_HOME':str(home/'.config'),'XDG_CACHE_HOME':str(home/'.cache')}
            with patch.dict(os.environ,env):
                # Only this private local test repository is unsigned.
                command('remote-add','--user','--no-gpg-verify',remote,repo.as_uri())
                command('install','--user','--noninteractive','-y',remote,app)
                folder=export(home,app,source)
                saved=load(folder/'index.json');self.assertEqual(len(saved),2)
                self.assertTrue(any(ref.startswith('runtime/') for ref in saved))
                self.assertNotIn('PRIVATE_DATA_FIXTURE',''.join(p.read_bytes().decode(errors='ignore') for p in folder.iterdir()))
                stamps={p.name:p.stat().st_mtime_ns for p in folder.iterdir()}
                export(home,app,source);self.assertEqual(stamps,{p.name:p.stat().st_mtime_ns for p in folder.iterdir()})
                shutil.rmtree(home/'.local/share/flatpak')
                restore(home,app)
                for ref,record in saved.items():self.assertEqual(command('info','--user','--show-commit',ref),record['commit'])
                export(home,app,source) # Restored bundle origins still match approved source.
                self.assertEqual((private/'secret').read_text(),'PRIVATE_DATA_FIXTURE')

if __name__=='__main__':unittest.main()
