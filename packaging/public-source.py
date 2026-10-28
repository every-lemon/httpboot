#!/usr/bin/env python3
"""Create a secret-free source archive from the explicit Server/Client allowlists."""
import argparse
import importlib.util
import re
import tarfile
import gzip
import os
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('deb_package',ROOT/'packaging/build-server-deb.py')
package=importlib.util.module_from_spec(spec);spec.loader.exec_module(package)
spec=importlib.util.spec_from_file_location('public_audit',ROOT/'packaging/audit-public.py')
public_audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(public_audit)


def files():
    selected=[Path('httpboot')/name for name in package.MODULES]+[Path('client')/name for name in package.CLIENT]
    selected += [Path(name) for name in ('LICENSE','THIRD_PARTY_NOTICES.md','docs/README-public.md','docs/INSTALL-v2.md',
                  'docs/3.1.15-implementation.md','docs/3.1.15-verification.md','packaging/build-server-deb.py','packaging/build-builder-installer.py','packaging/public-source.py',
                  'packaging/audit-public.py','.gitignore','CONTRIBUTING.md','SECURITY.md','CHANGELOG.md','.github/workflows/ci.yml')]
    selected += [Path('examples')/name for name in ('client-v2.json','maintenance-policy.json','persistence-rules.json')]
    selected += [p.relative_to(ROOT) for p in sorted((ROOT/'tests').glob('test_v2*.py'))]
    selected += [Path('httpboot/assets/fonts')/name for name in ('DejaVuSansMono.ttf','DejaVuSansMono-LICENSE.txt')]
    return sorted(set(selected))


def build(output):
    output=Path(output);output.parent.mkdir(parents=True,exist_ok=True)
    selected=files()
    public_audit.audit([ROOT/name for name in selected],ROOT)
    for name in selected:
        source=ROOT/name
        if source.is_symlink() or not source.is_file():raise ValueError('Public source contains an unexpected file: '+str(name))
        raw=source.read_bytes()
        if re.search(rb'^-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----\r?$',raw,re.M):raise ValueError('Private key in public source')
        if re.search(rb'\$6\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}',raw):raise ValueError('Password hash in public source')
    epoch=int(os.environ.get('SOURCE_DATE_EPOCH','0'))
    if epoch<0:raise ValueError('SOURCE_DATE_EPOCH must not be negative')
    with output.open('wb') as stream,gzip.GzipFile(fileobj=stream,mode='wb',filename='',mtime=epoch) as compressed,tarfile.open(fileobj=compressed,mode='w') as archive:
        for name in selected:
            def metadata(member):
                member.uid=member.gid=0;member.uname=member.gname='root';member.mode=0o644;member.mtime=epoch
                return member
            archive.add(ROOT/name,arcname=str(name),filter=metadata)
        archive.add(ROOT/'docs/README-public.md',arcname='README.md',filter=metadata)
    return output

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    print(build(parser.parse_args().output))
