"""Export immutable Flatpak installation content independently of private app data."""
import hashlib
import json
import re
import subprocess
from pathlib import Path
from common import dump,load,sha256

APP=re.compile(r'^[A-Za-z][A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]+){2,}$')


def command(*args):
    return subprocess.run(['flatpak',*args],check=True,capture_output=True,text=True).stdout.strip()


def remote_name(source):return 'httpboot-'+hashlib.sha256(source.encode()).hexdigest()[:16]


def approved_origin(origin,remotes,approved,previous):
    url=remotes.get(origin,'').rstrip('/')
    for source in approved:
        if url==source.rstrip('/') or (origin==remote_name(source) and url):return source
        if any(record.get('source')==source and record.get('repo_url','').rstrip('/')==url and url for record in previous.values()):return source
    return None


def export(home,app,source,approved_sources=None):
    import fcntl
    if not APP.fullmatch(app):raise ValueError('Invalid Flatpak application ID')
    locks=Path(home)/'.local/share/httpboot/flatpak-locks';locks.mkdir(parents=True,exist_ok=True,mode=0o700)
    with (locks/(app+'.lock')).open('a') as guard:
        fcntl.flock(guard,fcntl.LOCK_EX)
        return _export(home,app,source,approved_sources)


def _export(home,app,source,approved_sources=None):
    if not APP.fullmatch(app):raise ValueError('Invalid Flatpak application ID')
    remotes={line.split('\t')[0]:line.split('\t')[1] for line in command('remotes','--user','--columns=name,url').splitlines() if '\t' in line}
    base=Path(home)/'.local/share/httpboot/flatpak-bundles'/app
    base.mkdir(parents=True,exist_ok=True,mode=0o700)
    old=load(base/'index.json') if (base/'index.json').is_file() else {}
    origin=command('info','--user','--show-origin',app)
    if approved_origin(origin,remotes,[source],old)!=source:
        raise ValueError('Installed app origin differs from its approved source')
    refs=[]
    for kind in ('app','runtime'):
        rows=command('list','--user','--'+kind,'--all','--columns=application,arch,branch').splitlines()
        for row in rows:
            values=row.split('\t')
            if len(values)!=3:raise ValueError('Unexpected Flatpak reference output')
            refs.append(kind+'/'+ '/'.join(values))
    approved=approved_sources or [source]
    required=command('info','--user','--show-runtime',app)
    if not required.startswith('runtime/'):required='runtime/'+required
    selected=[ref for ref in refs if ref.startswith('runtime/') or ref.startswith('app/'+app+'/')]
    if not any(ref.startswith('app/'+app+'/') for ref in selected):raise ValueError('Per-user app is not installed')
    index={}
    for ref in selected:
        parts=ref.split('/')
        if len(parts)!=4 or parts[2]!='x86_64' or not APP.fullmatch(parts[1]) or not re.fullmatch(r'[A-Za-z0-9._-]+',parts[3]):
            raise ValueError('Only explicit x86_64 application/runtime references are supported')
        ref_origin=command('info','--user','--show-origin',ref)
        repo_url=remotes.get(ref_origin,'').rstrip('/')
        ref_source=approved_origin(ref_origin,remotes,approved,old)
        if ref_source is None:
            if ref==required or ref.startswith('app/'):raise ValueError('Application or required runtime source is not approved')
            continue
        commit=command('info','--user','--show-commit',ref)
        name=hashlib.sha256(ref.encode()).hexdigest()+'.flatpak';file=base/name
        prior=old.get(ref,{})
        unchanged=file.is_file() and prior.get('file_identity')==[file.stat().st_size,file.stat().st_mtime_ns,file.stat().st_ctime_ns]
        if prior.get('commit')!=commit or not unchanged:
            partial=file.with_suffix('.partial');partial.unlink(missing_ok=True)
            command('build-bundle',*(['--runtime'] if parts[0]=='runtime' else []),'--arch=x86_64',
                    '--repo-url='+repo_url,str(Path(home)/'.local/share/flatpak/repo'),str(partial),parts[1],parts[3])
            partial.replace(file)
        checksum=prior['sha256'] if unchanged and prior.get('commit')==commit else sha256(file)
        index[ref]={'commit':commit,'file':name,'sha256':checksum,'source':ref_source,'repo_url':repo_url,
                    'file_identity':[file.stat().st_size,file.stat().st_mtime_ns,file.stat().st_ctime_ns]}
    if index!=old:dump(base/'index.json',index)
    return base


def restore(home,app):
    if not APP.fullmatch(app):raise ValueError('Invalid Flatpak application ID')
    base=Path(home)/'.local/share/httpboot/flatpak-bundles'/app
    index=load(base/'index.json')
    for ref,record in sorted(index.items(),key=lambda pair:(not pair[0].startswith('runtime/'),pair[0])):
        name=record['file']
        if not re.fullmatch(r'[0-9a-f]{64}\.flatpak',name) or sha256(base/name)!=record['sha256']:
            raise ValueError('Flatpak bundle failed content verification')
        command('install','--user','--bundle','--noninteractive','--no-deps','-y',str(base/name))
        if command('info','--user','--show-commit',ref)!=record['commit']:
            raise ValueError('Restored Flatpak commit does not match its verified installation reference')


def install(app,source):
    if not APP.fullmatch(app):raise ValueError('Invalid application ID')
    from common import safe_url
    safe_url(source,https=True)
    remote=remote_name(source)
    command('remote-add','--user','--if-not-exists',remote,source)
    command('install','--user','--noninteractive','-y',remote,app)


def search(query,sources):
    """Search only administrator-approved repositories, never unrelated remotes."""
    if not isinstance(query,str) or not 1<=len(query.strip())<=120:raise ValueError('Enter a search term (up to 120 characters)')
    results=[]
    for source in sources:
        remote=remote_name(source)
        command('remote-add','--user','--if-not-exists',remote,source)
        rows=command('remote-ls','--user','--app','--arch=x86_64','--columns=application,name,description',remote)
        for line in rows.splitlines():
            fields=line.split('\t',2)
            if len(fields)!=3 or not APP.fullmatch(fields[0]):continue
            if query.casefold() in line.casefold():results.append({'id':fields[0],'name':fields[1],'description':fields[2],'source':source})
            if len(results)>=100:return results
    return results


def details(app,source):
    if not APP.fullmatch(app):raise ValueError('Invalid application ID')
    return command('remote-info','--user','--show-metadata',remote_name(source),app)


def uninstall(app):
    if not APP.fullmatch(app):raise ValueError('Invalid application ID')
    # Deliberately omit --delete-data. Existing verified saves remain available.
    command('uninstall','--user','--noninteractive','-y',app)
