"""Durable v2 Builder jobs; network listener and privileged supervisor are separate."""
import argparse
import fcntl
import hashlib
import hmac
import http.client
import json
import os
import pwd
import re
import secrets
import shutil
import ssl
import subprocess
import threading
import stat
import sys
import time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from common import atomic,dump,load,sha256,safe_url
from control_transport import TLSHTTPServer
from product_version import VERSION,BUILDER_REVISION

REVISION=BUILDER_REVISION
ARTIFACTS={'filesystem.squashfs','recovery.squashfs','boot.efi','recovery.efi','release.json','qualification-v2.json'}


def validate(value):
    if not isinstance(value,dict) or set(value)!={'schema','job','profile','revision','drivers'} or value['schema']!=2 or value['revision']!=REVISION:
        raise ValueError('Matching v2 Builder revision required')
    if not re.fullmatch('[a-f0-9]{32}',str(value['job'])) or not re.fullmatch('[a-zA-Z0-9_-]{1,64}',str(value['profile'])):
        raise ValueError('Invalid build job or profile')
    if not isinstance(value['drivers'],list) or len(value['drivers'])>64:raise ValueError('Invalid approved drivers')
    for driver in value['drivers']:
        if not isinstance(driver,dict) or not re.fullmatch('[a-f0-9]{64}',str(driver.get('sha256',''))) or type(driver.get('size')) is not int or not 0<driver['size']<=512*1024**2:raise ValueError('Invalid approved driver')
        if not re.fullmatch(r'[A-Za-z0-9_.+-]{1,128}\.(deb|bin|fw|ucode)',str(driver.get('filename',''))):raise ValueError('Invalid driver filename')
    return value


class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_GET(self):self.respond()
    def do_POST(self):self.respond()
    def do_PUT(self):self.respond()
    def respond(self):
        self.connection.settimeout(30);cfg=self.server.config;root=Path(cfg['state'])
        try:
            if not hmac.compare_digest(self.headers.get('Authorization',''),'Bearer '+cfg['token']):raise ValueError('Builder authentication required')
            if self.command=='PUT' and (upload:=re.fullmatch(r'/v2/drivers/([a-f0-9]{64})',self.path)):
                size=int(self.headers.get('Content-Length','0'))
                if self.headers.get('Transfer-Encoding') or not 0<size<=512*1024**2:raise ValueError('Invalid driver upload size')
                if shutil.disk_usage(root).free<size+1024**3:raise ValueError('Insufficient Builder staging space')
                digest=upload[1];target=root/'inbox/drivers'/digest
                import tempfile
                fd,name=tempfile.mkstemp(dir=target.parent,prefix='.upload-')
                try:
                    hashed=hashlib.sha256();remaining=size
                    with os.fdopen(fd,'wb') as out:
                        while remaining:
                            block=self.rfile.read(min(1024**2,remaining))
                            if not block:raise ValueError('Interrupted driver upload')
                            hashed.update(block);out.write(block);remaining-=len(block)
                        out.flush();os.fsync(out.fileno())
                    if hashed.hexdigest()!=digest:raise ValueError('Driver digest mismatch')
                    os.replace(name,target)
                finally:
                    if os.path.exists(name):os.unlink(name)
                result={'ok':True}
            elif self.path=='/v2/health' and self.command=='GET':
                state=load(root/'public/health.json');state.setdefault('version',VERSION);state['healthy']=time.time()-state['seen']<30;result=state
            elif self.path=='/v2/jobs' and self.command=='POST':
                size=int(self.headers.get('Content-Length','0'))
                if self.headers.get('Transfer-Encoding') or not 0<size<=65536:raise ValueError('Invalid build request size')
                value=validate(json.loads(self.rfile.read(size)))
                if value['profile'] not in cfg['profiles']:raise ValueError('Unknown approved Builder profile')
                target=root/'inbox'/(value['job']+'.json')
                with open(root/'inbox/submission.lock','a') as lock:
                    fcntl.flock(lock,fcntl.LOCK_EX)
                    if target.exists() and load(target)!=value:raise ValueError('Job ID already has different inputs')
                    if not target.exists():
                        if sum(not (root/'public'/p.stem/'status.json').exists() or load(root/'public'/p.stem/'status.json')['state'] not in ('complete','failed') for p in (root/'inbox').glob('*.json'))>=32:raise ValueError('Builder queue full')
                        dump(target,value)
                result={'job':value['job'],'state':'accepted'}
            elif self.command=='GET' and (event:=re.fullmatch(r'/v2/jobs/([a-f0-9]{32})/events',self.path)):
                file=root/'public'/event[1]/'status.json'
                result={'events':load(file).get('events',[]) if file.exists() else []}
            elif self.command=='GET' and (match:=re.fullmatch(r'/v2/jobs/([a-f0-9]{32})(?:/artifacts/([a-z0-9.-]+))?',self.path)):
                job,name=match.groups();folder=root/'public'/job
                if name:
                    if name not in ARTIFACTS:raise ValueError('Unknown build artifact')
                    status=load(folder/'status.json')
                    if status['state']!='complete':raise ValueError('Build is not complete')
                    file=folder/name;size=file.stat().st_size;offset=0
                    header=self.headers.get('Range')
                    if header:
                        matched=re.fullmatch(r'bytes=([0-9]+)-',header)
                        if not matched or not 0<=int(matched[1])<size:raise ValueError('Invalid artifact range')
                        offset=int(matched[1])
                    self.send_response(206 if offset else 200);self.send_header('Content-Length',str(size-offset))
                    if offset:self.send_header('Content-Range',f'bytes {offset}-{size-1}/{size}')
                    self.end_headers()
                    with file.open('rb') as stream:stream.seek(offset);shutil.copyfileobj(stream,self.wfile,1024**2)
                    return
                result=load(folder/'status.json') if (folder/'status.json').exists() else {'job':job,'state':'queued'}
            else:raise ValueError('Unknown Builder operation')
            raw=json.dumps(result).encode();code=200
        except (ValueError,OSError,KeyError,TypeError) as error:
            raw=json.dumps({'error':str(error)[:500]}).encode();code=400
        self.send_response(code);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)


class LimitedServer(TLSHTTPServer):
    def __init__(self,address,handler,context):
        super().__init__(address,handler,context,max_connections=8)


def read_request(path,owner):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        metadata=os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid!=owner or metadata.st_size>65536:raise ValueError('Unsafe build request')
        return validate(json.loads(stream.read(65537)))


def listen(config):
    if os.geteuid()==0:raise ValueError('Builder network listener must be unprivileged')
    cfg=load(config);context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cfg['certificate'],cfg['key'])
    with LimitedServer((cfg.get('bind','0.0.0.0'),cfg.get('port',9091)),Handler,context) as server:
        server.config=cfg;server.serve_forever()


def supervise(config):
    from build_public import require_builder
    require_builder();cfg=load(config);root=Path(cfg['state'])
    if root.is_symlink():raise ValueError('Builder state must not be a symlink')
    root.mkdir(mode=0o750,parents=True,exist_ok=True)
    with open(root/'supervisor.lock','a') as guard:
        fcntl.flock(guard,fcntl.LOCK_EX|fcntl.LOCK_NB)
        try:user=pwd.getpwnam('httpboot-build-api')
        except KeyError:
            subprocess.run(['useradd','--system','--no-create-home','--shell','/usr/sbin/nologin','httpboot-build-api'],check=True)
            user=pwd.getpwnam('httpboot-build-api')
        os.chown(root,0,user.pw_gid);root.chmod(0o750)
        for name in ('inbox','public','tls','jobs'):
            folder=root/name;folder.mkdir(mode=0o750,exist_ok=True)
            os.chown(folder,user.pw_uid if name=='inbox' else 0,user.pw_gid);folder.chmod(0o750)
        objects=root/'inbox/drivers';objects.mkdir(mode=0o700,exist_ok=True);os.chown(objects,user.pw_uid,user.pw_gid)
        from control_transport import ca
        ca(root/'tls',cfg['address'])
        token=root/'token'
        if not token.exists():atomic(token,secrets.token_urlsafe(32))
        # Only the dedicated listener can read its TLS key and transport credential.
        for name in ('server.pem','server.key'):
            file=root/'tls'/name;os.chown(file,0,user.pw_gid);file.chmod(0o640)
        api={key:cfg[key] for key in ('state','profiles')}
        api.update(token=token.read_text().strip(),certificate=str(root/'tls/server.pem'),key=str(root/'tls/server.key'),bind=cfg.get('bind','0.0.0.0'),port=cfg.get('port',9091))
        api['profiles']=list(cfg['profiles']);dump(root/'listener.json',api,0o640);os.chown(root/'listener.json',0,user.pw_gid)
        def public(path,value):
            if path.name=='status.json':
                prior=load(path) if path.exists() else {}
                events=prior.get('events',[])
                if (value.get('state'),value.get('stage'))!=(prior.get('state'),prior.get('stage')):events=(events+[{'time':time.time(),'state':value['state'],'stage':value.get('stage','')}])[-200:]
                value['events']=events
            dump(path,value,0o640);os.chown(path,0,user.pw_gid)
        listener=subprocess.Popen([sys.executable,__file__,'listen',str(root/'listener.json')],user=user.pw_uid,group=user.pw_gid,extra_groups=[])
        worker=None;stream=None;current=None
        try:
            while True:
                if listener.poll() is not None:raise ValueError('Builder listener stopped')
                public(root/'public/health.json',{'schema':2,'version':VERSION,'revision':REVISION,'architecture':'amd64','seen':time.time(),'busy':worker is not None})
                if worker and worker.poll() is None:
                    log=root/'jobs'/current.name/'build.log'
                    with log.open('rb') as incoming_log:
                        incoming_log.seek(max(0,log.stat().st_size-16384));tail=incoming_log.read().decode(errors='replace')
                    stages=re.findall(r'HTTPBOOT_STAGE:([a-zA-Z0-9 _:().-]{1,180})',tail)
                    if stages:
                        status=load(current/'status.json')
                        if status.get('stage')!=stages[-1]:status['stage']=stages[-1];public(current/'status.json',status)
                if worker and worker.poll() is not None:
                    stream.close();stream=None;status=load(current/'status.json');status['finished']=time.time()
                    if worker.returncode==0:
                        try:
                            output=root/'jobs'/status['job']/('image-'+status['job'])
                            # Qualification is independently checked again by the publishing Server.
                            records={}
                            for name in ARTIFACTS:
                                source=output/name;target=current/name
                                if not source.is_file() or source.is_symlink():raise ValueError('Incomplete Builder output')
                                if target.exists():target.unlink()
                                os.link(source,target);os.chown(target,0,user.pw_gid);target.chmod(0o640)
                                records[name]={'size':target.stat().st_size,'sha256':sha256(target)}
                            status.update(state='complete',artifacts=records)
                        except (OSError,ValueError):
                            status.update(state='failed',reason='Builder output was incomplete or unreadable; logs and checkpoints retained')
                    else:status.update(state='failed',reason='Image build or qualification failed; retained Builder log and checkpoints are available')
                    public(current/'status.json',status);worker=None
                if worker is None:
                    for incoming in sorted((root/'inbox').glob('*.json')):
                        if incoming.is_symlink() or incoming.stat().st_size>65536:continue
                        try:request=read_request(incoming,user.pw_uid)
                        except (OSError,ValueError,KeyError,TypeError):continue
                        job=request['job'];profile=cfg['profiles'].get(request['profile'])
                        if not profile:continue
                        folder=root/'jobs'/job;folder.mkdir(mode=0o700,exist_ok=True)
                        durable=folder/'request.json'
                        if durable.exists() and load(durable)!=request:continue
                        dump(durable,request)
                        current=root/'public'/job;current.mkdir(mode=0o750,exist_ok=True);os.chown(current,0,user.pw_gid)
                        status_file=current/'status.json'
                        if status_file.exists() and load(status_file)['state'] in ('complete','failed'):continue
                        try:
                            output=folder/('image-'+job)
                            if output.exists():output.rename(folder/('interrupted-'+str(time.time_ns())))
                            approved=folder/'drivers';approved.mkdir(exist_ok=True)
                            from driver_imports import inspect,approve
                            for record in request['drivers']:
                                source=root/'inbox/drivers'/record['sha256']
                                target=folder/record['filename']
                                fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW)
                                with os.fdopen(fd,'rb') as incoming_driver,target.open('wb') as outgoing_driver:
                                    if not stat.S_ISREG(os.fstat(incoming_driver.fileno()).st_mode) or os.fstat(incoming_driver.fileno()).st_size!=record['size']:raise ValueError('Invalid driver object')
                                    shutil.copyfileobj(incoming_driver,outgoing_driver)
                                if target.stat().st_size!=record['size'] or sha256(target)!=record['sha256']:raise ValueError('Driver changed before build')
                                checked=inspect(target,record['kernel'],record['hardware_ids'],record['provenance'])
                                approve(approved,target,checked)
                            command=[sys.executable,str(Path(__file__).with_name('build_public.py')),'--server',safe_url(profile['server'],https=True),'--ca',profile['ca'],'--output',str(output),'--cache',profile.get('cache','/var/cache/kagnode/httpboot'),'--refresh-packages','--validate-startup']
                            if request['drivers']:command.extend(['--drivers',str(approved)])
                            for key,option in (('private_base','--private-base'),('legacy_config','--legacy-config')):
                                if profile.get(key):command.extend([option,profile[key]])
                            public(status_file,{'job':job,'state':'running','revision':REVISION,'started':time.time()})
                            stream=(folder/'build.log').open('ab');worker=subprocess.Popen(command,stdout=stream,stderr=subprocess.STDOUT)
                            break
                        except (ValueError,OSError,KeyError,subprocess.SubprocessError):
                            if stream:stream.close();stream=None
                            worker=None
                            public(status_file,{'job':job,'state':'failed','revision':REVISION,'finished':time.time(),'reason':'Builder preparation failed; inspect the protected local inputs and driver records'})

                time.sleep(2)
        finally:
            # Service shutdown leaves durable inputs/cache for restart; never cancels Client work.
            if worker and worker.poll() is None:worker.terminate();worker.wait(timeout=30)
            if stream:stream.close()
            listener.terminate();listener.wait(timeout=10)


class Remote:
    def __init__(self,config):
        self.cfg=config;self.url=urlsplit(safe_url(config['url'],https=True))
        if not re.fullmatch('[a-f0-9]{64}',config['fingerprint']):raise ValueError('Invalid pinned Builder certificate')
    def open(self,path,data=None,offset=None):
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.check_hostname=False;context.verify_mode=ssl.CERT_NONE
        connection=http.client.HTTPSConnection(self.url.hostname,self.url.port or 9091,context=context,timeout=30);connection.connect()
        if hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest()!=self.cfg['fingerprint']:
            connection.close();raise ValueError('Builder certificate changed; re-pair explicitly')
        headers={'Authorization':'Bearer '+Path(self.cfg['token_file']).read_text().strip(),'Content-Type':'application/json'}
        if offset:headers['Range']=f'bytes={offset}-'
        connection.request('POST' if data is not None else 'GET',path,json.dumps(data).encode() if data is not None else None,headers)
        response=connection.getresponse()
        if response.status not in (200,206):
            response.read(4096);connection.close();raise ValueError('Builder rejected the request')
        return connection,response
    def upload_driver(self,file,digest):
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.check_hostname=False;context.verify_mode=ssl.CERT_NONE
        connection=http.client.HTTPSConnection(self.url.hostname,self.url.port or 9091,context=context,timeout=60);connection.connect()
        try:
            if hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest()!=self.cfg['fingerprint']:raise ValueError('Builder certificate changed')
            with Path(file).open('rb') as stream:
                connection.request('PUT','/v2/drivers/'+digest,stream,{'Content-Length':str(Path(file).stat().st_size),'Authorization':'Bearer '+Path(self.cfg['token_file']).read_text().strip()})
            reply=connection.getresponse()
            if reply.status!=200:raise ValueError('Builder driver upload failed')
            reply.read(4096)
        finally:connection.close()
    def call(self,path,data=None):
        connection,response=self.open(path,data)
        try:
            raw=response.read(1024**2+1)
            if len(raw)>1024**2:raise ValueError('Builder reply too large')
            return json.loads(raw)
        finally:connection.close()
    def download(self,job,name,metadata,destination):
        if name not in ARTIFACTS or type(metadata['size']) is not int or not 0<metadata['size']<=64*1024**3 or not re.fullmatch('[a-f0-9]{64}',metadata['sha256']):raise ValueError('Invalid Builder artifact')
        destination=Path(destination);temporary=destination.with_name(destination.name+'.part')
        if destination.exists() and destination.stat().st_size==metadata['size'] and sha256(destination)==metadata['sha256']:return
        offset=temporary.stat().st_size if temporary.exists() else 0
        if offset>=metadata['size']:temporary.unlink();offset=0
        connection,response=self.open(f'/v2/jobs/{job}/artifacts/{name}',offset=offset)
        try:
            if offset and response.status!=206:raise ValueError('Builder did not honor resume offset')
            with temporary.open('ab' if offset else 'wb') as stream:
                while block:=response.read(1024**2):
                    offset+=len(block)
                    if offset>metadata['size']:raise ValueError('Builder artifact exceeds declared size')
                    stream.write(block)
                stream.flush();os.fsync(stream.fileno())
        finally:connection.close()
        if offset!=metadata['size'] or sha256(temporary)!=metadata['sha256']:raise ValueError('Builder artifact failed verification')
        os.replace(temporary,destination)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=('serve','listen'));parser.add_argument('config',type=Path)
    args=parser.parse_args()
    if args.action=='serve':supervise(args.config)
    else:listen(args.config)
