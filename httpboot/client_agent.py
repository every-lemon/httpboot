"""Privileged Client authority: mTLS credentials and session tokens never reach users."""
import argparse
import json
import os
import pwd
import grp
import time
import signal
import socket
import struct
import subprocess
import threading
from pathlib import Path
from common import atomic,dump,load,NAME,safe_url
from control_transport import key_request,request

WARNING='Non-persistent apps will not save data'
ACCOUNT_SERVICE_USERS=Path('/var/lib/AccountsService/users')


def hardware():
    result={'architecture':os.uname().machine}
    for field in ('product_name','product_uuid','board_name'):
        path=Path('/sys/class/dmi/id')/field
        if path.is_file():result[field]=path.read_text().strip()[:256]
    return result


def rpc(action,**values):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
        connection.settimeout(1800);connection.connect('/run/httpboot-v2/control.sock')
        connection.sendall(json.dumps({'action':action,**values}).encode()+b'\n')
        received=b''
        while not received.endswith(b'\n'):
            block=connection.recv(65536)
            if not block:raise ValueError('Client service disconnected')
            received+=block
            if len(received)>8*1024*1024:raise ValueError('Client response is too large')
        result=json.loads(received)
        if 'error' in result:raise ValueError(result['error'])
        return result


class WorkerError(ValueError):
    pass


class Agent:
    def __init__(self,config,run=Path('/run/httpboot-v2')):
        self.config=config;self.run=run;self.run.mkdir(mode=0o755,parents=True,exist_ok=True);self.run.chmod(0o755)
        self.credentials=Path(config['identity']);self.url=safe_url(config['server'],https=True)
        from client_policy import select_origin
        self.url=select_origin(self.url,self.credentials)
        self.lock=threading.RLock();self.accounts={};self.sessions={};self.status={};self.sources=[];self.pending_media=None;self.client_policy={};self.stage_attempts={}
        self.report_dir=self.run/'reports';self.report_dir.mkdir(mode=0o700,exist_ok=True)
        early=Path('/run/httpboot/boot-report.json')
        if early.is_file():
            from boot_reports import store
            try:store(self.report_dir,load(early))
            except (ValueError,OSError):pass
        self.journal=self.run/'sessions.json'
        if self.journal.exists():self.sessions=load(self.journal)
        self.boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        self.session_health={};self.supports_checkpoints=False
        self.saving_paused=False
        self.image_status={'state':'checking','message':'Checking for the latest validated image…'}
        from client_updates import Updates
        self.updates=Updates(self)
        from client_power import Power
        self.power=Power(self)

    def call(self,path,data=None):
        # Never probe or replay another endpoint inside a persistence operation.
        return request(self.url,path,data,self.credentials)

    def activate(self):
        if (self.credentials/'client.pem').exists():
            self.call('/v2/health');self.call('/v2/hardware',hardware());return True
        csr=key_request(self.credentials,'httpboot-client')
        response=self.call('/v2/activation',{'csr':csr,'hardware':hardware()})
        if response.get('approved'):
            atomic(self.credentials/'client.pem',response['certificate'])
            return True
        dump(self.run/'activation.json',response,0o644)
        return False

    def provision(self):
        # Accounts may only be materialized into a diskless RAM root.
        filesystem=subprocess.run(['findmnt','-n','-o','FSTYPE','/'],check=True,capture_output=True,text=True).stdout.strip()
        if filesystem not in ('overlay','tmpfs','ramfs'):raise ValueError('Account provisioning requires a RAM root')
        accounts=self.call('/v2/accounts')['accounts']
        if not accounts:raise ValueError('Client approved; waiting for account assignment')
        policy=self.call('/v2/policy');self.sources=policy['sources'];self.supports_checkpoints=policy.get('snapshot_sets',False);self.pending_media=policy.get('pending_media');self.client_policy=policy.get('client_policy',{})
        seen=set()
        for account in accounts:
            name=account['name'];uid=account['uid'];gid=account['gid']
            if not NAME.fullmatch(name) or type(uid) is not int or type(gid) is not int or min(uid,gid)<1000 or max(uid,gid)>60000:
                raise ValueError('Invalid assigned account')
            if uid in seen:raise ValueError('Duplicate assigned UID')
            seen.add(uid)
            try:
                prior=pwd.getpwnam(name)
                if (prior.pw_uid,prior.pw_gid,prior.pw_dir)!=(uid,gid,'/home/'+name):raise ValueError('Assigned account conflicts with image account')
            except KeyError:
                try:pwd.getpwuid(uid)
                except KeyError:pass
                else:raise ValueError('Assigned UID already belongs to another account')
                try:
                    group=grp.getgrgid(gid)
                    if group.gr_name!=name:raise ValueError('Assigned group ID conflicts with an existing group')
                except KeyError:
                    try:grp.getgrnam(name)
                    except KeyError:subprocess.run(['groupadd','--gid',str(gid),name],check=True)
                    else:raise ValueError('Assigned group name conflicts with another ID')
                subprocess.run(['useradd','--create-home','--uid',str(uid),'--gid',str(gid),'--shell','/bin/bash',name],check=True)
            if not __import__('re').fullmatch(r'\$(6|y)\$[A-Za-z0-9./$]+',account['password_hash']):raise ValueError('Invalid assigned password hash')
            subprocess.run(['chpasswd','--encrypted'],input=(name+':'+account['password_hash']+'\n').encode(),check=True)
            if account.get('system_admin'):
                subprocess.run(['usermod','--append','--groups','sudo',name],check=True)
            elif name in __import__('grp').getgrnam('sudo').gr_mem:
                subprocess.run(['gpasswd','--delete',name,'sudo'],check=True)
            visibility=ACCOUNT_SERVICE_USERS/name
            visibility.parent.mkdir(parents=True,exist_ok=True)
            atomic(visibility,'[User]\nSystemAccount='+('false' if account.get('login_visible',True) else 'true')+'\n',0o600)
            users=self.run/'users';users.mkdir(mode=0o755,exist_ok=True);users.chmod(0o755)
            cache=users/str(uid);cache.mkdir(mode=0o700,exist_ok=True)
            os.chown(cache,uid,gid);cache.chmod(0o700)
            self.accounts[str(uid)]={k:v for k,v in account.items() if k!='password_hash'}
        dump(self.run/'accounts.json',self.accounts)
        from printers import install_configuration
        install_configuration(self.call('/v2/printers')['configuration'])

    def worker(self,uid,action):
        account=self.accounts[str(uid)]
        result=subprocess.run(['runuser','-u',account['name'],'--','env','HOME=/home/'+account['name'],
                        'python3',str(Path(__file__).with_name('client_worker.py')),action],capture_output=True,text=True,timeout=1800)
        if result.returncode:
            import re
            codes=re.findall(r'^HTTPBOOT_WORKER_ERROR=([A-Za-z][A-Za-z0-9_:.]{0,150})$',result.stderr,re.M)
            code=codes[-1] if codes else 'worker-exit-'+str(abs(result.returncode))
            error=WorkerError('Saved-data '+action+' failed ('+code+'). Inspect Server Boot health; your verified saves are retained.')
            error.diagnostic_code=code
            raise error

    def dispatch(self,uid,data):
        action=data.get('action')
        if action=='login-progress':
            if uid!=0:raise ValueError('Login progress requires root')
            account=next((a for a in self.accounts.values() if a['name']==data.get('name')),None)
            if account is None:raise ValueError('Unknown assigned account')
            with self.lock:rows=list(self.status.get(str(account['uid']),{}).values())
            rows=[r for r in rows if r.get('phase')=='restoring']
            done=sum(r.get('bytes_done',0) for r in rows);total=sum(r.get('bytes_total',0) for r in rows)
            speed=sum(r.get('speed',0) for r in rows if r.get('bytes_done',0)<r.get('bytes_total',0))
            message='Restoring saved data…'
            if total:message=f'{done/1048576:.0f}/{total/1048576:.0f} MiB restored'
            if speed:message+=f', {speed/1048576:.1f} MiB/s, ~{int((total-done)/speed)}s left'
            if self.sessions.get(str(account['uid']),{}).get('closing'):message='Saving and verifying selected data…'
            return {'message':message}
        if action in ('open-login','close-login'):
            if uid!=0:raise ValueError('PAM session management requires root')
            name=data['name'];account=next((a for a in self.accounts.values() if a['name']==name),None)
            if account is None:raise ValueError('Account is not assigned to this Client')
            user=str(account['uid'])
            login_id=data.get('login_id','legacy')
            if not isinstance(login_id,str) or not __import__('re').fullmatch(r'(legacy|[0-9]+:[0-9]+)',login_id):raise ValueError('Invalid local login identity')
            if action=='open-login' and self.power.snapshot().get('state')=='running':raise ValueError('The Client is preparing to shut down; retry when it is ready')
            with self.lock:
                if action=='open-login':
                    if user in self.sessions:
                        if self.sessions[user].get('closing'):raise ValueError('Saved-data save is still running; wait before trying another login')
                        if not self.sessions[user].get('ready',True):raise ValueError('Saved-data restore is still running; wait before trying another login')
                        self.call('/v2/sessions/check',self.sessions[user])
                        logins=self.sessions[user].setdefault('logins',[])
                        if login_id not in logins:logins.append(login_id)
                        self.sessions[user]['detached']=False;dump(self.journal,self.sessions)
                        return {'ok':True,'continued_ram_session':True}
                    session=self.call('/v2/sessions',{'name':name,'boot_id':self.boot_id})
                    self.sessions[user]={'name':name,'token':session['token'],'ready':False,'logins':[login_id]};dump(self.journal,self.sessions)
                elif user not in self.sessions:return {'ok':True}
                else:
                    logins=self.sessions[user].get('logins',[login_id])
                    if login_id not in logins:return {'ok':True}
                    logins.remove(login_id);self.sessions[user]['logins']=logins
                    if logins:
                        dump(self.journal,self.sessions);return {'ok':True,'other_local_logins':True}
                    self.sessions[user]['closing']=True
            try:self.worker(user,'restore' if action=='open-login' else 'save')
            except BaseException:
                if action=='close-login':
                    with self.lock:self.sessions[user]['detached']=True;self.sessions[user]['closing']=False;dump(self.journal,self.sessions)
                    raise  # Preserve ownership and RAM work for a later login.
                with self.lock:
                    session=self.sessions.pop(user);self.call('/v2/sessions/release',session);dump(self.journal,self.sessions)
                raise
            if action=='open-login':
                with self.lock:self.sessions[user]['ready']=True;dump(self.journal,self.sessions)
            if action=='close-login':
                with self.lock:
                    # A lost release response must not strand this RAM session.
                    self.sessions[user]['detached']=True;self.sessions[user]['closing']=False;dump(self.journal,self.sessions)
                    self.call('/v2/sessions/release',self.sessions[user]);self.sessions.pop(user);dump(self.journal,self.sessions)
            return {'ok':True}
        if action=='shutdown-cleanup':
            if uid!=0:raise ValueError('Shutdown cleanup requires root')
            return self.power.cleanup()
        account=self.accounts.get(str(uid))
        if account is None:raise ValueError('Assigned account required')
        if action=='save-now':
            if str(uid) not in self.sessions:raise ValueError('A persistent login is required before saving')
            return self.power.save_user(str(uid))
        if action=='power':
            fresh=next((item for item in self.call('/v2/accounts')['accounts'] if item['uid']==uid and item['name']==account['name']),None)
            if fresh is None:raise ValueError('This account is no longer assigned to the Client')
            account['system_admin']=fresh.get('system_admin',False)
            if any(user!=str(uid) for user in self.sessions) and not account.get('system_admin'):raise ValueError('Other users are signed in; administrator access is required')
            return self.power.start(data.get('operation'))
        if action=='state':
            return {'access':account['access'],'ssh_persistence':account.get('persist_ssh',False),'warning':WARNING,'pending_warning':'Pending work exists only in RAM',
                    'supports_checkpoints':self.supports_checkpoints,'power':self.power.snapshot(),'session_health':self.session_health.get(str(uid),{}),'session_ready':bool(self.sessions.get(str(uid),{}).get('ready',False)),'status':self.status.get(str(uid),{}),'rules':json.loads(account['rules']),'sources':self.sources,'pending_media_available':self.pending_media is not None,'saving_paused':self.saving_paused,'operation':self.updates.snapshot(),'image_status':self.image_status}
        if action=='pending-export':
            if self.pending_media is None:raise ValueError('No administrator-approved pending-save medium is configured')
            # Source reads run with the account UID; public encryption recipients grant no read privilege.
            descriptor=self.run/('pending-'+str(uid)+'.json')
            dump(descriptor,{'home':'/home/'+account['name'],'rules':json.loads(account['rules']),'policy':self.pending_media,'user':account['name']},0o440)
            os.chown(descriptor,0,account['gid'])
            process=subprocess.run(['runuser','-u',account['name'],'--','python3',str(Path(__file__).with_name('pending_worker.py')),str(descriptor)],capture_output=True,text=True,check=True,timeout=1800)
            return json.loads(process.stdout)
        if action=='status':
            # Worker status is advisory, never an authorization decision.
            value=data.get('value')
            if not isinstance(value,dict) or len(json.dumps(value))>8192:raise ValueError('Invalid status')
            folder=str(value.get('folder','general'))
            if folder!='general' and folder not in {rule['folder'] for rule in json.loads(account['rules'])}:raise ValueError('Status must belong to a selected folder')
            with self.lock:
                self.status.setdefault(str(uid),{})[folder]=value
            return {'ok':True}
        if action=='rules':
            if self.power.snapshot().get('state')=='running':raise ValueError('Wait for the power operation before changing persistence')
            if account['access']!='edit':raise ValueError('Server policy does not permit persistence edits')
            session=self.sessions.get(str(uid))
            if not session:raise ValueError('Persistent login required')
            from server_v2 import validate_rules
            rules=validate_rules(data['rules'])
            if account.get('persist_ssh') is True and not any(r['folder']=='.ssh' for r in rules):raise ValueError('SSH persistence is managed by the administrator')
            if account.get('persist_ssh') is False and any(r['folder']=='.ssh' or r['folder'].startswith('.ssh/') for r in rules):raise ValueError('SSH persistence is disabled by the administrator')
            result=self.call('/v2/persistence',{**session,'rules':rules})
            account['rules']=json.dumps(result.get('rules',rules));return result
        if action=='snapshot':
            if data['route'] not in ('missing','put','get','latest','history','manifest-page','begin','stage','commit','restore-set','checkpoint'):raise ValueError('Unknown snapshot operation')
            session=self.sessions.get(str(uid))
            if not session:raise ValueError('No persistent session; saves remain in RAM')
            if data['route'] in ('missing','put','begin','stage','commit','checkpoint') and not session.get('ready',True):
                raise ValueError('Restore is incomplete; saves remain blocked')
            return self.call('/v2/snapshots/'+data['route'],{**data['value'],**session})
        if account['access']=='none':raise ValueError('Server policy grants no app access')
        if action in ('prepare-update','retry-update','restart-update','images','diagnostics','printers'):
            fresh=next((item for item in self.call('/v2/accounts')['accounts'] if item['name']==account['name'] and item['uid']==uid),None)
            if not fresh or fresh['access']=='none':raise ValueError('Current Server policy denies this app action')
            account['access']=fresh['access'];account['system_admin']=fresh.get('system_admin',False)
        if action in ('prepare-update','retry-update','restart-update'):
            if self.power.snapshot().get('state')=='running':raise ValueError('Wait for the current power operation')
            if account['access']!='edit':raise ValueError('Server policy does not permit update actions')
            if action=='restart-update' and any(user!=str(uid) for user in self.sessions) and not account.get('system_admin'):raise ValueError('Other users are signed in; administrator access is required')
            if str(uid) not in self.sessions:raise ValueError('A persistent login is required')
            return self.updates.restart() if action=='restart-update' else self.updates.start(retry=action=='retry-update')
        if action=='images':return self.call('/v2/images')
        if action=='diagnostics':
            from boot_reports import sanitize
            report=sanitize({'schema':1,'stage':'client-diagnostics','exit_status':0,'line':0,
                             'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()})
            return self.call('/v2/diagnostics',report)
        if action=='printers':
            from printers import dispatch
            operation=data.get('operation','list')
            result=dispatch(operation,data.get('printer'),data.get('job'),edit=account['access']=='edit',user=account['name'])
            if operation=='default':
                from printers import configuration
                session=self.sessions.get(str(uid))
                if not session:raise ValueError('Persistent login required to retain printer configuration')
                self.call('/v2/printers',{**session,'configuration':configuration()})
            return result
        raise ValueError('Unknown Client action')

    def queue_report(self,error=None):
        from boot_reports import store,collect
        report=collect('client-operation','operation-failed')
        if error is not None:
            import traceback
            frames=traceback.extract_tb(error.__traceback__)
            frame=next((f for f in reversed(frames) if Path(f.filename).parent==Path(__file__).parent),None)
            # Send code locations and numeric status only, never exception messages
            # that may contain private user paths or network credentials.
            report['details']['error_code']=getattr(error,'diagnostic_code',None) or type(error).__name__[:64]+(':'+Path(frame.filename).name+':'+str(frame.lineno) if frame else '')
            if isinstance(error,subprocess.CalledProcessError):report['exit_status']=min(100000,abs(error.returncode))
        store(self.report_dir,report)
        try:
            identity=Path((self.run/'cache-location').read_text().strip())
            if identity==self.run/'media/httpboot-v2/identity' and (self.run/'media').is_mount():store(identity/'reports',report)
        except (OSError,ValueError):pass

    def heartbeat_once(self):
        with self.lock:
            entries=[{'name':s['name'],'token':s['token']} for s in self.sessions.values()]
        result=self.call('/v2/sessions/heartbeat',{'boot_id':self.boot_id,'sessions':entries})
        active={item['name']:item['active'] for item in result['sessions']}
        with self.lock:
            for uid,session in self.sessions.items():
                ok=active.get(session['name'],False)
                self.session_health[uid]={'state':'online' if ok else 'expired',
                    'message':'Server session online; 15-minute disconnect grace' if ok else 'Server session expired or was released. RAM work is retained; old-session saves are blocked.',
                    'last_confirmed':time.time()}
        return result

    def heartbeats(self):
        while True:
            try:self.heartbeat_once()
            except Exception:
                with self.lock:
                    for uid in self.sessions:
                        previous=self.session_health.get(uid,{})
                        self.session_health[uid]={**previous,'state':'offline',
                            'message':'Server heartbeat unavailable. Pending work remains in RAM; the session expires after 15 minutes without contact.'}
            time.sleep(30)

    def drain_reports(self):
        import time
        while True:
            try:
                from client_policy import select_origin
                self.url=select_origin(self.config['server'],self.credentials)
                values=self.call('/v2/accounts')['accounts']
                policy=self.call('/v2/policy')
                dump(self.credentials/'server-origins.json',policy.get('client_policy',{}))
                try:
                    media=self.run/'media';location=self.run/'cache-location'
                    if location.is_file() and media.is_mount() and Path(location.read_text().strip())==media/'httpboot-v2/identity':
                        dump(media/'httpboot-v2/identity/server-origins.json',policy.get('client_policy',{}))
                except OSError:pass
                with self.lock:
                    self.sources=policy['sources'];self.supports_checkpoints=policy.get('snapshot_sets',False);self.pending_media=policy.get('pending_media');self.client_policy=policy.get('client_policy',{})
                    for account in values:
                        if str(account['uid']) in self.accounts:
                            self.accounts[str(account['uid'])].update({k:v for k,v in account.items() if k!='password_hash'})
            except Exception:pass
            self.refresh_images()
            try:
                from boot_reports import collect
                self.call('/v2/diagnostics',collect('desktop-ready'))
            except Exception:pass
            for path in sorted(self.report_dir.glob('*.json'))[:100]:
                try:self.call('/v2/diagnostics',load(path));path.unlink()
                except Exception:break
            time.sleep(30)

    def refresh_images(self):
        try:
            images=self.call('/v2/images')['images']
            current=load(Path('/run/httpboot/filesystem.metadata.json')).get('release') if Path('/run/httpboot/filesystem.metadata.json').is_file() else None
            latest=images[0]['release'] if images else None
            self.image_status={'state':'current' if latest==current and latest else 'available' if latest else 'empty',
                               'message':'No update is available.' if latest==current and latest else 'Latest validated image: '+latest if latest else 'No validated image has been published.',
                               'current':current,'latest':latest}
            if latest and latest!=current and self.client_policy.get('automatic_staging',False) and self.power.snapshot().get('state')!='running':
                operation=self.updates.snapshot()
                attempts,next_try=self.stage_attempts.get(latest,(0,0))
                limit=3 if self.client_policy.get('safe_repairs',True) else 1
                if attempts<limit and time.monotonic()>=next_try and operation.get('state')!='running' and not (operation.get('release')==latest and operation.get('phase')=='ready-to-restart'):
                    self.stage_attempts[latest]=(attempts+1,time.monotonic()+60*(2**attempts))
                    self.updates.start()
        except Exception as error:
            self.image_status={'state':'error','message':'Activation Server Error: '+str(error)[:300]}

    def check_recovery_background(self):
        # Never delay normal login on a full recovery-image readback.
        time.sleep(30)
        try:
            location=self.run/'cache-location';media=self.run/'media'
            if not location.is_file() or not media.is_mount():return
            identity=Path(location.read_text().strip())
            if identity!=media/'httpboot-v2/identity':return
            from recovery_cache import check_integrity
            check_integrity(identity)
        except Exception as error:self.queue_report(error)

    def serve(self):
        path=self.run/'control.sock';path.unlink(missing_ok=True)
        def handle(connection):
            with connection:
                try:
                    connection.settimeout(1800)
                    _,uid,_=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                    raw=b''
                    while not raw.endswith(b'\n'):
                        block=connection.recv(65536)
                        if not block:raise ValueError('Incomplete local request')
                        raw+=block
                        if len(raw)>8*1024*1024:raise ValueError('Local request too large')
                    result=self.dispatch(uid,json.loads(raw))
                except Exception as error:
                    self.queue_report(error);result={'error':str(error)[:1000]}
                try:connection.sendall(json.dumps(result).encode()+b'\n')
                except OSError:pass
        threading.Thread(target=self.check_recovery_background,daemon=True).start()
        threading.Thread(target=self.heartbeats,daemon=True).start()
        threading.Thread(target=self.drain_reports,daemon=True).start()
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
            server.bind(str(path));path.chmod(0o666);server.listen(16)
            notify=os.environ.get('NOTIFY_SOCKET')
            if notify:
                with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as notification:
                    notification.connect('\0'+notify[1:] if notify.startswith('@') else notify)
                    notification.sendall(b'READY=1')
            while True:
                connection,_=server.accept()
                threading.Thread(target=handle,args=(connection,),daemon=True).start()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,default=Path('/etc/httpboot/client-v2.json'))
    parser.add_argument('action',choices=('activate','serve','provision'))
    args=parser.parse_args()
    if os.geteuid()!=0:parser.error('Privileged Client service requires root')
    os.umask(0o077);agent=Agent(load(args.config))
    if args.action=='activate':
        if not agent.activate():
            print(json.dumps(load(agent.run/'activation.json')));raise SystemExit(2)
    elif args.action=='provision':agent.provision()
    else:
        if not agent.activate():raise ValueError('Please configure your server to allow this client.')
        while True:
            try:
                agent.provision()
                dump(agent.run/'provisioning.json',{'state':'ready','assigned_accounts':len(agent.accounts)},0o644)
                break
            except (ValueError,OSError,subprocess.CalledProcessError) as error:
                message=str(error) if isinstance(error,ValueError) else 'Account provisioning failed; inspect Server diagnostics'
                dump(agent.run/'provisioning.json',{'state':'waiting','message':message},0o644)
                print(message,flush=True)
                agent.queue_report()
                time.sleep(10)
        agent.serve()

if __name__=='__main__':main()
