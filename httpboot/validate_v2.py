"""Qualify the production v2 initramfs through authenticated RAM boot and offline X startup."""
import argparse
import base64
import gzip
import hashlib
import json
import os
import re
import selectors
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from common import atomic,dump,load,run,sha256
from control_transport import Server,ca,key_request,issue
from server_v2 import Authority,csr_key
from image_delivery import ARTIFACTS,ImageHandler

SOURCE=Path(__file__).resolve().parents[1]
VALIDATOR_SHA256=sha256(Path(__file__))


def log_path(source,case):
    """Keep serial capture responsive when file-backed guest RAM is paging."""
    if case not in ('native-http','desktop','recovery'):raise ValueError('Invalid qualification log')
    directory=os.environ.get('HTTPBOOT_QUALIFY_LOG_DIR')
    folder=Path(directory) if directory else Path(source)
    folder.mkdir(parents=True,exist_ok=True)
    return folder/('startup-v2-'+case+'.log')


def stage_budget():
    """Permit bounded extra time on memory-constrained emulation hosts."""
    try:seconds=int(os.environ.get('HTTPBOOT_QUALIFY_STAGE_SECONDS','180'))
    except ValueError:raise ValueError('Qualification stage budget must be an integer from 180 to 600 seconds')
    if not 180<=seconds<=600:raise ValueError('Qualification stage budget must remain between 180 and 600 seconds')
    return seconds


def fresh_http(efi,source,authority,work,timeout=300):
    """Exercise firmware HTTP download and a device-generated first-boot CSR."""
    work.mkdir();requests=[]
    class Bootstrap(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def respond(self,body):
            if self.path!='/boot.efi':self.send_error(404);return
            self.send_response(200)
            self.send_header('Content-Length',str(efi.stat().st_size))
            self.send_header('Content-Type','application/octet-stream');self.end_headers()
            if body:
                with efi.open('rb') as stream:shutil.copyfileobj(stream,self.wfile)
                requests.append('GET')
        def do_HEAD(self):self.respond(False)
        def do_GET(self):self.respond(True)
    bootstrap=ThreadingHTTPServer(('127.0.0.1',0),Bootstrap)
    thread=threading.Thread(target=bootstrap.serve_forever,daemon=True);thread.start()
    process=None;log=bytearray();temporary_selected=False;temporary_confirmed=False;interrupt_sent=False
    try:
        run(['virt-fw-vars','-i','/usr/share/OVMF/OVMF_VARS_4M.fd',
             '--set-boot-uri',f'http://10.0.2.2:{bootstrap.server_port}/boot.efi','-o',work/'vars.fd'])
        command=['qemu-system-x86_64','-machine','q35,accel=tcg','-cpu','max','-m','1024','-smp','2',
                 '-display','none','-serial','stdio','-monitor','none','-no-reboot',
                 '-drive','if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                 '-drive','if=pflash,format=raw,unit=1,file='+str(work/'vars.fd'),
                 '-netdev','user,id=net','-device','virtio-net-pci,netdev=net',
                 '-fw_cfg','name=opt/org.tianocore/IPv4PXESupport,string=no',
                 '-fw_cfg','name=opt/org.tianocore/IPv6PXESupport,string=no']
        process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        deadline=time.monotonic()+timeout;last=time.monotonic()
        with selectors.DefaultSelector() as poll:
            poll.register(process.stdout,selectors.EVENT_READ)
            while process.poll() is None and time.monotonic()<deadline:
                for key,_ in poll.select(1):
                    block=os.read(key.fd,65536)
                    if block:log.extend(block)
                if not interrupt_sent and b'httpboot: device-discovery' in log:
                    process.stdin.write(b'\x03');process.stdin.flush();interrupt_sent=True
                if b'Use temporary identity' in log and b'<Ok>' in log[log.find(b'Use temporary identity'):] and not temporary_selected:
                    time.sleep(0.3)
                    process.stdin.write(b't\r');process.stdin.flush();temporary_selected=True
                if b'Approval will not survive' in log and b'<Ok>' in log[log.find(b'Approval will not survive'):] and not temporary_confirmed:
                    time.sleep(0.3)
                    process.stdin.write(b'\r');process.stdin.flush();temporary_confirmed=True
                if b'Activation Server Error:' in log or b'Kernel panic' in log:
                    raise ValueError('Fresh HTTP bootstrap failed before pairing; inspect startup-v2-native-http.log')
                match=re.search(rb'Pairing code: ([A-Za-z0-9]{6}) ',log)
                if match and b'Please configure your server to allow this client.' in log and requests:
                    # Confirm the screen follows an actual unauthenticated CSR
                    # registration, rather than accepting a printed fixture.
                    with authority.db() as db:
                        row=db.execute('SELECT approved FROM devices WHERE code=?',(match[1].decode(),)).fetchone()
                    if row is None or row['approved']:raise ValueError('Fresh Client pairing was not recorded as pending')
                    if not interrupt_sent:raise ValueError('Native HTTP boot interrupt protection was not exercised')
                    return
                if time.monotonic()-last>=30:
                    atomic(log_path(source,'native-http'),bytes(log))
                    print('HTTPBOOT_STAGE:v2 fresh native HTTP boot remains in progress',flush=True);last=time.monotonic()
        raise ValueError('Fresh native HTTP boot did not reach device pairing')
    finally:
        if process is not None:
            process.terminate()
            try:process.wait(timeout=10)
            except subprocess.TimeoutExpired:process.kill();process.wait()
            process.stdout.close()
        bootstrap.shutdown();thread.join(10);bootstrap.server_close()
        atomic(log_path(source,'native-http'),bytes(log))


def overlay(original,output,files):
    if set(files)!={'httpboot/server-ca.pem','httpboot/client-v2.json'}:raise ValueError('Qualification may change only bootstrap Server configuration')
    data=bytearray();inode=1
    for name,content in files.items():
        encoded=name.encode()+b'\0'
        values=(inode,0o100600,0,0,1,0,len(content),0,0,0,0,len(encoded),0)
        data.extend(b'070701'+b''.join(f'{v:08x}'.encode() for v in values)+encoded)
        data.extend(bytes((-len(data))%4));data.extend(content);data.extend(bytes((-len(data))%4));inode+=1
    name=b'TRAILER!!!\0';values=(inode,0,0,0,1,0,0,0,0,0,0,len(name),0)
    data.extend(b'070701'+b''.join(f'{v:08x}'.encode() for v in values)+name);data.extend(bytes((-len(data))%512))
    with open(original,'rb') as source,open(output,'xb') as target:
        shutil.copyfileobj(source,target);target.write(bytes((-target.tell())%4));target.write(gzip.compress(bytes(data),mtime=0))


def guest(efi,source,identity,manifest,work,recovery,password=None,timeout=2400):
    stage_seconds=stage_budget()
    work.mkdir();disk=work/'card.img'
    size=(source/'recovery.squashfs').stat().st_size+efi.stat().st_size+256*1024**2
    with open(disk,'wb') as stream:stream.truncate(((size+1024**2-1)//1024**2)*1024**2)
    run(['sfdisk',disk],input='label: gpt\nstart=2048, type=c12a7328-f81f-11d2-ba4b-00a0c93ec93b\n',text=True,capture_output=True)
    fat=str(disk)+'@@1048576'
    run(['mformat','-i',fat,'-F','::'],capture_output=True)
    run(['mmd','-i',fat,'::/EFI','::/EFI/BOOT','::/httpboot-v2','::/httpboot-v2/identity'],capture_output=True)
    run(['mcopy','-i',fat,efi,'::/EFI/BOOT/BOOTX64.EFI'],capture_output=True)
    for name in ('client.key','client.csr','client.pem','ca.pem'):
        run(['mcopy','-i',fat,identity/name,'::/httpboot-v2/identity/'+name],capture_output=True)
    run(['mcopy','-i',fat,source/'recovery.squashfs','::/httpboot-v2/identity/recovery.squashfs'],capture_output=True)
    manifest_path=work/'verified-image.json';dump(manifest_path,manifest)
    run(['mcopy','-i',fat,manifest_path,'::/httpboot-v2/identity/verified-image.json'],capture_output=True)
    shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd',work/'vars.fd')
    image=source/('recovery.squashfs' if recovery else 'filesystem.squashfs')
    memory=max(4096,(image.stat().st_size+1024**2-1)//1024**2+3072)
    command=['qemu-system-x86_64','-machine','q35,accel=tcg','-cpu','max','-m',str(memory),'-smp','2','-display','none','-serial','stdio','-monitor','none','-no-reboot',
             '-drive','if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
             '-drive','if=pflash,format=raw,unit=1,file='+str(work/'vars.fd'),'-drive','format=raw,file='+str(disk),
             '-netdev','user,id=net','-device','virtio-net-pci,netdev=net',
             '-device','virtio-balloon-pci,free-page-reporting=on']
    expected=b'HTTPBOOT_RECOVERY_DISPLAY_STARTED' if recovery else b'HTTPBOOT_SYSTEMD_STARTED'
    process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    log=bytearray();deadline=time.monotonic()+timeout;last=time.monotonic();answered=False;interrupt_sent=False
    login_stage=0;logout_offset=0;display_ready=False;login_deadline=None;deadline_stage=0;last_power_status=0
    try:
        with selectors.DefaultSelector() as poll:
            poll.register(process.stdout,selectors.EVENT_READ)
            while process.poll() is None and time.monotonic()<deadline:
                # Bound each meaningful login/save/logout stage independently.
                # A slow RAM-backed VM must not spend the logout allowance on
                # authentication and restore; the total guest deadline still applies.
                if login_stage!=deadline_stage:
                    deadline_stage=login_stage;login_deadline=time.monotonic()+stage_seconds
                if login_deadline is not None and time.monotonic()>login_deadline:
                    raise ValueError('Assigned account login/restore/save/logout timed out at stage '+str(login_stage))
                for key,_ in poll.select(1):
                    block=os.read(key.fd,65536)
                    if not block:continue
                    log.extend(block)
                    if len(log)>8*1024**2:del log[:-8*1024**2]
                    if not recovery and not interrupt_sent and b'Downloading and verifying the Client image' in log:
                        process.stdin.write(b'\x03');process.stdin.flush();interrupt_sent=True
                    if recovery and not answered and b'Choose an available recovery action' in log and b'<Ok>' in log[log.find(b'Choose an available recovery action'):] :
                        process.stdin.write(b'\x03');process.stdin.flush();interrupt_sent=True
                        time.sleep(0.3)
                        process.stdin.write(b'\r');process.stdin.flush();answered=True
                    if expected in log:
                        if recovery:return {'interrupt_verified':interrupt_sent}
                        display_ready=True
                        if login_deadline is None:login_deadline=time.monotonic()+stage_seconds
                    if not recovery and display_ready:
                        if login_stage==0:
                            process.stdin.write(b'\r');process.stdin.flush();login_stage=1
                        if login_stage==1 and b'login:' in log:
                            process.stdin.write(b'bootcheck\r');process.stdin.flush();login_stage=2
                        elif login_stage==2 and b'Password:' in log:
                            process.stdin.write(password.encode()+b'\r');process.stdin.flush();login_stage=3
                        elif login_stage==3 and b'bootcheck@' in log:
                            command="if test \"$(id -u)\" = 1100 && test \"$(cat \"$HOME/Documents/restore.txt\")\" = qualification-restore-fixture && printf '%s' qualification-save-fixture >\"$HOME/Documents/check.txt\" && python3 /usr/local/lib/httpboot/client_worker.py save; then printf '\\n%s%s\\n' HTTPBOOT_ASSIGNED_ LOGIN_VERIFIED; else printf '\\n%s%s\\n' HTTPBOOT_LOGIN_ CHECK_FAILED; fi\r"
                            check="import signal,sys;sys.path.insert(0,'/usr/local/lib/httpboot');from client_agent import rpc;p=rpc('state')['status']['general'];assert signal.getsignal(signal.SIGINT)!=signal.SIG_IGN;assert p.get('stage')=='complete' and p['bytes_done']==p['bytes_total']"
                            command=command.replace('if test ','if python3 -c '+shlex.quote(check)+' && test ',1)
                            process.stdin.write(command.encode());process.stdin.flush();login_stage=4
                        elif login_stage==4 and b'HTTPBOOT_ASSIGNED_LOGIN_VERIFIED' in log:
                            logout_offset=len(log);process.stdin.write(b'exit\r');process.stdin.flush();login_stage=5
                        elif login_stage==5 and b'login:' in log[logout_offset:]:
                            logout_offset=len(log);process.stdin.write(b'bootcheck\r');process.stdin.flush();login_stage=6
                        elif login_stage==6 and b'Password:' in log[logout_offset:]:
                            logout_offset=len(log);process.stdin.write(password.encode()+b'\r');process.stdin.flush();login_stage=7
                        elif login_stage==7 and b'bootcheck@' in log[logout_offset:]:
                            command="python3 -c \"import sys; sys.path.insert(0,'/usr/local/lib/httpboot'); from client_agent import rpc; rpc('power',operation='poweroff'); print('HTTPBOOT_POWER_'+'REQUESTED')\"\r"
                            process.stdin.write(command.encode());process.stdin.flush();login_stage=8
                        elif login_stage==8 and b'HTTPBOOT_POWER_REQUESTED' in log and b'Power down' in log:return {'interrupt_verified':interrupt_sent}
                        if login_stage==8:
                            replies=re.findall(rb'HTTPBOOT_POWER_STATUS=(\{[^\r\n]+\})',log)
                            if replies:
                                power=json.loads(replies[-1])
                                if power.get('state')=='failed':raise ValueError('Client shutdown failed: '+power.get('message','Unknown power failure'))
                        if b'Login incorrect' in log or b'HTTPBOOT_LOGIN_CHECK_FAILED' in log:
                            raise ValueError('Assigned account login, restore or authenticated save failed')
                    if b'Kernel panic' in log or b'Freezing execution' in log:raise ValueError('Production v2 kernel/systemd startup failed')
                if not recovery and login_stage==8 and time.monotonic()-last_power_status>=10:
                    command="python3 -c \"import sys,json; sys.path.insert(0,'/usr/local/lib/httpboot'); from client_agent import rpc; print('HTTPBOOT_POWER_'+'STATUS='+json.dumps(rpc('state')['power']))\"\r"
                    try:process.stdin.write(command.encode());process.stdin.flush()
                    except BrokenPipeError:
                        if process.poll()==0 and b'HTTPBOOT_POWER_REQUESTED' in log:return {'interrupt_verified':interrupt_sent}
                        raise
                    last_power_status=time.monotonic()
                if time.monotonic()-last>=30:
                    atomic(log_path(source,'recovery' if recovery else 'desktop'),bytes(log))
                    print('HTTPBOOT_STAGE:v2 '+('offline recovery' if recovery else 'authenticated desktop')+' boot remains in progress',flush=True);last=time.monotonic()
            if not recovery and login_stage==8 and process.poll()==0 and b'HTTPBOOT_POWER_REQUESTED' in log:return {'interrupt_verified':interrupt_sent}
            raise ValueError('Production v2 boot did not reach '+expected.decode())
    finally:
        process.terminate()
        try:process.wait(timeout=10)
        except subprocess.TimeoutExpired:process.kill();process.wait()
        process.stdin.close();process.stdout.close()
        atomic(log_path(source,'recovery' if recovery else 'desktop'),bytes(log))


def verify_runtime_dns(source):
    listing=subprocess.run(['unsquashfs','-ll',str(Path(source)/'filesystem.squashfs'),'etc/resolv.conf'],check=True,capture_output=True,text=True).stdout
    expected='squashfs-root/etc/resolv.conf -> /run/systemd/resolve/stub-resolv.conf'
    if not any(line.startswith('l') and line.endswith(expected) for line in listing.splitlines()):
        raise ValueError('Client image DNS contains build-time settings; restore the runtime resolver before qualification')


def check(source):
    source=Path(source).resolve()
    if load(source/'release.json').get('schema')!=2:raise ValueError('Use artifacts from the generic v2 Builder')
    for name in ('qemu-system-x86_64','mcopy','mformat','mmd','sfdisk','cpio','virt-fw-vars'):
        if not shutil.which(name):raise ValueError('Install Builder validation prerequisite: '+name)
    verify_runtime_dns(source)
    import pefile
    for name in ('boot.efi','recovery.efi'):
        image=pefile.PE(str(source/name),fast_load=True)
        try:
            sections={s.Name.rstrip(b'\0').decode():s for s in image.sections}
            if sections['.uname'].get_data()[:sections['.uname'].Misc_VirtualSize].rstrip(b'\0').decode().strip()!=load(source/'release.json')['kernel']:
                raise ValueError('EFI kernel version differs from release metadata')
            if hashlib.sha256(sections['.linux'].get_data()[:sections['.linux'].Misc_VirtualSize]).hexdigest()!=sha256(source/'vmlinuz'):
                raise ValueError('EFI kernel differs from the staged kernel')
            if hashlib.sha256(sections['.initrd'].get_data()[:sections['.initrd'].Misc_VirtualSize]).hexdigest()!=sha256(source/'initrd'):
                raise ValueError('EFI initramfs differs from the staged initramfs')
        finally:image.close()
    records={name:{'size':(source/name).stat().st_size,'sha256':sha256(source/name)} for name in ARTIFACTS}
    with tempfile.TemporaryDirectory(prefix='httpboot-v2-qualification-',dir=source.parent) as temporary:
        work=Path(temporary);view=work/'view'
        from initrd_reader import extract
        extract(source/'initrd',view)
        for name,target in (('init','init'),('init-v2-rest','httpboot/init-v2-rest'),('boot-guard.sh','httpboot/boot-guard.sh')):
            if (view/target).read_bytes()!=(SOURCE/'client'/name).read_bytes():raise ValueError('Qualification requires current production startup code')
        for name in ('boot_client_v2.py','client_policy.py','recovery_cache.py','control_transport.py','image_delivery.py'):
            if (view/'httpboot/v2'/name).read_bytes()!=(SOURCE/'httpboot'/name).read_bytes():raise ValueError('Qualification requires current production bootstrap module: '+name)
        authority=Authority(work/'server/authority.db');pki=authority.database.parent/'pki';ca(pki,'10.0.2.2')
        identity=work/'identity';csr=key_request(identity,'qualification');peer='client-'+__import__('secrets').token_hex(16)
        atomic(identity/'ca.pem',(pki/'ca.pem').read_bytes());certificate=issue(pki,csr,peer);atomic(identity/'client.pem',certificate)
        with authority.db() as db:
            db.execute('INSERT INTO devices(id,fingerprint,hardware,approved,certificate) VALUES (?,?,?,1,?)',
                       (peer,csr_key(csr),json.dumps({'migration':'legacy-enrolled-card'}),certificate))
        password=__import__('secrets').token_urlsafe(24)
        password_hash=run(['openssl','passwd','-6','-stdin'],input=password.encode()+b'\n',capture_output=True).stdout.decode().strip()
        authority.account('bootcheck',1100,1100,password_hash,'status');authority.assign('bootcheck',peer)
        with authority.db() as db:
            db.execute('UPDATE accounts SET rules=? WHERE name=?',(json.dumps([{'folder':'Documents','mode':'folder','source':None}]),'bootcheck'))
        session={'name':'bootcheck',**authority.acquire(peer,'bootcheck')}
        seed=b'qualification-restore-fixture';digest=hashlib.sha256(seed).hexdigest()
        authority.snapshots.dispatch('put',peer,{**session,'digest':digest,'content':base64.b64encode(seed).decode()})
        authority.snapshots.dispatch('commit',peer,{**session,'folder':'Documents','files':{'restore.txt':{'size':len(seed),'chunks':[digest]}}})
        authority.release('bootcheck')
        # The isolated test catalogue never calls the production publication API.
        manifest={'schema':2,'release':'qualification','architecture':'amd64','kernel':load(source/'release.json')['kernel'],'artifacts':records}
        signature=run(['openssl','dgst','-sha256','-sign',pki/'server.key'],input=json.dumps(manifest,sort_keys=True,separators=(',',':')).encode(),capture_output=True).stdout
        manifest['signature']=base64.b64encode(signature).decode();manifest['signer']=(pki/'server.pem').read_text()
        folder=authority.images.root/'qualification';folder.mkdir()
        from build_cache import link_or_copy
        for name in ARTIFACTS:link_or_copy(source/name,folder/name)
        with authority.db() as db:db.execute('INSERT INTO images VALUES (?,?,?,1)',('qualification',json.dumps(manifest),time.time()))
        server=Server(('127.0.0.1',0),pki,authority,handler=ImageHandler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            config={'schema':2,'server':f'https://10.0.2.2:{server.server_port}','ca':'/httpboot/server-ca.pem'}
            initrd=work/'initrd';overlay(source/'initrd',initrd,{'httpboot/server-ca.pem':(pki/'ca.pem').read_bytes(),'httpboot/client-v2.json':json.dumps(config).encode()})
            osrel=work/'os-release';atomic(osrel,'ID=httpboot-qualification\nNAME="HTTP Boot qualification"\nVERSION_ID=3.1.15\n')
            for recovery in (False,True):
                efi=work/('recovery.efi' if recovery else 'desktop.efi')
                command='console=ttyS0 loglevel=3'+(' httpboot.recovery=1' if recovery else '')
                run(['/usr/lib/systemd/ukify','build','--linux',source/'vmlinuz','--initrd',initrd,'--cmdline',command,'--os-release','@'+str(osrel),'--output',efi])
                if not recovery:fresh_http(efi,source,authority,work/'fresh-http')
                if recovery:server.shutdown();thread.join(10) # The second boot must work without authorization service.
                case=work/('offline' if recovery else 'online')
                result=guest(efi,source,identity,manifest,case,recovery,password)
                if not result.get('interrupt_verified'):raise ValueError('Startup Ctrl+C protection was not exercised')
                if not recovery:
                    with authority.db() as db:
                        if db.execute('SELECT 1 FROM sessions WHERE name=?',('bootcheck',)).fetchone():
                            raise ValueError('PAM logout did not release the persistent test session')
                        saved=db.execute('SELECT manifest FROM snapshots WHERE owner=? AND rule=? ORDER BY rowid DESC LIMIT 1',('bootcheck','Documents')).fetchone()
                        files=json.loads(saved[0])
                        if files.get('check.txt',{}).get('chunks')!=[hashlib.sha256(b'qualification-save-fixture').hexdigest()]:
                            raise ValueError('Assigned account did not commit its test document')
                for transient in ('ram.bin','card.img','vars.fd'):(case/transient).unlink(missing_ok=True)
        finally:
            if thread.is_alive():server.shutdown();thread.join(10)
            server.server_close()
    if sha256(Path(__file__))!=VALIDATOR_SHA256:
        raise ValueError('Validator source changed during qualification; rerun before publication')
    proof={'schema':2,'architecture':'amd64','kernel':load(source/'release.json')['kernel'],'startup_verified':True,'recovery_verified':True,'assigned_login_verified':True,'native_http_pairing_verified':True,'clean_shutdown_verified':True,'startup_interrupt_verified':True,
           'validator_sha256':VALIDATOR_SHA256,'stage_timeout_seconds':stage_budget(),'artifacts':records}
    dump(source/'qualification-v2.json',proof)
    return proof

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('artifacts',type=Path)
    print(json.dumps(check(parser.parse_args().artifacts)))
