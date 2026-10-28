"""Durable update policy and host package transactions; no automatic cleanup."""
import contextlib
import datetime
import fcntl
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from zoneinfo import ZoneInfo
from common import dump, load, run
from apt_tools import keep_downloads

STATE=Path('/var/lib/httpboot')
SERVICE_ETC=Path('/etc')

def in_progress(state=STATE):
    path=state/'maintenance.json'
    return path.exists() and load(path).get('packages_started') is True

def daily_due(last, now=None):
    now=datetime.datetime.fromtimestamp(now or time.time(),ZoneInfo('Asia/Taipei'))
    today=now.replace(hour=4,minute=0,second=0,microsecond=0).timestamp()
    return now.hour>=4 and last<today

def consent(clients, request_id, now=None):
    now=time.time() if now is None else now
    active=[c for c in clients if now-c.get('seen',0)<900]
    if not active:return 'idle'
    relevant=[c for c in active if c.get('request_id')==request_id]
    if len(relevant)==len(active) and all(c.get('decision')=='yes' and c.get('synced') is True for c in relevant):return 'ready'
    if any(c.get('decision')=='no' and now-c.get('decision_at',0)<3600 for c in relevant):return 'postponed'
    return 'approval-required'

@contextlib.contextmanager
def reserved(role, state=STATE, cache=Path('/var/lib/httpboot-build-cache')):
    """Same ordering as tool activation, then the actual worker lock."""
    handles=[]
    try:
        paths=[state/'management.lock',state/'update.lock']
        if role=='builder':
            cache.mkdir(parents=True,exist_ok=True);paths.append(cache/'worker.lock')
        for path in paths:
            path.parent.mkdir(parents=True,exist_ok=True)
            handle=open(path,'a');handles.append(handle)
            fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield
    finally:
        for handle in reversed(handles):handle.close()

def packages(logdir):
    """Caller holds maintenance/build locks and has already obtained consent."""
    logdir.mkdir(parents=True,exist_ok=True,mode=0o700)
    keep_downloads()
    env={**os.environ,'DEBIAN_FRONTEND':'noninteractive','NEEDRESTART_MODE':'l','LC_ALL':'C'}
    options=['-o','DPkg::Lock::Timeout=300','-o','Acquire::Retries=3',
             '-o','Dpkg::Options::=--force-confold']
    with open(logdir/'apt.log','a') as log:
        def execute(command, retry_dpkg_lock=False):
            deadline=time.monotonic()+600
            log.write('Running: '+' '.join(command)+'\n');log.flush()
            while True:
                offset=log.tell()
                proc=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,env=env)
                log.flush();os.fsync(log.fileno())
                if not proc.returncode:return
                # dpkg has no APT-style lock timeout. Retry only its explicit
                # lock refusal; package/script failures must remain failures.
                with open(logdir/'apt.log') as output:
                    output.seek(offset);failure=output.read()
                locked=re.search(r'^dpkg: error: (?:dpkg frontend lock|dpkg database lock|dpkg status database(?: area)?) (?:was |is )?locked by another process',failure,re.M)
                if not retry_dpkg_lock or not locked:
                    raise ValueError(f'Package operation stopped; retained log: {logdir}/apt.log')
                if time.monotonic()>=deadline:
                    raise ValueError(f'Package manager remained busy for 10 minutes; retained log: {logdir}/apt.log')
                log.write('Waiting for the other package manager; existing locks are retained.\n');log.flush()
                time.sleep(5)
        execute(['dpkg','--force-confold','--configure','-a'],retry_dpkg_lock=True)
        execute(['apt-get',*options,'--no-remove','--fix-broken','install','-y'])
        execute(['apt-get',*options,'update'])
        # --no-remove makes both the simulation and actual transaction fail closed.
        execute(['apt-get',*options,'--simulate','--no-remove','upgrade','--with-new-pkgs'])
        execute(['apt-get',*options,'--no-remove','upgrade','--with-new-pkgs','-y'])
        execute(['apt-get','check'])
        audit=run(['dpkg','--audit'],capture_output=True,text=True).stdout.strip()
        if audit:raise ValueError('dpkg audit is not clean: '+audit[:1000])
    return Path('/var/run/reboot-required').exists()

def healthy(role):
    if role=='pi':repair_services()
    units=['httpboot-builder.service'] if role=='builder' else ['nginx.service','nfs-ganesha.service','httpboot-control.service']
    for unit in units:run(['systemctl','is-active','--quiet',unit])
    if role=='pi':
        import storage
        from common import validate_config
        storage.check_config(validate_config(load(Path('/etc/httpboot/server.json'))))
        run(['nginx','-t'],capture_output=True)
        config=validate_config(load(Path('/etc/httpboot/server.json')))
        if (Path(config['web_dir'])/'current/boot.efi').exists():
            run(['curl','--fail','--silent','--show-error','--head','--max-time','10',
                 config['boot_base_url']+'/current/boot.efi'],capture_output=True)
    run(['apt-get','check'],capture_output=True)
    if run(['dpkg','--audit'],capture_output=True,text=True).stdout.strip():
        raise ValueError('Package configuration is incomplete')
    return True

def repair_services():
    """Idempotent managed-service repair; never bypass storage verification."""
    import storage
    from common import atomic,validate_config
    config=validate_config(load(SERVICE_ETC/'httpboot/server.json'))
    storage.check_config(config)
    public=[Path(config['web_dir']),Path(config['web_dir'])/'releases']
    if config.get('schema')==2:public.insert(0,Path(config['storage']['mountpoint'])/'httpboot')
    for path in public:
        if path.is_symlink():raise ValueError('Public boot directory must not be a symlink')
        if path.exists():path.chmod(0o755)
    unit_text=('[Unit]\nWants=network-online.target\nAfter=network-online.target\n'
               '[Service]\nRestart=on-failure\nRestartSec=10s\n')
    changes={SERVICE_ETC/'systemd/system'/(name+'.service.d/httpboot-network.conf'):unit_text
             for name in ('nginx','nfs-ganesha')}
    ganesha=SERVICE_ETC/'ganesha/ganesha.conf'
    text=ganesha.read_text()
    if text.startswith('# Managed by httpboot.'):
        changes[ganesha]=re.sub(r'(?<![0-9.])0\.0\.0\.0/0(?![0-9])','*',text)
    changed=[]
    for path,text in changes.items():
        if path.exists() and path.read_text()==text:continue
        backup=STATE/'service-repairs'/str(time.time_ns());backup.mkdir(parents=True,mode=0o700)
        if path.exists():shutil.copy2(path,backup/path.name)
        atomic(path,text,0o644);changed.append(path)
    if changed:run(['systemctl','daemon-reload'])
    for unit in ('nginx.service','nfs-ganesha.service','httpboot-control.service'):
        if ganesha in changed and unit=='nfs-ganesha.service':run(['systemctl','restart',unit])
        else:run(['systemctl','start',unit])
