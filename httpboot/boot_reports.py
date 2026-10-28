"""Allowlisted early-boot diagnostics, without command lines or credentials."""
import hashlib
import json
import re
import time
from pathlib import Path
from common import atomic,load

MAX_REPORT=256*1024

def sanitize(data):
    if not isinstance(data,dict) or data.get('schema') not in (1,2):raise ValueError('Invalid boot report')
    allowed={'schema','stage','exit_status','line','boot_id'}
    if data['schema']==2:
        allowed.add('details')
        details=data.get('details',{})
        fields={'kernel','hardware','interfaces','storage','provisioning','error_code','driver_errors'}
        if not isinstance(details,dict) or set(details)-fields:raise ValueError('Invalid diagnostic details')
        for key,value in details.items():
            if not isinstance(value,str) or len(value)>16000 or re.search(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]',value):raise ValueError('Invalid diagnostic detail')
            if re.search(r'password|passphrase|psk|private.key|ssid|/home/',value,re.I):raise ValueError('Private diagnostic content rejected')
    if len(json.dumps(data).encode())>MAX_REPORT:raise ValueError('Boot report too large')
    if set(data)-allowed:raise ValueError('Unknown boot report fields')
    if not isinstance(data.get('stage'),str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,63}',data['stage']):raise ValueError('Invalid boot stage')
    for name in ('exit_status','line'):
        if type(data.get(name)) is not int or not 0<=data[name]<=100000:raise ValueError('Invalid boot report status')
    if 'boot_id' in data and not re.fullmatch(r'[a-f0-9-]{36}',str(data['boot_id'])):raise ValueError('Invalid boot id')
    return {key:data[key] for key in sorted(allowed) if key in data}

def store(folder,data):
    raw=json.dumps(data).encode()
    if len(raw)>MAX_REPORT:raise ValueError('Boot report too large')
    clean=sanitize(data);raw=json.dumps(clean,sort_keys=True)+'\n'
    digest=hashlib.sha256(raw.encode()).hexdigest()
    path=folder/(digest+'.json')
    if path.is_symlink():raise ValueError('Report file must not be a symlink')
    if not path.exists():atomic(path,raw,0o600)
    else:__import__('os').utime(path,None,follow_symlinks=False)
    # Deduplicated, bounded queues cannot grow indefinitely during an outage.
    for old in sorted(folder.glob('*.json'),key=lambda p:p.stat().st_mtime,reverse=True)[100:]:old.unlink(missing_ok=True)
    return {'ok':True,'id':digest}

def display(state,identifier=None):
    if identifier and not re.fullmatch(r'[a-f0-9]{64}',identifier):raise ValueError('Invalid report id')
    for path in sorted((state/'devices').glob('*/boot-reports/*.json')):
        if identifier and path.stem!=identifier:continue
        data=sanitize(load(path))
        print(path.parent.parent.name+' '+path.stem+' '+json.dumps(data,sort_keys=True))


def collect(stage,code='none'):
    """Collect structured device facts even when no network interface exists."""
    import os,subprocess
    hardware=[]
    for device in sorted(Path('/sys/bus/pci/devices').glob('*')):
        try:
            if not (device/'class').read_text().startswith(('0x02','0x0c03')):continue
            values=dict(line.split('=',1) for line in (device/'uevent').read_text().splitlines() if '=' in line)
            hardware.append(device.name+' '+values.get('PCI_ID','unknown')+' driver='+values.get('DRIVER','unbound'))
        except OSError:continue
    for device in sorted(Path('/sys/bus/usb/devices').glob('*')):
        try:hardware.append('USB '+(device/'idVendor').read_text().strip()+':'+(device/'idProduct').read_text().strip())
        except OSError:continue
    interfaces=[]
    for interface in sorted(Path('/sys/class/net').glob('*')):
        driver=interface/'device/driver'
        interfaces.append(interface.name+' driver='+(driver.resolve().name if driver.exists() else 'none'))
    details={'kernel':os.uname().release,'hardware':'\n'.join(hardware)[:16000],'interfaces':'\n'.join(interfaces)[:4000],'error_code':code}
    kernel_log=subprocess.run(['dmesg'],capture_output=True,text=True).stdout
    lines=[line for line in kernel_log.splitlines() if re.search(r'rtw|iwl|firmware|xhci|mmc|rtsx',line,re.I) and not re.search(r'password|passphrase|psk|private.key|ssid|/home/',line,re.I)]
    details['driver_errors']='\n'.join(lines[-40:])[-12000:]
    for key,name in (('storage','identity-storage.json'),('provisioning','provisioning.json')):
        try:
            value=load(Path('/run/httpboot-v2')/name)
            details[key]=str(value.get('state','unknown'))
        except (OSError,ValueError):details[key]='unknown'
    return sanitize({'schema':2,'stage':stage,'exit_status':int(code!='none'),'line':0,
                     'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'details':details})


def import_report(state,file):
    file=Path(file)
    if not file.is_file() or file.is_symlink() or file.stat().st_size>MAX_REPORT:raise ValueError('Select a bounded JSON diagnostic report')
    return store(Path(state)/'reports'/'offline-import',sanitize(load(file)))


def export_report(destination,stage='offline-diagnostics'):
    destination=Path(destination).resolve(strict=True)
    if not destination.is_mount():raise ValueError('Select the mountpoint of an explicitly mounted report USB')
    report=collect(stage);folder=destination/'httpboot-reports'
    if folder.is_symlink():raise ValueError('Report destination must not be a symlink')
    return store(folder,report)


def health(authority):
    result=[]
    with authority.db(write=False) as db:
        clients=list(db.execute('SELECT id,approved,hardware FROM devices'))
        counts=dict(db.execute('SELECT device,COUNT(*) FROM assignments GROUP BY device'))
        sessions=list(db.execute('SELECT s.name,s.device,p.last_seen,p.boot_id FROM sessions s LEFT JOIN session_presence p ON s.name=p.name AND s.token=p.token'))
    for client in clients:
        files=list((authority.database.parent/'reports'/client['id']).glob('*.json'))
        latest=max(files,key=lambda p:p.stat().st_mtime) if files else None
        report=sanitize(load(latest)) if latest else None
        seen=latest.stat().st_mtime if latest else None
        result.append({'client':client['id'],'approved':bool(client['approved']),'assigned_accounts':counts.get(client['id'],0),
                       'duplicate_hardware':sum(row['hardware']==client['hardware'] for row in clients)>1,'last_contact':seen,'stale':seen is None or time.time()-seen>120,'report':report,'sessions':[{'name':s['name'],'online':s['last_seen'] is not None and time.time()-s['last_seen']<90,'grace_remaining_seconds':max(0,int(900-(time.time()-s['last_seen']))) if s['last_seen'] is not None else 0} for s in sessions if s['device']==client['id']]})
    return result


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--export',type=Path);parser.add_argument('--stage',default='network-diagnostics')
    args=parser.parse_args()
    if args.export:print(json.dumps(export_report(args.export,args.stage)))
    else:
        report=collect(args.stage)
        for folder in (Path('/run/httpboot-v2/reports'),Path('/run/httpboot-v2/media/httpboot-v2/identity/reports')):
            if folder.parts[-4:-1]==('media','httpboot-v2','identity') and not Path('/run/httpboot-v2/media').is_mount():continue
            try:store(folder,report)
            except OSError:pass
        print(json.dumps(report,indent=2))
