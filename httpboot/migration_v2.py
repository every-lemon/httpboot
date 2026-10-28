"""Transactional authority import; legacy images and verified saves remain untouched."""
import hashlib
import json
import re
import sqlite3
import subprocess
import time
from pathlib import Path
from common import atomic,load,validate_config


def restore_trust(authority,etc):
    legacy_ca=Path(etc)/'control-pki/ca.pem'
    public_ca=authority.database.parent/'pki/ca.pem'
    if legacy_ca.is_file() and public_ca.is_file():
        atomic(authority.database.parent/'pki/trusted-clients.pem',public_ca.read_bytes()+legacy_ca.read_bytes())


def migrate(authority,etc,legacy_state):
    import fcntl
    with open(Path(legacy_state)/'management.lock','a') as guard:
        try:fcntl.flock(guard,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise ValueError('Legacy maintenance is active; defer migration without interrupting Clients')
        return migrate_locked(authority,etc,legacy_state)


def migrate_locked(authority,etc,legacy_state):
    etc=Path(etc);legacy_state=Path(legacy_state)
    config=validate_config(load(etc/'server.json'))
    hashes=load(etc/'desktop-passwords.json')
    accounts=[]
    for user in config['users']:
        name=user['name'];hashed=hashes.get(name,'')
        if not re.fullmatch(r'\$(6|y)\$[A-Za-z0-9./$]+',hashed):raise ValueError('Legacy password hash missing or invalid')
        rules=[{'folder':'.config/google-chrome','mode':'folder','source':None},
               {'folder':'.config/ChatGPT','mode':'folder','source':None},
               {'folder':'.var/app/org.vinegarhq.Sober','mode':'folder','source':None},
               {'folder':'.var/app/org.prismlauncher.PrismLauncher','mode':'folder','source':None}]
        if user['workspace']:rules.append({'folder':'workspace','mode':'folder','source':None})
        accounts.append((name,user['uid'],user['gid'],hashed,'edit' if user['admin'] else 'status',json.dumps(rules)))
    devices=[]
    for record in (legacy_state/'devices').glob('dell-*/identity.json'):
        identifier=load(record)['id']
        if not re.fullmatch(r'dell-[0-9a-f]{32}',identifier):raise ValueError('Invalid legacy device identity')
        certfile=record.parent/'client.pem'
        cert=certfile.read_text()
        public=subprocess.run(['openssl','x509','-pubkey','-noout'],input=cert.encode(),capture_output=True,check=True).stdout
        devices.append((identifier,hashlib.sha256(public).hexdigest(),json.dumps({'migration':'legacy-enrolled-card'}),cert))
    source=hashlib.sha256((etc/'server.json').read_bytes()+(etc/'desktop-passwords.json').read_bytes()).hexdigest()
    backup=authority.database.with_name('before-migration-'+str(time.time_ns())+'.sqlite3')
    with sqlite3.connect(authority.database) as original,sqlite3.connect(backup) as target:original.backup(target)
    backup.chmod(0o600)
    with authority.db() as db:
        previous=db.execute("SELECT value FROM settings WHERE key='legacy-import'").fetchone()
        if previous:
            if json.loads(previous[0])['source']!=source:raise ValueError('Legacy source changed after migration; review before another import')
            marker=json.loads(previous[0])
            if not marker.get('system_admin_imported'):
                for user in config['users']:
                    db.execute('UPDATE accounts SET system_admin=? WHERE name=? AND uid=? AND gid=?',(int(user['admin']),user['name'],user['uid'],user['gid']))
                marker['system_admin_imported']=True
                db.execute("UPDATE settings SET value=? WHERE key='legacy-import'",(json.dumps(marker),))
            restore_trust(authority,etc)
            return {'ok':True,'unchanged':True}
        for account in accounts:
            if db.execute('SELECT 1 FROM accounts WHERE name=? OR uid=? OR gid=?',account[:3]).fetchone():
                raise ValueError('Migration conflicts with an existing stable account')
            db.execute('INSERT INTO accounts(name,uid,gid,password_hash,access,rules) VALUES (?,?,?,?,?,?)',account)
        for user in config['users']:
            db.execute('UPDATE accounts SET system_admin=? WHERE name=?',(int(user['admin']),user['name']))
        for identifier,fingerprint,hardware,cert in devices:
            db.execute('INSERT INTO devices(id,fingerprint,hardware,approved,certificate) VALUES (?,?,?,1,?)',
                       (identifier,fingerprint,hardware,cert))
            for account in accounts:db.execute('INSERT INTO assignments VALUES (?,?)',(account[0],identifier))
        marker={'source':source,'created':authority.clock(),'legacy_data':config['data_dir'],
                'backup':str(backup),'phase':'authority-imported','legacy_service_required':True,'system_admin_imported':True}
        db.execute("INSERT INTO settings VALUES ('legacy-import',?)",(json.dumps(marker),))
        from schedule_policy import defaults
        db.execute("INSERT OR IGNORE INTO settings VALUES ('schedules',?)",(json.dumps(defaults('Asia/Taipei')),))
    restore_trust(authority,etc)
    return {'ok':True,'accounts':len(accounts),'clients':len(devices),'backup':str(backup),'legacy_service_required':True}
