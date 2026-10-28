"""Opt-in version 2 Server authority. Legacy Clients keep their existing service."""
import argparse
import hashlib
import json
import re
import secrets
import sqlite3
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

from common import NAME
from product_version import VERSION

UNKNOWN = 'Please configure your server to allow this client.'
ACCESS = ('none', 'status', 'edit')


def folder_rule(value):
    if not isinstance(value, str) or len(value) > 1024:
        raise ValueError('Invalid home folder')
    path = PurePosixPath(value)
    if not value or path.is_absolute() or any(p in ('', '.', '..') for p in value.split('/')):
        raise ValueError('Select a relative folder inside your home')
    return path.as_posix()


def validate_rules(rules):
    if not isinstance(rules, list) or len(rules) > 129 or (len(rules)==129 and not any(isinstance(r,dict) and r.get('folder')=='.ssh' for r in rules)):
        raise ValueError('At most 128 persistence rules are allowed')
    names = set()
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) != ({'folder','mode','source','process'} if rule.get('mode')=='closed-folder' else {'folder','mode','source'}):
            raise ValueError('Invalid persistence rule')
        name = folder_rule(rule['folder'])
        if name in names or rule['mode'] not in ('folder', 'closed-folder', 'app-only', 'app-and-data'):
            raise ValueError('Duplicate folder or invalid persistence mode')
        if rule['mode'] in ('folder','closed-folder') and rule['source'] is not None:
            raise ValueError('Folder rules have no application source')
        if rule['mode'] not in ('folder','closed-folder') and not isinstance(rule['source'], str):
            raise ValueError('Applications require an administrator-approved source')
        if rule['mode']=='closed-folder' and (not isinstance(rule['process'],str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',rule['process'])):
            raise ValueError('Application data requires an executable name to verify closure')
        if rule['mode']=='app-only' and not name.startswith('.local/share/httpboot/flatpak-bundles/'):
            raise ValueError('App-only rules must select Flatpak installation bundles, separately from private app data')
        names.add(name)
    return rules


def csr_key(csr):
    if not isinstance(csr, str) or len(csr) > 16384:
        raise ValueError('Invalid device CSR')
    verified = subprocess.run(['openssl', 'req', '-verify', '-noout'], input=csr.encode(),
                              capture_output=True, timeout=10)
    if verified.returncode:
        raise ValueError('Device CSR proof failed')
    result = subprocess.run(['openssl', 'req', '-pubkey', '-noout'], input=csr.encode(),
                            capture_output=True, timeout=10, check=True)
    return hashlib.sha256(result.stdout).hexdigest()


class Authority:
    def __init__(self, database, clock=time.time):
        self.database = Path(database)
        self.clock = clock
        self.certificate_cache={}
        self.database.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Readers must not queue behind snapshot writers or fsync-heavy saves.
        # Keep durable writes serialized; WAL readers see only committed state.
        setup=sqlite3.connect(self.database,timeout=15)
        try:
            if setup.execute('PRAGMA journal_mode').fetchone()[0].lower()!='wal':
                setup.execute('PRAGMA journal_mode=WAL')
        finally:setup.close()
        with self.db() as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY, fingerprint TEXT UNIQUE, hardware TEXT, csr TEXT,
                code TEXT UNIQUE, expires REAL, approved INTEGER DEFAULT 0, certificate TEXT);
            CREATE TABLE IF NOT EXISTS accounts (
                name TEXT PRIMARY KEY, uid INTEGER UNIQUE, gid INTEGER UNIQUE,
                password_hash TEXT, access TEXT, rules TEXT DEFAULT '[]');
            CREATE TABLE IF NOT EXISTS assignments (
                name TEXT, device TEXT, PRIMARY KEY(name,device),
                FOREIGN KEY(name) REFERENCES accounts(name), FOREIGN KEY(device) REFERENCES devices(id));
            CREATE TABLE IF NOT EXISTS sessions (
                name TEXT PRIMARY KEY, device TEXT, token TEXT UNIQUE, created REAL,
                FOREIGN KEY(name) REFERENCES accounts(name), FOREIGN KEY(device) REFERENCES devices(id));
            CREATE TABLE IF NOT EXISTS attempts (scope TEXT, time REAL);
            CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE IF NOT EXISTS runs (kind TEXT, day TEXT, PRIMARY KEY(kind,day));
            ''')
            if 'system_admin' not in {row[1] for row in db.execute('PRAGMA table_info(accounts)')}:
                db.execute('ALTER TABLE accounts ADD COLUMN system_admin INTEGER NOT NULL DEFAULT 0')
            if 'login_visible' not in {row[1] for row in db.execute('PRAGMA table_info(accounts)')}:
                db.execute('ALTER TABLE accounts ADD COLUMN login_visible INTEGER NOT NULL DEFAULT 1')
            if 'persist_ssh' not in {row[1] for row in db.execute('PRAGMA table_info(accounts)')}:
                db.execute('ALTER TABLE accounts ADD COLUMN persist_ssh INTEGER')
            from client_policy import FLATHUB
            db.execute("INSERT OR IGNORE INTO settings VALUES ('sources',?)",(json.dumps([FLATHUB]),))
        self.database.chmod(0o600)
        from snapshot_store import Snapshots
        from image_delivery import Images
        self.snapshots=Snapshots(self)
        self.images=Images(self)
        from session_leases import Leases
        self.leases=Leases(self)

    @contextmanager
    def db(self,write=True):
        connection = sqlite3.connect(self.database, timeout=15)
        connection.row_factory = sqlite3.Row
        connection.execute('PRAGMA foreign_keys=ON')
        try:
            if not write:connection.execute('PRAGMA query_only=ON')
            connection.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def limited(self, scope, limit, window=60):
        # Commit failed attempts too. This transaction is independent of validation.
        with self.db() as db:
            now = self.clock()
            db.execute('DELETE FROM attempts WHERE time < ?', (now-window,))
            count = db.execute('SELECT COUNT(*) FROM attempts WHERE scope=?', (scope,)).fetchone()[0]
            if count >= limit:
                raise ValueError('Too many attempts; retry later')
            db.execute('INSERT INTO attempts VALUES (?,?)', (scope, now))

    def activation(self, data, address):
        self.limited('activation', 60)
        self.limited('activation:'+address, 6)
        if not isinstance(data, dict) or set(data) != {'csr', 'hardware'}:
            raise ValueError('CSR and hardware inventory required')
        hardware = data['hardware']
        if not isinstance(hardware, dict) or not hardware or len(json.dumps(hardware)) > 8192:
            raise ValueError('Invalid hardware inventory')
        hardware = json.dumps(hardware, sort_keys=True)
        fingerprint = csr_key(data['csr'])
        with self.db() as db:
            row = db.execute('SELECT * FROM devices WHERE fingerprint=?', (fingerprint,)).fetchone()
            if row and row['hardware'] != hardware:
                raise ValueError('Hardware changed; administrator re-enrollment required')
            if row and row['approved']:
                return {'device': row['id'], 'approved': True, 'certificate': row['certificate']}
            if row and row['expires'] > self.clock():
                return {'device': row['id'], 'approved': False, 'code': row['code'],
                        'expires': row['expires'], 'message': UNKNOWN}
            code = ''.join(secrets.choice('ABCDEFGHJKLMNPQRSTUVWXYZ23456789') for _ in range(6))
            identifier = row['id'] if row else 'client-'+secrets.token_hex(16)
            expires = self.clock()+600
            if row:
                db.execute('UPDATE devices SET code=?,expires=? WHERE id=?', (code, expires, identifier))
            else:
                db.execute('INSERT INTO devices(id,fingerprint,hardware,csr,code,expires) VALUES (?,?,?,?,?,?)',
                           (identifier, fingerprint, hardware, data['csr'], code, expires))
            return {'device': identifier, 'approved': False, 'code': code, 'expires': expires, 'message': UNKNOWN}

    def approve(self, code, issuer, accounts=None):
        if accounts is not None and (not isinstance(accounts,list) or not accounts or len(accounts)!=len(set(accounts))):raise ValueError('Select at least one distinct existing account')
        self.limited('approval', 5)
        with self.db() as db:
            row = db.execute('SELECT * FROM devices WHERE code=? AND expires>? AND approved=0',
                             (code, self.clock())).fetchone()
            if not row:
                raise ValueError('Unknown, consumed or expired pairing code')
            for name in accounts or []:
                if not db.execute('SELECT 1 FROM accounts WHERE name=?',(name,)).fetchone():raise ValueError('Unknown selected account')
            certificate = issuer(row['csr'], row['id'])
            db.execute('UPDATE devices SET approved=1,certificate=?,code=NULL WHERE id=?',
                       (certificate, row['id']))
            for name in accounts or []:db.execute('INSERT INTO assignments VALUES (?,?)',(name,row['id']))
            return row['id']

    def verify_certificate(self,peer,der):
        digest=hashlib.sha256(der).hexdigest()
        fingerprint=self.certificate_cache.get(digest)
        if fingerprint is None:
            public=subprocess.run(['openssl','x509','-inform','DER','-pubkey','-noout'],input=der,
                                  capture_output=True,check=True,timeout=10).stdout
            fingerprint=hashlib.sha256(public).hexdigest()
            if len(self.certificate_cache)>1024:self.certificate_cache.clear()
            self.certificate_cache[digest]=fingerprint
        with self.db(write=False) as db:
            row=db.execute('SELECT fingerprint FROM devices WHERE id=? AND approved=1',(peer,)).fetchone()
            if not row or row['fingerprint']!=fingerprint:raise ValueError('Device certificate key does not match its approved identity')

    def device(self, db, peer):
        if not peer or not db.execute('SELECT 1 FROM devices WHERE id=? AND approved=1', (peer,)).fetchone():
            raise ValueError(UNKNOWN)

    def account(self, name, uid, gid, password_hash, access, system_admin=None):
        if system_admin is not None and type(system_admin) is not bool:raise ValueError('Invalid system administrator policy')
        if not isinstance(name, str) or not NAME.fullmatch(name) or name in {'root','nobody','daemon','bin','sys','sync','games','man','lp','mail','news','uucp','proxy','www-data','backup','list','irc','_apt','systemd-network','systemd-resolve','messagebus','syslog','sshd','avahi','polkitd','gdm','sudo','adm','disk','tty','audio','video','plugdev','netdev','input','render'} or access not in ACCESS:
            raise ValueError('Invalid account or app permission')
        if any(type(v) is not int or not 1000 <= v <= 60000 for v in (uid, gid)):
            raise ValueError('UID/GID must be in 1000..60000')
        if not isinstance(password_hash, str) or not re.fullmatch(r'\$(6|y)\$[A-Za-z0-9./$]+', password_hash):
            raise ValueError('Use a SHA512 or yescrypt password hash from a protected file')
        with self.db() as db:
            prior = db.execute('SELECT uid,gid FROM accounts WHERE name=?', (name,)).fetchone()
            if prior and (prior['uid'], prior['gid']) != (uid, gid):
                raise ValueError('Existing stable user IDs cannot change')
            db.execute('INSERT INTO accounts(name,uid,gid,password_hash,access) VALUES (?,?,?,?,?) '
                       'ON CONFLICT(name) DO UPDATE SET password_hash=excluded.password_hash,access=excluded.access',
                       (name, uid, gid, password_hash, access))
            if system_admin is not None:db.execute('UPDATE accounts SET system_admin=? WHERE name=?',(int(system_admin),name))

    def visibility(self, name, visible):
        if type(visible) is not bool:raise ValueError('Visibility must be a boolean')
        with self.db() as db:
            if not db.execute('SELECT 1 FROM accounts WHERE name=?',(name,)).fetchone():raise ValueError('Unknown account')
            db.execute('UPDATE accounts SET login_visible=? WHERE name=?',(int(visible),name))

    def ssh_enabled(self, db, account):
        override=account['persist_ssh']
        if override is not None:return bool(override)
        row=db.execute("SELECT value FROM settings WHERE key='default-ssh-persistence'").fetchone()
        return json.loads(row[0]) if row else True

    def effective_rules(self, db, account):
        rules=json.loads(account['rules'])
        if not self.ssh_enabled(db,account):
            return [r for r in rules if r['folder']!='.ssh' and not r['folder'].startswith('.ssh/')]
        # The managed default is independent of a user's app-access permission.
        return [{'folder':'.ssh','mode':'folder','source':None}]+[r for r in rules if r['folder']!='.ssh']

    def ssh_policy(self, name, enabled):
        if enabled is not None and type(enabled) is not bool:raise ValueError('SSH persistence policy must be boolean')
        with self.db() as db:
            if name is None:
                if enabled is None:raise ValueError('Choose an enabled or disabled Server default')
                db.execute("INSERT OR REPLACE INTO settings VALUES ('default-ssh-persistence',?)",(json.dumps(enabled),))
            else:
                if not db.execute('SELECT 1 FROM accounts WHERE name=?',(name,)).fetchone():raise ValueError('Unknown account')
                db.execute('UPDATE accounts SET persist_ssh=? WHERE name=?',(None if enabled is None else int(enabled),name))

    def assign(self, name, peer):
        with self.db() as db:
            self.device(db, peer)
            db.execute('INSERT OR IGNORE INTO assignments VALUES (?,?)', (name, peer))

    def unassign(self, name, peer):
        with self.db() as db:
            if db.execute('SELECT 1 FROM sessions WHERE name=? AND device=?',(name,peer)).fetchone():
                raise ValueError('Account has an active persistent session; save and log out or explicitly release a stale session first')
            db.execute('DELETE FROM assignments WHERE name=? AND device=?',(name,peer))

    def accounts(self, peer):
        with self.db(write=False) as db:
            self.device(db, peer)
            result=[]
            for row in db.execute('SELECT a.* FROM accounts a JOIN assignments x ON a.name=x.name WHERE x.device=?',(peer,)):
                account=dict(row);account['ssh_policy_override']=account['persist_ssh']
                account['rules']=json.dumps(self.effective_rules(db,row));account['persist_ssh']=self.ssh_enabled(db,row)
                result.append(account)
            return result

    def acquire(self, peer, name, boot_id=None):
        with self.db() as db:
            self.device(db, peer)
            if not db.execute('SELECT 1 FROM assignments WHERE name=? AND device=?', (name, peer)).fetchone():
                raise ValueError('Account is not assigned to this Client')
            self.leases.expire(db)
            if db.execute('SELECT 1 FROM sessions WHERE name=?', (name,)).fetchone():
                raise ValueError('Persistent session is active; waiting for the Client heartbeat or its 15-minute offline grace period')
            token = secrets.token_urlsafe(32)
            db.execute('INSERT INTO sessions VALUES (?,?,?,?)', (name, peer, token, self.clock()))
            self.leases.bind(db,name,token,peer,boot_id)
            return {'token': token}

    def session(self, db, peer, name, token):
        self.device(db, peer)
        if not db.execute('SELECT 1 FROM sessions s JOIN assignments a ON s.name=a.name AND s.device=a.device '
                          'WHERE s.name=? AND s.device=? AND s.token=?', (name, peer, token)).fetchone():
            raise ValueError('Stale or unauthorized session; writes rejected')
        if not self.leases.valid(db,name,token):raise ValueError('Persistent session expired after 15 minutes offline; RAM work must be retained')

    def release(self, name):
        with self.db() as db:
            db.execute('DELETE FROM sessions WHERE name=?', (name,))
            db.execute('DELETE FROM session_presence WHERE name=?',(name,))

    def rules(self, peer, name, token, rules):
        validate_rules(rules)
        with self.db() as db:
            self.session(db, peer, name, token)
            row = db.execute('SELECT * FROM accounts WHERE name=?', (name,)).fetchone()
            if row['access'] != 'edit':
                raise ValueError('Server policy does not permit persistence edits')
            sources = json.loads((db.execute("SELECT value FROM settings WHERE key='sources'").fetchone() or ['[]'])[0])
            if any(r['mode']=='app-only' and r['source'] not in sources for r in rules):
                raise ValueError('Application source is not administrator-approved')
            if not self.ssh_enabled(db,row) and any(r['folder']=='.ssh' or r['folder'].startswith('.ssh/') for r in rules):
                raise ValueError('SSH persistence is disabled by the administrator')
            db.execute('UPDATE accounts SET rules=? WHERE name=?', (json.dumps(rules), name))
            updated=dict(row);updated['rules']=json.dumps(rules)
            effective=self.effective_rules(db,updated)
        return {'ok': True,'rules':effective}

    def __call__(self, method, path, peer, address, data):
        if method == 'POST' and path == '/v2/activation':
            return self.activation(data, address)
        with self.db(write=False) as db:
            self.device(db, peer)
        if method=='POST' and path=='/v2/sessions/heartbeat':return self.leases.heartbeat(peer,data)
        if method=='POST' and path=='/v2/sessions/release-all':return self.leases.release_many(peer,data.get('sessions'))
        if method=='POST' and path=='/v2/deployment':
            with self.db() as db:
                if not db.execute('SELECT 1 FROM images WHERE id=?',(data['release'],)).fetchone():raise ValueError('Unknown deployment release')
                db.execute('INSERT OR IGNORE INTO image_pins VALUES (?,?)',(data['release'],'deployed:'+peer))
            return {'ok':True}
        if path=='/v2/printers' and method in ('GET','POST'):
            from printers import validate_configuration
            key='printer-config:'+peer
            with self.db(write=method=='POST') as db:
                if method=='POST':
                    self.session(db,peer,data['name'],data['token'])
                    access=db.execute('SELECT access FROM accounts WHERE name=?',(data['name'],)).fetchone()[0]
                    if access!='edit':raise ValueError('Server policy does not permit printer changes')
                    db.execute('INSERT OR REPLACE INTO settings VALUES (?,?)',(key,json.dumps(validate_configuration(data['configuration']))))
                row=db.execute('SELECT value FROM settings WHERE key=?',(key,)).fetchone()
            return {'configuration':json.loads(row[0]) if row else {}}
        if method=='POST' and path=='/v2/renew':
            fingerprint=csr_key(data['csr'])
            with self.db() as db:
                row=db.execute('SELECT fingerprint FROM devices WHERE id=? AND approved=1',(peer,)).fetchone()
                if not row or row[0]!=fingerprint:raise ValueError('Certificate renewal cannot change the approved device key')
                from control_transport import issue
                certificate=issue(self.database.parent/'pki',data['csr'],peer)
                db.execute('UPDATE devices SET certificate=? WHERE id=?',(certificate,peer))
            return {'certificate':certificate}
        if method == 'POST' and path == '/v2/hardware':
            if not isinstance(data,dict) or not data or len(json.dumps(data))>8192:raise ValueError('Invalid hardware inventory')
            encoded=json.dumps(data,sort_keys=True)
            with self.db() as db:
                prior=db.execute('SELECT hardware FROM devices WHERE id=?',(peer,)).fetchone()[0]
                if prior not in (encoded,json.dumps({'migration':'legacy-enrolled-card'})):
                    raise ValueError('Hardware changed; administrator re-enrollment required')
                db.execute('UPDATE devices SET hardware=? WHERE id=?',(encoded,peer))
            return {'ok':True}
        if method == 'POST' and path == '/v2/sessions/check':
            with self.db(write=False) as db:self.session(db,peer,data['name'],data['token'])
            return {'ok':True}
        if method == 'POST' and path.startswith('/v2/drivers/'):
            with self.db(write=False) as db:enabled=db.execute("SELECT value FROM settings WHERE key='experimental-driver-uploads'").fetchone()
            if not enabled or enabled[0]!='true':raise ValueError('Server-managed driver uploads are deferred and not enabled in this repair rollout')
            from driver_store import Imports
            return Imports(self).dispatch(peer,path.removeprefix('/v2/drivers/'),data)
        if method == 'POST' and path == '/v2/diagnostics':
            from boot_reports import store
            result=store(self.database.parent/'reports'/peer,data)
            if data.get('stage')=='desktop-ready' and data.get('exit_status')==0:self.leases.observe_legacy(peer,data.get('boot_id'))
            return result
        if method == 'GET' and path in ('/v2/images','/v2/recovery/images'):
            return self.images.catalogue(peer,recovery=path=='/v2/recovery/images')
        if method == 'POST' and path.startswith('/v2/snapshots/'):
            return self.snapshots.dispatch(path.removeprefix('/v2/snapshots/'),peer,data)
        if method == 'POST' and path == '/v2/sessions/release':
            return self.leases.release_many(peer,[{'name':data['name'],'token':data['token']}])
        if method == 'GET' and path == '/v2/policy':
            with self.db(write=False) as db:
                row=db.execute("SELECT value FROM settings WHERE key='sources'").fetchone()
                pending=db.execute('SELECT value FROM settings WHERE key=?',('pending-media:'+peer,)).fetchone()
                policy=db.execute("SELECT value FROM settings WHERE key='client-policy'").fetchone()
            from client_policy import validate
            return {'sources':json.loads(row[0]) if row else [],'pending_media':json.loads(pending[0]) if pending else None,'client_policy':validate(json.loads(policy[0]) if policy else {}),'snapshot_sets':True}
        if method == 'GET' and path == '/v2/health':
            return {'schema': 2, 'version': VERSION, 'role': 'Server', 'architecture': {'x86_64':'amd64','aarch64':'arm64'}.get(__import__('os').uname().machine,'unsupported'), 'status': 'healthy'}
        if method == 'GET' and path == '/v2/accounts':
            return {'schema': 2, 'accounts': self.accounts(peer)}
        if method == 'POST' and path == '/v2/sessions':
            return self.acquire(peer, data['name'],data.get('boot_id'))
        if method == 'POST' and path == '/v2/persistence':
            return self.rules(peer, data['name'], data['token'], data['rules'])
        raise ValueError('Unknown version 2 operation')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version',action='version',version=f'HTTP Boot Server {VERSION} (amd64/arm64)')
    parser.add_argument('--state', type=Path, default=Path('/var/lib/httpboot-server'))
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('status')
    sub.add_parser('create-media')
    sub.add_parser('boot-health')
    remote=sub.add_parser('configure-remote-builder');remote.add_argument('file',type=Path)
    sub.add_parser('driver-imports')
    driver=sub.add_parser('review-driver');driver.add_argument('id');driver.add_argument('--approve',action='store_true')
    report=sub.add_parser('import-report');report.add_argument('file',type=Path)
    media=sub.add_parser('enroll-media');media.add_argument('mountpoint',type=Path);media.add_argument('--release')
    sub.add_parser('maintain')
    builder=sub.add_parser('configure-builder');builder.add_argument('file',type=Path)
    initialize=sub.add_parser('init-pki');initialize.add_argument('--address',required=True)
    sub.add_parser('clients')
    sub.add_parser('approve-client')
    defaults=sub.add_parser('approval-defaults');defaults.add_argument('--accounts',nargs='+',required=True)
    public=sub.add_parser('bootstrap-http');public.add_argument('--host',default='0.0.0.0');public.add_argument('--port',type=int,default=8080)
    saves=sub.add_parser('import-legacy-saves');saves.add_argument('config',type=Path)
    migration=sub.add_parser('migrate-legacy');migration.add_argument('--etc',type=Path,required=True);migration.add_argument('--legacy-state',type=Path,required=True)
    publish=sub.add_parser('publish-image');publish.add_argument('release');publish.add_argument('directory',type=Path);publish.add_argument('--proof',type=Path,required=True)
    policy=sub.add_parser('set-rules');policy.add_argument('name');policy.add_argument('file',type=Path)
    schedule=sub.add_parser('schedules');schedule.add_argument('--file',type=Path)
    clean=sub.add_parser('cleanup');clean.add_argument('--apply',action='store_true')
    history=sub.add_parser('cleanup-tools');history.add_argument('--apply',action='store_true')
    retention=sub.add_parser('snapshot-retention');retention.add_argument('--keep',type=int,required=True)
    pin=sub.add_parser('pin-image');pin.add_argument('release');pin.add_argument('reason')
    pending=sub.add_parser('pending-media');pending.add_argument('device');pending.add_argument('file',type=Path)
    sub.add_parser('setup')
    console=sub.add_parser('console');console.add_argument('--port',type=int,default=8081)
    approve = sub.add_parser('approve');approve.add_argument('code');approve.add_argument('--accounts',nargs='+')
    release = sub.add_parser('release-session');release.add_argument('name')
    assign = sub.add_parser('assign');assign.add_argument('name');assign.add_argument('device')
    unassign = sub.add_parser('unassign');unassign.add_argument('name');unassign.add_argument('device')
    account = sub.add_parser('account')
    account.add_argument('name');account.add_argument('--uid', type=int, required=True)
    account.add_argument('--gid', type=int, required=True)
    account.add_argument('--hash-file', type=Path, required=True)
    account.add_argument('--access', choices=ACCESS, default='status')
    account.add_argument('--system-admin',action=argparse.BooleanOptionalAction,default=None)
    ssh=sub.add_parser('ssh-persistence');ssh.add_argument('name',nargs='?');ssh.add_argument('--default',action='store_true');ssh.add_argument('--enabled',action=argparse.BooleanOptionalAction,default=None);ssh.add_argument('--inherit',action='store_true')
    visibility=sub.add_parser('account-visibility');visibility.add_argument('name');visibility.add_argument('--visible',action=argparse.BooleanOptionalAction,required=True)
    client_policy=sub.add_parser('client-policy');client_policy.add_argument('--file',type=Path)
    sources = sub.add_parser('sources');sources.add_argument('urls', nargs='*')
    serve = sub.add_parser('serve');serve.add_argument('--host', default='127.0.0.1')
    serve.add_argument('--port', type=int, default=9444)
    serve.add_argument('--pki', type=Path)
    args = parser.parse_args()
    import os
    if os.geteuid() != 0:
        parser.error('Server administration requires root')
    os.umask(0o077)
    authority = Authority(args.state/'authority.sqlite3')
    if args.command == 'serve':
        from control_transport import Server
        # PKI must be provisioned explicitly; do not silently replace trust roots.
        from image_delivery import ImageHandler
        with Server((args.host,args.port), args.pki or args.state/'pki', authority,handler=ImageHandler) as server:
            import threading,time
            def sweep():
                while True:
                    time.sleep(30)
                    try:
                        with authority.db() as db:authority.leases.expire(db)
                    except (OSError,sqlite3.Error):pass
            threading.Thread(target=sweep,daemon=True).start()
            server.serve_forever()
    elif args.command == 'init-pki':
        import ipaddress
        from control_transport import ca
        ca(args.state/'pki',str(ipaddress.ip_address(args.address)))
    elif args.command == 'approval-defaults':
        with authority.db() as db:
            for name in args.accounts:
                if not db.execute('SELECT 1 FROM accounts WHERE name=?',(name,)).fetchone():raise ValueError('Unknown account')
            db.execute("INSERT OR REPLACE INTO settings VALUES ('approval-defaults',?)",(json.dumps(args.accounts),))
    elif args.command == 'approve-client':
        from approval_wizard import wizard
        wizard(authority)
    elif args.command == 'approve':
        from control_transport import issue
        print(authority.approve(args.code, lambda csr, peer: issue(args.state/'pki', csr, peer),args.accounts))
    elif args.command == 'configure-remote-builder':
        with authority.db() as db:enabled=db.execute("SELECT value FROM settings WHERE key='experimental-remote-builder'").fetchone()
        if not enabled or enabled[0]!='true':raise ValueError('Remote Builder scheduling is deferred and not enabled in this repair rollout')
        from common import load
        from builder_v2 import Remote,REVISION
        pending=args.state/'remote-build.json'
        if pending.exists() and load(pending).get('state') not in ('published','failed'):raise ValueError('A remote build is active; retain its Builder configuration until completion')
        value=load(args.file)
        if set(value)!={'url','fingerprint','token_file','profile'} or not re.fullmatch('[a-zA-Z0-9_-]{1,64}',value['profile']):raise ValueError('Invalid remote Builder configuration')
        secret=Path(value['token_file'])
        if secret.is_symlink() or not secret.is_file() or secret.stat().st_uid != 0 or secret.stat().st_mode & 0o077:raise ValueError('Builder token file must be root-private')
        health=Remote(value).call('/v2/health')
        if health.get('revision')!=REVISION or not health.get('healthy'):raise ValueError('Builder revision or health mismatch')
        with authority.db() as db:
            db.execute("INSERT OR REPLACE INTO settings VALUES ('remote-builder',?)",(json.dumps(value),))
            db.execute("DELETE FROM settings WHERE key='local-builder'")
        print('Remote Builder configured')
    elif args.command == 'driver-imports':
        from driver_store import Imports
        print(json.dumps(Imports(authority).listing(),indent=2))
    elif args.command == 'review-driver':
        from driver_store import Imports
        print(json.dumps(Imports(authority).review(args.id,args.approve)))
    elif args.command == 'boot-health':
        from boot_reports import health
        print(json.dumps(health(authority),indent=2))
    elif args.command == 'import-report':
        from boot_reports import import_report
        print(json.dumps(import_report(args.state,args.file)))
    elif args.command == 'create-media':
        from media_setup import interactive
        interactive(authority)
    elif args.command == 'enroll-media':
        from media_v2 import enroll
        print(json.dumps(enroll(authority,args.mountpoint,args.release)))
    elif args.command == 'maintain':
        from server_maintenance import tick
        try:print(json.dumps(tick(authority)))
        except Exception as error:
            from common import dump
            dump(authority.database.parent/'maintenance-status.json',{'state':'failed','message':str(error)[:1000],'time':time.time()})
            from boot_reports import store
            store(authority.database.parent/'reports/server',{'schema':1,'stage':'server-maintenance','exit_status':1,'line':0,
                  'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()})
            raise
    elif args.command == 'configure-builder':
        from common import load
        pending=args.state/'remote-build.json'
        if pending.exists() and load(pending).get('state') not in ('published','failed'):raise ValueError('A remote build is active; wait for completion before switching Builders')
        value=json.loads(args.file.read_text())
        from common import safe_url
        safe_url(value['server'],https=True)
        for key in ('ca','cache','output'):
            path=Path(value[key])
            if not path.is_absolute() or '..' in path.parts or path==Path('/'):raise ValueError('Use explicit absolute Builder paths')
        with authority.db() as db:
            db.execute("INSERT OR REPLACE INTO settings VALUES ('local-builder',?)",(json.dumps(value),))
            db.execute("DELETE FROM settings WHERE key='remote-builder'")
    elif args.command == 'bootstrap-http':
        from bootstrap_http import serve
        serve(authority,args.host,args.port)
    elif args.command == 'console':
        from server_console import serve
        serve(authority,args.state/'pki',args.port)
    elif args.command == 'setup':
        from server_setup import setup
        setup(authority,args.state)
    elif args.command == 'import-legacy-saves':
        from legacy_snapshots import import_latest
        print(json.dumps(import_latest(authority,args.config)))
    elif args.command == 'migrate-legacy':
        from migration_v2 import migrate
        print(json.dumps(migrate(authority,args.etc,args.legacy_state)))
    elif args.command == 'publish-image':print(json.dumps(authority.images.publish(args.release,args.directory,args.proof)))
    elif args.command == 'set-rules':
        rules=validate_rules(json.loads(args.file.read_text()))
        with authority.db() as db:
            if not db.execute('SELECT 1 FROM accounts WHERE name=?',(args.name,)).fetchone():raise ValueError('Unknown account')
            sources=json.loads((db.execute("SELECT value FROM settings WHERE key='sources'").fetchone() or ['[]'])[0])
            if any(r['mode']=='app-only' and r['source'] not in sources for r in rules):raise ValueError('Unapproved application source')
            db.execute('UPDATE accounts SET rules=? WHERE name=?',(json.dumps(rules),args.name))
    elif args.command == 'pending-media':
        from pending_storage import validate
        value=validate(json.loads(args.file.read_text()))
        with authority.db() as db:
            self_device=db.execute('SELECT 1 FROM devices WHERE id=? AND approved=1',(args.device,)).fetchone()
            if not self_device:raise ValueError('Approved Client required')
            db.execute('INSERT OR REPLACE INTO settings VALUES (?,?)',('pending-media:'+args.device,json.dumps(value)))
    elif args.command == 'schedules':
        from schedule_policy import validate,defaults
        with authority.db() as db:
            if args.file:
                value=validate(json.loads(args.file.read_text()))
                db.execute("INSERT OR REPLACE INTO settings VALUES ('schedules',?)",(json.dumps(value),))
            row=db.execute("SELECT value FROM settings WHERE key='schedules'").fetchone()
            print(row[0] if row else json.dumps(defaults()))
    elif args.command == 'snapshot-retention':
        if not 2<=args.keep<=100:raise ValueError('Keep between 2 and 100 verified snapshots per folder')
        with authority.db() as db:db.execute("INSERT OR REPLACE INTO settings VALUES ('snapshot-retention',?)",(str(args.keep),))
    elif args.command == 'cleanup-tools':
        from release_cleanup import tools
        print(json.dumps(tools(Path('/opt/httpboot'),Path('/var/lib/httpboot'),Path('/var/lib/httpboot-build-cache'),time.time(),args.apply)))
    elif args.command == 'cleanup':
        from release_cleanup import cleanup
        print(json.dumps(cleanup(authority,time.time(),args.apply)))
    elif args.command == 'pin-image':
        from release_cleanup import candidates
        candidates(authority,time.time())
        with authority.db() as db:
            if not db.execute('SELECT 1 FROM images WHERE id=?',(args.release,)).fetchone():raise ValueError('Unknown image')
            db.execute('INSERT OR IGNORE INTO image_pins VALUES (?,?)',(args.release,args.reason))
    elif args.command == 'account':
        authority.account(args.name,args.uid,args.gid,args.hash_file.read_text().strip(),args.access,args.system_admin)
    elif args.command == 'ssh-persistence':
        if bool(args.name)==args.default:raise ValueError('Choose an account name or --default')
        if args.inherit:
            if args.default or args.enabled is not None:raise ValueError('Use --inherit only for an account override')
        elif args.enabled is None:raise ValueError('Choose --enabled, --no-enabled, or --inherit')
        authority.ssh_policy(args.name,args.enabled)
    elif args.command == 'account-visibility':authority.visibility(args.name,args.visible)
    elif args.command == 'assign':authority.assign(args.name,args.device)
    elif args.command == 'unassign':authority.unassign(args.name,args.device)
    elif args.command == 'release-session':authority.release(args.name)
    elif args.command == 'client-policy':
        from client_policy import validate
        with authority.db() as db:
            if args.file:
                value=validate(json.loads(args.file.read_text()))
                from client_policy import extend_transport_certificate
                extend_transport_certificate(args.state/'pki',value['allowed_origins'])
                db.execute("INSERT OR REPLACE INTO settings VALUES ('client-policy',?)",(json.dumps(value),))
            row=db.execute("SELECT value FROM settings WHERE key='client-policy'").fetchone()
            print(json.dumps(validate(json.loads(row[0]) if row else {}),indent=2))
    elif args.command == 'sources':
        from common import safe_url
        urls = [safe_url(url, https=True) for url in args.urls]
        with authority.db() as db:
            db.execute("INSERT OR REPLACE INTO settings VALUES ('sources',?)", (json.dumps(urls),))
    elif args.command == 'clients':
        with authority.db() as db:
            print(json.dumps([dict(r) for r in db.execute('SELECT id,hardware,code,approved,expires FROM devices')],indent=2))
    else:print(json.dumps({'schema':2,'role':'Server','database':str(authority.database)}))


if __name__ == '__main__':
    main()
